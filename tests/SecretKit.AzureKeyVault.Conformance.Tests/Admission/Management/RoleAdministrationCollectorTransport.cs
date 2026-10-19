using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal sealed partial class RoleAdministrationCollector
{
    private enum Collection { Assignments, Definitions, Secret }

    // One narrow transport per inventory/read. The host transport and credential
    // are borrowed. Response storage is ours and is zeroed on all exit paths.
    private sealed class BoundaryTransport(HttpPipelineTransport inner, Binding binding, Limits limits,
        string path, Collection collection) : HttpPipelineTransport, IDisposable
    {
        private readonly HashSet<string> visited = new(StringComparer.Ordinal);
        private readonly HashSet<string> rowIds = new(StringComparer.OrdinalIgnoreCase);
        private ZeroingStream? buffer;
        private Response? response;
        private string? next;
        private int pages;
        private int items;
        private int pageItems;
        private int sends;
        private bool checkedPage = true;
        private bool challengeSeen;
        internal string? RequestId { get; private set; }
        internal int LastStatus { get; private set; }
        internal bool ValidResponse { get; private set; }

        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new Boundary();

        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            message.CancellationToken.ThrowIfCancellationRequested();
            Uri uri = message.Request.Uri.ToUri();
            string key = ValidateUri(uri.OriginalString, pages == 0);
            if (message.Request.Method != RequestMethod.Get || message.Request.Content is not null)
                throw new Boundary();
            if (collection == Collection.Secret)
            {
                // A native authentication challenge is not a retry budget. At most
                // one challenge exchange and one final read can cross this boundary.
                if (++sends > 2 || sends == 2 && !challengeSeen) throw new Boundary();
            }
            else
            {
                if (!checkedPage || pages >= limits.MaximumPages || items >= limits.MaximumItems)
                    throw new Boundary(Failure.Budget);
                if (pages != 0 && (next is null || key != ValidateUri(next, false)) || !visited.Add(key))
                    throw new Boundary();
            }
            ValidResponse = false;
            RequestId = null;
            buffer?.Dispose();
            response?.Dispose();
            buffer = null;
            response = null;
            message.BufferResponse = false;
            try
            {
                await inner.ProcessAsync(message).ConfigureAwait(false);
                response = message.Response;
                LastStatus = response.Status;
                message.CancellationToken.ThrowIfCancellationRequested();
                if (message.Response.Headers.TryGetValues("x-ms-request-id", out var requestIds))
                {
                    string[] ids = requestIds.ToArray();
                    if (ids.Length != 1 || ids[0].Length is < 1 or > 256 ||
                        !ids[0].All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.'))
                        throw new Boundary();
                    RequestId = ids[0];
                }
                if (LastStatus is >= 300 and < 400) throw new Boundary();
                long? declaredLength = null;
                if (message.Response.Headers.TryGetValues("Content-Length", out var lengths))
                {
                    string[] values = lengths.ToArray();
                    if (values.Length != 1 || !long.TryParse(values[0], NumberStyles.None, CultureInfo.InvariantCulture, out long length) ||
                        length > limits.MaximumResponseBytes)
                        throw new Boundary(Failure.Budget);
                    declaredLength = length;
                }
                buffer = await Buffer(message).ConfigureAwait(false);
                if (declaredLength is { } expected && expected != buffer.Bytes.Length) throw new Boundary();
                if (collection == Collection.Secret && LastStatus == 401 && sends == 1 &&
                    message.Response.Headers.TryGetValue("WWW-Authenticate", out _))
                {
                    challengeSeen = true;
                    ValidResponse = true;
                    return;
                }
                if (collection == Collection.Secret)
                {
                    if (RequestId is null) throw new Boundary();
                    if (LastStatus == 200)
                    {
                        using var document = Parse(buffer, message.CancellationToken);
                        JsonElement root = document.RootElement;
                        if (!Same(Text(root, "id"), SecretOrigin(binding) + path) ||
                            !root.TryGetProperty("value", out var value) || value.ValueKind != JsonValueKind.String)
                            throw new Boundary();
                    }
                    else if (LastStatus < 400) throw new Boundary();
                    message.CancellationToken.ThrowIfCancellationRequested();
                    ValidResponse = true;
                    return;
                }
                if (LastStatus != 200) throw new Boundary(Failure.Unavailable);
                using (var document = Parse(buffer, message.CancellationToken))
                {
                    JsonElement root = document.RootElement;
                    JsonElement rows = Array(root, "value");
                    pageItems = rows.GetArrayLength();
                    if (pageItems > limits.MaximumItems - items) throw new Boundary(Failure.Budget);
                    foreach (var row in rows.EnumerateArray()) ValidateRow(row);
                    next = null;
                    if (root.TryGetProperty("nextLink", out var continuation) && continuation.ValueKind != JsonValueKind.Null)
                    {
                        if (continuation.ValueKind != JsonValueKind.String) throw new Boundary();
                        next = continuation.GetString();
                        string nextKey = ValidateUri(next!, false);
                        if (visited.Contains(nextKey) || pageItems == 0) throw new Boundary();
                        if (pages + 1 >= limits.MaximumPages || items + pageItems >= limits.MaximumItems)
                            throw new Boundary(Failure.Budget);
                    }
                    items += pageItems;
                    pages++;
                    checkedPage = false;
                    message.CancellationToken.ThrowIfCancellationRequested();
                    ValidResponse = true;
                }
            }
            catch
            {
                if (message.HasResponse) message.Response.Dispose();
                throw;
            }
        }

        internal void CheckPage(string? continuation, int count)
        {
            if (!ValidResponse || checkedPage || count != pageItems || !string.Equals(continuation, next, StringComparison.Ordinal))
                throw new Boundary();
            checkedPage = true;
        }

        internal void RequireComplete(int count)
        {
            if (!checkedPage || !ValidResponse || pages == 0 || next is not null || count != items)
                throw new Boundary();
        }

        private string ValidateUri(string text, bool first)
        {
            string origin = collection == Collection.Secret ? SecretOrigin(binding) : ArmOrigin;
            if (string.IsNullOrEmpty(text) || text.Length > 8192 || !Uri.TryCreate(text, UriKind.Absolute, out var uri) ||
                uri.Scheme != "https" || !uri.IsDefaultPort || uri.UserInfo.Length != 0 || text.Contains('#') ||
                !Same(text.Split('?')[0], origin + path) || uri.Query.Length == 0)
                throw new Boundary();
            var query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string part in uri.Query[1..].Split('&'))
            {
                string[] pair = part.Split('=', 2);
                if (pair.Length != 2 || pair.Any(v => HasBadEscape(v))) throw new Boundary();
                string name = Uri.UnescapeDataString(pair[0]);
                string value = Uri.UnescapeDataString(pair[1]);
                if (name is not ("api-version" or "$filter" or "$skiptoken") ||
                    !query.TryAdd(name, value) || value.Length == 0 || value.Length > 4096 ||
                    value.Any(char.IsControl))
                    throw new Boundary();
            }
            if (!query.TryGetValue("api-version", out string? revision) ||
                revision != (collection == Collection.Secret ? SecretRevision : ArmRevision))
                throw new Boundary();
            if (collection == Collection.Secret && query.Count != 1 ||
                collection == Collection.Definitions && query.ContainsKey("$filter") ||
                query.TryGetValue("$filter", out string? filter) && filter != "atScope()" ||
                collection == Collection.Assignments && first && !query.ContainsKey("$filter") ||
                collection != Collection.Secret && !first && !query.ContainsKey("$skiptoken") ||
                first && query.ContainsKey("$skiptoken"))
                throw new Boundary();
            return string.Join("&", query.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p =>
                Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value)));
        }

        private static bool HasBadEscape(string text)
        {
            for (int i = 0; i < text.Length; i++)
                if (text[i] == '%' && (i + 2 >= text.Length || !char.IsAsciiHexDigit(text[i + 1]) || !char.IsAsciiHexDigit(text[i + 2])))
                    return true;
            return false;
        }

        private void ValidateRow(JsonElement row)
        {
            string id = Text(row, "id");
            string name = Text(row, "name");
            string type = Text(row, "type");
            if (!rowIds.Add(id) || !row.TryGetProperty("properties", out var properties) ||
                properties.ValueKind != JsonValueKind.Object) throw new Boundary();
            Guid identifier;
            if (collection == Collection.Assignments)
            {
                identifier = AssignmentIdentifier(id, Text(properties, "scope"), binding);
                _ = DefinitionIdentifier(Text(properties, "roleDefinitionId"), binding);
                if (!Guid.TryParseExact(Text(properties, "principalId"), "D", out var principal) || principal == Guid.Empty ||
                    !Same(type, "Microsoft.Authorization/roleAssignments")) throw new Boundary();
                foreach (string field in new[] { "principalType", "description", "condition", "conditionVersion" })
                    OptionalText(properties, field);
            }
            else
            {
                identifier = DefinitionIdentifier(id, binding);
                if (!Same(type, "Microsoft.Authorization/roleDefinitions")) throw new Boundary();
                foreach (string field in new[] { "roleName", "description", "type" }) OptionalText(properties, field);
                StringArray(properties, "assignableScopes");
                foreach (var permission in Array(properties, "permissions").EnumerateArray())
                    foreach (string field in new[] { "actions", "notActions", "dataActions", "notDataActions" })
                        StringArray(permission, field);
            }
            if (!Guid.TryParseExact(name, "D", out var named) || named != identifier) throw new Boundary();
        }

        private static string Text(JsonElement root, string field) =>
            root.ValueKind == JsonValueKind.Object && root.TryGetProperty(field, out var value) &&
                value.ValueKind == JsonValueKind.String && value.GetString() is { } text
                ? text : throw new Boundary();
        private static void OptionalText(JsonElement root, string field)
        {
            if (root.TryGetProperty(field, out var value) && value.ValueKind is not (JsonValueKind.String or JsonValueKind.Null))
                throw new Boundary();
        }
        private static JsonElement Array(JsonElement root, string field) =>
            root.ValueKind == JsonValueKind.Object && root.TryGetProperty(field, out var value) &&
                value.ValueKind == JsonValueKind.Array ? value : throw new Boundary();
        private static void StringArray(JsonElement root, string field)
        {
            if (Array(root, field).EnumerateArray().Any(v => v.ValueKind != JsonValueKind.String)) throw new Boundary();
        }

        private static JsonDocument Parse(ZeroingStream stream, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            JsonDocument document = JsonDocument.Parse(stream.Bytes, new JsonDocumentOptions { MaxDepth = 32 });
            try
            {
                UniqueProperties(document.RootElement);
                token.ThrowIfCancellationRequested();
                return document;
            }
            catch
            {
                document.Dispose();
                throw;
            }
        }
        private static void UniqueProperties(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var property in value.EnumerateObject())
                {
                    if (!names.Add(property.Name)) throw new Boundary();
                    UniqueProperties(property.Value);
                }
            }
            else if (value.ValueKind == JsonValueKind.Array)
                foreach (var item in value.EnumerateArray()) UniqueProperties(item);
        }

        private async ValueTask<ZeroingStream> Buffer(HttpMessage message)
        {
            byte[] storage = new byte[limits.MaximumResponseBytes + 1];
            try
            {
                int count = 0;
                if (message.Response.ContentStream is { } source)
                {
                    using (source)
                    {
                        int read;
                        do
                        {
                            read = await source.ReadAsync(storage.AsMemory(count), message.CancellationToken).ConfigureAwait(false);
                            message.CancellationToken.ThrowIfCancellationRequested();
                            count += read;
                            if (count > limits.MaximumResponseBytes) throw new Boundary(Failure.Budget);
                        } while (read != 0);
                    }
                }
                var buffer = new ZeroingStream(storage, count);
                message.Response.ContentStream = buffer;
                return buffer;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(storage);
                throw;
            }
        }

        public void Dispose()
        {
            buffer?.Dispose();
            response?.Dispose();
        }
    }

    private sealed class ZeroingStream : MemoryStream
    {
        private readonly byte[] storage;
        private readonly int count;
        internal ZeroingStream(byte[] storage, int count) : base(storage, 0, count, false)
        {
            this.storage = storage;
            this.count = count;
        }
        internal ReadOnlyMemory<byte> Bytes => storage.AsMemory(0, count);
        protected override void Dispose(bool disposing)
        {
            if (disposing) CryptographicOperations.ZeroMemory(storage);
            base.Dispose(disposing);
        }
    }
}
