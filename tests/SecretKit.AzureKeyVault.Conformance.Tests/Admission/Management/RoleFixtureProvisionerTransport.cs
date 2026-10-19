using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal sealed partial class RoleFixtureProvisioner
{
    // The wrapper owns only response buffers. It never disposes the host transport
    // or credentials. Requests are exact single-resource operations, not arbitrary
    // execution or native polling links.
    internal sealed class BoundaryTransport(HttpPipelineTransport inner, string origin, string path,
        string revision, RequestMethod method, int maximumBytes, bool secret, System.Action? beforeSend = null,
        bool strictRole = false, System.Action? rolePresence = null, bool strictOwnedRead = false)
        : HttpPipelineTransport, IDisposable
    {
        private readonly List<MemoryStream> buffers = [];
        private readonly OwnedArmResponse.Storage roleStorage = new();
        private bool storageDisposed;
        internal OwnedArmResponse.Body? RoleBody { get; private set; }
        internal OwnedArmResponse.ParserCustody? RoleParser { get; private set; }
        internal Func<bool>? RoleIntegrity { get; private set; }
        internal string? RequestSha256 { get; private set; }
        private int sends;
        private bool challenged;
        private bool statusOnly;
        private int statusSends;
        private readonly HashSet<string> statusUris = new(StringComparer.OrdinalIgnoreCase);
        internal int? Status { get; private set; }
        internal string? RequestId { get; private set; }
        internal string? BodySha256 { get; private set; }
        internal bool Valid { get; private set; }
        internal void BeginStatus(bool retainValidatedResponse = false)
        {
            Require(!secret && statusUris.Count > 0);
            statusOnly = true;
            statusSends = 0;
            if (!retainValidatedResponse) Valid = false;
        }
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw Failure();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            Require(!strictRole || !strictOwnedRead);
            bool strict = strictRole || strictOwnedRead;
            message.CancellationToken.ThrowIfCancellationRequested();
            Uri uri = message.Request.Uri.ToUri();
            Require(uri.Scheme == "https" &&
                uri.IsDefaultPort && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
                Same(uri.GetLeftPart(UriPartial.Authority), origin));
            if (statusOnly)
                Require(message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
                    statusUris.Contains(uri.AbsoluteUri) && ++statusSends <= 2);
            else
                Require(message.Request.Method == method && Same(uri.AbsolutePath, path) &&
                    uri.Query == "?api-version=" + revision &&
                    ++sends <= (secret ? 2 : 1) && (sends == 1 || challenged));
            Valid = false;
            Status = null;
            RequestId = null;
            BodySha256 = null;
            if (!statusOnly && sends == 1) beforeSend?.Invoke();
            Request? roleRequest = strict ? message.Request : null;
            HttpHeader[]? roleRequestHeaders = strict ? message.Request.Headers.ToArray() : null;
            void CheckRoleRequest()
            {
                if (!strict) return;
                Require(ReferenceEquals(message.Request, roleRequest) &&
                    message.Request.Uri.ToUri().AbsoluteUri == uri.AbsoluteUri &&
                    message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
                    roleRequestHeaders!.SequenceEqual(message.Request.Headers));
            }
            if (strict)
            {
                Require(!secret && !statusOnly && method == RequestMethod.Get && message.Request.Content is null &&
                    uri.OriginalString == uri.AbsoluteUri && roleRequestHeaders!.Length <= 32 &&
                    roleRequestHeaders.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
                    roleRequestHeaders.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == roleRequestHeaders.Length &&
                    roleRequestHeaders.All(h => h.Name.Length is > 0 and <= 128 && h.Value.Length <= 16384 &&
                        !h.Name.Any(char.IsControl) && !h.Value.Any(char.IsControl)) &&
                    !message.Request.Headers.Contains("Content-Encoding") &&
                    !message.Request.Headers.Contains("Transfer-Encoding") &&
                    !message.Request.Headers.Contains("Content-Range") &&
                    message.Request.Headers.TryGetValue("Authorization", out var authorization) &&
                    authorization.StartsWith("Bearer ", StringComparison.Ordinal) && authorization.Length > 7);
                if (message.Request.Headers.TryGetValue("Host", out var requestHost)) Require(requestHost == "management.azure.com");
                if (message.Request.Headers.TryGetValue("Content-Length", out var requestLength)) Require(requestLength == "0");
                RequestSha256 = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(
                    "GET " + uri.AbsoluteUri)));
            }
            message.BufferResponse = false;
            try { await inner.ProcessAsync(message).ConfigureAwait(false); }
            finally
            {
                if (strict && message.HasResponse)
                {
                    roleStorage.Own(message.Response);
                    if (message.Response.Status == 200) rolePresence?.Invoke();
                }
            }
            Status = message.Response.Status;
            try
            {
                message.CancellationToken.ThrowIfCancellationRequested();
                CheckRoleRequest();
                if (strict)
                {
                    Require(Status is 200 or 404);
                    var original = message.Response;
                    var roleInput = original.ContentStream;
                    var headers = original.Headers.ToArray();
                    string reason = original.ReasonPhrase, clientId = original.ClientRequestId;
                    int status = original.Status;
                    RoleBody = await OwnedArmResponse.CaptureAsync(message, maximumBytes, roleStorage).ConfigureAwait(false);
                    CheckRoleRequest();
                    using (var document = JsonDocument.Parse(RoleBody.Bytes, new JsonDocumentOptions { MaxDepth = 8 }))
                        Unique(document.RootElement);
                    BodySha256 = RoleBody.Sha256;
                    RequestId = RoleBody.NativeRequestId;
                    RoleIntegrity = () => original.Status == status && original.ReasonPhrase == reason &&
                        original.ClientRequestId == clientId && headers.SequenceEqual(original.Headers) &&
                        ReferenceEquals(original.ContentStream, roleInput);
                    Require(RoleIntegrity());
                    RoleParser = OwnedArmResponse.ParserCustody.Install(message, RoleBody.Response, RoleBody.Bytes,
                        roleStorage, requireRebuffer: false, requireDownstreamRead: true);
                    Valid = true;
                    return;
                }
                Require(Status is not (>= 300 and < 400));
                if (!secret && !statusOnly)
                {
                    statusUris.Add(origin + path + "?api-version=" + revision);
                    string[] parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
                    foreach (string header in new[] { "Azure-AsyncOperation", "Operation-Location", "Location" })
                    {
                        if (!message.Response.Headers.TryGetValue(header, out string? value)) continue;
                        Require(Uri.TryCreate(value, UriKind.Absolute, out var status) &&
                            status.Scheme == "https" && status.IsDefaultPort && status.UserInfo.Length == 0 &&
                            status.Fragment.Length == 0 && Same(status.GetLeftPart(UriPartial.Authority), origin) &&
                            parts.Length >= 2 && status.AbsolutePath.StartsWith("/subscriptions/" + parts[1] + "/",
                                StringComparison.OrdinalIgnoreCase) &&
                            (status.Query.Length == 0 || status.Query == "?api-version=" + revision));
                        statusUris.Add(status!.Query.Length == 0 ? status.AbsoluteUri + "?api-version=" + revision : status.AbsoluteUri);
                    }
                }
                if (message.Response.Headers.TryGetValues("x-ms-request-id", out var ids))
                {
                    string[] values = ids.ToArray();
                    Require(values.Length == 1 && values[0].Length is > 0 and <= 256 &&
                        values[0].All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.'));
                    RequestId = values[0];
                }
                if (message.Response.Headers.TryGetValues("Content-Length", out var lengths))
                {
                    string[] values = lengths.ToArray();
                    Require(values.Length == 1 && long.TryParse(values[0], NumberStyles.None, CultureInfo.InvariantCulture, out long length) &&
                        length >= 0 && length <= maximumBytes);
                }
                var buffer = new MemoryStream();
                buffers.Add(buffer);
                Stream? input = message.Response.ContentStream;
                byte[] chunk = new byte[4096];
                try
                {
                    if (input is not null)
                    {
                        int read;
                        while ((read = await input.ReadAsync(chunk, message.CancellationToken).ConfigureAwait(false)) != 0)
                        {
                            Require(buffer.Length + read <= maximumBytes);
                            buffer.Write(chunk, 0, read);
                        }
                        input.Dispose();
                    }
                }
                finally { CryptographicOperations.ZeroMemory(chunk); }
                buffer.Position = 0;
                message.Response.ContentStream = buffer;
                if (buffer.Length > 0)
                {
                    using var document = JsonDocument.Parse(buffer.GetBuffer().AsMemory(0, (int)buffer.Length),
                        new JsonDocumentOptions { MaxDepth = 32 });
                    Unique(document.RootElement);
                    BodySha256 = Convert.ToHexString(SHA256.HashData(buffer.GetBuffer().AsSpan(0, (int)buffer.Length)));
                }
                if (secret && Status == 401 && message.Response.Headers.TryGetValue("WWW-Authenticate", out _))
                {
                    Require(sends == 1 && !challenged);
                    challenged = true;
                }
                Valid = true;
            }
            catch
            {
                message.Response.Dispose();
                throw;
            }
        }
        private static void Unique(JsonElement node)
        {
            if (node.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in node.EnumerateObject())
                {
                    Require(names.Add(property.Name));
                    Unique(property.Value);
                }
            }
            else if (node.ValueKind == JsonValueKind.Array)
                foreach (var child in node.EnumerateArray()) Unique(child);
        }
        public void Dispose()
        {
            if (!storageDisposed)
            {
                storageDisposed = true;
                roleStorage.Dispose();
            }
            foreach (var buffer in buffers)
            {
                if (buffer.TryGetBuffer(out var bytes)) CryptographicOperations.ZeroMemory(bytes.AsSpan());
                buffer.Dispose();
            }
            buffers.Clear();
        }
    }
}
