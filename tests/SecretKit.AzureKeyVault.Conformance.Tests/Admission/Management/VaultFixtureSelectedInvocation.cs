using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using E = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;
using M = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal sealed partial class VaultFixtureObserverService
{
    private sealed class SelectedCall(Session session, VaultAdministration client, VaultScope vault,
        ManagementReceipt receipt)
    {
        internal readonly Session Session = session;
        internal readonly VaultAdministration Client = client;
        internal readonly VaultScope Vault = vault;
        internal readonly ManagementReceipt Receipt = receipt;
        internal Task<SecretOutcome<AccessPolicyObservation>>? OriginalTask;
        internal Task? SendTask;
        internal Guid Dispatch;
        internal int Sends;
        internal bool Started, ThroughSource, Attempted, Terminated, NativeProof, Settled, Finalized, RejectedBeforeDispatch;
        internal int? NativeStatus;
        internal readonly List<byte[]> Buffers = [];
        internal readonly List<IDisposable> Storage = [];
        internal void Clear()
        {
            // Only the owner of the fully joined original task calls this.
            bool failed = false;
            foreach (var item in Storage)
            {
                try { item.Dispose(); }
                catch (Exception) { failed = true; }
            }
            Storage.Clear();
            foreach (var bytes in Buffers) CryptographicOperations.ZeroMemory(bytes);
            Buffers.Clear();
            if (failed) throw Failure();
        }
        public override string ToString() => "[VaultSelectedInvocation]";
    }

    public async ValueTask<SecretOutcome<AccessPolicyObservation>> RunChangeAccessPoliciesAsync(
        FixtureSelector selector, VaultAdministration client, VaultScope scope, AccessPolicyChange change,
        IReadOnlyList<SecretAccessPolicy> policies, ManagementReceipt receipt, CancellationToken cancellationToken)
    {
        ValidateSelector(selector);
        Require(client is not null && scope is not null && receipt is not null &&
            policies is not null && policies.Count == principals.Length &&
            change == (selector.Variant switch
            {
                "change.Remove" => AccessPolicyChange.Remove,
                "change.Replace" => AccessPolicyChange.Replace,
                _ => AccessPolicyChange.Add
            }) &&
            receipt.Evidence == DispatchEvidence.NotDispatched);
        var selected = policies.ToArray();
        Require(selected.Select((p, i) => p is not null && Matches(new(p.TenantId, p.ObjectId,
            p.Permissions.ToArray(), p.ApplicationId), principals[i].Principal, selector)).All(m => m));
        Session session;
        SelectedCall call;
        lock (gate)
        {
            Require(sessions.TryGetValue(selector.Nonce, out session!) && !disposed &&
                session.Selector == selector && !session.Closed && session.Armed && session.BaselineReady &&
                !session.AfterClaimed && session.Selected is null && session.Active == 0 &&
                scope.ExportResourceId() == session.Plan!.VaultId);
            call = new(session, client, scope, receipt);
            session.Selected = call;
            // Reserve both drains before ANY host/SDK callback. A credential
            // borrower ignoring cancellation cannot race root deletion.
            session.Active++;
            active++;
        }
        using var deadline = new CancellationTokenSource(limits.Timeout, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token,
            session.Stop.Token, lifetime.Token);
        var previous = current.Value;
        try
        {
            current.Value = call;
            lock (gate)
            {
                Require(!session.Closed && !disposed);
                linked.Token.ThrowIfCancellationRequested();
                call.Dispatch = source.Journal.BeginSelectedUpdate(owner, selector, session.Plan!.VaultId);
                call.Started = true;
                // The SDK itself checks the receipt's private client authority,
                // exact scope reference, operation and Used flag before asking
                // for credentials. Never substitute a new client/scope/receipt.
                call.OriginalTask = call.Client.ChangeAccessPoliciesAsync(call.Vault, change, selected,
                    call.Receipt, linked.Token).AsTask();
            }
            var result = await call.OriginalTask.ConfigureAwait(false);
            // The original SDK's receipt validation returns Invalid before
            // credentials or transport. This is positive rejection evidence,
            // unlike a callback exception or an Unknown outcome.
            call.RejectedBeforeDispatch = result.Status == SecretStatus.Invalid &&
                !call.ThroughSource && call.Sends == 0 && !call.Attempted &&
                call.Receipt.Evidence == DispatchEvidence.NotDispatched;
            Require(call.ThroughSource || call.RejectedBeforeDispatch);
            return result;
        }
        finally
        {
            current.Value = previous;
            // Awaiting OriginalTask above includes transport, credential,
            // serialization and parsing. No caller acknowledgement ends a fence.
            call.Terminated = true;
            call.Settled = call.RejectedBeforeDispatch || call.ThroughSource && call.Sends == 1 &&
                call.Attempted && call.NativeProof && call.SendTask is { IsCompleted: true } &&
                call.NativeStatus is 200 or 403;
            try
            {
                if (call.Dispatch != Guid.Empty) FinalizeSelected(call);
            }
            finally
            {
                try { call.Clear(); }
                finally
                {
                    try { Leave(session); }
                    finally { EndRequest(); }
                }
            }
        }
    }

    private void FinalizeSelected(SelectedCall call)
    {
        lock (gate)
        {
            Require(call.Terminated && (call.OriginalTask is null || call.OriginalTask.IsCompleted) &&
                (call.SendTask is null || call.SendTask.IsCompleted));
            if (call.Finalized) return;
            if (call.Dispatch == Guid.Empty) { call.Finalized = true; return; }
            source.Journal.EndDispatch(owner, call.Session.Selector, call.Session.Plan!.VaultId,
                call.Dispatch, call.Settled);
            call.Finalized = true;
        }
    }

    private sealed class OriginalTransport(VaultFixtureObserverService service) : HttpPipelineTransport
    {
        private SelectedCall Current
        {
            get
            {
                var call = service.current.Value ?? throw Failure();
                Require(call.Started && !call.Terminated && !call.Session.Closed && !service.disposed &&
                    ReferenceEquals(call.Session.Selected, call));
                return call;
            }
        }
        public override Request CreateRequest()
        {
            lock (service.gate)
            {
                _ = Current;
                return service.source.SelectedTransport.CreateRequest();
            }
        }
        public override void Process(HttpMessage message) => throw Failure();
        public override ValueTask ProcessAsync(HttpMessage message)
        {
            lock (service.gate)
            {
                var call = Current;
                call.ThroughSource = true;
                Require(++call.Sends == 1);
                return service.Send(call, message);
            }
        }
        public override string ToString() => "[VaultOriginalSelectedTransport]";
    }

    private async ValueTask Send(SelectedCall call, HttpMessage message)
    {
        ValidateRequest(call, message);
        message.CancellationToken.ThrowIfCancellationRequested();
        // Always send source-owned canonical bytes. If the SDK has a warm
        // request body, validate it first; absent cold-challenge content never
        // becomes a discovery send or a different request.
        byte[] canonical = CanonicalPolicy(call.Session.Selector);
        call.Buffers.Add(canonical);
        if (message.Request.Content is { } original)
        {
            using var body = new RequestBuffer(limits.MaximumBodyBytes);
            Require(original.TryComputeLength(out long length) && length is > 0 && length <= limits.MaximumBodyBytes);
            await original.WriteToAsync(body, message.CancellationToken).ConfigureAwait(false);
            Require(body.Length == length);
            ValidatePolicyBody(body.Bytes, call.Session.Selector);
        }
        var content = RequestContent.Create(canonical.AsMemory());
        call.Storage.Add(content);
        message.Request.Content = content;
        message.Request.Headers.SetValue("Content-Type", "application/json");
        message.Request.Headers.SetValue("Content-Length", canonical.Length.ToString(CultureInfo.InvariantCulture));
        ValidateRequest(call, message);
        Require(message.Request.Headers.TryGetValue("Authorization", out var authorization) &&
            authorization.StartsWith("Bearer ", StringComparison.Ordinal) && Text(authorization[7..], 16384));
        var headers = message.Request.Headers.Select(h => (h.Name, h.Value)).ToArray();
        lock (gate)
        {
            message.CancellationToken.ThrowIfCancellationRequested();
            Require(!disposed && !call.Session.Closed && !call.Terminated);
            var journal = source.Journal.Read(owner, call.Session.Selector);
            Require(!journal.Closing && journal.LeaseId == call.Session.Plan!.LeaseId &&
                journal.Resources.Single(r => r.Id == call.Session.Plan.VaultId).ActiveDispatch == call.Dispatch &&
                journal.Resources.Where(r => r.Id != call.Session.Plan.VaultId).All(r => r.ActiveDispatch == Guid.Empty));
            message.BufferResponse = false;
            call.Attempted = true;
            call.SendTask = source.SelectedTransport.ProcessAsync(message).AsTask();
        }
        await call.SendTask.ConfigureAwait(false);
        ValidateRequest(call, message);
        Require(headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))) &&
            ReferenceEquals(message.Request.Content, content) && message.HasResponse);
        var response = message.Response;
        call.Storage.Add(response);
        call.NativeStatus = response.Status;
        // A native transport exception, 202, continuation, malformed success or
        // unknown state never receives a settlement certificate.
        Require(response.Status is 200 or 403);
        long? declared = ValidateResponseHeaders(response);
        byte[] bytes = new byte[limits.MaximumReplyBytes + 1];
        call.Buffers.Add(bytes);
        int count = 0;
        if (response.ContentStream is { } input)
        {
            while (true)
            {
                message.CancellationToken.ThrowIfCancellationRequested();
                int read = await input.ReadAsync(bytes.AsMemory(count), message.CancellationToken).ConfigureAwait(false);
                if (read == 0) break;
                count += read;
                Require(count <= limits.MaximumReplyBytes);
            }
            input.Dispose();
        }
        Require(count > 0 && count <= limits.MaximumReplyBytes && (declared is null || declared == count));
        using (var document = JsonDocument.Parse(bytes.AsMemory(0, count), new JsonDocumentOptions { MaxDepth = 16 }))
        {
            Unique(document.RootElement);
            if (response.Status == 200) ValidateSuccess(call, document.RootElement);
            else ValidateDenied(document.RootElement);
        }
        message.CancellationToken.ThrowIfCancellationRequested();
        var buffered = new MemoryStream(bytes, 0, count, writable: false, publiclyVisible: true);
        call.Storage.Add(buffered);
        response.ContentStream = buffered;
        // This proof is retained before the OUTER management boundary can inject
        // cancellation/loss. Neither SDK Unknown nor cancellation erases it.
        call.NativeProof = true;
    }

    private void ValidateRequest(SelectedCall call, HttpMessage message)
    {
        var uri = message.Request.Uri.ToUri();
        Require(message.Request.Method == RequestMethod.Put &&
            uri.GetLeftPart(UriPartial.Authority) == M.ArmOrigin &&
            uri.AbsolutePath.Equals(call.Session.Plan!.VaultId + "/accessPolicies/" +
                (call.Session.Selector.Variant switch
                {
                    "change.Remove" => "remove",
                    "change.Replace" => "replace",
                    _ => "add"
                }), StringComparison.OrdinalIgnoreCase) &&
            uri.Query == "?api-version=" + M.Revision && uri.Fragment.Length == 0 && uri.UserInfo.Length == 0);
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int total = 0;
        foreach (var header in message.Request.Headers)
        {
            Require(names.Add(header.Name) && Text(header.Name, 128) && Text(header.Value, 16384));
            total += header.Name.Length + header.Value.Length;
            Require(total <= 32768);
        }
        if (message.Request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
        Require(!message.Request.Headers.Contains("Content-Encoding") &&
            !message.Request.Headers.Contains("Transfer-Encoding"));
    }

    private byte[] CanonicalPolicy(FixtureSelector selector)
    {
        using var buffer = new RequestBuffer(limits.MaximumBodyBytes);
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteStartObject("properties");
            writer.WriteStartArray("accessPolicies");
            foreach (var source in principals)
            {
                var principal = source.Principal;
                writer.WriteStartObject();
                writer.WriteString("tenantId", principal.TenantId);
                writer.WriteString("objectId", principal.PrincipalId);
                if (principal.ApplicationId is { } application) writer.WriteString("applicationId", application);
                writer.WriteStartObject("permissions");
                writer.WriteStartArray("secrets");
                foreach (var permission in Permissions(selector))
                    writer.WriteStringValue(permission.ToString().ToLowerInvariant());
                writer.WriteEndArray();
                writer.WriteEndObject();
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        return buffer.Bytes.ToArray();
    }

    private void ValidatePolicyBody(ReadOnlyMemory<byte> bytes, FixtureSelector selector)
    {
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        Unique(root);
        Require(Only(root, "properties"));
        var properties = root.GetProperty("properties");
        Require(Only(properties, "accessPolicies"));
        var policies = properties.GetProperty("accessPolicies");
        Require(policies.ValueKind == JsonValueKind.Array && policies.GetArrayLength() == principals.Length);
        for (int i = 0; i < principals.Length; i++)
            Require(Matches(ParsePolicy(policies[i], allowOmittedSecrets: Permissions(selector).Length == 0),
                principals[i].Principal, selector));
    }

    private void ValidateSuccess(SelectedCall call, JsonElement root)
    {
        Require(Only(root, "id", "name", "type", "location", "properties") &&
            root.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String &&
            string.Equals(id.GetString(), call.Session.Plan!.VaultId, StringComparison.OrdinalIgnoreCase));
        var properties = root.GetProperty("properties");
        Require(Only(properties, "accessPolicies", "provisioningState"));
        var policies = properties.GetProperty("accessPolicies");
        Require(policies.ValueKind == JsonValueKind.Array && policies.GetArrayLength() is >= 0 and <= 16);
        if (root.TryGetProperty("name", out var name))
            Require(name.ValueKind == JsonValueKind.String && name.GetString() == call.Session.Plan.VaultName);
        if (root.TryGetProperty("type", out var type))
            Require(type.ValueKind == JsonValueKind.String && type.GetString() == "Microsoft.KeyVault/vaults");
        if (root.TryGetProperty("location", out var location))
            Require(location.ValueKind == JsonValueKind.String && location.GetString() == scope.Location);
        if (properties.TryGetProperty("provisioningState", out var state))
            Require(state.ValueKind == JsonValueKind.String && state.GetString() == "Succeeded");
        var projected = policies.EnumerateArray().Select(p => ParsePolicy(p)).ToArray();
        E.Policy[] expected = [.. baseline.Policies.Where(p => principals.All(s => p.PrincipalId != s.Principal.PrincipalId))];
        if (call.Session.Selector.Variant != "change.Remove")
            expected = [.. expected, .. principals.Select(s => new E.Policy(s.Principal.TenantId, s.Principal.PrincipalId,
                Permissions(call.Session.Selector), s.Principal.ApplicationId))];
        Require(E.SamePolicies(projected, expected));
    }

    private static E.Policy ParsePolicy(JsonElement policy, bool allowOmittedSecrets = false)
    {
        Require(Only(policy, "tenantId", "objectId", "applicationId", "permissions"));
        var tenant = policy.GetProperty("tenantId");
        var obj = policy.GetProperty("objectId");
        Require(tenant.ValueKind == JsonValueKind.String && obj.ValueKind == JsonValueKind.String);
        Require(tenant.TryGetGuid(out var tenantId) && tenantId != Guid.Empty);
        Require(obj.TryGetGuid(out var principalId) && principalId != Guid.Empty);
        var permissions = policy.GetProperty("permissions");
        Require(Only(permissions, "secrets", "keys", "certificates", "storage"));
        // The installed SDK omits its undefined empty request collection.
        // Only the already-bound empty request may normalize that shape;
        // native response proof still requires an explicit secrets array.
        bool hasSecrets = permissions.TryGetProperty("secrets", out var secrets);
        Require(hasSecrets ? secrets.ValueKind == JsonValueKind.Array && secrets.GetArrayLength() <= 8 : allowOmittedSecrets);
        Guid? applicationId = null;
        if (policy.TryGetProperty("applicationId", out var app) && app.ValueKind != JsonValueKind.Null)
        {
            Require(app.ValueKind == JsonValueKind.String);
            Require(app.TryGetGuid(out var parsed) && parsed != Guid.Empty);
            applicationId = parsed;
        }
        foreach (string other in new[] { "keys", "certificates", "storage" })
            if (permissions.TryGetProperty(other, out var values))
                Require(values.ValueKind == JsonValueKind.Array && values.GetArrayLength() == 0);
        var result = new List<SecretPermission>();
        if (hasSecrets)
            foreach (var value in secrets.EnumerateArray())
            {
                Require(value.ValueKind == JsonValueKind.String);
                Require(Enum.TryParse<SecretPermission>(value.GetString(), true, out var permission) && Enum.IsDefined(permission) &&
                    permission.ToString().Equals(value.GetString(), StringComparison.OrdinalIgnoreCase) && !result.Contains(permission));
                result.Add(permission);
            }
        return new(tenantId, principalId, result.ToArray(), applicationId);
    }

    private static void ValidateDenied(JsonElement root)
    {
        Require(Only(root, "error"));
        var error = root.GetProperty("error");
        Require(Only(error, "code", "message", "target", "details", "innererror") &&
            error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String &&
            code.GetString() is "Forbidden" or "AuthorizationFailed" or "AccessDenied");
        if (error.TryGetProperty("message", out var message))
            Require(message.ValueKind == JsonValueKind.String && message.GetString()!.Length <= 8192);
        if (error.TryGetProperty("target", out var target))
            Require(target.ValueKind == JsonValueKind.String && Text(target.GetString(), 2048));
        if (error.TryGetProperty("details", out var details))
            Require(details.ValueKind == JsonValueKind.Array && details.GetArrayLength() == 0);
        if (error.TryGetProperty("innererror", out var inner))
            Require(inner.ValueKind == JsonValueKind.Object && !inner.EnumerateObject().Any());
    }

    private long? ValidateResponseHeaders(Response response)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int total = 0;
        foreach (var header in response.Headers)
        {
            Require(names.Add(header.Name) && Text(header.Name, 128) && Text(header.Value, 16384));
            total += header.Name.Length + header.Value.Length;
            Require(total <= 32768);
        }
        Require(!new[] { "Azure-AsyncOperation", "Operation-Location", "Location", "Retry-After",
            "Content-Encoding", "Transfer-Encoding" }.Any(name => response.Headers.TryGetValue(name, out _)) &&
            response.Headers.TryGetValue("x-ms-request-id", out var requestId) && Text(requestId, 128) &&
            response.Headers.TryGetValue("Content-Type", out var type) &&
            type.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase));
        if (!response.Headers.TryGetValue("Content-Length", out var length)) return null;
        Require(long.TryParse(length, NumberStyles.None, CultureInfo.InvariantCulture, out long parsed) &&
            parsed >= 0 && parsed <= limits.MaximumReplyBytes);
        return parsed;
    }
    private static bool Only(JsonElement value, params string[] fields) => value.ValueKind == JsonValueKind.Object &&
        value.EnumerateObject().All(p => fields.Contains(p.Name, StringComparer.Ordinal));

    private sealed class RequestBuffer(int maximum) : Stream
    {
        private readonly byte[] bytes = new byte[maximum];
        private int count;
        internal ReadOnlyMemory<byte> Bytes => bytes.AsMemory(0, count);
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => count;
        public override long Position { get => count; set => throw Failure(); }
        public override void Write(byte[] buffer, int offset, int length) => Write(buffer.AsSpan(offset, length));
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Require(buffer.Length <= bytes.Length - count);
            buffer.CopyTo(bytes.AsSpan(count));
            count += buffer.Length;
        }
        public override Task WriteAsync(byte[] buffer, int offset, int length, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer, offset, length);
            return Task.CompletedTask;
        }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer.Span);
            return ValueTask.CompletedTask;
        }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw Failure();
        public override long Seek(long offset, SeekOrigin origin) => throw Failure();
        public override void SetLength(long value) => throw Failure();
        protected override void Dispose(bool disposing)
        {
            CryptographicOperations.ZeroMemory(bytes);
            base.Dispose(disposing);
        }
    }
}
