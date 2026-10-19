using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Provenance of ONE original runtime write, not notification emission, delivery,
// filter exclusion, a remote watermark, or credential/principal qualification.
// The host owns credentials, transports and journal. No remote cleanup occurs.
internal sealed class NotificationRuntimeTriggerCapture :
    NotificationAdministrationEffects.RuntimeInvocation, IAsyncDisposable
{
    internal sealed record Authority([property: JsonIgnore] TokenCredential Credential,
        [property: JsonIgnore] HttpPipelineTransport Transport)
    {
        public override string ToString() => "[NotificationRuntimeAuthority]";
    }

    internal sealed record Limits(int MaximumRequestBytes, int MaximumResponseBytes, int MaximumHeaderBytes,
        int MaximumNodes, int MaximumDepth, TimeSpan Timeout);

    internal sealed record Binding([property: JsonIgnore] FixtureSelector Selector, Guid LeaseId, Guid ObservationId,
        [property: JsonIgnore] Guid AzureSubscriptionId, [property: JsonIgnore] string ResourceGroup,
        [property: JsonIgnore] string VaultName, [property: JsonIgnore] string RuntimeSecretName,
        [property: JsonIgnore] string PreparedVersion)
    {
        public override string ToString() => "[NotificationRuntimeBinding]";
    }

    internal sealed class Window
    {
        internal Guid Id { get; } = Guid.NewGuid();
        public override string ToString() => "[NotificationRuntimeWindow]";
    }

    internal sealed class Measurement
    {
        private Measurement(Call call)
        {
            Binding = call.Binding;
            WindowId = call.Window.Id;
            StartedAt = call.StartedAt;
            FinishedAt = call.FinishedAt;
            Version = call.Version;
            NativeRequestId = call.NativeRequestId;
            MaterialSha256 = call.MaterialSha256;
            Status = call.Status;
            TaskDrained = call.OriginalTask is { IsCompleted: true };
            NativeAcknowledged = call.NativeProof;
            NativeSettled = TaskDrained && (call.NativeProof || call.NativeRejected) && call.Sends == 1 &&
                call.SendTask is { IsCompleted: true };
        }

        // Private issuance reads only the source's registered, drained call.
        // Even a caller of this factory cannot supply measurement fields.
        internal static Measurement Issue(NotificationRuntimeTriggerCapture source, Window window)
        {
            lock (source.gate)
            {
                var call = source.Registered(window);
                Require(call.Finished && source.active == 0 && call.OriginalTask is { IsCompleted: true } &&
                    call.FinishedAt >= call.StartedAt);
                return call.Measurement ??= new(call);
            }
        }

        [JsonIgnore] internal Binding Binding { get; }
        internal Guid WindowId { get; }
        internal DateTimeOffset StartedAt { get; }
        internal DateTimeOffset FinishedAt { get; }
        [JsonIgnore] internal string? Version { get; }
        [JsonIgnore] internal string? NativeRequestId { get; }
        [JsonIgnore] internal string MaterialSha256 { get; }
        internal SecretStatus? Status { get; }
        internal bool TaskDrained { get; }
        internal bool NativeAcknowledged { get; }
        internal bool NativeSettled { get; }
        internal bool EmissionEstablished => false;
        public override string ToString() => "[NotificationRuntimeMeasurement]";
    }

    private sealed class Call(Binding binding, Window window, byte[] expected, byte[] body,
        DateTimeOffset armedAt, long timestamp)
    {
        internal readonly Binding Binding = binding;
        internal readonly Window Window = window;
        internal readonly byte[] Expected = expected, Body = body;
        internal readonly string MaterialSha256 = Convert.ToHexString(SHA256.HashData(expected));
        internal readonly DateTimeOffset ArmedAt = armedAt;
        internal readonly long Timestamp = timestamp;
        internal readonly List<byte[]> Buffers = [];
        internal readonly List<IDisposable> Storage = [];
        internal AzureKeyVaultClient? Client;
        internal AzureSetSecretRequest? Request;
        internal MutationReceipt? Receipt;
        internal Task<SecretOutcome<AzureSetSecretResult>>? OriginalTask;
        internal Task? SendTask;
        internal Guid Dispatch;
        internal int Sends;
        internal bool Claimed, Started, Finished, NativeProof, NativeRejected, PreDispatchRejected, EnteredTransport;
        internal DateTimeOffset StartedAt, FinishedAt;
        internal SecretStatus? Status;
        internal string? Version, NativeRequestId;
        internal Measurement? Measurement;

        internal void Clear()
        {
            bool failed = false;
            // A throwing response/content disposer must not strand other
            // storage, protected bytes, or either lifetime drain.
            foreach (var item in Storage)
            {
                try { item.Dispose(); }
                catch (Exception) { failed = true; }
            }
            Storage.Clear();
            CryptographicOperations.ZeroMemory(Expected);
            CryptographicOperations.ZeroMemory(Body);
            foreach (var bytes in Buffers) CryptographicOperations.ZeroMemory(bytes);
            Buffers.Clear();
            Client = null;
            Request = null;
            Receipt = null;
            if (failed) throw Failure();
        }
    }

    private readonly object gate = new();
    private readonly RoleFixtureJournal journal;
    private readonly string owner;
    private readonly Authority runtime;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly AsyncLocal<Call?> current = new();
    private readonly CancellationTokenSource lifetime = new();
    private readonly TaskCompletionSource drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Call? registered;
    private bool disposed, armClaimed;
    private int active;
    private TaskCompletionSource? disposal;

    internal NotificationRuntimeTriggerCapture(RoleFixtureJournal journal, string owner, Authority runtime,
        Limits limits, TimeProvider? time = null)
    {
        Require(journal is not null && Text(owner, 128) && runtime is not null &&
            runtime.Credential is not null && runtime.Transport is not null && limits is not null &&
            limits.MaximumRequestBytes is >= 128 and <= 1024 * 1024 &&
            limits.MaximumResponseBytes is >= 128 and <= 1024 * 1024 &&
            limits.MaximumHeaderBytes is >= 128 and <= 65536 &&
            limits.MaximumNodes is >= 4 and <= 65536 && limits.MaximumDepth is >= 2 and <= 32 &&
            limits.Timeout > TimeSpan.Zero && limits.Timeout <= TimeSpan.FromMinutes(2));
        this.journal = journal;
        this.owner = owner;
        this.runtime = runtime;
        this.limits = limits;
        this.time = time ?? TimeProvider.System;
        RuntimeTransport = new OriginalTransport(this);
    }

    internal HttpPipelineTransport RuntimeTransport { get; }

    internal Window Arm(Binding binding, SecretMaterial expectedValue)
    {
        ValidateBinding(binding);
        Require(expectedValue is not null);
        lock (gate)
        {
            Require(!disposed && !armClaimed);
            armClaimed = true;
            active++;
        }
        byte[]? expected = null, body = null;
        bool published = false;
        try
        {
            RequirePrepared(binding);
            expected = Export(expectedValue);
            Require(expected.Length <= 25 * 1024);
            using (var buffer = new RequestBuffer(limits.MaximumRequestBytes))
            {
                using (var writer = new Utf8JsonWriter(buffer))
                {
                    writer.WriteStartObject();
                    writer.WriteString("value", expected.AsSpan());
                    writer.WriteEndObject();
                }
                body = buffer.Bytes.ToArray();
            }
            // Clock providers are host callbacks. They may close/dispose the
            // source or root; recheck after every callback before publishing.
            DateTimeOffset armedAt = time.GetUtcNow();
            long timestamp = time.GetTimestamp();
            lock (gate)
            {
                Require(!disposed);
                RequirePrepared(binding);
                var window = new Window();
                registered = new(binding with { Selector = binding.Selector with { } }, window,
                    expected, body, armedAt, timestamp);
                published = true;
                return window;
            }
        }
        finally
        {
            if (!published)
            {
                if (expected is not null) CryptographicOperations.ZeroMemory(expected);
                if (body is not null) CryptographicOperations.ZeroMemory(body);
            }
            Leave();
        }
    }

    public async ValueTask<SecretOutcome<AzureSetSecretResult>> RunSetAsync(FixtureSelector selector,
        AzureKeyVaultClient client, AzureSetSecretRequest request, MutationReceipt receipt,
        CancellationToken cancellationToken)
    {
        Require(client is not null && request is not null && receipt is not null);
        Call call;
        lock (gate)
        {
            call = registered ?? throw Failure();
            Require(!disposed && call.Binding.Selector == selector && !call.Claimed && active == 0);
            Require(request.Target.BelongsTo(client.Authority) &&
                request.Target.Address is AzureSecretAddress address &&
                address.Name == call.Binding.RuntimeSecretName && address.Version is null &&
                request.Precondition == AzureSetSecretPrecondition.None);
            call.Claimed = true;
            call.Client = client;
            call.Request = request;
            call.Receipt = receipt;
            // Reserve before time, credential, request or SDK callbacks.
            active++;
        }
        CancellationTokenSource? deadline = null, linked = null;
        var previous = current.Value;
        try
        {
            byte[] supplied = Export(request.Material);
            try { Require(CryptographicOperations.FixedTimeEquals(supplied, call.Expected)); }
            finally { CryptographicOperations.ZeroMemory(supplied); }
            call.StartedAt = Check(call);
            deadline = new(limits.Timeout, time);
            linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token, lifetime.Token);
            current.Value = call;
            lock (gate)
            {
                Require(!disposed);
                linked.Token.ThrowIfCancellationRequested();
                RequirePrepared(call.Binding);
                call.Dispatch = journal.BeginSelectedUpdate(owner, selector, SecretResource(call.Binding));
                call.Started = true;
                // This is the original client, request reference and receipt.
                // No replacement client, substitute Set, or caller task exists.
                call.OriginalTask = client.SetSecretAsync(request, receipt, linked.Token).AsTask();
            }
            var result = await call.OriginalTask.ConfigureAwait(false);
            call.Status = result.Status;
            call.PreDispatchRejected = result.Status == SecretStatus.Invalid &&
                receipt.Evidence == DispatchEvidence.NotDispatched && call.Sends == 0 && !call.EnteredTransport;
            return result;
        }
        finally
        {
            current.Value = previous;
            try
            {
                // Only the real task ending can retire its journal fence. A
                // callback exception without positive Invalid evidence cannot.
                bool taskDrained = call.OriginalTask is { IsCompleted: true };
                if (call.Dispatch != Guid.Empty)
                    journal.EndDispatch(owner, selector, SecretResource(call.Binding), call.Dispatch,
                        taskDrained && (call.PreDispatchRejected ||
                            (call.NativeProof || call.NativeRejected) && call.Sends == 1 &&
                            call.SendTask is { IsCompleted: true }));
                call.FinishedAt = time.GetUtcNow();
            }
            finally
            {
                try { call.Clear(); }
                finally
                {
                    try { linked?.Dispose(); }
                    finally
                    {
                        try { deadline?.Dispose(); }
                        finally { lock (gate) { call.Finished = true; } Leave(); }
                    }
                }
            }
        }
    }

    internal Measurement Read(Window window, Binding binding)
    {
        lock (gate) { Require(Registered(window).Binding == binding); }
        return Measurement.Issue(this, window);
    }

    internal void ValidateMeasurement(RoleFixtureJournal journal, string owner, Window window, Binding binding,
        Measurement measurement)
    {
        lock (gate)
        {
            var call = Registered(window);
            Require(ReferenceEquals(this.journal, journal) && this.owner == owner &&
                binding == call.Binding && call.Finished && active == 0 &&
                call.OriginalTask is { IsCompleted: true } && measurement is not null &&
                ReferenceEquals(call.Measurement, measurement) && measurement.Binding == binding &&
                measurement.WindowId == window.Id && measurement.TaskDrained && !measurement.EmissionEstablished);
        }
    }

    private Call Registered(Window window)
    {
        Require(window is not null && registered is not null && ReferenceEquals(registered.Window, window));
        return registered;
    }

    private sealed class OriginalTransport(NotificationRuntimeTriggerCapture source) : HttpPipelineTransport
    {
        private Call Current()
        {
            var call = source.current.Value ?? throw Failure();
            lock (source.gate)
            {
                Require(!source.disposed && ReferenceEquals(source.registered, call) &&
                    call.Started && !call.Finished);
                return call;
            }
        }
        public override Request CreateRequest()
        {
            var call = Current();
            call.EnteredTransport = true;
            return source.runtime.Transport.CreateRequest();
        }
        public override void Process(HttpMessage message) => throw Failure();
        public override ValueTask ProcessAsync(HttpMessage message) => source.Send(Current(), message);
        public override string ToString() => "[NotificationOriginalRuntimeTransport]";
    }

    private async ValueTask Send(Call call, HttpMessage message)
    {
        Check(call);
        ValidateRequest(call, message);
        Require(call.Sends == 0 && call.SendTask is null);
        if (message.Request.Content is { } original)
        {
            using var body = new RequestBuffer(limits.MaximumRequestBytes);
            Require(original.TryComputeLength(out long length) && length > 0 && length <= limits.MaximumRequestBytes);
            await original.WriteToAsync(body, message.CancellationToken).ConfigureAwait(false);
            Require(body.Length == length);
            using var document = Parse(body.Bytes);
            var root = document.RootElement;
            Require(root.ValueKind == JsonValueKind.Object &&
                root.EnumerateObject().All(p => p.Name is "value" or "attributes"));
            Require(root.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.String);
            MatchMaterial(value, call);
            if (root.TryGetProperty("attributes", out var attributes))
                Require(attributes.ValueKind == JsonValueKind.Object && !attributes.EnumerateObject().Any());
        }
        // Cold SDK challenge processing can strip content. The exact original
        // typed request was checked above, so reconstruct ONLY its owned value.
        // Never touch SDK challenge caches or use challenge/discovery sends.
        var token = await runtime.Credential.GetTokenAsync(
            new TokenRequestContext(["https://vault.azure.net/.default"]), message.CancellationToken).ConfigureAwait(false);
        DateTimeOffset now = Check(call);
        message.CancellationToken.ThrowIfCancellationRequested();
        Require(Text(token.Token, 16384) && token.ExpiresOn > now);
        ValidateRequest(call, message);
        // Credential callbacks can mutate SDK content. Dispatch the frozen
        // source bytes AFTER credential acquisition, never that mutable body.
        var content = RequestContent.Create(call.Body.AsMemory());
        call.Storage.Add(content);
        message.Request.Content = content;
        foreach (var header in message.Request.Headers.ToArray()) message.Request.Headers.Remove(header.Name);
        message.Request.Headers.SetValue("Authorization", "Bearer " + token.Token);
        message.Request.Headers.SetValue("Content-Type", "application/json");
        message.Request.Headers.SetValue("Content-Length", call.Body.Length.ToString(CultureInfo.InvariantCulture));
        ValidateRequest(call, message);
        var headers = message.Request.Headers.Select(h => (h.Name, h.Value)).ToArray();
        try
        {
            lock (gate)
            {
                Require(!disposed && call.Started && !call.Finished && call.Sends == 0);
                message.CancellationToken.ThrowIfCancellationRequested();
                RequireDispatch(call);
                // The SDK's cold bodyless request has not marked its receipt.
                // Mark the SAME receipt at this actual authorized boundary.
                if (call.Receipt!.Evidence == DispatchEvidence.NotDispatched)
                    call.Receipt.BeginDispatch(call.Request!.Target);
                Require(call.Receipt.Evidence == DispatchEvidence.PossiblyDispatched);
                message.BufferResponse = false;
                call.Sends++;
                call.SendTask = runtime.Transport.ProcessAsync(message).AsTask();
            }
            await call.SendTask.ConfigureAwait(false);
        }
        finally
        {
            if (message.HasResponse) call.Storage.Add(message.Response);
        }
        ValidateRequest(call, message);
        Require(ReferenceEquals(message.Request.Content, content) &&
            headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))) && message.HasResponse);
        var response = message.Response;
        Require(response.Status is 200 or 403);
        long? declared = ResponseHeaders(response, out string requestId);
        byte[] bytes = new byte[limits.MaximumResponseBytes + 1];
        call.Buffers.Add(bytes);
        Stream input = response.ContentStream ?? throw Failure();
        call.Storage.Add(input);
        int count = 0;
        while (true)
        {
            message.CancellationToken.ThrowIfCancellationRequested();
            int read = await input.ReadAsync(bytes.AsMemory(count), message.CancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            count += read;
            Require(count <= limits.MaximumResponseBytes);
        }
        Require(count > 0 && (declared is null || declared == count));
        using (var document = Parse(bytes.AsMemory(0, count)))
        {
            var root = document.RootElement;
            if (response.Status == 403) ValidateDenied(root);
            else
            {
                Require(root.ValueKind == JsonValueKind.Object &&
                    root.EnumerateObject().All(p => p.Name is "id" or "value" or "attributes" or "tags" or
                        "contentType" or "kid" or "managed"));
                Require(root.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String);
                Require(root.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.String);
                string target = id.GetString()!;
                string prefix = Origin(call.Binding) + "/secrets/" + call.Binding.RuntimeSecretName + "/";
                Require(target.StartsWith(prefix, StringComparison.Ordinal));
                string version = target[prefix.Length..];
                Require(Version(version) && version != call.Binding.PreparedVersion);
                MatchMaterial(value, call);
                if (root.TryGetProperty("attributes", out var attributes))
                {
                    Require(attributes.ValueKind == JsonValueKind.Object);
                    if (attributes.TryGetProperty("enabled", out var enabled)) Require(enabled.ValueKind == JsonValueKind.True);
                }
                call.Version = version;
            }
        }
        // Keep exact-length, offset-zero storage until the original SDK parser
        // and every wrapper finishes. Do not confuse this raw proof with that drain.
        var buffered = new MemoryStream(bytes, 0, count, writable: false, publiclyVisible: true);
        call.Storage.Add(buffered);
        response.ContentStream = buffered;
        Check(call);
        call.NativeRequestId = requestId;
        call.NativeProof = response.Status == 200;
        call.NativeRejected = response.Status == 403;
    }

    private static void ValidateDenied(JsonElement root)
    {
        Require(root.ValueKind == JsonValueKind.Object && root.EnumerateObject().All(p => p.Name == "error"));
        Require(root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object);
        Require(error.EnumerateObject().All(p => p.Name is "code" or "message" or "target" or "details" or "innererror") &&
            error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String &&
            code.GetString() is "Forbidden" or "AccessDenied" or "AuthorizationFailed");
        if (error.TryGetProperty("message", out var message))
            Require(message.ValueKind == JsonValueKind.String && message.GetString()!.Length <= 8192);
        if (error.TryGetProperty("target", out var target))
            Require(target.ValueKind == JsonValueKind.String && Text(target.GetString(), 2048));
        if (error.TryGetProperty("details", out var details))
            Require(details.ValueKind == JsonValueKind.Array && details.GetArrayLength() == 0);
        if (error.TryGetProperty("innererror", out var inner))
        {
            Require(inner.ValueKind == JsonValueKind.Object && inner.EnumerateObject().All(p => p.Name == "code"));
            Require(inner.TryGetProperty("code", out var innerCode) && innerCode.ValueKind == JsonValueKind.String &&
                innerCode.GetString() is "ForbiddenByRbac" or "AccessDenied" or "ForbiddenByPolicy");
        }
    }

    private DateTimeOffset Check(Call call)
    {
        DateTimeOffset now = time.GetUtcNow();
        TimeSpan elapsed = time.GetElapsedTime(call.Timestamp, time.GetTimestamp());
        Require(now >= call.ArmedAt && now - call.ArmedAt <= limits.Timeout &&
            elapsed >= TimeSpan.Zero && elapsed <= limits.Timeout);
        lock (gate)
        {
            Require(!disposed && !call.Finished && ReferenceEquals(registered, call));
            if (call.Dispatch != Guid.Empty) RequireDispatch(call);
            else RequirePrepared(call.Binding);
        }
        return now;
    }

    private void RequirePrepared(Binding binding)
    {
        var state = journal.Read(owner, binding.Selector);
        Require(state.Owner == owner && state.Selector == binding.Selector && state.LeaseId == binding.LeaseId &&
            !state.Closing && state.Resources.All(r => r.ActiveDispatch == Guid.Empty) &&
            !state.Resources.Any(r => !r.Borrowed && r.CreateAttempted &&
                r.Id.Contains("/deletedVaults/", StringComparison.OrdinalIgnoreCase)));
        foreach (string id in new[] { VaultResource(binding), SecretResource(binding) })
        {
            var row = state.Resources.Single(r => r.Id == id);
            Require(!row.Borrowed && !row.CleanupOnly && row.CreateAttempted &&
                !row.DeleteAttempted && !row.Absent && !row.SelectedAttempted);
        }
    }

    private void RequireDispatch(Call call)
    {
        var state = journal.Read(owner, call.Binding.Selector);
        Require(!state.Closing && state.Owner == owner && state.Selector == call.Binding.Selector &&
            state.LeaseId == call.Binding.LeaseId &&
            state.Resources.Single(r => r.Id == SecretResource(call.Binding)).ActiveDispatch == call.Dispatch &&
            state.Resources.Where(r => r.Id != SecretResource(call.Binding)).All(r => r.ActiveDispatch == Guid.Empty));
    }

    private void ValidateRequest(Call call, HttpMessage message)
    {
        Require(message.Request.Method == RequestMethod.Put &&
            message.Request.Uri.ToUri().AbsoluteUri == Origin(call.Binding) +
                "/secrets/" + call.Binding.RuntimeSecretName + "?api-version=2025-07-01");
        Headers(message.Request.Headers.Select(h => (h.Name, h.Value)));
        Require(!message.Request.Headers.Contains("Content-Encoding") &&
            !message.Request.Headers.Contains("Transfer-Encoding"));
    }

    private long? ResponseHeaders(Response response, out string requestId)
    {
        Headers(response.Headers.Select(h => (h.Name, h.Value)));
        Require(!new[] { "Location", "Operation-Location", "Azure-AsyncOperation", "Retry-After",
            "Content-Encoding", "Transfer-Encoding", "WWW-Authenticate" }.Any(h => response.Headers.TryGetValue(h, out _)));
        Require(response.Headers.TryGetValue("x-ms-request-id", out var id) && Text(id, 128));
        Require(response.Headers.TryGetValue("Content-Type", out var type) &&
            type.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase));
        requestId = id;
        if (!response.Headers.TryGetValue("Content-Length", out var length)) return null;
        Require(long.TryParse(length, NumberStyles.None, CultureInfo.InvariantCulture, out long parsed) &&
            parsed > 0 && parsed <= limits.MaximumResponseBytes);
        return parsed;
    }

    private void Headers(IEnumerable<(string Name, string Value)> headers)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int total = 0;
        foreach (var (name, value) in headers)
        {
            Require(Text(name, 128) && Text(value, limits.MaximumHeaderBytes) && names.Add(name));
            total += name.Length + value.Length;
            Require(total <= limits.MaximumHeaderBytes);
        }
    }

    private JsonDocument Parse(ReadOnlyMemory<byte> bytes)
    {
        var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = limits.MaximumDepth });
        try
        {
            int nodes = 0;
            Visit(document.RootElement);
            return document;
            void Visit(JsonElement element)
            {
                Require(++nodes <= limits.MaximumNodes);
                if (element.ValueKind == JsonValueKind.Object)
                {
                    var names = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var property in element.EnumerateObject())
                    {
                        Require(names.Add(property.Name));
                        Visit(property.Value);
                    }
                }
                else if (element.ValueKind == JsonValueKind.Array)
                    foreach (var child in element.EnumerateArray()) Visit(child);
            }
        }
        catch { document.Dispose(); throw; }
    }

    private static void MatchMaterial(JsonElement value, Call call)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value.GetString()!);
        try { Require(CryptographicOperations.FixedTimeEquals(bytes, call.Expected)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private byte[] Export(SecretMaterial material)
    {
        char[] characters = material.ExportCharacters();
        try
        {
            var encoding = new UTF8Encoding(false, true);
            Require(encoding.GetByteCount(characters) <= limits.MaximumRequestBytes);
            return encoding.GetBytes(characters);
        }
        finally { Array.Clear(characters); }
    }

    private static void ValidateBinding(Binding b)
    {
        Require(b is not null && b.Selector is not null && b.Selector.Nonce != Guid.Empty &&
            new[] { b.Selector.Scope, b.Selector.Operation, b.Selector.Variant, b.Selector.Case }.All(s => Text(s, 1024)) &&
            NotificationAdministrationEffects.Members.Any(m => m.Operation == b.Selector.Operation &&
                m.Variants.Contains(b.Selector.Variant, StringComparer.Ordinal)) &&
            b.LeaseId != Guid.Empty && b.ObservationId != Guid.Empty && b.AzureSubscriptionId != Guid.Empty &&
            Segment(b.ResourceGroup, 90) && b.VaultName is { Length: >= 3 and <= 24 } &&
            char.IsAsciiLetter(b.VaultName[0]) && char.IsAsciiLetterOrDigit(b.VaultName[^1]) &&
            b.VaultName.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') &&
            !b.VaultName.Contains("--", StringComparison.Ordinal) &&
            Segment(b.RuntimeSecretName, 127) && b.RuntimeSecretName.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') &&
            Version(b.PreparedVersion));
    }

    private static string Origin(Binding b) => "https://" + b.VaultName + ".vault.azure.net";
    private static string VaultResource(Binding b) =>
        $"/subscriptions/{b.AzureSubscriptionId:D}/resourceGroups/{b.ResourceGroup}/providers/Microsoft.KeyVault/vaults/{b.VaultName}";
    private static string SecretResource(Binding b) => VaultResource(b) + "/secrets/" + b.RuntimeSecretName;
    private static bool Segment(string? value, int maximum) => Text(value, maximum) &&
        value!.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');
    private static bool Version(string? value) => value is { Length: 32 } && value.All(char.IsAsciiHexDigit);
    private static bool Text(string? value, int maximum) =>
        value is { Length: > 0 } && value.Length <= maximum && !value.Any(char.IsControl);
    private static InvalidOperationException Failure() => new("notification-runtime-capture");
    private static void Require([DoesNotReturnIf(false)] bool condition)
    {
        if (!condition) throw Failure();
    }

    private void Leave()
    {
        lock (gate)
        {
            active--;
            if (disposed && active == 0) drained.TrySetResult();
        }
    }

    public ValueTask DisposeAsync()
    {
        TaskCompletionSource completion;
        lock (gate)
        {
            if (disposal is not null) return new(disposal.Task);
            disposed = true;
            completion = disposal = new(TaskCreationOptions.RunContinuationsAsynchronously);
            if (active == 0) drained.TrySetResult();
        }
        _ = DisposeCore(completion);
        return new(completion.Task);
    }

    private async Task DisposeCore(TaskCompletionSource completion)
    {
        bool failed = false;
        try { await lifetime.CancelAsync().ConfigureAwait(false); }
        catch (Exception) { failed = true; }
        await drained.Task.ConfigureAwait(false);
        try { registered?.Clear(); }
        catch (Exception) { failed = true; }
        finally { lifetime.Dispose(); }
        if (failed) completion.TrySetException(Failure());
        else completion.TrySetResult();
    }

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
