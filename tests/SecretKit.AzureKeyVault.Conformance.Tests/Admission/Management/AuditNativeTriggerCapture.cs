using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Management;
using TriggerKind = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.AuditDiagnosticsEffects.TriggerKind;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Source-owned evidence at the final native transport boundary. Host transport
// exclusivity/redirect behavior and client-header-to-audit correlation still need
// independent qualification. No response request ID is an audit CorrelationId.
internal sealed class AuditNativeTriggerCapture
{
    internal sealed record Binding(
        [property: JsonIgnore] FixtureSelector Selector,
        [property: JsonIgnore] Guid LeaseId,
        [property: JsonIgnore] VaultScope Vault,
        [property: JsonIgnore] TriggerKind Operation,
        [property: JsonIgnore] string? SecretName,
        [property: JsonIgnore] string? SecretVersion,
        [property: JsonIgnore] string ApiRevision)
    {
        public override string ToString() => "[AuditNativeTriggerBinding]";
    }

    internal sealed class Attempt
    {
        internal required Guid ClientCorrelationId { get; init; }
        internal required bool Authorized { get; init; }
        internal required TriggerKind Operation { get; init; }
        internal required string NativePath { get; init; }
        internal required RequestMethod NativeMethod { get; init; }
        // A digest of captured bytes only, not a semantic body or secret identity.
        internal string? BodySha256 { get; init; }
        internal int? HttpStatus { get; init; }
        internal string? NativeResponseRequestId { get; init; }
        internal bool ResponseObserved { get; init; }
        internal bool TransportTerminated { get; init; }
        public override string ToString() => "[AuditNativeTriggerAttempt]";
    }

    internal sealed class Capture
    {
        internal required Binding Binding { get; init; }
        internal required IReadOnlyList<Attempt> Attempts { get; init; }
        public override string ToString() => "[AuditNativeTriggerCapture]";
    }

    internal sealed class Window
    {
        internal Window(object owner, Binding binding) { Owner = owner; Binding = binding; }
        internal object Owner { get; }
        internal Binding Binding { get; }
        internal readonly List<Attempt> Attempts = [];
        internal readonly TaskCompletionSource Drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool Sealed, Active, Started, ChallengeReady;
        public override string ToString() => "[AuditNativeTriggerWindow]";
    }

    private readonly object gate = new(), owner = new();
    private readonly HashSet<Guid> nonces = [], leases = [];
    private readonly HttpPipelineTransport inner;
    private readonly int maximumRequestBytes;

    internal AuditNativeTriggerCapture(HttpPipelineTransport inner, int maximumRequestBytes = 65536)
    {
        if (inner is null || maximumRequestBytes is < 1024 or > 1024 * 1024)
            throw new ArgumentException("audit-trigger-input");
        this.inner = inner;
        this.maximumRequestBytes = maximumRequestBytes;
    }

    internal Window Arm(Binding binding)
    {
        if (binding is null || binding.Selector is null || binding.Selector.Nonce == Guid.Empty ||
            binding.LeaseId == Guid.Empty || binding.Vault is null || !Enum.IsDefined(binding.Operation) ||
            binding.ApiRevision != "2025-07-01" ||
            new[] { binding.Selector.Scope, binding.Selector.Operation, binding.Selector.Variant, binding.Selector.Case }
                .Any(s => string.IsNullOrWhiteSpace(s) || s.Length > 1024 || s.Any(char.IsControl)) ||
            (binding.Operation == TriggerKind.List
                ? binding.SecretName is not null || binding.SecretVersion is not null
                : binding.SecretName is not { Length: > 0 and <= 127 } name ||
                    !name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-')) ||
            (binding.SecretVersion is { } version && (version.Length != 32 || !version.All(char.IsAsciiHexDigit))) ||
            (binding.Operation == TriggerKind.UpdateProperties && binding.SecretVersion is null) ||
            (binding.Operation is not (TriggerKind.Get or TriggerKind.UpdateProperties) && binding.SecretVersion is not null))
            throw new ArgumentException("audit-trigger-binding");
        lock (gate)
        {
            Require(!nonces.Contains(binding.Selector.Nonce) && !leases.Contains(binding.LeaseId));
            nonces.Add(binding.Selector.Nonce);
            leases.Add(binding.LeaseId);
            return new(owner, binding);
        }
    }

    internal HttpPipelineTransport CreateTransport(Window window, FixtureSelector selection)
    {
        lock (gate)
        {
            Own(window);
            Require(!window.Sealed && window.Binding.Selector == selection);
            return new SelectedTransport(this, window);
        }
    }

    // This is an actual transport-send drain, not an SDK invocation drain or
    // remote settlement. The service must also retain and drain the actual SDK
    // invocation task before cleanup, including challenge processing and parsing.
    internal async ValueTask<Capture> SealAsync(Window window)
    {
        Task drain;
        lock (gate)
        {
            Own(window);
            window.Sealed = true;
            if (!window.Active) window.Drained.TrySetResult();
            drain = window.Drained.Task;
        }
        await drain.ConfigureAwait(false);
        lock (gate)
            return new() { Binding = window.Binding, Attempts = Array.AsReadOnly(window.Attempts.ToArray()) };
    }

    private void Own(Window window) => Require(window is not null && ReferenceEquals(window.Owner, owner));
    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("audit-trigger-boundary");
    }

    private static (string Path, RequestMethod Method) Route(Binding binding)
    {
        string secret = "/secrets/" + binding.SecretName;
        return binding.Operation switch
        {
            TriggerKind.Get => (secret + "/" + binding.SecretVersion, RequestMethod.Get),
            TriggerKind.List => ("/secrets/", RequestMethod.Get),
            TriggerKind.Set => (secret, RequestMethod.Put),
            TriggerKind.Delete => (secret, RequestMethod.Delete),
            TriggerKind.Recover => ("/deletedsecrets/" + binding.SecretName + "/recover", RequestMethod.Post),
            TriggerKind.Backup => (secret + "/backup", RequestMethod.Post),
            TriggerKind.Restore => ("/secrets/restore", RequestMethod.Post),
            TriggerKind.Purge => ("/deletedsecrets/" + binding.SecretName, RequestMethod.Delete),
            TriggerKind.UpdateProperties => (secret + "/" + binding.SecretVersion, RequestMethod.Patch),
            _ => throw new InvalidOperationException("audit-trigger-operation")
        };
    }

    private sealed class SelectedTransport(AuditNativeTriggerCapture source, Window window) : HttpPipelineTransport
    {
        public override Request CreateRequest() => source.inner.CreateRequest();
        public override void Process(HttpMessage message) => ProcessAsync(message).AsTask().GetAwaiter().GetResult();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            message.CancellationToken.ThrowIfCancellationRequested();
            lock (source.gate)
            {
                source.Own(window);
                Require(!window.Sealed && !window.Active && (!window.Started || window.ChallengeReady));
                window.Active = true;
                window.Started = true;
            }
            RequestContent? original = message.Request.Content, snapshot = null;
            byte[]? storage = null, dispatched = null;
            Guid sentCorrelation = Guid.Empty;
            bool authorized = false, responseObserved = false;
            string? digest = null, requestId = null, nativePath = null;
            RequestMethod nativeMethod = default;
            int? status = null;
            bool challenge = false;
            try
            {
                Binding binding = window.Binding;
                var (path, method) = Route(binding);
                Uri uri = message.Request.Uri.ToUri();
                string origin = "https://" + binding.Vault.VaultName.ToLowerInvariant() + ".vault.azure.net";
                Require(uri.IsAbsoluteUri && uri.Scheme == "https" && uri.IsDefaultPort &&
                    uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
                    uri.GetLeftPart(UriPartial.Authority) == origin &&
                    uri.AbsolutePath == path && uri.Query == "?api-version=" + binding.ApiRevision &&
                    message.Request.Method == method);
                authorized = message.Request.Headers.Contains("Authorization");
                lock (source.gate)
                {
                    Require(!window.Sealed && (window.Attempts.Count == 0 || window.ChallengeReady && authorized));
                    window.ChallengeReady = false;
                }
                // The native challenge policy can suppress the initial body.
                // Only the authenticated operation requires its concrete body.
                bool bodyRequired = binding.Operation is TriggerKind.Set or TriggerKind.Restore or TriggerKind.UpdateProperties;
                Require(!authorized || !bodyRequired || original is not null);
                Require(bodyRequired || original is null);
                int length = 0;
                if (original is not null)
                {
                    storage = new byte[source.maximumRequestBytes];
                    using var output = new MemoryStream(storage, 0, storage.Length, writable: true, publiclyVisible: true);
                    await original.WriteToAsync(output, message.CancellationToken).ConfigureAwait(false);
                    length = checked((int)output.Position);
                    // The borrowed writer may retain the staging stream buffer.
                    // Dispatch and hash only an independently owned byte copy.
                    dispatched = storage.AsSpan(0, length).ToArray();
                    snapshot = RequestContent.Create(dispatched);
                    message.Request.Content = snapshot;
                }
                message.CancellationToken.ThrowIfCancellationRequested();
                ValueTask send;
                lock (source.gate)
                {
                    Require(!window.Sealed);
                    // A stateful borrowed content writer must not change the
                    // coordinates between validation and actual dispatch.
                    Require(message.Request.Uri.ToUri().AbsoluteUri == uri.AbsoluteUri &&
                        message.Request.Method == method && ReferenceEquals(message.Request.Content, snapshot) &&
                        message.Request.Headers.Contains("Authorization") == authorized);
                    digest = dispatched is null ? null : Convert.ToHexString(SHA256.HashData(dispatched));
                    nativePath = uri.AbsolutePath;
                    nativeMethod = message.Request.Method;
                    Guid correlation = Guid.NewGuid();
                    message.Request.Headers.SetValue("x-ms-client-request-id", correlation.ToString("D"));
                    sentCorrelation = correlation;
                    // Admission and entry into the borrowed transport are one
                    // transition with respect to SealAsync.
                    send = source.inner.ProcessAsync(message);
                }
                await send.ConfigureAwait(false);
                status = message.Response.Status;
                responseObserved = true;
                if (message.Response.Headers.TryGetValues("x-ms-request-id", out var ids))
                {
                    string[] values = ids.ToArray();
                    Require(values.Length == 1 && values[0].Length is > 0 and <= 256 &&
                        values[0].All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.'));
                    requestId = values[0];
                }
                // Only recognize the transition. Parsing and validating the
                // challenge authority/resource remains the native SDK's job.
                challenge = !authorized && window.Attempts.Count == 0 && status == 401 &&
                    message.Response.Headers.TryGetValue("WWW-Authenticate", out _);
            }
            catch (OperationCanceledException)
            {
                throw new OperationCanceledException(message.CancellationToken);
            }
            catch (Exception)
            {
                // Preserve uncertain dispatched evidence, never raw provider,
                // content, credential or coordinate-bearing exception text.
                if (sentCorrelation != Guid.Empty) throw new IOException("audit-trigger-transport");
                throw new InvalidOperationException("audit-trigger-boundary");
            }
            finally
            {
                message.Request.Content = original;
                snapshot?.Dispose();
                if (dispatched is not null) CryptographicOperations.ZeroMemory(dispatched);
                if (storage is not null) CryptographicOperations.ZeroMemory(storage);
                lock (source.gate)
                {
                    if (sentCorrelation != Guid.Empty)
                        window.Attempts.Add(new()
                        {
                            ClientCorrelationId = sentCorrelation,
                            Authorized = authorized,
                            Operation = window.Binding.Operation,
                            NativePath = nativePath!,
                            NativeMethod = nativeMethod,
                            BodySha256 = digest,
                            HttpStatus = status,
                            NativeResponseRequestId = requestId,
                            ResponseObserved = responseObserved,
                            TransportTerminated = true
                        });
                    window.ChallengeReady = challenge;
                    window.Active = false;
                    if (window.Sealed) window.Drained.TrySetResult();
                }
            }
        }
        public override string ToString() => "[AuditNativeTriggerTransport]";
    }

    public override string ToString() => "[AuditNativeTriggerSource]";
}
