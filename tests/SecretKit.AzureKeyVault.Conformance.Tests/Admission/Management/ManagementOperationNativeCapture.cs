using System.ClientModel.Primitives;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager.EventGrid;
using Azure.ResourceManager.EventGrid.Models;
using Azure.ResourceManager.KeyVault;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// In-process provenance only. Neither a response coordinate nor a completed SDK
// wrapper grants cleanup authority, remote settlement, principal or egress proof.
internal sealed class ManagementOperationNativeCapture
{
    internal enum WireState { Unavailable, Pending, Succeeded, Failed, Canceled, Denied, Unknown, Lost }

    internal sealed class StatusDeniedVaultRecoverStartProof(Binding binding, StatusTarget target,
        int responseBytes, string requestSha256, string nativeRequestId, Task startTask, VaultConfiguration configuration)
    {
        internal Binding Binding { get; } = binding;
        internal StatusTarget Target { get; } = target;
        internal Guid StartDispatch => Target.StartDispatch;
        internal int HttpStatus => 201;
        internal int ResponseBytes { get; } = responseBytes;
        internal VaultConfiguration Configuration { get; } = configuration;
        internal string ResponseSha256 => Target.StartResponseSha256;
        internal string RequestSha256 { get; } = requestSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal Task StartTask { get; } = startTask;
        internal Task ActualTask => StartTask;
        internal SecretStatus Outcome => SecretStatus.Success;
        internal NativeProvisioningState State => NativeProvisioningState.Pending;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusDeniedVaultRecoverStartProof]";
    }

    internal sealed class StatusDeniedVaultRecoverDeniedProof(StatusDeniedVaultRecoverStartProof start, Task checkTask,
        int httpStatus, int responseBytes, string requestSha256, string responseSha256, string nativeRequestId)
    {
        internal StatusDeniedVaultRecoverStartProof Start { get; } = start;
        internal Task CheckTask { get; } = checkTask;
        internal Task ActualTask => CheckTask;
        internal Binding Binding => Start.Binding;
        internal StatusTarget Target => Start.Target;
        internal Guid StartDispatch => Start.StartDispatch;
        internal int ResponseBytes { get; } = responseBytes;
        internal string RequestSha256 { get; } = requestSha256;
        internal int HttpStatus { get; } = httpStatus;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Denied;
        internal NativeProvisioningState State => NativeProvisioningState.Failed;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusDeniedVaultRecoverDeniedProof]";
    }

    private sealed class StatusDeniedVaultRecoverSlot(CancellationToken token, CancellationToken caller)
    {
        internal readonly CancellationToken Token = token;
        internal readonly CancellationToken Caller = caller;
        internal readonly Invocation Invocation = new();
        internal readonly TaskCompletionSource Drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly HashSet<Request> Requests = new(ReferenceEqualityComparer.Instance);
        internal readonly List<Task> Sends = [];
        internal readonly List<StatusPendingPurgeResponse> Responses = [];
        internal Task? NativeTask;
        internal string? RequestSha256;
        internal Action? ValidateCustody;
        internal int Factories, SendCount;
        internal bool FactoryActive, Sending, HookReturned, Success, Finished;
    }

    private sealed class StatusDeniedVaultRecoverRegistration(Window window)
    {
        internal readonly Window Window = window;
        internal readonly List<OwnedArmResponse.Storage> Storage = [];
        internal readonly List<StatusPendingPurgeResponse> Responses = [];
        internal readonly ManagementScope InitialScope = window.Binding.Resource;
        internal readonly FixtureSelector BindingSelector = window.Binding.Selector;
        internal VaultConfiguration? Configuration;
        internal bool DisposalComplete, DisposalFailed;
        internal Action? BeforeSend;
        internal VaultAdministration? Client;
        internal VaultScope? Scope;
        internal ManagementReceipt? Receipt;
        internal ManagementOperation? Handle;
        internal StatusDeniedVaultRecoverSlot? Start, Selected;
        internal StatusPendingPurgeStartFacts? Candidate;
        internal StatusDeniedVaultRecoverStartProof? StartProof;
        internal StatusDeniedVaultRecoverDeniedProof? DeniedProof;
        internal string? AuthorizationSha256;
        internal Task<Capture>? SealTask;
        internal bool Invalid, Revoked, Sealed, AdmissionClosed;
    }

    private sealed record StatusDeniedVaultRecoverContext(StatusDeniedVaultRecoverRegistration Registration,
        StatusDeniedVaultRecoverSlot Slot, bool Start);
    private readonly AsyncLocal<StatusDeniedVaultRecoverContext?> currentStatusDeniedVaultRecover = new();
    private readonly Dictionary<Window, StatusDeniedVaultRecoverRegistration> statusDeniedVaultRecovers =
        new(ReferenceEqualityComparer.Instance);

    private static bool StatusDeniedVaultRecoverSelector(FixtureSelector selector) =>
        selector is { Operation: "a.management.ManagementOperation.CheckStatusAsync",
            Variant: "operation.RecoverVault", Case: "denied-authority" };

    internal Window ArmStatusDeniedVaultRecover(Binding binding)
    {
        Require(binding is not null && StatusDeniedVaultRecoverSelector(binding.Selector) &&
            binding.Operation == ManagementMutation.RecoverVault &&
            binding.Resource is VaultScope && binding.ApiRevision == "2026-02-01");
        var window = Arm(binding);
        lock (gate) statusDeniedVaultRecovers.Add(window, new(window));
        return window;
    }

    private StatusDeniedVaultRecoverRegistration RequireStatusDeniedVaultRecover(Window window, FixtureSelector selector)
    {
        Own(window, selector);
        Require(ReferenceEquals(window.Binding.Selector, selector) && StatusDeniedVaultRecoverSelector(selector));
        Require(statusDeniedVaultRecovers.TryGetValue(window, out var r) && ReferenceEquals(r.Window, window));
        return r;
    }

    private bool StatusDeniedVaultRecoverTargetValid(StatusDeniedVaultRecoverRegistration r, Binding binding) =>
        ReferenceEquals(r.Window.Binding, binding) && ReferenceEquals(binding.Resource, r.Scope) &&
        StatusDeniedVaultRecoverLive(r) && !r.AdmissionClosed &&
        r.Start is { Finished: true, HookReturned: true, Success: true } &&
        r.Start.Drained.Task.IsCompletedSuccessfully && r.StartProof is { } proof &&
        ReferenceEquals(proof.Binding, binding) && ReferenceEquals(proof.StartTask, r.Start.NativeTask) &&
        ReferenceEquals(targets.GetValueOrDefault(r.Window), proof.Target) &&
        r.Receipt!.Evidence == DispatchEvidence.Pending;

    private static bool StatusDeniedVaultRecoverHistoryValid(StatusDeniedVaultRecoverRegistration r) =>
        !r.Invalid && !r.DisposalFailed &&
        r.Responses.All(response => response.Valid);

    private static bool StatusDeniedVaultRecoverLive(StatusDeniedVaultRecoverRegistration r) =>
        StatusDeniedVaultRecoverHistoryValid(r) && !r.Revoked && !r.Sealed && !r.Window.Closed &&
        !(r.Start?.Token.IsCancellationRequested ?? false) &&
        !(r.Start?.Caller.IsCancellationRequested ?? false) &&
        !(r.Selected?.Token.IsCancellationRequested ?? false) &&
        !(r.Selected?.Caller.IsCancellationRequested ?? false);

    internal async Task<SecretOutcome<ManagementOperation>> StartStatusDeniedVaultRecoverAsync(Window window,
        FixtureSelector selector, VaultAdministration client, ManagementScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token = default, Action<Task>? retained = null,
        Action? beforeSend = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(receipt);
        StatusDeniedVaultRecoverRegistration r;
        StatusDeniedVaultRecoverSlot slot;
        lock (gate)
        {
            r = RequireStatusDeniedVaultRecover(window, selector);
            bool valid = StatusDeniedVaultRecoverLive(r) && !r.AdmissionClosed && r.Start is null && window.Start is null &&
                scope is VaultScope && ReferenceEquals(window.Binding.Resource, r.InitialScope) &&
                Route(window.Binding with { Resource = scope }) == Route(window.Binding) &&
                input is not null && InputMatches(window.Binding, input) &&
                input.StatusOperation == ManagementMutation.RecoverVault &&
                receipt.Evidence == DispatchEvidence.NotDispatched &&
                !token.IsCancellationRequested && !startedWindows.Contains(window);
            r.Invalid |= !valid;
            Require(valid);
            window.Binding.Resource = scope;
            r.BeforeSend = beforeSend;
            r.Client = client;
            r.Scope = (VaultScope)scope;
            r.Configuration = new(input!.Location, input.TenantId, input.Sku, true, false, input.RetentionDays, true);
            r.Receipt = receipt;
            r.Start = slot = new(token, token);
            window.Start = slot.Invocation;
            startedWindows.Add(window);
        }
        try
        {
            var previous = currentStatusDeniedVaultRecover.Value;
            currentStatusDeniedVaultRecover.Value = new(r, slot, true);
            Task<SecretOutcome<ManagementOperation>> task;
            try
            {
                task = client.RecoverVaultAsync((VaultScope)scope, r.Configuration!, receipt, token).AsTask();
                slot.NativeTask = slot.Invocation.SdkTask = task;
            }
            finally { currentStatusDeniedVaultRecover.Value = previous; }
            try { retained?.Invoke(task); slot.HookReturned = true; }
            finally
            {
                var result = await task.ConfigureAwait(false);
                r.Handle = result.IsSuccess ? result.Value : null;
                slot.Invocation.Outcome = result.Status;
                slot.Invocation.WrapperState = r.Handle?.State;
                slot.Invocation.HasNativeHandle = r.Handle is not null;
                slot.Success = result.IsSuccess && r.Handle?.State == NativeProvisioningState.Pending &&
                    receipt.Evidence == DispatchEvidence.Pending;
            }
            return await task.ConfigureAwait(false);
        }
        catch { r.Invalid = true; throw; }
        finally { await FinishStatusDeniedVaultRecoverAsync(r, slot, start: true).ConfigureAwait(false); }
    }

    internal async Task<SecretStatus> CheckStatusDeniedVaultRecoverAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null,
        CancellationToken originalCallerToken = default)
    {
        StatusDeniedVaultRecoverRegistration r;
        StatusDeniedVaultRecoverSlot slot;
        lock (gate)
        {
            r = RequireStatusDeniedVaultRecover(window, selector);
            // A foreign handle cannot consume or invalidate the owned one-use check.
            Require(ReferenceEquals(r.Handle, handle));
            bool valid = StatusDeniedVaultRecoverTargetValid(r, window.Binding) && r.StartProof is not null &&
                r.Start is { Finished: true } && r.Start.Drained.Task.IsCompletedSuccessfully &&
                r.Selected is null && ReferenceEquals(r.Handle, handle) &&
                handle.State == NativeProvisioningState.Pending && r.Receipt!.Evidence == DispatchEvidence.Pending &&
                !token.IsCancellationRequested && !originalCallerToken.IsCancellationRequested;
            r.Invalid |= !valid;
            Require(valid);
            r.Selected = slot = new(token, originalCallerToken);
            window.Status = slot.Invocation;
        }
        try
        {
            var previous = currentStatusDeniedVaultRecover.Value;
            currentStatusDeniedVaultRecover.Value = new(r, slot, false);
            Task<SecretStatus> task;
            try
            {
                task = handle.CheckStatusAsync(token).AsTask();
                slot.NativeTask = slot.Invocation.SdkTask = task;
            }
            finally { currentStatusDeniedVaultRecover.Value = previous; }
            try { retained?.Invoke(task); slot.HookReturned = true; }
            finally
            {
                var result = await task.ConfigureAwait(false);
                slot.Invocation.Outcome = result;
                slot.Invocation.WrapperState = handle.State;
                slot.Success = result == SecretStatus.Denied && handle.State == NativeProvisioningState.Failed &&
                    r.Receipt!.Evidence == DispatchEvidence.Pending;
            }
            return await task.ConfigureAwait(false);
        }
        catch { r.Invalid = true; throw; }
        finally { await FinishStatusDeniedVaultRecoverAsync(r, slot, start: false).ConfigureAwait(false); }
    }

    private async Task FinishStatusDeniedVaultRecoverAsync(StatusDeniedVaultRecoverRegistration r, StatusDeniedVaultRecoverSlot slot, bool start)
    {
        try
        {
            if (slot.NativeTask is not null)
                try { await slot.NativeTask.ConfigureAwait(false); } catch { r.Invalid = true; }
            Task[] sends;
            lock (gate) sends = slot.Sends.ToArray();
            try { await Task.WhenAll(sends).ConfigureAwait(false); } catch { r.Invalid = true; }
            try { slot.ValidateCustody?.Invoke(); } catch { r.Invalid = true; }
            if (!start)
            {
                // Both actual native tasks, retention hooks and sends have ended.
                // Validate the installed parsers before and after physical disposal.
                try { r.Start?.ValidateCustody?.Invoke(); } catch { r.Invalid = true; }
                r.Invalid |= !StatusDeniedVaultRecoverHistoryValid(r) || slot.FactoryActive || slot.Sending ||
                    r.Start is not { Finished: true, FactoryActive: false, Sending: false };
                foreach (var storage in r.Storage)
                    try { storage.Dispose(); } catch { r.DisposalFailed = r.Invalid = true; }
                r.Storage.Clear();
                r.DisposalComplete = !r.DisposalFailed;
                r.Invalid |= !StatusDeniedVaultRecoverHistoryValid(r);
            }
            lock (gate)
            {
                bool valid = StatusDeniedVaultRecoverLive(r) && !slot.Token.IsCancellationRequested &&
                    slot.NativeTask is { IsCompletedSuccessfully: true } && slot.HookReturned && slot.Success &&
                    slot.RequestSha256 is not null && slot.ValidateCustody is not null && !slot.FactoryActive && !slot.Sending && slot.Factories == 1 && slot.SendCount == 1 &&
                    slot.Sends.Count == 1 && (start ? slot.Responses.Count == 1 && r.Candidate is not null :
                        slot.Responses.Count == 1 && r.DisposalComplete) &&
                    r.Receipt!.Evidence == DispatchEvidence.Pending;
                r.Invalid |= !valid;
                if (valid && start && r.Candidate is { } candidate)
                {
                    r.StartProof = new(candidate.Binding, candidate.Target, candidate.ResponseBytes,
                        candidate.RequestSha256, candidate.NativeRequestId, slot.NativeTask!, r.Configuration!);
                    targets[r.Window] = candidate.Target;
                    eligible.Add(r.Window);
                }
                else if (valid && !start && r.StartProof is not null)
                {
                    var body = slot.Responses[0].Body;
                    r.DeniedProof = new(r.StartProof, slot.NativeTask!, body.Response.Status, body.Bytes.Length,
                        slot.RequestSha256!, body.Sha256, body.NativeRequestId);
                }
                else r.Invalid = true;
            }
        }
        finally
        {
            lock (gate)
            {
                slot.Finished = slot.Invocation.Terminated = true;
                slot.Invocation.Drained.TrySetResult();
                slot.Drained.TrySetResult();
            }
        }
    }

    internal bool TryGetStatusDeniedVaultRecoverStart(Window window, Binding binding, VaultAdministration client,
        VaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        [NotNullWhen(true)] out StatusDeniedVaultRecoverStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || binding is null || client is null || scope is null || receipt is null ||
                startTask is null || handle is null || !ReferenceEquals(window.Owner, owner) ||
                !statusDeniedVaultRecovers.TryGetValue(window, out var r) || !StatusDeniedVaultRecoverSelector(binding.Selector) ||
                !ReferenceEquals(window.Binding, binding) || !ReferenceEquals(r.Window, window) ||
                !ReferenceEquals(binding.Selector, r.BindingSelector) ||
                !ReferenceEquals(r.Client, client) || !ReferenceEquals(r.Scope, scope) ||
                !ReferenceEquals(binding.Resource, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.Handle, handle) || !ReferenceEquals(r.Start?.NativeTask, startTask) ||
                r.Start is not { Finished: true, HookReturned: true, Success: true } ||
                !r.Start.Drained.Task.IsCompletedSuccessfully || !startTask.IsCompletedSuccessfully ||
                !StatusDeniedVaultRecoverHistoryValid(r) || r.AdmissionClosed || r.Sealed || r.Revoked || window.Closed ||
                r.Start.Token.IsCancellationRequested || r.Start.Caller.IsCancellationRequested ||
                (r.Selected?.Token.IsCancellationRequested ?? false) ||
                (r.Selected?.Caller.IsCancellationRequested ?? false) ||
                receipt.Evidence != DispatchEvidence.Pending || r.StartProof is not { } issued ||
                !ReferenceEquals(issued.StartTask, startTask) ||
                !ReferenceEquals(targets.GetValueOrDefault(window), issued.Target))
                return false;
            proof = issued;
            return true;
        }
    }

    internal bool TryGetStatusDeniedVaultRecoverDenied(Window window, Binding binding, VaultAdministration client,
        VaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task checkTask,
        [NotNullWhen(true)] out StatusDeniedVaultRecoverDeniedProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusDeniedVaultRecoverStart(window, binding, client, scope, receipt, startTask, handle, out var start) ||
                !statusDeniedVaultRecovers.TryGetValue(window, out var r) ||
                r.Selected is not { Finished: true, HookReturned: true, Success: true } selected ||
                !selected.Drained.Task.IsCompletedSuccessfully || !ReferenceEquals(selected.NativeTask, checkTask) ||
                !checkTask.IsCompletedSuccessfully || handle.State != NativeProvisioningState.Failed ||
                r.DeniedProof is not { } issued || !ReferenceEquals(issued.Start, start) ||
                !ReferenceEquals(issued.CheckTask, checkTask))
                return false;
            proof = issued;
            return true;
        }
    }

    internal void RevokeStatusDeniedVaultRecoverSelected(Window window)
    {
        lock (gate)
        {
            var r = RequireStatusDeniedVaultRecover(window, window.Binding.Selector);
            r.Invalid |= r.Start is not { Finished: true } || r.Selected is not { Finished: true } ||
                r.DeniedProof is null || !StatusDeniedVaultRecoverHistoryValid(r) ||
                r.Start.Token.IsCancellationRequested || r.Selected.Token.IsCancellationRequested ||
                r.Selected.Caller.IsCancellationRequested;
            r.Revoked = window.Closed = true;
        }
    }

    private Task<Capture> SealStatusDeniedVaultRecoverAsync(Window window)
    {
        StatusDeniedVaultRecoverRegistration r;
        TaskCompletionSource ready;
        Task<Capture> task;
        lock (gate)
        {
            r = RequireStatusDeniedVaultRecover(window, window.Binding.Selector);
            r.AdmissionClosed = true;
            if (r.SealTask is not null) return r.SealTask;
            ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = r.SealTask = Drain(ready.Task);
        }
        ready.SetResult();
        return task;

        async Task<Capture> Drain(Task admission)
        {
            await admission.ConfigureAwait(false);
            var tasks = new[] { r.Start, r.Selected }.OfType<StatusDeniedVaultRecoverSlot>()
                .Select(slot => slot.Drained.Task).ToArray();
            await Task.WhenAll(tasks).ConfigureAwait(false);
            r.Invalid |= !StatusDeniedVaultRecoverHistoryValid(r);
            foreach (var storage in r.Storage)
                try { storage.Dispose(); } catch { r.DisposalFailed = r.Invalid = true; }
            r.Storage.Clear();
            r.DisposalComplete = !r.DisposalFailed;
            r.Invalid |= !StatusDeniedVaultRecoverHistoryValid(r);
            lock (gate) r.Sealed = r.Revoked = window.Closed = true;
            r.AuthorizationSha256 = null;
            Require(!r.DisposalFailed);
            return new() { Binding = window.Binding, Start = r.Start?.Invocation, Status = r.Selected?.Invocation };
        }
    }

    private async Task SendStatusDeniedVaultRecoverAsync(StatusDeniedVaultRecoverContext context, HttpMessage message)
    {
        var r = context.Registration;
        var slot = context.Slot;
        bool start = context.Start;
        var request = message.Request;
        var headers = request.Headers.ToArray();
        var storage = new OwnedArmResponse.Storage();
        RequestContent? frozen = null;
        byte[]? dispatchBytes = null;
        var attempt = new Attempt { Dispatch = Guid.NewGuid() };
        try
        {
            lock (gate)
            {
                bool valid = StatusDeniedVaultRecoverLive(r) && !slot.Finished && !slot.Sending &&
                    slot.Requests.Contains(request) && ++slot.SendCount == 1 && slot.Responses.Count == 0;
                r.Invalid |= !valid;
                Require(valid);
                slot.Sending = slot.Invocation.Sending = true;
                r.Storage.Add(storage);
            }
            if (start)
            {
                var originalContent = request.Content;
                Require(originalContent is not null);
                storage.Own(originalContent);
                Require(originalContent.TryComputeLength(out long length) && length > 0 && length <= maximumBytes);
                byte[] staging = new byte[maximumBytes];
                storage.Own(staging);
                using var buffer = new MemoryStream(staging, 0, staging.Length, true, true);
                await originalContent.WriteToAsync(buffer, message.CancellationToken).ConfigureAwait(false);
                Require(buffer.Position == length && ReferenceEquals(message.Request, request) &&
                    ReferenceEquals(request.Content, originalContent) && headers.SequenceEqual(request.Headers));
                dispatchBytes = staging.AsSpan(0, (int)length).ToArray();
                storage.Own(dispatchBytes);
                ValidateCreateVaultRequest(dispatchBytes, r.Configuration!, recover: true);
                frozen = RequestContent.Create(dispatchBytes);
                storage.Own(frozen);
                request.Content = frozen;
                if (request.Headers.TryGetValue("Content-Length", out var declared))
                    Require(declared == length.ToString(CultureInfo.InvariantCulture));
            }
            void Check()
            {
                Require(StatusDeniedVaultRecoverLive(r) && !slot.Token.IsCancellationRequested &&
                    !slot.Caller.IsCancellationRequested && !message.CancellationToken.IsCancellationRequested &&
                    ReferenceEquals(message.Request, request) && headers.SequenceEqual(request.Headers));
                if (start)
                {
                    var uri = request.Uri.ToUri();
                    Require(Trusted(uri) && uri.AbsolutePath == r.Window.Path && uri.Query == "?api-version=2026-02-01" &&
                        request.Method == RequestMethod.Put && ReferenceEquals(request.Content, frozen) &&
                        request.Headers.TryGetValue("Authorization", out var auth) &&
                        auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
                        request.Headers.TryGetValue("Content-Type", out var type) &&
                        type.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase) &&
                        !request.Headers.Contains("Content-Encoding") && !request.Headers.Contains("Transfer-Encoding") &&
                        !request.Headers.Contains("Content-Range"));
                    if (request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
                }
                else OriginalVaultRequest(message, r.Window.Path, RequestMethod.Get, r.StartProof!.Target.TargetUri.AbsoluteUri);
                Headers(headers);
                Require(!request.Headers.Contains("Range"));
            }
            Check();
            Require(r.Receipt!.Evidence == (start ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Pending));
            byte[] requestIdentity = System.Text.Encoding.UTF8.GetBytes(request.Method + " " + request.Uri.ToUri().AbsoluteUri);
            storage.Own(requestIdentity);
            attempt = new() { Dispatch = attempt.Dispatch,
                RequestSha256 = Convert.ToHexString(SHA256.HashData(start ? dispatchBytes! : requestIdentity)) };
            lock (gate)
            {
                slot.RequestSha256 = attempt.RequestSha256;
                slot.Invocation.Attempts.Add(attempt);
            }
            request.Headers.TryGetValue("Authorization", out var authorization);
            byte[] authorizationBytes = System.Text.Encoding.UTF8.GetBytes(authorization!);
            string authorizationSha256;
            try { authorizationSha256 = Convert.ToHexString(SHA256.HashData(authorizationBytes)); }
            finally { CryptographicOperations.ZeroMemory(authorizationBytes); }
            if (start) r.AuthorizationSha256 = authorizationSha256;
            else Require(r.AuthorizationSha256 == authorizationSha256);
            message.BufferResponse = false;
            if (start) r.BeforeSend?.Invoke();
            Check();
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) storage.Own(message.Response); }
            Check();
            Require(message.HasResponse);
            var original = message.Response;
            var stream = original.ContentStream;
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, storage,
                allowContinuation: start).ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(original.ContentStream, stream) && body.Bytes.Length > 0 &&
                (start ? body.Response.Status == 201 : body.Response.Status is 401 or 403));
            Require(body.Response.Headers.TryGetValue("Content-Type", out var contentType));
            string[] media = contentType.Split(';').Select(value => value.Trim()).ToArray();
            Require(media.Length is 1 or 2 && media[0].Equals("application/json", StringComparison.OrdinalIgnoreCase) &&
                (media.Length == 1 || media[1].Equals("charset=utf-8", StringComparison.OrdinalIgnoreCase)));
            string? next = Continuation(r.Window, message);
            using var json = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int nodes = 512;
            JsonRows(json.RootElement, ref nodes);
            var root = json.RootElement;
            if (start)
            {
                Require(next is not null && root.ValueKind == JsonValueKind.Object &&
                    !new[] { "error", "errors", "partial", "nextLink", "value", "status" }
                        .Any(name => root.TryGetProperty(name, out _)));
                var state = root.GetProperty("properties").GetProperty("provisioningState").GetString();
                Require(state is "Creating" or "Updating");
                _ = VaultFixtureProvisioner.ParseOwnedVaultResource(r.Window.Path, r.BindingSelector.Nonce,
                    root, CreateVaultConfiguration(r.Configuration!), state!, recover: true);
                byte[] targetBytes = System.Text.Encoding.UTF8.GetBytes(next!);
                try
                {
                    var target = new StatusTarget(r.Window.Binding, attempt.Dispatch, StatusTargetKind.Operation, new Uri(next!),
                        Convert.ToHexString(SHA256.HashData(targetBytes)), body.Sha256);
                    r.Candidate = new(r.Window.Binding, target, body.Bytes.Length, attempt.RequestSha256!, body.NativeRequestId);
                }
                finally { CryptographicOperations.ZeroMemory(targetBytes); }
            }
            else
            {
                Require(next is null && root.ValueKind == JsonValueKind.Object && root.EnumerateObject().All(p => p.Name == "error") &&
                    root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object &&
                    error.EnumerateObject().All(p => p.Name is "code" or "message") &&
                    error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String &&
                    code.GetString() is { Length: > 0 and <= 128 } errorCode && !errorCode.Any(char.IsControl) &&
                    error.TryGetProperty("message", out var text) && text.ValueKind == JsonValueKind.String &&
                    text.GetString() is { Length: > 0 and <= 2048 } errorMessage && !errorMessage.Any(char.IsControl));
            }
            var parser = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, storage,
                requireRebuffer: true, requireDownstreamRead: !start);
            var frame = new StatusPendingPurgeResponse(body, parser, storage);
            lock (gate)
            {
                slot.Responses.Add(frame);
                r.Responses.Add(frame);
                attempt.HttpStatus = body.Response.Status;
                attempt.ResponseSha256 = body.Sha256;
                attempt.ResponseObserved = true;
                attempt.HasProviderContinuation = next is not null;
                attempt.State = start ? WireState.Pending : WireState.Denied;
                attempt.Valid = true;
            }
            // Inspect retained wire custody only after the real native borrower ends.
            // SDK request disposal may dispose headers; it must not change the
            // request route/content or the original host response identity.
            var originalHeaders = body.Response.Headers.ToArray();
            string originalRequestId = body.Response.ClientRequestId;
            string originalReason = body.Response.ReasonPhrase;
            int originalStatus = body.Response.Status;
            string requestUri = request.Uri.ToUri().AbsoluteUri;
            var requestMethod = request.Method;
            slot.ValidateCustody = () =>
            {
                Require(ReferenceEquals(message.Request, request) && request.Method == requestMethod &&
                    request.Uri.ToUri().AbsoluteUri == requestUri && ReferenceEquals(request.Content, frozen) &&
                    original.Status == originalStatus && original.ReasonPhrase == originalReason &&
                    original.ClientRequestId == originalRequestId && originalHeaders.SequenceEqual(original.Headers) &&
                    ReferenceEquals(original.ContentStream, stream) &&
                    Convert.ToHexString(SHA256.HashData(body.Bytes.Span)) == body.Sha256 &&
                    (!start || Convert.ToHexString(SHA256.HashData(dispatchBytes!)) == attempt.RequestSha256));
                try
                {
                    var remainingHeaders = request.Headers.ToArray();
                    Require(remainingHeaders.Length == 0 || headers.SequenceEqual(remainingHeaders));
                }
                catch (ObjectDisposedException) { }
            };
            // Initial201 proves ControlledTransport EOF/exact rebuffer, not a
            // deferred generated model read. Denial requires its native parser.
            Require(!slot.Token.IsCancellationRequested && !slot.Caller.IsCancellationRequested &&
                !message.CancellationToken.IsCancellationRequested && !r.Revoked && !r.Sealed && !r.Window.Closed &&
                ReferenceEquals(message.Request, request) && ReferenceEquals(request.Content, frozen) &&
                headers.SequenceEqual(request.Headers));
        }
        catch { r.Invalid = true; attempt.Valid = false; throw; }
        finally
        {
            lock (gate)
            {
                attempt.TransportTerminated = true;
                slot.Sending = slot.Invocation.Sending = false;
            }
        }
    }

    internal sealed class StatusDeniedVaultUpdateStartProof(Binding binding, StatusTarget target,
        int responseBytes, string requestSha256, string nativeRequestId, Task startTask, VaultConfiguration configuration)
    {
        internal Binding Binding { get; } = binding;
        internal StatusTarget Target { get; } = target;
        internal Guid StartDispatch => Target.StartDispatch;
        internal int HttpStatus => 201;
        internal int ResponseBytes { get; } = responseBytes;
        internal VaultConfiguration Configuration { get; } = configuration;
        internal string ResponseSha256 => Target.StartResponseSha256;
        internal string RequestSha256 { get; } = requestSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal Task StartTask { get; } = startTask;
        internal Task ActualTask => StartTask;
        internal SecretStatus Outcome => SecretStatus.Success;
        internal NativeProvisioningState State => NativeProvisioningState.Pending;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusDeniedVaultUpdateStartProof]";
    }

    internal sealed class StatusDeniedVaultUpdateDeniedProof(StatusDeniedVaultUpdateStartProof start, Task checkTask,
        int httpStatus, int responseBytes, string requestSha256, string responseSha256, string nativeRequestId)
    {
        internal StatusDeniedVaultUpdateStartProof Start { get; } = start;
        internal Task CheckTask { get; } = checkTask;
        internal Task ActualTask => CheckTask;
        internal Binding Binding => Start.Binding;
        internal StatusTarget Target => Start.Target;
        internal Guid StartDispatch => Start.StartDispatch;
        internal int ResponseBytes { get; } = responseBytes;
        internal string RequestSha256 { get; } = requestSha256;
        internal int HttpStatus { get; } = httpStatus;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Denied;
        internal NativeProvisioningState State => NativeProvisioningState.Failed;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusDeniedVaultUpdateDeniedProof]";
    }

    private sealed class StatusDeniedVaultUpdateSlot(CancellationToken token, CancellationToken caller)
    {
        internal readonly CancellationToken Token = token;
        internal readonly CancellationToken Caller = caller;
        internal readonly Invocation Invocation = new();
        internal readonly TaskCompletionSource Drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly HashSet<Request> Requests = new(ReferenceEqualityComparer.Instance);
        internal readonly List<Task> Sends = [];
        internal readonly List<StatusPendingPurgeResponse> Responses = [];
        internal Task? NativeTask;
        internal string? RequestSha256;
        internal int Factories, SendCount;
        internal bool FactoryActive, Sending, HookReturned, Success, Finished;
    }

    private sealed class StatusDeniedVaultUpdateRegistration(Window window)
    {
        internal readonly Window Window = window;
        internal readonly List<OwnedArmResponse.Storage> Storage = [];
        internal readonly List<StatusPendingPurgeResponse> Responses = [];
        internal readonly ManagementScope InitialScope = window.Binding.Resource;
        internal readonly FixtureSelector BindingSelector = window.Binding.Selector;
        internal VaultConfiguration? Configuration;
        internal bool DisposalComplete, DisposalFailed;
        internal Action? BeforeSend;
        internal VaultAdministration? Client;
        internal VaultScope? Scope;
        internal ManagementReceipt? Receipt;
        internal ManagementOperation? Handle;
        internal StatusDeniedVaultUpdateSlot? Start, Selected;
        internal StatusPendingPurgeStartFacts? Candidate;
        internal StatusDeniedVaultUpdateStartProof? StartProof;
        internal StatusDeniedVaultUpdateDeniedProof? DeniedProof;
        internal string? AuthorizationSha256;
        internal Task<Capture>? SealTask;
        internal bool Invalid, Revoked, Sealed;
    }

    private sealed record StatusDeniedVaultUpdateContext(StatusDeniedVaultUpdateRegistration Registration,
        StatusDeniedVaultUpdateSlot Slot, bool Start);
    private readonly AsyncLocal<StatusDeniedVaultUpdateContext?> currentStatusDeniedVaultUpdate = new();
    private readonly Dictionary<Window, StatusDeniedVaultUpdateRegistration> statusDeniedVaultUpdates =
        new(ReferenceEqualityComparer.Instance);

    private static bool StatusDeniedVaultUpdateSelector(FixtureSelector selector) =>
        selector is { Operation: "a.management.ManagementOperation.CheckStatusAsync",
            Variant: "operation.CreateOrUpdateVault", Case: "denied-authority" };

    internal Window ArmStatusDeniedVaultUpdate(Binding binding)
    {
        Require(binding is not null && StatusDeniedVaultUpdateSelector(binding.Selector) &&
            binding.Operation == ManagementMutation.CreateOrUpdateVault &&
            binding.Resource is VaultScope && binding.ApiRevision == "2026-02-01");
        var window = Arm(binding);
        lock (gate) statusDeniedVaultUpdates.Add(window, new(window));
        return window;
    }

    private StatusDeniedVaultUpdateRegistration RequireStatusDeniedVaultUpdate(Window window, FixtureSelector selector)
    {
        Own(window, selector);
        Require(ReferenceEquals(window.Binding.Selector, selector) && StatusDeniedVaultUpdateSelector(selector));
        Require(statusDeniedVaultUpdates.TryGetValue(window, out var r) && ReferenceEquals(r.Window, window));
        return r;
    }

    private bool StatusDeniedVaultUpdateTargetValid(StatusDeniedVaultUpdateRegistration r, Binding binding) =>
        ReferenceEquals(r.Window.Binding, binding) && ReferenceEquals(binding.Resource, r.Scope) &&
        StatusDeniedVaultUpdateLive(r) &&
        r.Start is { Finished: true, HookReturned: true, Success: true } &&
        r.Start.Drained.Task.IsCompletedSuccessfully && r.StartProof is { } proof &&
        ReferenceEquals(proof.Binding, binding) && ReferenceEquals(proof.StartTask, r.Start.NativeTask) &&
        ReferenceEquals(targets.GetValueOrDefault(r.Window), proof.Target) &&
        r.Receipt!.Evidence == DispatchEvidence.Pending;

    private static bool StatusDeniedVaultUpdateHistoryValid(StatusDeniedVaultUpdateRegistration r) =>
        !r.Invalid && !r.DisposalFailed &&
        r.Responses.All(response => response.Valid);

    private static bool StatusDeniedVaultUpdateLive(StatusDeniedVaultUpdateRegistration r) =>
        StatusDeniedVaultUpdateHistoryValid(r) && !r.Revoked && !r.Sealed && !r.Window.Closed &&
        !(r.Start?.Token.IsCancellationRequested ?? false) &&
        !(r.Start?.Caller.IsCancellationRequested ?? false) &&
        !(r.Selected?.Token.IsCancellationRequested ?? false) &&
        !(r.Selected?.Caller.IsCancellationRequested ?? false);

    internal async Task<SecretOutcome<ManagementOperation>> StartStatusDeniedVaultUpdateAsync(Window window,
        FixtureSelector selector, VaultAdministration client, ManagementScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token = default, Action<Task>? retained = null,
        Action? beforeSend = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(receipt);
        StatusDeniedVaultUpdateRegistration r;
        StatusDeniedVaultUpdateSlot slot;
        lock (gate)
        {
            r = RequireStatusDeniedVaultUpdate(window, selector);
            bool valid = StatusDeniedVaultUpdateLive(r) && r.Start is null && window.Start is null &&
                scope is VaultScope && ReferenceEquals(window.Binding.Resource, r.InitialScope) &&
                Route(window.Binding with { Resource = scope }) == Route(window.Binding) &&
                input is not null && InputMatches(window.Binding, input) &&
                input.StatusOperation == ManagementMutation.CreateOrUpdateVault &&
                receipt.Evidence == DispatchEvidence.NotDispatched &&
                !token.IsCancellationRequested && !startedWindows.Contains(window);
            r.Invalid |= !valid;
            Require(valid);
            window.Binding.Resource = scope;
            r.BeforeSend = beforeSend;
            r.Client = client;
            r.Scope = (VaultScope)scope;
            r.Configuration = new(input!.Location, input.TenantId, input.Sku, true, false, input.RetentionDays, true);
            r.Receipt = receipt;
            r.Start = slot = new(token, token);
            window.Start = slot.Invocation;
            startedWindows.Add(window);
        }
        try
        {
            var previous = currentStatusDeniedVaultUpdate.Value;
            currentStatusDeniedVaultUpdate.Value = new(r, slot, true);
            Task<SecretOutcome<ManagementOperation>> task;
            try
            {
                task = client.CreateOrUpdateVaultAsync((VaultScope)scope, r.Configuration!, receipt, token).AsTask();
                slot.NativeTask = slot.Invocation.SdkTask = task;
            }
            finally { currentStatusDeniedVaultUpdate.Value = previous; }
            try { retained?.Invoke(task); slot.HookReturned = true; }
            finally
            {
                var result = await task.ConfigureAwait(false);
                r.Handle = result.IsSuccess ? result.Value : null;
                slot.Invocation.Outcome = result.Status;
                slot.Invocation.WrapperState = r.Handle?.State;
                slot.Invocation.HasNativeHandle = r.Handle is not null;
                slot.Success = result.IsSuccess && r.Handle?.State == NativeProvisioningState.Pending &&
                    receipt.Evidence == DispatchEvidence.Pending;
            }
            return await task.ConfigureAwait(false);
        }
        catch { r.Invalid = true; throw; }
        finally { await FinishStatusDeniedVaultUpdateAsync(r, slot, start: true).ConfigureAwait(false); }
    }

    internal async Task<SecretStatus> CheckStatusDeniedVaultUpdateAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null,
        CancellationToken originalCallerToken = default)
    {
        StatusDeniedVaultUpdateRegistration r;
        StatusDeniedVaultUpdateSlot slot;
        lock (gate)
        {
            r = RequireStatusDeniedVaultUpdate(window, selector);
            // A foreign handle cannot consume or invalidate the owned one-use check.
            Require(ReferenceEquals(r.Handle, handle));
            bool valid = StatusDeniedVaultUpdateTargetValid(r, window.Binding) && r.StartProof is not null &&
                r.Start is { Finished: true } && r.Start.Drained.Task.IsCompletedSuccessfully &&
                r.Selected is null && ReferenceEquals(r.Handle, handle) &&
                handle.State == NativeProvisioningState.Pending && r.Receipt!.Evidence == DispatchEvidence.Pending &&
                !token.IsCancellationRequested && !originalCallerToken.IsCancellationRequested;
            r.Invalid |= !valid;
            Require(valid);
            r.Selected = slot = new(token, originalCallerToken);
            window.Status = slot.Invocation;
        }
        try
        {
            var previous = currentStatusDeniedVaultUpdate.Value;
            currentStatusDeniedVaultUpdate.Value = new(r, slot, false);
            Task<SecretStatus> task;
            try
            {
                task = handle.CheckStatusAsync(token).AsTask();
                slot.NativeTask = slot.Invocation.SdkTask = task;
            }
            finally { currentStatusDeniedVaultUpdate.Value = previous; }
            try { retained?.Invoke(task); slot.HookReturned = true; }
            finally
            {
                var result = await task.ConfigureAwait(false);
                slot.Invocation.Outcome = result;
                slot.Invocation.WrapperState = handle.State;
                slot.Success = result == SecretStatus.Denied && handle.State == NativeProvisioningState.Failed &&
                    r.Receipt!.Evidence == DispatchEvidence.Pending;
            }
            return await task.ConfigureAwait(false);
        }
        catch { r.Invalid = true; throw; }
        finally { await FinishStatusDeniedVaultUpdateAsync(r, slot, start: false).ConfigureAwait(false); }
    }

    private async Task FinishStatusDeniedVaultUpdateAsync(StatusDeniedVaultUpdateRegistration r, StatusDeniedVaultUpdateSlot slot, bool start)
    {
        try
        {
            if (slot.NativeTask is not null)
                try { await slot.NativeTask.ConfigureAwait(false); } catch { r.Invalid = true; }
            Task[] sends;
            lock (gate) sends = slot.Sends.ToArray();
            try { await Task.WhenAll(sends).ConfigureAwait(false); } catch { r.Invalid = true; }
            if (!start)
            {
                // Both actual native tasks, retention hooks and sends have ended.
                // Validate the installed parsers before and after physical disposal.
                r.Invalid |= !StatusDeniedVaultUpdateHistoryValid(r) || slot.FactoryActive || slot.Sending ||
                    r.Start is not { Finished: true, FactoryActive: false, Sending: false };
                foreach (var storage in r.Storage)
                    try { storage.Dispose(); } catch { r.DisposalFailed = r.Invalid = true; }
                r.Storage.Clear();
                r.DisposalComplete = !r.DisposalFailed;
                r.Invalid |= !StatusDeniedVaultUpdateHistoryValid(r);
            }
            lock (gate)
            {
                bool valid = StatusDeniedVaultUpdateLive(r) && !slot.Token.IsCancellationRequested &&
                    slot.NativeTask is { IsCompletedSuccessfully: true } && slot.HookReturned && slot.Success &&
                    slot.RequestSha256 is not null && !slot.FactoryActive && !slot.Sending && slot.Factories == 1 && slot.SendCount == 1 &&
                    slot.Sends.Count == 1 && (start ? slot.Responses.Count == 1 && r.Candidate is not null :
                        slot.Responses.Count == 1 && r.DisposalComplete) &&
                    r.Receipt!.Evidence == DispatchEvidence.Pending;
                r.Invalid |= !valid;
                if (valid && start && r.Candidate is { } candidate)
                {
                    r.StartProof = new(candidate.Binding, candidate.Target, candidate.ResponseBytes,
                        candidate.RequestSha256, candidate.NativeRequestId, slot.NativeTask!, r.Configuration!);
                    targets[r.Window] = candidate.Target;
                    eligible.Add(r.Window);
                }
                else if (valid && !start && r.StartProof is not null)
                {
                    var body = slot.Responses[0].Body;
                    r.DeniedProof = new(r.StartProof, slot.NativeTask!, body.Response.Status, body.Bytes.Length,
                        slot.RequestSha256!, body.Sha256, body.NativeRequestId);
                }
                else r.Invalid = true;
            }
        }
        finally
        {
            lock (gate)
            {
                slot.Finished = slot.Invocation.Terminated = true;
                slot.Invocation.Drained.TrySetResult();
                slot.Drained.TrySetResult();
            }
        }
    }

    internal bool TryGetStatusDeniedVaultUpdateStart(Window window, Binding binding, VaultAdministration client,
        VaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        [NotNullWhen(true)] out StatusDeniedVaultUpdateStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || binding is null || client is null || scope is null || receipt is null ||
                startTask is null || handle is null || !ReferenceEquals(window.Owner, owner) ||
                !statusDeniedVaultUpdates.TryGetValue(window, out var r) || !StatusDeniedVaultUpdateSelector(binding.Selector) ||
                !ReferenceEquals(window.Binding, binding) || !ReferenceEquals(r.Window, window) ||
                !ReferenceEquals(binding.Selector, r.BindingSelector) ||
                !ReferenceEquals(r.Client, client) || !ReferenceEquals(r.Scope, scope) ||
                !ReferenceEquals(binding.Resource, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.Handle, handle) || !ReferenceEquals(r.Start?.NativeTask, startTask) ||
                r.Start is not { Finished: true, HookReturned: true, Success: true } ||
                !r.Start.Drained.Task.IsCompletedSuccessfully || !startTask.IsCompletedSuccessfully ||
                !StatusDeniedVaultUpdateHistoryValid(r) || r.Sealed || r.Revoked || window.Closed ||
                r.Start.Token.IsCancellationRequested || r.Start.Caller.IsCancellationRequested ||
                (r.Selected?.Token.IsCancellationRequested ?? false) ||
                (r.Selected?.Caller.IsCancellationRequested ?? false) ||
                receipt.Evidence != DispatchEvidence.Pending || r.StartProof is not { } issued ||
                !ReferenceEquals(issued.StartTask, startTask) ||
                !ReferenceEquals(targets.GetValueOrDefault(window), issued.Target))
                return false;
            proof = issued;
            return true;
        }
    }

    internal bool TryGetStatusDeniedVaultUpdateDenied(Window window, Binding binding, VaultAdministration client,
        VaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task checkTask,
        [NotNullWhen(true)] out StatusDeniedVaultUpdateDeniedProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusDeniedVaultUpdateStart(window, binding, client, scope, receipt, startTask, handle, out var start) ||
                !statusDeniedVaultUpdates.TryGetValue(window, out var r) ||
                r.Selected is not { Finished: true, HookReturned: true, Success: true } selected ||
                !selected.Drained.Task.IsCompletedSuccessfully || !ReferenceEquals(selected.NativeTask, checkTask) ||
                !checkTask.IsCompletedSuccessfully || handle.State != NativeProvisioningState.Failed ||
                r.DeniedProof is not { } issued || !ReferenceEquals(issued.Start, start) ||
                !ReferenceEquals(issued.CheckTask, checkTask))
                return false;
            proof = issued;
            return true;
        }
    }

    internal void RevokeStatusDeniedVaultUpdateSelected(Window window)
    {
        lock (gate)
        {
            var r = RequireStatusDeniedVaultUpdate(window, window.Binding.Selector);
            r.Invalid |= r.Start is not { Finished: true } || r.Selected is not { Finished: true } ||
                r.DeniedProof is null || !StatusDeniedVaultUpdateHistoryValid(r) ||
                r.Start.Token.IsCancellationRequested || r.Selected.Token.IsCancellationRequested ||
                r.Selected.Caller.IsCancellationRequested;
            r.Revoked = window.Closed = true;
        }
    }

    private Task<Capture> SealStatusDeniedVaultUpdateAsync(Window window)
    {
        StatusDeniedVaultUpdateRegistration r;
        TaskCompletionSource ready;
        Task<Capture> task;
        lock (gate)
        {
            r = RequireStatusDeniedVaultUpdate(window, window.Binding.Selector);
            r.Sealed = r.Revoked = window.Closed = true;
            if (r.SealTask is not null) return r.SealTask;
            ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = r.SealTask = Drain(ready.Task);
        }
        ready.SetResult();
        return task;

        async Task<Capture> Drain(Task admission)
        {
            await admission.ConfigureAwait(false);
            var tasks = new[] { r.Start, r.Selected }.OfType<StatusDeniedVaultUpdateSlot>()
                .Select(slot => slot.Drained.Task).ToArray();
            await Task.WhenAll(tasks).ConfigureAwait(false);
            r.Invalid |= !StatusDeniedVaultUpdateHistoryValid(r);
            foreach (var storage in r.Storage)
                try { storage.Dispose(); } catch { r.DisposalFailed = r.Invalid = true; }
            r.Storage.Clear();
            r.DisposalComplete = !r.DisposalFailed;
            r.Invalid |= !StatusDeniedVaultUpdateHistoryValid(r);
            r.AuthorizationSha256 = null;
            Require(!r.DisposalFailed);
            return new() { Binding = window.Binding, Start = r.Start?.Invocation, Status = r.Selected?.Invocation };
        }
    }

    private async Task SendStatusDeniedVaultUpdateAsync(StatusDeniedVaultUpdateContext context, HttpMessage message)
    {
        var r = context.Registration;
        var slot = context.Slot;
        bool start = context.Start;
        var request = message.Request;
        var headers = request.Headers.ToArray();
        var storage = new OwnedArmResponse.Storage();
        RequestContent? frozen = null;
        byte[]? dispatchBytes = null;
        var attempt = new Attempt { Dispatch = Guid.NewGuid() };
        try
        {
            lock (gate)
            {
                bool valid = StatusDeniedVaultUpdateLive(r) && !slot.Finished && !slot.Sending &&
                    slot.Requests.Contains(request) && ++slot.SendCount == 1 && slot.Responses.Count == 0;
                r.Invalid |= !valid;
                Require(valid);
                slot.Sending = slot.Invocation.Sending = true;
                r.Storage.Add(storage);
            }
            if (start)
            {
                var originalContent = request.Content;
                Require(originalContent is not null);
                storage.Own(originalContent);
                Require(originalContent.TryComputeLength(out long length) && length > 0 && length <= maximumBytes);
                byte[] staging = new byte[maximumBytes];
                storage.Own(staging);
                using var buffer = new MemoryStream(staging, 0, staging.Length, true, true);
                await originalContent.WriteToAsync(buffer, message.CancellationToken).ConfigureAwait(false);
                Require(buffer.Position == length && ReferenceEquals(message.Request, request) &&
                    ReferenceEquals(request.Content, originalContent) && headers.SequenceEqual(request.Headers));
                dispatchBytes = staging.AsSpan(0, (int)length).ToArray();
                storage.Own(dispatchBytes);
                ValidateCreateVaultRequest(dispatchBytes, r.Configuration!);
                frozen = RequestContent.Create(dispatchBytes);
                storage.Own(frozen);
                request.Content = frozen;
                if (request.Headers.TryGetValue("Content-Length", out var declared))
                    Require(declared == length.ToString(CultureInfo.InvariantCulture));
            }
            void Check()
            {
                Require(StatusDeniedVaultUpdateLive(r) && !slot.Token.IsCancellationRequested &&
                    !slot.Caller.IsCancellationRequested && !message.CancellationToken.IsCancellationRequested &&
                    ReferenceEquals(message.Request, request) && headers.SequenceEqual(request.Headers));
                if (start)
                {
                    var uri = request.Uri.ToUri();
                    Require(Trusted(uri) && uri.AbsolutePath == r.Window.Path && uri.Query == "?api-version=2026-02-01" &&
                        request.Method == RequestMethod.Put && ReferenceEquals(request.Content, frozen) &&
                        request.Headers.TryGetValue("Authorization", out var auth) &&
                        auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
                        request.Headers.TryGetValue("Content-Type", out var type) &&
                        type.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase) &&
                        !request.Headers.Contains("Content-Encoding") && !request.Headers.Contains("Transfer-Encoding") &&
                        !request.Headers.Contains("Content-Range"));
                    if (request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
                }
                else OriginalVaultRequest(message, r.Window.Path, RequestMethod.Get, r.StartProof!.Target.TargetUri.AbsoluteUri);
                Headers(headers);
                Require(!request.Headers.Contains("Range"));
            }
            Check();
            Require(r.Receipt!.Evidence == (start ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Pending));
            byte[] requestIdentity = System.Text.Encoding.UTF8.GetBytes(request.Method + " " + request.Uri.ToUri().AbsoluteUri);
            storage.Own(requestIdentity);
            attempt = new() { Dispatch = attempt.Dispatch,
                RequestSha256 = Convert.ToHexString(SHA256.HashData(start ? dispatchBytes! : requestIdentity)) };
            lock (gate)
            {
                slot.RequestSha256 = attempt.RequestSha256;
                slot.Invocation.Attempts.Add(attempt);
            }
            request.Headers.TryGetValue("Authorization", out var authorization);
            byte[] authorizationBytes = System.Text.Encoding.UTF8.GetBytes(authorization!);
            string authorizationSha256;
            try { authorizationSha256 = Convert.ToHexString(SHA256.HashData(authorizationBytes)); }
            finally { CryptographicOperations.ZeroMemory(authorizationBytes); }
            if (start) r.AuthorizationSha256 = authorizationSha256;
            else Require(r.AuthorizationSha256 == authorizationSha256);
            message.BufferResponse = false;
            if (start) r.BeforeSend?.Invoke();
            Check();
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) storage.Own(message.Response); }
            Check();
            Require(message.HasResponse);
            var original = message.Response;
            var stream = original.ContentStream;
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, storage,
                allowContinuation: start).ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(original.ContentStream, stream) && body.Bytes.Length > 0 &&
                (start ? body.Response.Status == 201 : body.Response.Status is 401 or 403));
            Require(body.Response.Headers.TryGetValue("Content-Type", out var contentType));
            string[] media = contentType.Split(';').Select(value => value.Trim()).ToArray();
            Require(media.Length is 1 or 2 && media[0].Equals("application/json", StringComparison.OrdinalIgnoreCase) &&
                (media.Length == 1 || media[1].Equals("charset=utf-8", StringComparison.OrdinalIgnoreCase)));
            string? next = Continuation(r.Window, message);
            using var json = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int nodes = 512;
            JsonRows(json.RootElement, ref nodes);
            var root = json.RootElement;
            if (start)
            {
                Require(next is not null && root.ValueKind == JsonValueKind.Object &&
                    !new[] { "error", "errors", "partial", "nextLink", "value", "status" }
                        .Any(name => root.TryGetProperty(name, out _)));
                var state = root.GetProperty("properties").GetProperty("provisioningState").GetString();
                Require(state is "Creating" or "Updating");
                _ = VaultFixtureProvisioner.ParseOwnedVaultResource(r.Window.Path, r.BindingSelector.Nonce,
                    root, CreateVaultConfiguration(r.Configuration!), state!);
                byte[] targetBytes = System.Text.Encoding.UTF8.GetBytes(next!);
                try
                {
                    var target = new StatusTarget(r.Window.Binding, attempt.Dispatch, StatusTargetKind.Operation, new Uri(next!),
                        Convert.ToHexString(SHA256.HashData(targetBytes)), body.Sha256);
                    r.Candidate = new(r.Window.Binding, target, body.Bytes.Length, attempt.RequestSha256!, body.NativeRequestId);
                }
                finally { CryptographicOperations.ZeroMemory(targetBytes); }
            }
            else
            {
                Require(next is null && root.ValueKind == JsonValueKind.Object && root.EnumerateObject().All(p => p.Name == "error") &&
                    root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object &&
                    error.EnumerateObject().All(p => p.Name is "code" or "message") &&
                    error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String &&
                    code.GetString() is { Length: > 0 and <= 128 } errorCode && !errorCode.Any(char.IsControl) &&
                    error.TryGetProperty("message", out var text) && text.ValueKind == JsonValueKind.String &&
                    text.GetString() is { Length: > 0 and <= 2048 } errorMessage && !errorMessage.Any(char.IsControl));
            }
            var parser = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, storage,
                requireRebuffer: true, requireDownstreamRead: !start);
            var frame = new StatusPendingPurgeResponse(body, parser, storage);
            lock (gate)
            {
                slot.Responses.Add(frame);
                r.Responses.Add(frame);
                attempt.HttpStatus = body.Response.Status;
                attempt.ResponseSha256 = body.Sha256;
                attempt.ResponseObserved = true;
                attempt.HasProviderContinuation = next is not null;
                attempt.State = start ? WireState.Pending : WireState.Denied;
                attempt.Valid = true;
            }
            // Parsing occurs after this transport returns, under actual native task custody.
            Require(!slot.Token.IsCancellationRequested && !slot.Caller.IsCancellationRequested &&
                !message.CancellationToken.IsCancellationRequested && !r.Revoked && !r.Sealed && !r.Window.Closed &&
                ReferenceEquals(message.Request, request) && ReferenceEquals(request.Content, frozen) &&
                headers.SequenceEqual(request.Headers));
        }
        catch { r.Invalid = true; attempt.Valid = false; throw; }
        finally
        {
            lock (gate)
            {
                attempt.TransportTerminated = true;
                slot.Sending = slot.Invocation.Sending = false;
            }
        }
    }

    internal sealed class StatusDeniedPrivateConnectionDeleteStartProof(Binding binding, StatusTarget target,
        string requestSha256, string nativeRequestId, Task startTask)
    {
        internal Binding Binding { get; } = binding;
        internal StatusTarget Target { get; } = target;
        internal Guid StartDispatch => Target.StartDispatch;
        internal int HttpStatus => 202;
        internal int ResponseBytes => 0;
        internal string ResponseSha256 => Target.StartResponseSha256;
        internal string RequestSha256 { get; } = requestSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal Task StartTask { get; } = startTask;
        internal SecretStatus Outcome => SecretStatus.Success;
        internal NativeProvisioningState State => NativeProvisioningState.Pending;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusDeniedPrivateConnectionDeleteStartProof]";
    }

    internal sealed class StatusDeniedPrivateConnectionDeleteDeniedProof(StatusDeniedPrivateConnectionDeleteStartProof start, Task checkTask,
        int httpStatus, string responseSha256, string nativeRequestId)
    {
        internal StatusDeniedPrivateConnectionDeleteStartProof Start { get; } = start;
        internal Task CheckTask { get; } = checkTask;
        internal int HttpStatus { get; } = httpStatus;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Denied;
        internal NativeProvisioningState State => NativeProvisioningState.Failed;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusDeniedPrivateConnectionDeleteDeniedProof]";
    }

    private sealed class StatusDeniedPrivateConnectionDeleteSlot(CancellationToken token, CancellationToken caller)
    {
        internal readonly CancellationToken Token = token;
        internal readonly CancellationToken Caller = caller;
        internal readonly Invocation Invocation = new();
        internal readonly TaskCompletionSource Drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly HashSet<Request> Requests = new(ReferenceEqualityComparer.Instance);
        internal readonly List<Task> Sends = [];
        internal readonly List<StatusPendingPurgeResponse> Responses = [];
        internal Task? NativeTask;
        internal int Factories, SendCount;
        internal bool FactoryActive, Sending, HookReturned, Success, Finished;
    }

    private sealed class StatusDeniedPrivateConnectionDeleteRegistration(Window window)
    {
        internal readonly Window Window = window;
        internal readonly List<OwnedArmResponse.Storage> Storage = [];
        internal readonly List<StatusPendingPurgeResponse> Responses = [];
        internal readonly ManagementScope InitialScope = window.Binding.Resource;
        internal EmptyNotificationResponseCustody? EmptyCustody;
        internal bool? EmptyComplete;
        internal bool DisposalComplete, DisposalFailed;
        internal Action? BeforeSend;
        internal VaultAdministration? Client;
        internal PrivateConnectionScope? Scope;
        internal ManagementReceipt? Receipt;
        internal ManagementOperation? Handle;
        internal StatusDeniedPrivateConnectionDeleteSlot? Start, Selected;
        internal StatusPendingPurgeStartFacts? Candidate;
        internal StatusDeniedPrivateConnectionDeleteStartProof? StartProof;
        internal StatusDeniedPrivateConnectionDeleteDeniedProof? DeniedProof;
        internal string? AuthorizationSha256;
        internal Task<Capture>? SealTask;
        internal bool Invalid, Revoked, Sealed;
    }

    private sealed record StatusDeniedPrivateConnectionDeleteContext(StatusDeniedPrivateConnectionDeleteRegistration Registration,
        StatusDeniedPrivateConnectionDeleteSlot Slot, bool Start);
    private readonly AsyncLocal<StatusDeniedPrivateConnectionDeleteContext?> currentStatusDeniedPrivateConnectionDelete = new();
    private readonly Dictionary<Window, StatusDeniedPrivateConnectionDeleteRegistration> statusDeniedPrivateConnectionDeletes =
        new(ReferenceEqualityComparer.Instance);

    private static bool StatusDeniedPrivateConnectionDeleteSelector(FixtureSelector selector) =>
        selector is { Operation: "a.management.ManagementOperation.CheckStatusAsync",
            Variant: "operation.DeletePrivateConnection", Case: "denied-authority" };

    internal Window ArmStatusDeniedPrivateConnectionDelete(Binding binding)
    {
        Require(binding is not null && StatusDeniedPrivateConnectionDeleteSelector(binding.Selector) &&
            binding.Operation == ManagementMutation.DeletePrivateConnection &&
            binding.Resource is PrivateConnectionScope && binding.ApiRevision == "2026-02-01");
        var window = Arm(binding);
        lock (gate) statusDeniedPrivateConnectionDeletes.Add(window, new(window));
        return window;
    }

    private StatusDeniedPrivateConnectionDeleteRegistration RequireStatusDeniedPrivateConnectionDelete(Window window, FixtureSelector selector)
    {
        Own(window, selector);
        Require(ReferenceEquals(window.Binding.Selector, selector) && StatusDeniedPrivateConnectionDeleteSelector(selector));
        Require(statusDeniedPrivateConnectionDeletes.TryGetValue(window, out var r) && ReferenceEquals(r.Window, window));
        return r;
    }

    private bool StatusDeniedPrivateConnectionDeleteTargetValid(StatusDeniedPrivateConnectionDeleteRegistration r, Binding binding) =>
        ReferenceEquals(r.Window.Binding, binding) && ReferenceEquals(binding.Resource, r.Scope) &&
        StatusDeniedPrivateConnectionDeleteLive(r) &&
        r.Start is { Finished: true, HookReturned: true, Success: true } &&
        r.Start.Drained.Task.IsCompletedSuccessfully && r.StartProof is { } proof &&
        ReferenceEquals(proof.Binding, binding) && ReferenceEquals(proof.StartTask, r.Start.NativeTask) &&
        ReferenceEquals(targets.GetValueOrDefault(r.Window), proof.Target) &&
        r.Receipt!.Evidence == DispatchEvidence.Pending;

    private static bool StatusDeniedPrivateConnectionDeleteHistoryValid(StatusDeniedPrivateConnectionDeleteRegistration r) =>
        !r.Invalid && !r.DisposalFailed &&
        (r.EmptyComplete ?? (r.EmptyCustody is null || r.EmptyCustody.Complete)) &&
        r.Responses.All(response => response.Valid);

    private static bool StatusDeniedPrivateConnectionDeleteLive(StatusDeniedPrivateConnectionDeleteRegistration r) =>
        StatusDeniedPrivateConnectionDeleteHistoryValid(r) && !r.Revoked && !r.Sealed && !r.Window.Closed &&
        !(r.Start?.Token.IsCancellationRequested ?? false) &&
        !(r.Selected?.Token.IsCancellationRequested ?? false) &&
        !(r.Selected?.Caller.IsCancellationRequested ?? false);

    internal async Task<SecretOutcome<ManagementOperation>> StartStatusDeniedPrivateConnectionDeleteAsync(Window window,
        FixtureSelector selector, VaultAdministration client, ManagementScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token = default, Action<Task>? retained = null,
        Action? beforeSend = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(receipt);
        StatusDeniedPrivateConnectionDeleteRegistration r;
        StatusDeniedPrivateConnectionDeleteSlot slot;
        lock (gate)
        {
            r = RequireStatusDeniedPrivateConnectionDelete(window, selector);
            bool valid = StatusDeniedPrivateConnectionDeleteLive(r) && r.Start is null && window.Start is null &&
                scope is PrivateConnectionScope && ReferenceEquals(window.Binding.Resource, r.InitialScope) &&
                Route(window.Binding with { Resource = scope }) == Route(window.Binding) &&
                input is not null && InputMatches(window.Binding, input) &&
                input.StatusOperation == ManagementMutation.DeletePrivateConnection &&
                receipt.Evidence == DispatchEvidence.NotDispatched &&
                !token.IsCancellationRequested && !startedWindows.Contains(window);
            r.Invalid |= !valid;
            Require(valid);
            window.Binding.Resource = scope;
            r.BeforeSend = beforeSend;
            r.Client = client;
            r.Scope = (PrivateConnectionScope)scope;
            r.Receipt = receipt;
            r.Start = slot = new(token, token);
            window.Start = slot.Invocation;
            startedWindows.Add(window);
        }
        try
        {
            var previous = currentStatusDeniedPrivateConnectionDelete.Value;
            currentStatusDeniedPrivateConnectionDelete.Value = new(r, slot, true);
            Task<SecretOutcome<ManagementOperation>> task;
            try
            {
                task = client.DeletePrivateConnectionAsync((PrivateConnectionScope)scope, receipt, token).AsTask();
                slot.NativeTask = slot.Invocation.SdkTask = task;
            }
            finally { currentStatusDeniedPrivateConnectionDelete.Value = previous; }
            try { retained?.Invoke(task); slot.HookReturned = true; }
            finally
            {
                var result = await task.ConfigureAwait(false);
                r.Handle = result.IsSuccess ? result.Value : null;
                slot.Invocation.Outcome = result.Status;
                slot.Invocation.WrapperState = r.Handle?.State;
                slot.Invocation.HasNativeHandle = r.Handle is not null;
                slot.Success = result.IsSuccess && r.Handle?.State == NativeProvisioningState.Pending &&
                    receipt.Evidence == DispatchEvidence.Pending;
            }
            return await task.ConfigureAwait(false);
        }
        catch { r.Invalid = true; throw; }
        finally { await FinishStatusDeniedPrivateConnectionDeleteAsync(r, slot, start: true).ConfigureAwait(false); }
    }

    internal ValueTask<SecretStatus> CheckStatusDeniedPrivateConnectionDeleteAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null) =>
        CheckStatusDeniedPrivateConnectionDeleteCoreAsync(window, selector, handle, token, retained, token);

    private async ValueTask<SecretStatus> CheckStatusDeniedPrivateConnectionDeleteCoreAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained, CancellationToken originalCallerToken)
    {
        StatusDeniedPrivateConnectionDeleteRegistration r;
        StatusDeniedPrivateConnectionDeleteSlot slot;
        lock (gate)
        {
            r = RequireStatusDeniedPrivateConnectionDelete(window, selector);
            bool valid = StatusDeniedPrivateConnectionDeleteLive(r) && r.StartProof is not null &&
                r.Start is { Finished: true } && r.Start.Drained.Task.IsCompletedSuccessfully &&
                r.Selected is null && ReferenceEquals(r.Handle, handle) &&
                handle.State == NativeProvisioningState.Pending && r.Receipt!.Evidence == DispatchEvidence.Pending &&
                !token.IsCancellationRequested && !originalCallerToken.IsCancellationRequested;
            r.Invalid |= !valid;
            Require(valid);
            r.Selected = slot = new(token, originalCallerToken);
            window.Status = slot.Invocation;
        }
        try
        {
            var previous = currentStatusDeniedPrivateConnectionDelete.Value;
            currentStatusDeniedPrivateConnectionDelete.Value = new(r, slot, false);
            Task<SecretStatus> task;
            try
            {
                task = handle.CheckStatusAsync(token).AsTask();
                slot.NativeTask = slot.Invocation.SdkTask = task;
            }
            finally { currentStatusDeniedPrivateConnectionDelete.Value = previous; }
            try { retained?.Invoke(task); slot.HookReturned = true; }
            finally
            {
                var result = await task.ConfigureAwait(false);
                slot.Invocation.Outcome = result;
                slot.Invocation.WrapperState = handle.State;
                slot.Success = result == SecretStatus.Denied && handle.State == NativeProvisioningState.Failed &&
                    r.Receipt!.Evidence == DispatchEvidence.Pending;
            }
            return await task.ConfigureAwait(false);
        }
        catch { r.Invalid = true; throw; }
        finally { await FinishStatusDeniedPrivateConnectionDeleteAsync(r, slot, start: false).ConfigureAwait(false); }
    }

    private async Task FinishStatusDeniedPrivateConnectionDeleteAsync(StatusDeniedPrivateConnectionDeleteRegistration r, StatusDeniedPrivateConnectionDeleteSlot slot, bool start)
    {
        try
        {
            if (slot.NativeTask is not null)
                try { await slot.NativeTask.ConfigureAwait(false); } catch { r.Invalid = true; }
            Task[] sends;
            lock (gate) sends = slot.Sends.ToArray();
            try { await Task.WhenAll(sends).ConfigureAwait(false); } catch { r.Invalid = true; }
            if (!start)
            {
                // Native task, hook and every actual send have ended. Freeze the
                // empty rebuffer before disposal; Complete cannot run afterwards.
                try
                {
                    lock (gate)
                    {
                        r.Invalid |= !StatusDeniedPrivateConnectionDeleteHistoryValid(r) ||
                            slot.FactoryActive || slot.Sending ||
                            r.Start is not { Finished: true, FactoryActive: false, Sending: false };
                        r.EmptyComplete = r.EmptyCustody?.Complete == true;
                        r.Invalid |= r.EmptyComplete != true;
                    }
                }
                catch { r.Invalid = true; r.EmptyComplete = false; }
                foreach (var storage in r.Storage)
                    try { storage.Dispose(); } catch { r.DisposalFailed = r.Invalid = true; }
                r.Storage.Clear();
                r.DisposalComplete = !r.DisposalFailed;
                r.Invalid |= !StatusDeniedPrivateConnectionDeleteHistoryValid(r);
            }
            lock (gate)
            {
                bool valid = StatusDeniedPrivateConnectionDeleteLive(r) && !slot.Token.IsCancellationRequested &&
                    slot.NativeTask is { IsCompletedSuccessfully: true } && slot.HookReturned && slot.Success &&
                    !slot.FactoryActive && !slot.Sending && slot.Factories == 1 && slot.SendCount == 1 &&
                    slot.Sends.Count == 1 && (start ? r.EmptyCustody is not null && r.Candidate is not null :
                        slot.Responses.Count == 1 && r.DisposalComplete) &&
                    r.Receipt!.Evidence == DispatchEvidence.Pending;
                r.Invalid |= !valid;
                if (valid && start && r.Candidate is { } candidate)
                {
                    r.StartProof = new(candidate.Binding, candidate.Target,
                        candidate.RequestSha256, candidate.NativeRequestId, slot.NativeTask!);
                    targets[r.Window] = candidate.Target;
                    eligible.Add(r.Window);
                }
                else if (valid && !start && r.StartProof is not null)
                {
                    var body = slot.Responses[0].Body;
                    r.DeniedProof = new(r.StartProof, slot.NativeTask!, body.Response.Status,
                        body.Sha256, body.NativeRequestId);
                }
                else r.Invalid = true;
            }
        }
        finally
        {
            lock (gate)
            {
                slot.Finished = slot.Invocation.Terminated = true;
                slot.Invocation.Drained.TrySetResult();
                slot.Drained.TrySetResult();
            }
        }
    }

    internal bool TryGetStatusDeniedPrivateConnectionDeleteStart(Window window, Binding binding, VaultAdministration client,
        PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        [NotNullWhen(true)] out StatusDeniedPrivateConnectionDeleteStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !ReferenceEquals(window.Owner, owner) ||
                !statusDeniedPrivateConnectionDeletes.TryGetValue(window, out var r) || !StatusDeniedPrivateConnectionDeleteSelector(binding.Selector) ||
                !ReferenceEquals(window.Binding, binding) || !ReferenceEquals(r.Window, window) ||
                !ReferenceEquals(r.Client, client) || !ReferenceEquals(r.Scope, scope) ||
                !ReferenceEquals(binding.Resource, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.Handle, handle) || !ReferenceEquals(r.Start?.NativeTask, startTask) ||
                r.Start is not { Finished: true, HookReturned: true, Success: true } ||
                !r.Start.Drained.Task.IsCompletedSuccessfully || !startTask.IsCompletedSuccessfully ||
                !StatusDeniedPrivateConnectionDeleteHistoryValid(r) || r.Sealed ||
                r.Start.Token.IsCancellationRequested || (r.Selected?.Token.IsCancellationRequested ?? false) ||
                (r.Selected?.Caller.IsCancellationRequested ?? false) ||
                receipt.Evidence != DispatchEvidence.Pending || r.StartProof is not { } issued ||
                !ReferenceEquals(issued.StartTask, startTask) ||
                !ReferenceEquals(targets.GetValueOrDefault(window), issued.Target))
                return false;
            proof = issued;
            return true;
        }
    }

    internal bool TryGetStatusDeniedPrivateConnectionDeleteDenied(Window window, Binding binding, VaultAdministration client,
        PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task checkTask,
        [NotNullWhen(true)] out StatusDeniedPrivateConnectionDeleteDeniedProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusDeniedPrivateConnectionDeleteStart(window, binding, client, scope, receipt, startTask, handle, out var start) ||
                !statusDeniedPrivateConnectionDeletes.TryGetValue(window, out var r) ||
                r.Selected is not { Finished: true, HookReturned: true, Success: true } selected ||
                !selected.Drained.Task.IsCompletedSuccessfully || !ReferenceEquals(selected.NativeTask, checkTask) ||
                !checkTask.IsCompletedSuccessfully || handle.State != NativeProvisioningState.Failed ||
                r.DeniedProof is not { } issued || !ReferenceEquals(issued.Start, start) ||
                !ReferenceEquals(issued.CheckTask, checkTask))
                return false;
            proof = issued;
            return true;
        }
    }

    internal bool OwnsStatusDeniedPrivateConnectionDeleteStart(StatusDeniedPrivateConnectionDeleteStartProof proof, Window window, Binding binding,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle) =>
        TryGetStatusDeniedPrivateConnectionDeleteStart(window, binding, client, scope, receipt, startTask, handle, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool OwnsStatusDeniedPrivateConnectionDeleteDenied(StatusDeniedPrivateConnectionDeleteDeniedProof proof, Window window, Binding binding,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task checkTask) =>
        TryGetStatusDeniedPrivateConnectionDeleteDenied(window, binding, client, scope, receipt, startTask, handle, checkTask, out var issued) &&
        ReferenceEquals(proof, issued);

    internal void RevokeStatusDeniedPrivateConnectionDeleteSelected(Window window)
    {
        lock (gate)
        {
            var r = RequireStatusDeniedPrivateConnectionDelete(window, window.Binding.Selector);
            r.Invalid |= r.Start is not { Finished: true } || r.Selected is not { Finished: true } ||
                r.DeniedProof is null || !StatusDeniedPrivateConnectionDeleteHistoryValid(r) ||
                r.Start.Token.IsCancellationRequested || r.Selected.Token.IsCancellationRequested ||
                r.Selected.Caller.IsCancellationRequested;
            r.Revoked = window.Closed = true;
        }
    }

    private Task<Capture> SealStatusDeniedPrivateConnectionDeleteAsync(Window window)
    {
        StatusDeniedPrivateConnectionDeleteRegistration r;
        TaskCompletionSource ready;
        Task<Capture> task;
        lock (gate)
        {
            r = RequireStatusDeniedPrivateConnectionDelete(window, window.Binding.Selector);
            r.Sealed = r.Revoked = window.Closed = true;
            if (r.SealTask is not null) return r.SealTask;
            ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = r.SealTask = Drain(ready.Task);
        }
        ready.SetResult();
        return task;

        async Task<Capture> Drain(Task admission)
        {
            await admission.ConfigureAwait(false);
            var tasks = new[] { r.Start, r.Selected }.OfType<StatusDeniedPrivateConnectionDeleteSlot>()
                .Select(slot => slot.Drained.Task).ToArray();
            await Task.WhenAll(tasks).ConfigureAwait(false);
            // All admitted native work and hooks have drained. Complete inspects
            // the empty rebuffer and must never be evaluated after disposal.
            if (r.EmptyComplete is null)
            {
                try { r.EmptyComplete = r.EmptyCustody?.Complete == true; }
                catch { r.Invalid = true; r.EmptyComplete = false; }
                r.Invalid |= r.EmptyComplete != true;
            }
            foreach (var storage in r.Storage)
                try { storage.Dispose(); } catch { r.DisposalFailed = r.Invalid = true; }
            r.Storage.Clear();
            r.DisposalComplete = !r.DisposalFailed;
            r.Invalid |= !StatusDeniedPrivateConnectionDeleteHistoryValid(r);
            r.AuthorizationSha256 = null;
            Require(!r.DisposalFailed);
            return new() { Binding = window.Binding, Start = r.Start?.Invocation, Status = r.Selected?.Invocation };
        }
    }

    private async Task SendStatusDeniedPrivateConnectionDeleteAsync(StatusDeniedPrivateConnectionDeleteContext context, HttpMessage message)
    {
        var r = context.Registration;
        var slot = context.Slot;
        bool start = context.Start;
        var request = message.Request;
        var headers = request.Headers.ToArray();
        byte[] requestHashBytes = System.Text.Encoding.UTF8.GetBytes(request.Method + " " + request.Uri.ToUri().AbsoluteUri);
        string requestHash;
        try { requestHash = Convert.ToHexString(SHA256.HashData(requestHashBytes)); }
        finally { CryptographicOperations.ZeroMemory(requestHashBytes); }
        var attempt = new Attempt { Dispatch = Guid.NewGuid(), RequestSha256 = requestHash };
        try
        {
            lock (gate)
            {
                bool valid = StatusDeniedPrivateConnectionDeleteLive(r) && !slot.Finished && !slot.Sending &&
                    slot.Requests.Contains(request) && ++slot.SendCount == 1 && slot.Responses.Count == 0;
                r.Invalid |= !valid;
                Require(valid);
                slot.Sending = slot.Invocation.Sending = true;
                slot.Invocation.Attempts.Add(attempt);
            }
            void Check()
            {
                Require(StatusDeniedPrivateConnectionDeleteLive(r) && !slot.Token.IsCancellationRequested &&
                    !message.CancellationToken.IsCancellationRequested && ReferenceEquals(message.Request, request) &&
                    headers.SequenceEqual(request.Headers));
                OriginalVaultRequest(message, r.Window.Path, start ? RequestMethod.Delete : RequestMethod.Get,
                    start ? null : r.StartProof!.Target.TargetUri.AbsoluteUri);
                Headers(headers);
                Require(!request.Headers.Contains("Range"));
            }
            Check();
            Require(r.Receipt!.Evidence == (start ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Pending));
            request.Headers.TryGetValue("Authorization", out var authorization);
            byte[] authorizationBytes = System.Text.Encoding.UTF8.GetBytes(authorization!);
            string authorizationSha256;
            try { authorizationSha256 = Convert.ToHexString(SHA256.HashData(authorizationBytes)); }
            finally { CryptographicOperations.ZeroMemory(authorizationBytes); }
            if (start) r.AuthorizationSha256 = authorizationSha256;
            else Require(r.AuthorizationSha256 == authorizationSha256);
            lock (gate)
            {
                Require(StatusDeniedPrivateConnectionDeleteHistoryValid(r));
                // Retain original parser custody through the selected native drain.
            }
            var storage = new OwnedArmResponse.Storage();
            lock (gate) r.Storage.Add(storage);
            message.BufferResponse = false;
            if (start) r.BeforeSend?.Invoke();
            Check();
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) storage.Own(message.Response); }
            Check();
            Require(message.HasResponse);
            var original = message.Response;
            var stream = original.ContentStream;
            string? next;
            if (start)
            {
                int status = original.Status;
                string reason = original.ReasonPhrase, clientId = original.ClientRequestId;
                var responseHeaders = original.Headers.Take(33).ToArray();
                Headers(responseHeaders);
                Require(responseHeaders.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == responseHeaders.Length &&
                    responseHeaders.All(h => h.Name.Length > 0 && h.Name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') &&
                        !h.Value.Any(char.IsControl)) &&
                    status == 202 && reason.Length <= 256 && !reason.Any(char.IsControl) &&
                    clientId.Length <= 1024 && !clientId.Any(char.IsControl) &&
                    !responseHeaders.Any(h => new[] { "Operation-Location", "Retry-After", "WWW-Authenticate",
                        "Content-Encoding", "Content-Range", "Transfer-Encoding" }
                        .Contains(h.Name, StringComparer.OrdinalIgnoreCase)));
                var lengths = responseHeaders.Where(h => h.Name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)).ToArray();
                Require(lengths.Length == 0 || lengths is [{ Value: "0" }]);
                Require(original.Headers.TryGetValue("Location", out var location) &&
                    original.Headers.TryGetValue("Azure-AsyncOperation", out var operation) && location == operation &&
                    responseHeaders.FirstOrDefault(h => h.Name.Equals("Location", StringComparison.OrdinalIgnoreCase)).Value == location &&
                    responseHeaders.FirstOrDefault(h => h.Name.Equals("Azure-AsyncOperation", StringComparison.OrdinalIgnoreCase)).Value == operation);
                next = Continuation(r.Window, message);
                Require(next is not null && next == location);
                string? nativeId = responseHeaders.FirstOrDefault(h =>
                    h.Name.Equals("x-ms-request-id", StringComparison.OrdinalIgnoreCase)).Value;
                Require(nativeId is { Length: > 0 and <= 256 } &&
                    nativeId.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.'));
                if (stream is not null)
                {
                    storage.Own(stream);
                    byte[] one = new byte[1];
                    try { Require(await stream.ReadAsync(one, message.CancellationToken).ConfigureAwait(false) == 0); }
                    finally { CryptographicOperations.ZeroMemory(one); }
                }
                Check();
                Require(ReferenceEquals(message.Response, original) && ReferenceEquals(original.ContentStream, stream) &&
                    original.Status == status && original.ReasonPhrase == reason && original.ClientRequestId == clientId &&
                    responseHeaders.SequenceEqual(original.Headers));
                string hash = Convert.ToHexString(SHA256.HashData(ReadOnlySpan<byte>.Empty));
                var buffer = new MemoryStream([], writable: false);
                storage.Own(buffer);
                var owned = new OwnedArmResponse(status, reason, clientId, responseHeaders, buffer);
                r.EmptyCustody = new(message, original, stream, owned, storage);
                byte[] targetBytes = System.Text.Encoding.UTF8.GetBytes(next!);
                byte[] requestBytes = System.Text.Encoding.UTF8.GetBytes("DELETE " + request.Uri.ToUri().AbsoluteUri);
                try
                {
                    var target = new StatusTarget(r.Window.Binding, attempt.Dispatch, StatusTargetKind.Operation, new Uri(next!),
                        Convert.ToHexString(SHA256.HashData(targetBytes)), hash);
                    r.Candidate = new(r.Window.Binding, target, 0,
                        Convert.ToHexString(SHA256.HashData(requestBytes)), nativeId!);
                    Require(attempt.RequestSha256 == r.Candidate.RequestSha256);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(targetBytes);
                    CryptographicOperations.ZeroMemory(requestBytes);
                }
                attempt.HttpStatus = status;
                attempt.ResponseSha256 = hash;
            }
            else
            {
                var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, storage).ConfigureAwait(false);
                Check();
                Require(ReferenceEquals(original.ContentStream, stream) && body.Bytes.Length > 0 &&
                    body.Response.Status is 401 or 403);
                Require(body.Response.Headers.TryGetValue("Content-Type", out var contentType));
                string[] media = contentType.Split(';').Select(value => value.Trim()).ToArray();
                Require(media.Length is 1 or 2 && media[0].Equals("application/json", StringComparison.OrdinalIgnoreCase) &&
                    (media.Length == 1 || media[1].Equals("charset=utf-8", StringComparison.OrdinalIgnoreCase)));
                next = Continuation(r.Window, message);
                Require(next is null);
                using var json = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
                int nodes = 512;
                JsonRows(json.RootElement, ref nodes);
                var root = json.RootElement;
                Require(root.ValueKind == JsonValueKind.Object && root.EnumerateObject().All(p => p.Name == "error") &&
                    root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object &&
                    error.EnumerateObject().All(p => p.Name is "code" or "message") &&
                    error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String &&
                    code.GetString() is { Length: > 0 and <= 128 } errorCode && !errorCode.Any(char.IsControl) &&
                    error.TryGetProperty("message", out var text) && text.ValueKind == JsonValueKind.String &&
                    text.GetString() is { Length: > 0 and <= 2048 } errorMessage && !errorMessage.Any(char.IsControl));
                var parser = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, storage,
                    requireRebuffer: true, requireDownstreamRead: true);
                var frame = new StatusPendingPurgeResponse(body, parser, storage);
                lock (gate)
                {
                    slot.Responses.Add(frame);
                    r.Responses.Add(frame);
                    attempt.HttpStatus = body.Response.Status;
                    attempt.ResponseSha256 = body.Sha256;
                }
            }
            lock (gate)
            {
                attempt.ResponseObserved = true;
                attempt.HasProviderContinuation = next is not null;
                attempt.State = start ? WireState.Pending : WireState.Denied;
                attempt.Valid = true;
            }
            // Parser consumption has not happened yet; only recheck request and lifetime here.
            Require(!slot.Token.IsCancellationRequested && !message.CancellationToken.IsCancellationRequested &&
                !r.Revoked && !r.Sealed && !r.Window.Closed && ReferenceEquals(message.Request, request) &&
                headers.SequenceEqual(request.Headers));
        }
        catch { r.Invalid = true; attempt.Valid = false; throw; }
        finally
        {
            lock (gate)
            {
                attempt.TransportTerminated = true;
                slot.Sending = slot.Invocation.Sending = false;
            }
        }
    }

    internal sealed class StatusDeniedPurgeStartProof(Binding binding, StatusTarget target,
        int responseBytes, string requestSha256, string nativeRequestId, Task startTask)
    {
        internal Binding Binding { get; } = binding;
        internal StatusTarget Target { get; } = target;
        internal Guid StartDispatch => Target.StartDispatch;
        internal int HttpStatus => 202;
        internal int ResponseBytes { get; } = responseBytes;
        internal string ResponseSha256 => Target.StartResponseSha256;
        internal string RequestSha256 { get; } = requestSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal Task StartTask { get; } = startTask;
        internal SecretStatus Outcome => SecretStatus.Success;
        internal NativeProvisioningState State => NativeProvisioningState.Pending;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusDeniedPurgeStartProof]";
    }

    internal sealed class StatusDeniedPurgeDeniedProof(StatusDeniedPurgeStartProof start, Task checkTask,
        int httpStatus, string responseSha256, string nativeRequestId)
    {
        internal StatusDeniedPurgeStartProof Start { get; } = start;
        internal Task CheckTask { get; } = checkTask;
        internal int HttpStatus { get; } = httpStatus;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Denied;
        internal NativeProvisioningState State => NativeProvisioningState.Failed;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusDeniedPurgeDeniedProof]";
    }

    private sealed class StatusDeniedPurgeSlot(CancellationToken token)
    {
        internal readonly CancellationToken Token = token;
        internal readonly Invocation Invocation = new();
        internal readonly TaskCompletionSource Drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly HashSet<Request> Requests = new(ReferenceEqualityComparer.Instance);
        internal readonly List<Task> Sends = [];
        internal readonly List<StatusPendingPurgeResponse> Responses = [];
        internal Task? NativeTask;
        internal int Factories, SendCount;
        internal bool FactoryActive, Sending, HookReturned, Success, Finished;
    }

    private sealed class StatusDeniedPurgeRegistration(Window window)
    {
        internal readonly Window Window = window;
        internal readonly List<OwnedArmResponse.Storage> Storage = [];
        internal readonly List<StatusPendingPurgeResponse> Responses = [];
        internal VaultAdministration? Client;
        internal DeletedVaultScope? Scope;
        internal ManagementReceipt? Receipt;
        internal ManagementOperation? Handle;
        internal StatusDeniedPurgeSlot? Start, Selected;
        internal StatusPendingPurgeStartFacts? Candidate;
        internal StatusDeniedPurgeStartProof? StartProof;
        internal StatusDeniedPurgeDeniedProof? DeniedProof;
        internal string? AuthorizationSha256;
        internal Task<Capture>? SealTask;
        internal bool Invalid, Revoked, Sealed;
    }

    private sealed record StatusDeniedPurgeContext(StatusDeniedPurgeRegistration Registration,
        StatusDeniedPurgeSlot Slot, bool Start);
    private readonly AsyncLocal<StatusDeniedPurgeContext?> currentStatusDeniedPurge = new();
    private readonly Dictionary<Window, StatusDeniedPurgeRegistration> statusDeniedPurges =
        new(ReferenceEqualityComparer.Instance);

    private static bool StatusDeniedPurgeSelector(FixtureSelector selector) =>
        selector is { Operation: "a.management.ManagementOperation.CheckStatusAsync",
            Variant: "operation.PurgeDeletedVault" or "status.Succeeded" or "status.Pending" or
                "status.Failed" or "status.Canceled" or "status.Unknown", Case: "denied-authority" };

    internal Window ArmStatusDeniedPurge(Binding binding)
    {
        Require(binding is not null && StatusDeniedPurgeSelector(binding.Selector) &&
            binding.Operation == ManagementMutation.PurgeDeletedVault &&
            binding.Resource is DeletedVaultScope && binding.ApiRevision == "2026-02-01");
        var window = Arm(binding);
        lock (gate) statusDeniedPurges.Add(window, new(window));
        return window;
    }

    private StatusDeniedPurgeRegistration RequireStatusDeniedPurge(Window window, FixtureSelector selector)
    {
        Own(window, selector);
        Require(ReferenceEquals(window.Binding.Selector, selector) && StatusDeniedPurgeSelector(selector));
        Require(statusDeniedPurges.TryGetValue(window, out var r) && ReferenceEquals(r.Window, window));
        return r;
    }

    private bool StatusDeniedPurgeTargetValid(StatusDeniedPurgeRegistration r, Binding binding) =>
        ReferenceEquals(r.Window.Binding, binding) && StatusDeniedPurgeLive(r) &&
        r.Start is { Finished: true, HookReturned: true, Success: true } &&
        r.Start.Drained.Task.IsCompletedSuccessfully && r.StartProof is { } proof &&
        ReferenceEquals(proof.Binding, binding) && ReferenceEquals(proof.StartTask, r.Start.NativeTask) &&
        ReferenceEquals(targets.GetValueOrDefault(r.Window), proof.Target) &&
        r.Receipt!.Evidence == DispatchEvidence.Pending;

    private static bool StatusDeniedPurgeHistoryValid(StatusDeniedPurgeRegistration r) =>
        !r.Invalid && r.Responses.All(response => response.Valid);

    private static bool StatusDeniedPurgeLive(StatusDeniedPurgeRegistration r) =>
        StatusDeniedPurgeHistoryValid(r) && !r.Revoked && !r.Sealed && !r.Window.Closed &&
        !(r.Start?.Token.IsCancellationRequested ?? false) &&
        !(r.Selected?.Token.IsCancellationRequested ?? false);

    internal async ValueTask<SecretOutcome<ManagementOperation>> StartStatusDeniedPurgeAsync(Window window,
        FixtureSelector selector, VaultAdministration client, ManagementScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token, Action<Task>? retained = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(receipt);
        StatusDeniedPurgeRegistration r;
        StatusDeniedPurgeSlot slot;
        lock (gate)
        {
            r = RequireStatusDeniedPurge(window, selector);
            bool valid = StatusDeniedPurgeLive(r) && r.Start is null && window.Start is null &&
                scope is DeletedVaultScope && ReferenceEquals(window.Binding.Resource, scope) &&
                input is not null && InputMatches(window.Binding, input) &&
                input.StatusOperation == ManagementMutation.PurgeDeletedVault &&
                receipt.Evidence == DispatchEvidence.NotDispatched &&
                !token.IsCancellationRequested && !startedWindows.Contains(window);
            r.Invalid |= !valid;
            Require(valid);
            r.Client = client;
            r.Scope = (DeletedVaultScope)scope;
            r.Receipt = receipt;
            r.Start = slot = new(token);
            window.Start = slot.Invocation;
            startedWindows.Add(window);
        }
        try
        {
            var previous = currentStatusDeniedPurge.Value;
            currentStatusDeniedPurge.Value = new(r, slot, true);
            Task<SecretOutcome<ManagementOperation>> task;
            try
            {
                task = client.PurgeDeletedVaultAsync((DeletedVaultScope)scope, receipt, token).AsTask();
                slot.NativeTask = slot.Invocation.SdkTask = task;
            }
            finally { currentStatusDeniedPurge.Value = previous; }
            try { retained?.Invoke(task); slot.HookReturned = true; }
            finally
            {
                var result = await task.ConfigureAwait(false);
                r.Handle = result.IsSuccess ? result.Value : null;
                slot.Invocation.Outcome = result.Status;
                slot.Invocation.WrapperState = r.Handle?.State;
                slot.Invocation.HasNativeHandle = r.Handle is not null;
                slot.Success = result.IsSuccess && r.Handle?.State == NativeProvisioningState.Pending &&
                    receipt.Evidence == DispatchEvidence.Pending;
            }
            return await task.ConfigureAwait(false);
        }
        catch { r.Invalid = true; throw; }
        finally { await FinishStatusDeniedPurgeAsync(r, slot, start: true).ConfigureAwait(false); }
    }

    internal async ValueTask<SecretStatus> CheckStatusDeniedPurgeAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null)
    {
        StatusDeniedPurgeRegistration r;
        StatusDeniedPurgeSlot slot;
        lock (gate)
        {
            r = RequireStatusDeniedPurge(window, selector);
            bool valid = StatusDeniedPurgeLive(r) && r.StartProof is not null &&
                r.Start is { Finished: true } && r.Start.Drained.Task.IsCompletedSuccessfully &&
                r.Selected is null && ReferenceEquals(r.Handle, handle) &&
                handle.State == NativeProvisioningState.Pending && r.Receipt!.Evidence == DispatchEvidence.Pending &&
                !token.IsCancellationRequested;
            r.Invalid |= !valid;
            Require(valid);
            r.Selected = slot = new(token);
            window.Status = slot.Invocation;
        }
        try
        {
            var previous = currentStatusDeniedPurge.Value;
            currentStatusDeniedPurge.Value = new(r, slot, false);
            Task<SecretStatus> task;
            try
            {
                task = handle.CheckStatusAsync(token).AsTask();
                slot.NativeTask = slot.Invocation.SdkTask = task;
            }
            finally { currentStatusDeniedPurge.Value = previous; }
            try { retained?.Invoke(task); slot.HookReturned = true; }
            finally
            {
                var result = await task.ConfigureAwait(false);
                slot.Invocation.Outcome = result;
                slot.Invocation.WrapperState = handle.State;
                slot.Success = result == SecretStatus.Denied && handle.State == NativeProvisioningState.Failed &&
                    r.Receipt!.Evidence == DispatchEvidence.Pending;
            }
            return await task.ConfigureAwait(false);
        }
        catch { r.Invalid = true; throw; }
        finally { await FinishStatusDeniedPurgeAsync(r, slot, start: false).ConfigureAwait(false); }
    }

    private async Task FinishStatusDeniedPurgeAsync(StatusDeniedPurgeRegistration r, StatusDeniedPurgeSlot slot, bool start)
    {
        try
        {
            if (slot.NativeTask is not null)
                try { await slot.NativeTask.ConfigureAwait(false); } catch { r.Invalid = true; }
            Task[] sends;
            lock (gate) sends = slot.Sends.ToArray();
            try { await Task.WhenAll(sends).ConfigureAwait(false); } catch { r.Invalid = true; }
            if (!start)
            {
                r.Invalid |= !StatusDeniedPurgeHistoryValid(r);
                foreach (var storage in r.Storage)
                    try { storage.Dispose(); } catch { r.Invalid = true; }
                r.Storage.Clear();
                r.Invalid |= !StatusDeniedPurgeHistoryValid(r);
            }
            lock (gate)
            {
                bool valid = StatusDeniedPurgeLive(r) && !slot.Token.IsCancellationRequested &&
                    slot.NativeTask is { IsCompletedSuccessfully: true } && slot.HookReturned && slot.Success &&
                    !slot.FactoryActive && !slot.Sending && slot.Factories == 1 && slot.SendCount == 1 &&
                    slot.Sends.Count == 1 && slot.Responses.Count == 1 &&
                    r.Receipt!.Evidence == DispatchEvidence.Pending;
                r.Invalid |= !valid;
                if (valid && start && r.Candidate is { } candidate)
                {
                    r.StartProof = new(candidate.Binding, candidate.Target, candidate.ResponseBytes,
                        candidate.RequestSha256, candidate.NativeRequestId, slot.NativeTask!);
                    targets[r.Window] = candidate.Target;
                    eligible.Add(r.Window);
                }
                else if (valid && !start && r.StartProof is not null)
                {
                    var body = slot.Responses[0].Body;
                    r.DeniedProof = new(r.StartProof, slot.NativeTask!, body.Response.Status,
                        body.Sha256, body.NativeRequestId);
                }
                else r.Invalid = true;
            }
        }
        finally
        {
            lock (gate)
            {
                slot.Finished = slot.Invocation.Terminated = true;
                slot.Invocation.Drained.TrySetResult();
                slot.Drained.TrySetResult();
            }
        }
    }

    internal bool TryGetStatusDeniedPurgeStart(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        [NotNullWhen(true)] out StatusDeniedPurgeStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !ReferenceEquals(window.Owner, owner) ||
                !statusDeniedPurges.TryGetValue(window, out var r) || !StatusDeniedPurgeSelector(binding.Selector) ||
                !ReferenceEquals(window.Binding, binding) || !ReferenceEquals(r.Window, window) ||
                !ReferenceEquals(r.Client, client) || !ReferenceEquals(r.Scope, scope) ||
                !ReferenceEquals(binding.Resource, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.Handle, handle) || !ReferenceEquals(r.Start?.NativeTask, startTask) ||
                r.Start is not { Finished: true, HookReturned: true, Success: true } ||
                !r.Start.Drained.Task.IsCompletedSuccessfully || !startTask.IsCompletedSuccessfully ||
                !StatusDeniedPurgeHistoryValid(r) || r.Sealed ||
                r.Start.Token.IsCancellationRequested || (r.Selected?.Token.IsCancellationRequested ?? false) ||
                receipt.Evidence != DispatchEvidence.Pending || r.StartProof is not { } issued ||
                !ReferenceEquals(issued.StartTask, startTask) ||
                !ReferenceEquals(targets.GetValueOrDefault(window), issued.Target))
                return false;
            proof = issued;
            return true;
        }
    }

    internal bool TryGetStatusDeniedPurgeDenied(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task checkTask,
        [NotNullWhen(true)] out StatusDeniedPurgeDeniedProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusDeniedPurgeStart(window, binding, client, scope, receipt, startTask, handle, out var start) ||
                !statusDeniedPurges.TryGetValue(window, out var r) ||
                r.Selected is not { Finished: true, HookReturned: true, Success: true } selected ||
                !selected.Drained.Task.IsCompletedSuccessfully || !ReferenceEquals(selected.NativeTask, checkTask) ||
                !checkTask.IsCompletedSuccessfully || handle.State != NativeProvisioningState.Failed ||
                r.DeniedProof is not { } issued || !ReferenceEquals(issued.Start, start) ||
                !ReferenceEquals(issued.CheckTask, checkTask))
                return false;
            proof = issued;
            return true;
        }
    }

    internal bool OwnsStatusDeniedPurgeStart(StatusDeniedPurgeStartProof proof, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle) =>
        TryGetStatusDeniedPurgeStart(window, binding, client, scope, receipt, startTask, handle, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool OwnsStatusDeniedPurgeDenied(StatusDeniedPurgeDeniedProof proof, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task checkTask) =>
        TryGetStatusDeniedPurgeDenied(window, binding, client, scope, receipt, startTask, handle, checkTask, out var issued) &&
        ReferenceEquals(proof, issued);

    internal void RevokeStatusDeniedPurgeSelected(Window window)
    {
        lock (gate)
        {
            var r = RequireStatusDeniedPurge(window, window.Binding.Selector);
            r.Invalid |= r.Start is not { Finished: true } || r.Selected is not { Finished: true } ||
                r.DeniedProof is null || !StatusDeniedPurgeHistoryValid(r) ||
                r.Start.Token.IsCancellationRequested || r.Selected.Token.IsCancellationRequested;
            r.Revoked = window.Closed = true;
        }
    }

    private Task<Capture> SealStatusDeniedPurgeAsync(Window window)
    {
        lock (gate)
        {
            var r = RequireStatusDeniedPurge(window, window.Binding.Selector);
            r.Sealed = r.Revoked = window.Closed = true;
            return r.SealTask ??= Drain();

            async Task<Capture> Drain()
            {
                var tasks = new[] { r.Start, r.Selected }.OfType<StatusDeniedPurgeSlot>()
                    .Select(slot => slot.Drained.Task).ToArray();
                await Task.WhenAll(tasks).ConfigureAwait(false);
                bool failed = false;
                foreach (var storage in r.Storage)
                    try { storage.Dispose(); } catch { failed = true; }
                r.Storage.Clear();
                r.AuthorizationSha256 = null;
                r.Invalid |= failed;
                Require(!failed);
                return new() { Binding = window.Binding, Start = r.Start?.Invocation, Status = r.Selected?.Invocation };
            }
        }
    }

    private async Task SendStatusDeniedPurgeAsync(StatusDeniedPurgeContext context, HttpMessage message)
    {
        var r = context.Registration;
        var slot = context.Slot;
        bool start = context.Start;
        var request = message.Request;
        var headers = request.Headers.ToArray();
        var attempt = new Attempt { Dispatch = Guid.NewGuid() };
        try
        {
            lock (gate)
            {
                bool valid = StatusDeniedPurgeLive(r) && !slot.Finished && !slot.Sending &&
                    slot.Requests.Contains(request) && ++slot.SendCount == 1 && slot.Responses.Count == 0;
                r.Invalid |= !valid;
                Require(valid);
                slot.Sending = slot.Invocation.Sending = true;
                slot.Invocation.Attempts.Add(attempt);
            }
            void Check()
            {
                Require(StatusDeniedPurgeLive(r) && !slot.Token.IsCancellationRequested &&
                    !message.CancellationToken.IsCancellationRequested && ReferenceEquals(message.Request, request) &&
                    headers.SequenceEqual(request.Headers));
                OriginalVaultRequest(message, r.Window.Path, start ? RequestMethod.Post : RequestMethod.Get,
                    start ? null : r.StartProof!.Target.TargetUri.AbsoluteUri);
                Headers(headers);
                Require(!request.Headers.Contains("Range"));
            }
            Check();
            Require(r.Receipt!.Evidence == (start ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Pending));
            request.Headers.TryGetValue("Authorization", out var authorization);
            byte[] authorizationBytes = System.Text.Encoding.UTF8.GetBytes(authorization!);
            string authorizationSha256;
            try { authorizationSha256 = Convert.ToHexString(SHA256.HashData(authorizationBytes)); }
            finally { CryptographicOperations.ZeroMemory(authorizationBytes); }
            if (start) r.AuthorizationSha256 = authorizationSha256;
            else Require(r.AuthorizationSha256 == authorizationSha256);
            lock (gate)
            {
                Require(StatusDeniedPurgeHistoryValid(r));
                foreach (var response in r.Responses) response.Superseded = true;
            }
            var storage = new OwnedArmResponse.Storage();
            lock (gate) r.Storage.Add(storage);
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) storage.Own(message.Response); }
            Check();
            Require(message.HasResponse);
            var original = message.Response;
            var stream = original.ContentStream;
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, storage, allowContinuation: start)
                .ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(original.ContentStream, stream) && body.Bytes.Length > 0 &&
                (start ? body.Response.Status == 202 : body.Response.Status is 401 or 403) &&
                !body.Response.Headers.Contains("WWW-Authenticate"));
            string? next = Continuation(r.Window, message);
            Require(start ? next is not null : next is null);
            using var json = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int nodes = 512;
            JsonRows(json.RootElement, ref nodes);
            var root = json.RootElement;
            Require(root.ValueKind == JsonValueKind.Object);
            if (start)
            {
                Require(root.EnumerateObject().All(p => p.Name is "id" or "status" or "properties"));
                if (root.TryGetProperty("id", out var id)) Require(id.GetString() == r.Window.Path);
                bool direct = root.TryGetProperty("status", out var state);
                bool nested = root.TryGetProperty("properties", out var properties);
                Require(direct != nested);
                if (nested) Require(properties.ValueKind == JsonValueKind.Object &&
                    properties.EnumerateObject().All(p => p.Name == "provisioningState"));
                Require((direct ? state.GetString() : properties.GetProperty("provisioningState").GetString()) == "InProgress");
                byte[] targetBytes = System.Text.Encoding.UTF8.GetBytes(next!);
                byte[] requestBytes = System.Text.Encoding.UTF8.GetBytes("POST " + request.Uri.ToUri().AbsoluteUri);
                try
                {
                    var target = new StatusTarget(r.Window.Binding, attempt.Dispatch, StatusTargetKind.Operation, new Uri(next!),
                        Convert.ToHexString(SHA256.HashData(targetBytes)), body.Sha256);
                    r.Candidate = new(r.Window.Binding, target, body.Bytes.Length,
                        Convert.ToHexString(SHA256.HashData(requestBytes)), body.NativeRequestId);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(targetBytes);
                    CryptographicOperations.ZeroMemory(requestBytes);
                }
            }
            else
            {
                Require(root.EnumerateObject().All(p => p.Name == "error") &&
                    root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object &&
                    error.EnumerateObject().All(p => p.Name is "code" or "message") &&
                    error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String &&
                    code.GetString() is { Length: > 0 and <= 128 } errorCode && !errorCode.Any(char.IsControl) &&
                    error.TryGetProperty("message", out var text) && text.ValueKind == JsonValueKind.String &&
                    text.GetString() is { Length: > 0 and <= 2048 } errorMessage && !errorMessage.Any(char.IsControl));
            }
            var parser = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, storage,
                requireRebuffer: true, requireDownstreamRead: !start);
            var frame = new StatusPendingPurgeResponse(body, parser, storage);
            lock (gate)
            {
                slot.Responses.Add(frame);
                r.Responses.Add(frame);
                attempt.HttpStatus = body.Response.Status;
                attempt.ResponseSha256 = body.Sha256;
                attempt.ResponseObserved = true;
                attempt.HasProviderContinuation = next is not null;
                attempt.State = start ? WireState.Pending : WireState.Denied;
                attempt.Valid = true;
            }
            // Parser consumption has not happened yet; only recheck request and lifetime here.
            Require(!slot.Token.IsCancellationRequested && !message.CancellationToken.IsCancellationRequested &&
                !r.Revoked && !r.Sealed && !r.Window.Closed && ReferenceEquals(message.Request, request) &&
                headers.SequenceEqual(request.Headers));
        }
        catch { r.Invalid = true; attempt.Valid = false; throw; }
        finally
        {
            lock (gate)
            {
                attempt.TransportTerminated = true;
                slot.Sending = slot.Invocation.Sending = false;
            }
        }
    }

    internal sealed record Binding(
        [property: JsonIgnore] FixtureSelector Selector,
        [property: JsonIgnore] Guid LeaseId,
        ManagementScope Resource,
        [property: JsonIgnore] ManagementMutation Operation,
        [property: JsonIgnore] string Location,
        [property: JsonIgnore] string ApiRevision)
    {
        [JsonIgnore] public ManagementScope Resource { get; internal set; } = Resource;
        public override string ToString() => "[ManagementOperationNativeBinding]";
    }

    internal sealed class Attempt
    {
        internal Guid Dispatch { get; init; }
        internal int? HttpStatus { get; set; }
        internal bool ResponseObserved { get; set; }
        internal bool TransportTerminated { get; set; }
        internal bool Valid { get; set; }
        internal bool HasProviderContinuation { get; set; }
        internal string? RequestSha256 { get; init; }
        internal string? ResponseSha256 { get; set; }
        internal WireState State { get; set; } = WireState.Lost;
        public override string ToString() => "[ManagementOperationNativeAttempt]";
    }

    internal sealed class Invocation
    {
        // The actual whole selected SDK Task, not a transport-send completion.
        internal Task? SdkTask;
        internal bool Terminated;
        internal bool Canceled;
        internal SecretStatus? Outcome;
        internal NativeProvisioningState? WrapperState;
        internal readonly List<Attempt> Attempts = [];
        internal readonly List<byte[]> Owned = [];
        internal readonly List<IDisposable> Snapshots = [];
        internal readonly TaskCompletionSource Drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool Sending;
        internal WireState Evidence => Attempts.Count == 0 ? WireState.Unavailable : Attempts[^1].State;
        internal bool HasNativeHandle;
        public override string ToString() => "[ManagementOperationNativeInvocation]";
    }

    internal sealed class Window
    {
        internal Window(object owner, Binding binding, string path, RequestMethod method)
        {
            Owner = owner;
            Binding = binding;
            Path = path;
            Method = method;
        }
        internal object Owner { get; }
        internal Binding Binding { get; }
        internal string Path { get; }
        internal RequestMethod Method { get; }
        internal Invocation? Start, Status;
        internal string? Continuation;
        internal bool Closed;
        public override string ToString() => "[ManagementOperationNativeWindow]";
    }

    internal sealed class Capture
    {
        internal required Binding Binding { get; init; }
        internal Invocation? Start { get; init; }
        internal Invocation? Status { get; init; }
        public override string ToString() => "[ManagementOperationNativeCapture]";
    }

    internal enum StatusTargetKind { Operation, SelectedResource }
    internal sealed class StatusTarget(Binding binding, Guid startDispatch, StatusTargetKind kind,
        Uri targetUri, string targetSha256, string startResponseSha256)
    {
        internal Binding Binding { get; } = binding;
        internal Guid StartDispatch { get; } = startDispatch;
        internal StatusTargetKind Kind { get; } = kind;
        internal Uri TargetUri { get; } = targetUri;
        internal string TargetSha256 { get; } = targetSha256;
        internal string StartResponseSha256 { get; } = startResponseSha256;
        public override string ToString() => "[ManagementOperationStatusTarget]";
    }

    internal sealed class SynchronousDeleteProof
    {
        internal SynchronousDeleteProof(Binding binding, Guid startDispatch, int httpStatus,
            int responseBytes, string responseSha256)
        {
            Binding = binding;
            StartDispatch = startDispatch;
            HttpStatus = httpStatus;
            ResponseBytes = responseBytes;
            ResponseSha256 = responseSha256;
        }
        internal Binding Binding { get; }
        internal Guid StartDispatch { get; }
        internal int HttpStatus { get; }
        internal int ResponseBytes { get; }
        internal string ResponseSha256 { get; }
        public override string ToString() => "[SynchronousDeleteProof]";
    }

    internal sealed class StatusNotificationCreateCancellationStartProof(Binding binding, Guid startDispatch,
        int httpStatus, int responseBytes, string requestSha256, string responseSha256, string nativeRequestId,
        Guid namespaceEpoch = default, Guid selectedDispatch = default, string? rawLabels = null)
    {
        internal Binding Binding { get; } = binding;
        internal Guid StartDispatch { get; } = startDispatch;
        internal int HttpStatus { get; } = httpStatus;
        internal int ResponseBytes { get; } = responseBytes;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal Guid NamespaceEpoch { get; } = namespaceEpoch;
        internal Guid SelectedDispatch { get; } = selectedDispatch;
        internal string? RawLabels { get; } = rawLabels;
        public override string ToString() => "[StatusNotificationCreateCancellationStartProof]";
    }

    internal sealed class StatusNotificationUpdateCancellationStartProof(Binding binding, Guid startDispatch,
        int httpStatus, int responseBytes, string requestSha256, string responseSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal Guid StartDispatch { get; } = startDispatch;
        internal int HttpStatus { get; } = httpStatus;
        internal int ResponseBytes { get; } = responseBytes;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        public override string ToString() => "[StatusNotificationUpdateCancellationStartProof]";
    }

    internal sealed class StatusNotificationDeleteCancellationStartProof(Binding binding, Guid startDispatch,
        int httpStatus, string responseSha256)
    {
        internal Binding Binding { get; } = binding;
        internal Guid StartDispatch { get; } = startDispatch;
        internal int HttpStatus { get; } = httpStatus;
        internal int ResponseBytes => 0;
        internal string ResponseSha256 { get; } = responseSha256;
        public override string ToString() => "[StatusNotificationDeleteCancellationStartProof]";
    }

    internal sealed class StatusNotificationDeleteIndependentStartProof(Binding binding, Guid startDispatch,
        int httpStatus, string responseSha256)
    {
        internal Binding Binding { get; } = binding;
        internal Guid StartDispatch { get; } = startDispatch;
        internal int HttpStatus { get; } = httpStatus;
        internal int ResponseBytes => 0;
        internal string ResponseSha256 { get; } = responseSha256;
        public override string ToString() => "[StatusNotificationDeleteIndependentStartProof]";
    }

    internal sealed class StatusNotificationDeleteIndependentCompletionProof(
        StatusNotificationDeleteIndependentStartProof start)
    {
        internal StatusNotificationDeleteIndependentStartProof Start { get; } = start;
        public override string ToString() => "[StatusNotificationDeleteIndependentCompletionProof]";
    }

    internal sealed record StatusPendingPurgeClockBounds(TimeSpan MaxForwardUtcDeviation, TimeSpan MaxAuthorizationDelay);

    internal sealed class StatusPendingPurgeClockWindow
    {
        private readonly ManagementOperationNativeCapture source;
        private readonly Window window;
        private readonly DateTimeOffset expiresAt, startedUtc;
        private readonly long started;
        private readonly TimeSpan budget;
        private readonly StatusPendingPurgeClockBounds bounds;
        private readonly CancellationToken originalCallerToken;
        private readonly CancellationTokenSource deadline, lifetime;
        private readonly object clockGate = new();
        private Task? revocation;
        private int revoked;

        internal StatusPendingPurgeClockWindow(ManagementOperationNativeCapture source, Window window,
            DateTimeOffset expiresAt, StatusPendingPurgeClockBounds bounds, TimeSpan budget,
            CancellationToken originalCallerToken)
        {
            this.source = source;
            this.window = window;
            this.expiresAt = expiresAt;
            this.bounds = bounds;
            this.budget = budget;
            this.originalCallerToken = originalCallerToken;
            started = TimeProvider.System.GetTimestamp();
            startedUtc = DateTimeOffset.UtcNow;
            Require(bounds is not null && bounds.MaxForwardUtcDeviation >= TimeSpan.Zero &&
                bounds.MaxAuthorizationDelay > TimeSpan.Zero && budget > TimeSpan.Zero &&
                budget.TotalMilliseconds <= uint.MaxValue - 1 && !originalCallerToken.IsCancellationRequested);
            // Checked DateTimeOffset arithmetic also rejects unrepresentable host bounds.
            Require(expiresAt > startedUtc + budget + bounds.MaxForwardUtcDeviation +
                bounds.MaxAuthorizationDelay + TimeSpan.FromMinutes(5));
            deadline = new(budget, TimeProvider.System);
            lifetime = CancellationTokenSource.CreateLinkedTokenSource(originalCallerToken, deadline.Token);
            Token = lifetime.Token;
        }

        internal CancellationToken Token { get; }

        // Source stages call this OUTSIDE journal validators. The token alone
        // cannot establish that the system UTC clock stayed inside the envelope.
        internal bool IsValid()
        {
            lock (source.gate)
            {
                bool registered = source.TryGetStatusPendingPurgeRun(window, out var r) &&
                    ReferenceEquals(r.Clock, this);
                if (!registered || r!.Invalid || r.Sealed)
                {
                    Revoke();
                    return false;
                }
                return Check();
            }
        }

        internal bool Check()
        {
            if (Volatile.Read(ref revoked) != 0 || Token.IsCancellationRequested ||
                originalCallerToken.IsCancellationRequested)
            {
                Revoke();
                return false;
            }
            var elapsed = TimeProvider.System.GetElapsedTime(started);
            var utc = DateTimeOffset.UtcNow;
            bool valid = elapsed >= TimeSpan.Zero && elapsed < budget && utc >= startedUtc &&
                utc - startedUtc <= elapsed + bounds.MaxForwardUtcDeviation + bounds.MaxAuthorizationDelay &&
                expiresAt - utc > TimeSpan.FromMinutes(5) + bounds.MaxAuthorizationDelay;
            if (!valid) Revoke();
            return valid;
        }

        internal bool Matches(DateTimeOffset expiry) => expiry == expiresAt;

        internal bool AuthorizationWithinBounds(long factoryTimestamp) =>
            TimeProvider.System.GetElapsedTime(factoryTimestamp) <= bounds.MaxAuthorizationDelay && Check();

        internal void Revoke()
        {
            lock (clockGate)
                if (Interlocked.Exchange(ref revoked, 1) == 0)
                    revocation = lifetime.CancelAsync();
        }

        internal async Task DrainAsync()
        {
            Revoke();
            Task? pending;
            lock (clockGate) pending = revocation;
            if (pending is not null) await pending.ConfigureAwait(false);
            lifetime.Dispose();
            deadline.Dispose();
        }

        public override string ToString() => "[StatusPendingPurgeClockWindow]";
    }

    internal sealed class StatusPendingPurgeStartProof(Binding binding, StatusTarget target,
        int responseBytes, string requestSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal StatusTarget Target { get; } = target;
        internal Guid StartDispatch => Target.StartDispatch;
        internal int HttpStatus => 202;
        internal int ResponseBytes { get; } = responseBytes;
        internal string ResponseSha256 => Target.StartResponseSha256;
        internal string RequestSha256 { get; } = requestSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Success;
        internal NativeProvisioningState State => NativeProvisioningState.Pending;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusPendingPurgeStartProof]";
    }

    internal sealed class StatusPendingPurgeSelectedProof(StatusPendingPurgeStartProof start,
        string responseSha256, string nativeRequestId)
    {
        internal StatusPendingPurgeStartProof Start { get; } = start;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Pending;
        internal NativeProvisioningState State => NativeProvisioningState.Pending;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusPendingPurgeSelectedProof]";
    }

    internal sealed class StatusPendingPurgeCleanupProof(StatusPendingPurgeSelectedProof selected)
    {
        internal StatusPendingPurgeSelectedProof Selected { get; } = selected;
        internal StatusPendingPurgeStartProof Start => Selected.Start;
        internal SecretStatus Outcome => SecretStatus.Success;
        internal NativeProvisioningState State => NativeProvisioningState.Succeeded;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusPendingPurgeCleanupProof]";
    }

    internal sealed class StatusPendingPurgeIndependentStartProof(Binding binding, StatusTarget target,
        int responseBytes, string requestSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal StatusTarget Target { get; } = target;
        internal Guid StartDispatch => Target.StartDispatch;
        internal int HttpStatus => 202;
        internal int ResponseBytes { get; } = responseBytes;
        internal string ResponseSha256 => Target.StartResponseSha256;
        internal string RequestSha256 { get; } = requestSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Success;
        internal NativeProvisioningState State => NativeProvisioningState.Pending;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusPendingPurgeIndependentStartProof]";
    }

    internal sealed class StatusPendingPurgeIndependentSelectedProof(StatusPendingPurgeIndependentStartProof start,
        string responseSha256, string nativeRequestId)
    {
        internal StatusPendingPurgeIndependentStartProof Start { get; } = start;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Pending;
        internal NativeProvisioningState State => NativeProvisioningState.Pending;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusPendingPurgeIndependentSelectedProof]";
    }

    internal sealed class StatusPendingPurgeIndependentCleanupProof(StatusPendingPurgeIndependentSelectedProof selected)
    {
        internal StatusPendingPurgeIndependentSelectedProof Selected { get; } = selected;
        internal StatusPendingPurgeIndependentStartProof Start => Selected.Start;
        internal SecretStatus Outcome => SecretStatus.Success;
        internal NativeProvisioningState State => NativeProvisioningState.Succeeded;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusPendingPurgeIndependentCleanupProof]";
    }

    internal sealed class StatusPendingPurgeCancellationStartProof(Binding binding, StatusTarget target,
        int responseBytes, string requestSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal StatusTarget Target { get; } = target;
        internal Guid StartDispatch => Target.StartDispatch;
        internal int HttpStatus => 202;
        internal int ResponseBytes { get; } = responseBytes;
        internal string ResponseSha256 => Target.StartResponseSha256;
        internal string RequestSha256 { get; } = requestSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Success;
        internal NativeProvisioningState State => NativeProvisioningState.Pending;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusPendingPurgeCancellationStartProof]";
    }

    internal sealed class StatusPendingPurgeCancellationCanceledProof(StatusPendingPurgeCancellationStartProof start)
    {
        internal StatusPendingPurgeCancellationStartProof Start { get; } = start;
        public override string ToString() => "[StatusPendingPurgeCancellationCanceledProof]";
    }

    internal sealed class StatusPendingPurgeCancellationSelectedProof(StatusPendingPurgeCancellationStartProof start,
        StatusPendingPurgeCancellationCanceledProof canceled, string responseSha256, string nativeRequestId)
    {
        internal StatusPendingPurgeCancellationStartProof Start { get; } = start;
        internal StatusPendingPurgeCancellationCanceledProof Canceled { get; } = canceled;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Pending;
        internal NativeProvisioningState State => NativeProvisioningState.Pending;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusPendingPurgeCancellationSelectedProof]";
    }

    internal sealed class StatusPendingPurgeCancellationCleanupProof(StatusPendingPurgeCancellationSelectedProof selected)
    {
        internal StatusPendingPurgeCancellationSelectedProof Selected { get; } = selected;
        internal StatusPendingPurgeCancellationStartProof Start => Selected.Start;
        internal StatusPendingPurgeCancellationCanceledProof Canceled => Selected.Canceled;
        internal SecretStatus Outcome => SecretStatus.Success;
        internal NativeProvisioningState State => NativeProvisioningState.Succeeded;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusPendingPurgeCancellationCleanupProof]";
    }

    internal sealed class StatusFailedPurgeStartProof(Binding binding, StatusTarget target,
        int responseBytes, string requestSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal StatusTarget Target { get; } = target;
        internal Guid StartDispatch => Target.StartDispatch;
        internal int HttpStatus => 202;
        internal int ResponseBytes { get; } = responseBytes;
        internal string ResponseSha256 => Target.StartResponseSha256;
        internal string RequestSha256 { get; } = requestSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Success;
        internal NativeProvisioningState State => NativeProvisioningState.Pending;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusFailedPurgeStartProof]";
    }

    internal sealed class StatusFailedPurgeTerminalFailureProof(StatusFailedPurgeStartProof start,
        string responseSha256, string nativeRequestId)
    {
        internal StatusFailedPurgeStartProof Start { get; } = start;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Unknown;
        internal NativeProvisioningState State => NativeProvisioningState.Failed;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusFailedPurgeTerminalFailureProof]";
    }

    internal sealed class StatusFailedPurgeIndependentStartProof(Binding binding, StatusTarget target,
        int responseBytes, string requestSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal StatusTarget Target { get; } = target;
        internal Guid StartDispatch => Target.StartDispatch;
        internal int HttpStatus => 202;
        internal int ResponseBytes { get; } = responseBytes;
        internal string ResponseSha256 => Target.StartResponseSha256;
        internal string RequestSha256 { get; } = requestSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Success;
        internal NativeProvisioningState State => NativeProvisioningState.Pending;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusFailedPurgeIndependentStartProof]";
    }

    internal sealed class StatusFailedPurgeIndependentTerminalFailureProof(StatusFailedPurgeIndependentStartProof start,
        string responseSha256, string nativeRequestId)
    {
        internal StatusFailedPurgeIndependentStartProof Start { get; } = start;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Unknown;
        internal NativeProvisioningState State => NativeProvisioningState.Failed;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusFailedPurgeIndependentTerminalFailureProof]";
    }

    internal sealed class StatusFailedPurgeCancellationStartProof(Binding binding, StatusTarget target,
        int responseBytes, string requestSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal StatusTarget Target { get; } = target;
        internal Guid StartDispatch => Target.StartDispatch;
        internal int HttpStatus => 202;
        internal int ResponseBytes { get; } = responseBytes;
        internal string ResponseSha256 => Target.StartResponseSha256;
        internal string RequestSha256 { get; } = requestSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Success;
        internal NativeProvisioningState State => NativeProvisioningState.Pending;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusFailedPurgeCancellationStartProof]";
    }

    internal sealed class StatusFailedPurgeCancellationCanceledProof
    {
        internal StatusFailedPurgeCancellationCanceledProof(ManagementOperationNativeCapture source,
            StatusFailedPurgeCancellationStartProof start)
        {
            Start = start;
        }
        internal StatusFailedPurgeCancellationStartProof Start { get; }
        public override string ToString() => "[StatusFailedPurgeCancellationCanceledProof]";
    }

    internal sealed class StatusFailedPurgeCancellationTerminalFailureProof(StatusFailedPurgeCancellationStartProof start,
        StatusFailedPurgeCancellationCanceledProof canceled, string responseSha256, string nativeRequestId)
    {
        internal StatusFailedPurgeCancellationStartProof Start { get; } = start;
        internal StatusFailedPurgeCancellationCanceledProof Canceled { get; } = canceled;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Unknown;
        internal NativeProvisioningState State => NativeProvisioningState.Failed;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusFailedPurgeCancellationTerminalFailureProof]";
    }

    internal sealed class StatusCanceledPurgeStartProof(Binding binding, StatusTarget target,
        int responseBytes, string requestSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal StatusTarget Target { get; } = target;
        internal Guid StartDispatch => Target.StartDispatch;
        internal int HttpStatus => 202;
        internal int ResponseBytes { get; } = responseBytes;
        internal string ResponseSha256 => Target.StartResponseSha256;
        internal string RequestSha256 { get; } = requestSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Success;
        internal NativeProvisioningState State => NativeProvisioningState.Pending;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusCanceledPurgeStartProof]";
    }

    internal sealed class StatusCanceledPurgeTerminalCancellationProof(StatusCanceledPurgeStartProof start,
        string responseSha256, string nativeRequestId)
    {
        internal StatusCanceledPurgeStartProof Start { get; } = start;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Unknown;
        internal NativeProvisioningState State => NativeProvisioningState.Canceled;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusCanceledPurgeTerminalCancellationProof]";
    }

    internal sealed class StatusCanceledPurgeIndependentStartProof(Binding binding, StatusTarget target,
        int responseBytes, string requestSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal StatusTarget Target { get; } = target;
        internal Guid StartDispatch => Target.StartDispatch;
        internal int HttpStatus => 202;
        internal int ResponseBytes { get; } = responseBytes;
        internal string ResponseSha256 => Target.StartResponseSha256;
        internal string RequestSha256 { get; } = requestSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Success;
        internal NativeProvisioningState State => NativeProvisioningState.Pending;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusCanceledPurgeIndependentStartProof]";
    }

    internal sealed class StatusCanceledPurgeIndependentTerminalCancellationProof(StatusCanceledPurgeIndependentStartProof start,
        string responseSha256, string nativeRequestId)
    {
        internal StatusCanceledPurgeIndependentStartProof Start { get; } = start;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Unknown;
        internal NativeProvisioningState State => NativeProvisioningState.Canceled;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusCanceledPurgeIndependentTerminalCancellationProof]";
    }

    internal sealed class StatusCanceledPurgeCancellationStartProof(Binding binding, StatusTarget target,
        int responseBytes, string requestSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal StatusTarget Target { get; } = target;
        internal Guid StartDispatch => Target.StartDispatch;
        internal int HttpStatus => 202;
        internal int ResponseBytes { get; } = responseBytes;
        internal string ResponseSha256 => Target.StartResponseSha256;
        internal string RequestSha256 { get; } = requestSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Success;
        internal NativeProvisioningState State => NativeProvisioningState.Pending;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusCanceledPurgeCancellationStartProof]";
    }

    internal sealed class StatusCanceledPurgeCancellationCanceledProof
    {
        internal StatusCanceledPurgeCancellationCanceledProof(ManagementOperationNativeCapture source,
            StatusCanceledPurgeCancellationStartProof start)
        {
            Start = start;
        }
        internal StatusCanceledPurgeCancellationStartProof Start { get; }
        public override string ToString() => "[StatusCanceledPurgeCancellationCanceledProof]";
    }

    internal sealed class StatusCanceledPurgeCancellationTerminalCancellationProof(StatusCanceledPurgeCancellationStartProof start,
        StatusCanceledPurgeCancellationCanceledProof canceled, string responseSha256, string nativeRequestId)
    {
        internal StatusCanceledPurgeCancellationStartProof Start { get; } = start;
        internal StatusCanceledPurgeCancellationCanceledProof Canceled { get; } = canceled;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Unknown;
        internal NativeProvisioningState State => NativeProvisioningState.Canceled;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusCanceledPurgeCancellationTerminalCancellationProof]";
    }

    private enum StatusPendingPurgePhase { Start, Canceled, Selected, Cleanup, TerminalFailure, TerminalCancellation }

    private sealed class StatusPendingPurgeSlot(StatusPendingPurgePhase phase, CancellationToken token)
    {
        internal readonly StatusPendingPurgePhase Phase = phase;
        internal readonly CancellationToken Token = token;
        internal readonly Invocation Invocation = new();
        internal readonly TaskCompletionSource Drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly List<Task> Sends = [];
        internal readonly List<StatusPendingPurgeResponse> Responses = [];
        internal readonly Dictionary<Request, long> Requests = new(ReferenceEqualityComparer.Instance);
        internal Task? NativeTask;
        internal bool HookReturned, Success, CancellationObserved, FactoryActive, Sending, Finished;
        internal int Factories, SendCount;
    }

    private sealed class StatusPendingPurgeResponse(OwnedArmResponse.Body body,
        OwnedArmResponse.ParserCustody parser, OwnedArmResponse.Storage storage)
    {
        internal readonly OwnedArmResponse.Body Body = body;
        internal readonly OwnedArmResponse.ParserCustody Parser = parser;
        internal readonly OwnedArmResponse.Storage Storage = storage;
        // A later actual send can replace HttpMessage.Response legitimately.
        // Freeze custody before that send, never by re-reading a displaced body.
        internal bool Superseded;
        internal bool Valid => Superseded || Parser is { Complete: true, Invalid: false };
    }

    // Common physical state carries facts, never a profile's proof authority.
    private sealed record StatusPendingPurgeStartFacts(Binding Binding, StatusTarget Target,
        int ResponseBytes, string RequestSha256, string NativeRequestId);

    private sealed record StatusPendingPurgeSelectedFacts(string ResponseSha256, string NativeRequestId);

    private sealed class StatusPendingPurgeRun(Window window, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, StatusPendingPurgeClockWindow clock,
        CancellationToken originalCallerToken)
    {
        internal readonly Window Window = window;
        internal readonly VaultAdministration Client = client;
        internal readonly DeletedVaultScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly StatusPendingPurgeClockWindow Clock = clock;
        internal readonly CancellationToken OriginalCallerToken = originalCallerToken;
        internal readonly List<OwnedArmResponse.Storage> Storage = [];
        internal readonly List<StatusPendingPurgeResponse> Responses = [];
        internal StatusPendingPurgeSlot? Start, Canceled, Selected, Cleanup;
        internal ManagementOperation? Handle;
        internal StatusPendingPurgeStartFacts? Candidate, StartFacts;
        internal StatusPendingPurgeSelectedFacts? SelectedFacts;
        internal Task<Capture>? SealTask;
        internal string? AuthorizationSha256;
        internal bool StartClaimed, CanceledClaimed, SelectedClaimed, CleanupClaimed, SelectedRevoked, Invalid, Sealed;
    }

    private sealed class StatusPendingPurgeRegistration(StatusPendingPurgeRun run)
    {
        internal readonly StatusPendingPurgeRun Run = run;
        internal StatusPendingPurgeStartProof? StartProof;
        internal StatusPendingPurgeSelectedProof? SelectedProof;
        internal StatusPendingPurgeCleanupProof? CleanupProof;
    }

    private sealed class StatusPendingPurgeIndependentRegistration(StatusPendingPurgeRun run)
    {
        internal readonly StatusPendingPurgeRun Run = run;
        internal StatusPendingPurgeIndependentStartProof? StartProof;
        internal StatusPendingPurgeIndependentSelectedProof? SelectedProof;
        internal StatusPendingPurgeIndependentCleanupProof? CleanupProof;
    }

    private sealed class StatusPendingPurgeCancellationRegistration(StatusPendingPurgeRun run)
    {
        internal readonly StatusPendingPurgeRun Run = run;
        internal StatusPendingPurgeCancellationStartProof? StartProof;
        internal StatusPendingPurgeCancellationCanceledProof? CanceledProof;
        internal StatusPendingPurgeCancellationSelectedProof? SelectedProof;
        internal StatusPendingPurgeCancellationCleanupProof? CleanupProof;
    }

    private sealed class StatusFailedPurgeRegistration(StatusPendingPurgeRun run)
    {
        internal readonly StatusPendingPurgeRun Run = run;
        internal StatusFailedPurgeStartProof? StartProof;
        internal StatusFailedPurgeTerminalFailureProof? TerminalFailureProof;
    }

    private sealed class StatusCanceledPurgeRegistration(StatusPendingPurgeRun run)
    {
        internal readonly StatusPendingPurgeRun Run = run;
        internal StatusCanceledPurgeStartProof? StartProof;
        internal StatusCanceledPurgeTerminalCancellationProof? TerminalCancellationProof;
    }

    private sealed class StatusCanceledPurgeIndependentRegistration(StatusPendingPurgeRun run)
    {
        internal readonly StatusPendingPurgeRun Run = run;
        internal StatusCanceledPurgeIndependentStartProof? StartProof;
        internal StatusCanceledPurgeIndependentTerminalCancellationProof? TerminalCancellationProof;
    }

    private sealed class StatusFailedPurgeIndependentRegistration(StatusPendingPurgeRun run)
    {
        internal readonly StatusPendingPurgeRun Run = run;
        internal StatusFailedPurgeIndependentStartProof? StartProof;
        internal StatusFailedPurgeIndependentTerminalFailureProof? TerminalFailureProof;
    }

    private sealed class StatusFailedPurgeCancellationRegistration(StatusPendingPurgeRun run)
    {
        internal readonly StatusPendingPurgeRun Run = run;
        internal StatusFailedPurgeCancellationStartProof? StartProof;
        internal StatusFailedPurgeCancellationCanceledProof? CanceledProof;
        internal StatusFailedPurgeCancellationTerminalFailureProof? TerminalFailureProof;
    }

    private sealed class StatusCanceledPurgeCancellationRegistration(StatusPendingPurgeRun run)
    {
        internal readonly StatusPendingPurgeRun Run = run;
        internal StatusCanceledPurgeCancellationStartProof? StartProof;
        internal StatusCanceledPurgeCancellationCanceledProof? CanceledProof;
        internal StatusCanceledPurgeCancellationTerminalCancellationProof? TerminalCancellationProof;
    }

    private sealed record StatusPendingPurgeContext(StatusPendingPurgeRun Registration, StatusPendingPurgeSlot Slot);
    private readonly AsyncLocal<StatusPendingPurgeContext?> currentStatusPendingPurge = new();
    private readonly Dictionary<Window, StatusPendingPurgeRegistration> statusPendingPurges =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Window, StatusPendingPurgeIndependentRegistration> statusPendingPurgeIndependents =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Window, StatusPendingPurgeCancellationRegistration> statusPendingPurgeCancellations =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Window, StatusFailedPurgeRegistration> statusFailedPurges =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Window, StatusCanceledPurgeRegistration> statusCanceledPurges =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Window, StatusCanceledPurgeIndependentRegistration> statusCanceledPurgeIndependents =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Window, StatusFailedPurgeIndependentRegistration> statusFailedPurgeIndependents =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Window, StatusFailedPurgeCancellationRegistration> statusFailedPurgeCancellations =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Window, StatusCanceledPurgeCancellationRegistration> statusCanceledPurgeCancellations =
        new(ReferenceEqualityComparer.Instance);

    private static bool StatusPendingPurgeSelector(FixtureSelector selector) =>
        selector is { Operation: "a.management.ManagementOperation.CheckStatusAsync",
            Variant: "status.Pending", Case: "selected-contract" };

    private static bool StatusPendingPurgeIndependentSelector(FixtureSelector selector) =>
        selector is { Operation: "a.management.ManagementOperation.CheckStatusAsync",
            Variant: "status.Pending", Case: "independent-effect" };

    private static bool StatusPendingPurgeCancellationSelector(FixtureSelector selector) =>
        selector is { Operation: "a.management.ManagementOperation.CheckStatusAsync",
            Variant: "status.Pending", Case: "cancellation-boundary" };

    private static bool StatusFailedPurgeSelector(FixtureSelector selector) =>
        selector is { Operation: "a.management.ManagementOperation.CheckStatusAsync",
            Variant: "status.Failed", Case: "selected-contract" };

    private static bool StatusCanceledPurgeSelector(FixtureSelector selector) =>
        selector is { Operation: "a.management.ManagementOperation.CheckStatusAsync",
            Variant: "status.Canceled", Case: "selected-contract" };

    private static bool StatusCanceledPurgeIndependentSelector(FixtureSelector selector) =>
        selector is { Operation: "a.management.ManagementOperation.CheckStatusAsync",
            Variant: "status.Canceled", Case: "independent-effect" };

    private static bool StatusFailedPurgeIndependentSelector(FixtureSelector selector) =>
        selector is { Operation: "a.management.ManagementOperation.CheckStatusAsync",
            Variant: "status.Failed", Case: "independent-effect" };

    private static bool StatusFailedPurgeCancellationSelector(FixtureSelector selector) =>
        selector is { Operation: "a.management.ManagementOperation.CheckStatusAsync",
            Variant: "status.Failed", Case: "cancellation-boundary" };

    private static bool StatusCanceledPurgeCancellationSelector(FixtureSelector selector) =>
        selector is { Operation: "a.management.ManagementOperation.CheckStatusAsync",
            Variant: "status.Canceled", Case: "cancellation-boundary" };

    // Only clock, issued-target inspection and physical sealing may join registries.
    // Typed entry points and proof ownership always choose their own registry.
    private bool TryGetStatusPendingPurgeRun(Window window, [NotNullWhen(true)] out StatusPendingPurgeRun? run)
    {
        run = null;
        if (statusPendingPurges.TryGetValue(window, out var selected) &&
            StatusPendingPurgeSelector(window.Binding.Selector))
            run = selected.Run;
        else if (statusPendingPurgeIndependents.TryGetValue(window, out var independent) &&
            StatusPendingPurgeIndependentSelector(window.Binding.Selector))
            run = independent.Run;
        else if (statusPendingPurgeCancellations.TryGetValue(window, out var cancellation) &&
            StatusPendingPurgeCancellationSelector(window.Binding.Selector))
            run = cancellation.Run;
        else if (statusFailedPurges.TryGetValue(window, out var failed) &&
            StatusFailedPurgeSelector(window.Binding.Selector))
            run = failed.Run;
        else if (statusFailedPurgeIndependents.TryGetValue(window, out var failedIndependent) &&
            StatusFailedPurgeIndependentSelector(window.Binding.Selector))
            run = failedIndependent.Run;
        else if (statusFailedPurgeCancellations.TryGetValue(window, out var failedCancellation) &&
            StatusFailedPurgeCancellationSelector(window.Binding.Selector))
            run = failedCancellation.Run;
        else if (statusCanceledPurges.TryGetValue(window, out var providerCanceled) &&
            StatusCanceledPurgeSelector(window.Binding.Selector))
            run = providerCanceled.Run;
        else if (statusCanceledPurgeIndependents.TryGetValue(window, out var providerCanceledIndependent) &&
            StatusCanceledPurgeIndependentSelector(window.Binding.Selector))
            run = providerCanceledIndependent.Run;
        else if (statusCanceledPurgeCancellations.TryGetValue(window, out var providerCanceledCancellation) &&
            StatusCanceledPurgeCancellationSelector(window.Binding.Selector))
            run = providerCanceledCancellation.Run;
        return run is not null && ReferenceEquals(run.Window, window) && ReferenceEquals(window.Owner, owner);
    }

    internal StatusPendingPurgeClockWindow EnrollStatusCanceledPurgeCancellation(Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, DateTimeOffset expiresAt,
        StatusPendingPurgeClockBounds bounds, TimeSpan budget, CancellationToken originalCallerToken)
    {
        lock (gate)
        {
            Own(window, binding.Selector);
            Require(StatusCanceledPurgeCancellationSelector(binding.Selector));
            var run = EnrollStatusPendingPurgeRun(window, binding, client, scope, receipt, expiresAt,
                bounds, budget, originalCallerToken);
            statusCanceledPurgeCancellations.Add(window, new(run));
            return run.Clock;
        }
    }

    internal StatusPendingPurgeClockWindow EnrollStatusCanceledPurgeIndependent(Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, DateTimeOffset expiresAt,
        StatusPendingPurgeClockBounds bounds, TimeSpan budget, CancellationToken originalCallerToken)
    {
        lock (gate)
        {
            Own(window, binding.Selector);
            Require(StatusCanceledPurgeIndependentSelector(binding.Selector));
            var run = EnrollStatusPendingPurgeRun(window, binding, client, scope, receipt, expiresAt,
                bounds, budget, originalCallerToken);
            statusCanceledPurgeIndependents.Add(window, new(run));
            return run.Clock;
        }
    }

    internal StatusPendingPurgeClockWindow EnrollStatusCanceledPurge(Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, DateTimeOffset expiresAt,
        StatusPendingPurgeClockBounds bounds, TimeSpan budget, CancellationToken originalCallerToken)
    {
        lock (gate)
        {
            Own(window, binding.Selector);
            Require(StatusCanceledPurgeSelector(binding.Selector));
            var run = EnrollStatusPendingPurgeRun(window, binding, client, scope, receipt, expiresAt,
                bounds, budget, originalCallerToken);
            statusCanceledPurges.Add(window, new(run));
            return run.Clock;
        }
    }

    internal StatusPendingPurgeClockWindow EnrollStatusFailedPurgeCancellation(Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, DateTimeOffset expiresAt,
        StatusPendingPurgeClockBounds bounds, TimeSpan budget, CancellationToken originalCallerToken)
    {
        lock (gate)
        {
            Own(window, binding.Selector);
            Require(StatusFailedPurgeCancellationSelector(binding.Selector));
            var run = EnrollStatusPendingPurgeRun(window, binding, client, scope, receipt, expiresAt,
                bounds, budget, originalCallerToken);
            statusFailedPurgeCancellations.Add(window, new(run));
            return run.Clock;
        }
    }

    internal StatusPendingPurgeClockWindow EnrollStatusFailedPurge(Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, DateTimeOffset expiresAt,
        StatusPendingPurgeClockBounds bounds, TimeSpan budget, CancellationToken originalCallerToken)
    {
        lock (gate)
        {
            Own(window, binding.Selector);
            Require(StatusFailedPurgeSelector(binding.Selector));
            var run = EnrollStatusPendingPurgeRun(window, binding, client, scope, receipt, expiresAt,
                bounds, budget, originalCallerToken);
            statusFailedPurges.Add(window, new(run));
            return run.Clock;
        }
    }

    internal StatusPendingPurgeClockWindow EnrollStatusFailedPurgeIndependent(Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, DateTimeOffset expiresAt,
        StatusPendingPurgeClockBounds bounds, TimeSpan budget, CancellationToken originalCallerToken)
    {
        lock (gate)
        {
            Own(window, binding.Selector);
            Require(StatusFailedPurgeIndependentSelector(binding.Selector));
            var run = EnrollStatusPendingPurgeRun(window, binding, client, scope, receipt, expiresAt,
                bounds, budget, originalCallerToken);
            statusFailedPurgeIndependents.Add(window, new(run));
            return run.Clock;
        }
    }

    internal StatusPendingPurgeClockWindow EnrollStatusPendingPurge(Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, DateTimeOffset expiresAt,
        StatusPendingPurgeClockBounds bounds, TimeSpan budget, CancellationToken originalCallerToken)
    {
        lock (gate)
        {
            Own(window, binding.Selector);
            Require(StatusPendingPurgeSelector(binding.Selector));
            var run = EnrollStatusPendingPurgeRun(window, binding, client, scope, receipt, expiresAt,
                bounds, budget, originalCallerToken);
            statusPendingPurges.Add(window, new(run));
            return run.Clock;
        }
    }

    internal StatusPendingPurgeClockWindow EnrollStatusPendingPurgeIndependent(Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, DateTimeOffset expiresAt,
        StatusPendingPurgeClockBounds bounds, TimeSpan budget, CancellationToken originalCallerToken)
    {
        lock (gate)
        {
            Own(window, binding.Selector);
            Require(StatusPendingPurgeIndependentSelector(binding.Selector));
            var run = EnrollStatusPendingPurgeRun(window, binding, client, scope, receipt, expiresAt,
                bounds, budget, originalCallerToken);
            statusPendingPurgeIndependents.Add(window, new(run));
            return run.Clock;
        }
    }

    internal StatusPendingPurgeClockWindow EnrollStatusPendingPurgeCancellation(Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, DateTimeOffset expiresAt,
        StatusPendingPurgeClockBounds bounds, TimeSpan budget, CancellationToken originalCallerToken)
    {
        lock (gate)
        {
            Own(window, binding.Selector);
            Require(StatusPendingPurgeCancellationSelector(binding.Selector));
            var run = EnrollStatusPendingPurgeRun(window, binding, client, scope, receipt, expiresAt,
                bounds, budget, originalCallerToken);
            statusPendingPurgeCancellations.Add(window, new(run));
            return run.Clock;
        }
    }

    private StatusPendingPurgeRun EnrollStatusPendingPurgeRun(Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, DateTimeOffset expiresAt,
        StatusPendingPurgeClockBounds bounds, TimeSpan budget, CancellationToken originalCallerToken)
    {
        Require(ReferenceEquals(window.Binding, binding) &&
            binding.Operation == ManagementMutation.PurgeDeletedVault && binding.ApiRevision == "2026-02-01" &&
            ReferenceEquals(binding.Resource, scope) && scope.Location == binding.Location && client is not null &&
            receipt is not null && receipt.Evidence == DispatchEvidence.NotDispatched &&
            !window.Closed && window.Start is null && window.Status is null &&
            !startedWindows.Contains(window) && !statusPendingPurges.ContainsKey(window) &&
            !statusPendingPurgeIndependents.ContainsKey(window) && !statusPendingPurgeCancellations.ContainsKey(window) &&
            !statusFailedPurges.ContainsKey(window) && !statusFailedPurgeIndependents.ContainsKey(window) &&
            !statusFailedPurgeCancellations.ContainsKey(window) &&
            !statusCanceledPurges.ContainsKey(window) &&
            !statusCanceledPurgeIndependents.ContainsKey(window) &&
            !statusCanceledPurgeCancellations.ContainsKey(window) &&
            typeof(TokenCredential).Assembly.GetName().Version == new Version(1, 63, 0, 0) &&
            typeof(Azure.ResourceManager.ArmClient).Assembly.GetName().Version == new Version(1, 14, 0, 0) &&
            typeof(KeyVaultResource).Assembly.GetName().Version == new Version(1, 4, 0, 0));
        var clock = new StatusPendingPurgeClockWindow(this, window, expiresAt, bounds, budget, originalCallerToken);
        return new(window, client, scope, receipt, clock, originalCallerToken);
    }

    private StatusPendingPurgeRun RequireStatusPendingPurgeRun(Window window, FixtureSelector selector)
    {
        lock (gate)
        {
            Own(window, selector);
            Require(StatusPendingPurgeSelector(selector) && statusPendingPurges.ContainsKey(window));
            return statusPendingPurges[window].Run;
        }
    }

    private StatusPendingPurgeRun RequireStatusPendingPurgeIndependentRun(Window window, FixtureSelector selector)
    {
        lock (gate)
        {
            Own(window, selector);
            Require(StatusPendingPurgeIndependentSelector(selector) && statusPendingPurgeIndependents.ContainsKey(window));
            return statusPendingPurgeIndependents[window].Run;
        }
    }

    private StatusPendingPurgeRun RequireStatusPendingPurgeCancellationRun(Window window, FixtureSelector selector)
    {
        lock (gate)
        {
            Own(window, selector);
            Require(StatusPendingPurgeCancellationSelector(selector) && statusPendingPurgeCancellations.ContainsKey(window));
            return statusPendingPurgeCancellations[window].Run;
        }
    }

    private StatusPendingPurgeRun RequireStatusFailedPurgeRun(Window window, FixtureSelector selector)
    {
        lock (gate)
        {
            Own(window, selector);
            Require(StatusFailedPurgeSelector(selector) && statusFailedPurges.ContainsKey(window));
            return statusFailedPurges[window].Run;
        }
    }

    private StatusPendingPurgeRun RequireStatusCanceledPurgeIndependentRun(Window window, FixtureSelector selector)
    {
        lock (gate)
        {
            Own(window, selector);
            Require(StatusCanceledPurgeIndependentSelector(selector) && statusCanceledPurgeIndependents.ContainsKey(window));
            return statusCanceledPurgeIndependents[window].Run;
        }
    }

    internal async ValueTask<SecretOutcome<ManagementOperation>> StartStatusCanceledPurgeIndependentAsync(Window window,
        FixtureSelector selector, VaultAdministration client, ManagementScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token, Action<Task>? retained = null) =>
        await StartStatusPendingPurgeCoreAsync(RequireStatusCanceledPurgeIndependentRun(window, selector), window, selector,
            client, scope, input, receipt, token, retained).ConfigureAwait(false);

    private StatusPendingPurgeRun RequireStatusCanceledPurgeRun(Window window, FixtureSelector selector)
    {
        lock (gate)
        {
            Own(window, selector);
            Require(StatusCanceledPurgeSelector(selector) && statusCanceledPurges.ContainsKey(window));
            return statusCanceledPurges[window].Run;
        }
    }

    internal async ValueTask<SecretOutcome<ManagementOperation>> StartStatusCanceledPurgeAsync(Window window,
        FixtureSelector selector, VaultAdministration client, ManagementScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token, Action<Task>? retained = null) =>
        await StartStatusPendingPurgeCoreAsync(RequireStatusCanceledPurgeRun(window, selector), window, selector,
            client, scope, input, receipt, token, retained).ConfigureAwait(false);

    private StatusPendingPurgeRun RequireStatusFailedPurgeIndependentRun(Window window, FixtureSelector selector)
    {
        lock (gate)
        {
            Own(window, selector);
            Require(StatusFailedPurgeIndependentSelector(selector) && statusFailedPurgeIndependents.ContainsKey(window));
            return statusFailedPurgeIndependents[window].Run;
        }
    }

    private StatusPendingPurgeRun RequireStatusCanceledPurgeCancellationRun(Window window, FixtureSelector selector)
    {
        lock (gate)
        {
            Own(window, selector);
            Require(StatusCanceledPurgeCancellationSelector(selector) && statusCanceledPurgeCancellations.ContainsKey(window));
            return statusCanceledPurgeCancellations[window].Run;
        }
    }

    internal async ValueTask<SecretOutcome<ManagementOperation>> StartStatusCanceledPurgeCancellationAsync(Window window,
        FixtureSelector selector, VaultAdministration client, ManagementScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token, Action<Task>? retained = null) =>
        await StartStatusPendingPurgeCoreAsync(RequireStatusCanceledPurgeCancellationRun(window, selector), window, selector,
            client, scope, input, receipt, token, retained).ConfigureAwait(false);

    private StatusPendingPurgeRun RequireStatusFailedPurgeCancellationRun(Window window, FixtureSelector selector)
    {
        lock (gate)
        {
            Own(window, selector);
            Require(StatusFailedPurgeCancellationSelector(selector) && statusFailedPurgeCancellations.ContainsKey(window));
            return statusFailedPurgeCancellations[window].Run;
        }
    }

    internal async ValueTask<SecretOutcome<ManagementOperation>> StartStatusFailedPurgeCancellationAsync(Window window,
        FixtureSelector selector, VaultAdministration client, ManagementScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token, Action<Task>? retained = null) =>
        await StartStatusPendingPurgeCoreAsync(RequireStatusFailedPurgeCancellationRun(window, selector), window, selector,
            client, scope, input, receipt, token, retained).ConfigureAwait(false);

    internal async ValueTask<SecretOutcome<ManagementOperation>> StartStatusFailedPurgeIndependentAsync(Window window,
        FixtureSelector selector, VaultAdministration client, ManagementScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token, Action<Task>? retained = null) =>
        await StartStatusPendingPurgeCoreAsync(RequireStatusFailedPurgeIndependentRun(window, selector), window, selector,
            client, scope, input, receipt, token, retained).ConfigureAwait(false);

    internal async ValueTask<SecretOutcome<ManagementOperation>> StartStatusFailedPurgeAsync(Window window,
        FixtureSelector selector, VaultAdministration client, ManagementScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token, Action<Task>? retained = null) =>
        await StartStatusPendingPurgeCoreAsync(RequireStatusFailedPurgeRun(window, selector), window, selector,
            client, scope, input, receipt, token, retained).ConfigureAwait(false);

    internal async ValueTask<SecretOutcome<ManagementOperation>> StartStatusPendingPurgeAsync(Window window,
        FixtureSelector selector, VaultAdministration client, ManagementScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token, Action<Task>? retained = null) =>
        await StartStatusPendingPurgeCoreAsync(RequireStatusPendingPurgeRun(window, selector), window, selector,
            client, scope, input, receipt, token, retained).ConfigureAwait(false);

    internal async ValueTask<SecretOutcome<ManagementOperation>> StartStatusPendingPurgeIndependentAsync(Window window,
        FixtureSelector selector, VaultAdministration client, ManagementScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token, Action<Task>? retained = null) =>
        await StartStatusPendingPurgeCoreAsync(RequireStatusPendingPurgeIndependentRun(window, selector), window, selector,
            client, scope, input, receipt, token, retained).ConfigureAwait(false);

    internal async ValueTask<SecretOutcome<ManagementOperation>> StartStatusPendingPurgeCancellationAsync(Window window,
        FixtureSelector selector, VaultAdministration client, ManagementScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token, Action<Task>? retained = null) =>
        await StartStatusPendingPurgeCoreAsync(RequireStatusPendingPurgeCancellationRun(window, selector), window, selector,
            client, scope, input, receipt, token, retained).ConfigureAwait(false);

    private async ValueTask<SecretOutcome<ManagementOperation>> StartStatusPendingPurgeCoreAsync(StatusPendingPurgeRun r,
        Window window, FixtureSelector selector, VaultAdministration client, ManagementScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token, Action<Task>? retained = null)
    {
        StatusPendingPurgeSlot slot;
        lock (gate)
        {
            Own(window, selector);
            Require(ReferenceEquals(r.Client, client) &&
                ReferenceEquals(r.Scope, scope) && ReferenceEquals(r.Receipt, receipt));
            bool valid = !r.StartClaimed && !r.SelectedRevoked && !window.Closed &&
                StatusPendingPurgeLive(r) && input is not null && InputMatches(window.Binding, input) &&
                input.StatusOperation == ManagementMutation.PurgeDeletedVault &&
                r.Clock.Matches(input.Arm.Administrative.ExpiresAt) &&
                receipt.Evidence == DispatchEvidence.NotDispatched && !token.IsCancellationRequested;
            r.StartClaimed = true;
            r.Invalid |= !valid;
            Require(valid);
            r.Start = slot = new(StatusPendingPurgePhase.Start, token);
            window.Start = slot.Invocation;
            startedWindows.Add(window);
        }
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, r.Clock.Token);
            Require(StatusPendingPurgeLive(r));
            var previous = currentStatusPendingPurge.Value;
            currentStatusPendingPurge.Value = new(r, slot);
            Task<SecretOutcome<ManagementOperation>> task;
            try
            {
                task = client.PurgeDeletedVaultAsync(r.Scope, receipt, linked.Token).AsTask();
                slot.NativeTask = slot.Invocation.SdkTask = task;
            }
            finally { currentStatusPendingPurge.Value = previous; }
            try
            {
                r.Invalid |= !StatusPendingPurgeLive(r);
                retained?.Invoke(task);
                slot.HookReturned = true;
                r.Invalid |= !StatusPendingPurgeLive(r);
            }
            finally
            {
                var result = await task.ConfigureAwait(false);
                r.Handle = result.IsSuccess ? result.Value : null;
                slot.Invocation.Outcome = result.Status;
                slot.Invocation.WrapperState = r.Handle?.State;
                slot.Invocation.HasNativeHandle = r.Handle is not null;
                slot.Success = result.IsSuccess && r.Handle?.State == NativeProvisioningState.Pending &&
                    receipt.Evidence == DispatchEvidence.Pending;
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException) { slot.Invocation.Canceled = true; r.Invalid = true; throw; }
        catch { r.Invalid = true; throw; }
        finally { await FinishStatusPendingPurgeAsync(r, slot).ConfigureAwait(false); }
    }

    internal async ValueTask<SecretStatus> CheckStatusPendingPurgeAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null) =>
        await CheckStatusPendingPurgeCoreAsync(RequireStatusPendingPurgeRun(window, selector),
            window, selector, handle, token, retained, cleanup: false).ConfigureAwait(false);

    internal async ValueTask<SecretStatus> CheckStatusPendingPurgeCleanupAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null) =>
        await CheckStatusPendingPurgeCoreAsync(RequireStatusPendingPurgeRun(window, selector),
            window, selector, handle, token, retained, cleanup: true).ConfigureAwait(false);

    internal async ValueTask<SecretStatus> CheckStatusPendingPurgeIndependentAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null) =>
        await CheckStatusPendingPurgeCoreAsync(RequireStatusPendingPurgeIndependentRun(window, selector),
            window, selector, handle, token, retained, cleanup: false).ConfigureAwait(false);

    internal async ValueTask<SecretStatus> CheckStatusPendingPurgeIndependentCleanupAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null) =>
        await CheckStatusPendingPurgeCoreAsync(RequireStatusPendingPurgeIndependentRun(window, selector),
            window, selector, handle, token, retained, cleanup: true).ConfigureAwait(false);

    internal async ValueTask<SecretStatus> CheckStatusPendingPurgeCancellationCanceledAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken canceledToken, Action<Task>? retained = null) =>
        await CheckStatusPendingPurgeCoreAsync(RequireStatusPendingPurgeCancellationRun(window, selector),
            window, selector, handle, canceledToken, retained, cleanup: false, canceled: true).ConfigureAwait(false);

    internal async ValueTask<SecretStatus> CheckStatusPendingPurgeCancellationAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null) =>
        await CheckStatusPendingPurgeCoreAsync(RequireStatusPendingPurgeCancellationRun(window, selector),
            window, selector, handle, token, retained, cleanup: false).ConfigureAwait(false);

    internal async ValueTask<SecretStatus> CheckStatusPendingPurgeCancellationCleanupAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null) =>
        await CheckStatusPendingPurgeCoreAsync(RequireStatusPendingPurgeCancellationRun(window, selector),
            window, selector, handle, token, retained, cleanup: true).ConfigureAwait(false);

    internal async ValueTask<SecretStatus> CheckStatusFailedPurgeAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null) =>
        await CheckStatusPendingPurgeCoreAsync(RequireStatusFailedPurgeRun(window, selector),
            window, selector, handle, token, retained, cleanup: false).ConfigureAwait(false);

    internal async ValueTask<SecretStatus> CheckStatusFailedPurgeIndependentAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null) =>
        await CheckStatusPendingPurgeCoreAsync(RequireStatusFailedPurgeIndependentRun(window, selector),
            window, selector, handle, token, retained, cleanup: false).ConfigureAwait(false);

    internal async ValueTask<SecretStatus> CheckStatusFailedPurgeCancellationCanceledAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken canceledToken, Action<Task>? retained = null) =>
        await CheckStatusPendingPurgeCoreAsync(RequireStatusFailedPurgeCancellationRun(window, selector),
            window, selector, handle, canceledToken, retained, cleanup: false, canceled: true).ConfigureAwait(false);

    internal async ValueTask<SecretStatus> CheckStatusFailedPurgeCancellationAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null) =>
        await CheckStatusPendingPurgeCoreAsync(RequireStatusFailedPurgeCancellationRun(window, selector),
            window, selector, handle, token, retained, cleanup: false).ConfigureAwait(false);

    internal async ValueTask<SecretStatus> CheckStatusCanceledPurgeCancellationCanceledAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken canceledToken, Action<Task>? retained = null) =>
        await CheckStatusPendingPurgeCoreAsync(RequireStatusCanceledPurgeCancellationRun(window, selector),
            window, selector, handle, canceledToken, retained, cleanup: false, canceled: true).ConfigureAwait(false);

    internal async ValueTask<SecretStatus> CheckStatusCanceledPurgeCancellationAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null) =>
        await CheckStatusPendingPurgeCoreAsync(RequireStatusCanceledPurgeCancellationRun(window, selector),
            window, selector, handle, token, retained, cleanup: false).ConfigureAwait(false);

    internal async ValueTask<SecretStatus> CheckStatusCanceledPurgeAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null) =>
        await CheckStatusPendingPurgeCoreAsync(RequireStatusCanceledPurgeRun(window, selector),
            window, selector, handle, token, retained, cleanup: false).ConfigureAwait(false);

    internal async ValueTask<SecretStatus> CheckStatusCanceledPurgeIndependentAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null) =>
        await CheckStatusPendingPurgeCoreAsync(RequireStatusCanceledPurgeIndependentRun(window, selector),
            window, selector, handle, token, retained, cleanup: false).ConfigureAwait(false);

    private async ValueTask<SecretStatus> CheckStatusPendingPurgeCoreAsync(StatusPendingPurgeRun r, Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained, bool cleanup, bool canceled = false)
    {
        StatusPendingPurgeSlot slot;
        lock (gate)
        {
            Own(window, selector);
            Require(ReferenceEquals(r.Handle, handle));
            bool cancellationProfile = statusPendingPurgeCancellations.TryGetValue(window, out var cancellation);
            bool failedProfile = statusFailedPurges.TryGetValue(window, out var failed);
            bool failedIndependentProfile = statusFailedPurgeIndependents.TryGetValue(window, out var failedIndependent);
            bool failedCancellationProfile = statusFailedPurgeCancellations.TryGetValue(window, out var failedCancellation);
            bool providerCanceledProfile = statusCanceledPurges.TryGetValue(window, out var providerCanceled);
            bool providerCanceledIndependentProfile = statusCanceledPurgeIndependents.TryGetValue(window, out var providerCanceledIndependent);
            bool providerCanceledCancellationProfile = statusCanceledPurgeCancellations.TryGetValue(window, out var providerCanceledCancellation);
            bool valid = StatusPendingPurgeLive(r) && StatusPendingPurgeHistoryValid(r) &&
                (!providerCanceledCancellationProfile || ReferenceEquals(providerCanceledCancellation!.Run, r) &&
                    providerCanceledCancellation.StartProof is not null && !cleanup &&
                    (canceled || StatusCanceledPurgeCancellationCanceledValid(providerCanceledCancellation))) &&
                (!providerCanceledIndependentProfile || ReferenceEquals(providerCanceledIndependent!.Run, r) &&
                    providerCanceledIndependent.StartProof is not null && !cleanup && !canceled) &&
                (!providerCanceledProfile || ReferenceEquals(providerCanceled!.Run, r) &&
                    providerCanceled.StartProof is not null && !cleanup && !canceled) &&
                (!failedProfile || ReferenceEquals(failed!.Run, r) && failed.StartProof is not null && !cleanup && !canceled) &&
                (!failedIndependentProfile || ReferenceEquals(failedIndependent!.Run, r) &&
                    failedIndependent.StartProof is not null && !cleanup && !canceled) &&
                (!failedCancellationProfile || ReferenceEquals(failedCancellation!.Run, r) &&
                    failedCancellation.StartProof is not null && !cleanup &&
                    (canceled || StatusFailedPurgeCancellationCanceledValid(failedCancellation))) &&
                (canceled ? token.IsCancellationRequested : !token.IsCancellationRequested) &&
                handle.State == NativeProvisioningState.Pending &&
                r.StartFacts is not null && r.Start is { Finished: true } &&
                (!cancellationProfile || canceled || StatusPendingPurgeCancellationCanceledValid(cancellation!)) &&
                (canceled ? (cancellationProfile && ReferenceEquals(cancellation!.Run, r) &&
                    cancellation.StartProof is not null || failedCancellationProfile || providerCanceledCancellationProfile) &&
                    !r.CanceledClaimed && !r.SelectedClaimed &&
                    !r.SelectedRevoked && !window.Closed && !r.Start.Token.IsCancellationRequested
                    : cleanup ? r.SelectedRevoked && window.Closed && !r.CleanupClaimed &&
                    r.SelectedFacts is not null && r.Selected is { Finished: true }
                    : !r.SelectedRevoked && !window.Closed && !r.SelectedClaimed &&
                        !r.Start.Token.IsCancellationRequested);
            if (canceled) r.CanceledClaimed = true;
            else if (cleanup) r.CleanupClaimed = true;
            else r.SelectedClaimed = true;
            r.Invalid |= !valid;
            Require(valid);
            slot = new(canceled ? StatusPendingPurgePhase.Canceled :
                cleanup ? StatusPendingPurgePhase.Cleanup :
                providerCanceledProfile || providerCanceledIndependentProfile || providerCanceledCancellationProfile
                    ? StatusPendingPurgePhase.TerminalCancellation :
                failedProfile || failedIndependentProfile || failedCancellationProfile
                    ? StatusPendingPurgePhase.TerminalFailure : StatusPendingPurgePhase.Selected, token);
            if (canceled) r.Canceled = slot;
            else if (cleanup) r.Cleanup = slot;
            else
            {
                r.Selected = slot;
                window.Status = slot.Invocation;
            }
        }
        try
        {
            // The canceled operand belongs only to this private slot, never
            // to the original lifetime or the later positive check's token.
            using var linked = canceled ? null : CancellationTokenSource.CreateLinkedTokenSource(token, r.Clock.Token);
            Require(StatusPendingPurgeLive(r));
            var previous = currentStatusPendingPurge.Value;
            currentStatusPendingPurge.Value = new(r, slot);
            Task<SecretStatus> task;
            try
            {
                task = handle.CheckStatusAsync(canceled ? token : linked!.Token).AsTask();
                slot.NativeTask = slot.Invocation.SdkTask = task;
            }
            finally { currentStatusPendingPurge.Value = previous; }
            try
            {
                r.Invalid |= !StatusPendingPurgeLive(r);
                retained?.Invoke(task);
                slot.HookReturned = true;
                r.Invalid |= !StatusPendingPurgeLive(r);
            }
            finally
            {
                try
                {
                    var result = await task.ConfigureAwait(false);
                    slot.Invocation.Outcome = result;
                    slot.Invocation.WrapperState = handle.State;
                    bool terminalFailure = slot.Phase == StatusPendingPurgePhase.TerminalFailure;
                    bool terminalCancellation = slot.Phase == StatusPendingPurgePhase.TerminalCancellation;
                    slot.Success = !canceled &&
                        result == (terminalFailure || terminalCancellation ? SecretStatus.Unknown :
                            cleanup ? SecretStatus.Success : SecretStatus.Pending) &&
                        handle.State == (terminalCancellation ? NativeProvisioningState.Canceled :
                            terminalFailure ? NativeProvisioningState.Failed :
                            cleanup ? NativeProvisioningState.Succeeded : NativeProvisioningState.Pending) &&
                        r.Receipt.Evidence == DispatchEvidence.Pending;
                }
                catch (OperationCanceledException) when (canceled && token.IsCancellationRequested && task.IsCanceled)
                {
                    // Only awaiting this retained native task can record the
                    // expected OCE. A hook exception cannot manufacture it.
                    slot.CancellationObserved = slot.Invocation.Canceled = true;
                    slot.Invocation.WrapperState = handle.State;
                    slot.Success = handle.State == NativeProvisioningState.Pending &&
                        r.Receipt.Evidence == DispatchEvidence.Pending;
                    throw;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            slot.Invocation.Canceled = true;
            r.Invalid |= !canceled || !slot.CancellationObserved || !slot.HookReturned;
            throw;
        }
        catch { r.Invalid = true; throw; }
        finally { await FinishStatusPendingPurgeAsync(r, slot).ConfigureAwait(false); }
    }

    private static bool StatusPendingPurgeLive(StatusPendingPurgeRun r)
    {
        if (r.Invalid || r.Sealed || r.OriginalCallerToken.IsCancellationRequested ||
            (r.Canceled is not null || StatusFailedPurgeSelector(r.Window.Binding.Selector) ||
                StatusCanceledPurgeSelector(r.Window.Binding.Selector) ||
                StatusCanceledPurgeIndependentSelector(r.Window.Binding.Selector) ||
                StatusCanceledPurgeCancellationSelector(r.Window.Binding.Selector) ||
                StatusFailedPurgeIndependentSelector(r.Window.Binding.Selector) ||
                StatusFailedPurgeCancellationSelector(r.Window.Binding.Selector)) &&
                (r.Start is { } start && start.Token.IsCancellationRequested ||
                r.Selected is { } selected && selected.Token.IsCancellationRequested))
        {
            r.Clock.Revoke();
            return false;
        }
        return r.Clock.Check();
    }

    private static bool StatusPendingPurgeHistoryValid(StatusPendingPurgeRun r) =>
        r.Responses.All(response => response.Valid);

    private async Task FinishStatusPendingPurgeAsync(StatusPendingPurgeRun r, StatusPendingPurgeSlot slot)
    {
        try
        {
            if (slot.NativeTask is not null)
            {
                try { await slot.NativeTask.ConfigureAwait(false); }
                catch (OperationCanceledException) when (slot.Phase == StatusPendingPurgePhase.Canceled &&
                    slot.CancellationObserved && slot.Token.IsCancellationRequested && slot.NativeTask.IsCanceled) { }
                catch { r.Invalid = true; }
            }
            Task[] sends;
            lock (gate) sends = slot.Sends.ToArray();
            try { await Task.WhenAll(sends).ConfigureAwait(false); } catch { r.Invalid = true; }
            if (slot.Phase is StatusPendingPurgePhase.Cleanup or StatusPendingPurgePhase.TerminalFailure or
                StatusPendingPurgePhase.TerminalCancellation)
            {
                // This one-use phase has no future native reader. Unlike the
                // lazy start/Pending responses, all its finalizers must drain
                // before terminal authority is published. Failed retains its
                // registration and original clock until explicit Seal.
                r.Invalid |= !StatusPendingPurgeHistoryValid(r);
                foreach (var storage in r.Storage)
                    try { storage.Dispose(); } catch { r.Invalid = true; }
                r.Storage.Clear();
                r.Invalid |= !StatusPendingPurgeHistoryValid(r);
            }
            lock (gate)
            {
                bool canceled = slot.Phase == StatusPendingPurgePhase.Canceled;
                int expected = canceled ? 0 : slot.Phase == StatusPendingPurgePhase.Cleanup ? 2 : 1;
                bool valid = StatusPendingPurgeLive(r) &&
                    (canceled ? slot.Token.IsCancellationRequested && slot.CancellationObserved &&
                        slot.NativeTask is { IsCanceled: true } && slot.Requests.Count == 0 && slot.Sends.Count == 0
                        : !slot.Token.IsCancellationRequested && slot.NativeTask is { IsCompletedSuccessfully: true }) &&
                    slot.HookReturned && slot.Success &&
                    !slot.FactoryActive && !slot.Sending && slot.Factories == expected && slot.SendCount == expected &&
                    slot.Responses.Count == expected && StatusPendingPurgeHistoryValid(r) &&
                    r.Receipt.Evidence == DispatchEvidence.Pending &&
                    (slot.Phase == StatusPendingPurgePhase.Cleanup || !r.SelectedRevoked && !r.Window.Closed);
                r.Invalid |= !valid;
                if (valid)
                {
                    if (slot.Phase == StatusPendingPurgePhase.Start && r.Candidate is not null)
                    {
                        r.StartFacts = r.Candidate;
                        targets[r.Window] = r.Candidate.Target;
                        eligible.Add(r.Window);
                    }
                    else if (slot.Phase is StatusPendingPurgePhase.Selected or StatusPendingPurgePhase.TerminalFailure or
                        StatusPendingPurgePhase.TerminalCancellation &&
                        r.StartFacts is not null)
                        r.SelectedFacts = new(slot.Responses[0].Body.Sha256,
                            slot.Responses[0].Body.NativeRequestId);
                    else if (canceled && r.StartFacts is not null)
                    {
                        // No new send occurred: preserve the original lazy
                        // response custody and the unused normal status slot.
                        r.Invalid |= r.Handle?.State != NativeProvisioningState.Pending ||
                            r.Selected is not null || r.SelectedClaimed;
                    }
                    else if (slot.Phase != StatusPendingPurgePhase.Cleanup || r.SelectedFacts is null)
                        r.Invalid = true;
                    if (!r.Invalid) RegisterStatusPendingPurgeProof(r, slot.Phase);
                }
            }
        }
        finally
        {
            lock (gate)
            {
                slot.Finished = true;
                slot.Invocation.Terminated = true;
                slot.Invocation.Drained.TrySetResult();
                slot.Drained.TrySetResult();
            }
        }
    }

    // The shared runner produces facts. Each reference registry alone issues
    // its own typed proof; no Pending authority is minted for Failed.
    private void RegisterStatusPendingPurgeProof(StatusPendingPurgeRun run, StatusPendingPurgePhase phase)
    {
        var start = run.StartFacts!;
        if (statusPendingPurges.TryGetValue(run.Window, out var selected) &&
            ReferenceEquals(selected.Run, run) && StatusPendingPurgeSelector(run.Window.Binding.Selector))
        {
            if (phase == StatusPendingPurgePhase.Start)
                selected.StartProof = new(start.Binding, start.Target, start.ResponseBytes, start.RequestSha256, start.NativeRequestId);
            else if (phase == StatusPendingPurgePhase.Selected)
            {
                Require(selected.StartProof is not null && run.SelectedFacts is not null);
                selected.SelectedProof = new(selected.StartProof, run.SelectedFacts.ResponseSha256, run.SelectedFacts.NativeRequestId);
            }
            else
            {
                Require(selected.SelectedProof is not null);
                selected.CleanupProof = new(selected.SelectedProof);
            }
        }
        else if (statusPendingPurgeIndependents.TryGetValue(run.Window, out var independent) &&
            ReferenceEquals(independent.Run, run) && StatusPendingPurgeIndependentSelector(run.Window.Binding.Selector))
        {
            if (phase == StatusPendingPurgePhase.Start)
                independent.StartProof = new(start.Binding, start.Target, start.ResponseBytes, start.RequestSha256, start.NativeRequestId);
            else if (phase == StatusPendingPurgePhase.Selected)
            {
                Require(independent.StartProof is not null && run.SelectedFacts is not null);
                independent.SelectedProof = new(independent.StartProof, run.SelectedFacts.ResponseSha256, run.SelectedFacts.NativeRequestId);
            }
            else
            {
                Require(independent.SelectedProof is not null);
                independent.CleanupProof = new(independent.SelectedProof);
            }
        }
        else if (statusPendingPurgeCancellations.TryGetValue(run.Window, out var cancellation) &&
            ReferenceEquals(cancellation.Run, run) && StatusPendingPurgeCancellationSelector(run.Window.Binding.Selector))
        {
            if (phase == StatusPendingPurgePhase.Start)
                cancellation.StartProof = new(start.Binding, start.Target, start.ResponseBytes, start.RequestSha256, start.NativeRequestId);
            else if (phase == StatusPendingPurgePhase.Canceled)
            {
                Require(cancellation.StartProof is not null);
                cancellation.CanceledProof = new(cancellation.StartProof);
            }
            else if (phase == StatusPendingPurgePhase.Selected)
            {
                Require(cancellation.StartProof is not null && StatusPendingPurgeCancellationCanceledValid(cancellation) &&
                    run.SelectedFacts is not null);
                cancellation.SelectedProof = new(cancellation.StartProof, cancellation.CanceledProof!,
                    run.SelectedFacts.ResponseSha256, run.SelectedFacts.NativeRequestId);
            }
            else
            {
                Require(cancellation.SelectedProof is not null && StatusPendingPurgeCancellationCanceledValid(cancellation));
                cancellation.CleanupProof = new(cancellation.SelectedProof);
            }
        }
        else if (statusCanceledPurges.TryGetValue(run.Window, out var providerCanceled) &&
            ReferenceEquals(providerCanceled.Run, run) && StatusCanceledPurgeSelector(run.Window.Binding.Selector))
        {
            if (phase == StatusPendingPurgePhase.Start)
                providerCanceled.StartProof = new(start.Binding, start.Target, start.ResponseBytes,
                    start.RequestSha256, start.NativeRequestId);
            else
            {
                Require(phase == StatusPendingPurgePhase.TerminalCancellation &&
                    providerCanceled.StartProof is not null && run.SelectedFacts is not null);
                providerCanceled.TerminalCancellationProof = new(providerCanceled.StartProof,
                    run.SelectedFacts.ResponseSha256, run.SelectedFacts.NativeRequestId);
            }
        }
        else if (statusCanceledPurgeIndependents.TryGetValue(run.Window, out var providerCanceledIndependent) &&
            ReferenceEquals(providerCanceledIndependent.Run, run) && StatusCanceledPurgeIndependentSelector(run.Window.Binding.Selector))
        {
            if (phase == StatusPendingPurgePhase.Start)
                providerCanceledIndependent.StartProof = new(start.Binding, start.Target, start.ResponseBytes,
                    start.RequestSha256, start.NativeRequestId);
            else
            {
                Require(phase == StatusPendingPurgePhase.TerminalCancellation &&
                    providerCanceledIndependent.StartProof is not null && run.SelectedFacts is not null);
                providerCanceledIndependent.TerminalCancellationProof = new(providerCanceledIndependent.StartProof,
                    run.SelectedFacts.ResponseSha256, run.SelectedFacts.NativeRequestId);
            }
        }
        else if (statusCanceledPurgeCancellations.TryGetValue(run.Window, out var providerCanceledCancellation) &&
            ReferenceEquals(providerCanceledCancellation.Run, run) && StatusCanceledPurgeCancellationSelector(run.Window.Binding.Selector))
        {
            if (phase == StatusPendingPurgePhase.Start)
                providerCanceledCancellation.StartProof = new(start.Binding, start.Target, start.ResponseBytes,
                    start.RequestSha256, start.NativeRequestId);
            else if (phase == StatusPendingPurgePhase.Canceled)
            {
                Require(providerCanceledCancellation.StartProof is not null);
                providerCanceledCancellation.CanceledProof = new(this, providerCanceledCancellation.StartProof);
            }
            else
            {
                Require(phase == StatusPendingPurgePhase.TerminalCancellation &&
                    providerCanceledCancellation.StartProof is not null &&
                    StatusCanceledPurgeCancellationCanceledValid(providerCanceledCancellation) && run.SelectedFacts is not null);
                providerCanceledCancellation.TerminalCancellationProof = new(providerCanceledCancellation.StartProof,
                    providerCanceledCancellation.CanceledProof!, run.SelectedFacts.ResponseSha256, run.SelectedFacts.NativeRequestId);
            }
        }
        else if (statusFailedPurges.TryGetValue(run.Window, out var failed) &&
            ReferenceEquals(failed.Run, run) && StatusFailedPurgeSelector(run.Window.Binding.Selector))
        {
            if (phase == StatusPendingPurgePhase.Start)
                failed.StartProof = new(start.Binding, start.Target, start.ResponseBytes, start.RequestSha256, start.NativeRequestId);
            else
            {
                Require(phase == StatusPendingPurgePhase.TerminalFailure &&
                    failed.StartProof is not null && run.SelectedFacts is not null);
                failed.TerminalFailureProof = new(failed.StartProof,
                    run.SelectedFacts.ResponseSha256, run.SelectedFacts.NativeRequestId);
            }
        }
        else if (statusFailedPurgeIndependents.TryGetValue(run.Window, out var failedIndependent) &&
            ReferenceEquals(failedIndependent.Run, run) && StatusFailedPurgeIndependentSelector(run.Window.Binding.Selector))
        {
            if (phase == StatusPendingPurgePhase.Start)
                failedIndependent.StartProof = new(start.Binding, start.Target, start.ResponseBytes, start.RequestSha256, start.NativeRequestId);
            else
            {
                Require(phase == StatusPendingPurgePhase.TerminalFailure &&
                    failedIndependent.StartProof is not null && run.SelectedFacts is not null);
                failedIndependent.TerminalFailureProof = new(failedIndependent.StartProof,
                    run.SelectedFacts.ResponseSha256, run.SelectedFacts.NativeRequestId);
            }
        }
        else if (statusFailedPurgeCancellations.TryGetValue(run.Window, out var failedCancellation) &&
            ReferenceEquals(failedCancellation.Run, run) && StatusFailedPurgeCancellationSelector(run.Window.Binding.Selector))
        {
            if (phase == StatusPendingPurgePhase.Start)
                failedCancellation.StartProof = new(start.Binding, start.Target, start.ResponseBytes, start.RequestSha256, start.NativeRequestId);
            else if (phase == StatusPendingPurgePhase.Canceled)
            {
                Require(failedCancellation.StartProof is not null);
                failedCancellation.CanceledProof = new(this, failedCancellation.StartProof);
            }
            else
            {
                Require(phase == StatusPendingPurgePhase.TerminalFailure &&
                    failedCancellation.StartProof is not null && StatusFailedPurgeCancellationCanceledValid(failedCancellation) &&
                    run.SelectedFacts is not null);
                failedCancellation.TerminalFailureProof = new(failedCancellation.StartProof, failedCancellation.CanceledProof!,
                    run.SelectedFacts.ResponseSha256, run.SelectedFacts.NativeRequestId);
            }
        }
        else
        {
            run.Invalid = true;
            Require(false);
        }
    }

    internal void RevokeStatusPendingPurgeSelected(Window window) =>
        RevokeStatusPendingPurgeSelectedCore(RequireStatusPendingPurgeRun(window, window.Binding.Selector));

    internal void RevokeStatusPendingPurgeIndependentSelected(Window window) =>
        RevokeStatusPendingPurgeSelectedCore(RequireStatusPendingPurgeIndependentRun(window, window.Binding.Selector));

    internal void RevokeStatusPendingPurgeCancellationSelected(Window window) =>
        RevokeStatusPendingPurgeSelectedCore(RequireStatusPendingPurgeCancellationRun(window, window.Binding.Selector));

    internal void RevokeStatusFailedPurgeSelected(Window window) =>
        RevokeStatusPendingPurgeSelectedCore(RequireStatusFailedPurgeRun(window, window.Binding.Selector));

    internal void RevokeStatusCanceledPurgeSelected(Window window) =>
        RevokeStatusPendingPurgeSelectedCore(RequireStatusCanceledPurgeRun(window, window.Binding.Selector));

    internal void RevokeStatusCanceledPurgeIndependentSelected(Window window) =>
        RevokeStatusPendingPurgeSelectedCore(RequireStatusCanceledPurgeIndependentRun(window, window.Binding.Selector));

    internal void RevokeStatusFailedPurgeIndependentSelected(Window window) =>
        RevokeStatusPendingPurgeSelectedCore(RequireStatusFailedPurgeIndependentRun(window, window.Binding.Selector));

    internal void RevokeStatusFailedPurgeCancellationSelected(Window window) =>
        RevokeStatusPendingPurgeSelectedCore(RequireStatusFailedPurgeCancellationRun(window, window.Binding.Selector));

    internal void RevokeStatusCanceledPurgeCancellationSelected(Window window) =>
        RevokeStatusPendingPurgeSelectedCore(RequireStatusCanceledPurgeCancellationRun(window, window.Binding.Selector));

    private void RevokeStatusPendingPurgeSelectedCore(StatusPendingPurgeRun r)
    {
        lock (gate)
        {
            if (r.SelectedRevoked) return;
            r.Invalid |= !StatusPendingPurgeLive(r) || r.StartFacts is null || r.SelectedFacts is null ||
                r.Start is not { Finished: true } || r.Selected is not { Finished: true } ||
                r.Start.Token.IsCancellationRequested || r.Selected.Token.IsCancellationRequested ||
                statusPendingPurgeCancellations.TryGetValue(r.Window, out var cancellation) &&
                    !StatusPendingPurgeCancellationCanceledValid(cancellation) ||
                statusFailedPurgeCancellations.TryGetValue(r.Window, out var failedCancellation) &&
                    !StatusFailedPurgeCancellationCanceledValid(failedCancellation) ||
                statusCanceledPurgeCancellations.TryGetValue(r.Window, out var providerCanceledCancellation) &&
                    !StatusCanceledPurgeCancellationCanceledValid(providerCanceledCancellation) ||
                !StatusPendingPurgeHistoryValid(r);
            r.SelectedRevoked = true;
            r.Window.Closed = true;
            if (r.Invalid) r.Clock.Revoke();
        }
    }

    private bool StatusPendingPurgeIdentity(StatusPendingPurgeRun r, Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle)
    {
        if (!ReferenceEquals(r.Window, window) ||
            !ReferenceEquals(window.Owner, owner) || !ReferenceEquals(window.Binding, binding) ||
            !ReferenceEquals(r.Client, client) || !ReferenceEquals(r.Scope, scope) ||
            !ReferenceEquals(binding.Resource, scope) || !ReferenceEquals(r.Receipt, receipt) ||
            !ReferenceEquals(r.Start?.NativeTask, startTask) || !ReferenceEquals(r.Handle, handle) ||
            startTask is not { IsCompletedSuccessfully: true } || r.Start is not { Finished: true } ||
            r.StartFacts is null || receipt.Evidence != DispatchEvidence.Pending ||
            !StatusPendingPurgeLive(r) || !StatusPendingPurgeHistoryValid(r) ||
            !r.SelectedRevoked && (r.Start.Token.IsCancellationRequested ||
                r.Selected is { } selected && selected.Token.IsCancellationRequested) ||
            r.Cleanup is { } cleanup && cleanup.Token.IsCancellationRequested)
            return false;
        return true;
    }

    internal bool TryGetStatusPendingPurgeStart(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        [NotNullWhen(true)] out StatusPendingPurgeStartProof? proof)
    {
        lock (gate)
        {
            proof = window is not null && statusPendingPurges.TryGetValue(window, out var r) &&
                StatusPendingPurgeSelector(window.Binding.Selector) &&
                StatusPendingPurgeIdentity(r.Run, window, binding, client, scope, receipt, startTask, handle)
                ? r.StartProof : null;
            return proof is not null;
        }
    }

    internal bool TryGetStatusPendingPurgeSelected(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task checkTask,
        [NotNullWhen(true)] out StatusPendingPurgeSelectedProof? proof)
    {
        lock (gate)
        {
            proof = window is not null && statusPendingPurges.TryGetValue(window, out var r) &&
                StatusPendingPurgeSelector(window.Binding.Selector) &&
                StatusPendingPurgeIdentity(r.Run, window, binding, client, scope, receipt, startTask, handle) &&
                r.Run.Selected is { Finished: true } && ReferenceEquals(r.Run.Selected.NativeTask, checkTask) &&
                checkTask.IsCompletedSuccessfully ? r.SelectedProof : null;
            return proof is not null;
        }
    }

    internal bool TryGetStatusPendingPurgeCleanup(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task checkTask,
        [NotNullWhen(true)] out StatusPendingPurgeCleanupProof? proof)
    {
        lock (gate)
        {
            proof = window is not null && statusPendingPurges.TryGetValue(window, out var r) &&
                StatusPendingPurgeSelector(window.Binding.Selector) &&
                StatusPendingPurgeIdentity(r.Run, window, binding, client, scope, receipt, startTask, handle) &&
                r.Run.SelectedRevoked && window.Closed && r.Run.Cleanup is { Finished: true } &&
                ReferenceEquals(r.Run.Cleanup.NativeTask, checkTask) && checkTask.IsCompletedSuccessfully &&
                handle.State == NativeProvisioningState.Succeeded ? r.CleanupProof : null;
            return proof is not null;
        }
    }

    internal bool OwnsStatusPendingPurgeStart(StatusPendingPurgeStartProof proof, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle) =>
        TryGetStatusPendingPurgeStart(window, binding, client, scope, receipt, startTask, handle, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool OwnsStatusPendingPurgeSelected(StatusPendingPurgeSelectedProof proof, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task checkTask) =>
        TryGetStatusPendingPurgeSelected(window, binding, client, scope, receipt, startTask, handle, checkTask, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool OwnsStatusPendingPurgeCleanup(StatusPendingPurgeCleanupProof proof, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task checkTask) =>
        TryGetStatusPendingPurgeCleanup(window, binding, client, scope, receipt, startTask, handle, checkTask, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool TryGetStatusPendingPurgeIndependentStart(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        [NotNullWhen(true)] out StatusPendingPurgeIndependentStartProof? proof)
    {
        lock (gate)
        {
            proof = window is not null && statusPendingPurgeIndependents.TryGetValue(window, out var r) &&
                StatusPendingPurgeIndependentSelector(window.Binding.Selector) &&
                StatusPendingPurgeIdentity(r.Run, window, binding, client, scope, receipt, startTask, handle)
                ? r.StartProof : null;
            return proof is not null;
        }
    }

    internal bool TryGetStatusPendingPurgeIndependentSelected(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task checkTask,
        [NotNullWhen(true)] out StatusPendingPurgeIndependentSelectedProof? proof)
    {
        lock (gate)
        {
            proof = window is not null && statusPendingPurgeIndependents.TryGetValue(window, out var r) &&
                StatusPendingPurgeIndependentSelector(window.Binding.Selector) &&
                StatusPendingPurgeIdentity(r.Run, window, binding, client, scope, receipt, startTask, handle) &&
                r.Run.Selected is { Finished: true } && ReferenceEquals(r.Run.Selected.NativeTask, checkTask) &&
                checkTask.IsCompletedSuccessfully ? r.SelectedProof : null;
            return proof is not null;
        }
    }

    internal bool TryGetStatusPendingPurgeIndependentCleanup(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task checkTask,
        [NotNullWhen(true)] out StatusPendingPurgeIndependentCleanupProof? proof)
    {
        lock (gate)
        {
            proof = window is not null && statusPendingPurgeIndependents.TryGetValue(window, out var r) &&
                StatusPendingPurgeIndependentSelector(window.Binding.Selector) &&
                StatusPendingPurgeIdentity(r.Run, window, binding, client, scope, receipt, startTask, handle) &&
                r.Run.SelectedRevoked && window.Closed && r.Run.Cleanup is { Finished: true } &&
                ReferenceEquals(r.Run.Cleanup.NativeTask, checkTask) && checkTask.IsCompletedSuccessfully &&
                handle.State == NativeProvisioningState.Succeeded ? r.CleanupProof : null;
            return proof is not null;
        }
    }

    internal bool OwnsStatusPendingPurgeIndependentStart(StatusPendingPurgeIndependentStartProof proof, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle) =>
        TryGetStatusPendingPurgeIndependentStart(window, binding, client, scope, receipt, startTask, handle, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool OwnsStatusPendingPurgeIndependentSelected(StatusPendingPurgeIndependentSelectedProof proof, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task checkTask) =>
        TryGetStatusPendingPurgeIndependentSelected(window, binding, client, scope, receipt, startTask, handle, checkTask, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool OwnsStatusPendingPurgeIndependentCleanup(StatusPendingPurgeIndependentCleanupProof proof, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task checkTask) =>
        TryGetStatusPendingPurgeIndependentCleanup(window, binding, client, scope, receipt, startTask, handle, checkTask, out var issued) &&
        ReferenceEquals(proof, issued);

    private static bool StatusPendingPurgeCancellationCanceledValid(StatusPendingPurgeCancellationRegistration registration)
    {
        var r = registration.Run;
        return registration.StartProof is not null && registration.CanceledProof is { } proof &&
            ReferenceEquals(proof.Start, registration.StartProof) &&
            r.Canceled is { Finished: true, HookReturned: true, Success: true, CancellationObserved: true,
                FactoryActive: false, Sending: false, Factories: 0, SendCount: 0 } slot &&
            slot.Drained.Task.IsCompletedSuccessfully && slot.Token.IsCancellationRequested &&
            slot.NativeTask is { IsCanceled: true } && slot.Requests.Count == 0 &&
            slot.Sends.Count == 0 && slot.Responses.Count == 0;
    }

    internal bool TryGetStatusPendingPurgeCancellationStart(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        [NotNullWhen(true)] out StatusPendingPurgeCancellationStartProof? proof)
    {
        lock (gate)
        {
            proof = window is not null && statusPendingPurgeCancellations.TryGetValue(window, out var r) &&
                StatusPendingPurgeCancellationSelector(window.Binding.Selector) &&
                StatusPendingPurgeIdentity(r.Run, window, binding, client, scope, receipt, startTask, handle)
                ? r.StartProof : null;
            return proof is not null;
        }
    }

    internal bool TryGetStatusPendingPurgeCancellationCanceled(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task canceledTask,
        [NotNullWhen(true)] out StatusPendingPurgeCancellationCanceledProof? proof)
    {
        lock (gate)
        {
            proof = window is not null && statusPendingPurgeCancellations.TryGetValue(window, out var r) &&
                StatusPendingPurgeCancellationSelector(window.Binding.Selector) &&
                StatusPendingPurgeIdentity(r.Run, window, binding, client, scope, receipt, startTask, handle) &&
                StatusPendingPurgeCancellationCanceledValid(r) && ReferenceEquals(r.Run.Canceled!.NativeTask, canceledTask)
                ? r.CanceledProof : null;
            return proof is not null;
        }
    }

    internal bool TryGetStatusPendingPurgeCancellationSelected(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task canceledTask,
        Task checkTask, [NotNullWhen(true)] out StatusPendingPurgeCancellationSelectedProof? proof)
    {
        lock (gate)
        {
            proof = window is not null && statusPendingPurgeCancellations.TryGetValue(window, out var r) &&
                StatusPendingPurgeCancellationSelector(window.Binding.Selector) &&
                StatusPendingPurgeIdentity(r.Run, window, binding, client, scope, receipt, startTask, handle) &&
                StatusPendingPurgeCancellationCanceledValid(r) && ReferenceEquals(r.Run.Canceled!.NativeTask, canceledTask) &&
                r.Run.Selected is { Finished: true } selected && selected.Drained.Task.IsCompletedSuccessfully &&
                ReferenceEquals(selected.NativeTask, checkTask) && checkTask.IsCompletedSuccessfully &&
                r.SelectedProof is { } issued && ReferenceEquals(issued.Start, r.StartProof) &&
                ReferenceEquals(issued.Canceled, r.CanceledProof) ? issued : null;
            return proof is not null;
        }
    }

    internal bool TryGetStatusPendingPurgeCancellationCleanup(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task canceledTask,
        Task checkTask, Task cleanupTask, [NotNullWhen(true)] out StatusPendingPurgeCancellationCleanupProof? proof)
    {
        lock (gate)
        {
            proof = window is not null && statusPendingPurgeCancellations.TryGetValue(window, out var r) &&
                StatusPendingPurgeCancellationSelector(window.Binding.Selector) &&
                StatusPendingPurgeIdentity(r.Run, window, binding, client, scope, receipt, startTask, handle) &&
                StatusPendingPurgeCancellationCanceledValid(r) && ReferenceEquals(r.Run.Canceled!.NativeTask, canceledTask) &&
                r.Run.Selected is { Finished: true } selected && selected.Drained.Task.IsCompletedSuccessfully &&
                ReferenceEquals(selected.NativeTask, checkTask) && checkTask.IsCompletedSuccessfully &&
                r.Run.SelectedRevoked && window.Closed && r.Run.Cleanup is { Finished: true } cleanup &&
                cleanup.Drained.Task.IsCompletedSuccessfully && ReferenceEquals(cleanup.NativeTask, cleanupTask) &&
                cleanupTask.IsCompletedSuccessfully && handle.State == NativeProvisioningState.Succeeded &&
                r.CleanupProof is { } issued && ReferenceEquals(issued.Start, r.StartProof) &&
                ReferenceEquals(issued.Canceled, r.CanceledProof) && ReferenceEquals(issued.Selected, r.SelectedProof)
                ? issued : null;
            return proof is not null;
        }
    }

    internal bool OwnsStatusPendingPurgeCancellationStart(StatusPendingPurgeCancellationStartProof proof, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle) =>
        TryGetStatusPendingPurgeCancellationStart(window, binding, client, scope, receipt, startTask, handle, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool OwnsStatusPendingPurgeCancellationCanceled(StatusPendingPurgeCancellationCanceledProof proof, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        Task canceledTask) =>
        TryGetStatusPendingPurgeCancellationCanceled(window, binding, client, scope, receipt, startTask, handle, canceledTask, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool OwnsStatusPendingPurgeCancellationSelected(StatusPendingPurgeCancellationSelectedProof proof, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        Task canceledTask, Task checkTask) =>
        TryGetStatusPendingPurgeCancellationSelected(window, binding, client, scope, receipt, startTask, handle,
            canceledTask, checkTask, out var issued) && ReferenceEquals(proof, issued);

    internal bool OwnsStatusPendingPurgeCancellationCleanup(StatusPendingPurgeCancellationCleanupProof proof, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        Task canceledTask, Task checkTask, Task cleanupTask) =>
        TryGetStatusPendingPurgeCancellationCleanup(window, binding, client, scope, receipt, startTask, handle,
            canceledTask, checkTask, cleanupTask, out var issued) && ReferenceEquals(proof, issued);

    internal bool TryGetStatusCanceledPurgeStart(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        [NotNullWhen(true)] out StatusCanceledPurgeStartProof? proof)
    {
        lock (gate)
        {
            proof = window is not null && statusCanceledPurges.TryGetValue(window, out var r) &&
                StatusCanceledPurgeSelector(window.Binding.Selector) &&
                StatusPendingPurgeIdentity(r.Run, window, binding, client, scope, receipt, startTask, handle) &&
                r.Run.Start!.Drained.Task.IsCompletedSuccessfully &&
                r.StartProof is { } issued && ReferenceEquals(issued.Binding, binding) &&
                ReferenceEquals(issued.Target, r.Run.StartFacts!.Target) &&
                ReferenceEquals(targets.GetValueOrDefault(window), issued.Target) ? issued : null;
            return proof is not null;
        }
    }

    internal bool TryGetStatusCanceledPurgeTerminalCancellation(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task checkTask,
        [NotNullWhen(true)] out StatusCanceledPurgeTerminalCancellationProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusCanceledPurgeStart(window, binding, client, scope, receipt, startTask, handle, out var start) ||
                !statusCanceledPurges.TryGetValue(window, out var r) ||
                r.Run.Selected is not { Phase: StatusPendingPurgePhase.TerminalCancellation, Finished: true,
                    HookReturned: true, Success: true } selected ||
                !selected.Drained.Task.IsCompletedSuccessfully || !ReferenceEquals(selected.NativeTask, checkTask) ||
                !checkTask.IsCompletedSuccessfully || handle.State != NativeProvisioningState.Canceled ||
                r.Run.Canceled is not null || r.Run.Cleanup is not null ||
                r.TerminalCancellationProof is not { } issued || !ReferenceEquals(issued.Start, start))
                return false;
            proof = issued;
            return true;
        }
    }

    internal bool OwnsStatusCanceledPurgeStart(StatusCanceledPurgeStartProof proof, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle) =>
        TryGetStatusCanceledPurgeStart(window, binding, client, scope, receipt, startTask, handle, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool OwnsStatusCanceledPurgeTerminalCancellation(StatusCanceledPurgeTerminalCancellationProof proof,
        Window window, Binding binding, VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt,
        Task startTask, ManagementOperation handle, Task checkTask) =>
        TryGetStatusCanceledPurgeTerminalCancellation(window, binding, client, scope, receipt, startTask, handle, checkTask,
            out var issued) && ReferenceEquals(proof, issued);

    internal bool TryGetStatusCanceledPurgeIndependentStart(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        [NotNullWhen(true)] out StatusCanceledPurgeIndependentStartProof? proof)
    {
        lock (gate)
        {
            proof = window is not null && statusCanceledPurgeIndependents.TryGetValue(window, out var r) &&
                StatusCanceledPurgeIndependentSelector(window.Binding.Selector) &&
                StatusPendingPurgeIdentity(r.Run, window, binding, client, scope, receipt, startTask, handle) &&
                r.Run.Start!.Drained.Task.IsCompletedSuccessfully &&
                r.StartProof is { } issued && ReferenceEquals(issued.Binding, binding) &&
                ReferenceEquals(issued.Target, r.Run.StartFacts!.Target) &&
                ReferenceEquals(targets.GetValueOrDefault(window), issued.Target) ? issued : null;
            return proof is not null;
        }
    }

    internal bool TryGetStatusCanceledPurgeIndependentTerminalCancellation(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task checkTask,
        [NotNullWhen(true)] out StatusCanceledPurgeIndependentTerminalCancellationProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusCanceledPurgeIndependentStart(window, binding, client, scope, receipt, startTask, handle, out var start) ||
                !statusCanceledPurgeIndependents.TryGetValue(window, out var r) ||
                r.Run.Selected is not { Phase: StatusPendingPurgePhase.TerminalCancellation, Finished: true,
                    HookReturned: true, Success: true } selected ||
                !selected.Drained.Task.IsCompletedSuccessfully || !ReferenceEquals(selected.NativeTask, checkTask) ||
                !checkTask.IsCompletedSuccessfully || handle.State != NativeProvisioningState.Canceled ||
                r.Run.Canceled is not null || r.Run.Cleanup is not null ||
                r.TerminalCancellationProof is not { } issued || !ReferenceEquals(issued.Start, start))
                return false;
            proof = issued;
            return true;
        }
    }

    internal bool OwnsStatusCanceledPurgeIndependentStart(StatusCanceledPurgeIndependentStartProof proof, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle) =>
        TryGetStatusCanceledPurgeIndependentStart(window, binding, client, scope, receipt, startTask, handle, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool OwnsStatusCanceledPurgeIndependentTerminalCancellation(StatusCanceledPurgeIndependentTerminalCancellationProof proof,
        Window window, Binding binding, VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt,
        Task startTask, ManagementOperation handle, Task checkTask) =>
        TryGetStatusCanceledPurgeIndependentTerminalCancellation(window, binding, client, scope, receipt, startTask, handle, checkTask,
            out var issued) && ReferenceEquals(proof, issued);

    internal bool TryGetStatusFailedPurgeStart(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        [NotNullWhen(true)] out StatusFailedPurgeStartProof? proof)
    {
        lock (gate)
        {
            proof = window is not null && statusFailedPurges.TryGetValue(window, out var r) &&
                StatusFailedPurgeSelector(window.Binding.Selector) &&
                StatusPendingPurgeIdentity(r.Run, window, binding, client, scope, receipt, startTask, handle) &&
                r.Run.Start!.Drained.Task.IsCompletedSuccessfully &&
                r.StartProof is { } issued && ReferenceEquals(issued.Binding, binding) &&
                ReferenceEquals(issued.Target, r.Run.StartFacts!.Target) &&
                ReferenceEquals(targets.GetValueOrDefault(window), issued.Target) ? issued : null;
            return proof is not null;
        }
    }

    internal bool TryGetStatusFailedPurgeTerminalFailure(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task checkTask,
        [NotNullWhen(true)] out StatusFailedPurgeTerminalFailureProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusFailedPurgeStart(window, binding, client, scope, receipt, startTask, handle, out var start) ||
                !statusFailedPurges.TryGetValue(window, out var r) ||
                r.Run.Selected is not { Phase: StatusPendingPurgePhase.TerminalFailure, Finished: true,
                    HookReturned: true, Success: true } selected ||
                !selected.Drained.Task.IsCompletedSuccessfully || !ReferenceEquals(selected.NativeTask, checkTask) ||
                !checkTask.IsCompletedSuccessfully || handle.State != NativeProvisioningState.Failed ||
                r.Run.Canceled is not null || r.Run.Cleanup is not null ||
                r.TerminalFailureProof is not { } issued || !ReferenceEquals(issued.Start, start))
                return false;
            proof = issued;
            return true;
        }
    }

    internal bool OwnsStatusFailedPurgeStart(StatusFailedPurgeStartProof proof, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle) =>
        TryGetStatusFailedPurgeStart(window, binding, client, scope, receipt, startTask, handle, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool OwnsStatusFailedPurgeTerminalFailure(StatusFailedPurgeTerminalFailureProof proof, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task checkTask) =>
        TryGetStatusFailedPurgeTerminalFailure(window, binding, client, scope, receipt, startTask, handle, checkTask, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool TryGetStatusFailedPurgeIndependentStart(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        [NotNullWhen(true)] out StatusFailedPurgeIndependentStartProof? proof)
    {
        lock (gate)
        {
            proof = window is not null && statusFailedPurgeIndependents.TryGetValue(window, out var r) &&
                StatusFailedPurgeIndependentSelector(window.Binding.Selector) &&
                StatusPendingPurgeIdentity(r.Run, window, binding, client, scope, receipt, startTask, handle) &&
                r.Run.Start!.Drained.Task.IsCompletedSuccessfully &&
                r.StartProof is { } issued && ReferenceEquals(issued.Binding, binding) &&
                ReferenceEquals(issued.Target, r.Run.StartFacts!.Target) &&
                ReferenceEquals(targets.GetValueOrDefault(window), issued.Target) ? issued : null;
            return proof is not null;
        }
    }

    internal bool TryGetStatusFailedPurgeIndependentTerminalFailure(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task checkTask,
        [NotNullWhen(true)] out StatusFailedPurgeIndependentTerminalFailureProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusFailedPurgeIndependentStart(window, binding, client, scope, receipt, startTask, handle, out var start) ||
                !statusFailedPurgeIndependents.TryGetValue(window, out var r) ||
                r.Run.Selected is not { Phase: StatusPendingPurgePhase.TerminalFailure, Finished: true,
                    HookReturned: true, Success: true } selected ||
                !selected.Drained.Task.IsCompletedSuccessfully || !ReferenceEquals(selected.NativeTask, checkTask) ||
                !checkTask.IsCompletedSuccessfully || handle.State != NativeProvisioningState.Failed ||
                r.Run.Canceled is not null || r.Run.Cleanup is not null ||
                r.TerminalFailureProof is not { } issued || !ReferenceEquals(issued.Start, start))
                return false;
            proof = issued;
            return true;
        }
    }

    internal bool OwnsStatusFailedPurgeIndependentStart(StatusFailedPurgeIndependentStartProof proof, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle) =>
        TryGetStatusFailedPurgeIndependentStart(window, binding, client, scope, receipt, startTask, handle, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool OwnsStatusFailedPurgeIndependentTerminalFailure(StatusFailedPurgeIndependentTerminalFailureProof proof,
        Window window, Binding binding, VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt,
        Task startTask, ManagementOperation handle, Task checkTask) =>
        TryGetStatusFailedPurgeIndependentTerminalFailure(window, binding, client, scope, receipt, startTask, handle, checkTask, out var issued) &&
        ReferenceEquals(proof, issued);

    private static bool StatusFailedPurgeCancellationCanceledValid(StatusFailedPurgeCancellationRegistration registration)
    {
        var r = registration.Run;
        return registration.StartProof is not null && registration.CanceledProof is { } proof &&
            ReferenceEquals(proof.Start, registration.StartProof) &&
            r.Canceled is { Finished: true, HookReturned: true, Success: true, CancellationObserved: true,
                FactoryActive: false, Sending: false, Factories: 0, SendCount: 0 } slot &&
            slot.Drained.Task.IsCompletedSuccessfully && slot.Token.IsCancellationRequested &&
            slot.NativeTask is { IsCanceled: true } && slot.Requests.Count == 0 &&
            slot.Sends.Count == 0 && slot.Responses.Count == 0;
    }

    internal bool TryGetStatusFailedPurgeCancellationStart(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        [NotNullWhen(true)] out StatusFailedPurgeCancellationStartProof? proof)
    {
        lock (gate)
        {
            proof = window is not null && statusFailedPurgeCancellations.TryGetValue(window, out var r) &&
                StatusFailedPurgeCancellationSelector(window.Binding.Selector) &&
                StatusPendingPurgeIdentity(r.Run, window, binding, client, scope, receipt, startTask, handle) &&
                r.Run.Start!.Drained.Task.IsCompletedSuccessfully &&
                r.StartProof is { } issued && ReferenceEquals(issued.Binding, binding) &&
                ReferenceEquals(issued.Target, r.Run.StartFacts!.Target) &&
                ReferenceEquals(targets.GetValueOrDefault(window), issued.Target) ? issued : null;
            return proof is not null;
        }
    }

    internal bool TryGetStatusFailedPurgeCancellationCanceled(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task canceledTask,
        [NotNullWhen(true)] out StatusFailedPurgeCancellationCanceledProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusFailedPurgeCancellationStart(window, binding, client, scope, receipt, startTask, handle, out var start) ||
                !statusFailedPurgeCancellations.TryGetValue(window, out var r) ||
                !StatusFailedPurgeCancellationCanceledValid(r) || !ReferenceEquals(r.Run.Canceled!.NativeTask, canceledTask) ||
                r.CanceledProof is not { } issued || !ReferenceEquals(issued.Start, start))
                return false;
            proof = issued;
            return true;
        }
    }

    internal bool TryGetStatusFailedPurgeCancellationTerminalFailure(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task canceledTask,
        Task checkTask, [NotNullWhen(true)] out StatusFailedPurgeCancellationTerminalFailureProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusFailedPurgeCancellationCanceled(window, binding, client, scope, receipt, startTask,
                    handle, canceledTask, out var canceled) ||
                !statusFailedPurgeCancellations.TryGetValue(window, out var r) ||
                r.Run.Selected is not { Phase: StatusPendingPurgePhase.TerminalFailure, Finished: true,
                    HookReturned: true, Success: true } selected ||
                !selected.Drained.Task.IsCompletedSuccessfully || !ReferenceEquals(selected.NativeTask, checkTask) ||
                !checkTask.IsCompletedSuccessfully || ReferenceEquals(canceledTask, checkTask) ||
                handle.State != NativeProvisioningState.Failed || r.Run.Cleanup is not null ||
                r.TerminalFailureProof is not { } issued || !ReferenceEquals(issued.Start, r.StartProof) ||
                !ReferenceEquals(issued.Canceled, canceled))
                return false;
            proof = issued;
            return true;
        }
    }

    internal bool OwnsStatusFailedPurgeCancellationStart(StatusFailedPurgeCancellationStartProof proof,
        Window window, Binding binding, VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt,
        Task startTask, ManagementOperation handle) =>
        TryGetStatusFailedPurgeCancellationStart(window, binding, client, scope, receipt, startTask, handle, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool OwnsStatusFailedPurgeCancellationCanceled(StatusFailedPurgeCancellationCanceledProof proof,
        Window window, Binding binding, VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt,
        Task startTask, ManagementOperation handle, Task canceledTask) =>
        TryGetStatusFailedPurgeCancellationCanceled(window, binding, client, scope, receipt, startTask, handle,
            canceledTask, out var issued) && ReferenceEquals(proof, issued);

    internal bool OwnsStatusFailedPurgeCancellationTerminalFailure(StatusFailedPurgeCancellationTerminalFailureProof proof,
        Window window, Binding binding, VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt,
        Task startTask, ManagementOperation handle, Task canceledTask, Task checkTask) =>
        TryGetStatusFailedPurgeCancellationTerminalFailure(window, binding, client, scope, receipt, startTask, handle,
            canceledTask, checkTask, out var issued) && ReferenceEquals(proof, issued);

    private static bool StatusCanceledPurgeCancellationCanceledValid(StatusCanceledPurgeCancellationRegistration registration)
    {
        var r = registration.Run;
        return registration.StartProof is not null && registration.CanceledProof is { } proof &&
            ReferenceEquals(proof.Start, registration.StartProof) &&
            r.Canceled is { Finished: true, HookReturned: true, Success: true, CancellationObserved: true,
                FactoryActive: false, Sending: false, Factories: 0, SendCount: 0 } slot &&
            slot.Drained.Task.IsCompletedSuccessfully && slot.Token.IsCancellationRequested &&
            slot.NativeTask is { IsCanceled: true } && slot.Requests.Count == 0 &&
            slot.Sends.Count == 0 && slot.Responses.Count == 0;
    }

    internal bool TryGetStatusCanceledPurgeCancellationStart(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        [NotNullWhen(true)] out StatusCanceledPurgeCancellationStartProof? proof)
    {
        lock (gate)
        {
            proof = window is not null && statusCanceledPurgeCancellations.TryGetValue(window, out var r) &&
                StatusCanceledPurgeCancellationSelector(window.Binding.Selector) &&
                StatusPendingPurgeIdentity(r.Run, window, binding, client, scope, receipt, startTask, handle) &&
                r.Run.Start!.Drained.Task.IsCompletedSuccessfully &&
                r.StartProof is { } issued && ReferenceEquals(issued.Binding, binding) &&
                ReferenceEquals(issued.Target, r.Run.StartFacts!.Target) &&
                ReferenceEquals(targets.GetValueOrDefault(window), issued.Target) ? issued : null;
            return proof is not null;
        }
    }

    internal bool TryGetStatusCanceledPurgeCancellationCanceled(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task canceledTask,
        [NotNullWhen(true)] out StatusCanceledPurgeCancellationCanceledProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusCanceledPurgeCancellationStart(window, binding, client, scope, receipt, startTask, handle, out var start) ||
                !statusCanceledPurgeCancellations.TryGetValue(window, out var r) ||
                !StatusCanceledPurgeCancellationCanceledValid(r) || !ReferenceEquals(r.Run.Canceled!.NativeTask, canceledTask) ||
                r.CanceledProof is not { } issued || !ReferenceEquals(issued.Start, start))
                return false;
            proof = issued;
            return true;
        }
    }

    internal bool TryGetStatusCanceledPurgeCancellationTerminalCancellation(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task canceledTask,
        Task checkTask, [NotNullWhen(true)] out StatusCanceledPurgeCancellationTerminalCancellationProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusCanceledPurgeCancellationCanceled(window, binding, client, scope, receipt, startTask,
                    handle, canceledTask, out var canceled) ||
                !statusCanceledPurgeCancellations.TryGetValue(window, out var r) ||
                r.Run.Selected is not { Phase: StatusPendingPurgePhase.TerminalCancellation, Finished: true,
                    HookReturned: true, Success: true } selected ||
                !selected.Drained.Task.IsCompletedSuccessfully || !ReferenceEquals(selected.NativeTask, checkTask) ||
                !checkTask.IsCompletedSuccessfully || ReferenceEquals(canceledTask, checkTask) ||
                handle.State != NativeProvisioningState.Canceled || r.Run.Cleanup is not null ||
                r.TerminalCancellationProof is not { } issued || !ReferenceEquals(issued.Start, r.StartProof) ||
                !ReferenceEquals(issued.Canceled, canceled))
                return false;
            proof = issued;
            return true;
        }
    }

    internal bool OwnsStatusCanceledPurgeCancellationStart(StatusCanceledPurgeCancellationStartProof proof,
        Window window, Binding binding, VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt,
        Task startTask, ManagementOperation handle) =>
        TryGetStatusCanceledPurgeCancellationStart(window, binding, client, scope, receipt, startTask, handle, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool OwnsStatusCanceledPurgeCancellationCanceled(StatusCanceledPurgeCancellationCanceledProof proof,
        Window window, Binding binding, VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt,
        Task startTask, ManagementOperation handle, Task canceledTask) =>
        TryGetStatusCanceledPurgeCancellationCanceled(window, binding, client, scope, receipt, startTask, handle,
            canceledTask, out var issued) && ReferenceEquals(proof, issued);

    internal bool OwnsStatusCanceledPurgeCancellationTerminalCancellation(StatusCanceledPurgeCancellationTerminalCancellationProof proof,
        Window window, Binding binding, VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt,
        Task startTask, ManagementOperation handle, Task canceledTask, Task checkTask) =>
        TryGetStatusCanceledPurgeCancellationTerminalCancellation(window, binding, client, scope, receipt, startTask, handle,
            canceledTask, checkTask, out var issued) && ReferenceEquals(proof, issued);

    private async Task SendStatusPendingPurgeAsync(StatusPendingPurgeContext context, HttpMessage message)
    {
        var r = context.Registration;
        var slot = context.Slot;
        var request = message.Request;
        var headers = request.Headers.ToArray();
        var attempt = new Attempt { Dispatch = Guid.NewGuid() };
        try
        {
            lock (gate)
            {
                Require(StatusPendingPurgeLive(r) && slot.Phase != StatusPendingPurgePhase.Canceled &&
                    !slot.Finished && !slot.Sending &&
                    slot.Requests.TryGetValue(request, out var timestamp) && r.Clock.AuthorizationWithinBounds(timestamp) &&
                    ++slot.SendCount <= (slot.Phase == StatusPendingPurgePhase.Cleanup ? 2 : 1) &&
                    slot.SendCount == slot.Responses.Count + 1 &&
                    (slot.Phase == StatusPendingPurgePhase.Cleanup ? r.SelectedRevoked && r.Window.Closed
                        : !r.SelectedRevoked && !r.Window.Closed));
                slot.Sending = slot.Invocation.Sending = true;
                slot.Invocation.Attempts.Add(attempt);
            }
            bool start = slot.Phase == StatusPendingPurgePhase.Start;
            void Check()
            {
                Require(StatusPendingPurgeLive(r) && !slot.Token.IsCancellationRequested &&
                    !message.CancellationToken.IsCancellationRequested && ReferenceEquals(message.Request, request) &&
                    headers.SequenceEqual(request.Headers));
                OriginalVaultRequest(message, r.Window.Path, start ? RequestMethod.Post : RequestMethod.Get,
                    start ? null : r.StartFacts!.Target.TargetUri.AbsoluteUri);
                Headers(headers);
                Require(!request.Headers.Contains("Range"));
            }
            Check();
            Require(start ? r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched
                : r.Receipt.Evidence == DispatchEvidence.Pending);
            request.Headers.TryGetValue("Authorization", out var authorization);
            byte[] authorizationBytes = System.Text.Encoding.UTF8.GetBytes(authorization!);
            string authorizationSha256;
            try { authorizationSha256 = Convert.ToHexString(SHA256.HashData(authorizationBytes)); }
            finally { CryptographicOperations.ZeroMemory(authorizationBytes); }
            if (start) r.AuthorizationSha256 = authorizationSha256;
            else Require(r.AuthorizationSha256 == authorizationSha256);
            lock (gate)
            {
                Require(StatusPendingPurgeHistoryValid(r));
                foreach (var response in r.Responses) response.Superseded = true;
            }
            var storage = new OwnedArmResponse.Storage();
            lock (gate) r.Storage.Add(storage);
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) storage.Own(message.Response); }
            Check();
            Require(message.HasResponse);
            var original = message.Response;
            var stream = original.ContentStream;
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, storage, allowContinuation: start)
                .ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(original.ContentStream, stream) && body.Bytes.Length > 0 &&
                body.Response.Status == (start ? 202 : 200) &&
                !body.Response.Headers.Contains("WWW-Authenticate"));
            string? next = Continuation(r.Window, message);
            Require(start ? next is not null : next is null);
            using var json = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int nodes = 512;
            JsonRows(json.RootElement, ref nodes);
            var root = json.RootElement;
            bool terminalFailure = slot.Phase == StatusPendingPurgePhase.TerminalFailure;
            bool terminalCancellation = slot.Phase == StatusPendingPurgePhase.TerminalCancellation;
            Require(root.ValueKind == JsonValueKind.Object);
            if (root.TryGetProperty("id", out var id))
                Require(id.GetString() == (start ? r.Window.Path : r.StartFacts!.Target.TargetUri.AbsolutePath));
            if (terminalFailure || terminalCancellation)
            {
                Require(root.EnumerateObject().All(p => p.Name is "id" or "status" or "error") &&
                    root.TryGetProperty("status", out var state) && state.ValueKind == JsonValueKind.String &&
                    state.GetString() == (terminalCancellation ? "Canceled" : "Failed"));
                if (root.TryGetProperty("error", out var error))
                {
                    Require(error.ValueKind == JsonValueKind.Object &&
                        error.EnumerateObject().All(p => p.Name is "code" or "message") &&
                        error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String &&
                        code.GetString() is { Length: > 0 and <= 128 } errorCode && !errorCode.Any(char.IsControl) &&
                        error.TryGetProperty("message", out var text) && text.ValueKind == JsonValueKind.String &&
                        text.GetString() is { Length: > 0 and <= 2048 } errorMessage && !errorMessage.Any(char.IsControl));
                }
            }
            else
            {
                Require(root.EnumerateObject().All(p => p.Name is "id" or "status" or "properties"));
                bool direct = root.TryGetProperty("status", out var state);
                bool nested = root.TryGetProperty("properties", out var properties);
                Require(direct != nested);
                if (nested) Require(properties.ValueKind == JsonValueKind.Object &&
                    properties.EnumerateObject().All(p => p.Name == "provisioningState"));
                Require((direct ? state.GetString() : properties.GetProperty("provisioningState").GetString()) ==
                    (slot.Phase == StatusPendingPurgePhase.Cleanup ? "Succeeded" : "InProgress"));
            }
            if (start)
            {
                byte[] targetBytes = System.Text.Encoding.UTF8.GetBytes(next!);
                byte[] requestBytes = System.Text.Encoding.UTF8.GetBytes("POST " + request.Uri.ToUri().AbsoluteUri);
                try
                {
                    var target = new StatusTarget(r.Window.Binding, attempt.Dispatch, StatusTargetKind.Operation, new Uri(next!),
                        Convert.ToHexString(SHA256.HashData(targetBytes)), body.Sha256);
                    r.Candidate = new(r.Window.Binding, target, body.Bytes.Length,
                        Convert.ToHexString(SHA256.HashData(requestBytes)), body.NativeRequestId);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(targetBytes);
                    CryptographicOperations.ZeroMemory(requestBytes);
                }
            }
            var parser = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, storage,
                requireRebuffer: true, requireDownstreamRead: !start &&
                    !(slot.Phase == StatusPendingPurgePhase.Cleanup && slot.SendCount == 2));
            var frame = new StatusPendingPurgeResponse(body, parser, storage);
            lock (gate)
            {
                slot.Responses.Add(frame);
                r.Responses.Add(frame);
                attempt.HttpStatus = body.Response.Status;
                attempt.ResponseSha256 = body.Sha256;
                attempt.ResponseObserved = true;
                attempt.HasProviderContinuation = next is not null;
                attempt.State = terminalCancellation ? WireState.Canceled : terminalFailure ? WireState.Failed :
                    slot.Phase == StatusPendingPurgePhase.Cleanup ? WireState.Succeeded : WireState.Pending;
                attempt.Valid = true;
            }
            Check();
        }
        catch { r.Invalid = true; attempt.Valid = false; throw; }
        finally
        {
            lock (gate)
            {
                attempt.TransportTerminated = true;
                slot.Sending = slot.Invocation.Sending = false;
            }
        }
    }

    private Task<Capture> SealStatusPendingPurgeAsync(Window window)
    {
        lock (gate)
        {
            Require(TryGetStatusPendingPurgeRun(window, out var r));
            r.Sealed = r.SelectedRevoked = window.Closed = true;
            r.Clock.Revoke();
            return r.SealTask ??= Drain();

            async Task<Capture> Drain()
            {
                Task[] tasks = new[] { r.Start, r.Canceled, r.Selected, r.Cleanup }.OfType<StatusPendingPurgeSlot>()
                    .Select(slot => slot.Drained.Task).ToArray();
                await Task.WhenAll(tasks).ConfigureAwait(false);
                bool failed = false;
                try { await r.Clock.DrainAsync().ConfigureAwait(false); } catch { failed = true; }
                foreach (var storage in r.Storage)
                    try { storage.Dispose(); } catch { failed = true; }
                r.Storage.Clear();
                r.AuthorizationSha256 = null;
                r.Invalid |= failed;
                Require(!failed);
                return new() { Binding = window.Binding, Start = r.Start?.Invocation, Status = r.Selected?.Invocation };
            }
        }
    }

    internal sealed class StatusSucceededDeleteVaultStartProof(Binding binding, StatusTarget target,
        int httpStatus, int responseBytes, string requestSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal StatusTarget Target { get; } = target;
        internal Guid StartDispatch => Target.StartDispatch;
        internal int HttpStatus { get; } = httpStatus;
        internal int ResponseBytes { get; } = responseBytes;
        internal string ResponseSha256 => Target.StartResponseSha256;
        internal string RequestSha256 { get; } = requestSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        public override string ToString() => "[StatusSucceededDeleteVaultStartProof]";
    }

    internal sealed class StatusSucceededDeleteVaultCompletionProof(StatusSucceededDeleteVaultStartProof start)
    {
        internal StatusSucceededDeleteVaultStartProof Start { get; } = start;
        public override string ToString() => "[StatusSucceededDeleteVaultCompletionProof]";
    }

    private sealed class StatusSucceededDeleteVaultRegistration(Window window, VaultAdministration client,
        VaultScope scope, ManagementReceipt receipt, CancellationToken token, Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Invocation Start = window.Start!;
        internal Invocation? Status;
        internal readonly VaultAdministration Client = client;
        internal readonly VaultScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken StartToken = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly HashSet<Request> Requests = new(ReferenceEqualityComparer.Instance);
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task? SendTask;
        internal ManagementOperation? Handle;
        internal OwnedArmResponse.ParserCustody? Parser;
        internal StatusSucceededDeleteVaultStartProof? Candidate, StartProof;
        internal StatusSucceededDeleteVaultCompletionProof? Completion;
        internal CancellationToken CheckToken;
        internal bool Invalid, Sealed, CheckClaimed, StartHook, CheckHook, StartSuccess, CheckSuccess;
        internal int Sends, CheckFactories;
    }
    private sealed record StatusSucceededDeleteVaultContext(StatusSucceededDeleteVaultRegistration Registration, bool Check);
    private readonly AsyncLocal<StatusSucceededDeleteVaultContext?> currentStatusSucceededDeleteVault = new();
    private readonly Dictionary<Window, StatusSucceededDeleteVaultRegistration> statusSucceededDeleteVault =
        new(ReferenceEqualityComparer.Instance);

    internal async Task<SecretOutcome<ManagementOperation>> StartStatusSucceededDeleteVaultAsync(Window window,
        FixtureSelector selector, VaultAdministration client, VaultScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token = default, Action<Task>? retained = null, Action? beforeSend = null)
    {
        StatusSucceededDeleteVaultRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(VaultFixtureProvisioner.StatusSucceededDeleteVaultSelector(selector) &&
                window.Binding.Operation == ManagementMutation.DeleteVault && window.Binding.ApiRevision == "2026-02-01" &&
                ReferenceEquals(window.Binding.Resource, scope) && client is not null && receipt is not null &&
                input.StatusOperation == ManagementMutation.DeleteVault && InputMatches(window.Binding, input) &&
                !window.Closed && window.Start is null && startedWindows.Add(window));
            window.Start = new();
            r = new(window, client, scope, receipt, token, beforeSend);
            statusSucceededDeleteVault.Add(window, r);
        }
        try
        {
            var previous = currentStatusSucceededDeleteVault.Value;
            currentStatusSucceededDeleteVault.Value = new(r, false);
            try
            {
                r.StartTask = ManagementOperationEffects.StartAsync(client, scope, ManagementMutation.DeleteVault,
                    input, receipt, token).AsTask();
                r.Start.SdkTask = r.StartTask;
            }
            finally { currentStatusSucceededDeleteVault.Value = previous; }
            try { retained?.Invoke(r.StartTask); r.StartHook = true; }
            finally
            {
                var result = await r.StartTask.ConfigureAwait(false);
                r.Handle = result.IsSuccess ? result.Value : null;
                r.StartSuccess = result.IsSuccess && r.Handle!.State == NativeProvisioningState.Succeeded &&
                    receipt.Evidence == DispatchEvidence.Applied;
                r.Start.Outcome = result.Status;
                r.Start.WrapperState = r.Handle?.State;
                r.Start.HasNativeHandle = r.Handle is not null;
            }
            return await r.StartTask.ConfigureAwait(false);
        }
        catch { r.Invalid = true; throw; }
        finally
        {
            if (r.StartTask is not null)
                try { await r.StartTask.ConfigureAwait(false); } catch { r.Invalid = true; }
            if (r.SendTask is not null)
                try { await r.SendTask.ConfigureAwait(false); } catch { r.Invalid = true; }
            bool custody = r.Parser is { Complete: true, Invalid: false };
            try { r.Storage.Dispose(); } catch { r.Invalid = true; }
            lock (gate)
            {
                r.Invalid |= !custody || r.Parser is not { Complete: true, Invalid: false };
                if (!r.Invalid && !r.Sealed && r.StartHook && r.StartSuccess && r.Sends == 1 &&
                    r.StartTask is { IsCompletedSuccessfully: true } && !token.IsCancellationRequested &&
                    r.Candidate is not null && receipt.Evidence == DispatchEvidence.Applied)
                {
                    r.StartProof = r.Candidate;
                    targets[window] = r.Candidate.Target;
                    eligible.Add(window);
                }
                r.Start.Terminated = true;
                r.Start.Drained.TrySetResult();
                r.Started.TrySetResult();
            }
        }
    }

    internal bool TryGetStatusSucceededDeleteVaultStart(Window window, Binding binding, VaultAdministration client,
        VaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        [NotNullWhen(true)] out StatusSucceededDeleteVaultStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!statusSucceededDeleteVault.TryGetValue(window, out var r) || r.Invalid || r.Sealed ||
                !ReferenceEquals(window.Binding, binding) || !ReferenceEquals(r.Client, client) ||
                !ReferenceEquals(r.Scope, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.StartTask, startTask) || !ReferenceEquals(r.Handle, handle) ||
                !r.Started.Task.IsCompletedSuccessfully || !startTask.IsCompletedSuccessfully ||
                r.StartToken.IsCancellationRequested || receipt.Evidence != DispatchEvidence.Applied ||
                handle.State != NativeProvisioningState.Succeeded || r.StartProof is null ||
                !ReferenceEquals(targets.GetValueOrDefault(window), r.StartProof.Target) ||
                completedStatusReads.Contains(window)) return false;
            proof = r.StartProof;
            return true;
        }
    }

    internal bool TryGetStatusSucceededDeleteVaultCompletion(Window window, Binding binding, VaultAdministration client,
        VaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task statusTask,
        [NotNullWhen(true)] out StatusSucceededDeleteVaultCompletionProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusSucceededDeleteVaultStart(window, binding, client, scope, receipt, startTask, handle, out _) ||
                !statusSucceededDeleteVault.TryGetValue(window, out var r) || !ReferenceEquals(r.StatusTask, statusTask) ||
                !r.Checked.Task.IsCompletedSuccessfully || !statusTask.IsCompletedSuccessfully ||
                r.CheckToken.IsCancellationRequested || r.Completion is null) return false;
            proof = r.Completion;
            return true;
        }
    }

    private async Task<SecretStatus> CheckStatusSucceededDeleteVaultAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained)
    {
        StatusSucceededDeleteVaultRegistration r;
        lock (gate)
        {
            Own(window, selector);
            r = statusSucceededDeleteVault[window];
            Require(ReferenceEquals(r.Handle, handle));
            bool valid = !r.CheckClaimed && !window.Closed && !token.IsCancellationRequested &&
                TryGetStatusSucceededDeleteVaultStart(window, window.Binding, r.Client, r.Scope, r.Receipt,
                    r.StartTask!, handle, out _);
            r.CheckClaimed = true;
            r.Invalid |= !valid;
            Require(valid);
            r.CheckToken = token;
            r.Status = window.Status = new();
        }
        try
        {
            var previous = currentStatusSucceededDeleteVault.Value;
            currentStatusSucceededDeleteVault.Value = new(r, true);
            try { r.StatusTask = handle.CheckStatusAsync(token).AsTask(); r.Status!.SdkTask = r.StatusTask; }
            finally { currentStatusSucceededDeleteVault.Value = previous; }
            try { retained?.Invoke(r.StatusTask); r.CheckHook = true; }
            finally
            {
                var outcome = await r.StatusTask.ConfigureAwait(false);
                r.CheckSuccess = outcome == SecretStatus.Success && handle.State == NativeProvisioningState.Succeeded &&
                    r.Receipt.Evidence == DispatchEvidence.Applied;
                r.Status!.Outcome = outcome;
                r.Status.WrapperState = handle.State;
            }
            return await r.StatusTask.ConfigureAwait(false);
        }
        catch { r.Invalid = true; throw; }
        finally
        {
            if (r.StatusTask is not null)
                try { await r.StatusTask.ConfigureAwait(false); } catch { r.Invalid = true; }
            lock (gate)
            {
                if (!r.Invalid && !r.Sealed && r.CheckHook && r.CheckSuccess && r.CheckFactories == 0 &&
                    r.StatusTask is { IsCompletedSuccessfully: true } && !token.IsCancellationRequested &&
                    !r.StartToken.IsCancellationRequested && r.StartProof is not null)
                    r.Completion = new(r.StartProof);
                r.Status!.Terminated = true;
                r.Status.Drained.TrySetResult();
                r.Checked.TrySetResult();
            }
        }
    }

    private async Task<Capture> SealStatusSucceededDeleteVaultAsync(Window window)
    {
        StatusSucceededDeleteVaultRegistration r;
        lock (gate) { r = statusSucceededDeleteVault[window]; r.Sealed = true; window.Closed = true; }
        await r.Started.Task.ConfigureAwait(false);
        if (r.Status is not null) await r.Checked.Task.ConfigureAwait(false);
        return new() { Binding = window.Binding, Start = r.Start, Status = r.Status };
    }

    private async Task SendStatusSucceededDeleteVaultAsync(StatusSucceededDeleteVaultContext context, HttpMessage message)
    {
        var r = context.Registration;
        var request = message.Request;
        var headers = request.Headers.ToArray();
        void Check()
        {
            Require(!r.Invalid && !r.Sealed && !context.Check && ReferenceEquals(message.Request, request) &&
                headers.SequenceEqual(request.Headers) && request.Method == RequestMethod.Delete &&
                request.Content is null && Trusted(request.Uri.ToUri()) &&
                request.Uri.ToUri().AbsoluteUri == "https://management.azure.com" + r.Window.Path + "?api-version=2026-02-01" &&
                request.Headers.TryGetValue("Authorization", out var auth) &&
                auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7);
            Headers(headers);
            Require(!headers.Any(h => new[] { "Content-Encoding", "Transfer-Encoding", "Content-Range", "Range" }
                .Contains(h.Name, StringComparer.OrdinalIgnoreCase)));
            if (request.Headers.TryGetValue("Content-Length", out var length)) Require(length == "0");
            if (request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
            r.StartToken.ThrowIfCancellationRequested();
            message.CancellationToken.ThrowIfCancellationRequested();
        }
        try
        {
            lock (gate)
                Require(!context.Check && r.Sends++ == 0 && r.Requests.Contains(request) &&
                    r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched);
            Check();
            r.BeforeSend?.Invoke();
            Check();
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            Check();
            var original = message.Response;
            var stream = original.ContentStream;
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, r.Storage, allowContinuation: true)
                .ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(original.ContentStream, stream) && body.Response.Status == 200 &&
                body.Response.Headers.Count(h => new[] { "Location", "Azure-AsyncOperation", "Operation-Location" }
                    .Contains(h.Name, StringComparer.OrdinalIgnoreCase)) == 1);
            string next = Continuation(r.Window, message) ?? throw new InvalidOperationException("status-succeeded-delete-target");
            using var json = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int nodes = 512;
            JsonRows(json.RootElement, ref nodes);
            var root = json.RootElement;
            Require(root.ValueKind == JsonValueKind.Object &&
                root.EnumerateObject().All(p => p.Name is "id" or "status" or "properties"));
            if (root.TryGetProperty("id", out var id)) Require(id.GetString() == r.Window.Path);
            bool direct = root.TryGetProperty("status", out var status);
            bool nested = root.TryGetProperty("properties", out var properties);
            Require(direct != nested);
            if (nested) Require(properties.ValueKind == JsonValueKind.Object &&
                properties.EnumerateObject().All(p => p.Name == "provisioningState"));
            Require(State(direct ? status.GetString() : properties.GetProperty("provisioningState").GetString()) == WireState.Pending);
            var target = new StatusTarget(r.Window.Binding, Guid.NewGuid(), StatusTargetKind.Operation, new Uri(next),
                Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(next))), body.Sha256);
            r.Candidate = new(r.Window.Binding, target, body.Response.Status, body.Bytes.Length,
                Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("DELETE " + request.Uri.ToUri().AbsoluteUri))),
                body.NativeRequestId);
            r.Parser = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, r.Storage,
                requireRebuffer: true, requireDownstreamRead: false);
        }
        catch { r.Invalid = true; throw; }
    }

    internal sealed class StatusSucceededDeleteVaultIndependentStartProof(Binding binding, StatusTarget target,
        int httpStatus, int responseBytes, string requestSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal StatusTarget Target { get; } = target;
        internal Guid StartDispatch => Target.StartDispatch;
        internal int HttpStatus { get; } = httpStatus;
        internal int ResponseBytes { get; } = responseBytes;
        internal string ResponseSha256 => Target.StartResponseSha256;
        internal string RequestSha256 { get; } = requestSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        public override string ToString() => "[StatusSucceededDeleteVaultIndependentStartProof]";
    }

    internal sealed class StatusSucceededDeleteVaultIndependentCompletionProof(StatusSucceededDeleteVaultIndependentStartProof start)
    {
        internal StatusSucceededDeleteVaultIndependentStartProof Start { get; } = start;
        public override string ToString() => "[StatusSucceededDeleteVaultIndependentCompletionProof]";
    }

    private sealed class StatusSucceededDeleteVaultIndependentRegistration(Window window, VaultAdministration client,
        VaultScope scope, ManagementReceipt receipt, CancellationToken token, Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Invocation Start = window.Start!;
        internal Invocation? Status;
        internal readonly VaultAdministration Client = client;
        internal readonly VaultScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken StartToken = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly HashSet<Request> Requests = new(ReferenceEqualityComparer.Instance);
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task? SendTask;
        internal ManagementOperation? Handle;
        internal OwnedArmResponse.ParserCustody? Parser;
        internal StatusSucceededDeleteVaultIndependentStartProof? Candidate, StartProof;
        internal StatusSucceededDeleteVaultIndependentCompletionProof? Completion;
        internal CancellationToken CheckToken;
        internal bool Invalid, Sealed, CheckClaimed, StartHook, CheckHook, StartSuccess, CheckSuccess;
        internal int Sends, CheckFactories;
    }
    private sealed record StatusSucceededDeleteVaultIndependentContext(StatusSucceededDeleteVaultIndependentRegistration Registration, bool Check);
    private readonly AsyncLocal<StatusSucceededDeleteVaultIndependentContext?> currentStatusSucceededDeleteVaultIndependent = new();
    private readonly Dictionary<Window, StatusSucceededDeleteVaultIndependentRegistration> statusSucceededDeleteVaultIndependent =
        new(ReferenceEqualityComparer.Instance);

    internal async Task<SecretOutcome<ManagementOperation>> StartStatusSucceededDeleteVaultIndependentAsync(Window window,
        FixtureSelector selector, VaultAdministration client, VaultScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token = default, Action<Task>? retained = null, Action? beforeSend = null)
    {
        StatusSucceededDeleteVaultIndependentRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(VaultFixtureProvisioner.StatusSucceededDeleteVaultIndependentSelector(selector) &&
                window.Binding.Operation == ManagementMutation.DeleteVault && window.Binding.ApiRevision == "2026-02-01" &&
                ReferenceEquals(window.Binding.Resource, scope) && client is not null && receipt is not null &&
                input.StatusOperation == ManagementMutation.DeleteVault && InputMatches(window.Binding, input) &&
                !window.Closed && window.Start is null && startedWindows.Add(window));
            window.Start = new();
            r = new(window, client, scope, receipt, token, beforeSend);
            statusSucceededDeleteVaultIndependent.Add(window, r);
        }
        try
        {
            var previous = currentStatusSucceededDeleteVaultIndependent.Value;
            currentStatusSucceededDeleteVaultIndependent.Value = new(r, false);
            try
            {
                r.StartTask = ManagementOperationEffects.StartAsync(client, scope, ManagementMutation.DeleteVault,
                    input, receipt, token).AsTask();
                r.Start.SdkTask = r.StartTask;
            }
            finally { currentStatusSucceededDeleteVaultIndependent.Value = previous; }
            try { retained?.Invoke(r.StartTask); r.StartHook = true; }
            finally
            {
                var result = await r.StartTask.ConfigureAwait(false);
                r.Handle = result.IsSuccess ? result.Value : null;
                r.StartSuccess = result.IsSuccess && r.Handle!.State == NativeProvisioningState.Succeeded &&
                    receipt.Evidence == DispatchEvidence.Applied;
                r.Start.Outcome = result.Status;
                r.Start.WrapperState = r.Handle?.State;
                r.Start.HasNativeHandle = r.Handle is not null;
            }
            return await r.StartTask.ConfigureAwait(false);
        }
        catch { r.Invalid = true; throw; }
        finally
        {
            if (r.StartTask is not null)
                try { await r.StartTask.ConfigureAwait(false); } catch { r.Invalid = true; }
            if (r.SendTask is not null)
                try { await r.SendTask.ConfigureAwait(false); } catch { r.Invalid = true; }
            bool custody = r.Parser is { Complete: true, Invalid: false };
            try { r.Storage.Dispose(); } catch { r.Invalid = true; }
            lock (gate)
            {
                r.Invalid |= !custody || r.Parser is not { Complete: true, Invalid: false };
                if (!r.Invalid && !r.Sealed && r.StartHook && r.StartSuccess && r.Sends == 1 &&
                    r.StartTask is { IsCompletedSuccessfully: true } && !token.IsCancellationRequested &&
                    r.Candidate is not null && receipt.Evidence == DispatchEvidence.Applied)
                {
                    r.StartProof = r.Candidate;
                    targets[window] = r.Candidate.Target;
                    eligible.Add(window);
                }
                r.Start.Terminated = true;
                r.Start.Drained.TrySetResult();
                r.Started.TrySetResult();
            }
        }
    }

    internal bool TryGetStatusSucceededDeleteVaultIndependentStart(Window window, Binding binding, VaultAdministration client,
        VaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        [NotNullWhen(true)] out StatusSucceededDeleteVaultIndependentStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!statusSucceededDeleteVaultIndependent.TryGetValue(window, out var r) || r.Invalid || r.Sealed ||
                !ReferenceEquals(window.Binding, binding) || !ReferenceEquals(r.Client, client) ||
                !ReferenceEquals(r.Scope, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.StartTask, startTask) || !ReferenceEquals(r.Handle, handle) ||
                !r.Started.Task.IsCompletedSuccessfully || !startTask.IsCompletedSuccessfully ||
                r.StartToken.IsCancellationRequested || receipt.Evidence != DispatchEvidence.Applied ||
                handle.State != NativeProvisioningState.Succeeded || r.StartProof is null ||
                !ReferenceEquals(targets.GetValueOrDefault(window), r.StartProof.Target) ||
                completedStatusReads.Contains(window)) return false;
            proof = r.StartProof;
            return true;
        }
    }

    internal bool TryGetStatusSucceededDeleteVaultIndependentCompletion(Window window, Binding binding, VaultAdministration client,
        VaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task statusTask,
        [NotNullWhen(true)] out StatusSucceededDeleteVaultIndependentCompletionProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusSucceededDeleteVaultIndependentStart(window, binding, client, scope, receipt, startTask, handle, out _) ||
                !statusSucceededDeleteVaultIndependent.TryGetValue(window, out var r) || !ReferenceEquals(r.StatusTask, statusTask) ||
                !r.Checked.Task.IsCompletedSuccessfully || !statusTask.IsCompletedSuccessfully ||
                r.CheckToken.IsCancellationRequested || r.Completion is null) return false;
            proof = r.Completion;
            return true;
        }
    }

    private async Task<SecretStatus> CheckStatusSucceededDeleteVaultIndependentAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained)
    {
        StatusSucceededDeleteVaultIndependentRegistration r;
        lock (gate)
        {
            Own(window, selector);
            r = statusSucceededDeleteVaultIndependent[window];
            Require(ReferenceEquals(r.Handle, handle));
            bool valid = !r.CheckClaimed && !window.Closed && !token.IsCancellationRequested &&
                TryGetStatusSucceededDeleteVaultIndependentStart(window, window.Binding, r.Client, r.Scope, r.Receipt,
                    r.StartTask!, handle, out _);
            r.CheckClaimed = true;
            r.Invalid |= !valid;
            Require(valid);
            r.CheckToken = token;
            r.Status = window.Status = new();
        }
        try
        {
            var previous = currentStatusSucceededDeleteVaultIndependent.Value;
            currentStatusSucceededDeleteVaultIndependent.Value = new(r, true);
            try { r.StatusTask = handle.CheckStatusAsync(token).AsTask(); r.Status!.SdkTask = r.StatusTask; }
            finally { currentStatusSucceededDeleteVaultIndependent.Value = previous; }
            try { retained?.Invoke(r.StatusTask); r.CheckHook = true; }
            finally
            {
                var outcome = await r.StatusTask.ConfigureAwait(false);
                r.CheckSuccess = outcome == SecretStatus.Success && handle.State == NativeProvisioningState.Succeeded &&
                    r.Receipt.Evidence == DispatchEvidence.Applied;
                r.Status!.Outcome = outcome;
                r.Status.WrapperState = handle.State;
            }
            return await r.StatusTask.ConfigureAwait(false);
        }
        catch { r.Invalid = true; throw; }
        finally
        {
            if (r.StatusTask is not null)
                try { await r.StatusTask.ConfigureAwait(false); } catch { r.Invalid = true; }
            lock (gate)
            {
                if (!r.Invalid && !r.Sealed && r.CheckHook && r.CheckSuccess && r.CheckFactories == 0 &&
                    r.StatusTask is { IsCompletedSuccessfully: true } && !token.IsCancellationRequested &&
                    !r.StartToken.IsCancellationRequested && r.StartProof is not null)
                    r.Completion = new(r.StartProof);
                r.Status!.Terminated = true;
                r.Status.Drained.TrySetResult();
                r.Checked.TrySetResult();
            }
        }
    }

    private async Task<Capture> SealStatusSucceededDeleteVaultIndependentAsync(Window window)
    {
        StatusSucceededDeleteVaultIndependentRegistration r;
        lock (gate) { r = statusSucceededDeleteVaultIndependent[window]; r.Sealed = true; window.Closed = true; }
        await r.Started.Task.ConfigureAwait(false);
        if (r.Status is not null) await r.Checked.Task.ConfigureAwait(false);
        return new() { Binding = window.Binding, Start = r.Start, Status = r.Status };
    }

    private async Task SendStatusSucceededDeleteVaultIndependentAsync(StatusSucceededDeleteVaultIndependentContext context, HttpMessage message)
    {
        var r = context.Registration;
        var request = message.Request;
        var headers = request.Headers.ToArray();
        void Check()
        {
            Require(!r.Invalid && !r.Sealed && !context.Check && ReferenceEquals(message.Request, request) &&
                headers.SequenceEqual(request.Headers) && request.Method == RequestMethod.Delete &&
                request.Content is null && Trusted(request.Uri.ToUri()) &&
                request.Uri.ToUri().AbsoluteUri == "https://management.azure.com" + r.Window.Path + "?api-version=2026-02-01" &&
                request.Headers.TryGetValue("Authorization", out var auth) &&
                auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7);
            Headers(headers);
            Require(!headers.Any(h => new[] { "Content-Encoding", "Transfer-Encoding", "Content-Range", "Range" }
                .Contains(h.Name, StringComparer.OrdinalIgnoreCase)));
            if (request.Headers.TryGetValue("Content-Length", out var length)) Require(length == "0");
            if (request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
            r.StartToken.ThrowIfCancellationRequested();
            message.CancellationToken.ThrowIfCancellationRequested();
        }
        try
        {
            lock (gate)
                Require(!context.Check && r.Sends++ == 0 && r.Requests.Contains(request) &&
                    r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched);
            Check();
            r.BeforeSend?.Invoke();
            Check();
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            Check();
            var original = message.Response;
            var stream = original.ContentStream;
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, r.Storage, allowContinuation: true)
                .ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(original.ContentStream, stream) && body.Response.Status == 200 &&
                body.Response.Headers.Count(h => new[] { "Location", "Azure-AsyncOperation", "Operation-Location" }
                    .Contains(h.Name, StringComparer.OrdinalIgnoreCase)) == 1);
            string next = Continuation(r.Window, message) ?? throw new InvalidOperationException("status-succeeded-delete-target");
            using var json = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int nodes = 512;
            JsonRows(json.RootElement, ref nodes);
            var root = json.RootElement;
            Require(root.ValueKind == JsonValueKind.Object &&
                root.EnumerateObject().All(p => p.Name is "id" or "status" or "properties"));
            if (root.TryGetProperty("id", out var id)) Require(id.GetString() == r.Window.Path);
            bool direct = root.TryGetProperty("status", out var status);
            bool nested = root.TryGetProperty("properties", out var properties);
            Require(direct != nested);
            if (nested) Require(properties.ValueKind == JsonValueKind.Object &&
                properties.EnumerateObject().All(p => p.Name == "provisioningState"));
            Require(State(direct ? status.GetString() : properties.GetProperty("provisioningState").GetString()) == WireState.Pending);
            var target = new StatusTarget(r.Window.Binding, Guid.NewGuid(), StatusTargetKind.Operation, new Uri(next),
                Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(next))), body.Sha256);
            r.Candidate = new(r.Window.Binding, target, body.Response.Status, body.Bytes.Length,
                Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("DELETE " + request.Uri.ToUri().AbsoluteUri))),
                body.NativeRequestId);
            r.Parser = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, r.Storage,
                requireRebuffer: true, requireDownstreamRead: false);
        }
        catch { r.Invalid = true; throw; }
    }

    internal sealed class StatusUnknownNotificationUpdateCancellationStartProof(Binding binding, Guid startDispatch,
        int httpStatus, int responseBytes, string requestSha256, string responseSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal Guid StartDispatch { get; } = startDispatch;
        internal int HttpStatus { get; } = httpStatus;
        internal int ResponseBytes { get; } = responseBytes;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        public override string ToString() => "[StatusUnknownNotificationUpdateCancellationStartProof]";
    }

    internal sealed class StatusUnknownNotificationUpdateCancellationCanceledProof
    {
        internal StatusUnknownNotificationUpdateCancellationCanceledProof(ManagementOperationNativeCapture source,
            StatusUnknownNotificationUpdateCancellationStartProof start, Task canceledTask)
        {
            Start = start;
            CanceledTask = canceledTask;
        }
        internal StatusUnknownNotificationUpdateCancellationStartProof Start { get; }
        internal Task CanceledTask { get; }
        public override string ToString() => "[StatusUnknownNotificationUpdateCancellationCanceledProof]";
    }

    // The paired calls prove local Unknown completion, never remote termination.
    internal sealed class StatusUnknownNotificationUpdateCancellationCompletionProof(StatusUnknownNotificationUpdateCancellationStartProof start,
        StatusUnknownNotificationUpdateCancellationCanceledProof canceled)
    {
        internal StatusUnknownNotificationUpdateCancellationStartProof Start { get; } = start;
        internal StatusUnknownNotificationUpdateCancellationCanceledProof Canceled { get; } = canceled;
        public override string ToString() => "[StatusUnknownNotificationUpdateCancellationCompletionProof]";
    }

    private sealed class StatusUnknownNotificationUpdateCancellationRegistration(Window window, Invocation start,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, CancellationToken token,
        Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly Invocation Start = start;
        internal readonly VaultAdministration Client = client;
        internal readonly NotificationScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken StartToken = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource CanceledDrained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly List<OwnedArmResponse.ParserCustody> Parsers = [];
        internal NotificationConfiguration Configuration = null!;
        internal StatusTarget? Target;
        internal StatusVaultCancellationWire? StatusWire;
        internal int StatusSends;
        internal StatusVaultCancellationWire? Wire;
        internal StatusUnknownNotificationUpdateCancellationStartProof? Candidate, StartProof;
        internal StatusUnknownNotificationUpdateCancellationCompletionProof? Completion;
        internal StatusUnknownNotificationUpdateCancellationCanceledProof? CanceledProof;
        internal Invocation? Canceled;
        internal Task<SecretStatus>? CanceledTask;
        internal CancellationToken CanceledToken;
        internal int CanceledFactories, CanceledSends;
        internal bool CanceledClaimed, CanceledHookReturned, CancellationObserved, CanceledComplete;
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task<Capture>? SealTask;
        internal Invocation? Status;
        internal ManagementOperation? Handle;
        internal CancellationToken StatusToken, StatusCallerToken;
        internal int Sends;
        internal bool Invalid, Sealed, StartHookReturned, StartSucceeded, TransportSucceeded, StartComplete;
        internal bool CheckClaimed, StatusHookReturned, StatusCompleted, Complete;
    }

    private readonly Dictionary<Window, StatusUnknownNotificationUpdateCancellationRegistration> statusUnknownNotificationUpdateCancellation =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Invocation, StatusUnknownNotificationUpdateCancellationRegistration> statusUnknownNotificationUpdateCancellationInvocations =
        new(ReferenceEqualityComparer.Instance);

    internal bool TryGetStatusUnknownNotificationUpdateCancellationStart(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, [NotNullWhen(true)] out StatusUnknownNotificationUpdateCancellationStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusUnknownNotificationUpdateCancellation.TryGetValue(window, out var r) ||
                !NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationSelector(binding.Selector) ||
                !ReferenceEquals(r.Binding, binding) || !ReferenceEquals(r.Client, client) ||
                !ReferenceEquals(r.Scope, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.StartTask, startTask) || !ReferenceEquals(r.Handle, handle) ||
                !StatusUnknownNotificationUpdateCancellationStartValid(r) ||
                receipt.Evidence != DispatchEvidence.Pending ||
                !(handle.State == NativeProvisioningState.Pending || r.Complete && handle.State == NativeProvisioningState.Unknown) ||
                !ReferenceEquals(targets.GetValueOrDefault(window), r.Target)) return false;
            proof = r.StartProof;
            return proof is not null;
        }
    }

    internal bool TryGetStatusUnknownNotificationUpdateCancellationCompletion(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask, Task checkTask,
        [NotNullWhen(true)] out StatusUnknownNotificationUpdateCancellationCompletionProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusUnknownNotificationUpdateCancellationCanceled(window, binding, client, scope, receipt,
                    startTask, handle, canceledTask, out var canceled) || !statusUnknownNotificationUpdateCancellation.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.StatusTask, checkTask) || !r.Complete ||
                !ReferenceEquals(r.Completion?.Canceled, canceled) ||
                !r.Checked.Task.IsCompletedSuccessfully || r.StatusTask is not { IsCompletedSuccessfully: true } ||
                r.StatusToken.IsCancellationRequested || r.StatusCallerToken.IsCancellationRequested ||
                handle.State != NativeProvisioningState.Unknown || receipt.Evidence != DispatchEvidence.Pending) return false;
            proof = r.Completion;
            return proof is not null;
        }
    }

    private static bool StatusUnknownNotificationUpdateCancellationCanceledValid(StatusUnknownNotificationUpdateCancellationRegistration r) =>
        StatusUnknownNotificationUpdateCancellationStartValid(r) && r.CanceledComplete && r.CanceledProof is not null &&
        r.CanceledDrained.Task.IsCompletedSuccessfully && r.Canceled is { Terminated: true, Canceled: true } &&
        r.Canceled.Drained.Task.IsCompletedSuccessfully && r.CanceledTask is { IsCanceled: true } &&
        ReferenceEquals(r.Canceled.SdkTask, r.CanceledTask) &&
        ReferenceEquals(r.CanceledProof.Start, r.StartProof) &&
        ReferenceEquals(r.CanceledProof.CanceledTask, r.CanceledTask) &&
        r.CanceledToken.IsCancellationRequested && r.CanceledHookReturned && r.CancellationObserved &&
        r.CanceledFactories == 0 && r.CanceledSends == 0 && r.Canceled.Attempts.Count == 0;

    internal bool TryGetStatusUnknownNotificationUpdateCancellationCanceled(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask,
        [NotNullWhen(true)] out StatusUnknownNotificationUpdateCancellationCanceledProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusUnknownNotificationUpdateCancellationStart(window, binding, client, scope, receipt,
                    startTask, handle, out var start) || !statusUnknownNotificationUpdateCancellation.TryGetValue(window, out var r) ||
                !StatusUnknownNotificationUpdateCancellationCanceledValid(r) || !ReferenceEquals(r.CanceledTask, canceledTask) ||
                !ReferenceEquals(r.CanceledProof?.Start, start)) return false;
            proof = r.CanceledProof;
            return proof is not null;
        }
    }

    internal bool OwnsStatusUnknownNotificationUpdateCancellationStart(StatusUnknownNotificationUpdateCancellationStartProof proof,
        Window window, Binding binding, VaultAdministration client, NotificationScope scope,
        ManagementReceipt receipt, Task startTask, ManagementOperation handle) =>
        TryGetStatusUnknownNotificationUpdateCancellationStart(window, binding, client, scope, receipt, startTask, handle, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool OwnsStatusUnknownNotificationUpdateCancellationCanceled(StatusUnknownNotificationUpdateCancellationCanceledProof proof,
        Window window, Binding binding, VaultAdministration client, NotificationScope scope,
        ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task canceledTask) =>
        TryGetStatusUnknownNotificationUpdateCancellationCanceled(window, binding, client, scope, receipt, startTask, handle,
            canceledTask, out var issued) && ReferenceEquals(proof, issued);

    internal bool OwnsStatusUnknownNotificationUpdateCancellationCompletion(StatusUnknownNotificationUpdateCancellationCompletionProof proof,
        Window window, Binding binding, VaultAdministration client, NotificationScope scope,
        ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task canceledTask, Task checkTask) =>
        TryGetStatusUnknownNotificationUpdateCancellationCompletion(window, binding, client, scope, receipt, startTask, handle,
            canceledTask, checkTask, out var issued) && ReferenceEquals(proof, issued);

    internal async ValueTask<SecretStatus> CheckStatusUnknownNotificationUpdateCancellationCanceledAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken canceledToken, Action<Task>? retained = null)
    {
        StatusUnknownNotificationUpdateCancellationRegistration r;
        Invocation invocation;
        lock (gate)
        {
            Own(window, selector);
            Require(statusUnknownNotificationUpdateCancellation.TryGetValue(window, out r!) &&
                handle is not null && ReferenceEquals(r.Handle, handle));
            bool valid = !r.CanceledClaimed && !r.CheckClaimed && !window.Closed && window.Status is null &&
                StatusUnknownNotificationUpdateCancellationStartValid(r) && canceledToken.IsCancellationRequested &&
                handle.State == NativeProvisioningState.Pending && r.Receipt.Evidence == DispatchEvidence.Pending;
            r.CanceledClaimed = true;
            r.Invalid |= !valid;
            Require(valid);
            invocation = r.Canceled = new();
            r.CanceledToken = canceledToken;
            statusUnknownNotificationUpdateCancellationInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretStatus> task;
            var previous = current.Value;
            current.Value = new(window, invocation, true);
            try { task = handle.CheckStatusAsync(canceledToken).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) invocation.SdkTask = r.CanceledTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.CanceledHookReturned = true;
            }
            finally
            {
                try { await task.ConfigureAwait(false); }
                catch (OperationCanceledException) when (canceledToken.IsCancellationRequested && task.IsCanceled)
                {
                    lock (gate)
                    {
                        // Only awaiting the actual SDK task records this expected OCE.
                        r.CancellationObserved = invocation.Canceled = true;
                        invocation.WrapperState = handle.State;
                    }
                    throw;
                }
            }
            lock (gate) r.Invalid = true;
            throw new InvalidOperationException("management-capture-boundary");
        }
        catch (OperationCanceledException)
        {
            lock (gate) r.Invalid |= !r.CancellationObserved || !r.CanceledHookReturned;
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusUnknownNotificationUpdateCancellationAsync(r, invocation).ConfigureAwait(false); }
    }

    private static bool StatusUnknownNotificationUpdateCancellationStartValid(StatusUnknownNotificationUpdateCancellationRegistration r) =>
        !r.Invalid && !r.Sealed && r.StartComplete && r.StartProof is not null &&
        r.Started.Task.IsCompletedSuccessfully && r.StartTask is { IsCompletedSuccessfully: true } &&
        !r.StartToken.IsCancellationRequested &&
        (!r.CheckClaimed || !r.StatusToken.IsCancellationRequested && !r.StatusCallerToken.IsCancellationRequested);

    internal async Task<SecretOutcome<ManagementOperation>> StartStatusUnknownNotificationUpdateCancellationAsync(
        Window window, FixtureSelector selector, VaultAdministration client, ManagementScope scope,
        ManagementOperationEffects.Input input, ManagementReceipt receipt, CancellationToken token = default,
        Action<Task>? retained = null, Action? beforeSend = null)
    {
        StatusUnknownNotificationUpdateCancellationRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(client is not null && receipt is not null && scope is NotificationScope &&
                NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationSelector(selector) &&
                window.Binding.Operation == ManagementMutation.UpdateNotification &&
                window.Binding.ApiRevision == "2025-02-15" && InputMatches(window.Binding, input) &&
                Route(window.Binding with { Resource = scope }) == Route(window.Binding));
            if (statusUnknownNotificationUpdateCancellation.TryGetValue(window, out var existing))
            {
                Require(ReferenceEquals(existing.Client, client) && ReferenceEquals(existing.Scope, scope) &&
                    ReferenceEquals(existing.Receipt, receipt));
                existing.Invalid = true;
                throw new InvalidOperationException("management-capture-boundary");
            }
            Require(!window.Closed && window.Start is null && startedWindows.Add(window) && !token.IsCancellationRequested);
            var invocation = window.Start = new();
            r = new(window, invocation, client, (NotificationScope)scope, receipt, token, beforeSend)
            { Configuration = new(input.WebhookUrl, [VaultNotificationEvent.SecretNewVersionCreated], []) };
            statusUnknownNotificationUpdateCancellation.Add(window, r);
            statusUnknownNotificationUpdateCancellationInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretOutcome<ManagementOperation>> task;
            var previous = current.Value;
            current.Value = new(window, r.Start, false);
            try { task = ManagementOperationEffects.StartAsync(client, scope, window.Binding.Operation, input, receipt, token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) r.Start.SdkTask = r.StartTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StartHookReturned = true;
            }
            finally
            {
                var result = await task.ConfigureAwait(false);
                lock (gate)
                {
                    r.Start.Outcome = result.Status;
                    r.Handle = result.IsSuccess ? result.Value : null;
                    r.Start.WrapperState = r.Handle?.State;
                    r.StartSucceeded = task.IsCompletedSuccessfully && result.IsSuccess &&
                        r.Handle!.State == NativeProvisioningState.Pending && receipt.Evidence == DispatchEvidence.Pending;

                    r.Start.HasNativeHandle = r.StartSucceeded;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; r.Start.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusUnknownNotificationUpdateCancellationAsync(r, r.Start).ConfigureAwait(false); }
    }

    private async Task<SecretStatus> CheckStatusUnknownNotificationUpdateCancellationAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained, CancellationToken originalCallerToken)
    {
        StatusUnknownNotificationUpdateCancellationRegistration r;
        Invocation invocation;
        lock (gate)
        {
            Own(window, selector);
            Require(statusUnknownNotificationUpdateCancellation.TryGetValue(window, out r!) &&
                handle is not null && ReferenceEquals(r.Handle, handle));
            bool valid = StatusUnknownNotificationUpdateCancellationCanceledValid(r) &&
                !r.CheckClaimed && !window.Closed && window.Status is null &&
                StatusUnknownNotificationUpdateCancellationStartValid(r) && !token.IsCancellationRequested && !originalCallerToken.IsCancellationRequested &&
                handle.State == NativeProvisioningState.Pending && r.Receipt.Evidence == DispatchEvidence.Pending;
            r.CheckClaimed = true;
            r.Invalid |= !valid;
            Require(valid);
            invocation = r.Status = window.Status = new();
            r.StatusToken = token;
            r.StatusCallerToken = originalCallerToken;
            statusUnknownNotificationUpdateCancellationInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretStatus> task;
            var previous = current.Value;
            current.Value = new(window, invocation, true);
            try { task = handle.CheckStatusAsync(token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) invocation.SdkTask = r.StatusTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StatusHookReturned = true;
            }
            finally
            {
                var outcome = await task.ConfigureAwait(false);
                lock (gate)
                {
                    invocation.Outcome = outcome;
                    invocation.WrapperState = handle.State;
                    r.StatusCompleted = task.IsCompletedSuccessfully && outcome == SecretStatus.Unknown &&
                        handle.State == NativeProvisioningState.Unknown;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; invocation.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusUnknownNotificationUpdateCancellationAsync(r, invocation).ConfigureAwait(false); }
    }

    private async Task FinishStatusUnknownNotificationUpdateCancellationAsync(StatusUnknownNotificationUpdateCancellationRegistration r,
        Invocation invocation)
    {
        bool start = ReferenceEquals(r.Start, invocation);
        bool canceled = ReferenceEquals(r.Canceled, invocation);
        Task<Task>? borrower;
        lock (gate)
        {
            Task? actual = start ? r.StartTask : canceled ? r.CanceledTask : r.StatusTask;
            Require(actual is null || actual.IsCompleted);
            finishing.Add(invocation);
            borrower = borrowers.TryGetValue(invocation, out var pending) ? pending.Task : null;
        }
        if (borrower is not null)
        {
            var actual = await borrower.ConfigureAwait(false);
            try { await actual.ConfigureAwait(false); }
            catch { lock (gate) r.Invalid = true; }
        }
        bool custodyValid, disposalFailed = false;
        try { custodyValid = r.Parsers.Count == (start || canceled ? 1 : 2) && r.Parsers.All(p => p.Complete && !p.Invalid); }
        catch { custodyValid = false; }
        if (!start && !canceled)
        {
            try { r.Storage.Dispose(); }
            catch { disposalFailed = true; }
            try { custodyValid &= r.Parsers.All(p => p.Complete && !p.Invalid); }
            catch { custodyValid = false; }
        }
        lock (gate)
        {
            r.Invalid |= !custodyValid || disposalFailed;
            requestOwners.Remove(invocation);
            requestCandidates.Remove(invocation);
            borrowers.Remove(invocation);
            if (start)
            {
                r.StartComplete = !r.Invalid && r.StartHookReturned && r.StartSucceeded &&
                    r.TransportSucceeded && r.Sends == 1 && r.Candidate is not null &&
                    r.Wire is { Ordinal: 0, HttpStatus: 201, State: WireState.Pending, Complete: true } &&
                    r.Target is { Kind: StatusTargetKind.SelectedResource } &&
                    r.Target.StartDispatch == r.Candidate.StartDispatch &&
                    r.StartTask is { IsCompletedSuccessfully: true } && !r.StartToken.IsCancellationRequested &&
                    r.Handle?.State == NativeProvisioningState.Pending && r.Receipt.Evidence == DispatchEvidence.Pending;
                if (r.StartComplete)
                {
                    r.StartProof = r.Candidate;
                    targets[r.Window] = r.Target;
                    eligible.Add(r.Window);
                }
                r.Started.TrySetResult();
            }
            else if (canceled)
            {
                r.CanceledComplete = StatusUnknownNotificationUpdateCancellationStartValid(r) && r.CanceledHookReturned &&
                    r.CancellationObserved && r.CanceledTask is { IsCanceled: true } &&
                    r.CanceledToken.IsCancellationRequested && r.CanceledFactories == 0 && r.CanceledSends == 0 &&
                    invocation.Attempts.Count == 0 && !invocation.Sending &&
                    r.Handle?.State == NativeProvisioningState.Pending && r.Receipt.Evidence == DispatchEvidence.Pending;
                r.Invalid |= !r.CanceledComplete;
                if (r.CanceledComplete) r.CanceledProof = new(this, r.StartProof!, r.CanceledTask!);
                r.CanceledDrained.TrySetResult();
            }
            else
            {
                r.Complete = StatusUnknownNotificationUpdateCancellationCanceledValid(r) && StatusUnknownNotificationUpdateCancellationStartValid(r) && r.StatusHookReturned && r.StatusCompleted &&
                    r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                    !r.StatusCallerToken.IsCancellationRequested &&
                    r.Receipt.Evidence == DispatchEvidence.Pending && r.Handle?.State == NativeProvisioningState.Unknown &&
                    r.StatusSends == 1 && r.StatusWire is { Ordinal: 1, HttpStatus: 200, State: WireState.Unknown, Complete: true } wire &&
                    r.Target is { } target && r.Wire is { } originalWire &&
                    wire.Uri == target.TargetUri.AbsoluteUri && wire.Dispatch != originalWire.Dispatch &&
                    !ReferenceEquals(wire.Request, originalWire.Request);
                if (r.Complete)
                {
                    r.Completion = new(r.StartProof!, r.CanceledProof!);
                    // Historical Unknown cannot grant generic remote-completion authority.
                }
                r.Checked.TrySetResult();
            }
            invocation.Terminated = true;
            invocation.Drained.TrySetResult();
        }
        if (disposalFailed) throw new InvalidOperationException("management-capture-finalization");
    }

    private Task<Capture> SealStatusUnknownNotificationUpdateCancellationAsync(Window window)
    {
        StatusUnknownNotificationUpdateCancellationRegistration r;
        TaskCompletionSource ready;
        Task<Capture> task;
        lock (gate)
        {
            Own(window, window.Binding.Selector);
            r = statusUnknownNotificationUpdateCancellation[window];
            window.Closed = true;
            if (r.SealTask is not null) return r.SealTask;
            r.Sealed = true;
            ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = r.SealTask = Drain(ready.Task);
        }
        ready.SetResult();
        return task;

        async Task<Capture> Drain(Task admission)
        {
            await admission.ConfigureAwait(false);
            await r.Started.Task.ConfigureAwait(false);
            if (r.Canceled is not null) await r.CanceledDrained.Task.ConfigureAwait(false);
            if (r.Status is not null) await r.Checked.Task.ConfigureAwait(false);
            try { r.Storage.Dispose(); r.Configuration.Dispose(); }
            catch { lock (gate) r.Invalid = true; throw; }
            return new() { Binding = r.Binding, Start = r.Start, Status = r.Status };
        }
    }

    private async Task SendStatusUnknownNotificationUpdateCancellationAsync(StatusUnknownNotificationUpdateCancellationRegistration r,
        InvocationContext context, HttpMessage message, TaskCompletionSource<Task> borrower)
    {
        var invocation = context.Invocation;
        bool status = context.Status;
        lock (gate)
        {
            bool valid = !r.Invalid && !r.Sealed && !finishing.Contains(invocation) &&
                ReferenceEquals(invocation, status ? r.Status : r.Start) &&
                (status ? ++r.StatusSends == 1 && r.Target is not null && r.Receipt.Evidence == DispatchEvidence.Pending :
                    ++r.Sends == 1 && r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched) &&
                requestCandidates.TryGetValue(invocation, out var candidates) && candidates.Contains(message.Request);
            r.Invalid |= !valid;
            Require(valid);
            borrowers.Add(invocation, borrower);
            invocation.Sending = true;
            requestOwners.Add(invocation, message.Request);
            requestCandidates.Remove(invocation);
        }
        Attempt? attempt = null;
        RequestContent? original = message.Request.Content;
        RequestContent? snapshot = null;
        try
        {
            var request = message.Request;
            var headers = request.Headers.ToArray();
            string expectedUri = Origin + r.Window.Path + "?api-version=2025-02-15";
            void Check()
            {
                Require(ReferenceEquals(message.Request, request) && headers.SequenceEqual(request.Headers) &&
                    headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                    request.Method == (status ? RequestMethod.Get : RequestMethod.Patch) &&
                    ReferenceEquals(request.Content, snapshot) && Trusted(request.Uri.ToUri()) &&
                    request.Uri.ToUri().AbsoluteUri == expectedUri &&
                    (!status || expectedUri == r.Target!.TargetUri.AbsoluteUri) &&
                    request.Headers.TryGetValue("Authorization", out var auth) &&
                    auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
                    !headers.Any(h => new[] { "Content-Encoding", "Transfer-Encoding", "Content-Range", "Range" }
                        .Contains(h.Name, StringComparer.OrdinalIgnoreCase)));
                Headers(headers);
                if (request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
                r.StartToken.ThrowIfCancellationRequested();
                if (status)
                {
                    r.StatusToken.ThrowIfCancellationRequested();
                    r.StatusCallerToken.ThrowIfCancellationRequested();
                }
                message.CancellationToken.ThrowIfCancellationRequested();
            }
            string requestHash;
            if (status)
            {
                Require(original is null);
                if (request.Headers.TryGetValue("Content-Length", out var length)) Require(length == "0");
                requestHash = Convert.ToHexString(SHA256.HashData(ReadOnlySpan<byte>.Empty));
            }
            else
            {
                long length = 0;
                Require(original is not null && original.TryComputeLength(out length) && length > 0 && length <= maximumBytes);
                Require(request.Headers.TryGetValue("Content-Type", out var contentType) &&
                    contentType.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase));
                byte[] bytes = new byte[maximumBytes];
                r.Storage.Own(bytes);
                using var output = new MemoryStream(bytes, 0, bytes.Length, true, true);
                await original.WriteToAsync(output, message.CancellationToken).ConfigureAwait(false);
                Require(output.Position == length && ReferenceEquals(request.Content, original));
                if (request.Headers.TryGetValue("Content-Length", out var declared))
                    Require(declared == length.ToString(CultureInfo.InvariantCulture));
                var payload = bytes.AsMemory(0, checked((int)length));
                using var json = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 16 });
                int nodes = 512;
                JsonRows(json.RootElement, ref nodes);
                ValidateStatusUnknownNotificationUpdateCancellation(r, json.RootElement, request: true, status: false);
                requestHash = Convert.ToHexString(SHA256.HashData(payload.Span));
                snapshot = RequestContent.Create(payload);
                r.Storage.Own(snapshot);
                r.Storage.Own(original);
                request.Content = snapshot;
            }
            Check();
            if (!status) r.BeforeSend?.Invoke();
            Check();
            Guid dispatch = Guid.NewGuid();
            attempt = new() { Dispatch = dispatch, RequestSha256 = requestHash };
            lock (gate) invocation.Attempts.Add(attempt);
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            Check();
            var response = message.Response;
            var stream = response.ContentStream;
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, r.Storage, allowContinuation: !status)
                .ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(response.ContentStream, stream) && body.Response.Status == (status ? 200 : 201));
            var responseHeaders = body.Response.Headers.ToArray();
            Require(!responseHeaders.Any(h => h.Name.Equals("Retry-After", StringComparison.OrdinalIgnoreCase)) &&
                responseHeaders.Count(h => new[] { "Location", "Azure-AsyncOperation", "Operation-Location" }
                    .Contains(h.Name, StringComparer.OrdinalIgnoreCase)) == (status ? 0 : 1));
            if (!status) Require(responseHeaders.Single(h => h.Name.Equals("Location", StringComparison.OrdinalIgnoreCase)).Value == expectedUri);
            using var document = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int rows = 512;
            JsonRows(document.RootElement, ref rows);
            ValidateStatusUnknownNotificationUpdateCancellation(r, document.RootElement, request: false, status);
            var native = ModelReaderWriter.Read<EventGridSubscriptionData>(new BinaryData(body.Bytes));
            Require(native is not null && native.Id?.ToString() == r.Window.Path &&
                native.Name == r.Scope.SubscriptionName && native.ResourceType.ToString() == "Microsoft.EventGrid/eventSubscriptions" &&
                native.Topic == r.Scope.Vault.ExportResourceId() && native.ProvisioningState?.ToString() == (status ? "Unknown" : "Updating") &&
                native.Labels.SequenceEqual(["secretkit-fixture-" + r.Binding.Selector.Nonce.ToString("N")]) &&
                native.Filter is not null && native.Filter.IncludedEventTypes.SequenceEqual(["Microsoft.KeyVault.SecretNewVersionCreated"]) &&
                native.Destination is WebHookEventSubscriptionDestination webhook &&
                webhook.Endpoint?.OriginalString == r.Configuration.Endpoint.Reveal() && webhook.DeliveryAttributeMappings.Count == 0);
            r.Parsers.Add(OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, r.Storage,
                requireRebuffer: true, requireDownstreamRead: status));
            attempt.HttpStatus = body.Response.Status;
            attempt.ResponseObserved = true;
            attempt.ResponseSha256 = body.Sha256;
            attempt.State = status ? WireState.Unknown : WireState.Pending;
            attempt.Valid = true;
            attempt.HasProviderContinuation = !status;
            var wire = new StatusVaultCancellationWire(status ? 1 : 0, request, expectedUri, dispatch,
                body.Response.Status, attempt.State, body.Sha256, body.NativeRequestId, true, requestHash,
                Array.AsReadOnly(headers.Select(h => (h.Name, h.Value)).ToArray()));
            lock (gate)
            {
                if (status) r.StatusWire = wire;
                else
                {
                    r.Wire = wire;
                    r.Target = new(r.Binding, dispatch, StatusTargetKind.SelectedResource, new Uri(expectedUri),
                        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(expectedUri))), body.Sha256);
                    r.Candidate = new(r.Binding, dispatch, body.Response.Status, body.Bytes.Length, requestHash, body.Sha256, body.NativeRequestId);
                    r.TransportSucceeded = true;
                }
            }
        }
        catch (OperationCanceledException) { lock (gate) r.Invalid = true; throw; }
        catch { lock (gate) r.Invalid = true; throw new IOException("management-capture-transport"); }
        finally
        {
            message.Request.Content = original;
            lock (gate)
            {
                if (attempt is not null) attempt.TransportTerminated = true;
                invocation.Sending = false;
            }
        }
    }

    private static void ValidateStatusUnknownNotificationUpdateCancellation(StatusUnknownNotificationUpdateCancellationRegistration r, JsonElement root,
        bool request, bool status)
    {
        var scope = r.Scope;
        var configuration = r.Configuration;
        Require(OnlyApprovalFields(root, request ? ["destination", "filter"] :
            ["id", "name", "type", "properties"]));
        if (!request)
            Require(ApprovalText(root, "id") == r.Window.Path &&
                ApprovalText(root, "name") == scope.SubscriptionName &&
                ApprovalText(root, "type") == "Microsoft.EventGrid/eventSubscriptions");
        var properties = request ? root : root.GetProperty("properties");
        Require(OnlyApprovalFields(properties, request ? ["destination", "filter"] :
            ["topic", "labels", "provisioningState", "destination", "filter"]));
        if (!request)
        {
            Require(ApprovalText(properties, "topic") == scope.Vault.ExportResourceId() &&
                ApprovalText(properties, "provisioningState") == (status ? "Unknown" : "Updating"));
            var labels = properties.GetProperty("labels");
            Require(labels.ValueKind == JsonValueKind.Array && labels.GetArrayLength() == 1 &&
                labels[0].ValueKind == JsonValueKind.String &&
                labels[0].GetString() == "secretkit-fixture-" + r.Binding.Selector.Nonce.ToString("N"));
        }
        var filter = properties.GetProperty("filter");
        Require(OnlyApprovalFields(filter, "includedEventTypes", "advancedFilters"));
        var events = filter.GetProperty("includedEventTypes");
        Require(events.ValueKind == JsonValueKind.Array && events.GetArrayLength() == 1 &&
            events[0].GetString() == "Microsoft.KeyVault.SecretNewVersionCreated");
        if (filter.TryGetProperty("advancedFilters", out var advanced))
            Require(advanced.ValueKind == JsonValueKind.Array && advanced.GetArrayLength() == 0);
        var destination = properties.GetProperty("destination");
        Require(OnlyApprovalFields(destination, "endpointType", "properties") &&
            ApprovalText(destination, "endpointType") == "WebHook");
        var settings = destination.GetProperty("properties");
        Require(OnlyApprovalFields(settings, request ? ["endpointUrl"] :
            ["endpointUrl", "endpointBaseUrl", "deliveryAttributeMappings"]) &&
            ApprovalText(settings, "endpointUrl") == configuration.Endpoint.Reveal());
        var endpoint = new Uri(configuration.Endpoint.Reveal(), UriKind.Absolute);
        Require(endpoint.Scheme == "https" && endpoint.UserInfo.Length == 0 && endpoint.Fragment.Length == 0);
        if (!request)
        {
            var mappings = settings.GetProperty("deliveryAttributeMappings");
            Require(mappings.ValueKind == JsonValueKind.Array && mappings.GetArrayLength() == 0);
            if (settings.TryGetProperty("endpointBaseUrl", out var endpointBase))
                Require(endpointBase.ValueKind == JsonValueKind.String &&
                    endpointBase.GetString() == endpoint.GetLeftPart(UriPartial.Path));
        }
    }

    internal sealed class StatusUnknownNotificationUpdateIndependentStartProof(Binding binding, Guid startDispatch,
        int httpStatus, int responseBytes, string requestSha256, string responseSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal Guid StartDispatch { get; } = startDispatch;
        internal int HttpStatus { get; } = httpStatus;
        internal int ResponseBytes { get; } = responseBytes;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        public override string ToString() => "[StatusUnknownNotificationUpdateIndependentStartProof]";
    }

    // This capability proves the native Unknown call drained, never remote termination.
    internal sealed class StatusUnknownNotificationUpdateIndependentCompletionProof(StatusUnknownNotificationUpdateIndependentStartProof start)
    {
        internal StatusUnknownNotificationUpdateIndependentStartProof Start { get; } = start;
        public override string ToString() => "[StatusUnknownNotificationUpdateIndependentCompletionProof]";
    }

    private sealed class StatusUnknownNotificationUpdateIndependentRegistration(Window window, Invocation start,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, CancellationToken token,
        Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly Invocation Start = start;
        internal readonly VaultAdministration Client = client;
        internal readonly NotificationScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken StartToken = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly List<OwnedArmResponse.ParserCustody> Parsers = [];
        internal NotificationConfiguration Configuration = null!;
        internal StatusTarget? Target;
        internal StatusVaultCancellationWire? StatusWire;
        internal int StatusSends;
        internal StatusVaultCancellationWire? Wire;
        internal StatusUnknownNotificationUpdateIndependentStartProof? Candidate, StartProof;
        internal StatusUnknownNotificationUpdateIndependentCompletionProof? Completion;
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task<Capture>? SealTask;
        internal Invocation? Status;
        internal ManagementOperation? Handle;
        internal CancellationToken StatusToken, StatusCallerToken;
        internal int Sends;
        internal bool Invalid, Sealed, StartHookReturned, StartSucceeded, TransportSucceeded, StartComplete;
        internal bool CheckClaimed, StatusHookReturned, StatusCompleted, Complete;
    }

    private readonly Dictionary<Window, StatusUnknownNotificationUpdateIndependentRegistration> statusUnknownNotificationUpdateIndependent =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Invocation, StatusUnknownNotificationUpdateIndependentRegistration> statusUnknownNotificationUpdateIndependentInvocations =
        new(ReferenceEqualityComparer.Instance);

    internal bool TryGetStatusUnknownNotificationUpdateIndependentStart(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, [NotNullWhen(true)] out StatusUnknownNotificationUpdateIndependentStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusUnknownNotificationUpdateIndependent.TryGetValue(window, out var r) ||
                !NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentSelector(binding.Selector) ||
                !ReferenceEquals(r.Binding, binding) || !ReferenceEquals(r.Client, client) ||
                !ReferenceEquals(r.Scope, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.StartTask, startTask) || !ReferenceEquals(r.Handle, handle) ||
                !StatusUnknownNotificationUpdateIndependentStartValid(r) ||
                receipt.Evidence != DispatchEvidence.Pending ||
                !(handle.State == NativeProvisioningState.Pending || r.Complete && handle.State == NativeProvisioningState.Unknown) ||
                !ReferenceEquals(targets.GetValueOrDefault(window), r.Target)) return false;
            proof = r.StartProof;
            return proof is not null;
        }
    }

    internal bool TryGetStatusUnknownNotificationUpdateIndependentCompletion(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task statusTask,
        [NotNullWhen(true)] out StatusUnknownNotificationUpdateIndependentCompletionProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusUnknownNotificationUpdateIndependentStart(window, binding, client, scope, receipt,
                    startTask, handle, out _) || !statusUnknownNotificationUpdateIndependent.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.StatusTask, statusTask) || !r.Complete ||
                !r.Checked.Task.IsCompletedSuccessfully || r.StatusTask is not { IsCompletedSuccessfully: true } ||
                r.StatusToken.IsCancellationRequested || r.StatusCallerToken.IsCancellationRequested ||
                handle.State != NativeProvisioningState.Unknown || receipt.Evidence != DispatchEvidence.Pending) return false;
            proof = r.Completion;
            return proof is not null;
        }
    }

    private static bool StatusUnknownNotificationUpdateIndependentStartValid(StatusUnknownNotificationUpdateIndependentRegistration r) =>
        !r.Invalid && !r.Sealed && r.StartComplete && r.StartProof is not null &&
        r.Started.Task.IsCompletedSuccessfully && r.StartTask is { IsCompletedSuccessfully: true } &&
        !r.StartToken.IsCancellationRequested &&
        (!r.CheckClaimed || !r.StatusToken.IsCancellationRequested && !r.StatusCallerToken.IsCancellationRequested);

    internal async Task<SecretOutcome<ManagementOperation>> StartStatusUnknownNotificationUpdateIndependentAsync(
        Window window, FixtureSelector selector, VaultAdministration client, ManagementScope scope,
        ManagementOperationEffects.Input input, ManagementReceipt receipt, CancellationToken token = default,
        Action<Task>? retained = null, Action? beforeSend = null)
    {
        StatusUnknownNotificationUpdateIndependentRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(client is not null && receipt is not null && scope is NotificationScope &&
                NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentSelector(selector) &&
                window.Binding.Operation == ManagementMutation.UpdateNotification &&
                window.Binding.ApiRevision == "2025-02-15" && InputMatches(window.Binding, input) &&
                Route(window.Binding with { Resource = scope }) == Route(window.Binding));
            if (statusUnknownNotificationUpdateIndependent.TryGetValue(window, out var existing))
            {
                Require(ReferenceEquals(existing.Client, client) && ReferenceEquals(existing.Scope, scope) &&
                    ReferenceEquals(existing.Receipt, receipt));
                existing.Invalid = true;
                throw new InvalidOperationException("management-capture-boundary");
            }
            Require(!window.Closed && window.Start is null && startedWindows.Add(window) && !token.IsCancellationRequested);
            var invocation = window.Start = new();
            r = new(window, invocation, client, (NotificationScope)scope, receipt, token, beforeSend)
            { Configuration = new(input.WebhookUrl, [VaultNotificationEvent.SecretNewVersionCreated], []) };
            statusUnknownNotificationUpdateIndependent.Add(window, r);
            statusUnknownNotificationUpdateIndependentInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretOutcome<ManagementOperation>> task;
            var previous = current.Value;
            current.Value = new(window, r.Start, false);
            try { task = ManagementOperationEffects.StartAsync(client, scope, window.Binding.Operation, input, receipt, token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) r.Start.SdkTask = r.StartTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StartHookReturned = true;
            }
            finally
            {
                var result = await task.ConfigureAwait(false);
                lock (gate)
                {
                    r.Start.Outcome = result.Status;
                    r.Handle = result.IsSuccess ? result.Value : null;
                    r.Start.WrapperState = r.Handle?.State;
                    r.StartSucceeded = task.IsCompletedSuccessfully && result.IsSuccess &&
                        r.Handle!.State == NativeProvisioningState.Pending && receipt.Evidence == DispatchEvidence.Pending;
                    r.Start.HasNativeHandle = r.StartSucceeded;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; r.Start.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusUnknownNotificationUpdateIndependentAsync(r, r.Start).ConfigureAwait(false); }
    }

    private async Task<SecretStatus> CheckStatusUnknownNotificationUpdateIndependentAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained, CancellationToken originalCallerToken)
    {
        StatusUnknownNotificationUpdateIndependentRegistration r;
        Invocation invocation;
        lock (gate)
        {
            Own(window, selector);
            Require(statusUnknownNotificationUpdateIndependent.TryGetValue(window, out r!) &&
                handle is not null && ReferenceEquals(r.Handle, handle));
            bool valid = !r.CheckClaimed && !window.Closed && window.Status is null &&
                StatusUnknownNotificationUpdateIndependentStartValid(r) && !token.IsCancellationRequested && !originalCallerToken.IsCancellationRequested &&
                handle.State == NativeProvisioningState.Pending && r.Receipt.Evidence == DispatchEvidence.Pending;
            r.CheckClaimed = true;
            r.Invalid |= !valid;
            Require(valid);
            invocation = r.Status = window.Status = new();
            r.StatusToken = token;
            r.StatusCallerToken = originalCallerToken;
            statusUnknownNotificationUpdateIndependentInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretStatus> task;
            var previous = current.Value;
            current.Value = new(window, invocation, true);
            try { task = handle.CheckStatusAsync(token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) invocation.SdkTask = r.StatusTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StatusHookReturned = true;
            }
            finally
            {
                var outcome = await task.ConfigureAwait(false);
                lock (gate)
                {
                    invocation.Outcome = outcome;
                    invocation.WrapperState = handle.State;
                    r.StatusCompleted = task.IsCompletedSuccessfully && outcome == SecretStatus.Unknown &&
                        handle.State == NativeProvisioningState.Unknown;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; invocation.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusUnknownNotificationUpdateIndependentAsync(r, invocation).ConfigureAwait(false); }
    }

    private async Task FinishStatusUnknownNotificationUpdateIndependentAsync(StatusUnknownNotificationUpdateIndependentRegistration r,
        Invocation invocation)
    {
        bool start = ReferenceEquals(r.Start, invocation);
        Task<Task>? borrower;
        lock (gate)
        {
            Task? actual = start ? r.StartTask : r.StatusTask;
            Require(actual is null || actual.IsCompleted);
            finishing.Add(invocation);
            borrower = borrowers.TryGetValue(invocation, out var pending) ? pending.Task : null;
        }
        if (borrower is not null)
        {
            var actual = await borrower.ConfigureAwait(false);
            try { await actual.ConfigureAwait(false); }
            catch { lock (gate) r.Invalid = true; }
        }
        bool custodyValid, disposalFailed = false;
        try { custodyValid = r.Parsers.Count == (start ? 1 : 2) && r.Parsers.All(p => p.Complete && !p.Invalid); }
        catch { custodyValid = false; }
        if (!start)
        {
            try { r.Storage.Dispose(); }
            catch { disposalFailed = true; }
            try { custodyValid &= r.Parsers.All(p => p.Complete && !p.Invalid); }
            catch { custodyValid = false; }
        }
        lock (gate)
        {
            r.Invalid |= !custodyValid || disposalFailed;
            requestOwners.Remove(invocation);
            requestCandidates.Remove(invocation);
            borrowers.Remove(invocation);
            if (start)
            {
                r.StartComplete = !r.Invalid && r.StartHookReturned && r.StartSucceeded &&
                    r.TransportSucceeded && r.Sends == 1 && r.Candidate is not null &&
                    r.Wire is { Ordinal: 0, HttpStatus: 201, State: WireState.Pending, Complete: true } &&
                    r.Target is { Kind: StatusTargetKind.SelectedResource } &&
                    r.Target.StartDispatch == r.Candidate.StartDispatch &&
                    r.StartTask is { IsCompletedSuccessfully: true } && !r.StartToken.IsCancellationRequested &&
                    r.Handle?.State == NativeProvisioningState.Pending && r.Receipt.Evidence == DispatchEvidence.Pending;
                if (r.StartComplete)
                {
                    r.StartProof = r.Candidate;
                    targets[r.Window] = r.Target;
                    eligible.Add(r.Window);
                }
                r.Started.TrySetResult();
            }
            else
            {
                r.Complete = StatusUnknownNotificationUpdateIndependentStartValid(r) && r.StatusHookReturned && r.StatusCompleted &&
                    r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                    !r.StatusCallerToken.IsCancellationRequested &&
                    r.Receipt.Evidence == DispatchEvidence.Pending && r.Handle?.State == NativeProvisioningState.Unknown &&
                    r.StatusSends == 1 && r.StatusWire is { Ordinal: 1, HttpStatus: 200, State: WireState.Unknown, Complete: true } wire &&
                    r.Target is { } target && r.Wire is { } originalWire &&
                    wire.Uri == target.TargetUri.AbsoluteUri && wire.Dispatch != originalWire.Dispatch &&
                    !ReferenceEquals(wire.Request, originalWire.Request);
                if (r.Complete)
                {
                    r.Completion = new(r.StartProof!);
                    // Historical Unknown cannot grant generic remote-completion authority.
                }
                r.Checked.TrySetResult();
            }
            invocation.Terminated = true;
            invocation.Drained.TrySetResult();
        }
        if (disposalFailed) throw new InvalidOperationException("management-capture-finalization");
    }

    private Task<Capture> SealStatusUnknownNotificationUpdateIndependentAsync(Window window)
    {
        StatusUnknownNotificationUpdateIndependentRegistration r;
        TaskCompletionSource ready;
        Task<Capture> task;
        lock (gate)
        {
            Own(window, window.Binding.Selector);
            r = statusUnknownNotificationUpdateIndependent[window];
            window.Closed = true;
            if (r.SealTask is not null) return r.SealTask;
            r.Sealed = true;
            ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = r.SealTask = Drain(ready.Task);
        }
        ready.SetResult();
        return task;

        async Task<Capture> Drain(Task admission)
        {
            await admission.ConfigureAwait(false);
            await r.Started.Task.ConfigureAwait(false);
            if (r.Status is not null) await r.Checked.Task.ConfigureAwait(false);
            try { r.Storage.Dispose(); r.Configuration.Dispose(); }
            catch { lock (gate) r.Invalid = true; throw; }
            return new() { Binding = r.Binding, Start = r.Start, Status = r.Status };
        }
    }

    private async Task SendStatusUnknownNotificationUpdateIndependentAsync(StatusUnknownNotificationUpdateIndependentRegistration r,
        InvocationContext context, HttpMessage message, TaskCompletionSource<Task> borrower)
    {
        var invocation = context.Invocation;
        bool status = context.Status;
        lock (gate)
        {
            bool valid = !r.Invalid && !r.Sealed && !finishing.Contains(invocation) &&
                ReferenceEquals(invocation, status ? r.Status : r.Start) &&
                (status ? ++r.StatusSends == 1 && r.Target is not null && r.Receipt.Evidence == DispatchEvidence.Pending :
                    ++r.Sends == 1 && r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched) &&
                requestCandidates.TryGetValue(invocation, out var candidates) && candidates.Contains(message.Request);
            r.Invalid |= !valid;
            Require(valid);
            borrowers.Add(invocation, borrower);
            invocation.Sending = true;
            requestOwners.Add(invocation, message.Request);
            requestCandidates.Remove(invocation);
        }
        Attempt? attempt = null;
        RequestContent? original = message.Request.Content;
        RequestContent? snapshot = null;
        try
        {
            var request = message.Request;
            var headers = request.Headers.ToArray();
            string expectedUri = Origin + r.Window.Path + "?api-version=2025-02-15";
            void Check()
            {
                Require(ReferenceEquals(message.Request, request) && headers.SequenceEqual(request.Headers) &&
                    headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                    request.Method == (status ? RequestMethod.Get : RequestMethod.Patch) &&
                    ReferenceEquals(request.Content, snapshot) && Trusted(request.Uri.ToUri()) &&
                    request.Uri.ToUri().AbsoluteUri == expectedUri &&
                    (!status || expectedUri == r.Target!.TargetUri.AbsoluteUri) &&
                    request.Headers.TryGetValue("Authorization", out var auth) &&
                    auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
                    !headers.Any(h => new[] { "Content-Encoding", "Transfer-Encoding", "Content-Range", "Range" }
                        .Contains(h.Name, StringComparer.OrdinalIgnoreCase)));
                Headers(headers);
                if (request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
                r.StartToken.ThrowIfCancellationRequested();
                if (status)
                {
                    r.StatusToken.ThrowIfCancellationRequested();
                    r.StatusCallerToken.ThrowIfCancellationRequested();
                }
                message.CancellationToken.ThrowIfCancellationRequested();
            }
            string requestHash;
            if (status)
            {
                Require(original is null);
                if (request.Headers.TryGetValue("Content-Length", out var length)) Require(length == "0");
                requestHash = Convert.ToHexString(SHA256.HashData(ReadOnlySpan<byte>.Empty));
            }
            else
            {
                long length = 0;
                Require(original is not null && original.TryComputeLength(out length) && length > 0 && length <= maximumBytes);
                Require(request.Headers.TryGetValue("Content-Type", out var contentType) &&
                    contentType.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase));
                byte[] bytes = new byte[maximumBytes];
                r.Storage.Own(bytes);
                using var output = new MemoryStream(bytes, 0, bytes.Length, true, true);
                await original.WriteToAsync(output, message.CancellationToken).ConfigureAwait(false);
                Require(output.Position == length && ReferenceEquals(request.Content, original));
                if (request.Headers.TryGetValue("Content-Length", out var declared))
                    Require(declared == length.ToString(CultureInfo.InvariantCulture));
                var payload = bytes.AsMemory(0, checked((int)length));
                using var json = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 16 });
                int nodes = 512;
                JsonRows(json.RootElement, ref nodes);
                ValidateStatusUnknownNotificationUpdateIndependent(r, json.RootElement, request: true, status: false);
                requestHash = Convert.ToHexString(SHA256.HashData(payload.Span));
                snapshot = RequestContent.Create(payload);
                r.Storage.Own(snapshot);
                r.Storage.Own(original);
                request.Content = snapshot;
            }
            Check();
            if (!status) r.BeforeSend?.Invoke();
            Check();
            Guid dispatch = Guid.NewGuid();
            attempt = new() { Dispatch = dispatch, RequestSha256 = requestHash };
            lock (gate) invocation.Attempts.Add(attempt);
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            Check();
            var response = message.Response;
            var stream = response.ContentStream;
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, r.Storage, allowContinuation: !status)
                .ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(response.ContentStream, stream) && body.Response.Status == (status ? 200 : 201));
            var responseHeaders = body.Response.Headers.ToArray();
            Require(!responseHeaders.Any(h => h.Name.Equals("Retry-After", StringComparison.OrdinalIgnoreCase)) &&
                responseHeaders.Count(h => new[] { "Location", "Azure-AsyncOperation", "Operation-Location" }
                    .Contains(h.Name, StringComparer.OrdinalIgnoreCase)) == (status ? 0 : 1));
            if (!status) Require(responseHeaders.Single(h => h.Name.Equals("Location", StringComparison.OrdinalIgnoreCase)).Value == expectedUri);
            using var document = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int rows = 512;
            JsonRows(document.RootElement, ref rows);
            ValidateStatusUnknownNotificationUpdateIndependent(r, document.RootElement, request: false, status);
            var native = ModelReaderWriter.Read<EventGridSubscriptionData>(new BinaryData(body.Bytes));
            Require(native is not null && native.Id?.ToString() == r.Window.Path &&
                native.Name == r.Scope.SubscriptionName && native.ResourceType.ToString() == "Microsoft.EventGrid/eventSubscriptions" &&
                native.Topic == r.Scope.Vault.ExportResourceId() && native.ProvisioningState?.ToString() == (status ? "Unknown" : "Updating") &&
                native.Labels.SequenceEqual(["secretkit-fixture-" + r.Binding.Selector.Nonce.ToString("N")]) &&
                native.Filter is not null && native.Filter.IncludedEventTypes.SequenceEqual(["Microsoft.KeyVault.SecretNewVersionCreated"]) &&
                native.Destination is WebHookEventSubscriptionDestination webhook &&
                webhook.Endpoint?.OriginalString == r.Configuration.Endpoint.Reveal() && webhook.DeliveryAttributeMappings.Count == 0);
            r.Parsers.Add(OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, r.Storage,
                requireRebuffer: true, requireDownstreamRead: status));
            attempt.HttpStatus = body.Response.Status;
            attempt.ResponseObserved = true;
            attempt.ResponseSha256 = body.Sha256;
            attempt.State = status ? WireState.Unknown : WireState.Pending;
            attempt.Valid = true;
            attempt.HasProviderContinuation = !status;
            var wire = new StatusVaultCancellationWire(status ? 1 : 0, request, expectedUri, dispatch,
                body.Response.Status, attempt.State, body.Sha256, body.NativeRequestId, true, requestHash,
                Array.AsReadOnly(headers.Select(h => (h.Name, h.Value)).ToArray()));
            lock (gate)
            {
                if (status) r.StatusWire = wire;
                else
                {
                    r.Wire = wire;
                    r.Target = new(r.Binding, dispatch, StatusTargetKind.SelectedResource, new Uri(expectedUri),
                        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(expectedUri))), body.Sha256);
                    r.Candidate = new(r.Binding, dispatch, body.Response.Status, body.Bytes.Length, requestHash, body.Sha256, body.NativeRequestId);
                    r.TransportSucceeded = true;
                }
            }
        }
        catch (OperationCanceledException) { lock (gate) r.Invalid = true; throw; }
        catch { lock (gate) r.Invalid = true; throw new IOException("management-capture-transport"); }
        finally
        {
            message.Request.Content = original;
            lock (gate)
            {
                if (attempt is not null) attempt.TransportTerminated = true;
                invocation.Sending = false;
            }
        }
    }

    private static void ValidateStatusUnknownNotificationUpdateIndependent(StatusUnknownNotificationUpdateIndependentRegistration r, JsonElement root,
        bool request, bool status)
    {
        var scope = r.Scope;
        var configuration = r.Configuration;
        Require(OnlyApprovalFields(root, request ? ["destination", "filter"] :
            ["id", "name", "type", "properties"]));
        if (!request)
            Require(ApprovalText(root, "id") == r.Window.Path &&
                ApprovalText(root, "name") == scope.SubscriptionName &&
                ApprovalText(root, "type") == "Microsoft.EventGrid/eventSubscriptions");
        var properties = request ? root : root.GetProperty("properties");
        Require(OnlyApprovalFields(properties, request ? ["destination", "filter"] :
            ["topic", "labels", "provisioningState", "destination", "filter"]));
        if (!request)
        {
            Require(ApprovalText(properties, "topic") == scope.Vault.ExportResourceId() &&
                ApprovalText(properties, "provisioningState") == (status ? "Unknown" : "Updating"));
            var labels = properties.GetProperty("labels");
            Require(labels.ValueKind == JsonValueKind.Array && labels.GetArrayLength() == 1 &&
                labels[0].ValueKind == JsonValueKind.String &&
                labels[0].GetString() == "secretkit-fixture-" + r.Binding.Selector.Nonce.ToString("N"));
        }
        var filter = properties.GetProperty("filter");
        Require(OnlyApprovalFields(filter, "includedEventTypes", "advancedFilters"));
        var events = filter.GetProperty("includedEventTypes");
        Require(events.ValueKind == JsonValueKind.Array && events.GetArrayLength() == 1 &&
            events[0].GetString() == "Microsoft.KeyVault.SecretNewVersionCreated");
        if (filter.TryGetProperty("advancedFilters", out var advanced))
            Require(advanced.ValueKind == JsonValueKind.Array && advanced.GetArrayLength() == 0);
        var destination = properties.GetProperty("destination");
        Require(OnlyApprovalFields(destination, "endpointType", "properties") &&
            ApprovalText(destination, "endpointType") == "WebHook");
        var settings = destination.GetProperty("properties");
        Require(OnlyApprovalFields(settings, request ? ["endpointUrl"] :
            ["endpointUrl", "endpointBaseUrl", "deliveryAttributeMappings"]) &&
            ApprovalText(settings, "endpointUrl") == configuration.Endpoint.Reveal());
        var endpoint = new Uri(configuration.Endpoint.Reveal(), UriKind.Absolute);
        Require(endpoint.Scheme == "https" && endpoint.UserInfo.Length == 0 && endpoint.Fragment.Length == 0);
        if (!request)
        {
            var mappings = settings.GetProperty("deliveryAttributeMappings");
            Require(mappings.ValueKind == JsonValueKind.Array && mappings.GetArrayLength() == 0);
            if (settings.TryGetProperty("endpointBaseUrl", out var endpointBase))
                Require(endpointBase.ValueKind == JsonValueKind.String &&
                    endpointBase.GetString() == endpoint.GetLeftPart(UriPartial.Path));
        }
    }

    internal sealed class StatusDeniedNotificationUpdateStartProof(Binding binding, Guid startDispatch,
        int httpStatus, int responseBytes, string requestSha256, string responseSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal Guid StartDispatch { get; } = startDispatch;
        internal int HttpStatus { get; } = httpStatus;
        internal int ResponseBytes { get; } = responseBytes;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        public override string ToString() => "[StatusDeniedNotificationUpdateStartProof]";
    }

    // Local Failed is not remote settlement; the observer must join independent S/N evidence.
    internal sealed class StatusDeniedNotificationUpdateDeniedProof(StatusDeniedNotificationUpdateStartProof start,
        Task checkTask, int httpStatus, string responseSha256, string nativeRequestId)
    {
        internal StatusDeniedNotificationUpdateStartProof Start { get; } = start;
        internal Task CheckTask { get; } = checkTask;
        internal int HttpStatus { get; } = httpStatus;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal SecretStatus Outcome => SecretStatus.Denied;
        internal NativeProvisioningState State => NativeProvisioningState.Failed;
        internal DispatchEvidence ReceiptEvidence => DispatchEvidence.Pending;
        public override string ToString() => "[StatusDeniedNotificationUpdateDeniedProof]";
    }

    private static bool StatusDeniedNotificationUpdateSelector(FixtureSelector selector) =>
        selector is { Operation: "a.management.ManagementOperation.CheckStatusAsync",
            Variant: "operation.UpdateNotification" or "operation.CreateOrUpdateNotification", Case: "denied-authority" };

    private sealed class StatusDeniedNotificationUpdateRegistration(Window window, Invocation start,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, CancellationToken token,
        Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly Invocation Start = start;
        internal readonly VaultAdministration Client = client;
        internal readonly NotificationScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken StartToken = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly List<OwnedArmResponse.ParserCustody> Parsers = [];
        internal NotificationConfiguration Configuration = null!;
        internal StatusTarget? Target;
        internal StatusVaultCancellationWire? StatusWire;
        internal int StatusSends;
        internal StatusVaultCancellationWire? Wire;
        internal StatusDeniedNotificationUpdateStartProof? Candidate, StartProof;
        internal StatusDeniedNotificationUpdateDeniedProof? Denied;
        internal string? AuthorizationSha256;
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task<Capture>? SealTask;
        internal Invocation? Status;
        internal ManagementOperation? Handle;
        internal CancellationToken StatusToken, StatusCallerToken;
        internal int Sends;
        internal bool Invalid, Sealed, StartHookReturned, StartSucceeded, TransportSucceeded, StartComplete;
        internal bool CheckClaimed, StatusHookReturned, StatusCompleted, Complete;
    }

    private readonly Dictionary<Window, StatusDeniedNotificationUpdateRegistration> statusDeniedNotificationUpdate =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Invocation, StatusDeniedNotificationUpdateRegistration> statusDeniedNotificationUpdateInvocations =
        new(ReferenceEqualityComparer.Instance);

    internal bool TryGetStatusDeniedNotificationUpdateStart(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, [NotNullWhen(true)] out StatusDeniedNotificationUpdateStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusDeniedNotificationUpdate.TryGetValue(window, out var r) ||
                !StatusDeniedNotificationUpdateSelector(binding.Selector) ||
                !ReferenceEquals(r.Binding, binding) || !ReferenceEquals(r.Client, client) ||
                !ReferenceEquals(r.Scope, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.StartTask, startTask) || !ReferenceEquals(r.Handle, handle) ||
                !StatusDeniedNotificationUpdateStartValid(r) ||
                receipt.Evidence != DispatchEvidence.Pending ||
                !(handle.State == NativeProvisioningState.Pending || r.Complete && handle.State == NativeProvisioningState.Failed) ||
                !ReferenceEquals(targets.GetValueOrDefault(window), r.Target)) return false;
            proof = r.StartProof;
            return proof is not null;
        }
    }

    internal bool TryGetStatusDeniedNotificationUpdateDenied(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task checkTask,
        [NotNullWhen(true)] out StatusDeniedNotificationUpdateDeniedProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusDeniedNotificationUpdateStart(window, binding, client, scope, receipt,
                    startTask, handle, out _) || !statusDeniedNotificationUpdate.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.StatusTask, checkTask) || !r.Complete ||
                !r.Checked.Task.IsCompletedSuccessfully || r.StatusTask is not { IsCompletedSuccessfully: true } ||
                r.StatusToken.IsCancellationRequested || r.StatusCallerToken.IsCancellationRequested ||
                handle.State != NativeProvisioningState.Failed || receipt.Evidence != DispatchEvidence.Pending) return false;
            proof = r.Denied;
            return proof is not null && ReferenceEquals(proof.Start, r.StartProof) &&
                ReferenceEquals(proof.CheckTask, checkTask);
        }
    }

    internal bool OwnsStatusDeniedNotificationUpdateStart(StatusDeniedNotificationUpdateStartProof proof,
        Window window, Binding binding, VaultAdministration client, NotificationScope scope,
        ManagementReceipt receipt, Task startTask, ManagementOperation handle) =>
        TryGetStatusDeniedNotificationUpdateStart(window, binding, client, scope, receipt, startTask, handle, out var issued) &&
        ReferenceEquals(proof, issued);

    internal bool OwnsStatusDeniedNotificationUpdateDenied(StatusDeniedNotificationUpdateDeniedProof proof,
        Window window, Binding binding, VaultAdministration client, NotificationScope scope,
        ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task checkTask) =>
        TryGetStatusDeniedNotificationUpdateDenied(window, binding, client, scope, receipt, startTask, handle, checkTask, out var issued) &&
        ReferenceEquals(proof, issued);

    private static bool StatusDeniedNotificationUpdateStartValid(StatusDeniedNotificationUpdateRegistration r) =>
        !r.Invalid && !r.Sealed && r.StartComplete && r.StartProof is not null &&
        r.Started.Task.IsCompletedSuccessfully && r.StartTask is { IsCompletedSuccessfully: true } &&
        !r.StartToken.IsCancellationRequested &&
        (!r.CheckClaimed || !r.StatusToken.IsCancellationRequested && !r.StatusCallerToken.IsCancellationRequested);

    internal async Task<SecretOutcome<ManagementOperation>> StartStatusDeniedNotificationUpdateAsync(
        Window window, FixtureSelector selector, VaultAdministration client, ManagementScope scope,
        ManagementOperationEffects.Input input, ManagementReceipt receipt, CancellationToken token = default,
        Action<Task>? retained = null, Action? beforeSend = null)
    {
        StatusDeniedNotificationUpdateRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(client is not null && receipt is not null && scope is NotificationScope &&
                StatusDeniedNotificationUpdateSelector(selector) &&
                ReferenceEquals(window.Binding.Selector, selector) &&
                selector.Variant == "operation." + window.Binding.Operation &&
                window.Binding.ApiRevision == "2025-02-15" && InputMatches(window.Binding, input) &&
                Route(window.Binding with { Resource = scope }) == Route(window.Binding));
            if (statusDeniedNotificationUpdate.TryGetValue(window, out var existing))
            {
                Require(ReferenceEquals(existing.Client, client) && ReferenceEquals(existing.Scope, scope) &&
                    ReferenceEquals(existing.Receipt, receipt));
                existing.Invalid = true;
                throw new InvalidOperationException("management-capture-boundary");
            }
            Require(!window.Closed && window.Start is null && !token.IsCancellationRequested &&
                receipt.Evidence == DispatchEvidence.NotDispatched && startedWindows.Add(window));
            var invocation = window.Start = new();
            r = new(window, invocation, client, (NotificationScope)scope, receipt, token, beforeSend)
            { Configuration = new(input.WebhookUrl, [VaultNotificationEvent.SecretNewVersionCreated], []) };
            statusDeniedNotificationUpdate.Add(window, r);
            statusDeniedNotificationUpdateInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretOutcome<ManagementOperation>> task;
            var previous = current.Value;
            current.Value = new(window, r.Start, false);
            try { task = ManagementOperationEffects.StartAsync(client, scope, window.Binding.Operation, input, receipt, token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) r.Start.SdkTask = r.StartTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StartHookReturned = true;
            }
            finally
            {
                var result = await task.ConfigureAwait(false);
                lock (gate)
                {
                    r.Start.Outcome = result.Status;
                    r.Handle = result.IsSuccess ? result.Value : null;
                    r.Start.WrapperState = r.Handle?.State;
                    r.StartSucceeded = task.IsCompletedSuccessfully && result.IsSuccess &&
                        r.Handle!.State == NativeProvisioningState.Pending && receipt.Evidence == DispatchEvidence.Pending;
                    r.Start.HasNativeHandle = r.StartSucceeded;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; r.Start.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusDeniedNotificationUpdateAsync(r, r.Start).ConfigureAwait(false); }
    }

    internal ValueTask<SecretStatus> CheckStatusDeniedNotificationUpdateAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null)
        => CheckStatusDeniedNotificationUpdateCoreAsync(window, selector, handle, token, retained, token);

    private async ValueTask<SecretStatus> CheckStatusDeniedNotificationUpdateCoreAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained, CancellationToken originalCallerToken)
    {
        StatusDeniedNotificationUpdateRegistration r;
        Invocation invocation;
        lock (gate)
        {
            Own(window, selector);
            Require(ReferenceEquals(window.Binding.Selector, selector));
            Require(statusDeniedNotificationUpdate.TryGetValue(window, out r!));
            Require(handle is not null && ReferenceEquals(r.Handle, handle));
            bool valid = !r.CheckClaimed && !window.Closed && window.Status is null &&
                StatusDeniedNotificationUpdateStartValid(r) && !token.IsCancellationRequested && !originalCallerToken.IsCancellationRequested &&
                handle.State == NativeProvisioningState.Pending && r.Receipt.Evidence == DispatchEvidence.Pending;
            r.CheckClaimed = true;
            r.Invalid |= !valid;
            Require(valid);
            invocation = r.Status = window.Status = new();
            r.StatusToken = token;
            r.StatusCallerToken = originalCallerToken;
            statusDeniedNotificationUpdateInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretStatus> task;
            var previous = current.Value;
            current.Value = new(window, invocation, true);
            try { task = handle.CheckStatusAsync(token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) invocation.SdkTask = r.StatusTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StatusHookReturned = true;
            }
            finally
            {
                var outcome = await task.ConfigureAwait(false);
                lock (gate)
                {
                    invocation.Outcome = outcome;
                    invocation.WrapperState = handle.State;
                    r.StatusCompleted = task.IsCompletedSuccessfully && outcome == SecretStatus.Denied &&
                        handle.State == NativeProvisioningState.Failed;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; invocation.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusDeniedNotificationUpdateAsync(r, invocation).ConfigureAwait(false); }
    }

    private async Task FinishStatusDeniedNotificationUpdateAsync(StatusDeniedNotificationUpdateRegistration r,
        Invocation invocation)
    {
        bool start = ReferenceEquals(r.Start, invocation);
        Task<Task>? borrower;
        lock (gate)
        {
            Task? actual = start ? r.StartTask : r.StatusTask;
            Require(actual is null || actual.IsCompleted);
            finishing.Add(invocation);
            borrower = borrowers.TryGetValue(invocation, out var pending) ? pending.Task : null;
        }
        if (borrower is not null)
        {
            var actual = await borrower.ConfigureAwait(false);
            try { await actual.ConfigureAwait(false); }
            catch { lock (gate) r.Invalid = true; }
        }
        bool custodyValid, disposalFailed = false;
        try { custodyValid = r.Parsers.Count == (start ? 1 : 2) && r.Parsers.All(p => p.Complete && !p.Invalid); }
        catch { custodyValid = false; }
        if (!start)
        {
            try { r.Storage.Dispose(); }
            catch { disposalFailed = true; }
            try { custodyValid &= r.Parsers.All(p => p.Complete && !p.Invalid); }
            catch { custodyValid = false; }
        }
        lock (gate)
        {
            r.Invalid |= !custodyValid || disposalFailed;
            requestOwners.Remove(invocation);
            requestCandidates.Remove(invocation);
            borrowers.Remove(invocation);
            if (start)
            {
                r.StartComplete = !r.Invalid && r.StartHookReturned && r.StartSucceeded &&
                    r.TransportSucceeded && r.Sends == 1 && r.Candidate is not null &&
                    r.Wire is { Ordinal: 0, HttpStatus: 201, State: WireState.Pending, Complete: true } &&
                    r.Target is { Kind: StatusTargetKind.SelectedResource } &&
                    r.Target.StartDispatch == r.Candidate.StartDispatch &&
                    r.StartTask is { IsCompletedSuccessfully: true } && !r.StartToken.IsCancellationRequested &&
                    r.Handle?.State == NativeProvisioningState.Pending && r.Receipt.Evidence == DispatchEvidence.Pending;
                if (r.StartComplete)
                {
                    r.StartProof = r.Candidate;
                    targets[r.Window] = r.Target;
                    eligible.Add(r.Window);
                }
                r.Started.TrySetResult();
            }
            else
            {
                r.Complete = StatusDeniedNotificationUpdateStartValid(r) && r.StatusHookReturned && r.StatusCompleted &&
                    r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                    !r.StatusCallerToken.IsCancellationRequested &&
                    r.Receipt.Evidence == DispatchEvidence.Pending && r.Handle?.State == NativeProvisioningState.Failed &&
                    r.StatusSends == 1 && r.StatusWire is { Ordinal: 1, HttpStatus: 401 or 403, State: WireState.Denied, Complete: true } wire &&
                    r.Target is { } target && r.Wire is { } originalWire &&
                    wire.Uri == target.TargetUri.AbsoluteUri && wire.Dispatch != originalWire.Dispatch &&
                    !ReferenceEquals(wire.Request, originalWire.Request);
                if (r.Complete)
                {
                    var deniedWire = r.StatusWire!;
                    r.Denied = new(r.StartProof!, r.StatusTask!, deniedWire.HttpStatus,
                        deniedWire.ResponseSha256, deniedWire.NativeRequestId);
                    // Denial alone cannot grant generic remote-completion authority.
                }
                r.Checked.TrySetResult();
            }
            invocation.Terminated = true;
            invocation.Drained.TrySetResult();
        }
        if (disposalFailed) throw new InvalidOperationException("management-capture-finalization");
    }

    private Task<Capture> SealStatusDeniedNotificationUpdateAsync(Window window)
    {
        StatusDeniedNotificationUpdateRegistration r;
        TaskCompletionSource ready;
        Task<Capture> task;
        lock (gate)
        {
            Own(window, window.Binding.Selector);
            r = statusDeniedNotificationUpdate[window];
            window.Closed = true;
            if (r.SealTask is not null) return r.SealTask;
            r.Sealed = true;
            ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = r.SealTask = Drain(ready.Task);
        }
        ready.SetResult();
        return task;

        async Task<Capture> Drain(Task admission)
        {
            await admission.ConfigureAwait(false);
            await r.Started.Task.ConfigureAwait(false);
            if (r.Status is not null) await r.Checked.Task.ConfigureAwait(false);
            try { r.Storage.Dispose(); r.Configuration.Dispose(); r.AuthorizationSha256 = null; }
            catch { lock (gate) r.Invalid = true; throw; }
            return new() { Binding = r.Binding, Start = r.Start, Status = r.Status };
        }
    }

    private async Task SendStatusDeniedNotificationUpdateAsync(StatusDeniedNotificationUpdateRegistration r,
        InvocationContext context, HttpMessage message, TaskCompletionSource<Task> borrower)
    {
        var invocation = context.Invocation;
        bool status = context.Status;
        lock (gate)
        {
            bool valid = !r.Invalid && !r.Sealed && !finishing.Contains(invocation) &&
                ReferenceEquals(invocation, status ? r.Status : r.Start) &&
                (status ? ++r.StatusSends == 1 && r.Target is not null && r.Receipt.Evidence == DispatchEvidence.Pending :
                    ++r.Sends == 1 && r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched) &&
                requestCandidates.TryGetValue(invocation, out var candidates) && candidates.Contains(message.Request);
            r.Invalid |= !valid;
            Require(valid);
            borrowers.Add(invocation, borrower);
            invocation.Sending = true;
            requestOwners.Add(invocation, message.Request);
            requestCandidates.Remove(invocation);
        }
        Attempt? attempt = null;
        RequestContent? original = message.Request.Content;
        RequestContent? snapshot = null;
        try
        {
            var request = message.Request;
            var headers = request.Headers.ToArray();
            string expectedUri = Origin + r.Window.Path + "?api-version=2025-02-15";
            void Check()
            {
                Require(ReferenceEquals(message.Request, request) && headers.SequenceEqual(request.Headers) &&
                    headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                    request.Method == (status ? RequestMethod.Get : Route(r.Binding).Method) &&
                    ReferenceEquals(request.Content, snapshot) && Trusted(request.Uri.ToUri()) &&
                    request.Uri.ToUri().AbsoluteUri == expectedUri &&
                    (!status || expectedUri == r.Target!.TargetUri.AbsoluteUri) &&
                    request.Headers.TryGetValue("Authorization", out var auth) &&
                    auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
                    !headers.Any(h => new[] { "Content-Encoding", "Transfer-Encoding", "Content-Range", "Range" }
                        .Contains(h.Name, StringComparer.OrdinalIgnoreCase)));
                Headers(headers);
                if (request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
                r.StartToken.ThrowIfCancellationRequested();
                if (status)
                {
                    r.StatusToken.ThrowIfCancellationRequested();
                    r.StatusCallerToken.ThrowIfCancellationRequested();
                }
                message.CancellationToken.ThrowIfCancellationRequested();
            }
            string requestHash;
            if (status)
            {
                Require(original is null);
                if (request.Headers.TryGetValue("Content-Length", out var length)) Require(length == "0");
                requestHash = Convert.ToHexString(SHA256.HashData(ReadOnlySpan<byte>.Empty));
            }
            else
            {
                long length = 0;
                Require(original is not null && original.TryComputeLength(out length) && length > 0 && length <= maximumBytes);
                Require(request.Headers.TryGetValue("Content-Type", out var contentType) &&
                    contentType.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase));
                byte[] bytes = new byte[maximumBytes];
                r.Storage.Own(bytes);
                using var output = new MemoryStream(bytes, 0, bytes.Length, true, true);
                await original.WriteToAsync(output, message.CancellationToken).ConfigureAwait(false);
                Require(output.Position == length && ReferenceEquals(request.Content, original));
                if (request.Headers.TryGetValue("Content-Length", out var declared))
                    Require(declared == length.ToString(CultureInfo.InvariantCulture));
                var payload = bytes.AsMemory(0, checked((int)length));
                using var json = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 16 });
                int nodes = 512;
                JsonRows(json.RootElement, ref nodes);
                ValidateStatusDeniedNotificationUpdate(r, json.RootElement, request: true);
                requestHash = Convert.ToHexString(SHA256.HashData(payload.Span));
                snapshot = RequestContent.Create(payload);
                r.Storage.Own(snapshot);
                r.Storage.Own(original);
                request.Content = snapshot;
            }
            Check();
            request.Headers.TryGetValue("Authorization", out var authorization);
            byte[] authorizationBytes = System.Text.Encoding.UTF8.GetBytes(authorization!);
            string authorizationSha256;
            try { authorizationSha256 = Convert.ToHexString(SHA256.HashData(authorizationBytes)); }
            finally { CryptographicOperations.ZeroMemory(authorizationBytes); }
            if (status) Require(r.AuthorizationSha256 == authorizationSha256);
            else r.AuthorizationSha256 = authorizationSha256;
            if (!status) r.BeforeSend?.Invoke();
            Check();
            Guid dispatch = Guid.NewGuid();
            attempt = new() { Dispatch = dispatch, RequestSha256 = requestHash };
            lock (gate) invocation.Attempts.Add(attempt);
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            Check();
            var response = message.Response;
            var stream = response.ContentStream;
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, r.Storage, allowContinuation: !status)
                .ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(response.ContentStream, stream) && body.Bytes.Length > 0 &&
                (status ? body.Response.Status is 401 or 403 : body.Response.Status == 201) &&
                !body.Response.Headers.Contains("WWW-Authenticate"));
            var responseHeaders = body.Response.Headers.ToArray();
            Require(!responseHeaders.Any(h => h.Name.Equals("Retry-After", StringComparison.OrdinalIgnoreCase)) &&
                responseHeaders.Count(h => new[] { "Location", "Azure-AsyncOperation", "Operation-Location" }
                    .Contains(h.Name, StringComparer.OrdinalIgnoreCase)) == (status ? 0 : 1));
            if (!status) Require(responseHeaders.Single(h => h.Name.Equals("Location", StringComparison.OrdinalIgnoreCase)).Value == expectedUri);
            using var document = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int rows = 512;
            JsonRows(document.RootElement, ref rows);
            if (status)
            {
                var root = document.RootElement;
                Require(OnlyApprovalFields(root, "error") && root.TryGetProperty("error", out var error) &&
                    OnlyApprovalFields(error, "code", "message") &&
                    error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String &&
                    code.GetString() is { Length: > 0 and <= 128 } errorCode && !errorCode.Any(char.IsControl) &&
                    error.TryGetProperty("message", out var text) && text.ValueKind == JsonValueKind.String &&
                    text.GetString() is { Length: > 0 and <= 2048 } errorMessage && !errorMessage.Any(char.IsControl));
            }
            else
            {
                ValidateStatusDeniedNotificationUpdate(r, document.RootElement, request: false);
                var native = ModelReaderWriter.Read<EventGridSubscriptionData>(new BinaryData(body.Bytes));
                Require(native is not null && native.Id?.ToString() == r.Window.Path &&
                    native.Name == r.Scope.SubscriptionName && native.ResourceType.ToString() == "Microsoft.EventGrid/eventSubscriptions" &&
                    native.Topic == r.Scope.Vault.ExportResourceId() && native.ProvisioningState?.ToString() == "Updating" &&
                    native.Labels.SequenceEqual(["secretkit-fixture-" + r.Binding.Selector.Nonce.ToString("N")]) &&
                    native.Filter is not null && native.Filter.IncludedEventTypes.SequenceEqual(["Microsoft.KeyVault.SecretNewVersionCreated"]) &&
                    native.Destination is WebHookEventSubscriptionDestination webhook &&
                    webhook.Endpoint?.OriginalString == r.Configuration.Endpoint.Reveal() && webhook.DeliveryAttributeMappings.Count == 0);
            }
            r.Parsers.Add(OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, r.Storage,
                requireRebuffer: true, requireDownstreamRead: status));
            attempt.HttpStatus = body.Response.Status;
            attempt.ResponseObserved = true;
            attempt.ResponseSha256 = body.Sha256;
            attempt.State = status ? WireState.Denied : WireState.Pending;
            attempt.Valid = true;
            attempt.HasProviderContinuation = !status;
            var wire = new StatusVaultCancellationWire(status ? 1 : 0, request, expectedUri, dispatch,
                body.Response.Status, attempt.State, body.Sha256, body.NativeRequestId, true, requestHash,
                Array.AsReadOnly(headers.Select(h => (h.Name, h.Value)).ToArray()));
            lock (gate)
            {
                if (status) r.StatusWire = wire;
                else
                {
                    r.Wire = wire;
                    r.Target = new(r.Binding, dispatch, StatusTargetKind.SelectedResource, new Uri(expectedUri),
                        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(expectedUri))), body.Sha256);
                    r.Candidate = new(r.Binding, dispatch, body.Response.Status, body.Bytes.Length, requestHash, body.Sha256, body.NativeRequestId);
                    r.TransportSucceeded = true;
                }
            }
        }
        catch (OperationCanceledException) { lock (gate) r.Invalid = true; throw; }
        catch { lock (gate) r.Invalid = true; throw new IOException("management-capture-transport"); }
        finally
        {
            message.Request.Content = original;
            lock (gate)
            {
                if (attempt is not null) attempt.TransportTerminated = true;
                invocation.Sending = false;
            }
        }
    }

    private static void ValidateStatusDeniedNotificationUpdate(StatusDeniedNotificationUpdateRegistration r, JsonElement root,
        bool request)
    {
        var scope = r.Scope;
        var configuration = r.Configuration;
        bool flatRequest = request && r.Binding.Operation == ManagementMutation.UpdateNotification;
        Require(OnlyApprovalFields(root, request ? flatRequest ? ["destination", "filter"] : ["properties"] :
            ["id", "name", "type", "properties"]));
        if (!request)
            Require(ApprovalText(root, "id") == r.Window.Path &&
                ApprovalText(root, "name") == scope.SubscriptionName &&
                ApprovalText(root, "type") == "Microsoft.EventGrid/eventSubscriptions");
        var properties = flatRequest ? root : root.GetProperty("properties");
        Require(OnlyApprovalFields(properties, request ? ["destination", "filter"] :
            ["topic", "labels", "provisioningState", "destination", "filter"]));
        if (!request)
        {
            Require(ApprovalText(properties, "topic") == scope.Vault.ExportResourceId() &&
                ApprovalText(properties, "provisioningState") == "Updating");
            var labels = properties.GetProperty("labels");
            Require(labels.ValueKind == JsonValueKind.Array && labels.GetArrayLength() == 1 &&
                labels[0].ValueKind == JsonValueKind.String &&
                labels[0].GetString() == "secretkit-fixture-" + r.Binding.Selector.Nonce.ToString("N"));
        }
        var filter = properties.GetProperty("filter");
        Require(OnlyApprovalFields(filter, "includedEventTypes", "advancedFilters"));
        var events = filter.GetProperty("includedEventTypes");
        Require(events.ValueKind == JsonValueKind.Array && events.GetArrayLength() == 1 &&
            events[0].GetString() == "Microsoft.KeyVault.SecretNewVersionCreated");
        if (filter.TryGetProperty("advancedFilters", out var advanced))
            Require(advanced.ValueKind == JsonValueKind.Array && advanced.GetArrayLength() == 0);
        var destination = properties.GetProperty("destination");
        Require(OnlyApprovalFields(destination, "endpointType", "properties") &&
            ApprovalText(destination, "endpointType") == "WebHook");
        var settings = destination.GetProperty("properties");
        Require(OnlyApprovalFields(settings, request ? ["endpointUrl"] :
            ["endpointUrl", "endpointBaseUrl", "deliveryAttributeMappings"]) &&
            ApprovalText(settings, "endpointUrl") == configuration.Endpoint.Reveal());
        var endpoint = new Uri(configuration.Endpoint.Reveal(), UriKind.Absolute);
        Require(endpoint.Scheme == "https" && endpoint.UserInfo.Length == 0 && endpoint.Fragment.Length == 0);
        if (!request)
        {
            var mappings = settings.GetProperty("deliveryAttributeMappings");
            Require(mappings.ValueKind == JsonValueKind.Array && mappings.GetArrayLength() == 0);
            if (settings.TryGetProperty("endpointBaseUrl", out var endpointBase))
                Require(endpointBase.ValueKind == JsonValueKind.String &&
                    endpointBase.GetString() == endpoint.GetLeftPart(UriPartial.Path));
        }
    }


    internal sealed class StatusUnknownNotificationUpdateStartProof(Binding binding, Guid startDispatch,
        int httpStatus, int responseBytes, string requestSha256, string responseSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal Guid StartDispatch { get; } = startDispatch;
        internal int HttpStatus { get; } = httpStatus;
        internal int ResponseBytes { get; } = responseBytes;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        public override string ToString() => "[StatusUnknownNotificationUpdateStartProof]";
    }

    // This capability proves the native Unknown call drained, never remote termination.
    internal sealed class StatusUnknownNotificationUpdateCompletionProof(StatusUnknownNotificationUpdateStartProof start)
    {
        internal StatusUnknownNotificationUpdateStartProof Start { get; } = start;
        public override string ToString() => "[StatusUnknownNotificationUpdateCompletionProof]";
    }

    private sealed class StatusUnknownNotificationUpdateRegistration(Window window, Invocation start,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, CancellationToken token,
        Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly Invocation Start = start;
        internal readonly VaultAdministration Client = client;
        internal readonly NotificationScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken StartToken = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly List<OwnedArmResponse.ParserCustody> Parsers = [];
        internal NotificationConfiguration Configuration = null!;
        internal StatusTarget? Target;
        internal StatusVaultCancellationWire? StatusWire;
        internal int StatusSends;
        internal StatusVaultCancellationWire? Wire;
        internal StatusUnknownNotificationUpdateStartProof? Candidate, StartProof;
        internal StatusUnknownNotificationUpdateCompletionProof? Completion;
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task<Capture>? SealTask;
        internal Invocation? Status;
        internal ManagementOperation? Handle;
        internal CancellationToken StatusToken, StatusCallerToken;
        internal int Sends;
        internal bool Invalid, Sealed, StartHookReturned, StartSucceeded, TransportSucceeded, StartComplete;
        internal bool CheckClaimed, StatusHookReturned, StatusCompleted, Complete;
    }

    private readonly Dictionary<Window, StatusUnknownNotificationUpdateRegistration> statusUnknownNotificationUpdate =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Invocation, StatusUnknownNotificationUpdateRegistration> statusUnknownNotificationUpdateInvocations =
        new(ReferenceEqualityComparer.Instance);

    internal bool TryGetStatusUnknownNotificationUpdateStart(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, [NotNullWhen(true)] out StatusUnknownNotificationUpdateStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusUnknownNotificationUpdate.TryGetValue(window, out var r) ||
                !NotificationFixtureProvisioner.StatusUnknownNotificationUpdateSelector(binding.Selector) ||
                !ReferenceEquals(r.Binding, binding) || !ReferenceEquals(r.Client, client) ||
                !ReferenceEquals(r.Scope, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.StartTask, startTask) || !ReferenceEquals(r.Handle, handle) ||
                !StatusUnknownNotificationUpdateStartValid(r) ||
                receipt.Evidence != DispatchEvidence.Pending ||
                !(handle.State == NativeProvisioningState.Pending || r.Complete && handle.State == NativeProvisioningState.Unknown) ||
                !ReferenceEquals(targets.GetValueOrDefault(window), r.Target)) return false;
            proof = r.StartProof;
            return proof is not null;
        }
    }

    internal bool TryGetStatusUnknownNotificationUpdateCompletion(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task statusTask,
        [NotNullWhen(true)] out StatusUnknownNotificationUpdateCompletionProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusUnknownNotificationUpdateStart(window, binding, client, scope, receipt,
                    startTask, handle, out _) || !statusUnknownNotificationUpdate.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.StatusTask, statusTask) || !r.Complete ||
                !r.Checked.Task.IsCompletedSuccessfully || r.StatusTask is not { IsCompletedSuccessfully: true } ||
                r.StatusToken.IsCancellationRequested || r.StatusCallerToken.IsCancellationRequested ||
                handle.State != NativeProvisioningState.Unknown || receipt.Evidence != DispatchEvidence.Pending) return false;
            proof = r.Completion;
            return proof is not null;
        }
    }

    private static bool StatusUnknownNotificationUpdateStartValid(StatusUnknownNotificationUpdateRegistration r) =>
        !r.Invalid && !r.Sealed && r.StartComplete && r.StartProof is not null &&
        r.Started.Task.IsCompletedSuccessfully && r.StartTask is { IsCompletedSuccessfully: true } &&
        !r.StartToken.IsCancellationRequested &&
        (!r.CheckClaimed || !r.StatusToken.IsCancellationRequested && !r.StatusCallerToken.IsCancellationRequested);

    internal async Task<SecretOutcome<ManagementOperation>> StartStatusUnknownNotificationUpdateAsync(
        Window window, FixtureSelector selector, VaultAdministration client, ManagementScope scope,
        ManagementOperationEffects.Input input, ManagementReceipt receipt, CancellationToken token = default,
        Action<Task>? retained = null, Action? beforeSend = null)
    {
        StatusUnknownNotificationUpdateRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(client is not null && receipt is not null && scope is NotificationScope &&
                NotificationFixtureProvisioner.StatusUnknownNotificationUpdateSelector(selector) &&
                window.Binding.Operation == ManagementMutation.UpdateNotification &&
                window.Binding.ApiRevision == "2025-02-15" && InputMatches(window.Binding, input) &&
                Route(window.Binding with { Resource = scope }) == Route(window.Binding));
            if (statusUnknownNotificationUpdate.TryGetValue(window, out var existing))
            {
                Require(ReferenceEquals(existing.Client, client) && ReferenceEquals(existing.Scope, scope) &&
                    ReferenceEquals(existing.Receipt, receipt));
                existing.Invalid = true;
                throw new InvalidOperationException("management-capture-boundary");
            }
            Require(!window.Closed && window.Start is null && !token.IsCancellationRequested && startedWindows.Add(window));
            var invocation = window.Start = new();
            r = new(window, invocation, client, (NotificationScope)scope, receipt, token, beforeSend)
            { Configuration = new(input.WebhookUrl, [VaultNotificationEvent.SecretNewVersionCreated], []) };
            statusUnknownNotificationUpdate.Add(window, r);
            statusUnknownNotificationUpdateInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretOutcome<ManagementOperation>> task;
            var previous = current.Value;
            current.Value = new(window, r.Start, false);
            try { task = ManagementOperationEffects.StartAsync(client, scope, window.Binding.Operation, input, receipt, token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) r.Start.SdkTask = r.StartTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StartHookReturned = true;
            }
            finally
            {
                var result = await task.ConfigureAwait(false);
                lock (gate)
                {
                    r.Start.Outcome = result.Status;
                    r.Handle = result.IsSuccess ? result.Value : null;
                    r.Start.WrapperState = r.Handle?.State;
                    r.StartSucceeded = task.IsCompletedSuccessfully && result.IsSuccess &&
                        r.Handle!.State == NativeProvisioningState.Pending && receipt.Evidence == DispatchEvidence.Pending;
                    r.Start.HasNativeHandle = r.StartSucceeded;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; r.Start.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusUnknownNotificationUpdateAsync(r, r.Start).ConfigureAwait(false); }
    }

    private async Task<SecretStatus> CheckStatusUnknownNotificationUpdateAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained, CancellationToken originalCallerToken)
    {
        StatusUnknownNotificationUpdateRegistration r;
        Invocation invocation;
        lock (gate)
        {
            Own(window, selector);
            Require(statusUnknownNotificationUpdate.TryGetValue(window, out r!) &&
                handle is not null && ReferenceEquals(r.Handle, handle));
            bool valid = !r.CheckClaimed && !window.Closed && window.Status is null &&
                StatusUnknownNotificationUpdateStartValid(r) && !token.IsCancellationRequested && !originalCallerToken.IsCancellationRequested &&
                handle.State == NativeProvisioningState.Pending && r.Receipt.Evidence == DispatchEvidence.Pending;
            r.CheckClaimed = true;
            r.Invalid |= !valid;
            Require(valid);
            invocation = r.Status = window.Status = new();
            r.StatusToken = token;
            r.StatusCallerToken = originalCallerToken;
            statusUnknownNotificationUpdateInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretStatus> task;
            var previous = current.Value;
            current.Value = new(window, invocation, true);
            try { task = handle.CheckStatusAsync(token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) invocation.SdkTask = r.StatusTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StatusHookReturned = true;
            }
            finally
            {
                var outcome = await task.ConfigureAwait(false);
                lock (gate)
                {
                    invocation.Outcome = outcome;
                    invocation.WrapperState = handle.State;
                    r.StatusCompleted = task.IsCompletedSuccessfully && outcome == SecretStatus.Unknown &&
                        handle.State == NativeProvisioningState.Unknown;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; invocation.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusUnknownNotificationUpdateAsync(r, invocation).ConfigureAwait(false); }
    }

    private async Task FinishStatusUnknownNotificationUpdateAsync(StatusUnknownNotificationUpdateRegistration r,
        Invocation invocation)
    {
        bool start = ReferenceEquals(r.Start, invocation);
        Task<Task>? borrower;
        lock (gate)
        {
            Task? actual = start ? r.StartTask : r.StatusTask;
            Require(actual is null || actual.IsCompleted);
            finishing.Add(invocation);
            borrower = borrowers.TryGetValue(invocation, out var pending) ? pending.Task : null;
        }
        if (borrower is not null)
        {
            var actual = await borrower.ConfigureAwait(false);
            try { await actual.ConfigureAwait(false); }
            catch { lock (gate) r.Invalid = true; }
        }
        bool custodyValid, disposalFailed = false;
        try { custodyValid = r.Parsers.Count == (start ? 1 : 2) && r.Parsers.All(p => p.Complete && !p.Invalid); }
        catch { custodyValid = false; }
        if (!start)
        {
            try { r.Storage.Dispose(); }
            catch { disposalFailed = true; }
            try { custodyValid &= r.Parsers.All(p => p.Complete && !p.Invalid); }
            catch { custodyValid = false; }
        }
        lock (gate)
        {
            r.Invalid |= !custodyValid || disposalFailed;
            requestOwners.Remove(invocation);
            requestCandidates.Remove(invocation);
            borrowers.Remove(invocation);
            if (start)
            {
                r.StartComplete = !r.Invalid && r.StartHookReturned && r.StartSucceeded &&
                    r.TransportSucceeded && r.Sends == 1 && r.Candidate is not null &&
                    r.Wire is { Ordinal: 0, HttpStatus: 201, State: WireState.Pending, Complete: true } &&
                    r.Target is { Kind: StatusTargetKind.SelectedResource } &&
                    r.Target.StartDispatch == r.Candidate.StartDispatch &&
                    r.StartTask is { IsCompletedSuccessfully: true } && !r.StartToken.IsCancellationRequested &&
                    r.Handle?.State == NativeProvisioningState.Pending && r.Receipt.Evidence == DispatchEvidence.Pending;
                if (r.StartComplete)
                {
                    r.StartProof = r.Candidate;
                    targets[r.Window] = r.Target;
                    eligible.Add(r.Window);
                }
                r.Started.TrySetResult();
            }
            else
            {
                r.Complete = StatusUnknownNotificationUpdateStartValid(r) && r.StatusHookReturned && r.StatusCompleted &&
                    r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                    !r.StatusCallerToken.IsCancellationRequested &&
                    r.Receipt.Evidence == DispatchEvidence.Pending && r.Handle?.State == NativeProvisioningState.Unknown &&
                    r.StatusSends == 1 && r.StatusWire is { Ordinal: 1, HttpStatus: 200, State: WireState.Unknown, Complete: true } wire &&
                    r.Target is { } target && r.Wire is { } originalWire &&
                    wire.Uri == target.TargetUri.AbsoluteUri && wire.Dispatch != originalWire.Dispatch &&
                    !ReferenceEquals(wire.Request, originalWire.Request);
                if (r.Complete)
                {
                    r.Completion = new(r.StartProof!);
                    // Historical Unknown cannot grant generic remote-completion authority.
                }
                r.Checked.TrySetResult();
            }
            invocation.Terminated = true;
            invocation.Drained.TrySetResult();
        }
        if (disposalFailed) throw new InvalidOperationException("management-capture-finalization");
    }

    private Task<Capture> SealStatusUnknownNotificationUpdateAsync(Window window)
    {
        StatusUnknownNotificationUpdateRegistration r;
        TaskCompletionSource ready;
        Task<Capture> task;
        lock (gate)
        {
            Own(window, window.Binding.Selector);
            r = statusUnknownNotificationUpdate[window];
            window.Closed = true;
            if (r.SealTask is not null) return r.SealTask;
            r.Sealed = true;
            ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = r.SealTask = Drain(ready.Task);
        }
        ready.SetResult();
        return task;

        async Task<Capture> Drain(Task admission)
        {
            await admission.ConfigureAwait(false);
            await r.Started.Task.ConfigureAwait(false);
            if (r.Status is not null) await r.Checked.Task.ConfigureAwait(false);
            try { r.Storage.Dispose(); r.Configuration.Dispose(); }
            catch { lock (gate) r.Invalid = true; throw; }
            return new() { Binding = r.Binding, Start = r.Start, Status = r.Status };
        }
    }

    private async Task SendStatusUnknownNotificationUpdateAsync(StatusUnknownNotificationUpdateRegistration r,
        InvocationContext context, HttpMessage message, TaskCompletionSource<Task> borrower)
    {
        var invocation = context.Invocation;
        bool status = context.Status;
        lock (gate)
        {
            bool valid = !r.Invalid && !r.Sealed && !finishing.Contains(invocation) &&
                ReferenceEquals(invocation, status ? r.Status : r.Start) &&
                (status ? ++r.StatusSends == 1 && r.Target is not null && r.Receipt.Evidence == DispatchEvidence.Pending :
                    ++r.Sends == 1 && r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched) &&
                requestCandidates.TryGetValue(invocation, out var candidates) && candidates.Contains(message.Request);
            r.Invalid |= !valid;
            Require(valid);
            borrowers.Add(invocation, borrower);
            invocation.Sending = true;
            requestOwners.Add(invocation, message.Request);
            requestCandidates.Remove(invocation);
        }
        Attempt? attempt = null;
        RequestContent? original = message.Request.Content;
        RequestContent? snapshot = null;
        try
        {
            var request = message.Request;
            var headers = request.Headers.ToArray();
            string expectedUri = Origin + r.Window.Path + "?api-version=2025-02-15";
            void Check()
            {
                Require(ReferenceEquals(message.Request, request) && headers.SequenceEqual(request.Headers) &&
                    headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                    request.Method == (status ? RequestMethod.Get : RequestMethod.Patch) &&
                    ReferenceEquals(request.Content, snapshot) && Trusted(request.Uri.ToUri()) &&
                    request.Uri.ToUri().AbsoluteUri == expectedUri &&
                    (!status || expectedUri == r.Target!.TargetUri.AbsoluteUri) &&
                    request.Headers.TryGetValue("Authorization", out var auth) &&
                    auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
                    !headers.Any(h => new[] { "Content-Encoding", "Transfer-Encoding", "Content-Range", "Range" }
                        .Contains(h.Name, StringComparer.OrdinalIgnoreCase)));
                Headers(headers);
                if (request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
                r.StartToken.ThrowIfCancellationRequested();
                if (status)
                {
                    r.StatusToken.ThrowIfCancellationRequested();
                    r.StatusCallerToken.ThrowIfCancellationRequested();
                }
                message.CancellationToken.ThrowIfCancellationRequested();
            }
            string requestHash;
            if (status)
            {
                Require(original is null);
                if (request.Headers.TryGetValue("Content-Length", out var length)) Require(length == "0");
                requestHash = Convert.ToHexString(SHA256.HashData(ReadOnlySpan<byte>.Empty));
            }
            else
            {
                long length = 0;
                Require(original is not null && original.TryComputeLength(out length) && length > 0 && length <= maximumBytes);
                Require(request.Headers.TryGetValue("Content-Type", out var contentType) &&
                    contentType.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase));
                byte[] bytes = new byte[maximumBytes];
                r.Storage.Own(bytes);
                using var output = new MemoryStream(bytes, 0, bytes.Length, true, true);
                await original.WriteToAsync(output, message.CancellationToken).ConfigureAwait(false);
                Require(output.Position == length && ReferenceEquals(request.Content, original));
                if (request.Headers.TryGetValue("Content-Length", out var declared))
                    Require(declared == length.ToString(CultureInfo.InvariantCulture));
                var payload = bytes.AsMemory(0, checked((int)length));
                using var json = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 16 });
                int nodes = 512;
                JsonRows(json.RootElement, ref nodes);
                ValidateStatusUnknownNotificationUpdate(r, json.RootElement, request: true, status: false);
                requestHash = Convert.ToHexString(SHA256.HashData(payload.Span));
                snapshot = RequestContent.Create(payload);
                r.Storage.Own(snapshot);
                r.Storage.Own(original);
                request.Content = snapshot;
            }
            Check();
            if (!status) r.BeforeSend?.Invoke();
            Check();
            Guid dispatch = Guid.NewGuid();
            attempt = new() { Dispatch = dispatch, RequestSha256 = requestHash };
            lock (gate) invocation.Attempts.Add(attempt);
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            Check();
            var response = message.Response;
            var stream = response.ContentStream;
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, r.Storage, allowContinuation: !status)
                .ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(response.ContentStream, stream) && body.Response.Status == (status ? 200 : 201));
            var responseHeaders = body.Response.Headers.ToArray();
            Require(!responseHeaders.Any(h => h.Name.Equals("Retry-After", StringComparison.OrdinalIgnoreCase)) &&
                responseHeaders.Count(h => new[] { "Location", "Azure-AsyncOperation", "Operation-Location" }
                    .Contains(h.Name, StringComparer.OrdinalIgnoreCase)) == (status ? 0 : 1));
            if (!status) Require(responseHeaders.Single(h => h.Name.Equals("Location", StringComparison.OrdinalIgnoreCase)).Value == expectedUri);
            using var document = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int rows = 512;
            JsonRows(document.RootElement, ref rows);
            ValidateStatusUnknownNotificationUpdate(r, document.RootElement, request: false, status);
            var native = ModelReaderWriter.Read<EventGridSubscriptionData>(new BinaryData(body.Bytes));
            Require(native is not null && native.Id?.ToString() == r.Window.Path &&
                native.Name == r.Scope.SubscriptionName && native.ResourceType.ToString() == "Microsoft.EventGrid/eventSubscriptions" &&
                native.Topic == r.Scope.Vault.ExportResourceId() && native.ProvisioningState?.ToString() == (status ? "Unknown" : "Updating") &&
                native.Labels.SequenceEqual(["secretkit-fixture-" + r.Binding.Selector.Nonce.ToString("N")]) &&
                native.Filter is not null && native.Filter.IncludedEventTypes.SequenceEqual(["Microsoft.KeyVault.SecretNewVersionCreated"]) &&
                native.Destination is WebHookEventSubscriptionDestination webhook &&
                webhook.Endpoint?.OriginalString == r.Configuration.Endpoint.Reveal() && webhook.DeliveryAttributeMappings.Count == 0);
            r.Parsers.Add(OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, r.Storage,
                requireRebuffer: true, requireDownstreamRead: status));
            attempt.HttpStatus = body.Response.Status;
            attempt.ResponseObserved = true;
            attempt.ResponseSha256 = body.Sha256;
            attempt.State = status ? WireState.Unknown : WireState.Pending;
            attempt.Valid = true;
            attempt.HasProviderContinuation = !status;
            var wire = new StatusVaultCancellationWire(status ? 1 : 0, request, expectedUri, dispatch,
                body.Response.Status, attempt.State, body.Sha256, body.NativeRequestId, true, requestHash,
                Array.AsReadOnly(headers.Select(h => (h.Name, h.Value)).ToArray()));
            lock (gate)
            {
                if (status) r.StatusWire = wire;
                else
                {
                    r.Wire = wire;
                    r.Target = new(r.Binding, dispatch, StatusTargetKind.SelectedResource, new Uri(expectedUri),
                        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(expectedUri))), body.Sha256);
                    r.Candidate = new(r.Binding, dispatch, body.Response.Status, body.Bytes.Length, requestHash, body.Sha256, body.NativeRequestId);
                    r.TransportSucceeded = true;
                }
            }
        }
        catch (OperationCanceledException) { lock (gate) r.Invalid = true; throw; }
        catch { lock (gate) r.Invalid = true; throw new IOException("management-capture-transport"); }
        finally
        {
            message.Request.Content = original;
            lock (gate)
            {
                if (attempt is not null) attempt.TransportTerminated = true;
                invocation.Sending = false;
            }
        }
    }

    private static void ValidateStatusUnknownNotificationUpdate(StatusUnknownNotificationUpdateRegistration r, JsonElement root,
        bool request, bool status)
    {
        var scope = r.Scope;
        var configuration = r.Configuration;
        Require(OnlyApprovalFields(root, request ? ["destination", "filter"] :
            ["id", "name", "type", "properties"]));
        if (!request)
            Require(ApprovalText(root, "id") == r.Window.Path &&
                ApprovalText(root, "name") == scope.SubscriptionName &&
                ApprovalText(root, "type") == "Microsoft.EventGrid/eventSubscriptions");
        var properties = request ? root : root.GetProperty("properties");
        Require(OnlyApprovalFields(properties, request ? ["destination", "filter"] :
            ["topic", "labels", "provisioningState", "destination", "filter"]));
        if (!request)
        {
            Require(ApprovalText(properties, "topic") == scope.Vault.ExportResourceId() &&
                ApprovalText(properties, "provisioningState") == (status ? "Unknown" : "Updating"));
            var labels = properties.GetProperty("labels");
            Require(labels.ValueKind == JsonValueKind.Array && labels.GetArrayLength() == 1 &&
                labels[0].ValueKind == JsonValueKind.String &&
                labels[0].GetString() == "secretkit-fixture-" + r.Binding.Selector.Nonce.ToString("N"));
        }
        var filter = properties.GetProperty("filter");
        Require(OnlyApprovalFields(filter, "includedEventTypes", "advancedFilters"));
        var events = filter.GetProperty("includedEventTypes");
        Require(events.ValueKind == JsonValueKind.Array && events.GetArrayLength() == 1 &&
            events[0].GetString() == "Microsoft.KeyVault.SecretNewVersionCreated");
        if (filter.TryGetProperty("advancedFilters", out var advanced))
            Require(advanced.ValueKind == JsonValueKind.Array && advanced.GetArrayLength() == 0);
        var destination = properties.GetProperty("destination");
        Require(OnlyApprovalFields(destination, "endpointType", "properties") &&
            ApprovalText(destination, "endpointType") == "WebHook");
        var settings = destination.GetProperty("properties");
        Require(OnlyApprovalFields(settings, request ? ["endpointUrl"] :
            ["endpointUrl", "endpointBaseUrl", "deliveryAttributeMappings"]) &&
            ApprovalText(settings, "endpointUrl") == configuration.Endpoint.Reveal());
        var endpoint = new Uri(configuration.Endpoint.Reveal(), UriKind.Absolute);
        Require(endpoint.Scheme == "https" && endpoint.UserInfo.Length == 0 && endpoint.Fragment.Length == 0);
        if (!request)
        {
            var mappings = settings.GetProperty("deliveryAttributeMappings");
            Require(mappings.ValueKind == JsonValueKind.Array && mappings.GetArrayLength() == 0);
            if (settings.TryGetProperty("endpointBaseUrl", out var endpointBase))
                Require(endpointBase.ValueKind == JsonValueKind.String &&
                    endpointBase.GetString() == endpoint.GetLeftPart(UriPartial.Path));
        }
    }

    internal sealed class StatusNotificationUpdateIndependentStartProof(Binding binding, Guid startDispatch,
        int httpStatus, int responseBytes, string requestSha256, string responseSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal Guid StartDispatch { get; } = startDispatch;
        internal int HttpStatus { get; } = httpStatus;
        internal int ResponseBytes { get; } = responseBytes;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        public override string ToString() => "[StatusNotificationUpdateIndependentStartProof]";
    }

    internal sealed class StatusNotificationUpdateIndependentCompletionProof(StatusNotificationUpdateIndependentStartProof start)
    {
        internal StatusNotificationUpdateIndependentStartProof Start { get; } = start;
        public override string ToString() => "[StatusNotificationUpdateIndependentCompletionProof]";
    }

    private sealed class StatusNotificationUpdateIndependentRegistration(Window window, Invocation start,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, CancellationToken token,
        Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly Invocation Start = start;
        internal readonly VaultAdministration Client = client;
        internal readonly NotificationScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken StartToken = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly List<OwnedArmResponse.ParserCustody> Parsers = [];
        internal NotificationConfiguration Configuration = null!;
        internal StatusTarget? Target;
        internal StatusVaultCancellationWire? StatusWire;
        internal int StatusSends;
        internal StatusVaultCancellationWire? Wire;
        internal StatusNotificationUpdateIndependentStartProof? Candidate, StartProof;
        internal StatusNotificationUpdateIndependentCompletionProof? Completion;
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task<Capture>? SealTask;
        internal Invocation? Status;
        internal ManagementOperation? Handle;
        internal CancellationToken StatusToken;
        internal int Sends;
        internal bool Invalid, Sealed, StartHookReturned, StartSucceeded, TransportSucceeded, StartComplete;
        internal bool CheckClaimed, StatusHookReturned, StatusSucceeded, Complete;
    }

    private readonly Dictionary<Window, StatusNotificationUpdateIndependentRegistration> statusNotificationUpdateIndependent =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Invocation, StatusNotificationUpdateIndependentRegistration> statusNotificationUpdateIndependentInvocations =
        new(ReferenceEqualityComparer.Instance);

    internal bool TryGetStatusNotificationUpdateIndependentStart(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, [NotNullWhen(true)] out StatusNotificationUpdateIndependentStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusNotificationUpdateIndependent.TryGetValue(window, out var r) ||
                !NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(binding.Selector) ||
                !ReferenceEquals(r.Binding, binding) || !ReferenceEquals(r.Client, client) ||
                !ReferenceEquals(r.Scope, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.StartTask, startTask) || !ReferenceEquals(r.Handle, handle) ||
                !StatusNotificationUpdateIndependentStartValid(r) ||
                receipt.Evidence != DispatchEvidence.Pending ||
                !(handle.State == NativeProvisioningState.Pending || r.Complete && handle.State == NativeProvisioningState.Succeeded) ||
                !ReferenceEquals(targets.GetValueOrDefault(window), r.Target)) return false;
            proof = r.StartProof;
            return proof is not null;
        }
    }

    internal bool TryGetStatusNotificationUpdateIndependentCompletion(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task statusTask,
        [NotNullWhen(true)] out StatusNotificationUpdateIndependentCompletionProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusNotificationUpdateIndependentStart(window, binding, client, scope, receipt,
                    startTask, handle, out _) || !statusNotificationUpdateIndependent.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.StatusTask, statusTask) || !r.Complete ||
                !r.Checked.Task.IsCompletedSuccessfully || r.StatusTask is not { IsCompletedSuccessfully: true } ||
                r.StatusToken.IsCancellationRequested) return false;
            proof = r.Completion;
            return proof is not null;
        }
    }

    private static bool StatusNotificationUpdateIndependentStartValid(StatusNotificationUpdateIndependentRegistration r) =>
        !r.Invalid && !r.Sealed && r.StartComplete && r.StartProof is not null &&
        r.Started.Task.IsCompletedSuccessfully && r.StartTask is { IsCompletedSuccessfully: true } &&
        !r.StartToken.IsCancellationRequested;

    internal async Task<SecretOutcome<ManagementOperation>> StartNotificationUpdateIndependentAsync(
        Window window, FixtureSelector selector, VaultAdministration client, ManagementScope scope,
        ManagementOperationEffects.Input input, ManagementReceipt receipt, CancellationToken token = default,
        Action<Task>? retained = null, Action? beforeSend = null)
    {
        StatusNotificationUpdateIndependentRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(client is not null && receipt is not null && scope is NotificationScope &&
                NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector) &&
                window.Binding.Operation == ManagementMutation.UpdateNotification &&
                window.Binding.ApiRevision == "2025-02-15" && InputMatches(window.Binding, input) &&
                Route(window.Binding with { Resource = scope }) == Route(window.Binding));
            Require(!window.Closed && window.Start is null && startedWindows.Add(window));
            var invocation = window.Start = new();
            r = new(window, invocation, client, (NotificationScope)scope, receipt, token, beforeSend)
            { Configuration = new(input.WebhookUrl, [VaultNotificationEvent.SecretNewVersionCreated], []) };
            statusNotificationUpdateIndependent.Add(window, r);
            statusNotificationUpdateIndependentInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretOutcome<ManagementOperation>> task;
            var previous = current.Value;
            current.Value = new(window, r.Start, false);
            try { task = ManagementOperationEffects.StartAsync(client, scope, window.Binding.Operation, input, receipt, token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) r.Start.SdkTask = r.StartTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StartHookReturned = true;
            }
            finally
            {
                var result = await task.ConfigureAwait(false);
                lock (gate)
                {
                    r.Start.Outcome = result.Status;
                    r.Handle = result.IsSuccess ? result.Value : null;
                    r.Start.WrapperState = r.Handle?.State;
                    r.StartSucceeded = task.IsCompletedSuccessfully && result.IsSuccess &&
                        r.Handle!.State == NativeProvisioningState.Pending && receipt.Evidence == DispatchEvidence.Pending;
                    r.Start.HasNativeHandle = r.StartSucceeded;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; r.Start.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusNotificationUpdateIndependentAsync(r, r.Start).ConfigureAwait(false); }
    }

    private async Task<SecretStatus> CheckStatusNotificationUpdateIndependentAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained)
    {
        StatusNotificationUpdateIndependentRegistration r;
        Invocation invocation;
        lock (gate)
        {
            Own(window, selector);
            Require(statusNotificationUpdateIndependent.TryGetValue(window, out r!) &&
                handle is not null && ReferenceEquals(r.Handle, handle));
            bool valid = !r.CheckClaimed && !window.Closed && window.Status is null &&
                StatusNotificationUpdateIndependentStartValid(r) && !token.IsCancellationRequested &&
                handle.State == NativeProvisioningState.Pending && r.Receipt.Evidence == DispatchEvidence.Pending;
            r.CheckClaimed = true;
            r.Invalid |= !valid;
            Require(valid);
            invocation = r.Status = window.Status = new();
            r.StatusToken = token;
            statusNotificationUpdateIndependentInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretStatus> task;
            var previous = current.Value;
            current.Value = new(window, invocation, true);
            try { task = handle.CheckStatusAsync(token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) invocation.SdkTask = r.StatusTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StatusHookReturned = true;
            }
            finally
            {
                var outcome = await task.ConfigureAwait(false);
                lock (gate)
                {
                    invocation.Outcome = outcome;
                    invocation.WrapperState = handle.State;
                    r.StatusSucceeded = task.IsCompletedSuccessfully && outcome == SecretStatus.Success &&
                        handle.State == NativeProvisioningState.Succeeded;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; invocation.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusNotificationUpdateIndependentAsync(r, invocation).ConfigureAwait(false); }
    }

    private async Task FinishStatusNotificationUpdateIndependentAsync(StatusNotificationUpdateIndependentRegistration r,
        Invocation invocation)
    {
        bool start = ReferenceEquals(r.Start, invocation);
        Task<Task>? borrower;
        lock (gate)
        {
            Task? actual = start ? r.StartTask : r.StatusTask;
            Require(actual is null || actual.IsCompleted);
            finishing.Add(invocation);
            borrower = borrowers.TryGetValue(invocation, out var pending) ? pending.Task : null;
        }
        if (borrower is not null)
        {
            var actual = await borrower.ConfigureAwait(false);
            try { await actual.ConfigureAwait(false); }
            catch { lock (gate) r.Invalid = true; }
        }
        bool custodyValid, disposalFailed = false;
        try { custodyValid = r.Parsers.Count == (start ? 1 : 2) && r.Parsers.All(p => p.Complete && !p.Invalid); }
        catch { custodyValid = false; }
        if (!start)
        {
            try { r.Storage.Dispose(); }
            catch { disposalFailed = true; }
            try { custodyValid &= r.Parsers.All(p => p.Complete && !p.Invalid); }
            catch { custodyValid = false; }
        }
        lock (gate)
        {
            r.Invalid |= !custodyValid || disposalFailed;
            requestOwners.Remove(invocation);
            requestCandidates.Remove(invocation);
            borrowers.Remove(invocation);
            if (start)
            {
                r.StartComplete = !r.Invalid && r.StartHookReturned && r.StartSucceeded &&
                    r.TransportSucceeded && r.Sends == 1 && r.Candidate is not null &&
                    r.Wire is { Ordinal: 0, HttpStatus: 201, State: WireState.Pending, Complete: true } &&
                    r.Target is { Kind: StatusTargetKind.SelectedResource } &&
                    r.Target.StartDispatch == r.Candidate.StartDispatch &&
                    r.StartTask is { IsCompletedSuccessfully: true } && !r.StartToken.IsCancellationRequested &&
                    r.Handle?.State == NativeProvisioningState.Pending && r.Receipt.Evidence == DispatchEvidence.Pending;
                if (r.StartComplete)
                {
                    r.StartProof = r.Candidate;
                    targets[r.Window] = r.Target;
                    eligible.Add(r.Window);
                }
                r.Started.TrySetResult();
            }
            else
            {
                r.Complete = StatusNotificationUpdateIndependentStartValid(r) && r.StatusHookReturned && r.StatusSucceeded &&
                    r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                    r.Receipt.Evidence == DispatchEvidence.Pending && r.Handle?.State == NativeProvisioningState.Succeeded &&
                    r.StatusSends == 1 && r.StatusWire is { Ordinal: 1, HttpStatus: 200, State: WireState.Succeeded, Complete: true } wire &&
                    r.Target is { } target && r.Wire is { } originalWire &&
                    wire.Uri == target.TargetUri.AbsoluteUri && wire.Dispatch != originalWire.Dispatch &&
                    !ReferenceEquals(wire.Request, originalWire.Request);
                if (r.Complete)
                {
                    r.Completion = new(r.StartProof!);
                    completedStatusReads.Add(r.Window);
                }
                r.Checked.TrySetResult();
            }
            invocation.Terminated = true;
            invocation.Drained.TrySetResult();
        }
        if (disposalFailed) throw new InvalidOperationException("management-capture-finalization");
    }

    private Task<Capture> SealStatusNotificationUpdateIndependentAsync(Window window)
    {
        StatusNotificationUpdateIndependentRegistration r;
        TaskCompletionSource ready;
        Task<Capture> task;
        lock (gate)
        {
            Own(window, window.Binding.Selector);
            r = statusNotificationUpdateIndependent[window];
            window.Closed = true;
            if (r.SealTask is not null) return r.SealTask;
            r.Sealed = true;
            ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = r.SealTask = Drain(ready.Task);
        }
        ready.SetResult();
        return task;

        async Task<Capture> Drain(Task admission)
        {
            await admission.ConfigureAwait(false);
            await r.Started.Task.ConfigureAwait(false);
            if (r.Status is not null) await r.Checked.Task.ConfigureAwait(false);
            try { r.Storage.Dispose(); r.Configuration.Dispose(); }
            catch { lock (gate) r.Invalid = true; throw; }
            return new() { Binding = r.Binding, Start = r.Start, Status = r.Status };
        }
    }

    private async Task SendStatusNotificationUpdateIndependentAsync(StatusNotificationUpdateIndependentRegistration r,
        InvocationContext context, HttpMessage message, TaskCompletionSource<Task> borrower)
    {
        var invocation = context.Invocation;
        bool status = context.Status;
        lock (gate)
        {
            bool valid = !r.Invalid && !r.Sealed && !finishing.Contains(invocation) &&
                ReferenceEquals(invocation, status ? r.Status : r.Start) &&
                (status ? ++r.StatusSends == 1 && r.Target is not null && r.Receipt.Evidence == DispatchEvidence.Pending :
                    ++r.Sends == 1 && r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched) &&
                requestCandidates.TryGetValue(invocation, out var candidates) && candidates.Contains(message.Request);
            r.Invalid |= !valid;
            Require(valid);
            borrowers.Add(invocation, borrower);
            invocation.Sending = true;
            requestOwners.Add(invocation, message.Request);
            requestCandidates.Remove(invocation);
        }
        Attempt? attempt = null;
        RequestContent? original = message.Request.Content;
        RequestContent? snapshot = null;
        try
        {
            var request = message.Request;
            var headers = request.Headers.ToArray();
            string expectedUri = Origin + r.Window.Path + "?api-version=2025-02-15";
            void Check()
            {
                Require(ReferenceEquals(message.Request, request) && headers.SequenceEqual(request.Headers) &&
                    headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                    request.Method == (status ? RequestMethod.Get : RequestMethod.Patch) &&
                    ReferenceEquals(request.Content, snapshot) && Trusted(request.Uri.ToUri()) &&
                    request.Uri.ToUri().AbsoluteUri == expectedUri &&
                    (!status || expectedUri == r.Target!.TargetUri.AbsoluteUri) &&
                    request.Headers.TryGetValue("Authorization", out var auth) &&
                    auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
                    !headers.Any(h => new[] { "Content-Encoding", "Transfer-Encoding", "Content-Range", "Range" }
                        .Contains(h.Name, StringComparer.OrdinalIgnoreCase)));
                Headers(headers);
                if (request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
                (status ? r.StatusToken : r.StartToken).ThrowIfCancellationRequested();
                message.CancellationToken.ThrowIfCancellationRequested();
            }
            string requestHash;
            if (status)
            {
                Require(original is null);
                if (request.Headers.TryGetValue("Content-Length", out var length)) Require(length == "0");
                requestHash = Convert.ToHexString(SHA256.HashData(ReadOnlySpan<byte>.Empty));
            }
            else
            {
                long length = 0;
                Require(original is not null && original.TryComputeLength(out length) && length > 0 && length <= maximumBytes);
                Require(request.Headers.TryGetValue("Content-Type", out var contentType) &&
                    contentType.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase));
                byte[] bytes = new byte[maximumBytes];
                r.Storage.Own(bytes);
                using var output = new MemoryStream(bytes, 0, bytes.Length, true, true);
                await original.WriteToAsync(output, message.CancellationToken).ConfigureAwait(false);
                Require(output.Position == length && ReferenceEquals(request.Content, original));
                if (request.Headers.TryGetValue("Content-Length", out var declared))
                    Require(declared == length.ToString(CultureInfo.InvariantCulture));
                var payload = bytes.AsMemory(0, checked((int)length));
                using var json = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 16 });
                int nodes = 512;
                JsonRows(json.RootElement, ref nodes);
                ValidateNotificationUpdateIndependent(r, json.RootElement, request: true, status: false);
                requestHash = Convert.ToHexString(SHA256.HashData(payload.Span));
                snapshot = RequestContent.Create(payload);
                r.Storage.Own(snapshot);
                r.Storage.Own(original);
                request.Content = snapshot;
            }
            Check();
            if (!status) r.BeforeSend?.Invoke();
            Check();
            Guid dispatch = Guid.NewGuid();
            attempt = new() { Dispatch = dispatch, RequestSha256 = requestHash };
            lock (gate) invocation.Attempts.Add(attempt);
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            Check();
            var response = message.Response;
            var stream = response.ContentStream;
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, r.Storage, allowContinuation: !status)
                .ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(response.ContentStream, stream) && body.Response.Status == (status ? 200 : 201));
            var responseHeaders = body.Response.Headers.ToArray();
            Require(!responseHeaders.Any(h => h.Name.Equals("Retry-After", StringComparison.OrdinalIgnoreCase)) &&
                responseHeaders.Count(h => new[] { "Location", "Azure-AsyncOperation", "Operation-Location" }
                    .Contains(h.Name, StringComparer.OrdinalIgnoreCase)) == (status ? 0 : 1));
            if (!status) Require(responseHeaders.Single(h => h.Name.Equals("Location", StringComparison.OrdinalIgnoreCase)).Value == expectedUri);
            using var document = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int rows = 512;
            JsonRows(document.RootElement, ref rows);
            ValidateNotificationUpdateIndependent(r, document.RootElement, request: false, status);
            var native = ModelReaderWriter.Read<EventGridSubscriptionData>(new BinaryData(body.Bytes));
            Require(native is not null && native.Id?.ToString() == r.Window.Path &&
                native.Name == r.Scope.SubscriptionName && native.ResourceType.ToString() == "Microsoft.EventGrid/eventSubscriptions" &&
                native.Topic == r.Scope.Vault.ExportResourceId() && native.ProvisioningState?.ToString() == (status ? "Succeeded" : "Updating") &&
                native.Labels.SequenceEqual(["secretkit-fixture-" + r.Binding.Selector.Nonce.ToString("N")]) &&
                native.Filter is not null && native.Filter.IncludedEventTypes.SequenceEqual(["Microsoft.KeyVault.SecretNewVersionCreated"]) &&
                native.Destination is WebHookEventSubscriptionDestination webhook &&
                webhook.Endpoint?.OriginalString == r.Configuration.Endpoint.Reveal() && webhook.DeliveryAttributeMappings.Count == 0);
            r.Parsers.Add(OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, r.Storage,
                requireRebuffer: true, requireDownstreamRead: status));
            attempt.HttpStatus = body.Response.Status;
            attempt.ResponseObserved = true;
            attempt.ResponseSha256 = body.Sha256;
            attempt.State = status ? WireState.Succeeded : WireState.Pending;
            attempt.Valid = true;
            attempt.HasProviderContinuation = !status;
            var wire = new StatusVaultCancellationWire(status ? 1 : 0, request, expectedUri, dispatch,
                body.Response.Status, attempt.State, body.Sha256, body.NativeRequestId, true, requestHash,
                Array.AsReadOnly(headers.Select(h => (h.Name, h.Value)).ToArray()));
            lock (gate)
            {
                if (status) r.StatusWire = wire;
                else
                {
                    r.Wire = wire;
                    r.Target = new(r.Binding, dispatch, StatusTargetKind.SelectedResource, new Uri(expectedUri),
                        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(expectedUri))), body.Sha256);
                    r.Candidate = new(r.Binding, dispatch, body.Response.Status, body.Bytes.Length, requestHash, body.Sha256, body.NativeRequestId);
                    r.TransportSucceeded = true;
                }
            }
        }
        catch (OperationCanceledException) { lock (gate) r.Invalid = true; throw; }
        catch { lock (gate) r.Invalid = true; throw new IOException("management-capture-transport"); }
        finally
        {
            message.Request.Content = original;
            lock (gate)
            {
                if (attempt is not null) attempt.TransportTerminated = true;
                invocation.Sending = false;
            }
        }
    }

    private static void ValidateNotificationUpdateIndependent(StatusNotificationUpdateIndependentRegistration r, JsonElement root,
        bool request, bool status)
    {
        var scope = r.Scope;
        var configuration = r.Configuration;
        Require(OnlyApprovalFields(root, request ? ["destination", "filter"] :
            ["id", "name", "type", "properties"]));
        if (!request)
            Require(ApprovalText(root, "id") == r.Window.Path &&
                ApprovalText(root, "name") == scope.SubscriptionName &&
                ApprovalText(root, "type") == "Microsoft.EventGrid/eventSubscriptions");
        var properties = request ? root : root.GetProperty("properties");
        Require(OnlyApprovalFields(properties, request ? ["destination", "filter"] :
            ["topic", "labels", "provisioningState", "destination", "filter"]));
        if (!request)
        {
            Require(ApprovalText(properties, "topic") == scope.Vault.ExportResourceId() &&
                ApprovalText(properties, "provisioningState") == (status ? "Succeeded" : "Updating"));
            var labels = properties.GetProperty("labels");
            Require(labels.ValueKind == JsonValueKind.Array && labels.GetArrayLength() == 1 &&
                labels[0].ValueKind == JsonValueKind.String &&
                labels[0].GetString() == "secretkit-fixture-" + r.Binding.Selector.Nonce.ToString("N"));
        }
        var filter = properties.GetProperty("filter");
        Require(OnlyApprovalFields(filter, "includedEventTypes", "advancedFilters"));
        var events = filter.GetProperty("includedEventTypes");
        Require(events.ValueKind == JsonValueKind.Array && events.GetArrayLength() == 1 &&
            events[0].GetString() == "Microsoft.KeyVault.SecretNewVersionCreated");
        if (filter.TryGetProperty("advancedFilters", out var advanced))
            Require(advanced.ValueKind == JsonValueKind.Array && advanced.GetArrayLength() == 0);
        var destination = properties.GetProperty("destination");
        Require(OnlyApprovalFields(destination, "endpointType", "properties") &&
            ApprovalText(destination, "endpointType") == "WebHook");
        var settings = destination.GetProperty("properties");
        Require(OnlyApprovalFields(settings, request ? ["endpointUrl"] :
            ["endpointUrl", "endpointBaseUrl", "deliveryAttributeMappings"]) &&
            ApprovalText(settings, "endpointUrl") == configuration.Endpoint.Reveal());
        var endpoint = new Uri(configuration.Endpoint.Reveal(), UriKind.Absolute);
        Require(endpoint.Scheme == "https" && endpoint.UserInfo.Length == 0 && endpoint.Fragment.Length == 0);
        if (!request)
        {
            var mappings = settings.GetProperty("deliveryAttributeMappings");
            Require(mappings.ValueKind == JsonValueKind.Array && mappings.GetArrayLength() == 0);
            if (settings.TryGetProperty("endpointBaseUrl", out var endpointBase))
                Require(endpointBase.ValueKind == JsonValueKind.String &&
                    endpointBase.GetString() == endpoint.GetLeftPart(UriPartial.Path));
        }
    }

    internal sealed class StatusNotificationCreateIndependentStartProof(Binding binding, Guid startDispatch,
        int httpStatus, int responseBytes, string requestSha256, string responseSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal Guid StartDispatch { get; } = startDispatch;
        internal int HttpStatus { get; } = httpStatus;
        internal int ResponseBytes { get; } = responseBytes;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        public override string ToString() => "[StatusNotificationCreateIndependentStartProof]";
    }

    internal sealed class StatusNotificationCreateIndependentCompletionProof(StatusNotificationCreateIndependentStartProof start)
    {
        internal StatusNotificationCreateIndependentStartProof Start { get; } = start;
        public override string ToString() => "[StatusNotificationCreateIndependentCompletionProof]";
    }

    private sealed class StatusNotificationCreateIndependentRegistration(Window window, Invocation start,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, CancellationToken token,
        Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly Invocation Start = start;
        internal readonly VaultAdministration Client = client;
        internal readonly NotificationScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken StartToken = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly List<OwnedArmResponse.ParserCustody> Parsers = [];
        internal NotificationConfiguration Configuration = null!;
        internal StatusTarget? Target;
        internal StatusVaultCancellationWire? StatusWire;
        internal int StatusSends;
        internal StatusVaultCancellationWire? Wire;
        internal StatusNotificationCreateIndependentStartProof? Candidate, StartProof;
        internal StatusNotificationCreateIndependentCompletionProof? Completion;
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task<Capture>? SealTask;
        internal Invocation? Status;
        internal ManagementOperation? Handle;
        internal CancellationToken StatusToken;
        internal int Sends;
        internal bool Invalid, Sealed, StartHookReturned, StartSucceeded, TransportSucceeded, StartComplete;
        internal bool CheckClaimed, StatusHookReturned, StatusSucceeded, Complete;
    }

    private readonly Dictionary<Window, StatusNotificationCreateIndependentRegistration> statusNotificationCreateIndependent =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Invocation, StatusNotificationCreateIndependentRegistration> statusNotificationCreateIndependentInvocations =
        new(ReferenceEqualityComparer.Instance);

    internal bool TryGetStatusNotificationCreateIndependentStart(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, [NotNullWhen(true)] out StatusNotificationCreateIndependentStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusNotificationCreateIndependent.TryGetValue(window, out var r) ||
                !NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(binding.Selector) ||
                !ReferenceEquals(r.Binding, binding) || !ReferenceEquals(r.Client, client) ||
                !ReferenceEquals(r.Scope, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.StartTask, startTask) || !ReferenceEquals(r.Handle, handle) ||
                !StatusNotificationCreateIndependentStartValid(r) ||
                receipt.Evidence != DispatchEvidence.Pending ||
                !(handle.State == NativeProvisioningState.Pending || r.Complete && handle.State == NativeProvisioningState.Succeeded) ||
                !ReferenceEquals(targets.GetValueOrDefault(window), r.Target)) return false;
            proof = r.StartProof;
            return proof is not null;
        }
    }

    internal bool TryGetStatusNotificationCreateIndependentCompletion(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task statusTask,
        [NotNullWhen(true)] out StatusNotificationCreateIndependentCompletionProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusNotificationCreateIndependentStart(window, binding, client, scope, receipt,
                    startTask, handle, out _) || !statusNotificationCreateIndependent.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.StatusTask, statusTask) || !r.Complete ||
                !r.Checked.Task.IsCompletedSuccessfully || r.StatusTask is not { IsCompletedSuccessfully: true } ||
                r.StatusToken.IsCancellationRequested) return false;
            proof = r.Completion;
            return proof is not null;
        }
    }

    private static bool StatusNotificationCreateIndependentStartValid(StatusNotificationCreateIndependentRegistration r) =>
        !r.Invalid && !r.Sealed && r.StartComplete && r.StartProof is not null &&
        r.Started.Task.IsCompletedSuccessfully && r.StartTask is { IsCompletedSuccessfully: true } &&
        !r.StartToken.IsCancellationRequested;

    internal async Task<SecretOutcome<ManagementOperation>> StartNotificationCreateIndependentAsync(
        Window window, FixtureSelector selector, VaultAdministration client, ManagementScope scope,
        ManagementOperationEffects.Input input, ManagementReceipt receipt, CancellationToken token = default,
        Action<Task>? retained = null, Action? beforeSend = null)
    {
        StatusNotificationCreateIndependentRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(client is not null && receipt is not null && scope is NotificationScope &&
                NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector) &&
                window.Binding.Operation == ManagementMutation.CreateOrUpdateNotification &&
                window.Binding.ApiRevision == "2025-02-15" && InputMatches(window.Binding, input) &&
                Route(window.Binding with { Resource = scope }) == Route(window.Binding));
            Require(!window.Closed && window.Start is null && startedWindows.Add(window));
            var invocation = window.Start = new();
            r = new(window, invocation, client, (NotificationScope)scope, receipt, token, beforeSend)
            { Configuration = new(input.WebhookUrl, [VaultNotificationEvent.SecretNewVersionCreated], []) };
            statusNotificationCreateIndependent.Add(window, r);
            statusNotificationCreateIndependentInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretOutcome<ManagementOperation>> task;
            var previous = current.Value;
            current.Value = new(window, r.Start, false);
            try { task = ManagementOperationEffects.StartAsync(client, scope, window.Binding.Operation, input, receipt, token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) r.Start.SdkTask = r.StartTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StartHookReturned = true;
            }
            finally
            {
                var result = await task.ConfigureAwait(false);
                lock (gate)
                {
                    r.Start.Outcome = result.Status;
                    r.Handle = result.IsSuccess ? result.Value : null;
                    r.Start.WrapperState = r.Handle?.State;
                    r.StartSucceeded = task.IsCompletedSuccessfully && result.IsSuccess &&
                        r.Handle!.State == NativeProvisioningState.Pending && receipt.Evidence == DispatchEvidence.Pending;
                    r.Start.HasNativeHandle = r.StartSucceeded;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; r.Start.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusNotificationCreateIndependentAsync(r, r.Start).ConfigureAwait(false); }
    }

    private async Task<SecretStatus> CheckStatusNotificationCreateIndependentAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained)
    {
        StatusNotificationCreateIndependentRegistration r;
        Invocation invocation;
        lock (gate)
        {
            Own(window, selector);
            Require(statusNotificationCreateIndependent.TryGetValue(window, out r!) &&
                handle is not null && ReferenceEquals(r.Handle, handle));
            bool valid = !r.CheckClaimed && !window.Closed && window.Status is null &&
                StatusNotificationCreateIndependentStartValid(r) && !token.IsCancellationRequested &&
                handle.State == NativeProvisioningState.Pending && r.Receipt.Evidence == DispatchEvidence.Pending;
            r.CheckClaimed = true;
            r.Invalid |= !valid;
            Require(valid);
            invocation = r.Status = window.Status = new();
            r.StatusToken = token;
            statusNotificationCreateIndependentInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretStatus> task;
            var previous = current.Value;
            current.Value = new(window, invocation, true);
            try { task = handle.CheckStatusAsync(token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) invocation.SdkTask = r.StatusTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StatusHookReturned = true;
            }
            finally
            {
                var outcome = await task.ConfigureAwait(false);
                lock (gate)
                {
                    invocation.Outcome = outcome;
                    invocation.WrapperState = handle.State;
                    r.StatusSucceeded = task.IsCompletedSuccessfully && outcome == SecretStatus.Success &&
                        handle.State == NativeProvisioningState.Succeeded;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; invocation.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusNotificationCreateIndependentAsync(r, invocation).ConfigureAwait(false); }
    }

    private async Task FinishStatusNotificationCreateIndependentAsync(StatusNotificationCreateIndependentRegistration r,
        Invocation invocation)
    {
        bool start = ReferenceEquals(r.Start, invocation);
        Task<Task>? borrower;
        lock (gate)
        {
            Task? actual = start ? r.StartTask : r.StatusTask;
            Require(actual is null || actual.IsCompleted);
            finishing.Add(invocation);
            borrower = borrowers.TryGetValue(invocation, out var pending) ? pending.Task : null;
        }
        if (borrower is not null)
        {
            var actual = await borrower.ConfigureAwait(false);
            try { await actual.ConfigureAwait(false); }
            catch { lock (gate) r.Invalid = true; }
        }
        bool custodyValid, disposalFailed = false;
        try { custodyValid = r.Parsers.Count == (start ? 1 : 2) && r.Parsers.All(p => p.Complete && !p.Invalid); }
        catch { custodyValid = false; }
        if (!start)
        {
            try { r.Storage.Dispose(); }
            catch { disposalFailed = true; }
            try { custodyValid &= r.Parsers.All(p => p.Complete && !p.Invalid); }
            catch { custodyValid = false; }
        }
        lock (gate)
        {
            r.Invalid |= !custodyValid || disposalFailed;
            requestOwners.Remove(invocation);
            requestCandidates.Remove(invocation);
            borrowers.Remove(invocation);
            if (start)
            {
                r.StartComplete = !r.Invalid && r.StartHookReturned && r.StartSucceeded &&
                    r.TransportSucceeded && r.Sends == 1 && r.Candidate is not null &&
                    r.Wire is { Ordinal: 0, HttpStatus: 201, State: WireState.Pending, Complete: true } &&
                    r.Target is { Kind: StatusTargetKind.SelectedResource } &&
                    r.Target.StartDispatch == r.Candidate.StartDispatch &&
                    r.StartTask is { IsCompletedSuccessfully: true } && !r.StartToken.IsCancellationRequested &&
                    r.Handle?.State == NativeProvisioningState.Pending && r.Receipt.Evidence == DispatchEvidence.Pending;
                if (r.StartComplete)
                {
                    r.StartProof = r.Candidate;
                    targets[r.Window] = r.Target;
                    eligible.Add(r.Window);
                }
                r.Started.TrySetResult();
            }
            else
            {
                r.Complete = StatusNotificationCreateIndependentStartValid(r) && r.StatusHookReturned && r.StatusSucceeded &&
                    r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                    r.Receipt.Evidence == DispatchEvidence.Pending && r.Handle?.State == NativeProvisioningState.Succeeded &&
                    r.StatusSends == 1 && r.StatusWire is { Ordinal: 1, HttpStatus: 200, State: WireState.Succeeded, Complete: true } wire &&
                    r.Target is { } target && r.Wire is { } originalWire &&
                    wire.Uri == target.TargetUri.AbsoluteUri && wire.Dispatch != originalWire.Dispatch &&
                    !ReferenceEquals(wire.Request, originalWire.Request);
                if (r.Complete)
                {
                    r.Completion = new(r.StartProof!);
                    completedStatusReads.Add(r.Window);
                }
                r.Checked.TrySetResult();
            }
            invocation.Terminated = true;
            invocation.Drained.TrySetResult();
        }
        if (disposalFailed) throw new InvalidOperationException("management-capture-finalization");
    }

    private Task<Capture> SealStatusNotificationCreateIndependentAsync(Window window)
    {
        StatusNotificationCreateIndependentRegistration r;
        TaskCompletionSource ready;
        Task<Capture> task;
        lock (gate)
        {
            Own(window, window.Binding.Selector);
            r = statusNotificationCreateIndependent[window];
            window.Closed = true;
            if (r.SealTask is not null) return r.SealTask;
            r.Sealed = true;
            ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = r.SealTask = Drain(ready.Task);
        }
        ready.SetResult();
        return task;

        async Task<Capture> Drain(Task admission)
        {
            await admission.ConfigureAwait(false);
            await r.Started.Task.ConfigureAwait(false);
            if (r.Status is not null) await r.Checked.Task.ConfigureAwait(false);
            try { r.Storage.Dispose(); r.Configuration.Dispose(); }
            catch { lock (gate) r.Invalid = true; throw; }
            return new() { Binding = r.Binding, Start = r.Start, Status = r.Status };
        }
    }

    private async Task SendStatusNotificationCreateIndependentAsync(StatusNotificationCreateIndependentRegistration r,
        InvocationContext context, HttpMessage message, TaskCompletionSource<Task> borrower)
    {
        var invocation = context.Invocation;
        bool status = context.Status;
        lock (gate)
        {
            bool valid = !r.Invalid && !r.Sealed && !finishing.Contains(invocation) &&
                ReferenceEquals(invocation, status ? r.Status : r.Start) &&
                (status ? ++r.StatusSends == 1 && r.Target is not null && r.Receipt.Evidence == DispatchEvidence.Pending :
                    ++r.Sends == 1 && r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched) &&
                requestCandidates.TryGetValue(invocation, out var candidates) && candidates.Contains(message.Request);
            r.Invalid |= !valid;
            Require(valid);
            borrowers.Add(invocation, borrower);
            invocation.Sending = true;
            requestOwners.Add(invocation, message.Request);
            requestCandidates.Remove(invocation);
        }
        Attempt? attempt = null;
        RequestContent? original = message.Request.Content;
        RequestContent? snapshot = null;
        try
        {
            var request = message.Request;
            var headers = request.Headers.ToArray();
            string expectedUri = Origin + r.Window.Path + "?api-version=2025-02-15";
            void Check()
            {
                Require(ReferenceEquals(message.Request, request) && headers.SequenceEqual(request.Headers) &&
                    headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                    request.Method == (status ? RequestMethod.Get : RequestMethod.Put) &&
                    ReferenceEquals(request.Content, snapshot) && Trusted(request.Uri.ToUri()) &&
                    request.Uri.ToUri().AbsoluteUri == expectedUri &&
                    (!status || expectedUri == r.Target!.TargetUri.AbsoluteUri) &&
                    request.Headers.TryGetValue("Authorization", out var auth) &&
                    auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
                    !headers.Any(h => new[] { "Content-Encoding", "Transfer-Encoding", "Content-Range", "Range" }
                        .Contains(h.Name, StringComparer.OrdinalIgnoreCase)));
                Headers(headers);
                if (request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
                (status ? r.StatusToken : r.StartToken).ThrowIfCancellationRequested();
                message.CancellationToken.ThrowIfCancellationRequested();
            }
            string requestHash;
            if (status)
            {
                Require(original is null);
                if (request.Headers.TryGetValue("Content-Length", out var length)) Require(length == "0");
                requestHash = Convert.ToHexString(SHA256.HashData(ReadOnlySpan<byte>.Empty));
            }
            else
            {
                long length = 0;
                Require(original is not null && original.TryComputeLength(out length) && length > 0 && length <= maximumBytes);
                Require(request.Headers.TryGetValue("Content-Type", out var contentType) &&
                    contentType.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase));
                byte[] bytes = new byte[maximumBytes];
                r.Storage.Own(bytes);
                using var output = new MemoryStream(bytes, 0, bytes.Length, true, true);
                await original.WriteToAsync(output, message.CancellationToken).ConfigureAwait(false);
                Require(output.Position == length && ReferenceEquals(request.Content, original));
                if (request.Headers.TryGetValue("Content-Length", out var declared))
                    Require(declared == length.ToString(CultureInfo.InvariantCulture));
                var payload = bytes.AsMemory(0, checked((int)length));
                using var json = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 16 });
                int nodes = 512;
                JsonRows(json.RootElement, ref nodes);
                ValidateNotificationCreateIndependent(r, json.RootElement, request: true, status: false);
                requestHash = Convert.ToHexString(SHA256.HashData(payload.Span));
                snapshot = RequestContent.Create(payload);
                r.Storage.Own(snapshot);
                r.Storage.Own(original);
                request.Content = snapshot;
            }
            Check();
            if (!status) r.BeforeSend?.Invoke();
            Check();
            Guid dispatch = Guid.NewGuid();
            attempt = new() { Dispatch = dispatch, RequestSha256 = requestHash };
            lock (gate) invocation.Attempts.Add(attempt);
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            Check();
            var response = message.Response;
            var stream = response.ContentStream;
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, r.Storage, allowContinuation: !status)
                .ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(response.ContentStream, stream) && body.Response.Status == (status ? 200 : 201));
            var responseHeaders = body.Response.Headers.ToArray();
            Require(!responseHeaders.Any(h => h.Name.Equals("Retry-After", StringComparison.OrdinalIgnoreCase)) &&
                responseHeaders.Count(h => new[] { "Location", "Azure-AsyncOperation", "Operation-Location" }
                    .Contains(h.Name, StringComparer.OrdinalIgnoreCase)) == (status ? 0 : 1));
            if (!status) Require(responseHeaders.Single(h => h.Name.Equals("Location", StringComparison.OrdinalIgnoreCase)).Value == expectedUri);
            using var document = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int rows = 512;
            JsonRows(document.RootElement, ref rows);
            ValidateNotificationCreateIndependent(r, document.RootElement, request: false, status);
            var native = ModelReaderWriter.Read<EventGridSubscriptionData>(new BinaryData(body.Bytes));
            Require(native is not null && native.Id?.ToString() == r.Window.Path &&
                native.Name == r.Scope.SubscriptionName && native.ResourceType.ToString() == "Microsoft.EventGrid/eventSubscriptions" &&
                native.Topic == r.Scope.Vault.ExportResourceId() && native.ProvisioningState?.ToString() == (status ? "Succeeded" : "Updating") &&
                native.Labels.SequenceEqual(["secretkit-fixture-" + r.Binding.Selector.Nonce.ToString("N")]) &&
                native.Filter is not null && native.Filter.IncludedEventTypes.SequenceEqual(["Microsoft.KeyVault.SecretNewVersionCreated"]) &&
                native.Destination is WebHookEventSubscriptionDestination webhook &&
                webhook.Endpoint?.OriginalString == r.Configuration.Endpoint.Reveal() && webhook.DeliveryAttributeMappings.Count == 0);
            r.Parsers.Add(OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, r.Storage,
                requireRebuffer: true, requireDownstreamRead: status));
            attempt.HttpStatus = body.Response.Status;
            attempt.ResponseObserved = true;
            attempt.ResponseSha256 = body.Sha256;
            attempt.State = status ? WireState.Succeeded : WireState.Pending;
            attempt.Valid = true;
            attempt.HasProviderContinuation = !status;
            var wire = new StatusVaultCancellationWire(status ? 1 : 0, request, expectedUri, dispatch,
                body.Response.Status, attempt.State, body.Sha256, body.NativeRequestId, true, requestHash,
                Array.AsReadOnly(headers.Select(h => (h.Name, h.Value)).ToArray()));
            lock (gate)
            {
                if (status) r.StatusWire = wire;
                else
                {
                    r.Wire = wire;
                    r.Target = new(r.Binding, dispatch, StatusTargetKind.SelectedResource, new Uri(expectedUri),
                        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(expectedUri))), body.Sha256);
                    r.Candidate = new(r.Binding, dispatch, body.Response.Status, body.Bytes.Length, requestHash, body.Sha256, body.NativeRequestId);
                    r.TransportSucceeded = true;
                }
            }
        }
        catch (OperationCanceledException) { lock (gate) r.Invalid = true; throw; }
        catch { lock (gate) r.Invalid = true; throw new IOException("management-capture-transport"); }
        finally
        {
            message.Request.Content = original;
            lock (gate)
            {
                if (attempt is not null) attempt.TransportTerminated = true;
                invocation.Sending = false;
            }
        }
    }

    private static void ValidateNotificationCreateIndependent(StatusNotificationCreateIndependentRegistration r, JsonElement root,
        bool request, bool status)
    {
        var scope = r.Scope;
        var configuration = r.Configuration;
        Require(OnlyApprovalFields(root, request ? ["properties"] :
            ["id", "name", "type", "properties"]));
        if (!request)
            Require(ApprovalText(root, "id") == r.Window.Path &&
                ApprovalText(root, "name") == scope.SubscriptionName &&
                ApprovalText(root, "type") == "Microsoft.EventGrid/eventSubscriptions");
        var properties = root.GetProperty("properties");
        Require(OnlyApprovalFields(properties, request ? ["destination", "filter"] :
            ["topic", "labels", "provisioningState", "destination", "filter"]));
        if (!request)
        {
            Require(ApprovalText(properties, "topic") == scope.Vault.ExportResourceId() &&
                ApprovalText(properties, "provisioningState") == (status ? "Succeeded" : "Updating"));
            var labels = properties.GetProperty("labels");
            Require(labels.ValueKind == JsonValueKind.Array && labels.GetArrayLength() == 1 &&
                labels[0].ValueKind == JsonValueKind.String &&
                labels[0].GetString() == "secretkit-fixture-" + r.Binding.Selector.Nonce.ToString("N"));
        }
        var filter = properties.GetProperty("filter");
        Require(OnlyApprovalFields(filter, "includedEventTypes", "advancedFilters"));
        var events = filter.GetProperty("includedEventTypes");
        Require(events.ValueKind == JsonValueKind.Array && events.GetArrayLength() == 1 &&
            events[0].GetString() == "Microsoft.KeyVault.SecretNewVersionCreated");
        if (filter.TryGetProperty("advancedFilters", out var advanced))
            Require(advanced.ValueKind == JsonValueKind.Array && advanced.GetArrayLength() == 0);
        var destination = properties.GetProperty("destination");
        Require(OnlyApprovalFields(destination, "endpointType", "properties") &&
            ApprovalText(destination, "endpointType") == "WebHook");
        var settings = destination.GetProperty("properties");
        Require(OnlyApprovalFields(settings, request ? ["endpointUrl"] :
            ["endpointUrl", "endpointBaseUrl", "deliveryAttributeMappings"]) &&
            ApprovalText(settings, "endpointUrl") == configuration.Endpoint.Reveal());
        var endpoint = new Uri(configuration.Endpoint.Reveal(), UriKind.Absolute);
        Require(endpoint.Scheme == "https" && endpoint.UserInfo.Length == 0 && endpoint.Fragment.Length == 0);
        if (!request)
        {
            var mappings = settings.GetProperty("deliveryAttributeMappings");
            Require(mappings.ValueKind == JsonValueKind.Array && mappings.GetArrayLength() == 0);
            if (settings.TryGetProperty("endpointBaseUrl", out var endpointBase))
                Require(endpointBase.ValueKind == JsonValueKind.String &&
                    endpointBase.GetString() == endpoint.GetLeftPart(UriPartial.Path));
        }
    }

    private sealed class StatusNotificationDeleteIndependentRegistration(Window window, Invocation start,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, CancellationToken token,
        Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly Invocation Start = start;
        internal readonly VaultAdministration Client = client;
        internal readonly NotificationScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken StartToken = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal EmptyNotificationResponseCustody? Custody;
        internal StatusVaultCancellationWire? Wire;
        internal StatusNotificationDeleteIndependentStartProof? Candidate, StartProof;
        internal StatusNotificationDeleteIndependentCompletionProof? Completion;
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task<Capture>? SealTask;
        internal Invocation? Status;
        internal ManagementOperation? Handle;
        internal CancellationToken StatusToken;
        internal int Sends;
        internal bool Invalid, Sealed, StartHookReturned, StartSucceeded, TransportSucceeded, StartComplete;
        internal bool CheckClaimed, StatusHookReturned, StatusSucceeded, Complete;
    }

    private readonly Dictionary<Window, StatusNotificationDeleteIndependentRegistration> statusNotificationDeleteIndependent =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Invocation, StatusNotificationDeleteIndependentRegistration> statusNotificationDeleteIndependentInvocations =
        new(ReferenceEqualityComparer.Instance);

    internal bool TryGetStatusNotificationDeleteIndependentStart(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, [NotNullWhen(true)] out StatusNotificationDeleteIndependentStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusNotificationDeleteIndependent.TryGetValue(window, out var r) ||
                !NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(binding.Selector) ||
                !ReferenceEquals(r.Binding, binding) || !ReferenceEquals(r.Client, client) ||
                !ReferenceEquals(r.Scope, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.StartTask, startTask) || !ReferenceEquals(r.Handle, handle) ||
                !StatusNotificationDeleteIndependentStartValid(r) ||
                receipt.Evidence != DispatchEvidence.Applied || handle.State != NativeProvisioningState.Succeeded ||
                targets.GetValueOrDefault(window) is not null || completedStatusReads.Contains(window)) return false;
            proof = r.StartProof;
            return proof is not null;
        }
    }

    internal bool TryGetStatusNotificationDeleteIndependentCompletion(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task statusTask,
        [NotNullWhen(true)] out StatusNotificationDeleteIndependentCompletionProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusNotificationDeleteIndependentStart(window, binding, client, scope, receipt,
                    startTask, handle, out _) || !statusNotificationDeleteIndependent.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.StatusTask, statusTask) || !r.Complete ||
                !r.Checked.Task.IsCompletedSuccessfully || r.StatusTask is not { IsCompletedSuccessfully: true } ||
                r.StatusToken.IsCancellationRequested) return false;
            proof = r.Completion;
            return proof is not null;
        }
    }

    private static bool StatusNotificationDeleteIndependentStartValid(StatusNotificationDeleteIndependentRegistration r) =>
        !r.Invalid && !r.Sealed && r.StartComplete && r.StartProof is not null &&
        r.Started.Task.IsCompletedSuccessfully && r.StartTask is { IsCompletedSuccessfully: true } &&
        !r.StartToken.IsCancellationRequested;

    internal sealed class StatusRoleDeleteIndependentStartProof(Binding binding, Guid startDispatch,
        int httpStatus, string responseSha256)
    {
        internal Binding Binding { get; } = binding;
        internal Guid StartDispatch { get; } = startDispatch;
        internal int HttpStatus { get; } = httpStatus;
        internal int ResponseBytes => 0;
        internal string ResponseSha256 { get; } = responseSha256;
        public override string ToString() => "[StatusRoleDeleteIndependentStartProof]";
    }

    internal sealed class StatusRoleDeleteIndependentCompletionProof(StatusRoleDeleteIndependentStartProof start)
    {
        internal StatusRoleDeleteIndependentStartProof Start { get; } = start;
        public override string ToString() => "[StatusRoleDeleteIndependentCompletionProof]";
    }

    private sealed class StatusRoleDeleteIndependentRegistration(Window window, Invocation start,
        VaultAdministration client, RoleAssignmentScope scope, ManagementReceipt receipt, CancellationToken token,
        Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly Invocation Start = start;
        internal readonly VaultAdministration Client = client;
        internal readonly RoleAssignmentScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken StartToken = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal EmptyNotificationResponseCustody? Custody;
        internal StatusVaultCancellationWire? Wire;
        internal StatusRoleDeleteIndependentStartProof? Candidate, StartProof;
        internal StatusRoleDeleteIndependentCompletionProof? Completion;
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task<Capture>? SealTask;
        internal Invocation? Status;
        internal ManagementOperation? Handle;
        internal CancellationToken StatusToken;
        internal int Sends;
        internal bool Invalid, Sealed, StartHookReturned, StartSucceeded, TransportSucceeded, StartComplete;
        internal bool CheckClaimed, StatusHookReturned, StatusSucceeded, Complete;
    }

    private readonly Dictionary<Window, StatusRoleDeleteIndependentRegistration> statusRoleDeleteIndependent =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Invocation, StatusRoleDeleteIndependentRegistration> statusRoleDeleteIndependentInvocations =
        new(ReferenceEqualityComparer.Instance);

    internal bool TryGetStatusRoleDeleteIndependentStart(Window window, Binding binding,
        VaultAdministration client, RoleAssignmentScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, [NotNullWhen(true)] out StatusRoleDeleteIndependentStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusRoleDeleteIndependent.TryGetValue(window, out var r) ||
                !RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(binding.Selector) ||
                !ReferenceEquals(r.Binding, binding) || !ReferenceEquals(r.Client, client) ||
                !ReferenceEquals(r.Scope, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.StartTask, startTask) || !ReferenceEquals(r.Handle, handle) ||
                !StatusRoleDeleteIndependentStartValid(r) ||
                receipt.Evidence != DispatchEvidence.Applied || handle.State != NativeProvisioningState.Succeeded ||
                targets.GetValueOrDefault(window) is not null || completedStatusReads.Contains(window)) return false;
            proof = r.StartProof;
            return proof is not null;
        }
    }

    internal bool TryGetStatusRoleDeleteIndependentCompletion(Window window, Binding binding,
        VaultAdministration client, RoleAssignmentScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task statusTask,
        [NotNullWhen(true)] out StatusRoleDeleteIndependentCompletionProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusRoleDeleteIndependentStart(window, binding, client, scope, receipt,
                    startTask, handle, out _) || !statusRoleDeleteIndependent.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.StatusTask, statusTask) || !r.Complete ||
                !r.Checked.Task.IsCompletedSuccessfully || r.StatusTask is not { IsCompletedSuccessfully: true } ||
                r.StatusToken.IsCancellationRequested) return false;
            proof = r.Completion;
            return proof is not null;
        }
    }

    private static bool StatusRoleDeleteIndependentStartValid(StatusRoleDeleteIndependentRegistration r) =>
        !r.Invalid && !r.Sealed && r.StartComplete && r.StartProof is not null &&
        r.Started.Task.IsCompletedSuccessfully && r.StartTask is { IsCompletedSuccessfully: true } &&
        !r.StartToken.IsCancellationRequested;

    internal async Task<SecretOutcome<ManagementOperation>> StartRoleDeleteIndependentAsync(
        Window window, FixtureSelector selector, VaultAdministration client, RoleAssignmentScope scope,
        ManagementOperationEffects.Input input, ManagementReceipt receipt, CancellationToken token = default,
        Action<Task>? retained = null, Action? beforeSend = null)
    {
        StatusRoleDeleteIndependentRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(client is not null && receipt is not null && scope is { Parent: VaultScope } &&
                RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(selector) &&
                window.Binding.Operation == ManagementMutation.DeleteRoleAssignment &&
                window.Binding.ApiRevision == "2022-04-01" && InputMatches(window.Binding, input) &&
                Route(window.Binding with { Resource = scope }) == Route(window.Binding));
            Require(!window.Closed && window.Start is null && startedWindows.Add(window));
            var invocation = window.Start = new();
            r = new(window, invocation, client, (RoleAssignmentScope)scope, receipt, token, beforeSend);
            statusRoleDeleteIndependent.Add(window, r);
            statusRoleDeleteIndependentInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretOutcome<ManagementOperation>> task;
            var previous = current.Value;
            current.Value = new(window, r.Start, false);
            try { task = ManagementOperationEffects.StartAsync(client, scope, window.Binding.Operation, input, receipt, token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) r.Start.SdkTask = r.StartTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StartHookReturned = true;
            }
            finally
            {
                var result = await task.ConfigureAwait(false);
                lock (gate)
                {
                    r.Start.Outcome = result.Status;
                    r.Handle = result.IsSuccess ? result.Value : null;
                    r.Start.WrapperState = r.Handle?.State;
                    r.StartSucceeded = task.IsCompletedSuccessfully && result.IsSuccess &&
                        r.Handle!.State == NativeProvisioningState.Succeeded && receipt.Evidence == DispatchEvidence.Applied;
                    r.Start.HasNativeHandle = r.StartSucceeded;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; r.Start.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusRoleDeleteIndependentAsync(r, r.Start).ConfigureAwait(false); }
    }

    private async Task<SecretStatus> CheckStatusRoleDeleteIndependentAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained)
    {
        StatusRoleDeleteIndependentRegistration r;
        Invocation invocation;
        lock (gate)
        {
            Own(window, selector);
            Require(statusRoleDeleteIndependent.TryGetValue(window, out r!) &&
                handle is not null && ReferenceEquals(r.Handle, handle));
            bool valid = !r.CheckClaimed && !window.Closed && window.Status is null &&
                StatusRoleDeleteIndependentStartValid(r) && !token.IsCancellationRequested &&
                handle.State == NativeProvisioningState.Succeeded && r.Receipt.Evidence == DispatchEvidence.Applied;
            r.CheckClaimed = true;
            r.Invalid |= !valid;
            Require(valid);
            invocation = r.Status = window.Status = new();
            r.StatusToken = token;
            statusRoleDeleteIndependentInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretStatus> task;
            var previous = current.Value;
            current.Value = new(window, invocation, true);
            try { task = handle.CheckStatusAsync(token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) invocation.SdkTask = r.StatusTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StatusHookReturned = true;
            }
            finally
            {
                var outcome = await task.ConfigureAwait(false);
                lock (gate)
                {
                    invocation.Outcome = outcome;
                    invocation.WrapperState = handle.State;
                    r.StatusSucceeded = task.IsCompletedSuccessfully && outcome == SecretStatus.Success &&
                        handle.State == NativeProvisioningState.Succeeded;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; invocation.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusRoleDeleteIndependentAsync(r, invocation).ConfigureAwait(false); }
    }

    private async Task FinishStatusRoleDeleteIndependentAsync(StatusRoleDeleteIndependentRegistration r,
        Invocation invocation)
    {
        bool start = ReferenceEquals(r.Start, invocation);
        Task<Task>? borrower;
        lock (gate)
        {
            Task? actual = start ? r.StartTask : r.StatusTask;
            Require(actual is null || actual.IsCompleted);
            finishing.Add(invocation);
            borrower = borrowers.TryGetValue(invocation, out var pending) ? pending.Task : null;
        }
        if (borrower is not null)
        {
            var actual = await borrower.ConfigureAwait(false);
            try { await actual.ConfigureAwait(false); }
            catch { lock (gate) r.Invalid = true; }
        }
        bool custodyValid = true, disposalFailed = false;
        if (start)
        {
            try { custodyValid = r.Custody is { Complete: true }; }
            catch { custodyValid = false; }
            try { r.Storage.Dispose(); }
            catch { disposalFailed = true; }
        }
        lock (gate)
        {
            r.Invalid |= !custodyValid || disposalFailed;
            requestOwners.Remove(invocation);
            requestCandidates.Remove(invocation);
            borrowers.Remove(invocation);
            if (start)
            {
                r.StartComplete = !r.Invalid && r.StartHookReturned && r.StartSucceeded &&
                    r.TransportSucceeded && r.Sends == 1 && r.Candidate is not null &&
                    r.Wire is
                    {
                        Ordinal: 0, HttpStatus: 204, State: WireState.Succeeded, Complete: true,
                        RequestSha256.Length: 64, RequestHeaders: not null
                    } &&
                    r.Wire.Dispatch == r.Candidate.StartDispatch &&
                    r.StartTask is { IsCompletedSuccessfully: true } && !r.StartToken.IsCancellationRequested &&
                    r.Handle?.State == NativeProvisioningState.Succeeded && r.Receipt.Evidence == DispatchEvidence.Applied;
                if (r.StartComplete) r.StartProof = r.Candidate;
                r.Started.TrySetResult();
            }
            else
            {
                r.Complete = StatusRoleDeleteIndependentStartValid(r) && r.StatusHookReturned && r.StatusSucceeded &&
                    r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                    r.Receipt.Evidence == DispatchEvidence.Applied && r.Handle?.State == NativeProvisioningState.Succeeded &&
                    !requestFactories.Contains(invocation) && r.Status!.Attempts.Count == 0 &&
                    targets.GetValueOrDefault(r.Window) is null && !completedStatusReads.Contains(r.Window);
                if (r.Complete) r.Completion = new(r.StartProof!);
                r.Checked.TrySetResult();
            }
            invocation.Terminated = true;
            invocation.Drained.TrySetResult();
        }
        if (disposalFailed) throw new InvalidOperationException("management-capture-finalization");
    }

    private Task<Capture> SealStatusRoleDeleteIndependentAsync(Window window)
    {
        StatusRoleDeleteIndependentRegistration r;
        TaskCompletionSource ready;
        Task<Capture> task;
        lock (gate)
        {
            Own(window, window.Binding.Selector);
            r = statusRoleDeleteIndependent[window];
            window.Closed = true;
            if (r.SealTask is not null) return r.SealTask;
            r.Sealed = true;
            ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = r.SealTask = Drain(ready.Task);
        }
        ready.SetResult();
        return task;

        async Task<Capture> Drain(Task admission)
        {
            await admission.ConfigureAwait(false);
            await r.Started.Task.ConfigureAwait(false);
            if (r.Status is not null) await r.Checked.Task.ConfigureAwait(false);
            try { r.Storage.Dispose(); }
            catch { lock (gate) r.Invalid = true; throw; }
            return new() { Binding = r.Binding, Start = r.Start, Status = r.Status };
        }
    }

    private async Task SendStatusRoleDeleteIndependentAsync(StatusRoleDeleteIndependentRegistration r,
        InvocationContext context, HttpMessage message, TaskCompletionSource<Task> borrower)
    {
        var invocation = context.Invocation;
        lock (gate)
        {
            bool valid = !context.Status && ReferenceEquals(invocation, r.Start) && !r.Invalid && !r.Sealed &&
                !finishing.Contains(invocation) && ++r.Sends == 1 &&
                r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched &&
                requestCandidates.TryGetValue(invocation, out var candidates) && candidates.Contains(message.Request);
            r.Invalid |= !valid;
            Require(valid);
            borrowers.Add(invocation, borrower);
            invocation.Sending = true;
            requestOwners.Add(invocation, message.Request);
            requestCandidates.Remove(invocation);
        }
        Attempt? attempt = null;
        try
        {
            var request = message.Request;
            var headers = request.Headers.ToArray();
            var uri = request.Uri.ToUri();
            void CheckRequest()
            {
                Require(ReferenceEquals(message.Request, request) && headers.SequenceEqual(request.Headers) &&
                    headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                    request.Method == RequestMethod.Delete && request.Content is null &&
                    Trusted(request.Uri.ToUri()) && request.Uri.ToUri().AbsoluteUri == uri.AbsoluteUri &&
                    uri.AbsolutePath == r.Window.Path && uri.Query == "?api-version=2022-04-01" &&
                    !headers.Any(h => new[] { "Content-Encoding", "Transfer-Encoding", "Content-Range", "Range" }
                        .Contains(h.Name, StringComparer.OrdinalIgnoreCase)) &&
                    request.Headers.TryGetValue("Authorization", out var auth) &&
                    auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7);
                Headers(headers);
                var lengths = headers.Where(h => h.Name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)).ToArray();
                Require(lengths.Length == 0 || lengths is [{ Value: "0" }]);
                if (request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
                r.StartToken.ThrowIfCancellationRequested();
                message.CancellationToken.ThrowIfCancellationRequested();
            }
            CheckRequest();
            string hash = Convert.ToHexString(SHA256.HashData(ReadOnlySpan<byte>.Empty));
            Guid dispatch = Guid.NewGuid();
            attempt = new() { Dispatch = dispatch, RequestSha256 = hash };
            lock (gate) invocation.Attempts.Add(attempt);
            message.BufferResponse = false;
            r.BeforeSend?.Invoke();
            CheckRequest();
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            CheckRequest();
            var original = message.Response;
            var stream = original.ContentStream;
            int status = original.Status;
            string reason = original.ReasonPhrase, clientId = original.ClientRequestId;
            var responseHeaders = original.Headers.Take(33).ToArray();
            Headers(responseHeaders);
            attempt.HttpStatus = status;
            attempt.ResponseObserved = true;
            if (stream is not null)
            {
                r.Storage.Own(stream);
                byte[] one = new byte[1];
                try { Require(await stream.ReadAsync(one, message.CancellationToken).ConfigureAwait(false) == 0); }
                finally { CryptographicOperations.ZeroMemory(one); }
            }
            CheckRequest();
            Require(ReferenceEquals(message.Response, original) && ReferenceEquals(original.ContentStream, stream) &&
                original.Status == status && original.ReasonPhrase == reason && original.ClientRequestId == clientId &&
                responseHeaders.SequenceEqual(original.Headers) && reason.Length <= 256 && !reason.Any(char.IsControl) &&
                clientId.Length <= 1024 && !clientId.Any(char.IsControl) &&
                EmptyDeleteResponse(status, 0, responseHeaders, allow200: false));
            var buffer = new MemoryStream([], writable: false);
            r.Storage.Own(buffer);
            var owned = new OwnedArmResponse(status, reason, clientId, responseHeaders, buffer);
            r.Custody = new(message, original, stream, owned, r.Storage);
            attempt.ResponseSha256 = hash;
            attempt.State = WireState.Succeeded;
            attempt.Valid = true;
            lock (gate)
            {
                r.Wire = new(0, request, uri.AbsoluteUri, dispatch, status, WireState.Succeeded, hash,
                    responseHeaders.FirstOrDefault(h => h.Name.Equals("x-ms-request-id", StringComparison.OrdinalIgnoreCase)).Value ?? "",
                    true, hash, Array.AsReadOnly(headers.Select(h => (h.Name, h.Value)).ToArray()));
                r.Candidate = new(r.Binding, dispatch, status, hash);
                r.TransportSucceeded = true;
            }
        }
        catch (OperationCanceledException)
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw new IOException("management-capture-transport");
        }
        finally
        {
            lock (gate)
            {
                if (attempt is not null) attempt.TransportTerminated = true;
                invocation.Sending = false;
            }
        }
    }

    internal sealed class StatusRoleDeleteCancellationStartProof(Binding binding, Guid startDispatch,
        int httpStatus, string responseSha256)
    {
        internal Binding Binding { get; } = binding;
        internal Guid StartDispatch { get; } = startDispatch;
        internal int HttpStatus { get; } = httpStatus;
        internal int ResponseBytes => 0;
        internal string ResponseSha256 { get; } = responseSha256;
        public override string ToString() => "[StatusRoleDeleteCancellationStartProof]";
    }

    // Empty DELETE has adapter consumption but no downstream model/parser read.
    // Keep that contract local: nonempty OwnedArmResponse custody stays unchanged.
    private sealed class EmptyNotificationResponseCustody
    {
        private readonly HttpMessage message;
        private readonly Azure.Response original;
        private readonly OwnedArmResponse response;
        private readonly OwnedArmResponse.Storage storage;
        private readonly Azure.Core.HttpHeader[] headers;
        private readonly int status;
        private readonly string reason, clientRequestId;
        private readonly Stream? originalStream;
        private readonly EmptyStream initial;
        private readonly Envelope envelope;
        private MemoryStream? rebuffer;
        private bool invalid;

        internal EmptyNotificationResponseCustody(HttpMessage message, Azure.Response original,
            Stream? originalStream, OwnedArmResponse response, OwnedArmResponse.Storage storage)
        {
            this.message = message;
            this.original = original;
            this.response = response;
            this.storage = storage;
            status = response.Status;
            reason = response.ReasonPhrase;
            clientRequestId = response.ClientRequestId;
            this.originalStream = originalStream;
            headers = response.Headers.ToArray();
            initial = new(Check);
            storage.Own(initial);
            envelope = new(this);
            message.Response = envelope;
        }

        private void Check()
        {
            // HttpMessage detaches its response before native disposal. As with
            // nonempty custody, inspect identity only while the message owns it.
            if (message.HasResponse && !ReferenceEquals(message.Response, envelope) || original.Status != status ||
                original.ReasonPhrase != reason || original.ClientRequestId != clientRequestId ||
                !headers.SequenceEqual(original.Headers) ||
                !ReferenceEquals(original.ContentStream, originalStream))
                invalid = true;
            if (rebuffer is not null && (!rebuffer.CanRead || !rebuffer.CanSeek ||
                rebuffer.Length != 0 || rebuffer.Position != 0))
                invalid = true;
        }
        internal bool Complete
        {
            get { Check(); return !invalid && initial.Eof && rebuffer is not null; }
        }
        private void Rebuffer(Stream? value)
        {
            Check();
            if (!initial.Eof || value is not MemoryStream buffer || !buffer.CanRead ||
                !buffer.CanSeek || buffer.Position != 0 || buffer.Length != 0 || buffer.ToArray().Length != 0)
            {
                invalid = true;
                return;
            }
            storage.Own(buffer);
            rebuffer = buffer;
        }
        private sealed class Envelope(EmptyNotificationResponseCustody custody) : Azure.Response
        {
            public override BinaryData Content
            {
                get { custody.Check(); return BinaryData.FromBytes(ReadOnlyMemory<byte>.Empty); }
            }
            public override int Status { get { custody.Check(); return custody.response.Status; } }
            public override string ReasonPhrase { get { custody.Check(); return custody.response.ReasonPhrase; } }
            public override string ClientRequestId
            {
                get { custody.Check(); return custody.response.ClientRequestId; }
                set { custody.Check(); if (value != custody.clientRequestId) custody.invalid = true; }
            }
            public override Stream? ContentStream
            {
                get { custody.Check(); return custody.initial; }
                set => custody.Rebuffer(value);
            }
            public override void Dispose() => custody.Check();
            protected override bool ContainsHeader(string name)
            { custody.Check(); return custody.response.Headers.Contains(name); }
            protected override IEnumerable<Azure.Core.HttpHeader> EnumerateHeaders()
            { custody.Check(); return custody.response.Headers.ToArray(); }
            protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value)
            { custody.Check(); return custody.response.Headers.TryGetValue(name, out value); }
            protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values)
            { custody.Check(); return custody.response.Headers.TryGetValues(name, out values); }
        }
        private sealed class EmptyStream(Action check) : Stream
        {
            internal bool Eof { get; private set; }
            public override bool CanRead => true;
            // Match nonempty custody's seekable accounting stream. Otherwise
            // the native timeout policy substitutes its own stream before the
            // adapter can perform the exact rebuffer we are measuring.
            public override bool CanSeek => true;
            public override bool CanWrite => false;
            public override long Length => 0;
            public override long Position
            {
                get { check(); return 0; }
                set { check(); if (value != 0) throw new ArgumentOutOfRangeException(nameof(value)); }
            }
            public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
            public override int Read(Span<byte> buffer)
            { check(); if (buffer.Length != 0) Eof = true; return 0; }
            public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            { cancellationToken.ThrowIfCancellationRequested(); return ValueTask.FromResult(Read(buffer.Span)); }
            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
                ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
            public override void Flush() => check();
            public override long Seek(long offset, SeekOrigin origin)
            {
                if (origin is not (SeekOrigin.Begin or SeekOrigin.Current or SeekOrigin.End))
                    throw new ArgumentOutOfRangeException(nameof(origin));
                Position = offset;
                return 0;
            }
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            protected override void Dispose(bool disposing) { }
        }
    }

    // Only this source writes these facts. Invocation, Window and Attempt remain
    // diagnostics, not authority to manufacture or complete a capability.
    private enum SynchronousDeleteProfile { Notification, RoleAssignment }

    internal sealed class PrivateApprovalResponseProof(string endpointId)
    {
        [JsonIgnore] internal string EndpointId { get; } = endpointId;
        public override string ToString() => "[PrivateApprovalResponseProof]";
    }

    internal sealed class StatusPrivateConnectionUpdateIndependentStartProof(Binding binding, Guid dispatch,
        ManagementOperationResourceCollector.StatusPrivateConnectionFacts facts, string requestSha256,
        string responseSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal Guid Dispatch { get; } = dispatch;
        internal ManagementOperationResourceCollector.StatusPrivateConnectionFacts Facts { get; } = facts;
        internal string EndpointId => Facts.EndpointId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        public override string ToString() => "[StatusPrivateConnectionUpdateIndependentStartProof]";
    }
    internal sealed class StatusPrivateConnectionUpdateIndependentCompletionProof(StatusPrivateConnectionUpdateIndependentStartProof start)
    {
        internal StatusPrivateConnectionUpdateIndependentStartProof Start { get; } = start;
        public override string ToString() => "[StatusPrivateConnectionUpdateIndependentCompletionProof]";
    }
    private sealed class StatusPrivateUpdateIndependentRegistration(Window window, VaultAdministration client,
        PrivateConnectionScope scope, ManagementReceipt receipt, CancellationToken token, CancellationToken caller, Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly VaultAdministration Client = client;
        internal readonly PrivateConnectionScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken Token = token, Caller = caller;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly Invocation Start = window.Start!;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly HashSet<Request> Requests = new(ReferenceEqualityComparer.Instance);
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task? SendTask;
        internal Task<Capture>? SealTask;
        internal OwnedArmResponse.ParserCustody? Parser;
        internal ManagementOperation? Handle;
        internal Invocation? Status;
        internal StatusPrivateConnectionUpdateIndependentStartProof? Candidate, StartProof;
        internal StatusPrivateConnectionUpdateIndependentCompletionProof? Completion;
        internal CancellationToken CheckToken, CheckCaller;
        internal bool Invalid, Sealed, StartHook, StartSuccess, CheckClaimed, CheckHook, CheckSuccess, FactoryClaimed;
        internal int Sends, CheckFactories;
    }
    private sealed record StatusPrivateUpdateIndependentContext(StatusPrivateUpdateIndependentRegistration Registration, bool Check);
    private readonly AsyncLocal<StatusPrivateUpdateIndependentContext?> currentStatusPrivateUpdateIndependent = new();
    private readonly Dictionary<Window, StatusPrivateUpdateIndependentRegistration> statusPrivateUpdateIndependent =
        new(ReferenceEqualityComparer.Instance);

    internal async Task<SecretOutcome<ManagementOperation>> StartPrivateConnectionUpdateIndependentAsync(Window window,
        FixtureSelector selector, VaultAdministration client, ManagementScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token = default, Action<Task>? retained = null, Action? beforeSend = null,
        CancellationToken? originalCallerToken = null)
    {
        StatusPrivateUpdateIndependentRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(selector) &&
                ReferenceEquals(window.Binding.Resource, scope) && scope is PrivateConnectionScope && client is not null && receipt is not null);
            Require(!window.Closed && window.Start is null && startedWindows.Add(window));
            Require(window.Binding.Operation == ManagementMutation.UpdatePrivateConnection && window.Binding.ApiRevision == "2026-02-01" &&
                InputMatches(window.Binding, input));
            window.Start = new();
            r = new(window, client, (PrivateConnectionScope)scope, receipt, token, originalCallerToken ?? token, beforeSend);
            statusPrivateUpdateIndependent.Add(window, r);
        }
        try
        {
            r.Token.ThrowIfCancellationRequested();
            r.Caller.ThrowIfCancellationRequested();
            var previous = currentStatusPrivateUpdateIndependent.Value;
            currentStatusPrivateUpdateIndependent.Value = new(r, false);
            try
            {
                r.StartTask = ManagementOperationEffects.StartAsync(client, scope, ManagementMutation.UpdatePrivateConnection,
                    input, receipt, token).AsTask();
                r.Start.SdkTask = r.StartTask;
            }
            finally { currentStatusPrivateUpdateIndependent.Value = previous; }
            try { retained?.Invoke(r.StartTask); r.StartHook = true; }
            finally
            {
                var result = await r.StartTask.ConfigureAwait(false);
                r.Handle = result.IsSuccess ? result.Value : null;
                r.StartSuccess = result.IsSuccess && r.Handle!.State == NativeProvisioningState.Succeeded && receipt.Evidence == DispatchEvidence.Applied;
                r.Start.Outcome = result.Status;
                r.Start.WrapperState = r.Handle?.State;
                r.Start.HasNativeHandle = r.Handle is not null;
            }
            return await r.StartTask.ConfigureAwait(false);
        }
        catch { r.Invalid = true; throw; }
        finally
        {
            if (r.StartTask is not null) try { await r.StartTask.ConfigureAwait(false); } catch { r.Invalid = true; }
            if (r.SendTask is not null) try { await r.SendTask.ConfigureAwait(false); } catch { r.Invalid = true; }
            bool custody = r.Parser is { Complete: true, Invalid: false };
            try { r.Storage.Dispose(); } catch { r.Invalid = true; }
            lock (gate)
            {
                r.Invalid |= !custody || r.Parser is not { Complete: true, Invalid: false };
                if (!r.Invalid && !r.Sealed && r.StartHook && r.StartSuccess && r.Sends == 1 && r.Candidate is not null &&
                    !r.Token.IsCancellationRequested && !r.Caller.IsCancellationRequested && r.StartTask is { IsCompletedSuccessfully: true })
                { r.StartProof = r.Candidate; targets[window] = null; eligible.Add(window); }
                r.Start.Terminated = true;
                r.Start.Drained.TrySetResult();
                r.Started.TrySetResult();
            }
        }
    }
    internal bool TryGetStatusPrivateConnectionUpdateIndependentStart(Window window, Binding binding, VaultAdministration client,
        PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        [NotNullWhen(true)] out StatusPrivateConnectionUpdateIndependentStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusPrivateUpdateIndependent.TryGetValue(window, out var r) || r.Invalid || r.Sealed ||
                !ReferenceEquals(window.Binding, binding) || !ReferenceEquals(binding.Resource, scope) || !ReferenceEquals(r.Scope, scope) ||
                !ReferenceEquals(r.Client, client) || !ReferenceEquals(r.Receipt, receipt) || !ReferenceEquals(r.StartTask, startTask) ||
                !ReferenceEquals(r.Handle, handle) || !r.Started.Task.IsCompletedSuccessfully || !startTask.IsCompletedSuccessfully ||
                r.Token.IsCancellationRequested || r.Caller.IsCancellationRequested || r.StartProof is null ||
                receipt.Evidence != DispatchEvidence.Applied || handle.State != NativeProvisioningState.Succeeded ||
                targets.GetValueOrDefault(window) is not null || completedStatusReads.Contains(window)) return false;
            proof = r.StartProof;
            return true;
        }
    }
    internal bool TryGetStatusPrivateConnectionUpdateIndependentCompletion(Window window, Binding binding, VaultAdministration client,
        PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task statusTask,
        [NotNullWhen(true)] out StatusPrivateConnectionUpdateIndependentCompletionProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusPrivateConnectionUpdateIndependentStart(window, binding, client, scope, receipt, startTask, handle, out var start) ||
                !statusPrivateUpdateIndependent.TryGetValue(window, out var r) || !ReferenceEquals(r.StatusTask, statusTask) ||
                !r.Checked.Task.IsCompletedSuccessfully || !statusTask.IsCompletedSuccessfully || !r.CheckHook || !r.CheckSuccess ||
                r.CheckToken.IsCancellationRequested || r.CheckCaller.IsCancellationRequested || r.CheckFactories != 0 ||
                r.Completion is null || !ReferenceEquals(r.Completion.Start, start)) return false;
            proof = r.Completion;
            return true;
        }
    }
    internal bool OwnsStatusPrivateConnectionUpdateIndependentCompletion(StatusPrivateConnectionUpdateIndependentCompletionProof proof,
        Window window, Binding binding, VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt,
        Task startTask, ManagementOperation handle, Task statusTask) =>
        TryGetStatusPrivateConnectionUpdateIndependentCompletion(window, binding, client, scope, receipt, startTask, handle, statusTask,
            out var issued) && ReferenceEquals(proof, issued);

    private async Task<SecretStatus> CheckStatusPrivateUpdateIndependentAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained, CancellationToken caller)
    {
        StatusPrivateUpdateIndependentRegistration r;
        lock (gate)
        {
            Own(window, selector);
            r = statusPrivateUpdateIndependent[window];
            Require(ReferenceEquals(r.Handle, handle));
            bool valid = !r.CheckClaimed && !window.Closed && window.Status is null && !token.IsCancellationRequested && !caller.IsCancellationRequested &&
                TryGetStatusPrivateConnectionUpdateIndependentStart(window, window.Binding, r.Client, r.Scope, r.Receipt, r.StartTask!, handle, out _);
            r.CheckClaimed = true;
            r.Invalid |= !valid;
            Require(valid);
            r.CheckToken = token;
            r.CheckCaller = caller;
            r.Status = window.Status = new();
        }
        try
        {
            var previous = currentStatusPrivateUpdateIndependent.Value;
            currentStatusPrivateUpdateIndependent.Value = new(r, true);
            try { r.StatusTask = handle.CheckStatusAsync(token).AsTask(); r.Status.SdkTask = r.StatusTask; }
            finally { currentStatusPrivateUpdateIndependent.Value = previous; }
            try { retained?.Invoke(r.StatusTask); r.CheckHook = true; }
            finally
            {
                var status = await r.StatusTask.ConfigureAwait(false);
                r.Status.Outcome = status;
                r.Status.WrapperState = handle.State;
                r.CheckSuccess = status == SecretStatus.Success && handle.State == NativeProvisioningState.Succeeded &&
                    r.Receipt.Evidence == DispatchEvidence.Applied;
            }
            return await r.StatusTask.ConfigureAwait(false);
        }
        catch { r.Invalid = true; throw; }
        finally
        {
            if (r.StatusTask is not null) try { await r.StatusTask.ConfigureAwait(false); } catch { r.Invalid = true; }
            lock (gate)
            {
                if (!r.Invalid && !r.Sealed && r.CheckHook && r.CheckSuccess && r.CheckFactories == 0 && r.Sends == 1 &&
                    !r.Token.IsCancellationRequested && !r.Caller.IsCancellationRequested && !token.IsCancellationRequested &&
                    !caller.IsCancellationRequested && r.StartProof is not null && r.StatusTask is { IsCompletedSuccessfully: true })
                    r.Completion = new(r.StartProof);
                else r.Invalid = true;
                r.Status.Terminated = true;
                r.Status.Drained.TrySetResult();
                r.Checked.TrySetResult();
            }
        }
    }
    private Task<Capture> SealStatusPrivateUpdateIndependentAsync(Window window)
    {
        StatusPrivateUpdateIndependentRegistration r;
        TaskCompletionSource admitted;
        Task<Capture> task;
        lock (gate)
        {
            r = statusPrivateUpdateIndependent[window];
            r.Sealed = true;
            window.Closed = true;
            if (r.SealTask is not null) return r.SealTask;
            admitted = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = r.SealTask = Drain(admitted.Task);
        }
        admitted.SetResult();
        return task;
        async Task<Capture> Drain(Task start)
        {
            await start.ConfigureAwait(false);
            await r.Started.Task.ConfigureAwait(false);
            if (r.Status is not null) await r.Checked.Task.ConfigureAwait(false);
            return new() { Binding = window.Binding, Start = r.Start, Status = r.Status };
        }
    }
    private async Task SendStatusPrivateUpdateIndependentAsync(StatusPrivateUpdateIndependentContext context, HttpMessage message)
    {
        var r = context.Registration;
        var request = message.Request;
        var headers = request.Headers.ToArray();
        var originalContent = request.Content;
        RequestContent? requestSnapshot = null;
        Attempt? attempt = null;
        void Check()
        {
            Require(ReferenceEquals(request.Content, requestSnapshot ?? originalContent));
            Require(!r.Invalid && !r.Sealed && !context.Check && ReferenceEquals(message.Request, request) &&
                headers.SequenceEqual(request.Headers) && request.Method == RequestMethod.Put && request.Content is not null &&
                Trusted(request.Uri.ToUri()) && request.Uri.ToUri().AbsoluteUri == Origin + r.Window.Path + "?api-version=2026-02-01" &&
                request.Headers.TryGetValue("Authorization", out var auth) && auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7);
            Headers(headers);
            Require(!headers.Any(h => new[] { "Content-Encoding", "Transfer-Encoding", "Content-Range", "Range" }
                .Contains(h.Name, StringComparer.OrdinalIgnoreCase)));
            if (request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
            r.Token.ThrowIfCancellationRequested();
            r.Caller.ThrowIfCancellationRequested();
            message.CancellationToken.ThrowIfCancellationRequested();
        }
        try
        {
            lock (gate) Require(!context.Check && r.Sends++ == 0 && r.Requests.Contains(request) && r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched);
            Check();
            long requestLength = 0;
            Require(originalContent is not null && originalContent.TryComputeLength(out requestLength) &&
                requestLength > 0 && requestLength <= maximumBytes &&
                request.Headers.TryGetValue("Content-Type", out var contentType) &&
                contentType.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase));
            byte[] requestBytes = new byte[checked((int)requestLength)];
            r.Storage.Own(requestBytes);
            r.Storage.Own(originalContent);
            using (var output = new MemoryStream(requestBytes, 0, requestBytes.Length, true, true))
            {
                await originalContent.WriteToAsync(output, message.CancellationToken).ConfigureAwait(false);
                Require(output.Position == requestLength);
            }
            if (request.Headers.TryGetValue("Content-Length", out var requestDeclared))
                Require(requestDeclared == requestLength.ToString(CultureInfo.InvariantCulture));
            string requestHash;
            try
            {
                Require(requestBytes.Length is > 0 && requestBytes.Length <= maximumBytes);
                using var json = JsonDocument.Parse(requestBytes, new JsonDocumentOptions { MaxDepth = 16 });
                int nodes = 128;
                JsonRows(json.RootElement, ref nodes);
                var root = json.RootElement;
                Require(OnlyApprovalFields(root, "properties"));
                var properties = root.GetProperty("properties");
                Require(OnlyApprovalFields(properties, "privateLinkServiceConnectionState"));
                var state = properties.GetProperty("privateLinkServiceConnectionState");
                Require(OnlyApprovalFields(state, "status") && ApprovalText(state, "status") == "Approved");
                requestHash = Convert.ToHexString(SHA256.HashData(requestBytes));
            }
            finally { Check(); }
            requestSnapshot = RequestContent.Create(requestBytes);
            r.Storage.Own(requestSnapshot);
            request.Content = requestSnapshot;
            r.BeforeSend?.Invoke();
            Check();
            attempt = new() { Dispatch = Guid.NewGuid(), RequestSha256 = requestHash };
            lock (gate) r.Start.Attempts.Add(attempt);
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            Check();
            var original = message.Response;
            var stream = original.ContentStream;
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, r.Storage).ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(original.ContentStream, stream));
            attempt.HttpStatus = body.Response.Status;
            attempt.ResponseObserved = true;
            attempt.ResponseSha256 = body.Sha256;
            try
            {
                Require(body.Response.Status == 200 && body.Bytes.Length > 0 &&
                    PrivateApprovalHeaders(body.Response.Headers.Select(h => (h.Name, h.Value)).ToArray(), body.Bytes.Length));
                using var document = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
                int remaining = 512;
                JsonRows(document.RootElement, ref remaining);
                var model = ModelReaderWriter.Read<KeyVaultPrivateEndpointConnectionData>(new BinaryData(body.Bytes));
                Require(model is not null);
                var facts = ManagementOperationResourceCollector.ValidateStatusPrivateConnectionResource(document.RootElement, model,
                    r.Scope, r.Window.Binding.Location, allowLocation: false);
                Require(facts is { State: "Approved", Provisioning: "Succeeded" });
                r.Candidate = new(r.Window.Binding, attempt.Dispatch, facts, requestHash, body.Sha256, body.NativeRequestId);
            }
            catch (Exception)
            {
                // Eligibility never replaces the original adapter outcome: a
                // cached Success from HTTP 200/Updating still has no I proof.
                r.Candidate = null;
            }
            attempt.Valid = r.Candidate is not null;
            attempt.State = r.Candidate is not null ? WireState.Succeeded : WireState.Unknown;
            if (body.Bytes.Length != 0)
                r.Parser = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, r.Storage,
                    requireRebuffer: true, requireDownstreamRead: true);
        }
        catch { r.Invalid = true; throw; }
        finally { if (attempt is not null) attempt.TransportTerminated = true; }
    }

    internal sealed class StatusPrivateConnectionUpdateCancellationStartProof(Binding binding, Guid dispatch,
        ManagementOperationResourceCollector.StatusPrivateConnectionFacts facts, string requestSha256,
        string responseSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal Guid Dispatch { get; } = dispatch;
        internal ManagementOperationResourceCollector.StatusPrivateConnectionFacts Facts { get; } = facts;
        internal string EndpointId => Facts.EndpointId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        public override string ToString() => "[StatusPrivateConnectionUpdateCancellationStartProof]";
    }

    internal sealed class StatusPrivateConnectionDeleteCancellationStartProof(Binding binding, Guid dispatch,
        ManagementOperationResourceCollector.StatusPrivateConnectionFacts facts, string requestSha256,
        string responseSha256, string nativeRequestId, NativeProvisioningState startState)
    {
        internal Binding Binding { get; } = binding;
        internal Guid Dispatch { get; } = dispatch;
        internal ManagementOperationResourceCollector.StatusPrivateConnectionFacts Facts { get; } = facts;
        internal string EndpointId => Facts.EndpointId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal NativeProvisioningState StartState { get; } = startState;
        public override string ToString() => "[StatusPrivateConnectionDeleteCancellationStartProof]";
    }

    internal sealed class StatusSucceededDeleteVaultCancellationStartProof(Binding binding, StatusTarget target,
        int httpStatus, int responseBytes, string requestSha256, string nativeRequestId)
    {
        internal Binding Binding { get; } = binding;
        internal StatusTarget Target { get; } = target;
        internal Guid StartDispatch => Target.StartDispatch;
        internal int HttpStatus { get; } = httpStatus;
        internal int ResponseBytes { get; } = responseBytes;
        internal string ResponseSha256 => Target.StartResponseSha256;
        internal string RequestSha256 { get; } = requestSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        public override string ToString() => "[StatusSucceededDeleteVaultCancellationStartProof]";
    }

    internal sealed class StatusSucceededDeleteVaultCancellationCanceledProof(StatusSucceededDeleteVaultCancellationStartProof start)
    {
        internal StatusSucceededDeleteVaultCancellationStartProof Start { get; } = start;
        public override string ToString() => "[StatusSucceededDeleteVaultCancellationCanceledProof]";
    }

    internal sealed class StatusSucceededDeleteVaultCancellationCompletionProof(StatusSucceededDeleteVaultCancellationStartProof start,
        StatusSucceededDeleteVaultCancellationCanceledProof canceled)
    {
        internal StatusSucceededDeleteVaultCancellationStartProof Start { get; } = start;
        internal StatusSucceededDeleteVaultCancellationCanceledProof Canceled { get; } = canceled;
        public override string ToString() => "[StatusSucceededDeleteVaultCancellationCompletionProof]";
    }

    private sealed class StatusSucceededDeleteVaultCancellationRegistration(Window window, VaultAdministration client,
        VaultScope scope, ManagementReceipt receipt, CancellationToken token, Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Invocation Start = window.Start!;
        internal Invocation? Cancel, Status;
        internal readonly VaultAdministration Client = client;
        internal readonly VaultScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken StartToken = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly HashSet<Request> Requests = new(ReferenceEqualityComparer.Instance);
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Canceled = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? CanceledTask, StatusTask;
        internal Task? SendTask;
        internal ManagementOperation? Handle;
        internal OwnedArmResponse.ParserCustody? Parser;
        internal StatusSucceededDeleteVaultCancellationStartProof? Candidate, StartProof;
        internal StatusSucceededDeleteVaultCancellationCanceledProof? CanceledProof;
        internal StatusSucceededDeleteVaultCancellationCompletionProof? Completion;
        internal CancellationToken CancelToken, CheckToken;
        internal bool Invalid, Sealed, CancelClaimed, CheckClaimed, StartHook, CancelHook, CheckHook, StartSuccess, CheckSuccess, CancellationPropagated;
        internal int Sends, CancelFactories, CheckFactories;
    }
    private enum StatusSucceededDeleteVaultCancellationStage { Start, Canceled, Normal }
    private sealed record StatusSucceededDeleteVaultCancellationContext(StatusSucceededDeleteVaultCancellationRegistration Registration,
        StatusSucceededDeleteVaultCancellationStage Stage);
    private readonly AsyncLocal<StatusSucceededDeleteVaultCancellationContext?> currentStatusSucceededDeleteVaultCancellation = new();
    private readonly Dictionary<Window, StatusSucceededDeleteVaultCancellationRegistration> statusSucceededDeleteVaultCancellation =
        new(ReferenceEqualityComparer.Instance);

    internal async Task<SecretOutcome<ManagementOperation>> StartStatusSucceededDeleteVaultCancellationAsync(Window window,
        FixtureSelector selector, VaultAdministration client, VaultScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token = default, Action<Task>? retained = null, Action? beforeSend = null)
    {
        StatusSucceededDeleteVaultCancellationRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(VaultFixtureProvisioner.StatusSucceededDeleteVaultCancellationSelector(selector) &&
                window.Binding.Operation == ManagementMutation.DeleteVault && window.Binding.ApiRevision == "2026-02-01" &&
                ReferenceEquals(window.Binding.Resource, scope) && client is not null && receipt is not null &&
                input.StatusOperation == ManagementMutation.DeleteVault && InputMatches(window.Binding, input) &&
                !window.Closed && window.Start is null && startedWindows.Add(window));
            window.Start = new();
            r = new(window, client, scope, receipt, token, beforeSend);
            statusSucceededDeleteVaultCancellation.Add(window, r);
        }
        try
        {
            var previous = currentStatusSucceededDeleteVaultCancellation.Value;
            currentStatusSucceededDeleteVaultCancellation.Value = new(r, StatusSucceededDeleteVaultCancellationStage.Start);
            try
            {
                r.StartTask = ManagementOperationEffects.StartAsync(client, scope, ManagementMutation.DeleteVault,
                    input, receipt, token).AsTask();
                r.Start.SdkTask = r.StartTask;
            }
            finally { currentStatusSucceededDeleteVaultCancellation.Value = previous; }
            try { retained?.Invoke(r.StartTask); r.StartHook = true; }
            finally
            {
                var result = await r.StartTask.ConfigureAwait(false);
                r.Handle = result.IsSuccess ? result.Value : null;
                r.StartSuccess = result.IsSuccess && r.Handle!.State == NativeProvisioningState.Succeeded &&
                    receipt.Evidence == DispatchEvidence.Applied;
                r.Start.Outcome = result.Status;
                r.Start.WrapperState = r.Handle?.State;
                r.Start.HasNativeHandle = r.Handle is not null;
            }
            return await r.StartTask.ConfigureAwait(false);
        }
        catch { r.Invalid = true; throw; }
        finally
        {
            if (r.StartTask is not null)
                try { await r.StartTask.ConfigureAwait(false); } catch { r.Invalid = true; }
            if (r.SendTask is not null)
                try { await r.SendTask.ConfigureAwait(false); } catch { r.Invalid = true; }
            bool custody = r.Parser is { Complete: true, Invalid: false };
            try { r.Storage.Dispose(); } catch { r.Invalid = true; }
            lock (gate)
            {
                r.Invalid |= !custody || r.Parser is not { Complete: true, Invalid: false };
                if (!r.Invalid && !r.Sealed && r.StartHook && r.StartSuccess && r.Sends == 1 &&
                    r.StartTask is { IsCompletedSuccessfully: true } && !token.IsCancellationRequested &&
                    r.Candidate is not null && receipt.Evidence == DispatchEvidence.Applied)
                {
                    r.StartProof = r.Candidate;
                    targets[window] = r.Candidate.Target;
                    eligible.Add(window);
                }
                r.Start.Terminated = true;
                r.Start.Drained.TrySetResult();
                r.Started.TrySetResult();
            }
        }
    }

    internal bool TryGetStatusSucceededDeleteVaultCancellationStart(Window window, Binding binding, VaultAdministration client,
        VaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle,
        [NotNullWhen(true)] out StatusSucceededDeleteVaultCancellationStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!statusSucceededDeleteVaultCancellation.TryGetValue(window, out var r) || r.Invalid || r.Sealed ||
                !ReferenceEquals(window.Binding, binding) || !ReferenceEquals(r.Client, client) ||
                !ReferenceEquals(r.Scope, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.StartTask, startTask) || !ReferenceEquals(r.Handle, handle) ||
                !r.Started.Task.IsCompletedSuccessfully || !startTask.IsCompletedSuccessfully ||
                r.StartToken.IsCancellationRequested || receipt.Evidence != DispatchEvidence.Applied ||
                handle.State != NativeProvisioningState.Succeeded || r.StartProof is null ||
                !ReferenceEquals(targets.GetValueOrDefault(window), r.StartProof.Target) ||
                completedStatusReads.Contains(window)) return false;
            proof = r.StartProof;
            return true;
        }
    }

    internal bool TryGetStatusSucceededDeleteVaultCancellationCanceled(Window window, Binding binding, VaultAdministration client,
        VaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task canceledTask,
        [NotNullWhen(true)] out StatusSucceededDeleteVaultCancellationCanceledProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusSucceededDeleteVaultCancellationStart(window, binding, client, scope, receipt, startTask, handle, out var start) ||
                !statusSucceededDeleteVaultCancellation.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.CanceledTask, canceledTask) || !r.Canceled.Task.IsCompletedSuccessfully ||
                !canceledTask.IsCanceled || !r.CancelToken.IsCancellationRequested || !r.CancelHook ||
                !r.CancellationPropagated || r.CancelFactories != 0 || r.CanceledProof is null ||
                !ReferenceEquals(r.CanceledProof.Start, start)) return false;
            proof = r.CanceledProof;
            return true;
        }
    }

    internal bool TryGetStatusSucceededDeleteVaultCancellationCompletion(Window window, Binding binding, VaultAdministration client,
        VaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task canceledTask, Task statusTask,
        [NotNullWhen(true)] out StatusSucceededDeleteVaultCancellationCompletionProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusSucceededDeleteVaultCancellationCanceled(window, binding, client, scope, receipt, startTask, handle,
                    canceledTask, out var canceled) ||
                !statusSucceededDeleteVaultCancellation.TryGetValue(window, out var r) || !ReferenceEquals(r.StatusTask, statusTask) ||
                ReferenceEquals(canceledTask, statusTask) || !r.Checked.Task.IsCompletedSuccessfully ||
                !statusTask.IsCompletedSuccessfully || r.CheckToken.IsCancellationRequested || !r.CheckHook ||
                !r.CheckSuccess || r.CheckFactories != 0 || r.Completion is null ||
                !ReferenceEquals(r.Completion.Canceled, canceled)) return false;
            proof = r.Completion;
            return true;
        }
    }

    private async Task<SecretStatus> CheckStatusSucceededDeleteVaultCancellationAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained, bool canceled)
    {
        StatusSucceededDeleteVaultCancellationRegistration r;
        Invocation invocation;
        lock (gate)
        {
            Own(window, selector);
            r = statusSucceededDeleteVaultCancellation[window];
            Require(ReferenceEquals(r.Handle, handle));
            bool valid = !window.Closed && !r.CheckClaimed &&
                TryGetStatusSucceededDeleteVaultCancellationStart(window, window.Binding, r.Client, r.Scope, r.Receipt,
                    r.StartTask!, handle, out _) && (canceled
                    ? !r.CancelClaimed && token.IsCancellationRequested
                    : r.CancelClaimed && !token.IsCancellationRequested && r.CanceledTask is not null &&
                        TryGetStatusSucceededDeleteVaultCancellationCanceled(window, window.Binding, r.Client, r.Scope,
                            r.Receipt, r.StartTask!, handle, r.CanceledTask, out _));
            if (canceled) r.CancelClaimed = true;
            else r.CheckClaimed = true;
            r.Invalid |= !valid;
            Require(valid);
            if (canceled) { r.CancelToken = token; invocation = r.Cancel = new(); }
            else { r.CheckToken = token; invocation = r.Status = window.Status = new(); }
        }
        Task<SecretStatus>? task = null;
        try
        {
            var previous = currentStatusSucceededDeleteVaultCancellation.Value;
            currentStatusSucceededDeleteVaultCancellation.Value = new(r, canceled
                ? StatusSucceededDeleteVaultCancellationStage.Canceled : StatusSucceededDeleteVaultCancellationStage.Normal);
            try
            {
                task = handle.CheckStatusAsync(token).AsTask();
                invocation.SdkTask = task;
                if (canceled) r.CanceledTask = task;
                else r.StatusTask = task;
            }
            finally { currentStatusSucceededDeleteVaultCancellation.Value = previous; }
            try
            {
                retained?.Invoke(task);
                if (canceled) r.CancelHook = true;
                else r.CheckHook = true;
            }
            finally
            {
                try
                {
                    var outcome = await task.ConfigureAwait(false);
                    invocation.Outcome = outcome;
                    invocation.WrapperState = handle.State;
                    if (canceled) r.Invalid = true;
                    else r.CheckSuccess = outcome == SecretStatus.Success && handle.State == NativeProvisioningState.Succeeded &&
                        r.Receipt.Evidence == DispatchEvidence.Applied;
                }
                catch (OperationCanceledException) when (canceled && task.IsCanceled)
                {
                    r.CancellationPropagated = true;
                    invocation.Canceled = true;
                    throw;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (canceled && r.CancellationPropagated && r.CancelHook) { throw; }
        catch { r.Invalid = true; throw; }
        finally
        {
            if (task is not null)
                try { await task.ConfigureAwait(false); }
                catch (OperationCanceledException) when (canceled && task.IsCanceled) { }
                catch { r.Invalid = true; }
            lock (gate)
            {
                bool live = !r.Invalid && !r.Sealed && !r.StartToken.IsCancellationRequested &&
                    r.StartProof is not null && handle.State == NativeProvisioningState.Succeeded &&
                    r.Receipt.Evidence == DispatchEvidence.Applied && r.Sends == 1;
                if (canceled)
                {
                    if (live && r.CancelHook && r.CancellationPropagated && token.IsCancellationRequested &&
                        task is { IsCanceled: true } && r.CancelFactories == 0)
                        r.CanceledProof = new(r.StartProof!);
                    else r.Invalid = true;
                }
                else if (live && r.CheckHook && r.CheckSuccess && !token.IsCancellationRequested &&
                    task is { IsCompletedSuccessfully: true } && !ReferenceEquals(task, r.CanceledTask) &&
                    r.CheckFactories == 0 && r.CanceledProof is not null)
                    r.Completion = new(r.StartProof!, r.CanceledProof);
                else r.Invalid = true;
                invocation.Terminated = true;
                invocation.Drained.TrySetResult();
                if (canceled) r.Canceled.TrySetResult();
                else r.Checked.TrySetResult();
            }
        }
    }

    private async Task<Capture> SealStatusSucceededDeleteVaultCancellationAsync(Window window)
    {
        StatusSucceededDeleteVaultCancellationRegistration r;
        lock (gate) { r = statusSucceededDeleteVaultCancellation[window]; r.Sealed = true; window.Closed = true; }
        await r.Started.Task.ConfigureAwait(false);
        if (r.Cancel is not null) await r.Canceled.Task.ConfigureAwait(false);
        if (r.Status is not null) await r.Checked.Task.ConfigureAwait(false);
        return new() { Binding = window.Binding, Start = r.Start, Status = r.Status };
    }

    private async Task SendStatusSucceededDeleteVaultCancellationAsync(StatusSucceededDeleteVaultCancellationContext context, HttpMessage message)
    {
        var r = context.Registration;
        var request = message.Request;
        var headers = request.Headers.ToArray();
        void Check()
        {
            Require(!r.Invalid && !r.Sealed && context.Stage == StatusSucceededDeleteVaultCancellationStage.Start && ReferenceEquals(message.Request, request) &&
                headers.SequenceEqual(request.Headers) && request.Method == RequestMethod.Delete &&
                request.Content is null && Trusted(request.Uri.ToUri()) &&
                request.Uri.ToUri().AbsoluteUri == "https://management.azure.com" + r.Window.Path + "?api-version=2026-02-01" &&
                request.Headers.TryGetValue("Authorization", out var auth) &&
                auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7);
            Headers(headers);
            Require(!headers.Any(h => new[] { "Content-Encoding", "Transfer-Encoding", "Content-Range", "Range" }
                .Contains(h.Name, StringComparer.OrdinalIgnoreCase)));
            if (request.Headers.TryGetValue("Content-Length", out var length)) Require(length == "0");
            if (request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
            r.StartToken.ThrowIfCancellationRequested();
            message.CancellationToken.ThrowIfCancellationRequested();
        }
        try
        {
            lock (gate)
                Require(context.Stage == StatusSucceededDeleteVaultCancellationStage.Start && r.Sends++ == 0 && r.Requests.Contains(request) &&
                    r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched);
            Check();
            r.BeforeSend?.Invoke();
            Check();
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            Check();
            var original = message.Response;
            var stream = original.ContentStream;
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, r.Storage, allowContinuation: true)
                .ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(original.ContentStream, stream) && body.Response.Status == 200 &&
                body.Response.Headers.Count(h => new[] { "Location", "Azure-AsyncOperation", "Operation-Location" }
                    .Contains(h.Name, StringComparer.OrdinalIgnoreCase)) == 1);
            string next = Continuation(r.Window, message) ?? throw new InvalidOperationException("status-succeeded-delete-target");
            using var json = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int nodes = 512;
            JsonRows(json.RootElement, ref nodes);
            var root = json.RootElement;
            Require(root.ValueKind == JsonValueKind.Object &&
                root.EnumerateObject().All(p => p.Name is "id" or "status" or "properties"));
            if (root.TryGetProperty("id", out var id)) Require(id.GetString() == r.Window.Path);
            bool direct = root.TryGetProperty("status", out var status);
            bool nested = root.TryGetProperty("properties", out var properties);
            Require(direct != nested);
            if (nested) Require(properties.ValueKind == JsonValueKind.Object &&
                properties.EnumerateObject().All(p => p.Name == "provisioningState"));
            Require(State(direct ? status.GetString() : properties.GetProperty("provisioningState").GetString()) == WireState.Pending);
            var target = new StatusTarget(r.Window.Binding, Guid.NewGuid(), StatusTargetKind.Operation, new Uri(next),
                Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(next))), body.Sha256);
            r.Candidate = new(r.Window.Binding, target, body.Response.Status, body.Bytes.Length,
                Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("DELETE " + request.Uri.ToUri().AbsoluteUri))),
                body.NativeRequestId);
            r.Parser = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, r.Storage,
                requireRebuffer: true, requireDownstreamRead: false);
        }
        catch { r.Invalid = true; throw; }
    }

    internal sealed class StatusPrivateConnectionDeleteSelectedStartProof(Binding binding, Guid dispatch,
        ManagementOperationResourceCollector.StatusPrivateConnectionFacts facts, string requestSha256,
        string responseSha256, string nativeRequestId, NativeProvisioningState startState)
    {
        internal Binding Binding { get; } = binding;
        internal Guid Dispatch { get; } = dispatch;
        internal ManagementOperationResourceCollector.StatusPrivateConnectionFacts Facts { get; } = facts;
        internal string EndpointId => Facts.EndpointId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal NativeProvisioningState StartState { get; } = startState;
        public override string ToString() => "[StatusPrivateConnectionDeleteSelectedStartProof]";
    }

    internal sealed class StatusPrivateConnectionDeleteSelectedCompletionProof(
        StatusPrivateConnectionDeleteSelectedStartProof start)
    {
        internal StatusPrivateConnectionDeleteSelectedStartProof Start { get; } = start;
        public override string ToString() => "[StatusPrivateConnectionDeleteSelectedCompletionProof]";
    }

    private sealed class StatusPrivateDeleteSelectedRegistration(Window window, Invocation start,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt,
        CancellationToken token, Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly Invocation Start = start;
        internal readonly VaultAdministration Client = client;
        internal readonly PrivateConnectionScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken StartToken = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal OwnedArmResponse.ParserCustody? Parser;
        internal ManagementOperationResourceCollector.StatusPrivateConnectionFacts? Facts;
        internal StatusPrivateConnectionDeleteSelectedStartProof? StartProof;
        internal StatusPrivateConnectionDeleteSelectedCompletionProof? Completion;
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task<Capture>? SealTask;
        internal Invocation? Status;
        internal ManagementOperation? Handle;
        internal NativeProvisioningState? StartState;
        internal CancellationToken StatusToken;
        internal Guid Dispatch;
        internal string? RequestSha256, ResponseSha256, NativeRequestId;
        internal int Sends;
        internal bool Invalid, Sealed, StartHookReturned, StartSucceeded, TransportSucceeded, StartComplete;
        internal bool CheckClaimed, StatusHookReturned, StatusSucceeded, Complete;
    }

    private readonly Dictionary<Window, StatusPrivateDeleteSelectedRegistration> statusPrivateDeleteSelected =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Invocation, StatusPrivateDeleteSelectedRegistration> statusPrivateDeleteSelectedInvocations =
        new(ReferenceEqualityComparer.Instance);

    internal bool TryGetStatusPrivateConnectionDeleteSelectedStart(Window window, Binding binding,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, [NotNullWhen(true)] out StatusPrivateConnectionDeleteSelectedStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusPrivateDeleteSelected.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.Binding, binding) ||
                !VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(binding.Selector) ||
                !ReferenceEquals(binding.Resource, scope) ||
                !ReferenceEquals(r.Client, client) || !ReferenceEquals(r.Scope, scope) ||
                !ReferenceEquals(r.Receipt, receipt) || !ReferenceEquals(r.StartTask, startTask) ||
                !ReferenceEquals(r.Handle, handle) || !StatusPrivateDeleteSelectedStartValid(r) ||
                receipt.Evidence != DispatchEvidence.Pending ||
                !(handle.State == r.StartState || r.Complete && handle.State == NativeProvisioningState.Succeeded))
                return false;
            proof = r.StartProof;
            return proof is not null;
        }
    }

    internal bool TryGetStatusPrivateConnectionDeleteSelectedCompletion(Window window, Binding binding,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task statusTask,
        [NotNullWhen(true)] out StatusPrivateConnectionDeleteSelectedCompletionProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusPrivateConnectionDeleteSelectedStart(window, binding, client, scope, receipt,
                    startTask, handle, out _) || !statusPrivateDeleteSelected.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.StatusTask, statusTask) || !r.Complete ||
                !r.Checked.Task.IsCompletedSuccessfully || r.StatusTask is not { IsCompletedSuccessfully: true } ||
                r.StatusToken.IsCancellationRequested || handle.State != NativeProvisioningState.Succeeded ||
                completedStatusReads.Contains(window)) return false;
            proof = r.Completion;
            return proof is not null;
        }
    }

    internal bool OwnsStatusPrivateConnectionDeleteSelectedCompletion(
        StatusPrivateConnectionDeleteSelectedCompletionProof proof, Window window, Binding binding,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task statusTask) =>
        TryGetStatusPrivateConnectionDeleteSelectedCompletion(window, binding, client, scope, receipt,
            startTask, handle, statusTask, out var issued) && ReferenceEquals(proof, issued);

    private static bool StatusPrivateDeleteSelectedStartValid(StatusPrivateDeleteSelectedRegistration r) =>
        !r.Invalid && !r.Sealed && r.StartComplete && r.StartProof is not null &&
        r.Started.Task.IsCompletedSuccessfully && r.StartTask is { IsCompletedSuccessfully: true } &&
        !r.StartToken.IsCancellationRequested;

    internal sealed class StatusPrivateConnectionDeleteIndependentStartProof(Binding binding, Guid dispatch,
        ManagementOperationResourceCollector.StatusPrivateConnectionFacts facts, string requestSha256,
        string responseSha256, string nativeRequestId, NativeProvisioningState startState)
    {
        internal Binding Binding { get; } = binding;
        internal Guid Dispatch { get; } = dispatch;
        internal ManagementOperationResourceCollector.StatusPrivateConnectionFacts Facts { get; } = facts;
        internal string EndpointId => Facts.EndpointId;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal NativeProvisioningState StartState { get; } = startState;
        public override string ToString() => "[StatusPrivateConnectionDeleteIndependentStartProof]";
    }

    internal sealed class StatusPrivateConnectionDeleteIndependentCompletionProof(
        StatusPrivateConnectionDeleteIndependentStartProof start)
    {
        internal StatusPrivateConnectionDeleteIndependentStartProof Start { get; } = start;
        public override string ToString() => "[StatusPrivateConnectionDeleteIndependentCompletionProof]";
    }

    private sealed class StatusPrivateDeleteIndependentRegistration(Window window, Invocation start,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt,
        CancellationToken token, Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly Invocation Start = start;
        internal readonly VaultAdministration Client = client;
        internal readonly PrivateConnectionScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken StartToken = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal OwnedArmResponse.ParserCustody? Parser;
        internal ManagementOperationResourceCollector.StatusPrivateConnectionFacts? Facts;
        internal StatusPrivateConnectionDeleteIndependentStartProof? StartProof;
        internal StatusPrivateConnectionDeleteIndependentCompletionProof? Completion;
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task<Capture>? SealTask;
        internal Invocation? Status;
        internal ManagementOperation? Handle;
        internal NativeProvisioningState? StartState;
        internal CancellationToken StatusToken;
        internal Guid Dispatch;
        internal string? RequestSha256, ResponseSha256, NativeRequestId;
        internal int Sends;
        internal bool Invalid, Sealed, StartHookReturned, StartSucceeded, TransportSucceeded, StartComplete;
        internal bool CheckClaimed, StatusHookReturned, StatusSucceeded, Complete;
    }

    private readonly Dictionary<Window, StatusPrivateDeleteIndependentRegistration> statusPrivateDeleteIndependent =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Invocation, StatusPrivateDeleteIndependentRegistration> statusPrivateDeleteIndependentInvocations =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Window, Task<Capture>> statusPrivateDeleteIndependentSeals =
        new(ReferenceEqualityComparer.Instance);

    internal bool TryGetStatusPrivateConnectionDeleteIndependentStart(Window window, Binding binding,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, [NotNullWhen(true)] out StatusPrivateConnectionDeleteIndependentStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusPrivateDeleteIndependent.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.Binding, binding) ||
                !VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(binding.Selector) ||
                !ReferenceEquals(binding.Resource, scope) ||
                !ReferenceEquals(r.Client, client) || !ReferenceEquals(r.Scope, scope) ||
                !ReferenceEquals(r.Receipt, receipt) || !ReferenceEquals(r.StartTask, startTask) ||
                !ReferenceEquals(r.Handle, handle) || !StatusPrivateDeleteIndependentStartValid(r) ||
                receipt.Evidence != DispatchEvidence.Pending ||
                !(handle.State == r.StartState || r.Complete && handle.State == NativeProvisioningState.Succeeded))
                return false;
            proof = r.StartProof;
            return proof is not null;
        }
    }

    internal bool TryGetStatusPrivateConnectionDeleteIndependentCompletion(Window window, Binding binding,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task statusTask,
        [NotNullWhen(true)] out StatusPrivateConnectionDeleteIndependentCompletionProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetStatusPrivateConnectionDeleteIndependentStart(window, binding, client, scope, receipt,
                    startTask, handle, out _) || !statusPrivateDeleteIndependent.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.StatusTask, statusTask) || !r.Complete ||
                !r.Checked.Task.IsCompletedSuccessfully || r.StatusTask is not { IsCompletedSuccessfully: true } ||
                r.StatusToken.IsCancellationRequested || handle.State != NativeProvisioningState.Succeeded ||
                completedStatusReads.Contains(window)) return false;
            proof = r.Completion;
            return proof is not null;
        }
    }

    internal bool OwnsStatusPrivateConnectionDeleteIndependentCompletion(
        StatusPrivateConnectionDeleteIndependentCompletionProof proof, Window window, Binding binding,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task statusTask) =>
        TryGetStatusPrivateConnectionDeleteIndependentCompletion(window, binding, client, scope, receipt,
            startTask, handle, statusTask, out var issued) && ReferenceEquals(proof, issued);

    private static bool StatusPrivateDeleteIndependentStartValid(StatusPrivateDeleteIndependentRegistration r) =>
        !r.Invalid && !r.Sealed && r.StartComplete && r.StartProof is not null &&
        r.Started.Task.IsCompletedSuccessfully && r.StartTask is { IsCompletedSuccessfully: true } &&
        !r.StartToken.IsCancellationRequested;

    private sealed record PrivateApprovalFacts(string Id, string Name, string Type,
        string Approval, string Provisioning, string EndpointId)
    {
        public override string ToString() => "[PrivateApprovalFacts]";
    }

    private sealed class PrivateApprovalRegistration(Window window, Invocation start,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt,
        CancellationToken token, Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly Invocation Start = start;
        internal readonly VaultAdministration Client = client;
        internal readonly PrivateConnectionScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken Token = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly List<byte[]> Owned = [];
        internal readonly List<IDisposable> Snapshots = [];
        internal readonly TaskCompletionSource StartFinalized = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource StatusFinalized = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Invocation? Status;
        internal CancellationToken StatusToken;
        internal ManagementOperation? Handle;
        internal PrivateApprovalFacts? ResponseFacts;
        internal PrivateApprovalResponseProof? Proof;
        internal int Sends, StatusSends;
        internal bool Invalid, Sealed, StartHookReturned, StartSucceeded, TransportSucceeded;
        internal bool StatusInvalid, StatusHookReturned, StatusSucceeded, Completed;
    }

    private sealed class SynchronousDeleteRegistration(Window window, Invocation invocation,
        VaultAdministration client, ManagementScope scope, ManagementReceipt receipt, CancellationToken token,
        SynchronousDeleteProfile profile)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly Invocation Invocation = invocation;
        internal readonly VaultAdministration Client = client;
        internal readonly ManagementScope Scope = scope;
        internal readonly SynchronousDeleteProfile Profile = profile;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken Token = token;
        internal readonly List<byte[]> Owned = [];
        internal readonly List<IDisposable> Snapshots = [];
        internal readonly TaskCompletionSource Finalized = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task<SecretOutcome<ManagementOperation>>? Task;
        internal Request? Request;
        internal Guid Dispatch;
        internal int Sends;
        internal bool Invalid;
        internal bool HookReturned;
        internal bool SdkSucceeded;
        internal bool TransportSucceeded;
        internal ManagementOperation? Handle;
        internal SynchronousDeleteProof? Candidate;
        internal SynchronousDeleteProof? Proof;
    }

    private sealed record StatusVaultCancellationWire(int Ordinal, Request Request, string Uri, Guid Dispatch,
        int HttpStatus, WireState State, string ResponseSha256, string NativeRequestId, bool Complete,
        string? RequestSha256 = null, IReadOnlyList<(string Name, string Value)>? RequestHeaders = null)
    {
        public override string ToString() => "[StatusVaultCancellationWire]";
    }

    // K, P, R and U share task retention, never their operation-specific proof.
    // Diagnostics never own tasks, storage, wire facts or finalization signals.
    private sealed class StatusVaultCancellationRegistration(Window window, Invocation start,
        VaultAdministration client, ManagementScope scope, ManagementReceipt receipt, CancellationToken token)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly Invocation Start = start;
        internal readonly VaultAdministration Client = client;
        internal readonly ManagementScope ActualOriginalScope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken StartToken = token;
        internal readonly List<byte[]> Owned = [];
        internal readonly List<IDisposable> Snapshots = [];
        internal readonly OwnedArmResponse.Storage ParserStorage = new();
        internal readonly List<OwnedArmResponse.ParserCustody> Parsers = [];
        internal readonly List<StatusVaultCancellationWire> StatusWires = [];
        internal StatusVaultCancellationWire? StartWire;
        internal VaultConfiguration? RecoveryConfiguration;
        internal VaultConfiguration? UpdateConfiguration;
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Canceled = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? CanceledTask, StatusTask;
        internal Task<Capture>? SealTask;
        internal Invocation? PrivateCancel, NormalStatus;
        internal ManagementOperation? Handle;
        internal StatusTarget? Target;
        internal EmptyNotificationResponseCustody? NotificationCustody;
        internal StatusNotificationDeleteCancellationStartProof? NotificationCandidate, NotificationProof;
        internal StatusNotificationUpdateCancellationStartProof? NotificationUpdateCandidate, NotificationUpdateProof;
        internal StatusNotificationCreateCancellationStartProof? NotificationCreateCandidate, NotificationCreateProof;
        internal NotificationConfiguration? NotificationUpdateConfiguration;
        internal RoleFixtureJournal.NotificationAbsentCreateState? NotificationAbsentCreate;
        internal StatusRoleDeleteCancellationStartProof? RoleCandidate, RoleProof;
        internal StatusPrivateConnectionUpdateCancellationStartProof? PrivateCandidate, PrivateProof;
        internal ManagementOperationResourceCollector.StatusPrivateConnectionFacts? PrivateDeleteFacts;
        internal StatusPrivateConnectionDeleteCancellationStartProof? PrivateDeleteProof;
        internal Action? PrivateBeforeSend;
        internal DispatchEvidence StartReceipt;
        internal NativeProvisioningState? StartState, CancelState;
        internal CancellationToken CancelToken, StatusToken;
        internal int Sends, StatusSends;
        internal bool Invalid, Sealed, StartHookReturned, StartSucceeded, TransportSucceeded, WireQualified;
        internal bool CancelHookReturned, CancellationPropagated, StatusHookReturned, StatusSucceeded;
        internal bool StartComplete, CancelComplete, Complete;
    }

    private const string Origin = "https://management.azure.com";
    private readonly object owner = new(), gate = new();
    private readonly HashSet<Guid> nonces = [], leases = [];
    private readonly Dictionary<Window, StatusTarget?> targets = [];
    private readonly Dictionary<Window, ManagementOperation> handles = [];
    private readonly Dictionary<Window, string?> continuations = [];
    private readonly HashSet<Window> eligible = [];
    private readonly HashSet<Window> completedStatusReads = [];
    private readonly Dictionary<Invocation, int> nativeStatusReads = [];
    private readonly AsyncLocal<InvocationContext?> current = new();
    private readonly Dictionary<Invocation, Request> requestOwners = [];
    private readonly Dictionary<Invocation, HashSet<Request>> requestCandidates = [];
    private readonly Dictionary<Invocation, ManagementReceipt> originalReceipts = [];
    private readonly HashSet<Invocation> requestFactories = [];
    private readonly HashSet<Invocation> finalReadEligible = [];
    private readonly HashSet<Invocation> finishing = [];
    private readonly Dictionary<Invocation, TaskCompletionSource<Task>> borrowers = [];
    private readonly HashSet<Window> startedWindows = [];
    private readonly Dictionary<Invocation, SynchronousDeleteRegistration> synchronousDeletes = [];
    private readonly Dictionary<Window, PrivateApprovalRegistration> privateApprovals = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Invocation, PrivateApprovalRegistration> privateApprovalInvocations = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Window, DeleteVaultRegistration> deleteVaults = new(ReferenceEqualityComparer.Instance);
    private readonly HashSet<Window> deleteVaultWindows = new(ReferenceEqualityComparer.Instance);
    private readonly AsyncLocal<DeleteVaultContext?> currentDeleteVault = new();
    private readonly Dictionary<Window, PurgeDeletedVaultRegistration> purgeDeletedVaults = new(ReferenceEqualityComparer.Instance);
    private readonly HashSet<Window> purgeDeletedVaultWindows = new(ReferenceEqualityComparer.Instance);
    private readonly AsyncLocal<PurgeDeletedVaultContext?> currentPurgeDeletedVault = new();
    private readonly HashSet<Window> createVaultWindows = new(ReferenceEqualityComparer.Instance);
    private readonly HashSet<Window> recoverVaultWindows = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Window, CreateVaultRegistration> createVaults = new(ReferenceEqualityComparer.Instance);
    private readonly AsyncLocal<CreateVaultContext?> currentCreateVault = new();
    private readonly Dictionary<Window, PrivateConnectionState> privateUpdateWindows = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Window, PrivateConnectionUpdateRegistration> privateUpdates = new(ReferenceEqualityComparer.Instance);
    private readonly AsyncLocal<PrivateConnectionUpdateContext?> currentPrivateUpdate = new();
    private readonly HashSet<Window> privateDeleteWindows = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Window, PrivateConnectionDeleteRegistration> privateDeletes =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Invocation, PrivateConnectionDeleteRegistration> privateDeleteInvocations =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Window, StatusVaultCancellationRegistration> statusVaultCancellations =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Window, RoleFixtureJournal.NotificationAbsentCreateState> absentCreateWindows =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Invocation, StatusVaultCancellationRegistration> statusVaultCancellationInvocations =
        new(ReferenceEqualityComparer.Instance);
    private readonly HttpPipelineTransport backend;
    private readonly int maximumBytes;

    private sealed record InvocationContext(Window Window, Invocation Invocation, bool Status);

    internal bool TryGetStatusPrivateConnectionDeleteCancellationStart(Window window, Binding binding,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, [NotNullWhen(true)] out StatusPrivateConnectionDeleteCancellationStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusVaultCancellations.TryGetValue(window, out var r) ||
                !VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(r.Binding.Selector) ||
                !ReferenceEquals(r.Binding, binding) || !ReferenceEquals(r.Binding.Resource, scope) ||
                !ReferenceEquals(r.Client, client) || !ReferenceEquals(r.ActualOriginalScope, scope) ||
                !ReferenceEquals(r.Receipt, receipt) || !ReferenceEquals(r.StartTask, startTask) ||
                !ReferenceEquals(r.Handle, handle) || !StatusVaultCancellationStartValid(r) ||
                r.PrivateDeleteProof is null || r.Target is not null || receipt.Evidence != DispatchEvidence.Pending ||
                !(handle.State == r.StartState || r.Complete && handle.State == NativeProvisioningState.Succeeded))
                return false;
            proof = r.PrivateDeleteProof;
            return true;
        }
    }

    internal bool OwnsPrivateConnectionDeleteCanceledStatusAttempt(Window window, Binding binding,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask)
    {
        lock (gate)
            return TryGetStatusPrivateConnectionDeleteCancellationStart(window, binding, client, scope, receipt,
                startTask, handle, out _) && statusVaultCancellations.TryGetValue(window, out var r) &&
                ReferenceEquals(r.CanceledTask, canceledTask) && r.CancelComplete &&
                r.Canceled.Task.IsCompletedSuccessfully && r.CanceledTask is { IsCanceled: true } &&
                r.CancelToken.IsCancellationRequested && r.CancelState == r.StartState &&
                r.StatusSends == 0 && r.StatusWires.Count == 0;
    }

    internal bool OwnsStatusPrivateConnectionDeleteCancellationCompletion(Window window, Binding binding,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask, Task statusTask)
    {
        lock (gate)
            return OwnsPrivateConnectionDeleteCanceledStatusAttempt(window, binding, client, scope, receipt,
                startTask, handle, canceledTask) && statusVaultCancellations.TryGetValue(window, out var r) &&
                ReferenceEquals(r.StatusTask, statusTask) && !ReferenceEquals(canceledTask, statusTask) &&
                r.Complete && r.Checked.Task.IsCompletedSuccessfully &&
                r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                handle.State == NativeProvisioningState.Succeeded && !completedStatusReads.Contains(window);
    }

    internal bool TryGetStatusPrivateConnectionUpdateCancellationStart(Window window, Binding binding,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, [NotNullWhen(true)] out StatusPrivateConnectionUpdateCancellationStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusVaultCancellations.TryGetValue(window, out var r) ||
                !VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(r.Binding.Selector) ||
                !ReferenceEquals(r.Binding, binding) || !ReferenceEquals(r.Binding.Resource, scope) ||
                !ReferenceEquals(r.Client, client) || !ReferenceEquals(r.ActualOriginalScope, scope) ||
                !ReferenceEquals(r.Receipt, receipt) || !ReferenceEquals(r.StartTask, startTask) ||
                !ReferenceEquals(r.Handle, handle) || !StatusVaultCancellationStartValid(r) ||
                r.PrivateProof is null || r.Target is not null || receipt.Evidence != DispatchEvidence.Applied ||
                handle.State != NativeProvisioningState.Succeeded) return false;
            proof = r.PrivateProof;
            return true;
        }
    }

    internal bool OwnsPrivateConnectionUpdateCanceledStatusAttempt(Window window, Binding binding,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask)
    {
        lock (gate)
            return TryGetStatusPrivateConnectionUpdateCancellationStart(window, binding, client, scope, receipt,
                startTask, handle, out _) && statusVaultCancellations.TryGetValue(window, out var r) &&
                ReferenceEquals(r.CanceledTask, canceledTask) && r.CancelComplete &&
                r.Canceled.Task.IsCompletedSuccessfully && r.CanceledTask is { IsCanceled: true } &&
                r.CancelToken.IsCancellationRequested && r.StatusSends == 0 && r.StatusWires.Count == 0;
    }

    internal bool OwnsStatusPrivateConnectionUpdateCancellationCompletion(Window window, Binding binding,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask, Task statusTask)
    {
        lock (gate)
            return OwnsPrivateConnectionUpdateCanceledStatusAttempt(window, binding, client, scope, receipt,
                startTask, handle, canceledTask) && statusVaultCancellations.TryGetValue(window, out var r) &&
                ReferenceEquals(r.StatusTask, statusTask) && !ReferenceEquals(canceledTask, statusTask) &&
                r.Complete && r.Checked.Task.IsCompletedSuccessfully &&
                r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                !completedStatusReads.Contains(window);
    }

    internal bool TryGetStatusRoleDeleteCancellationStart(Window window, Binding binding,
        VaultAdministration client, RoleAssignmentScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, [NotNullWhen(true)] out StatusRoleDeleteCancellationStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusVaultCancellations.TryGetValue(window, out var r) ||
                !RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(r.Binding.Selector) ||
                !ReferenceEquals(r.Binding, binding) || !ReferenceEquals(r.Client, client) ||
                !ReferenceEquals(r.ActualOriginalScope, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.StartTask, startTask) || !ReferenceEquals(r.Handle, handle) ||
                !StatusVaultCancellationStartValid(r) || r.RoleProof is null ||
                r.Target is not null || r.Receipt.Evidence != DispatchEvidence.Applied ||
                handle.State != NativeProvisioningState.Succeeded) return false;
            proof = r.RoleProof;
            return true;
        }
    }

    internal bool OwnsRoleDeleteCanceledStatusAttempt(Window window, Binding binding,
        VaultAdministration client, RoleAssignmentScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask)
    {
        lock (gate)
            return TryGetStatusRoleDeleteCancellationStart(window, binding, client, scope, receipt,
                startTask, handle, out _) && statusVaultCancellations.TryGetValue(window, out var r) &&
                ReferenceEquals(r.CanceledTask, canceledTask) && r.CancelComplete &&
                r.Canceled.Task.IsCompletedSuccessfully && r.CanceledTask is { IsCanceled: true } &&
                r.CancelToken.IsCancellationRequested && r.StatusSends == 0 && r.StatusWires.Count == 0;
    }

    internal bool OwnsStatusRoleDeleteCancellationCompletion(Window window, Binding binding,
        VaultAdministration client, RoleAssignmentScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask, Task statusTask)
    {
        lock (gate)
            return OwnsRoleDeleteCanceledStatusAttempt(window, binding, client, scope, receipt,
                startTask, handle, canceledTask) && statusVaultCancellations.TryGetValue(window, out var r) &&
                ReferenceEquals(r.StatusTask, statusTask) && !ReferenceEquals(canceledTask, statusTask) &&
                r.Complete && r.Checked.Task.IsCompletedSuccessfully &&
                r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                !completedStatusReads.Contains(window);
    }

    internal void BindNotificationAbsentCreation(Window window, Binding binding,
        NotificationFixtureProvisioner source, NotificationFixtureProvisioner.Plan plan,
        NotificationFixtureProvisioner.StatusNotificationCreateReadProof baseline, Guid dispatch)
    {
        lock (gate)
        {
            Own(window, plan.Selector);
            Require(ReferenceEquals(window.Binding, binding) && binding.LeaseId == plan.LeaseId &&
                binding.Resource is NotificationScope scope && scope.SubscriptionName == plan.Scope.SubscriptionName &&
                scope.Vault.ExportResourceId() == plan.Scope.Vault.ExportResourceId() &&
                window.Start is null && !window.Closed && !absentCreateWindows.ContainsKey(window));
            var creation = source.BindAbsentCreationDispatch(plan, baseline, dispatch, this, window, binding);
            absentCreateWindows.Add(window, creation);
        }
    }

    internal string NotificationCreateCompletionDigest(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask, Task statusTask)
    {
        lock (gate)
        {
            Require(OwnsStatusNotificationCreateCancellationCompletion(window, binding, client, scope, receipt,
                startTask, handle, canceledTask, statusTask));
            var registration = statusVaultCancellations[window];
            Require(registration.NotificationAbsentCreate is not null);
            var wire = registration.StatusWires.Single();
            return NotificationFixtureProvisioner.Digest(registration.StartWire!.ResponseSha256,
                wire.RequestSha256!, wire.ResponseSha256, wire.NativeRequestId,
                "pre-canceled-native-GET0", "later-native-GET1-Succeeded", "receipt-Pending");
        }
    }

    internal bool TryGetStatusNotificationCreateCancellationStart(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, [NotNullWhen(true)] out StatusNotificationCreateCancellationStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusVaultCancellations.TryGetValue(window, out var r) ||
                !NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(r.Binding.Selector) ||
                !ReferenceEquals(r.Binding, binding) || !ReferenceEquals(r.Client, client) ||
                !ReferenceEquals(r.ActualOriginalScope, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.StartTask, startTask) || !ReferenceEquals(r.Handle, handle) ||
                !StatusVaultCancellationStartValid(r) || r.NotificationCreateProof is null ||
                r.StartReceipt != DispatchEvidence.Pending || receipt.Evidence != DispatchEvidence.Pending ||
                r.StartState != NativeProvisioningState.Pending ||
                !(handle.State == NativeProvisioningState.Pending ||
                    r.Complete && handle.State == NativeProvisioningState.Succeeded)) return false;
            proof = r.NotificationCreateProof;
            return true;
        }
    }

    internal bool OwnsNotificationCreateCanceledStatusAttempt(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask)
    {
        lock (gate)
            return TryGetStatusNotificationCreateCancellationStart(window, binding, client, scope, receipt,
                startTask, handle, out _) && statusVaultCancellations.TryGetValue(window, out var r) &&
                ReferenceEquals(r.CanceledTask, canceledTask) && r.CancelComplete &&
                r.Canceled.Task.IsCompletedSuccessfully && r.CanceledTask is { IsCanceled: true } &&
                r.CancelToken.IsCancellationRequested && r.CancelState == NativeProvisioningState.Pending;
    }

    internal bool OwnsStatusNotificationCreateCancellationCompletion(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask, Task statusTask)
    {
        lock (gate)
            return OwnsNotificationCreateCanceledStatusAttempt(window, binding, client, scope, receipt,
                startTask, handle, canceledTask) && statusVaultCancellations.TryGetValue(window, out var r) &&
                ReferenceEquals(r.StatusTask, statusTask) && !ReferenceEquals(canceledTask, statusTask) &&
                r.Complete && r.Checked.Task.IsCompletedSuccessfully && completedStatusReads.Contains(window) &&
                r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                StatusNotificationCreateWiresValid(r);
    }

    private static bool StatusNotificationCreateWiresValid(StatusVaultCancellationRegistration r) =>
        r.NotificationCreateProof is not null && r.StartReceipt == DispatchEvidence.Pending &&
        r.StartWire is { Ordinal: 0, HttpStatus: 201, State: WireState.Pending, Complete: true } start &&
        r.Target is { Kind: StatusTargetKind.SelectedResource } target &&
        target.StartDispatch == start.Dispatch && target.StartResponseSha256 == start.ResponseSha256 &&
        r.StatusSends == 1 && r.StatusWires is
            [{ Ordinal: 1, HttpStatus: 200, State: WireState.Succeeded, Complete: true } status] &&
        status.Uri == target.TargetUri.AbsoluteUri && status.Dispatch != start.Dispatch &&
        !ReferenceEquals(status.Request, start.Request);

    internal bool TryGetStatusNotificationUpdateCancellationStart(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, [NotNullWhen(true)] out StatusNotificationUpdateCancellationStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusVaultCancellations.TryGetValue(window, out var r) ||
                !NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(r.Binding.Selector) ||
                !ReferenceEquals(r.Binding, binding) || !ReferenceEquals(r.Client, client) ||
                !ReferenceEquals(r.ActualOriginalScope, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.StartTask, startTask) || !ReferenceEquals(r.Handle, handle) ||
                !StatusVaultCancellationStartValid(r) || r.NotificationUpdateProof is null ||
                r.StartReceipt != DispatchEvidence.Pending || receipt.Evidence != DispatchEvidence.Pending ||
                r.StartState != NativeProvisioningState.Pending ||
                !(handle.State == NativeProvisioningState.Pending ||
                    r.Complete && handle.State == NativeProvisioningState.Succeeded)) return false;
            proof = r.NotificationUpdateProof;
            return true;
        }
    }

    internal bool OwnsNotificationUpdateCanceledStatusAttempt(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask)
    {
        lock (gate)
            return TryGetStatusNotificationUpdateCancellationStart(window, binding, client, scope, receipt,
                startTask, handle, out _) && statusVaultCancellations.TryGetValue(window, out var r) &&
                ReferenceEquals(r.CanceledTask, canceledTask) && r.CancelComplete &&
                r.Canceled.Task.IsCompletedSuccessfully && r.CanceledTask is { IsCanceled: true } &&
                r.CancelToken.IsCancellationRequested && r.CancelState == NativeProvisioningState.Pending;
    }

    internal bool OwnsStatusNotificationUpdateCancellationCompletion(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask, Task statusTask)
    {
        lock (gate)
            return OwnsNotificationUpdateCanceledStatusAttempt(window, binding, client, scope, receipt,
                startTask, handle, canceledTask) && statusVaultCancellations.TryGetValue(window, out var r) &&
                ReferenceEquals(r.StatusTask, statusTask) && !ReferenceEquals(canceledTask, statusTask) &&
                r.Complete && r.Checked.Task.IsCompletedSuccessfully && completedStatusReads.Contains(window) &&
                r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                StatusNotificationUpdateWiresValid(r);
    }

    private static bool StatusNotificationUpdateWiresValid(StatusVaultCancellationRegistration r) =>
        r.NotificationUpdateProof is not null && r.StartReceipt == DispatchEvidence.Pending &&
        r.StartWire is { Ordinal: 0, HttpStatus: 201, State: WireState.Pending, Complete: true } start &&
        r.Target is { Kind: StatusTargetKind.SelectedResource } target &&
        target.StartDispatch == start.Dispatch && target.StartResponseSha256 == start.ResponseSha256 &&
        r.StatusSends == 1 && r.StatusWires is
            [{ Ordinal: 1, HttpStatus: 200, State: WireState.Succeeded, Complete: true } status] &&
        status.Uri == target.TargetUri.AbsoluteUri && status.Dispatch != start.Dispatch &&
        !ReferenceEquals(status.Request, start.Request);

    internal bool TryGetStatusNotificationDeleteCancellationStart(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, [NotNullWhen(true)] out StatusNotificationDeleteCancellationStartProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !statusVaultCancellations.TryGetValue(window, out var r) ||
                !NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(r.Binding.Selector) ||
                !ReferenceEquals(r.Binding, binding) || !ReferenceEquals(r.Client, client) ||
                !ReferenceEquals(r.ActualOriginalScope, scope) || !ReferenceEquals(r.Receipt, receipt) ||
                !ReferenceEquals(r.StartTask, startTask) || !ReferenceEquals(r.Handle, handle) ||
                !StatusVaultCancellationStartValid(r) || r.NotificationProof is null ||
                r.Target is not null || r.Receipt.Evidence != DispatchEvidence.Applied ||
                handle.State != NativeProvisioningState.Succeeded) return false;
            proof = r.NotificationProof;
            return true;
        }
    }

    internal bool OwnsNotificationDeleteCanceledStatusAttempt(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask)
    {
        lock (gate)
            return TryGetStatusNotificationDeleteCancellationStart(window, binding, client, scope, receipt,
                startTask, handle, out _) && statusVaultCancellations.TryGetValue(window, out var r) &&
                ReferenceEquals(r.CanceledTask, canceledTask) && r.CancelComplete &&
                r.Canceled.Task.IsCompletedSuccessfully && r.CanceledTask is { IsCanceled: true } &&
                r.CancelToken.IsCancellationRequested && r.StatusSends == 0 && r.StatusWires.Count == 0;
    }

    internal bool OwnsStatusNotificationDeleteCancellationCompletion(Window window, Binding binding,
        VaultAdministration client, NotificationScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask, Task statusTask)
    {
        lock (gate)
            return TryGetStatusNotificationDeleteCancellationStart(window, binding, client, scope, receipt,
                startTask, handle, out _) && statusVaultCancellations.TryGetValue(window, out var r) &&
                OwnsNotificationDeleteCanceledStatusAttempt(window, binding, client, scope, receipt,
                    startTask, handle, canceledTask) &&
                ReferenceEquals(r.StatusTask, statusTask) && !ReferenceEquals(canceledTask, statusTask) &&
                r.Complete && r.Checked.Task.IsCompletedSuccessfully &&
                r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                !completedStatusReads.Contains(window);
    }

    internal bool OwnsCanceledStatusAttempt(Window window, Binding binding, VaultAdministration client,
        VaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task canceledTask)
    {
        lock (gate)
            return window is not null && statusVaultCancellations.TryGetValue(window, out var r) &&
                VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(r.Binding.Selector) &&
                ReferenceEquals(r.Binding, binding) && ReferenceEquals(r.Client, client) &&
                ReferenceEquals(r.ActualOriginalScope, scope) && ReferenceEquals(r.Receipt, receipt) &&
                ReferenceEquals(r.StartTask, startTask) && ReferenceEquals(r.Handle, handle) &&
                ReferenceEquals(r.CanceledTask, canceledTask) && StatusVaultCancellationStartValid(r) &&
                r.CancelComplete && r.Canceled.Task.IsCompletedSuccessfully &&
                r.CanceledTask is { IsCanceled: true } && r.CancelToken.IsCancellationRequested &&
                r.Receipt.Evidence == r.StartReceipt && handle.State == NativeProvisioningState.Succeeded;
    }

    internal bool OwnsStatusVaultDeleteCancellationCompletion(Window window, Binding binding,
        VaultAdministration client, VaultScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask, Task statusTask)
    {
        lock (gate)
            return OwnsCanceledStatusAttempt(window, binding, client, scope, receipt, startTask, handle, canceledTask) &&
                statusVaultCancellations.TryGetValue(window, out var r) &&
                ReferenceEquals(r.StatusTask, statusTask) && r.Complete && r.Checked.Task.IsCompletedSuccessfully &&
                r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested;
    }

    internal bool OwnsPurgeCanceledStatusAttempt(Window window, Binding binding, VaultAdministration client,
        DeletedVaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task canceledTask)
    {
        lock (gate)
            return window is not null && statusVaultCancellations.TryGetValue(window, out var r) &&
                VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(r.Binding.Selector) &&
                ReferenceEquals(r.Binding, binding) && ReferenceEquals(r.Client, client) &&
                ReferenceEquals(r.ActualOriginalScope, scope) && ReferenceEquals(r.Receipt, receipt) &&
                ReferenceEquals(r.StartTask, startTask) && ReferenceEquals(r.Handle, handle) &&
                ReferenceEquals(r.CanceledTask, canceledTask) && StatusVaultCancellationStartValid(r) &&
                r.StartState == NativeProvisioningState.Pending && r.CancelState == NativeProvisioningState.Pending &&
                r.StartReceipt == DispatchEvidence.Pending && r.Receipt.Evidence == r.StartReceipt &&
                r.CancelComplete && r.Canceled.Task.IsCompletedSuccessfully &&
                r.CanceledTask is { IsCanceled: true } && r.CancelToken.IsCancellationRequested &&
                (handle.State == NativeProvisioningState.Pending ||
                    r.Complete && handle.State == NativeProvisioningState.Succeeded);
    }

    internal bool OwnsStatusVaultPurgeCancellationCompletion(Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask, Task statusTask)
    {
        lock (gate)
            return OwnsPurgeCanceledStatusAttempt(window, binding, client, scope, receipt, startTask, handle, canceledTask) &&
                statusVaultCancellations.TryGetValue(window, out var r) &&
                ReferenceEquals(r.StatusTask, statusTask) && r.Complete && r.Checked.Task.IsCompletedSuccessfully &&
                r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                completedStatusReads.Contains(window) && StatusVaultPurgeWiresValid(r);
    }

    private static bool StatusVaultPurgeWiresValid(StatusVaultCancellationRegistration r) =>
        r.StartWire is { Ordinal: 0, HttpStatus: 202, State: WireState.Pending, Complete: true } start &&
        r.Target is { } target && target.StartDispatch == start.Dispatch &&
        target.StartResponseSha256 == start.ResponseSha256 && r.StatusSends == 2 &&
        r.StatusWires is [var first, var second] &&
        first is { Ordinal: 1, HttpStatus: 200, State: WireState.Succeeded, Complete: true } &&
        second is { Ordinal: 2, HttpStatus: 200, State: WireState.Succeeded, Complete: true } &&
        first.Uri == target.TargetUri.AbsoluteUri && second.Uri == first.Uri &&
        first.Dispatch != second.Dispatch && !ReferenceEquals(first.Request, second.Request);

    internal bool OwnsRecoverCanceledStatusAttempt(Window window, Binding binding, VaultAdministration client,
        VaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task canceledTask)
    {
        lock (gate)
            return window is not null && statusVaultCancellations.TryGetValue(window, out var r) &&
                VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(r.Binding.Selector) &&
                ReferenceEquals(r.Binding, binding) && ReferenceEquals(r.Client, client) &&
                ReferenceEquals(r.ActualOriginalScope, scope) && ReferenceEquals(r.Receipt, receipt) &&
                ReferenceEquals(r.StartTask, startTask) && ReferenceEquals(r.Handle, handle) &&
                ReferenceEquals(r.CanceledTask, canceledTask) && StatusVaultCancellationStartValid(r) &&
                r.StartState == NativeProvisioningState.Pending && r.CancelState == NativeProvisioningState.Pending &&
                r.StartReceipt == DispatchEvidence.Pending && r.Receipt.Evidence == r.StartReceipt &&
                r.CancelComplete && r.Canceled.Task.IsCompletedSuccessfully &&
                r.CanceledTask is { IsCanceled: true } && r.CancelToken.IsCancellationRequested &&
                (handle.State == NativeProvisioningState.Pending ||
                    r.Complete && handle.State == NativeProvisioningState.Succeeded);
    }

    internal bool OwnsStatusVaultRecoverCancellationCompletion(Window window, Binding binding,
        VaultAdministration client, VaultScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask, Task statusTask)
    {
        lock (gate)
            return OwnsRecoverCanceledStatusAttempt(window, binding, client, scope, receipt, startTask, handle, canceledTask) &&
                statusVaultCancellations.TryGetValue(window, out var r) &&
                ReferenceEquals(r.StatusTask, statusTask) && r.Complete && r.Checked.Task.IsCompletedSuccessfully &&
                r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                completedStatusReads.Contains(window) && StatusVaultRecoverWiresValid(r);
    }

    private static bool StatusVaultRecoverWiresValid(StatusVaultCancellationRegistration r) =>
        r.RecoveryConfiguration is not null &&
        r.StartWire is
        {
            Ordinal: 0, HttpStatus: 201, State: WireState.Pending, Complete: true,
            RequestSha256.Length: 64, RequestHeaders: not null
        } start &&
        r.Target is { } target && target.StartDispatch == start.Dispatch &&
        target.StartResponseSha256 == start.ResponseSha256 && r.StatusSends == 2 &&
        r.StatusWires is [var first, var second] &&
        first is { Ordinal: 1, HttpStatus: 200, State: WireState.Succeeded, Complete: true } &&
        second is { Ordinal: 2, HttpStatus: 200, State: WireState.Succeeded, Complete: true } &&
        first.Uri == target.TargetUri.AbsoluteUri &&
        second.Uri == Origin + r.Window.Path + "?api-version=" + r.Binding.ApiRevision &&
        first.Dispatch != second.Dispatch && !ReferenceEquals(first.Request, second.Request);

    internal bool OwnsUpdateCanceledStatusAttempt(Window window, Binding binding, VaultAdministration client,
        VaultScope scope, ManagementReceipt receipt, Task startTask, ManagementOperation handle, Task canceledTask)
    {
        lock (gate)
            return window is not null && statusVaultCancellations.TryGetValue(window, out var r) &&
                VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(r.Binding.Selector) &&
                ReferenceEquals(r.Binding, binding) && ReferenceEquals(r.Client, client) &&
                ReferenceEquals(r.ActualOriginalScope, scope) && ReferenceEquals(r.Receipt, receipt) &&
                ReferenceEquals(r.StartTask, startTask) && ReferenceEquals(r.Handle, handle) &&
                ReferenceEquals(r.CanceledTask, canceledTask) && StatusVaultCancellationStartValid(r) &&
                r.UpdateConfiguration is not null && r.RecoveryConfiguration is null &&
                r.StartState == NativeProvisioningState.Pending && r.CancelState == NativeProvisioningState.Pending &&
                r.StartReceipt == DispatchEvidence.Pending && r.Receipt.Evidence == r.StartReceipt &&
                r.CancelComplete && r.Canceled.Task.IsCompletedSuccessfully &&
                r.CanceledTask is { IsCanceled: true } && r.CancelToken.IsCancellationRequested &&
                (handle.State == NativeProvisioningState.Pending ||
                    r.Complete && handle.State == NativeProvisioningState.Succeeded);
    }

    internal bool OwnsStatusVaultUpdateCancellationCompletion(Window window, Binding binding,
        VaultAdministration client, VaultScope scope, ManagementReceipt receipt, Task startTask,
        ManagementOperation handle, Task canceledTask, Task statusTask)
    {
        lock (gate)
            return OwnsUpdateCanceledStatusAttempt(window, binding, client, scope, receipt, startTask, handle, canceledTask) &&
                statusVaultCancellations.TryGetValue(window, out var r) &&
                ReferenceEquals(r.StatusTask, statusTask) && !ReferenceEquals(r.CanceledTask, statusTask) &&
                r.Complete && r.Checked.Task.IsCompletedSuccessfully &&
                r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                completedStatusReads.Contains(window) && StatusVaultUpdateWiresValid(r);
    }

    private static bool StatusVaultUpdateWiresValid(StatusVaultCancellationRegistration r) =>
        r.UpdateConfiguration is not null && r.RecoveryConfiguration is null &&
        r.StartWire is
        {
            Ordinal: 0, HttpStatus: 201, State: WireState.Pending, Complete: true,
            RequestSha256.Length: 64, RequestHeaders: not null
        } start &&
        r.Target is { } target && target.StartDispatch == start.Dispatch &&
        target.StartResponseSha256 == start.ResponseSha256 && r.StatusSends == 2 &&
        r.StatusWires is [var first, var second] &&
        first is { Ordinal: 1, HttpStatus: 200, State: WireState.Succeeded, Complete: true } &&
        second is { Ordinal: 2, HttpStatus: 200, State: WireState.Succeeded, Complete: true } &&
        first.Uri == target.TargetUri.AbsoluteUri &&
        second.Uri == Origin + r.Window.Path + "?api-version=" + r.Binding.ApiRevision &&
        first.Dispatch != second.Dispatch && !ReferenceEquals(first.Request, second.Request);

    private static bool StatusVaultCancellationStartValid(StatusVaultCancellationRegistration r) =>
        !r.Invalid && !r.Sealed && r.StartComplete && r.Started.Task.IsCompletedSuccessfully &&
        r.StartTask is { IsCompletedSuccessfully: true } &&
        (VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(r.Binding.Selector)
            ? r.PrivateDeleteProof is not null && r.Target is null && r.StartReceipt == DispatchEvidence.Pending
            : VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(r.Binding.Selector)
            ? r.PrivateProof is not null && r.Target is null && r.StartReceipt == DispatchEvidence.Applied
            : RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(r.Binding.Selector)
            ? r.RoleProof is not null && r.Target is null && r.StartReceipt == DispatchEvidence.Applied
            : NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(r.Binding.Selector)
            ? r.NotificationProof is not null && r.Target is null && r.StartReceipt == DispatchEvidence.Applied
            : NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(r.Binding.Selector)
            ? r.NotificationUpdateProof is not null && r.Target is not null && r.StartReceipt == DispatchEvidence.Pending
            : NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(r.Binding.Selector)
            ? r.NotificationCreateProof is not null && r.Target is not null && r.StartReceipt == DispatchEvidence.Pending
            : r.Target is not null) &&
        !r.StartToken.IsCancellationRequested;

    internal Task<SecretStatus> CheckCanceledStatusAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained = null)
    {
        bool cancellation;
        lock (gate) cancellation = statusSucceededDeleteVaultCancellation.ContainsKey(window);
        return cancellation ? CheckStatusSucceededDeleteVaultCancellationAsync(window, selector, handle, token, retained, canceled: true)
            : CheckStatusVaultCancellationAsync(window, selector, handle, token, retained, canceled: true);
    }

    private async Task<SecretStatus> CheckStatusVaultCancellationAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained, bool canceled)
    {
        StatusVaultCancellationRegistration r;
        Invocation invocation;
        lock (gate)
        {
            Own(window, selector);
            Require(statusVaultCancellations.TryGetValue(window, out r!));
            bool purge = VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(selector);
            bool recover = VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector);
            bool update = VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector);
            bool privateDelete = VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(selector);
            bool notificationUpdate = NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector) ||
                NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector);
            // Foreign handles cannot poison an owned registration. Once the
            // original handle is identified, an invalid first attempt is final.
            Require(ReferenceEquals(r.Handle, handle));
            if (privateDelete && (r.NormalStatus is not null || window.Status is not null ||
                (canceled ? !token.IsCancellationRequested || r.PrivateCancel is not null :
                    token.IsCancellationRequested || !r.CancelComplete ||
                        !r.Canceled.Task.IsCompletedSuccessfully || r.CanceledTask is not { IsCanceled: true })))
                r.Invalid = true;
            Require(!window.Closed &&
                (purge || recover || update || VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(selector) ||
                    privateDelete ||
                    VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(selector) ||
                    RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(selector) ||
                    NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(selector) || notificationUpdate) &&
                StatusVaultCancellationStartValid(r) && ReferenceEquals(r.Handle, handle) &&
                handle.State == (privateDelete ? r.StartState :
                    purge || recover || update || notificationUpdate ? NativeProvisioningState.Pending : NativeProvisioningState.Succeeded) &&
                r.Receipt.Evidence == r.StartReceipt &&
                r.NormalStatus is null && window.Status is null);
            if (notificationUpdate && (canceled
                    ? !token.IsCancellationRequested || r.PrivateCancel is not null
                    : token.IsCancellationRequested || !r.CancelComplete ||
                        !r.Canceled.Task.IsCompletedSuccessfully || r.CanceledTask is not { IsCanceled: true }))
                r.Invalid = true;
            if (canceled)
            {
                Require(token.IsCancellationRequested && r.PrivateCancel is null);
                invocation = r.PrivateCancel = new();
                r.CancelToken = token;
            }
            else
            {
                Require(!token.IsCancellationRequested && r.CancelComplete &&
                    r.Canceled.Task.IsCompletedSuccessfully && r.CanceledTask is { IsCanceled: true });
                invocation = r.NormalStatus = window.Status = new();
                r.StatusToken = token;
            }
            statusVaultCancellationInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretStatus> task;
            var previous = current.Value;
            current.Value = new(window, invocation, true);
            try { task = handle.CheckStatusAsync(token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate)
            {
                invocation.SdkTask = task;
                if (canceled) r.CanceledTask = task;
                else r.StatusTask = task;
            }
            try
            {
                retained?.Invoke(task);
                lock (gate)
                {
                    if (canceled) r.CancelHookReturned = true;
                    else r.StatusHookReturned = true;
                }
            }
            finally
            {
                // Await the actual SDK task even when retention throws. Only
                // cancellation thrown by this await can establish propagation.
                try
                {
                    var outcome = await task.ConfigureAwait(false);
                    lock (gate)
                    {
                        invocation.Outcome = outcome;
                        invocation.WrapperState = handle.State;
                        if (canceled) r.Invalid = true;
                        else r.StatusSucceeded = task.IsCompletedSuccessfully && outcome == SecretStatus.Success &&
                            handle.State == NativeProvisioningState.Succeeded;
                    }
                }
                catch (OperationCanceledException) when (canceled && task.IsCanceled)
                {
                    lock (gate)
                    {
                        r.CancelState = handle.State;
                        r.CancellationPropagated = true;
                    }
                    throw;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate)
            {
                invocation.Canceled = true;
                r.Invalid |= !canceled || !r.CancelHookReturned || !r.CancellationPropagated;
            }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishAsync(invocation).ConfigureAwait(false); }
    }

    internal HttpPipelineTransport SelectedTransport { get; }

    internal ManagementOperationNativeCapture(HttpPipelineTransport backend, int maximumBytes = 65536)
    {
        if (backend is null || maximumBytes is < 1024 or > 1024 * 1024)
            throw new ArgumentException("management-capture-input");
        this.backend = backend;
        this.maximumBytes = maximumBytes;
        SelectedTransport = new InvocationTransport(this);
    }

    internal Window Arm(Binding binding)
    {
        Require(binding is not null && binding.Selector is not null && binding.Resource is not null &&
            binding.Selector.Nonce != Guid.Empty && binding.LeaseId != Guid.Empty &&
            Segment(binding.Location, 50) &&
            new[] { binding.Selector.Scope, binding.Selector.Operation, binding.Selector.Variant, binding.Selector.Case }
                .All(s => !string.IsNullOrWhiteSpace(s) && s.Length <= 1024 && !s.Any(char.IsControl)) &&
            binding.Selector.Operation == ManagementOperationEffects.Members[0].Operation &&
            (binding.Selector.Variant == "operation." + binding.Operation ||
                ManagementOperationEffects.Members[0].Variants.Contains(binding.Selector.Variant) &&
                binding.Selector.Variant.StartsWith("status.", StringComparison.Ordinal)));
        var (path, method, revision) = Route(binding);
        Require(binding.ApiRevision == revision);
        lock (gate)
        {
            Require(nonces.Count < 32 && !nonces.Contains(binding.Selector.Nonce) && !leases.Contains(binding.LeaseId));
            nonces.Add(binding.Selector.Nonce);
            leases.Add(binding.LeaseId);
            var window = new Window(owner, binding, path, method);
            targets.Add(window, null);
            return window;
        }
    }

    internal sealed class PrivateConnectionDeleteDenied
    {
        public override string ToString() => "[PrivateConnectionDeleteDenied]";
    }

    internal sealed class PrivateConnectionDeleteCandidate(string endpointId, string responseSha256)
    {
        [JsonIgnore] internal string EndpointId { get; } = endpointId;
        [JsonIgnore] internal string ResponseSha256 { get; } = responseSha256;
        public override string ToString() => "[PrivateConnectionDeleteCandidate]";
    }

    internal sealed class PrivateConnectionDeleteCompletion
    {
        public override string ToString() => "[PrivateConnectionDeleteCompletion]";
    }

    private sealed class PrivateConnectionDeleteRegistration(Window window, Invocation start,
        VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt,
        CancellationToken token, Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly Invocation Start = start;
        internal readonly VaultAdministration Client = client;
        internal readonly PrivateConnectionScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken Token = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly List<OwnedArmResponse.ParserCustody> Parsers = [];
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task<Capture>? SealTask;
        internal ManagementOperation? Handle;
        internal Request? Request;
        internal string? RequestUri;
        internal (string Name, string Value)[]? RequestHeaders;
        internal readonly List<PrivateDeleteResponse> Responses = [];
        internal PrivateConnectionDeleteDenied? Denied;
        internal PrivateApprovalFacts? Facts;
        internal PrivateConnectionDeleteCandidate? Candidate;
        internal PrivateConnectionDeleteCompletion? Completion;
        internal DispatchEvidence? StartReceipt, CheckReceipt;
        internal CancellationToken CheckToken;
        internal bool StartSucceeded, TransportSucceeded, CheckHookReturned, CheckSucceeded, CheckCanceled;
        internal bool HookReturned, Invalid, Sealed, DeniedResponse, CheckClaimed;
        internal int Sends, CheckSends;
    }

    private sealed record PrivateDeleteResponse(int Status, (string Name, string Value)[] Headers,
        string Sha256, string? NativeRequestId);

    internal Window ArmPrivateConnectionDelete(Binding binding)
    {
        Require(binding is not null && binding.Selector is not null &&
            VaultFixtureProvisioner.PrivateConnectionDeleteSelector(binding.Selector) &&
            binding.Selector.Nonce != Guid.Empty && binding.LeaseId != Guid.Empty &&
            binding.Resource is PrivateConnectionScope && binding.Operation == ManagementMutation.DeletePrivateConnection &&
            binding.ApiRevision == "2026-02-01" && Segment(binding.Location, 50));
        var route = Route(binding);
        lock (gate)
        {
            Require(nonces.Count < 32 && nonces.Add(binding.Selector.Nonce) && leases.Add(binding.LeaseId));
            var window = new Window(owner, binding, route.Path, route.Method);
            targets.Add(window, null);
            privateDeleteWindows.Add(window);
            return window;
        }
    }

    internal Task<SecretOutcome<ManagementOperation>> StartPrivateConnectionDeleteAsync(Window window,
        FixtureSelector selector, VaultAdministration client, PrivateConnectionScope scope,
        ManagementReceipt receipt, CancellationToken token = default,
        Action<Task>? retainedActualTaskCallback = null, Action? beforeSend = null) =>
        StartCoreAsync(window, selector, client, scope, null, receipt, token,
            retainedActualTaskCallback, beforeSend, originalPrivateDelete: true);

    internal bool TryGetPrivateConnectionDeleteDenied(Window window, Binding binding,
        [NotNullWhen(true)] out PrivateConnectionDeleteDenied? evidence)
    {
        lock (gate)
        {
            evidence = null;
            if (window is null || !privateDeletes.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.Binding, binding) || r.Invalid || r.Sealed || !r.HookReturned ||
                r.Token.IsCancellationRequested || r.StartTask is not { IsCompletedSuccessfully: true } ||
                !r.Started.Task.IsCompletedSuccessfully || r.StartTask.Result.Status != SecretStatus.Denied ||
                r.Handle is not null || r.Receipt.Evidence != DispatchEvidence.Rejected ||
                r.Sends != 1 || r.Request is null || r.RequestHeaders is null ||
                r.RequestUri != Origin + r.Window.Path + "?api-version=" + r.Binding.ApiRevision ||
                r.Responses is not [{ Status: 403, NativeRequestId: not null }] || !r.DeniedResponse ||
                r.Parsers.Count != 1 || r.Parsers[0] is not { Complete: true, Invalid: false }) return false;
            evidence = r.Denied ??= new();
            return true;
        }
    }

    internal bool OwnsPrivateConnectionDeleteDenied(PrivateConnectionDeleteDenied evidence, Window window,
        Binding binding, VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt,
        Task originalStartTask)
    {
        lock (gate)
            return TryGetPrivateConnectionDeleteDenied(window, binding, out var issued) &&
                ReferenceEquals(evidence, issued) && privateDeletes.TryGetValue(window, out var r) &&
                ReferenceEquals(r.Client, client) && ReferenceEquals(r.Scope, scope) &&
                ReferenceEquals(binding.Resource, scope) && ReferenceEquals(r.Receipt, receipt) &&
                ReferenceEquals(r.StartTask, originalStartTask);
    }

    internal bool TryGetPrivateConnectionDeleteCandidate(Window window, Binding binding,
        [NotNullWhen(true)] out PrivateConnectionDeleteCandidate? candidate)
    {
        lock (gate)
        {
            candidate = null;
            if (window is null || !privateDeletes.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.Binding, binding) || r.Invalid || r.Sealed || !r.HookReturned ||
                !r.StartSucceeded || !r.TransportSucceeded || r.Token.IsCancellationRequested ||
                r.StartTask is not { IsCompletedSuccessfully: true } || !r.StartTask.Result.IsSuccess ||
                !r.Started.Task.IsCompletedSuccessfully || r.Handle is null ||
                r.StartReceipt != DispatchEvidence.Pending || r.Receipt.Evidence != DispatchEvidence.Pending ||
                r.Sends != 1 || r.Request is null || r.RequestHeaders is null ||
                r.RequestUri != Origin + r.Window.Path + "?api-version=" + r.Binding.ApiRevision ||
                r.Facts is null || r.Parsers.Count != 1 || r.Parsers[0].Invalid ||
                r.Responses is not [{ Status: 200, NativeRequestId: { } requestId } response] ||
                !Segment(requestId, 256)) return false;
            // Raw/native side decoding never reads the custody envelope. Native
            // model consumption may still be deferred until the original check.
            candidate = r.Candidate ??= new(r.Facts.EndpointId, response.Sha256);
            return true;
        }
    }

    internal bool OwnsPrivateConnectionDeleteCandidate(PrivateConnectionDeleteCandidate candidate,
        Window window, Binding binding, VaultAdministration client, PrivateConnectionScope scope,
        ManagementReceipt receipt, Task originalStartTask, ManagementOperation originalHandle)
    {
        lock (gate)
            return TryGetPrivateConnectionDeleteCandidate(window, binding, out var issued) &&
                ReferenceEquals(candidate, issued) && privateDeletes.TryGetValue(window, out var r) &&
                ReferenceEquals(r.Client, client) && ReferenceEquals(r.Scope, scope) &&
                ReferenceEquals(binding.Resource, scope) && ReferenceEquals(r.Receipt, receipt) &&
                ReferenceEquals(r.StartTask, originalStartTask) && ReferenceEquals(r.Handle, originalHandle);
    }

    internal bool TryGetPrivateConnectionDeleteCompletion(PrivateConnectionDeleteCandidate candidate,
        Window window, Binding binding, [NotNullWhen(true)] out PrivateConnectionDeleteCompletion? proof)
    {
        lock (gate)
        {
            proof = null;
            if (!TryGetPrivateConnectionDeleteCandidate(window, binding, out var issued) ||
                !ReferenceEquals(candidate, issued) || !privateDeletes.TryGetValue(window, out var r) ||
                !r.CheckClaimed || !r.CheckHookReturned || !r.CheckSucceeded || r.CheckCanceled ||
                r.CheckToken.IsCancellationRequested || r.CheckSends != 0 ||
                r.StatusTask is not { IsCompletedSuccessfully: true } || r.StatusTask.Result != SecretStatus.Success ||
                !r.Checked.Task.IsCompletedSuccessfully || r.Handle?.State != NativeProvisioningState.Succeeded ||
                r.CheckReceipt != DispatchEvidence.Pending ||
                r.Parsers[0] is not { Complete: true, Invalid: false }) return false;
            proof = r.Completion ??= new();
            return true;
        }
    }

    internal bool OwnsPrivateConnectionDeleteCompletion(PrivateConnectionDeleteCompletion proof,
        Window window, Binding binding, VaultAdministration client, PrivateConnectionScope scope,
        ManagementReceipt receipt, Task originalStartTask, ManagementOperation originalHandle, Task originalCheckTask)
    {
        lock (gate)
            return TryGetPrivateConnectionDeleteCandidate(window, binding, out var candidate) &&
                OwnsPrivateConnectionDeleteCandidate(candidate, window, binding, client, scope, receipt,
                    originalStartTask, originalHandle) &&
                TryGetPrivateConnectionDeleteCompletion(candidate, window, binding, out var issued) &&
                ReferenceEquals(proof, issued) && privateDeletes.TryGetValue(window, out var r) &&
                ReferenceEquals(r.StatusTask, originalCheckTask);
    }

    // Preserve actual outcomes for ineligible shapes; freeze any completion
    // before this one-shot drain erases its original parser storage.
    private Task<Capture> SealPrivateConnectionDeleteAsync(Window window)
    {
        PrivateConnectionDeleteRegistration r;
        TaskCompletionSource start;
        Task<Capture> task;
        lock (gate)
        {
            Own(window, window.Binding.Selector);
            window.Closed = true;
            if (!privateDeletes.TryGetValue(window, out r!))
                return Task.FromResult(new Capture { Binding = window.Binding });
            if (r.SealTask is not null) return r.SealTask;
            r.Sealed = true;
            start = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = r.SealTask = Drain(start.Task);
        }
        start.SetResult();
        return task;

        async Task<Capture> Drain(Task ready)
        {
            await ready.ConfigureAwait(false);
            await r.Started.Task.ConfigureAwait(false);
            if (r.CheckClaimed) await r.Checked.Task.ConfigureAwait(false);
            try { r.Storage.Dispose(); }
            catch { r.Invalid = true; throw; }
            return new() { Binding = r.Binding, Start = window.Start, Status = window.Status };
        }
    }

    internal sealed class PrivateConnectionUpdateStart(int? httpStatus, SecretStatus outcome,
        PrivateConnectionState requested, string? endpointId)
    {
        internal int? HttpStatus { get; } = httpStatus;
        internal SecretStatus Outcome { get; } = outcome;
        internal PrivateConnectionState Requested { get; } = requested;
        internal string? EndpointId { get; } = endpointId;
        public override string ToString() => "[PrivateConnectionUpdateStart]";
    }

    private sealed record PrivateConnectionUpdateContext(PrivateConnectionUpdateRegistration Registration, bool Check);
    private sealed class PrivateConnectionUpdateRegistration(Window window, VaultAdministration client,
        PrivateConnectionScope scope, PrivateConnectionState requested, ManagementReceipt receipt,
        CancellationToken token, Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly VaultAdministration Client = client;
        internal readonly PrivateConnectionScope Scope = scope;
        internal readonly PrivateConnectionState Requested = requested;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken Token = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly HashSet<Request> Requests = new(ReferenceEqualityComparer.Instance);
        internal readonly List<Task> Sends = [];
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task<Capture>? SealTask;
        internal OwnedArmResponse.ParserCustody? Parser;
        internal ManagementOperation? Handle;
        internal PrivateConnectionUpdateStart? Evidence;
        internal PrivateApprovalFacts? Facts;
        internal Request? Request;
        internal int? HttpStatus;
        internal int StartSends, CheckSends;
        internal bool Invalid, HookReturned, Denied, CheckClaimed, CheckSucceeded, Sealed;
        internal CancellationToken CheckToken;
    }

    internal Window ArmPrivateConnectionUpdate(Binding binding, PrivateConnectionState requested)
    {
        Require(binding is not null && VaultFixtureProvisioner.PrivateConnectionUpdateSelector(binding.Selector) &&
            binding.Selector.Nonce != Guid.Empty && binding.LeaseId != Guid.Empty &&
            binding.Resource is PrivateConnectionScope && binding.Operation == ManagementMutation.UpdatePrivateConnection &&
            binding.ApiRevision == "2026-02-01" && Segment(binding.Location, 50) &&
            requested == Enum.Parse<PrivateConnectionState>(binding.Selector.Variant.Split('.')[1]));
        var route = Route(binding);
        lock (gate)
        {
            Require(nonces.Count < 32 && nonces.Add(binding.Selector.Nonce) && leases.Add(binding.LeaseId));
            var window = new Window(owner, binding, route.Path, route.Method);
            targets.Add(window, null);
            privateUpdateWindows.Add(window, requested);
            return window;
        }
    }

    internal async Task<SecretOutcome<ManagementOperation>> StartPrivateConnectionUpdateAsync(Window window,
        FixtureSelector selector, VaultAdministration client, PrivateConnectionScope scope, PrivateConnectionState requested,
        ManagementReceipt receipt, CancellationToken token = default,
        Action<Task>? retainedActualTaskCallback = null, Action? beforeSend = null)
    {
        PrivateConnectionUpdateRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(privateUpdateWindows.TryGetValue(window, out var expected) && expected == requested &&
                !window.Closed && !privateUpdates.ContainsKey(window) && ReferenceEquals(window.Binding.Resource, scope) &&
                client is not null && receipt is not null);
            r = new(window, client, scope, requested, receipt, token, beforeSend);
            privateUpdates.Add(window, r);
        }
        try
        {
            var previous = currentPrivateUpdate.Value;
            currentPrivateUpdate.Value = new(r, false);
            try { r.StartTask = client.UpdatePrivateConnectionAsync(scope, requested, receipt, token).AsTask(); }
            finally { currentPrivateUpdate.Value = previous; }
            SecretOutcome<ManagementOperation> result;
            try { retainedActualTaskCallback?.Invoke(r.StartTask); r.HookReturned = true; }
            finally
            {
                result = await r.StartTask.ConfigureAwait(false);
                if (result.IsSuccess) r.Handle = result.Value;
            }
            await Task.WhenAll(r.Sends).ConfigureAwait(false);
            lock (gate)
            {
                bool rejected = requested is not (PrivateConnectionState.Approved or PrivateConnectionState.Rejected);
                if (!r.Invalid && r.HookReturned &&
                    (rejected
                        ? result.Status == SecretStatus.Invalid && r.StartSends == 0 && r.Requests.Count == 0 &&
                            r.Handle is null && receipt.Evidence == DispatchEvidence.NotDispatched
                        : !token.IsCancellationRequested && r.StartSends == 1 && r.Parser is { Complete: true, Invalid: false } &&
                            (r.Facts is not null && r.HttpStatus == 200 && result.IsSuccess &&
                                r.Handle?.State == NativeProvisioningState.Succeeded && receipt.Evidence == DispatchEvidence.Applied ||
                             r.Denied && r.HttpStatus == 403 && result.Status == SecretStatus.Denied &&
                                r.Handle is null && receipt.Evidence == DispatchEvidence.Rejected)))
                    r.Evidence = new(r.HttpStatus, result.Status, requested, r.Facts?.EndpointId);
            }
            return result;
        }
        catch { r.Invalid = true; throw; }
        finally
        {
            try { await Task.WhenAll(r.Sends).ConfigureAwait(false); }
            catch (Exception) { r.Invalid = true; }
            r.Started.TrySetResult();
        }
    }

    internal bool TryGetPrivateConnectionUpdateStart(Window window, Binding binding,
        [NotNullWhen(true)] out PrivateConnectionUpdateStart? evidence)
    {
        lock (gate)
        {
            evidence = null;
            if (window is null || !privateUpdates.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.Binding, binding) || r.Invalid || r.Sealed ||
                !r.Started.Task.IsCompletedSuccessfully || r.StartTask is not { IsCompletedSuccessfully: true } ||
                r.Evidence is null || r.Parser is { Complete: false } || r.Parser is { Invalid: true }) return false;
            evidence = r.Evidence;
            return true;
        }
    }

    internal bool OwnsPrivateConnectionUpdateStart(PrivateConnectionUpdateStart evidence, Window window, Binding binding,
        VaultAdministration client, PrivateConnectionScope scope, PrivateConnectionState requested, ManagementReceipt receipt,
        Task originalStartTask, ManagementOperation? originalHandle)
    {
        lock (gate)
            return TryGetPrivateConnectionUpdateStart(window, binding, out var issued) && ReferenceEquals(evidence, issued) &&
                privateUpdates.TryGetValue(window, out var r) && ReferenceEquals(r.Client, client) &&
                ReferenceEquals(r.Scope, scope) && ReferenceEquals(binding.Resource, scope) && requested == r.Requested &&
                ReferenceEquals(r.Receipt, receipt) && ReferenceEquals(r.StartTask, originalStartTask) &&
                ReferenceEquals(r.Handle, originalHandle);
    }

    internal bool OwnsPrivateConnectionUpdateCompletion(PrivateConnectionUpdateStart evidence, Window window, Binding binding,
        VaultAdministration client, PrivateConnectionScope scope, PrivateConnectionState requested, ManagementReceipt receipt,
        Task originalStartTask, ManagementOperation originalHandle, Task originalStatusTask)
    {
        lock (gate)
            return OwnsPrivateConnectionUpdateStart(evidence, window, binding, client, scope, requested, receipt,
                originalStartTask, originalHandle) && privateUpdates.TryGetValue(window, out var r) &&
                r.CheckSucceeded && r.CheckSends == 0 && ReferenceEquals(r.StatusTask, originalStatusTask) &&
                r.StatusTask is { IsCompletedSuccessfully: true } && r.Checked.Task.IsCompletedSuccessfully &&
                !r.CheckToken.IsCancellationRequested && receipt.Evidence == DispatchEvidence.Applied;
    }

    private async Task<SecretStatus> CheckPrivateConnectionUpdateAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained)
    {
        PrivateConnectionUpdateRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(privateUpdates.TryGetValue(window, out r!) && !r.Sealed && !r.CheckClaimed && !r.Invalid &&
                r.Evidence is { HttpStatus: 200, Outcome: SecretStatus.Success } &&
                ReferenceEquals(r.Handle, handle) && handle.State == NativeProvisioningState.Succeeded &&
                r.Started.Task.IsCompletedSuccessfully);
            r.CheckClaimed = true;
            r.CheckToken = token;
        }
        try
        {
            var previous = currentPrivateUpdate.Value;
            currentPrivateUpdate.Value = new(r, true);
            try { r.StatusTask = handle.CheckStatusAsync(token).AsTask(); }
            finally { currentPrivateUpdate.Value = previous; }
            SecretStatus result;
            try { retained?.Invoke(r.StatusTask); }
            finally { result = await r.StatusTask.ConfigureAwait(false); }
            token.ThrowIfCancellationRequested();
            r.CheckSucceeded = !r.Invalid && r.CheckSends == 0 && result == SecretStatus.Success &&
                handle.State == NativeProvisioningState.Succeeded && r.Parser is { Complete: true, Invalid: false };
            return result;
        }
        catch { r.Invalid = true; throw; }
        finally { r.Checked.TrySetResult(); }
    }

    private Task<Capture> SealPrivateConnectionUpdateAsync(Window window)
    {
        lock (gate)
        {
            Own(window, window.Binding.Selector);
            window.Closed = true;
            if (!privateUpdates.TryGetValue(window, out var r)) return Task.FromResult(new Capture { Binding = window.Binding });
            r.Sealed = true;
            return r.SealTask ??= Drain();
            async Task<Capture> Drain()
            {
                await r.Started.Task.ConfigureAwait(false);
                if (r.CheckClaimed) await r.Checked.Task.ConfigureAwait(false);
                foreach (var task in r.Sends)
                    try { await task.ConfigureAwait(false); }
                    catch (Exception) { r.Invalid = true; }
                // Callers freeze their decision before this erases parser storage.
                try { r.Storage.Dispose(); }
                catch { r.Invalid = true; throw; }
                return new() { Binding = r.Binding };
            }
        }
    }

    private async Task SendPrivateConnectionUpdateAsync(PrivateConnectionUpdateContext context, HttpMessage message)
    {
        var r = context.Registration;
        try
        {
            lock (gate)
            {
                if (context.Check) { r.CheckSends++; r.Invalid = true; throw new InvalidOperationException("private-update-cached-check"); }
                Require(!r.Sealed && !r.Invalid && ++r.StartSends == 1 && r.Requests.Contains(message.Request) &&
                    r.Requested is PrivateConnectionState.Approved or PrivateConnectionState.Rejected &&
                    r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched);
                r.Request = message.Request;
            }
            var request = message.Request;
            var headers = request.Headers.Select(h => (h.Name, h.Value)).ToArray();
            var original = request.Content;
            Require(original is not null);
            Require(original.TryComputeLength(out long length) && length > 0 && length <= maximumBytes);
            byte[] staging = new byte[maximumBytes];
            r.Storage.Own(staging);
            using var buffer = new MemoryStream(staging, 0, staging.Length, true, true);
            await original.WriteToAsync(buffer, message.CancellationToken).ConfigureAwait(false);
            Require(buffer.Position == length);
            byte[] bytes = staging.AsSpan(0, (int)length).ToArray();
            r.Storage.Own(bytes);
            Require(PrivateApprovalRequest(bytes, headers, r.Requested));
            var frozen = RequestContent.Create(bytes);
            r.Storage.Own(frozen);
            r.Storage.Own(original);
            request.Content = frozen;
            void Check()
            {
                var uri = request.Uri.ToUri();
                Require(ReferenceEquals(message.Request, request) && ReferenceEquals(request.Content, frozen) &&
                    headers.SequenceEqual(request.Headers.Select(h => (h.Name, h.Value))) &&
                    Trusted(uri) && uri.AbsolutePath == r.Window.Path && uri.Query == "?api-version=2026-02-01" &&
                    request.Method == RequestMethod.Put &&
                    request.Headers.TryGetValue("Authorization", out var auth) &&
                    auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7);
                Headers(request.Headers);
                if (request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
                message.CancellationToken.ThrowIfCancellationRequested();
                r.Token.ThrowIfCancellationRequested();
            }
            Check();
            r.BeforeSend?.Invoke();
            Check();
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            Check();
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, r.Storage,
                allowContinuation: true).ConfigureAwait(false);
            Check();
            r.HttpStatus = body.Response.Status;
            var responseHeaders = body.Response.Headers.Select(h => (h.Name, h.Value)).ToArray();
            r.Facts = PrivateConnectionResponse(r.Scope, r.Requested, body.Bytes, responseHeaders, body.Response.Status);
            r.Denied = body.Response.Status == 403 && PrivateApprovalHeaders(responseHeaders, body.Bytes.Length) &&
                PrivateUpdateDenied(body.Bytes);
            r.Parser = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, r.Storage,
                requireRebuffer: true);
        }
        catch { r.Invalid = true; throw; }
    }

    private static bool PrivateUpdateDenied(ReadOnlyMemory<byte> bytes)
    {
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int rows = 512;
            JsonRows(document.RootElement, ref rows);
            var root = document.RootElement;
            Require(OnlyApprovalFields(root, "error"));
            var error = root.GetProperty("error");
            Require(OnlyApprovalFields(error, "code", "message", "target", "details", "innererror") &&
                ApprovalText(error, "code") is "Forbidden" or "AuthorizationFailed" or "AccessDenied");
            ApprovalOptionalText(error, "message", "target");
            if (error.TryGetProperty("details", out var details)) Require(details.ValueKind == JsonValueKind.Array);
            if (error.TryGetProperty("innererror", out var inner)) Require(inner.ValueKind == JsonValueKind.Object);
            return true;
        }
        catch (Exception) { return false; }
    }

    internal sealed class CreateOrUpdateVaultStart(int httpStatus, SecretStatus outcome, string responseSha256,
        string nativeRequestId, StatusTarget? target)
    {
        internal int HttpStatus { get; } = httpStatus;
        internal SecretStatus Outcome { get; } = outcome;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal StatusTarget? Target { get; } = target;
        public override string ToString() => "[CreateOrUpdateVaultStart]";
    }
    internal sealed class RecoverVaultStart(int httpStatus, SecretStatus outcome, string responseSha256,
        string nativeRequestId, StatusTarget? target)
    {
        internal int HttpStatus { get; } = httpStatus;
        internal SecretStatus Outcome { get; } = outcome;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal StatusTarget? Target { get; } = target;
        public override string ToString() => "[RecoverVaultStart]";
    }
    private enum ConfigurationInvocationKind { Create, Recover }
    private sealed record CreateVaultContext(CreateVaultRegistration Registration, bool Check);
    private sealed class CreateVaultRegistration(Window window, VaultAdministration client, VaultScope scope,
        VaultConfiguration configuration, ManagementReceipt receipt, CancellationToken token, Action? beforeSend,
        ConfigurationInvocationKind kind)
    {
        internal readonly ConfigurationInvocationKind Kind = kind;
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly VaultAdministration Client = client;
        internal readonly VaultScope Scope = scope;
        internal readonly VaultConfiguration Configuration = configuration;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken Token = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly HashSet<Request> Requests = new(ReferenceEqualityComparer.Instance);
        internal readonly List<Task> Sends = [];
        internal readonly List<OwnedArmResponse.ParserCustody> Responses = [];
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task<Capture>? SealTask;
        internal ManagementOperation? Handle;
        internal CreateOrUpdateVaultStart? Evidence;
        internal RecoverVaultStart? RecoverEvidence;
        internal StatusTarget? Target;
        internal string? ResponseSha256, NativeRequestId;
        internal int HttpStatus, StartSends, CheckSends, ValidChecks;
        internal bool Invalid, HookReturned, CheckClaimed, CheckSucceeded, Sealed;
        internal CancellationToken CheckToken;
    }

    internal Window ArmCreateOrUpdateVault(Binding binding) => ArmConfigurationVault(binding, ConfigurationInvocationKind.Create);
    internal Window ArmRecoverVault(Binding binding) => ArmConfigurationVault(binding, ConfigurationInvocationKind.Recover);

    private Window ArmConfigurationVault(Binding binding, ConfigurationInvocationKind kind)
    {
        Require(binding is not null &&
            (kind == ConfigurationInvocationKind.Create ? VaultFixtureProvisioner.CreateOrUpdateVaultSelector(binding.Selector) :
                VaultFixtureProvisioner.RecoverVaultSelector(binding.Selector)) &&
            VaultAdministrationEffects.ConfigurationVariants.Contains(binding.Selector.Variant) && binding.Selector.Nonce != Guid.Empty &&
            binding.LeaseId != Guid.Empty && binding.Resource is VaultScope &&
            binding.Operation == (kind == ConfigurationInvocationKind.Create ?
                ManagementMutation.CreateOrUpdateVault : ManagementMutation.RecoverVault) &&
            binding.ApiRevision == "2026-02-01" && Segment(binding.Location, 50));
        var route = Route(binding);
        lock (gate)
        {
            Require(nonces.Count < 32 && nonces.Add(binding.Selector.Nonce) && leases.Add(binding.LeaseId));
            var window = new Window(owner, binding, route.Path, route.Method);
            targets.Add(window, null);
            (kind == ConfigurationInvocationKind.Create ? createVaultWindows : recoverVaultWindows).Add(window);
            return window;
        }
    }

    internal Task<SecretOutcome<ManagementOperation>> StartCreateOrUpdateVaultAsync(Window window,
        FixtureSelector selector, VaultAdministration client, VaultScope scope, VaultConfiguration configuration,
        ManagementReceipt receipt, CancellationToken token = default,
        Action<Task>? retainedActualTaskCallback = null, Action? beforeSend = null) =>
        StartConfigurationVaultAsync(window, selector, client, scope, configuration, receipt, token,
            retainedActualTaskCallback, beforeSend, ConfigurationInvocationKind.Create);

    internal Task<SecretOutcome<ManagementOperation>> StartRecoverVaultAsync(Window window,
        FixtureSelector selector, VaultAdministration client, VaultScope scope, VaultConfiguration configuration,
        ManagementReceipt receipt, CancellationToken token = default,
        Action<Task>? retainedActualTaskCallback = null, Action? beforeSend = null) =>
        StartConfigurationVaultAsync(window, selector, client, scope, configuration, receipt, token,
            retainedActualTaskCallback, beforeSend, ConfigurationInvocationKind.Recover);

    private async Task<SecretOutcome<ManagementOperation>> StartConfigurationVaultAsync(Window window,
        FixtureSelector selector, VaultAdministration client, VaultScope scope, VaultConfiguration configuration,
        ManagementReceipt receipt, CancellationToken token, Action<Task>? retainedActualTaskCallback,
        Action? beforeSend, ConfigurationInvocationKind kind)
    {
        CreateVaultRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require((kind == ConfigurationInvocationKind.Create ? createVaultWindows : recoverVaultWindows).Contains(window) &&
                !window.Closed && !createVaults.ContainsKey(window) &&
                ReferenceEquals(window.Binding.Resource, scope) && client is not null &&
                configuration is not null && receipt is not null);
            r = new(window, client, scope, configuration, receipt, token, beforeSend, kind);
            createVaults.Add(window, r);
        }
        try
        {
            var previous = currentCreateVault.Value;
            currentCreateVault.Value = new(r, false);
            try
            {
                r.StartTask = r.Kind == ConfigurationInvocationKind.Create
                    ? client.CreateOrUpdateVaultAsync(scope, configuration, receipt, token).AsTask()
                    : client.RecoverVaultAsync(scope, configuration, receipt, token).AsTask();
            }
            finally { currentCreateVault.Value = previous; }
            SecretOutcome<ManagementOperation> result;
            try { retainedActualTaskCallback?.Invoke(r.StartTask); r.HookReturned = true; }
            finally
            {
                result = await r.StartTask.ConfigureAwait(false);
                if (result.IsSuccess) r.Handle = result.Value;
            }
            await Task.WhenAll(r.Sends).ConfigureAwait(false);
            lock (gate)
                if (!r.Invalid && r.HookReturned && r.StartSends == 1 && !token.IsCancellationRequested &&
                    r.Responses.Count == 1 && r.Responses.All(p => p.Complete && !p.Invalid) &&
                    r.ResponseSha256 is not null && r.NativeRequestId is not null &&
                    (r.HttpStatus == 201 && result.IsSuccess && r.Target is not null &&
                        r.Handle?.State == NativeProvisioningState.Pending && receipt.Evidence == DispatchEvidence.Pending ||
                     r.HttpStatus == 403 && result.Status == SecretStatus.Denied && r.Handle is null &&
                        receipt.Evidence == DispatchEvidence.Rejected))
                {
                    if (r.Kind == ConfigurationInvocationKind.Create)
                        r.Evidence = new(r.HttpStatus, result.Status, r.ResponseSha256, r.NativeRequestId, r.Target);
                    else r.RecoverEvidence = new(r.HttpStatus, result.Status, r.ResponseSha256, r.NativeRequestId, r.Target);
                    if (r.Target is not null) { targets[window] = r.Target; eligible.Add(window); }
                }
            return result;
        }
        catch { r.Invalid = true; throw; }
        finally
        {
            try { await Task.WhenAll(r.Sends).ConfigureAwait(false); }
            catch (Exception) { r.Invalid = true; }
            r.Started.TrySetResult();
        }
    }

    internal bool TryGetCreateOrUpdateVaultStart(Window window, Binding binding,
        [NotNullWhen(true)] out CreateOrUpdateVaultStart? evidence)
    {
        lock (gate)
        {
            evidence = null;
            if (window is null || !createVaults.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.Binding, binding) || r.Invalid || !r.Started.Task.IsCompletedSuccessfully ||
                r.StartTask is not { IsCompletedSuccessfully: true } || r.Evidence is null ||
                r.Responses.Any(p => !p.Complete || p.Invalid)) return false;
            evidence = r.Evidence;
            return true;
        }
    }

    internal bool OwnsCreateOrUpdateVaultStart(CreateOrUpdateVaultStart evidence, Window window, Binding binding,
        VaultAdministration client, VaultScope scope, VaultConfiguration configuration, ManagementReceipt receipt,
        Task originalStartTask, ManagementOperation? originalHandle)
    {
        lock (gate)
            return TryGetCreateOrUpdateVaultStart(window, binding, out var issued) && ReferenceEquals(evidence, issued) &&
                createVaults.TryGetValue(window, out var r) && ReferenceEquals(r.Client, client) &&
                ReferenceEquals(r.Scope, scope) && ReferenceEquals(r.Configuration, configuration) &&
                ReferenceEquals(r.Receipt, receipt) && ReferenceEquals(r.StartTask, originalStartTask) &&
                ReferenceEquals(r.Handle, originalHandle);
    }

    internal bool OwnsCreateOrUpdateVaultCompletion(CreateOrUpdateVaultStart evidence, Window window, Binding binding,
        VaultAdministration client, VaultScope scope, VaultConfiguration configuration, ManagementReceipt receipt,
        Task originalStartTask, ManagementOperation originalHandle, Task originalStatusTask)
    {
        lock (gate)
            return OwnsCreateOrUpdateVaultStart(evidence, window, binding, client, scope, configuration, receipt,
                originalStartTask, originalHandle) && createVaults.TryGetValue(window, out var r) &&
                r.CheckSucceeded && r.CheckSends == 2 && r.ValidChecks == 2 && r.Responses.Count == 3 &&
                r.Responses.All(p => p.Complete && !p.Invalid) && ReferenceEquals(r.StatusTask, originalStatusTask) &&
                r.StatusTask is { IsCompletedSuccessfully: true } && r.Checked.Task.IsCompletedSuccessfully &&
                !r.CheckToken.IsCancellationRequested && receipt.Evidence == DispatchEvidence.Pending;
    }

    internal bool TryGetRecoverVaultStart(Window window, Binding binding,
        [NotNullWhen(true)] out RecoverVaultStart? evidence)
    {
        lock (gate)
        {
            evidence = null;
            if (window is null || !recoverVaultWindows.Contains(window) || !createVaults.TryGetValue(window, out var r) ||
                r.Kind != ConfigurationInvocationKind.Recover || !ReferenceEquals(r.Binding, binding) || r.Invalid ||
                !r.Started.Task.IsCompletedSuccessfully || r.StartTask is not { IsCompletedSuccessfully: true } ||
                r.RecoverEvidence is null || r.Responses.Any(p => !p.Complete || p.Invalid)) return false;
            evidence = r.RecoverEvidence;
            return true;
        }
    }

    internal bool OwnsRecoverVaultStart(RecoverVaultStart evidence, Window window, Binding binding,
        VaultAdministration client, VaultScope scope, VaultConfiguration configuration, ManagementReceipt receipt,
        Task originalStartTask, ManagementOperation? originalHandle)
    {
        lock (gate)
            return TryGetRecoverVaultStart(window, binding, out var issued) && ReferenceEquals(evidence, issued) &&
                createVaults.TryGetValue(window, out var r) && ReferenceEquals(r.Client, client) &&
                ReferenceEquals(r.Scope, scope) && ReferenceEquals(r.Configuration, configuration) &&
                ReferenceEquals(r.Receipt, receipt) && ReferenceEquals(r.StartTask, originalStartTask) &&
                ReferenceEquals(r.Handle, originalHandle);
    }

    internal bool OwnsRecoverVaultCompletion(RecoverVaultStart evidence, Window window, Binding binding,
        VaultAdministration client, VaultScope scope, VaultConfiguration configuration, ManagementReceipt receipt,
        Task originalStartTask, ManagementOperation originalHandle, Task originalStatusTask)
    {
        lock (gate)
            return OwnsRecoverVaultStart(evidence, window, binding, client, scope, configuration, receipt,
                originalStartTask, originalHandle) && createVaults.TryGetValue(window, out var r) &&
                r.CheckSucceeded && r.CheckSends == 2 && r.ValidChecks == 2 && r.Responses.Count == 3 &&
                r.Responses.All(p => p.Complete && !p.Invalid) && ReferenceEquals(r.StatusTask, originalStatusTask) &&
                r.StatusTask is { IsCompletedSuccessfully: true } && r.Checked.Task.IsCompletedSuccessfully &&
                !r.CheckToken.IsCancellationRequested && receipt.Evidence == DispatchEvidence.Pending;
    }

    private async Task<SecretStatus> CheckCreateVaultAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained)
    {
        CreateVaultRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(createVaults.TryGetValue(window, out r!) && !r.Sealed && !r.CheckClaimed && !r.Invalid &&
                (r.Kind == ConfigurationInvocationKind.Create ? r.Evidence is { HttpStatus: 201, Target: not null } :
                    r.RecoverEvidence is { HttpStatus: 201, Target: not null }) && ReferenceEquals(r.Handle, handle) &&
                handle.State == NativeProvisioningState.Pending && r.Started.Task.IsCompletedSuccessfully);
            r.CheckClaimed = true;
            r.CheckToken = token;
        }
        try
        {
            var previous = currentCreateVault.Value;
            currentCreateVault.Value = new(r, true);
            try { r.StatusTask = handle.CheckStatusAsync(token).AsTask(); }
            finally { currentCreateVault.Value = previous; }
            SecretStatus result;
            try { retained?.Invoke(r.StatusTask); }
            finally { result = await r.StatusTask.ConfigureAwait(false); }
            await Task.WhenAll(r.Sends).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            r.CheckSucceeded = !r.Invalid && result == SecretStatus.Success &&
                handle.State == NativeProvisioningState.Succeeded && r.CheckSends == 2 && r.ValidChecks == 2 &&
                r.Responses.Count == 3 && r.Responses.All(p => p.Complete && !p.Invalid) &&
                r.Receipt.Evidence == DispatchEvidence.Pending;
            return result;
        }
        catch { r.Invalid = true; throw; }
        finally
        {
            try { await Task.WhenAll(r.Sends).ConfigureAwait(false); }
            catch (Exception) { r.Invalid = true; }
            r.Checked.TrySetResult();
        }
    }

    private Task<Capture> SealCreateVaultAsync(Window window)
    {
        CreateVaultRegistration r;
        TaskCompletionSource<Capture> completion;
        lock (gate)
        {
            Own(window, window.Binding.Selector);
            window.Closed = true;
            if (!createVaults.TryGetValue(window, out r!)) return Task.FromResult(new Capture { Binding = window.Binding });
            r.Sealed = true;
            if (r.SealTask is not null) return r.SealTask;
            completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
            r.SealTask = completion.Task;
        }
        _ = Drain();
        return completion.Task;
        async Task Drain()
        {
            try
            {
                await r.Started.Task.ConfigureAwait(false);
                if (r.CheckClaimed) await r.Checked.Task.ConfigureAwait(false);
                await Task.WhenAll(r.Sends.Select(IgnoreFailure)).ConfigureAwait(false);
                r.Storage.Dispose();
                completion.TrySetResult(new() { Binding = r.Binding });
            }
            catch (Exception exception)
            {
                r.Invalid = true;
                completion.TrySetException(exception);
            }
        }
        async Task IgnoreFailure(Task task)
        {
            try { await task.ConfigureAwait(false); }
            catch (Exception) { r.Invalid = true; }
        }
    }

    private async Task SendCreateVaultAsync(CreateVaultContext context, HttpMessage message)
    {
        var r = context.Registration;
        try
        {
            lock (gate)
            {
                Require(!r.Sealed && !r.Invalid && r.Requests.Contains(message.Request));
                if (context.Check) Require(r.CheckClaimed && ++r.CheckSends <= 2 && r.ValidChecks == r.CheckSends - 1);
                else Require(++r.StartSends == 1 && r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched);
            }
            var request = message.Request;
            var headers = request.Headers.ToArray();
            RequestContent? frozen = null;
            if (!context.Check)
            {
                var original = request.Content;
                Require(original is not null);
                Require(original.TryComputeLength(out long length) && length > 0 && length <= maximumBytes);
                byte[] staging = new byte[maximumBytes];
                r.Storage.Own(staging);
                using var buffer = new MemoryStream(staging, 0, staging.Length, true, true);
                await original.WriteToAsync(buffer, message.CancellationToken).ConfigureAwait(false);
                Require(buffer.Position == length);
                byte[] bytes = staging.AsSpan(0, (int)length).ToArray();
                r.Storage.Own(bytes);
                ValidateCreateVaultRequest(bytes, r.Configuration, r.Kind == ConfigurationInvocationKind.Recover);
                frozen = RequestContent.Create(bytes);
                r.Storage.Own(frozen);
                r.Storage.Own(original);
                request.Content = frozen;
                if (request.Headers.TryGetValue("Content-Length", out var declared))
                    Require(declared == length.ToString(CultureInfo.InvariantCulture));
            }
            void Check()
            {
                if (context.Check)
                    OriginalVaultRequest(message, r.Window.Path, RequestMethod.Get,
                        r.CheckSends == 1 ? r.Target!.TargetUri.OriginalString :
                            Origin + r.Window.Path + "?api-version=2026-02-01");
                else
                {
                    Uri uri = request.Uri.ToUri();
                    Require(Trusted(uri) && uri.AbsolutePath == r.Window.Path && uri.Query == "?api-version=2026-02-01" &&
                        request.Method == RequestMethod.Put && ReferenceEquals(request.Content, frozen) &&
                        request.Headers.TryGetValue("Authorization", out var auth) &&
                        auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
                        request.Headers.TryGetValue("Content-Type", out var type) &&
                        type.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase) &&
                        !request.Headers.Contains("Content-Encoding") && !request.Headers.Contains("Transfer-Encoding") &&
                        !request.Headers.Contains("Content-Range"));
                    Headers(request.Headers);
                    if (request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
                }
                Require(ReferenceEquals(message.Request, request) && headers.SequenceEqual(request.Headers));
                message.CancellationToken.ThrowIfCancellationRequested();
                (context.Check ? r.CheckToken : r.Token).ThrowIfCancellationRequested();
            }
            Check();
            if (!context.Check) r.BeforeSend?.Invoke();
            Check();
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            Check();
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, r.Storage,
                allowContinuation: !context.Check).ConfigureAwait(false);
            Check();
            int status = body.Response.Status;
            Require(context.Check ? status == 200 : status is 201 or 403);
            using var json = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int rows = 512;
            JsonRows(json.RootElement, ref rows);
            var root = json.RootElement;
            Require(root.ValueKind == JsonValueKind.Object && !new[] { "nextLink", "value", "partial", "errors" }
                .Any(n => root.TryGetProperty(n, out _)));
            string? next = Continuation(r.Window, message);
            if (status == 403)
            {
                Require(next is null && root.EnumerateObject().All(p => p.Name == "error"));
                var error = root.GetProperty("error");
                Require(error.ValueKind == JsonValueKind.Object &&
                    error.GetProperty("code").GetString() is "Forbidden" or "AuthorizationFailed" or "AccessDenied" &&
                    error.EnumerateObject().All(p => p.Name is "code" or "message" or "target" or "details" or "innererror"));
                if (error.TryGetProperty("message", out var text)) Require(text.ValueKind == JsonValueKind.String);
                if (error.TryGetProperty("target", out var target)) Require(target.ValueKind == JsonValueKind.String);
                if (error.TryGetProperty("details", out var details)) Require(details.ValueKind == JsonValueKind.Array);
                if (error.TryGetProperty("innererror", out var inner)) Require(inner.ValueKind == JsonValueKind.Object);
            }
            else if (context.Check && r.CheckSends == 1)
            {
                Require(next is null && root.GetProperty("status").GetString() == "Succeeded" &&
                    !root.TryGetProperty("error", out _) &&
                    (!root.TryGetProperty("id", out var id) || id.GetString() == r.Target!.TargetUri.AbsolutePath));
                r.ValidChecks++;
            }
            else
            {
                var state = root.GetProperty("properties").GetProperty("provisioningState").GetString();
                Require(context.Check ? state == "Succeeded" && next is null :
                    state is "Updating" or "Creating" && next is not null);
                _ = VaultFixtureProvisioner.ParseOwnedVaultResource(r.Window.Path, r.Binding.Selector.Nonce,
                    root, CreateVaultConfiguration(r.Configuration), state!, recover: r.Kind == ConfigurationInvocationKind.Recover);
                if (context.Check) r.ValidChecks++;
                else
                {
                    byte[] bytes = System.Text.Encoding.UTF8.GetBytes(next!);
                    try
                    {
                        r.Target = new(r.Binding, Guid.NewGuid(), StatusTargetKind.Operation, new Uri(next!),
                            Convert.ToHexString(SHA256.HashData(bytes)), body.Sha256);
                    }
                    finally { CryptographicOperations.ZeroMemory(bytes); }
                }
            }
            if (!context.Check)
            {
                r.HttpStatus = status;
                r.ResponseSha256 = body.Sha256;
                r.NativeRequestId = body.NativeRequestId;
            }
            r.Responses.Add(OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes,
                // A 201 Pending start reads/parses the body in ControlledTransport
                // and installs its exact rebuffer; the native LRO retains only its
                // continuation. Poll/final/native-error paths still require the
                // downstream native parser's actual byte read.
                r.Storage, requireRebuffer: true, requireDownstreamRead: context.Check || status != 201));
        }
        catch { r.Invalid = true; throw; }
    }

    internal static VaultAdministrationEffects.Configuration CreateVaultConfiguration(VaultConfiguration configuration) =>
        new(configuration.Location, configuration.TenantId, configuration.Sku, configuration.EnableRbacAuthorization,
            configuration.EnablePurgeProtection, configuration.RetentionDays, configuration.PublicNetworkAccess,
            configuration.AccessPolicies.Select(p => new VaultAdministrationEffects.Policy(p.TenantId, p.ObjectId,
                p.Permissions.ToArray(), p.ApplicationId)).ToArray());

    private static void ValidateCreateVaultRequest(byte[] bytes, VaultConfiguration configuration, bool recover = false)
    {
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
        var root = document.RootElement;
        int rows = 512;
        JsonRows(root, ref rows);
        Require(OnlyApprovalFields(root, "location", "properties") &&
            root.GetProperty("location").GetString() == configuration.Location);
        var p = root.GetProperty("properties");
        Require(OnlyApprovalFields(p, "tenantId", "sku", "enableRbacAuthorization", "enableSoftDelete",
            "enablePurgeProtection", "softDeleteRetentionInDays", "publicNetworkAccess", "createMode", "accessPolicies") &&
            p.GetProperty("tenantId").GetGuid() == configuration.TenantId &&
            p.GetProperty("sku").GetProperty("family").GetString() == "A" &&
            p.GetProperty("sku").GetProperty("name").GetString() == configuration.Sku.ToString().ToLowerInvariant() &&
            p.GetProperty("enableRbacAuthorization").GetBoolean() == configuration.EnableRbacAuthorization &&
            p.GetProperty("enableSoftDelete").GetBoolean() &&
            p.GetProperty("enablePurgeProtection").GetBoolean() == configuration.EnablePurgeProtection &&
            p.GetProperty("softDeleteRetentionInDays").GetInt32() == configuration.RetentionDays &&
            p.GetProperty("publicNetworkAccess").GetString() == (configuration.PublicNetworkAccess ? "Enabled" : "Disabled") &&
            p.GetProperty("createMode").GetString() == (recover ? "recover" : "default"));
        if (!p.TryGetProperty("accessPolicies", out var policies))
            Require(configuration.AccessPolicies.Count == 0);
        else
        {
            var actual = policies.EnumerateArray().Select(policy =>
            {
                Require(OnlyApprovalFields(policy, "tenantId", "objectId", "applicationId", "permissions") &&
                    OnlyApprovalFields(policy.GetProperty("permissions"), "secrets"));
                return new VaultAdministrationEffects.Policy(policy.GetProperty("tenantId").GetGuid(),
                    policy.GetProperty("objectId").GetGuid(),
                    policy.GetProperty("permissions").GetProperty("secrets").EnumerateArray()
                        .Select(v => Enum.Parse<SecretPermission>(v.GetString()!, true)).ToArray(),
                    policy.TryGetProperty("applicationId", out var application) ? application.GetGuid() : null);
            }).ToArray();
            Require(VaultAdministrationEffects.SamePolicies(actual, CreateVaultConfiguration(configuration).Policies));
        }
    }

    internal sealed class DeleteVaultStart(int httpStatus, SecretStatus outcome, string responseSha256,
        string nativeRequestId, StatusTarget? target)
    {
        internal int HttpStatus { get; } = httpStatus;
        internal SecretStatus Outcome { get; } = outcome;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal StatusTarget? Target { get; } = target;
        public override string ToString() => "[DeleteVaultStart]";
    }

    private sealed record DeleteVaultWire(int HttpStatus, string Sha256, string NativeRequestId, StatusTarget? Target);
    private sealed record DeleteVaultContext(DeleteVaultRegistration Registration, bool Check);
    private sealed class DeleteVaultRegistration(Window window, VaultAdministration client, VaultScope scope,
        ManagementReceipt receipt, CancellationToken token, Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly VaultAdministration Client = client;
        internal readonly VaultScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken Token = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly HashSet<Request> Requests = new(ReferenceEqualityComparer.Instance);
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task? SendTask;
        internal DeleteVaultWire? Wire;
        internal DeleteVaultStart? Evidence;
        internal ManagementOperation? Handle;
        internal CancellationToken CheckToken;
        internal Task<Capture>? SealTask;
        internal int Sends, CheckSends;
        internal bool Invalid, HookReturned, CheckClaimed, CheckSucceeded, Sealed;
    }

    internal Window ArmDeleteVault(Binding binding)
    {
        Require(binding is not null && VaultFixtureProvisioner.DeleteVaultSelector(binding.Selector) &&
            binding.Selector.Nonce != Guid.Empty && binding.LeaseId != Guid.Empty &&
            binding.Resource is VaultScope && binding.Operation == ManagementMutation.DeleteVault &&
            binding.ApiRevision == "2026-02-01" && Segment(binding.Location, 50));
        var route = Route(binding);
        lock (gate)
        {
            Require(nonces.Count < 32 && nonces.Add(binding.Selector.Nonce) && leases.Add(binding.LeaseId));
            var window = new Window(owner, binding, route.Path, route.Method);
            targets.Add(window, null);
            deleteVaultWindows.Add(window);
            return window;
        }
    }

    internal async Task<SecretOutcome<ManagementOperation>> StartDeleteVaultAsync(Window window,
        FixtureSelector selector, VaultAdministration client, VaultScope scope, ManagementReceipt receipt,
        CancellationToken token = default, Action<Task>? retainedActualTaskCallback = null, Action? beforeSend = null)
    {
        DeleteVaultRegistration registration;
        lock (gate)
        {
            Own(window, selector);
            Require(deleteVaultWindows.Contains(window) && !window.Closed && !deleteVaults.ContainsKey(window) &&
                ReferenceEquals(window.Binding.Resource, scope) && client is not null && receipt is not null);
            registration = new(window, client, scope, receipt, token, beforeSend);
            deleteVaults.Add(window, registration);
        }
        try
        {
            var previous = currentDeleteVault.Value;
            currentDeleteVault.Value = new(registration, false);
            try { registration.StartTask = client.DeleteVaultAsync(scope, receipt, token).AsTask(); }
            finally { currentDeleteVault.Value = previous; }
            SecretOutcome<ManagementOperation> result;
            try
            {
                retainedActualTaskCallback?.Invoke(registration.StartTask);
                registration.HookReturned = true;
            }
            finally
            {
                // A failing callback must still await the exact original SDK task.
                result = await registration.StartTask.ConfigureAwait(false);
                if (result.IsSuccess) registration.Handle = result.Value;
            }
            if (registration.SendTask is { } send)
                try { await send.ConfigureAwait(false); }
                catch (Exception) { registration.Invalid = true; }
            lock (gate)
            {
                if (!registration.Invalid && registration.HookReturned && registration.Sends == 1 &&
                    !token.IsCancellationRequested && registration.Wire is { } wire &&
                    (wire.HttpStatus == 403 && result.Status == SecretStatus.Denied &&
                        receipt.Evidence == DispatchEvidence.Rejected && registration.Handle is null ||
                     wire.HttpStatus == 200 && result.IsSuccess && wire.Target is not null &&
                        registration.Handle?.State == NativeProvisioningState.Succeeded &&
                        receipt.Evidence == DispatchEvidence.Applied))
                {
                    registration.Evidence = new(wire.HttpStatus, result.Status, wire.Sha256, wire.NativeRequestId, wire.Target);
                    if (wire.Target is not null)
                    {
                        targets[window] = wire.Target;
                        eligible.Add(window);
                    }
                }
            }
            return result;
        }
        catch
        {
            registration.Invalid = true;
            throw;
        }
        finally
        {
            if (registration.SendTask is { } send)
                try { await send.ConfigureAwait(false); }
                catch (Exception) { registration.Invalid = true; }
            registration.Started.TrySetResult();
        }
    }

    internal bool TryGetDeleteVaultStart(Window window, Binding binding,
        [NotNullWhen(true)] out DeleteVaultStart? evidence)
    {
        lock (gate)
        {
            evidence = null;
            if (window is null || !deleteVaults.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.Binding, binding) || r.Invalid || !r.Started.Task.IsCompletedSuccessfully ||
                r.StartTask is not { IsCompletedSuccessfully: true } || r.Evidence is null)
                return false;
            evidence = r.Evidence;
            return true;
        }
    }

    internal bool OwnsDeleteVaultStart(DeleteVaultStart evidence, Window window, Binding binding,
        VaultAdministration client, VaultScope scope, ManagementReceipt receipt, Task originalStartTask,
        ManagementOperation? originalHandle)
    {
        lock (gate)
            return TryGetDeleteVaultStart(window, binding, out var issued) && ReferenceEquals(evidence, issued) &&
                deleteVaults.TryGetValue(window, out var r) && ReferenceEquals(r.Client, client) &&
                ReferenceEquals(r.Scope, scope) && ReferenceEquals(binding.Resource, scope) &&
                ReferenceEquals(r.Receipt, receipt) && ReferenceEquals(r.StartTask, originalStartTask) &&
                ReferenceEquals(r.Handle, originalHandle);
    }

    internal bool OwnsDeleteVaultCompletion(DeleteVaultStart evidence, Window window, Binding binding,
        VaultAdministration client, VaultScope scope, ManagementReceipt receipt, Task originalStartTask,
        ManagementOperation originalHandle, Task originalStatusTask)
    {
        lock (gate)
            return OwnsDeleteVaultStart(evidence, window, binding, client, scope, receipt, originalStartTask, originalHandle) &&
                deleteVaults.TryGetValue(window, out var r) && r.CheckSucceeded && r.CheckSends == 0 &&
                ReferenceEquals(r.StatusTask, originalStatusTask) && r.StatusTask is { IsCompletedSuccessfully: true } &&
                r.Checked.Task.IsCompletedSuccessfully && !r.CheckToken.IsCancellationRequested;
    }

    private async Task<SecretStatus> CheckDeleteVaultAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained)
    {
        DeleteVaultRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(deleteVaults.TryGetValue(window, out r!) && !r.Sealed && !r.CheckClaimed &&
                r.Evidence is { HttpStatus: 200 } && !r.Invalid && ReferenceEquals(r.Handle, handle) &&
                r.Started.Task.IsCompletedSuccessfully);
            r.CheckClaimed = true;
            r.CheckToken = token;
        }
        try
        {
            var previous = currentDeleteVault.Value;
            currentDeleteVault.Value = new(r, true);
            try { r.StatusTask = handle.CheckStatusAsync(token).AsTask(); }
            finally { currentDeleteVault.Value = previous; }
            SecretStatus result;
            try { retained?.Invoke(r.StatusTask); }
            finally { result = await r.StatusTask.ConfigureAwait(false); }
            token.ThrowIfCancellationRequested();
            lock (gate)
                r.CheckSucceeded = result == SecretStatus.Success && handle.State == NativeProvisioningState.Succeeded &&
                    r.CheckSends == 0 && !r.Invalid;
            return result;
        }
        catch { r.Invalid = true; throw; }
        finally { r.Checked.TrySetResult(); }
    }

    private Task<Capture> SealDeleteVaultAsync(Window window)
    {
        lock (gate)
        {
            Own(window, window.Binding.Selector);
            window.Closed = true;
            if (!deleteVaults.TryGetValue(window, out var r)) return Task.FromResult(new Capture { Binding = window.Binding });
            r.Sealed = true;
            return r.SealTask ??= Drain();
            async Task<Capture> Drain()
            {
                await r.Started.Task.ConfigureAwait(false);
                if (r.CheckClaimed) await r.Checked.Task.ConfigureAwait(false);
                try { r.Storage.Dispose(); }
                catch { r.Invalid = true; throw; }
                return new() { Binding = r.Binding };
            }
        }
    }

    private static void DeleteVaultRequest(DeleteVaultRegistration r, HttpMessage message)
        => OriginalVaultRequest(message, r.Window.Path, RequestMethod.Delete);

    private static void OriginalVaultRequest(HttpMessage message, string path, RequestMethod method,
        string? continuation = null)
    {
        var uri = message.Request.Uri.ToUri();
        var headers = message.Request.Headers.ToArray();
        Require(Trusted(uri) && (continuation is null ? uri.AbsolutePath == path : uri.OriginalString == continuation) &&
            uri.Query == "?api-version=2026-02-01" &&
            message.Request.Method == method && message.Request.Content is null &&
            headers.Length <= 32 && headers.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
            headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
            headers.All(h => h.Name.Length is > 0 and <= 128 && h.Value.Length <= 16384 &&
                !h.Name.Any(char.IsControl) && !h.Value.Any(char.IsControl)) &&
            message.Request.Headers.TryGetValue("Authorization", out var auth) &&
            auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
            !message.Request.Headers.Contains("Content-Encoding") &&
            !message.Request.Headers.Contains("Transfer-Encoding") &&
            !message.Request.Headers.Contains("Content-Range"));
        if (message.Request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
        if (message.Request.Headers.TryGetValue("Content-Length", out var length)) Require(length == "0");
    }

    internal sealed class PurgeDeletedVaultStart(int httpStatus, SecretStatus outcome, string responseSha256,
        string nativeRequestId, StatusTarget? target)
    {
        internal int HttpStatus { get; } = httpStatus;
        internal SecretStatus Outcome { get; } = outcome;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal StatusTarget? Target { get; } = target;
        public override string ToString() => "[PurgeDeletedVaultStart]";
    }

    private sealed record PurgeDeletedVaultContext(PurgeDeletedVaultRegistration Registration, bool Check);
    private sealed class PurgeDeletedVaultRegistration(Window window, VaultAdministration client, DeletedVaultScope scope,
        ManagementReceipt receipt, CancellationToken token, Action? beforeSend)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = window.Binding;
        internal readonly VaultAdministration Client = client;
        internal readonly DeletedVaultScope Scope = scope;
        internal readonly ManagementReceipt Receipt = receipt;
        internal readonly CancellationToken Token = token;
        internal readonly Action? BeforeSend = beforeSend;
        internal readonly OwnedArmResponse.Storage Storage = new();
        internal readonly HashSet<Request> Requests = new(ReferenceEqualityComparer.Instance);
        internal readonly List<Task> Sends = [];
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Checked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? StatusTask;
        internal Task<Capture>? SealTask;
        internal PurgeDeletedVaultStart? Evidence;
        internal ManagementOperation? Handle;
        internal StatusTarget? Target;
        internal string? ResponseSha256, NativeRequestId;
        internal int HttpStatus, StartSends, CheckSends, CompleteChecks;
        internal readonly List<PurgeSdkResponse> Responses = [];
        internal CancellationToken CheckToken;
        internal bool Invalid, HookReturned, CheckClaimed, CheckSucceeded, Sealed;
    }

    internal Window ArmPurgeDeletedVault(Binding binding)
    {
        Require(binding is not null && VaultFixtureProvisioner.PurgeDeletedVaultSelector(binding.Selector) &&
            binding.Selector.Nonce != Guid.Empty && binding.LeaseId != Guid.Empty &&
            binding.Resource is DeletedVaultScope && binding.Operation == ManagementMutation.PurgeDeletedVault &&
            binding.ApiRevision == "2026-02-01" && Segment(binding.Location, 50));
        var route = Route(binding);
        lock (gate)
        {
            Require(nonces.Count < 32 && nonces.Add(binding.Selector.Nonce) && leases.Add(binding.LeaseId));
            var window = new Window(owner, binding, route.Path, route.Method);
            targets.Add(window, null);
            purgeDeletedVaultWindows.Add(window);
            return window;
        }
    }

    internal async Task<SecretOutcome<ManagementOperation>> StartPurgeDeletedVaultAsync(Window window,
        FixtureSelector selector, VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt,
        CancellationToken token = default, Action<Task>? retainedActualTaskCallback = null, Action? beforeSend = null)
    {
        PurgeDeletedVaultRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(purgeDeletedVaultWindows.Contains(window) && !window.Closed && !purgeDeletedVaults.ContainsKey(window) &&
                ReferenceEquals(window.Binding.Resource, scope) && client is not null && receipt is not null);
            r = new(window, client, scope, receipt, token, beforeSend);
            purgeDeletedVaults.Add(window, r);
        }
        try
        {
            var previous = currentPurgeDeletedVault.Value;
            currentPurgeDeletedVault.Value = new(r, false);
            try { r.StartTask = client.PurgeDeletedVaultAsync(scope, receipt, token).AsTask(); }
            finally { currentPurgeDeletedVault.Value = previous; }
            SecretOutcome<ManagementOperation> result;
            try
            {
                retainedActualTaskCallback?.Invoke(r.StartTask);
                r.HookReturned = true;
            }
            finally
            {
                result = await r.StartTask.ConfigureAwait(false);
                if (result.IsSuccess) r.Handle = result.Value;
            }
            await Task.WhenAll(r.Sends).ConfigureAwait(false);
            lock (gate)
                if (!r.Invalid && r.HookReturned && r.StartSends == 1 && !token.IsCancellationRequested &&
                    r.Responses.Count == 1 && r.Responses.All(response => response.Consumed) &&
                    r.ResponseSha256 is not null && r.NativeRequestId is not null &&
                    (r.HttpStatus == 202 && result.IsSuccess && r.Target is not null &&
                        r.Handle?.State == NativeProvisioningState.Pending && receipt.Evidence == DispatchEvidence.Pending ||
                     r.HttpStatus == 403 && result.Status == SecretStatus.Denied && r.Handle is null &&
                        receipt.Evidence == DispatchEvidence.Rejected))
                {
                    r.Evidence = new(r.HttpStatus, result.Status, r.ResponseSha256, r.NativeRequestId, r.Target);
                    if (r.Target is not null)
                    {
                        targets[window] = r.Target;
                        eligible.Add(window);
                    }
                }
            return result;
        }
        catch { r.Invalid = true; throw; }
        finally
        {
            try { await Task.WhenAll(r.Sends).ConfigureAwait(false); }
            catch (Exception) { r.Invalid = true; }
            r.Started.TrySetResult();
        }
    }

    internal bool TryGetPurgeDeletedVaultStart(Window window, Binding binding,
        [NotNullWhen(true)] out PurgeDeletedVaultStart? evidence)
    {
        lock (gate)
        {
            evidence = null;
            if (window is null || !purgeDeletedVaults.TryGetValue(window, out var r) ||
                !ReferenceEquals(r.Binding, binding) || r.Invalid || !r.Started.Task.IsCompletedSuccessfully ||
                r.StartTask is not { IsCompletedSuccessfully: true } || r.Evidence is null)
                return false;
            evidence = r.Evidence;
            return true;
        }
    }

    internal bool OwnsPurgeDeletedVaultStart(PurgeDeletedVaultStart evidence, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task originalStartTask,
        ManagementOperation? originalHandle)
    {
        lock (gate)
            return TryGetPurgeDeletedVaultStart(window, binding, out var issued) && ReferenceEquals(evidence, issued) &&
                purgeDeletedVaults.TryGetValue(window, out var r) && ReferenceEquals(r.Client, client) &&
                ReferenceEquals(r.Scope, scope) && ReferenceEquals(binding.Resource, scope) &&
                ReferenceEquals(r.Receipt, receipt) && ReferenceEquals(r.StartTask, originalStartTask) &&
                ReferenceEquals(r.Handle, originalHandle);
    }

    internal bool OwnsPurgeDeletedVaultCompletion(PurgeDeletedVaultStart evidence, Window window, Binding binding,
        VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, Task originalStartTask,
        ManagementOperation originalHandle, Task originalStatusTask)
    {
        lock (gate)
            return OwnsPurgeDeletedVaultStart(evidence, window, binding, client, scope, receipt, originalStartTask, originalHandle) &&
                purgeDeletedVaults.TryGetValue(window, out var r) && r.CheckSucceeded &&
                r.CheckSends == 2 && r.CompleteChecks == 2 && r.Responses.Count == 3 &&
                r.Responses.All(response => response.Consumed) && ReferenceEquals(r.StatusTask, originalStatusTask) &&
                r.StatusTask is { IsCompletedSuccessfully: true } && r.Checked.Task.IsCompletedSuccessfully &&
                !r.CheckToken.IsCancellationRequested && receipt.Evidence == DispatchEvidence.Pending;
    }

    private async Task<SecretStatus> CheckPurgeDeletedVaultAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained)
    {
        PurgeDeletedVaultRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(purgeDeletedVaults.TryGetValue(window, out r!) && !r.Sealed && !r.CheckClaimed &&
                r.Evidence is { HttpStatus: 202, Target: not null } && !r.Invalid && ReferenceEquals(r.Handle, handle) &&
                r.Started.Task.IsCompletedSuccessfully);
            r.CheckClaimed = true;
            r.CheckToken = token;
        }
        try
        {
            var previous = currentPurgeDeletedVault.Value;
            currentPurgeDeletedVault.Value = new(r, true);
            try { r.StatusTask = handle.CheckStatusAsync(token).AsTask(); }
            finally { currentPurgeDeletedVault.Value = previous; }
            SecretStatus result;
            try { retained?.Invoke(r.StatusTask); }
            finally { result = await r.StatusTask.ConfigureAwait(false); }
            await Task.WhenAll(r.Sends).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            r.CheckSucceeded = !r.Invalid && result == SecretStatus.Success &&
                handle.State == NativeProvisioningState.Succeeded && r.CheckSends == 2 && r.CompleteChecks == 2 &&
                r.Receipt.Evidence == DispatchEvidence.Pending;
            return result;
        }
        catch { r.Invalid = true; throw; }
        finally
        {
            try { await Task.WhenAll(r.Sends).ConfigureAwait(false); }
            catch (Exception) { r.Invalid = true; }
            r.Checked.TrySetResult();
        }
    }

    private Task<Capture> SealPurgeDeletedVaultAsync(Window window)
    {
        lock (gate)
        {
            Own(window, window.Binding.Selector);
            window.Closed = true;
            if (!purgeDeletedVaults.TryGetValue(window, out var r)) return Task.FromResult(new Capture { Binding = window.Binding });
            r.Sealed = true;
            return r.SealTask ??= Drain();
            async Task<Capture> Drain()
            {
                await r.Started.Task.ConfigureAwait(false);
                if (r.CheckClaimed) await r.Checked.Task.ConfigureAwait(false);
                try { r.Storage.Dispose(); }
                catch { r.Invalid = true; throw; }
                return new() { Binding = r.Binding };
            }
        }
    }

    private async Task SendPurgeDeletedVaultAsync(PurgeDeletedVaultContext context, HttpMessage message)
    {
        var r = context.Registration;
        try
        {
            lock (gate)
            {
                Require(!r.Sealed && !r.Invalid && r.Requests.Contains(message.Request));
                if (context.Check)
                    Require(r.CheckClaimed && ++r.CheckSends <= 2 && r.CompleteChecks == r.CheckSends - 1);
                else Require(++r.StartSends == 1 && r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched);
            }
            void Check()
            {
                OriginalVaultRequest(message, r.Window.Path, context.Check ? RequestMethod.Get : RequestMethod.Post,
                    context.Check ? r.Target?.TargetUri.OriginalString ?? throw new InvalidOperationException("purge-target") : null);
                message.CancellationToken.ThrowIfCancellationRequested();
                (context.Check ? r.CheckToken : r.Token).ThrowIfCancellationRequested();
            }
            Check();
            var original = message.Request;
            var headers = original.Headers.ToArray();
            if (!context.Check) r.BeforeSend?.Invoke();
            Check();
            Require(ReferenceEquals(message.Request, original) && headers.SequenceEqual(original.Headers));
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            Check();
            Require(ReferenceEquals(message.Request, original) && headers.SequenceEqual(original.Headers));
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, r.Storage,
                allowContinuation: !context.Check).ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(message.Request, original) && headers.SequenceEqual(original.Headers));
            int status = body.Response.Status;
            Require(context.Check ? status == 200 : status is 202 or 403);
            using var json = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int rows = 512;
            JsonRows(json.RootElement, ref rows);
            var root = json.RootElement;
            Require(root.ValueKind == JsonValueKind.Object && !root.TryGetProperty("nextLink", out _) &&
                !root.TryGetProperty("value", out _) && !root.TryGetProperty("partial", out _) &&
                !root.TryGetProperty("errors", out _));
            string? next = Continuation(r.Window, message);
            if (status == 403)
            {
                Require(next is null && root.EnumerateObject().All(p => p.Name == "error"));
                var error = root.GetProperty("error");
                Require(error.ValueKind == JsonValueKind.Object &&
                    error.GetProperty("code").GetString() is "Forbidden" or "AuthorizationFailed" or "AccessDenied" &&
                    error.EnumerateObject().All(p => p.Name is "code" or "message" or "target" or "details" or "innererror"));
                if (error.TryGetProperty("message", out var text)) Require(text.ValueKind == JsonValueKind.String);
                if (error.TryGetProperty("target", out var target)) Require(target.ValueKind == JsonValueKind.String);
                if (error.TryGetProperty("details", out var details)) Require(details.ValueKind == JsonValueKind.Array);
                if (error.TryGetProperty("innererror", out var inner)) Require(inner.ValueKind == JsonValueKind.Object);
            }
            else
            {
                Require(!root.TryGetProperty("error", out _) &&
                    (!root.TryGetProperty("status", out _) || !root.TryGetProperty("properties", out var properties) ||
                        !properties.TryGetProperty("provisioningState", out _)));
                string? state = root.TryGetProperty("status", out var value) ? value.GetString() :
                    root.GetProperty("properties").GetProperty("provisioningState").GetString();
                Require(State(state) == (context.Check ? WireState.Succeeded : WireState.Pending));
                if (root.TryGetProperty("id", out var id))
                    Require(id.GetString() == (context.Check ? r.Target!.TargetUri.AbsolutePath : r.Window.Path));
                if (context.Check)
                {
                    Require(next is null);
                    r.CompleteChecks++;
                }
                else
                {
                    Require(next is not null);
                    byte[] targetBytes = System.Text.Encoding.UTF8.GetBytes(next);
                    try
                    {
                        r.Target = new(r.Binding, Guid.NewGuid(), StatusTargetKind.Operation, new Uri(next),
                            Convert.ToHexString(SHA256.HashData(targetBytes)), body.Sha256);
                    }
                    finally { CryptographicOperations.ZeroMemory(targetBytes); }
                }
            }
            if (!context.Check)
            {
                r.HttpStatus = status;
                r.ResponseSha256 = body.Sha256;
                r.NativeRequestId = body.NativeRequestId;
            }
            var response = new PurgeSdkResponse(message, body.Response, r, body.Bytes.Length);
            r.Responses.Add(response);
            message.Response = response;
        }
        catch { r.Invalid = true; throw; }
    }

    // Check ownership while the SDK is actually accessing or disposing its
    // response. HttpMessage itself is cleared by normal SDK disposal, so it
    // cannot serve as a post-task response snapshot.
    private sealed class PurgeSdkResponse : Azure.Response
    {
        private readonly HttpMessage message;
        private readonly OwnedArmResponse owned;
        private readonly PurgeDeletedVaultRegistration registration;
        private readonly PurgeParserStream parser;
        private Stream? content;
        internal PurgeSdkResponse(HttpMessage message, OwnedArmResponse owned,
            PurgeDeletedVaultRegistration registration, int length)
        {
            this.message = message;
            this.owned = owned;
            this.registration = registration;
            content = parser = new(owned.ContentStream ?? throw new InvalidOperationException("purge-parser-stream"),
                length, Check);
        }
        internal bool Consumed => parser.Complete;
        private void Check()
        {
            if (message.HasResponse && !ReferenceEquals(message.Response, this)) registration.Invalid = true;
        }
        public override int Status => owned.Status;
        public override string ReasonPhrase => owned.ReasonPhrase;
        public override string ClientRequestId { get => owned.ClientRequestId; set => owned.ClientRequestId = value; }
        public override Stream? ContentStream
        {
            get { Check(); return content; }
            set { Check(); content = value; }
        }
        public override void Dispose() => Check();
        protected override bool ContainsHeader(string name) => owned.Headers.Contains(name);
        protected override IEnumerable<HttpHeader> EnumerateHeaders() => owned.Headers;
        protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value) =>
            owned.Headers.TryGetValue(name, out value);
        protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values) =>
            owned.Headers.TryGetValues(name, out values);
    }

    // A getter or disposal is not evidence that the SDK consumed captured bytes.
    // The bounded adapter copy must read the complete source stream through EOF.
    private sealed class PurgeParserStream(Stream input, int length, Action check) : Stream
    {
        private int consumed;
        internal bool Complete { get; private set; }
        private int Record(int count)
        {
            consumed = checked(consumed + count);
            if (count == 0 && consumed == length) Complete = true;
            return count;
        }
        public override int Read(byte[] buffer, int offset, int count)
        {
            check();
            return Record(input.Read(buffer, offset, count));
        }
        public override int Read(Span<byte> buffer)
        {
            check();
            return Record(input.Read(buffer));
        }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            check();
            return Record(await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false));
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private async Task SendDeleteVaultAsync(DeleteVaultContext context, HttpMessage message)
    {
        var r = context.Registration;
        lock (gate)
        {
            if (context.Check) { r.CheckSends++; r.Invalid = true; throw new InvalidOperationException("delete-vault-cached-check"); }
            Require(!r.Sealed && r.Sends++ == 0 && r.Requests.Contains(message.Request) &&
                r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched);
        }
        Request original = message.Request;
        try
        {
            DeleteVaultRequest(r, message);
            var headers = original.Headers.ToArray();
            message.CancellationToken.ThrowIfCancellationRequested();
            r.BeforeSend?.Invoke();
            DeleteVaultRequest(r, message);
            Require(ReferenceEquals(message.Request, original) && headers.SequenceEqual(original.Headers));
            message.BufferResponse = false;
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            DeleteVaultRequest(r, message);
            Require(ReferenceEquals(message.Request, original) && headers.SequenceEqual(original.Headers));
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, r.Storage,
                allowContinuation: true).ConfigureAwait(false);
            DeleteVaultRequest(r, message);
            Require(ReferenceEquals(message.Request, original) && headers.SequenceEqual(original.Headers));
            int status = body.Response.Status;
            Require(status is 200 or 403);
            using var json = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int rows = 512;
            JsonRows(json.RootElement, ref rows);
            var root = json.RootElement;
            Require(root.ValueKind == JsonValueKind.Object && !root.TryGetProperty("nextLink", out _) &&
                !root.TryGetProperty("value", out _) && !root.TryGetProperty("partial", out _));
            string? next = Continuation(r.Window, message);
            StatusTarget? target = null;
            if (status == 403)
            {
                Require(next is null && root.EnumerateObject().All(p => p.Name == "error") &&
                    root.GetProperty("error").GetProperty("code").GetString() is
                    "Forbidden" or "AuthorizationFailed" or "AccessDenied");
                var error = root.GetProperty("error");
                Require(error.ValueKind == JsonValueKind.Object &&
                    error.EnumerateObject().All(p => p.Name is "code" or "message" or "target" or "details" or "innererror"));
                if (error.TryGetProperty("message", out var text)) Require(text.ValueKind == JsonValueKind.String);
                if (error.TryGetProperty("target", out var errorTarget)) Require(errorTarget.ValueKind == JsonValueKind.String);
                if (error.TryGetProperty("details", out var details)) Require(details.ValueKind == JsonValueKind.Array);
                if (error.TryGetProperty("innererror", out var innerError)) Require(innerError.ValueKind == JsonValueKind.Object);
            }
            else
            {
                Require(next is not null && !root.TryGetProperty("error", out _));
                if (root.TryGetProperty("id", out var id)) Require(id.GetString() == r.Window.Path);
                Require(!root.TryGetProperty("status", out _) || !root.TryGetProperty("properties", out var properties) ||
                    !properties.TryGetProperty("provisioningState", out _));
                string? state = root.TryGetProperty("status", out var value) ? value.GetString() :
                    root.GetProperty("properties").GetProperty("provisioningState").GetString();
                Require(State(state) == WireState.Pending);
                byte[] targetBytes = System.Text.Encoding.UTF8.GetBytes(next);
                try
                {
                    target = new(r.Binding, Guid.NewGuid(), StatusTargetKind.Operation, new Uri(next),
                        Convert.ToHexString(SHA256.HashData(targetBytes)), body.Sha256);
                }
                finally { CryptographicOperations.ZeroMemory(targetBytes); }
            }
            r.Wire = new(status, body.Sha256, body.NativeRequestId, target);
        }
        catch { r.Invalid = true; throw; }
    }

    internal bool TryGetStatusTarget(Window window, Binding expectedBinding,
        [NotNullWhen(true)] out StatusTarget? target)
    {
        lock (gate)
        {
            target = null;
            if (window is null || !ReferenceEquals(window.Owner, owner) || !eligible.Contains(window) ||
                window.Binding != expectedBinding ||
                StatusDeniedVaultRecoverSelector(window.Binding.Selector) &&
                    (!statusDeniedVaultRecovers.TryGetValue(window, out var deniedVaultRecover) ||
                        !StatusDeniedVaultRecoverTargetValid(deniedVaultRecover, expectedBinding)) ||
                StatusDeniedVaultUpdateSelector(window.Binding.Selector) &&
                    (!statusDeniedVaultUpdates.TryGetValue(window, out var deniedVaultUpdate) ||
                        !StatusDeniedVaultUpdateTargetValid(deniedVaultUpdate, expectedBinding)) ||
                StatusDeniedPrivateConnectionDeleteSelector(window.Binding.Selector) &&
                    (!statusDeniedPrivateConnectionDeletes.TryGetValue(window, out var deniedPrivateDelete) ||
                        !StatusDeniedPrivateConnectionDeleteTargetValid(deniedPrivateDelete, expectedBinding)) ||
                statusDeniedPurges.TryGetValue(window, out var deniedPurge) &&
                    !StatusDeniedPurgeTargetValid(deniedPurge, expectedBinding) ||
                statusDeniedNotificationUpdate.TryGetValue(window, out var deniedUpdate) &&
                    (!StatusDeniedNotificationUpdateStartValid(deniedUpdate) || !ReferenceEquals(window.Binding, expectedBinding)) ||
                TryGetStatusPendingPurgeRun(window, out var pending) &&
                    (!ReferenceEquals(window.Binding, expectedBinding) || !StatusPendingPurgeLive(pending) ||
                        pending.SelectedRevoked || pending.StartFacts is null || pending.Start is not { Finished: true } ||
                        pending.Start.Token.IsCancellationRequested || !StatusPendingPurgeHistoryValid(pending)) ||
                statusNotificationUpdateIndependent.TryGetValue(window, out var independentUpdate) &&
                    (!StatusNotificationUpdateIndependentStartValid(independentUpdate) || !ReferenceEquals(window.Binding, expectedBinding)) ||
                statusUnknownNotificationUpdate.TryGetValue(window, out var unknownUpdate) &&
                    (!StatusUnknownNotificationUpdateStartValid(unknownUpdate) || !ReferenceEquals(window.Binding, expectedBinding)) ||
                statusUnknownNotificationUpdateCancellation.TryGetValue(window, out var unknownCancellationUpdate) &&
                    (!StatusUnknownNotificationUpdateCancellationStartValid(unknownCancellationUpdate) || !ReferenceEquals(window.Binding, expectedBinding)) ||
                statusUnknownNotificationUpdateIndependent.TryGetValue(window, out var unknownIndependentUpdate) &&
                    (!StatusUnknownNotificationUpdateIndependentStartValid(unknownIndependentUpdate) || !ReferenceEquals(window.Binding, expectedBinding)) ||
                statusNotificationCreateIndependent.TryGetValue(window, out var independentCreate) &&
                    (!StatusNotificationCreateIndependentStartValid(independentCreate) || !ReferenceEquals(window.Binding, expectedBinding)) ||
                statusSucceededDeleteVault.TryGetValue(window, out var succeeded) &&
                    (succeeded.Invalid || succeeded.Sealed || succeeded.StartProof is null ||
                        succeeded.StartToken.IsCancellationRequested || !ReferenceEquals(window.Binding, expectedBinding)) ||
                statusSucceededDeleteVaultCancellation.TryGetValue(window, out var cancellationSucceeded) &&
                    (cancellationSucceeded.Invalid || cancellationSucceeded.Sealed || cancellationSucceeded.StartProof is null ||
                        cancellationSucceeded.StartToken.IsCancellationRequested || !ReferenceEquals(window.Binding, expectedBinding)) ||
                statusSucceededDeleteVaultIndependent.TryGetValue(window, out var independentSucceeded) &&
                    (independentSucceeded.Invalid || independentSucceeded.Sealed || independentSucceeded.StartProof is null ||
                        independentSucceeded.StartToken.IsCancellationRequested || !ReferenceEquals(window.Binding, expectedBinding)) ||
                (VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(window.Binding.Selector) ||
                    VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(window.Binding.Selector) ||
                    VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(window.Binding.Selector) ||
                    VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(window.Binding.Selector)) &&
                    (!statusVaultCancellations.TryGetValue(window, out var statusDeletion) ||
                        !ReferenceEquals(statusDeletion.Binding, expectedBinding) || !StatusVaultCancellationStartValid(statusDeletion)) ||
                (deleteVaultWindows.Contains(window) || purgeDeletedVaultWindows.Contains(window) ||
                    createVaultWindows.Contains(window) || recoverVaultWindows.Contains(window)) &&
                    !ReferenceEquals(window.Binding, expectedBinding) ||
                !targets.TryGetValue(window, out target) || target is null)
                return false;
            return true;
        }
    }

    internal bool OwnsStatusTarget(StatusTarget target, Binding expectedBinding)
    {
        lock (gate)
            return target is not null && target.Binding == expectedBinding &&
                targets.Any(pair => ReferenceEquals(pair.Value, target) && eligible.Contains(pair.Key) &&
                    (!StatusDeniedVaultRecoverSelector(pair.Key.Binding.Selector) ||
                        statusDeniedVaultRecovers.TryGetValue(pair.Key, out var deniedVaultRecover) &&
                        StatusDeniedVaultRecoverTargetValid(deniedVaultRecover, expectedBinding)) &&
                    (!StatusDeniedVaultUpdateSelector(pair.Key.Binding.Selector) ||
                        statusDeniedVaultUpdates.TryGetValue(pair.Key, out var deniedVaultUpdate) &&
                        StatusDeniedVaultUpdateTargetValid(deniedVaultUpdate, expectedBinding)) &&
                    (!StatusDeniedPrivateConnectionDeleteSelector(pair.Key.Binding.Selector) ||
                        statusDeniedPrivateConnectionDeletes.TryGetValue(pair.Key, out var deniedPrivateDelete) &&
                        StatusDeniedPrivateConnectionDeleteTargetValid(deniedPrivateDelete, expectedBinding)) &&
                    (!statusDeniedPurges.TryGetValue(pair.Key, out var deniedPurge) ||
                        StatusDeniedPurgeTargetValid(deniedPurge, expectedBinding)) &&
                    (!statusDeniedNotificationUpdate.TryGetValue(pair.Key, out var deniedUpdate) ||
                        StatusDeniedNotificationUpdateStartValid(deniedUpdate) && ReferenceEquals(pair.Key.Binding, expectedBinding)) &&
                    (!TryGetStatusPendingPurgeRun(pair.Key, out var pending) ||
                        ReferenceEquals(pair.Key.Binding, expectedBinding) && StatusPendingPurgeLive(pending) &&
                        !pending.SelectedRevoked && pending.StartFacts is not null && pending.Start is { Finished: true } &&
                        !pending.Start.Token.IsCancellationRequested && StatusPendingPurgeHistoryValid(pending)) &&
                    (!statusNotificationUpdateIndependent.TryGetValue(pair.Key, out var independentUpdate) ||
                        StatusNotificationUpdateIndependentStartValid(independentUpdate) && ReferenceEquals(pair.Key.Binding, expectedBinding)) &&
                    (!statusUnknownNotificationUpdate.TryGetValue(pair.Key, out var unknownUpdate) ||
                        StatusUnknownNotificationUpdateStartValid(unknownUpdate) && ReferenceEquals(pair.Key.Binding, expectedBinding)) &&
                    (!statusUnknownNotificationUpdateCancellation.TryGetValue(pair.Key, out var unknownCancellationUpdate) ||
                        StatusUnknownNotificationUpdateCancellationStartValid(unknownCancellationUpdate) && ReferenceEquals(pair.Key.Binding, expectedBinding)) &&
                    (!statusUnknownNotificationUpdateIndependent.TryGetValue(pair.Key, out var unknownIndependentUpdate) ||
                        StatusUnknownNotificationUpdateIndependentStartValid(unknownIndependentUpdate) && ReferenceEquals(pair.Key.Binding, expectedBinding)) &&
                    (!statusNotificationCreateIndependent.TryGetValue(pair.Key, out var independentCreate) ||
                        StatusNotificationCreateIndependentStartValid(independentCreate) && ReferenceEquals(pair.Key.Binding, expectedBinding)) &&
                    (!statusSucceededDeleteVault.TryGetValue(pair.Key, out var succeeded) ||
                        !succeeded.Invalid && !succeeded.Sealed && succeeded.StartProof is not null &&
                        !succeeded.StartToken.IsCancellationRequested && ReferenceEquals(pair.Key.Binding, expectedBinding)) &&
                    (!statusSucceededDeleteVaultCancellation.TryGetValue(pair.Key, out var cancellationSucceeded) ||
                        !cancellationSucceeded.Invalid && !cancellationSucceeded.Sealed && cancellationSucceeded.StartProof is not null &&
                        !cancellationSucceeded.StartToken.IsCancellationRequested && ReferenceEquals(pair.Key.Binding, expectedBinding)) &&
                    (!statusSucceededDeleteVaultIndependent.TryGetValue(pair.Key, out var independentSucceeded) ||
                        !independentSucceeded.Invalid && !independentSucceeded.Sealed && independentSucceeded.StartProof is not null &&
                        !independentSucceeded.StartToken.IsCancellationRequested && ReferenceEquals(pair.Key.Binding, expectedBinding)) &&
                    (!(VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(pair.Key.Binding.Selector) ||
                        VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(pair.Key.Binding.Selector) ||
                        VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(pair.Key.Binding.Selector) ||
                        VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(pair.Key.Binding.Selector)) ||
                        statusVaultCancellations.TryGetValue(pair.Key, out var statusDeletion) &&
                        ReferenceEquals(statusDeletion.Binding, expectedBinding) &&
                        ReferenceEquals(statusDeletion.Target, target) && StatusVaultCancellationStartValid(statusDeletion)) &&
                    (!(deleteVaultWindows.Contains(pair.Key) || purgeDeletedVaultWindows.Contains(pair.Key) ||
                        createVaultWindows.Contains(pair.Key) || recoverVaultWindows.Contains(pair.Key)) ||
                        ReferenceEquals(pair.Key.Binding, expectedBinding)));
    }

    internal bool OwnsNativeStatusCompletion(Window window, Binding expectedBinding)
    {
        lock (gate)
            return window is not null && ReferenceEquals(window.Owner, owner) &&
                !StatusDeniedVaultRecoverSelector(window.Binding.Selector) &&
                !statusDeniedVaultRecovers.ContainsKey(window) &&
                !StatusDeniedVaultUpdateSelector(window.Binding.Selector) &&
                !statusDeniedVaultUpdates.ContainsKey(window) &&
                !StatusDeniedPrivateConnectionDeleteSelector(window.Binding.Selector) &&
                !statusDeniedPrivateConnectionDeletes.ContainsKey(window) &&
                !statusDeniedPurges.ContainsKey(window) &&
                !(StatusDeniedNotificationUpdateSelector(window.Binding.Selector) &&
                    window.Binding.Selector.Variant == "operation." + window.Binding.Operation) &&
                !(NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationSelector(window.Binding.Selector) &&
                    window.Binding.Operation == ManagementMutation.UpdateNotification) &&
                !(NotificationFixtureProvisioner.StatusUnknownNotificationUpdateSelector(window.Binding.Selector) &&
                    window.Binding.Operation == ManagementMutation.UpdateNotification) &&
                !(NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentSelector(window.Binding.Selector) &&
                    window.Binding.Operation == ManagementMutation.UpdateNotification) &&
                !(StatusCanceledPurgeCancellationSelector(window.Binding.Selector) &&
                    window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
                !statusCanceledPurgeCancellations.ContainsKey(window) &&
                !(StatusCanceledPurgeIndependentSelector(window.Binding.Selector) &&
                    window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
                !statusCanceledPurgeIndependents.ContainsKey(window) &&
                !(StatusCanceledPurgeSelector(window.Binding.Selector) &&
                    window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
                !statusCanceledPurges.ContainsKey(window) &&
                !(StatusPendingPurgeIndependentSelector(window.Binding.Selector) &&
                    window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
                !(StatusPendingPurgeCancellationSelector(window.Binding.Selector) &&
                    window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
                !(StatusFailedPurgeSelector(window.Binding.Selector) &&
                    window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
                !(StatusFailedPurgeIndependentSelector(window.Binding.Selector) &&
                    window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
                !(StatusFailedPurgeCancellationSelector(window.Binding.Selector) &&
                    window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
                !statusPendingPurges.ContainsKey(window) && !statusPendingPurgeIndependents.ContainsKey(window) &&
                !statusPendingPurgeCancellations.ContainsKey(window) && !statusFailedPurges.ContainsKey(window) &&
                !statusFailedPurgeIndependents.ContainsKey(window) && !statusFailedPurgeCancellations.ContainsKey(window) &&
                window.Binding == expectedBinding && completedStatusReads.Contains(window) &&
                (!(VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(window.Binding.Selector) ||
                    VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(window.Binding.Selector) ||
                    VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(window.Binding.Selector)) ||
                    statusVaultCancellations.TryGetValue(window, out var r) &&
                    ReferenceEquals(r.Binding, expectedBinding) && StatusVaultCancellationStartValid(r) &&
                    r.Complete && r.Checked.Task.IsCompletedSuccessfully && !r.StatusToken.IsCancellationRequested);
    }

    internal bool TryGetSynchronousDeleteProof(Window window, Binding expectedBinding,
        [NotNullWhen(true)] out SynchronousDeleteProof? proof)
    {
        lock (gate)
        {
            proof = null;
            var registration = synchronousDeletes.Values.FirstOrDefault(r => ReferenceEquals(r.Window, window));
            if (registration is null || registration.Binding != expectedBinding || registration.Proof is null)
                return false;
            proof = registration.Proof;
            return true;
        }
    }

    internal bool OwnsSynchronousDeleteProof(SynchronousDeleteProof proof,
        Binding expectedBinding, VaultAdministration client, ManagementScope scope,
        ManagementReceipt receipt, ManagementOperation handle)
    {
        lock (gate)
            return proof is not null && synchronousDeletes.Values.Any(r =>
                ReferenceEquals(r.Proof, proof) && r.Binding == expectedBinding &&
                ReferenceEquals(r.Client, client) && ReferenceEquals(r.Scope, scope) &&
                ReferenceEquals(r.Receipt, receipt) && ReferenceEquals(r.Handle, handle));
    }

    internal bool TryGetPrivateApprovalResponseProof(Window window, Binding expectedBinding,
        [NotNullWhen(true)] out PrivateApprovalResponseProof? proof)
    {
        lock (gate)
        {
            proof = null;
            if (window is null || !privateApprovals.TryGetValue(window, out var registration) ||
                !ReferenceEquals(registration.Binding, expectedBinding) || !PrivateApprovalValid(registration))
                return false;
            proof = registration.Proof;
            return proof is not null;
        }
    }

    internal bool OwnsPrivateApprovalResponseProof(PrivateApprovalResponseProof proof, Window window,
        Binding expectedBinding, VaultAdministration client, PrivateConnectionScope scope,
        ManagementReceipt receipt, ManagementOperation handle, Task originalStartTask)
    {
        lock (gate)
            return window is not null && privateApprovals.TryGetValue(window, out var registration) &&
                proof is not null && ReferenceEquals(registration.Proof, proof) &&
                ReferenceEquals(registration.Binding, expectedBinding) &&
                ReferenceEquals(registration.Client, client) && ReferenceEquals(registration.Scope, scope) &&
                ReferenceEquals(registration.Receipt, receipt) && ReferenceEquals(registration.Handle, handle) &&
                originalStartTask is not null && ReferenceEquals(registration.StartTask, originalStartTask) &&
                PrivateApprovalValid(registration);
    }

    internal bool OwnsPrivateApprovalCompletion(PrivateApprovalResponseProof proof, Window window,
        Binding expectedBinding, VaultAdministration client, PrivateConnectionScope scope,
        ManagementReceipt receipt, ManagementOperation handle, Task originalStartTask, Task originalStatusTask)
    {
        lock (gate)
            return OwnsPrivateApprovalResponseProof(proof, window, expectedBinding, client, scope,
                receipt, handle, originalStartTask) &&
                privateApprovals.TryGetValue(window, out var registration) &&
                originalStatusTask is not null && ReferenceEquals(registration.StatusTask, originalStatusTask) &&
                registration.Completed && !registration.StatusInvalid && registration.StatusSends == 0 &&
                registration.StatusFinalized.Task.IsCompletedSuccessfully &&
                registration.StatusTask is { IsCompletedSuccessfully: true } &&
                !registration.StatusToken.IsCancellationRequested;
    }

    private static bool PrivateApprovalValid(PrivateApprovalRegistration registration) =>
        !registration.Sealed && !registration.Invalid && registration.Proof is not null &&
        registration.ResponseFacts is not null && registration.StartFinalized.Task.IsCompletedSuccessfully &&
        registration.StartTask is { IsCompletedSuccessfully: true } && registration.StartHookReturned &&
        registration.StartSucceeded && registration.TransportSucceeded && registration.Sends == 1 &&
        !registration.Token.IsCancellationRequested && registration.Handle?.State == NativeProvisioningState.Succeeded;

    // These typed hooks own the invocation itself. A caller cannot attach a
    // copied handle, a success dummy, a status variant, or an administrative LRO.
    // retained observes the exact Task for host lifetime accounting; it cannot
    // replace that Task or acknowledge it as drained.
    internal Task<SecretOutcome<ManagementOperation>> StartAsync(Window window, FixtureSelector selector,
        VaultAdministration client, ManagementScope scope, ManagementOperationEffects.Input input,
        ManagementReceipt receipt, CancellationToken token = default, Action<Task>? retained = null,
        Action? privateApprovalBeforeSend = null, bool statusPrivateDeleteSelectedProfile = false) =>
        StartCoreAsync(window, selector, client, scope, input, receipt, token, retained,
            privateApprovalBeforeSend, originalPrivateDelete: false, statusPrivateDeleteSelectedProfile);

    internal async Task<SecretOutcome<ManagementOperation>> StartNotificationDeleteIndependentAsync(
        Window window, FixtureSelector selector, VaultAdministration client, ManagementScope scope,
        ManagementOperationEffects.Input input, ManagementReceipt receipt, CancellationToken token = default,
        Action<Task>? retained = null, Action? beforeSend = null)
    {
        StatusNotificationDeleteIndependentRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(client is not null && receipt is not null && scope is NotificationScope &&
                NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(selector) &&
                window.Binding.Operation == ManagementMutation.DeleteNotification &&
                window.Binding.ApiRevision == "2025-02-15" && InputMatches(window.Binding, input) &&
                Route(window.Binding with { Resource = scope }) == Route(window.Binding));
            Require(!window.Closed && window.Start is null && startedWindows.Add(window));
            var invocation = window.Start = new();
            r = new(window, invocation, client, (NotificationScope)scope, receipt, token, beforeSend);
            statusNotificationDeleteIndependent.Add(window, r);
            statusNotificationDeleteIndependentInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretOutcome<ManagementOperation>> task;
            var previous = current.Value;
            current.Value = new(window, r.Start, false);
            try { task = ManagementOperationEffects.StartAsync(client, scope, window.Binding.Operation, input, receipt, token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) r.Start.SdkTask = r.StartTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StartHookReturned = true;
            }
            finally
            {
                var result = await task.ConfigureAwait(false);
                lock (gate)
                {
                    r.Start.Outcome = result.Status;
                    r.Handle = result.IsSuccess ? result.Value : null;
                    r.Start.WrapperState = r.Handle?.State;
                    r.StartSucceeded = task.IsCompletedSuccessfully && result.IsSuccess &&
                        r.Handle!.State == NativeProvisioningState.Succeeded && receipt.Evidence == DispatchEvidence.Applied;
                    r.Start.HasNativeHandle = r.StartSucceeded;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; r.Start.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusNotificationDeleteIndependentAsync(r, r.Start).ConfigureAwait(false); }
    }

    private async Task<SecretStatus> CheckStatusNotificationDeleteIndependentAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained)
    {
        StatusNotificationDeleteIndependentRegistration r;
        Invocation invocation;
        lock (gate)
        {
            Own(window, selector);
            Require(statusNotificationDeleteIndependent.TryGetValue(window, out r!) &&
                handle is not null && ReferenceEquals(r.Handle, handle));
            bool valid = !r.CheckClaimed && !window.Closed && window.Status is null &&
                StatusNotificationDeleteIndependentStartValid(r) && !token.IsCancellationRequested &&
                handle.State == NativeProvisioningState.Succeeded && r.Receipt.Evidence == DispatchEvidence.Applied;
            r.CheckClaimed = true;
            r.Invalid |= !valid;
            Require(valid);
            invocation = r.Status = window.Status = new();
            r.StatusToken = token;
            statusNotificationDeleteIndependentInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretStatus> task;
            var previous = current.Value;
            current.Value = new(window, invocation, true);
            try { task = handle.CheckStatusAsync(token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) invocation.SdkTask = r.StatusTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StatusHookReturned = true;
            }
            finally
            {
                var outcome = await task.ConfigureAwait(false);
                lock (gate)
                {
                    invocation.Outcome = outcome;
                    invocation.WrapperState = handle.State;
                    r.StatusSucceeded = task.IsCompletedSuccessfully && outcome == SecretStatus.Success &&
                        handle.State == NativeProvisioningState.Succeeded;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; invocation.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusNotificationDeleteIndependentAsync(r, invocation).ConfigureAwait(false); }
    }

    private async Task FinishStatusNotificationDeleteIndependentAsync(StatusNotificationDeleteIndependentRegistration r,
        Invocation invocation)
    {
        bool start = ReferenceEquals(r.Start, invocation);
        Task<Task>? borrower;
        lock (gate)
        {
            Task? actual = start ? r.StartTask : r.StatusTask;
            Require(actual is null || actual.IsCompleted);
            finishing.Add(invocation);
            borrower = borrowers.TryGetValue(invocation, out var pending) ? pending.Task : null;
        }
        if (borrower is not null)
        {
            var actual = await borrower.ConfigureAwait(false);
            try { await actual.ConfigureAwait(false); }
            catch { lock (gate) r.Invalid = true; }
        }
        bool custodyValid = true, disposalFailed = false;
        if (start)
        {
            try { custodyValid = r.Custody is { Complete: true }; }
            catch { custodyValid = false; }
            try { r.Storage.Dispose(); }
            catch { disposalFailed = true; }
        }
        lock (gate)
        {
            r.Invalid |= !custodyValid || disposalFailed;
            requestOwners.Remove(invocation);
            requestCandidates.Remove(invocation);
            borrowers.Remove(invocation);
            if (start)
            {
                r.StartComplete = !r.Invalid && r.StartHookReturned && r.StartSucceeded &&
                    r.TransportSucceeded && r.Sends == 1 && r.Candidate is not null &&
                    r.Wire is
                    {
                        Ordinal: 0, HttpStatus: 200 or 204, State: WireState.Succeeded, Complete: true,
                        RequestSha256.Length: 64, RequestHeaders: not null
                    } &&
                    r.Wire.Dispatch == r.Candidate.StartDispatch &&
                    r.StartTask is { IsCompletedSuccessfully: true } && !r.StartToken.IsCancellationRequested &&
                    r.Handle?.State == NativeProvisioningState.Succeeded && r.Receipt.Evidence == DispatchEvidence.Applied;
                if (r.StartComplete) r.StartProof = r.Candidate;
                r.Started.TrySetResult();
            }
            else
            {
                r.Complete = StatusNotificationDeleteIndependentStartValid(r) && r.StatusHookReturned && r.StatusSucceeded &&
                    r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                    r.Receipt.Evidence == DispatchEvidence.Applied && r.Handle?.State == NativeProvisioningState.Succeeded &&
                    !requestFactories.Contains(invocation) && r.Status!.Attempts.Count == 0 &&
                    targets.GetValueOrDefault(r.Window) is null && !completedStatusReads.Contains(r.Window);
                if (r.Complete) r.Completion = new(r.StartProof!);
                r.Checked.TrySetResult();
            }
            invocation.Terminated = true;
            invocation.Drained.TrySetResult();
        }
        if (disposalFailed) throw new InvalidOperationException("management-capture-finalization");
    }

    private Task<Capture> SealStatusNotificationDeleteIndependentAsync(Window window)
    {
        StatusNotificationDeleteIndependentRegistration r;
        TaskCompletionSource ready;
        Task<Capture> task;
        lock (gate)
        {
            Own(window, window.Binding.Selector);
            r = statusNotificationDeleteIndependent[window];
            window.Closed = true;
            if (r.SealTask is not null) return r.SealTask;
            r.Sealed = true;
            ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = r.SealTask = Drain(ready.Task);
        }
        ready.SetResult();
        return task;

        async Task<Capture> Drain(Task admission)
        {
            await admission.ConfigureAwait(false);
            await r.Started.Task.ConfigureAwait(false);
            if (r.Status is not null) await r.Checked.Task.ConfigureAwait(false);
            try { r.Storage.Dispose(); }
            catch { lock (gate) r.Invalid = true; throw; }
            return new() { Binding = r.Binding, Start = r.Start, Status = r.Status };
        }
    }

    private async Task SendStatusNotificationDeleteIndependentAsync(StatusNotificationDeleteIndependentRegistration r,
        InvocationContext context, HttpMessage message, TaskCompletionSource<Task> borrower)
    {
        var invocation = context.Invocation;
        lock (gate)
        {
            bool valid = !context.Status && ReferenceEquals(invocation, r.Start) && !r.Invalid && !r.Sealed &&
                !finishing.Contains(invocation) && ++r.Sends == 1 &&
                r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched &&
                requestCandidates.TryGetValue(invocation, out var candidates) && candidates.Contains(message.Request);
            r.Invalid |= !valid;
            Require(valid);
            borrowers.Add(invocation, borrower);
            invocation.Sending = true;
            requestOwners.Add(invocation, message.Request);
            requestCandidates.Remove(invocation);
        }
        Attempt? attempt = null;
        try
        {
            var request = message.Request;
            var headers = request.Headers.ToArray();
            var uri = request.Uri.ToUri();
            void CheckRequest()
            {
                Require(ReferenceEquals(message.Request, request) && headers.SequenceEqual(request.Headers) &&
                    headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                    request.Method == RequestMethod.Delete && request.Content is null &&
                    Trusted(request.Uri.ToUri()) && request.Uri.ToUri().AbsoluteUri == uri.AbsoluteUri &&
                    uri.AbsolutePath == r.Window.Path && uri.Query == "?api-version=2025-02-15" &&
                    !headers.Any(h => new[] { "Content-Encoding", "Transfer-Encoding", "Content-Range", "Range" }
                        .Contains(h.Name, StringComparer.OrdinalIgnoreCase)) &&
                    request.Headers.TryGetValue("Authorization", out var auth) &&
                    auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7);
                Headers(headers);
                var lengths = headers.Where(h => h.Name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)).ToArray();
                Require(lengths.Length == 0 || lengths is [{ Value: "0" }]);
                if (request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
                r.StartToken.ThrowIfCancellationRequested();
                message.CancellationToken.ThrowIfCancellationRequested();
            }
            CheckRequest();
            string hash = Convert.ToHexString(SHA256.HashData(ReadOnlySpan<byte>.Empty));
            Guid dispatch = Guid.NewGuid();
            attempt = new() { Dispatch = dispatch, RequestSha256 = hash };
            lock (gate) invocation.Attempts.Add(attempt);
            message.BufferResponse = false;
            r.BeforeSend?.Invoke();
            CheckRequest();
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            CheckRequest();
            var original = message.Response;
            var stream = original.ContentStream;
            int status = original.Status;
            string reason = original.ReasonPhrase, clientId = original.ClientRequestId;
            var responseHeaders = original.Headers.Take(33).ToArray();
            Headers(responseHeaders);
            attempt.HttpStatus = status;
            attempt.ResponseObserved = true;
            if (stream is not null)
            {
                r.Storage.Own(stream);
                byte[] one = new byte[1];
                try { Require(await stream.ReadAsync(one, message.CancellationToken).ConfigureAwait(false) == 0); }
                finally { CryptographicOperations.ZeroMemory(one); }
            }
            CheckRequest();
            Require(ReferenceEquals(message.Response, original) && ReferenceEquals(original.ContentStream, stream) &&
                original.Status == status && original.ReasonPhrase == reason && original.ClientRequestId == clientId &&
                responseHeaders.SequenceEqual(original.Headers) && reason.Length <= 256 && !reason.Any(char.IsControl) &&
                clientId.Length <= 1024 && !clientId.Any(char.IsControl) &&
                EmptyDeleteResponse(status, 0, responseHeaders, allow200: true));
            var buffer = new MemoryStream([], writable: false);
            r.Storage.Own(buffer);
            var owned = new OwnedArmResponse(status, reason, clientId, responseHeaders, buffer);
            r.Custody = new(message, original, stream, owned, r.Storage);
            attempt.ResponseSha256 = hash;
            attempt.State = WireState.Succeeded;
            attempt.Valid = true;
            lock (gate)
            {
                r.Wire = new(0, request, uri.AbsoluteUri, dispatch, status, WireState.Succeeded, hash,
                    responseHeaders.FirstOrDefault(h => h.Name.Equals("x-ms-request-id", StringComparison.OrdinalIgnoreCase)).Value ?? "",
                    true, hash, Array.AsReadOnly(headers.Select(h => (h.Name, h.Value)).ToArray()));
                r.Candidate = new(r.Binding, dispatch, status, hash);
                r.TransportSucceeded = true;
            }
        }
        catch (OperationCanceledException)
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw new IOException("management-capture-transport");
        }
        finally
        {
            lock (gate)
            {
                if (attempt is not null) attempt.TransportTerminated = true;
                invocation.Sending = false;
            }
        }
    }

    private async Task<SecretOutcome<ManagementOperation>> StartStatusPrivateDeleteSelectedAsync(
        Window window, FixtureSelector selector, VaultAdministration client, ManagementScope scope,
        ManagementOperationEffects.Input? input, ManagementReceipt receipt, CancellationToken token,
        Action<Task>? retained, Action? beforeSend)
    {
        StatusPrivateDeleteSelectedRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(client is not null && receipt is not null && scope is PrivateConnectionScope &&
                ReferenceEquals(window.Binding.Resource, scope));
            Require(!window.Closed && window.Start is null && startedWindows.Add(window));
            Require(VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(selector) &&
                window.Binding.Operation == ManagementMutation.DeletePrivateConnection &&
                window.Binding.ApiRevision == "2026-02-01" && InputMatches(window.Binding, input));
            var invocation = window.Start = new();
            r = new(window, invocation, client, (PrivateConnectionScope)scope, receipt, token, beforeSend);
            statusPrivateDeleteSelected.Add(window, r);
            statusPrivateDeleteSelectedInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretOutcome<ManagementOperation>> task;
            var previous = current.Value;
            current.Value = new(window, r.Start, false);
            try { task = client.DeletePrivateConnectionAsync(r.Scope, receipt, token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) r.Start.SdkTask = r.StartTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StartHookReturned = true;
            }
            finally
            {
                var result = await task.ConfigureAwait(false);
                lock (gate)
                {
                    r.Start.Outcome = result.Status;
                    r.Handle = result.IsSuccess ? result.Value : null;
                    r.Start.WrapperState = r.StartState = r.Handle?.State;
                    r.StartSucceeded = task.IsCompletedSuccessfully && result.IsSuccess &&
                        r.StartState is NativeProvisioningState.Pending or NativeProvisioningState.Succeeded &&
                        receipt.Evidence == DispatchEvidence.Pending;
                    r.Start.HasNativeHandle = r.StartSucceeded;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; r.Start.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusPrivateDeleteSelectedAsync(r, r.Start).ConfigureAwait(false); }
    }

    private async Task<SecretStatus> CheckStatusPrivateDeleteSelectedAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained)
    {
        StatusPrivateDeleteSelectedRegistration r;
        Invocation invocation;
        lock (gate)
        {
            Own(window, selector);
            Require(statusPrivateDeleteSelected.TryGetValue(window, out r!) &&
                handle is not null && ReferenceEquals(r.Handle, handle));
            bool valid = !r.CheckClaimed && !window.Closed && window.Status is null &&
                StatusPrivateDeleteSelectedStartValid(r) && !token.IsCancellationRequested &&
                handle.State == r.StartState && r.Receipt.Evidence == DispatchEvidence.Pending;
            r.CheckClaimed = true;
            r.Invalid |= !valid;
            Require(valid);
            invocation = r.Status = window.Status = new();
            r.StatusToken = token;
            statusPrivateDeleteSelectedInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretStatus> task;
            var previous = current.Value;
            current.Value = new(window, invocation, true);
            try { task = handle.CheckStatusAsync(token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) invocation.SdkTask = r.StatusTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StatusHookReturned = true;
            }
            finally
            {
                var outcome = await task.ConfigureAwait(false);
                lock (gate)
                {
                    invocation.Outcome = outcome;
                    invocation.WrapperState = handle.State;
                    r.StatusSucceeded = task.IsCompletedSuccessfully && outcome == SecretStatus.Success &&
                        handle.State == NativeProvisioningState.Succeeded;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; invocation.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusPrivateDeleteSelectedAsync(r, invocation).ConfigureAwait(false); }
    }

    private async Task FinishStatusPrivateDeleteSelectedAsync(StatusPrivateDeleteSelectedRegistration r,
        Invocation invocation)
    {
        bool start = ReferenceEquals(r.Start, invocation);
        Task<Task>? borrower;
        lock (gate)
        {
            Task? actual = start ? r.StartTask : r.StatusTask;
            Require(actual is null || actual.IsCompleted);
            finishing.Add(invocation);
            borrower = borrowers.TryGetValue(invocation, out var pending) ? pending.Task : null;
        }
        if (borrower is not null)
        {
            var actual = await borrower.ConfigureAwait(false);
            try { await actual.ConfigureAwait(false); }
            catch { lock (gate) r.Invalid = true; }
        }
        bool parserValid;
        try { parserValid = r.Parser is { Invalid: false } && (start || r.Parser.Complete); }
        catch { parserValid = false; }
        bool disposalFailed = false;
        if (!start)
        {
            try { r.Storage.Dispose(); }
            catch { disposalFailed = true; }
            try { parserValid &= r.Parser is { Complete: true, Invalid: false }; }
            catch { parserValid = false; }
        }
        lock (gate)
        {
            r.Invalid |= !parserValid || disposalFailed;
            requestOwners.Remove(invocation);
            requestCandidates.Remove(invocation);
            borrowers.Remove(invocation);
            if (start)
            {
                r.StartComplete = !r.Invalid && r.StartHookReturned && r.StartSucceeded &&
                    r.TransportSucceeded && r.Sends == 1 && r.Facts is not null && r.Dispatch != Guid.Empty &&
                    r.StartTask is { IsCompletedSuccessfully: true } && !r.StartToken.IsCancellationRequested &&
                    r.Handle?.State == r.StartState && r.Receipt.Evidence == DispatchEvidence.Pending;
                if (r.StartComplete)
                    r.StartProof = new(r.Binding, r.Dispatch, r.Facts!, r.RequestSha256!, r.ResponseSha256!,
                        r.NativeRequestId!, r.StartState!.Value);
                r.Started.TrySetResult();
            }
            else
            {
                r.Complete = StatusPrivateDeleteSelectedStartValid(r) && r.StatusHookReturned && r.StatusSucceeded &&
                    r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                    r.Receipt.Evidence == DispatchEvidence.Pending && r.Handle?.State == NativeProvisioningState.Succeeded &&
                    r.Status!.Attempts.Count == 0 && !completedStatusReads.Contains(r.Window);
                if (r.Complete) r.Completion = new(r.StartProof!);
                r.Checked.TrySetResult();
            }
            invocation.Terminated = true;
            invocation.Drained.TrySetResult();
        }
        if (disposalFailed) throw new InvalidOperationException("management-capture-finalization");
    }

    private Task<Capture> SealStatusPrivateDeleteSelectedAsync(Window window)
    {
        StatusPrivateDeleteSelectedRegistration r;
        TaskCompletionSource ready;
        Task<Capture> task;
        lock (gate)
        {
            Own(window, window.Binding.Selector);
            window.Closed = true;
            if (!statusPrivateDeleteSelected.TryGetValue(window, out r!))
                return Task.FromResult(new Capture { Binding = window.Binding });
            if (r.SealTask is not null) return r.SealTask;
            r.Sealed = true;
            ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = r.SealTask = Drain(ready.Task);
        }
        ready.SetResult();
        return task;

        async Task<Capture> Drain(Task admission)
        {
            await admission.ConfigureAwait(false);
            await r.Started.Task.ConfigureAwait(false);
            if (r.Status is not null) await r.Checked.Task.ConfigureAwait(false);
            try { r.Storage.Dispose(); }
            catch { lock (gate) r.Invalid = true; throw; }
            return new() { Binding = r.Binding, Start = r.Start, Status = r.Status };
        }
    }

    private async Task SendStatusPrivateDeleteSelectedAsync(StatusPrivateDeleteSelectedRegistration r,
        InvocationContext context, HttpMessage message, TaskCompletionSource<Task> borrower)
    {
        var invocation = context.Invocation;
        lock (gate)
        {
            bool valid = !context.Status && ReferenceEquals(invocation, r.Start) && !r.Invalid && !r.Sealed &&
                !finishing.Contains(invocation) && ++r.Sends == 1 &&
                r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched &&
                requestCandidates.TryGetValue(invocation, out var candidates) && candidates.Contains(message.Request);
            r.Invalid |= !valid;
            Require(valid);
            borrowers.Add(invocation, borrower);
            invocation.Sending = true;
            requestOwners.Add(invocation, message.Request);
            requestCandidates.Remove(invocation);
        }
        Attempt? attempt = null;
        try
        {
            var request = message.Request;
            var headers = request.Headers.Select(h => (h.Name, h.Value)).ToArray();
            void CheckRequest()
            {
                Require(ReferenceEquals(message.Request, request) &&
                    headers.SequenceEqual(request.Headers.Select(h => (h.Name, h.Value))));
                OriginalVaultRequest(message, r.Window.Path, RequestMethod.Delete);
                r.StartToken.ThrowIfCancellationRequested();
                message.CancellationToken.ThrowIfCancellationRequested();
            }
            CheckRequest();
            r.RequestSha256 = Convert.ToHexString(SHA256.HashData(ReadOnlySpan<byte>.Empty));
            r.Dispatch = Guid.NewGuid();
            attempt = new() { Dispatch = r.Dispatch, RequestSha256 = r.RequestSha256 };
            lock (gate) invocation.Attempts.Add(attempt);
            message.BufferResponse = false;
            r.BeforeSend?.Invoke();
            CheckRequest();
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            CheckRequest();
            var original = message.Response;
            var stream = original.ContentStream;
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, r.Storage).ConfigureAwait(false);
            Require(ReferenceEquals(original.ContentStream, stream));
            CheckRequest();
            var responseHeaders = body.Response.Headers.Select(h => (h.Name, h.Value)).ToArray();
            attempt.HttpStatus = body.Response.Status;
            attempt.ResponseObserved = true;
            attempt.ResponseSha256 = body.Sha256;
            r.ResponseSha256 = body.Sha256;
            r.NativeRequestId = body.NativeRequestId;
            r.Parser = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, r.Storage,
                requireRebuffer: true, requireDownstreamRead: true);
            var strict = PrivateConnectionResponse(r.Scope, PrivateConnectionState.Disconnected, body.Bytes,
                responseHeaders, body.Response.Status);
            if (strict is not null)
            {
                try
                {
                    using var json = JsonDocument.Parse(body.Bytes);
                    var model = ModelReaderWriter.Read<KeyVaultPrivateEndpointConnectionData>(new BinaryData(body.Bytes));
                    Require(model is not null);
                    r.Facts = ManagementOperationResourceCollector.ValidateStatusPrivateConnectionResource(
                        json.RootElement, model, r.Scope, r.Binding.Location, allowLocation: false);
                }
                catch { r.Facts = null; }
            }
            // Side decoding is eligibility only. The original operation retains
            // this same envelope and must consume it on its actual check.
            attempt.Valid = r.Facts is { State: "Disconnected", Provisioning: "Succeeded" };
            attempt.State = attempt.Valid ? WireState.Succeeded : WireState.Unknown;
            lock (gate) r.Invalid |= !attempt.Valid;
            CheckRequest();
            lock (gate) r.TransportSucceeded = true;
        }
        catch (OperationCanceledException)
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw new IOException("management-capture-transport");
        }
        finally
        {
            lock (gate)
            {
                if (attempt is not null) attempt.TransportTerminated = true;
                invocation.Sending = false;
            }
        }
    }

    internal async Task<SecretOutcome<ManagementOperation>> StartPrivateConnectionDeleteIndependentAsync(
        Window window, FixtureSelector selector, VaultAdministration client, ManagementScope scope,
        ManagementOperationEffects.Input input, ManagementReceipt receipt, CancellationToken token = default,
        Action<Task>? retained = null, Action? beforeSend = null)
    {
        StatusPrivateDeleteIndependentRegistration r;
        lock (gate)
        {
            Own(window, selector);
            Require(client is not null && receipt is not null && scope is PrivateConnectionScope &&
                ReferenceEquals(window.Binding.Resource, scope));
            Require(!window.Closed && window.Start is null && startedWindows.Add(window));
            Require(VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(selector) &&
                window.Binding.Operation == ManagementMutation.DeletePrivateConnection &&
                window.Binding.ApiRevision == "2026-02-01" && InputMatches(window.Binding, input));
            var invocation = window.Start = new();
            r = new(window, invocation, client, (PrivateConnectionScope)scope, receipt, token, beforeSend);
            statusPrivateDeleteIndependent.Add(window, r);
            statusPrivateDeleteIndependentInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretOutcome<ManagementOperation>> task;
            var previous = current.Value;
            current.Value = new(window, r.Start, false);
            try { task = client.DeletePrivateConnectionAsync(r.Scope, receipt, token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) r.Start.SdkTask = r.StartTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StartHookReturned = true;
            }
            finally
            {
                var result = await task.ConfigureAwait(false);
                lock (gate)
                {
                    r.Start.Outcome = result.Status;
                    r.Handle = result.IsSuccess ? result.Value : null;
                    r.Start.WrapperState = r.StartState = r.Handle?.State;
                    r.StartSucceeded = task.IsCompletedSuccessfully && result.IsSuccess &&
                        r.StartState is NativeProvisioningState.Pending or NativeProvisioningState.Succeeded &&
                        receipt.Evidence == DispatchEvidence.Pending;
                    r.Start.HasNativeHandle = r.StartSucceeded;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; r.Start.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusPrivateDeleteIndependentAsync(r, r.Start).ConfigureAwait(false); }
    }

    private async Task<SecretStatus> CheckStatusPrivateDeleteIndependentAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token, Action<Task>? retained)
    {
        StatusPrivateDeleteIndependentRegistration r;
        Invocation invocation;
        lock (gate)
        {
            Own(window, selector);
            Require(statusPrivateDeleteIndependent.TryGetValue(window, out r!) &&
                handle is not null && ReferenceEquals(r.Handle, handle));
            bool valid = !r.CheckClaimed && !window.Closed && window.Status is null &&
                StatusPrivateDeleteIndependentStartValid(r) && !token.IsCancellationRequested &&
                handle.State == r.StartState && r.Receipt.Evidence == DispatchEvidence.Pending;
            r.CheckClaimed = true;
            r.Invalid |= !valid;
            Require(valid);
            invocation = r.Status = window.Status = new();
            r.StatusToken = token;
            statusPrivateDeleteIndependentInvocations.Add(invocation, r);
        }
        try
        {
            Task<SecretStatus> task;
            var previous = current.Value;
            current.Value = new(window, invocation, true);
            try { task = handle.CheckStatusAsync(token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate) invocation.SdkTask = r.StatusTask = task;
            try
            {
                retained?.Invoke(task);
                lock (gate) r.StatusHookReturned = true;
            }
            finally
            {
                var outcome = await task.ConfigureAwait(false);
                lock (gate)
                {
                    invocation.Outcome = outcome;
                    invocation.WrapperState = handle.State;
                    r.StatusSucceeded = task.IsCompletedSuccessfully && outcome == SecretStatus.Success &&
                        handle.State == NativeProvisioningState.Succeeded;
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate) { r.Invalid = true; invocation.Canceled = true; }
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        finally { await FinishStatusPrivateDeleteIndependentAsync(r, invocation).ConfigureAwait(false); }
    }

    private async Task FinishStatusPrivateDeleteIndependentAsync(StatusPrivateDeleteIndependentRegistration r,
        Invocation invocation)
    {
        bool start = ReferenceEquals(r.Start, invocation);
        Task<Task>? borrower;
        lock (gate)
        {
            Task? actual = start ? r.StartTask : r.StatusTask;
            Require(actual is null || actual.IsCompleted);
            finishing.Add(invocation);
            borrower = borrowers.TryGetValue(invocation, out var pending) ? pending.Task : null;
        }
        if (borrower is not null)
        {
            var actual = await borrower.ConfigureAwait(false);
            try { await actual.ConfigureAwait(false); }
            catch { lock (gate) r.Invalid = true; }
        }
        bool parserValid;
        try { parserValid = r.Parser is { Invalid: false } && (start || r.Parser.Complete); }
        catch { parserValid = false; }
        bool disposalFailed = false;
        if (!start)
        {
            try { r.Storage.Dispose(); }
            catch { disposalFailed = true; }
            try { parserValid &= r.Parser is { Complete: true, Invalid: false }; }
            catch { parserValid = false; }
        }
        lock (gate)
        {
            r.Invalid |= !parserValid || disposalFailed;
            requestOwners.Remove(invocation);
            requestCandidates.Remove(invocation);
            borrowers.Remove(invocation);
            if (start)
            {
                r.StartComplete = !r.Invalid && r.StartHookReturned && r.StartSucceeded &&
                    r.TransportSucceeded && r.Sends == 1 && r.Facts is not null && r.Dispatch != Guid.Empty &&
                    r.StartTask is { IsCompletedSuccessfully: true } && !r.StartToken.IsCancellationRequested &&
                    r.Handle?.State == r.StartState && r.Receipt.Evidence == DispatchEvidence.Pending;
                if (r.StartComplete)
                    r.StartProof = new(r.Binding, r.Dispatch, r.Facts!, r.RequestSha256!, r.ResponseSha256!,
                        r.NativeRequestId!, r.StartState!.Value);
                r.Started.TrySetResult();
            }
            else
            {
                r.Complete = StatusPrivateDeleteIndependentStartValid(r) && r.StatusHookReturned && r.StatusSucceeded &&
                    r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                    r.Receipt.Evidence == DispatchEvidence.Pending && r.Handle?.State == NativeProvisioningState.Succeeded &&
                    r.Status!.Attempts.Count == 0 && !completedStatusReads.Contains(r.Window);
                if (r.Complete) r.Completion = new(r.StartProof!);
                r.Checked.TrySetResult();
            }
            invocation.Terminated = true;
            invocation.Drained.TrySetResult();
        }
        if (disposalFailed) throw new InvalidOperationException("management-capture-finalization");
    }

    private Task<Capture> SealStatusPrivateDeleteIndependentAsync(Window window)
    {
        StatusPrivateDeleteIndependentRegistration r;
        TaskCompletionSource ready;
        Task<Capture> task;
        lock (gate)
        {
            Own(window, window.Binding.Selector);
            if (statusPrivateDeleteIndependentSeals.TryGetValue(window, out var sealedTask)) return sealedTask;
            window.Closed = true;
            if (!statusPrivateDeleteIndependent.TryGetValue(window, out r!))
                return Task.FromResult(new Capture { Binding = window.Binding });
            if (r.SealTask is not null) return r.SealTask;
            r.Sealed = true;
            ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = r.SealTask = Drain(ready.Task);
            statusPrivateDeleteIndependentSeals.Add(window, task);
        }
        ready.SetResult();
        return task;

        async Task<Capture> Drain(Task admission)
        {
            await admission.ConfigureAwait(false);
            await r.Started.Task.ConfigureAwait(false);
            if (r.Status is not null) await r.Checked.Task.ConfigureAwait(false);
            try { r.Storage.Dispose(); }
            catch { lock (gate) r.Invalid = true; throw; }
            finally
            {
                lock (gate)
                {
                    r.StartProof = null;
                    r.Completion = null;
                    statusPrivateDeleteIndependentInvocations.Remove(r.Start);
                    if (r.Status is not null) statusPrivateDeleteIndependentInvocations.Remove(r.Status);
                    statusPrivateDeleteIndependent.Remove(window);
                }
            }
            return new() { Binding = r.Binding, Start = r.Start, Status = r.Status };
        }
    }

    private async Task SendStatusPrivateDeleteIndependentAsync(StatusPrivateDeleteIndependentRegistration r,
        InvocationContext context, HttpMessage message, TaskCompletionSource<Task> borrower)
    {
        var invocation = context.Invocation;
        lock (gate)
        {
            bool valid = !context.Status && ReferenceEquals(invocation, r.Start) && !r.Invalid && !r.Sealed &&
                !finishing.Contains(invocation) && ++r.Sends == 1 &&
                r.Receipt.Evidence == DispatchEvidence.PossiblyDispatched &&
                requestCandidates.TryGetValue(invocation, out var candidates) && candidates.Contains(message.Request);
            r.Invalid |= !valid;
            Require(valid);
            borrowers.Add(invocation, borrower);
            invocation.Sending = true;
            requestOwners.Add(invocation, message.Request);
            requestCandidates.Remove(invocation);
        }
        Attempt? attempt = null;
        try
        {
            var request = message.Request;
            var headers = request.Headers.Select(h => (h.Name, h.Value)).ToArray();
            void CheckRequest()
            {
                Require(ReferenceEquals(message.Request, request) &&
                    headers.SequenceEqual(request.Headers.Select(h => (h.Name, h.Value))));
                OriginalVaultRequest(message, r.Window.Path, RequestMethod.Delete);
                r.StartToken.ThrowIfCancellationRequested();
                message.CancellationToken.ThrowIfCancellationRequested();
            }
            CheckRequest();
            r.RequestSha256 = Convert.ToHexString(SHA256.HashData(ReadOnlySpan<byte>.Empty));
            r.Dispatch = Guid.NewGuid();
            attempt = new() { Dispatch = r.Dispatch, RequestSha256 = r.RequestSha256 };
            lock (gate) invocation.Attempts.Add(attempt);
            message.BufferResponse = false;
            r.BeforeSend?.Invoke();
            CheckRequest();
            try { await backend.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) r.Storage.Own(message.Response); }
            CheckRequest();
            var original = message.Response;
            var stream = original.ContentStream;
            var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, r.Storage).ConfigureAwait(false);
            Require(ReferenceEquals(original.ContentStream, stream));
            CheckRequest();
            var responseHeaders = body.Response.Headers.Select(h => (h.Name, h.Value)).ToArray();
            attempt.HttpStatus = body.Response.Status;
            attempt.ResponseObserved = true;
            attempt.ResponseSha256 = body.Sha256;
            r.ResponseSha256 = body.Sha256;
            r.NativeRequestId = body.NativeRequestId;
            r.Parser = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, r.Storage,
                requireRebuffer: true, requireDownstreamRead: true);
            var strict = PrivateConnectionResponse(r.Scope, PrivateConnectionState.Disconnected, body.Bytes,
                responseHeaders, body.Response.Status);
            if (strict is not null)
            {
                try
                {
                    using var json = JsonDocument.Parse(body.Bytes);
                    var model = ModelReaderWriter.Read<KeyVaultPrivateEndpointConnectionData>(new BinaryData(body.Bytes));
                    Require(model is not null);
                    r.Facts = ManagementOperationResourceCollector.ValidateStatusPrivateConnectionResource(
                        json.RootElement, model, r.Scope, r.Binding.Location, allowLocation: false);
                }
                catch { r.Facts = null; }
            }
            // Side decoding is eligibility only. The original operation retains
            // this same envelope and must consume it on its actual check.
            attempt.Valid = r.Facts is { State: "Disconnected", Provisioning: "Succeeded" };
            attempt.State = attempt.Valid ? WireState.Succeeded : WireState.Unknown;
            lock (gate) r.Invalid |= !attempt.Valid;
            CheckRequest();
            lock (gate) r.TransportSucceeded = true;
        }
        catch (OperationCanceledException)
        {
            lock (gate) r.Invalid = true;
            throw;
        }
        catch
        {
            lock (gate) r.Invalid = true;
            throw new IOException("management-capture-transport");
        }
        finally
        {
            lock (gate)
            {
                if (attempt is not null) attempt.TransportTerminated = true;
                invocation.Sending = false;
            }
        }
    }

    private async Task<SecretOutcome<ManagementOperation>> StartCoreAsync(Window window, FixtureSelector selector,
        VaultAdministration client, ManagementScope scope, ManagementOperationEffects.Input? input,
        ManagementReceipt receipt, CancellationToken token, Action<Task>? retained,
        Action? privateApprovalBeforeSend, bool originalPrivateDelete, bool statusPrivateDeleteSelectedProfile = false)
    {
        if (statusPrivateDeleteSelectedProfile)
            return await StartStatusPrivateDeleteSelectedAsync(window, selector, client, scope, input, receipt, token,
                retained, privateApprovalBeforeSend).ConfigureAwait(false);
        Invocation invocation;
        PrivateConnectionDeleteRegistration? privateDelete = null;
        SynchronousDeleteRegistration? synchronousDelete = null;
        PrivateApprovalRegistration? privateApproval = null;
        StatusVaultCancellationRegistration? statusDeletion = null;
        lock (gate)
        {
            Own(window, selector);
            Require(!statusDeniedVaultRecovers.ContainsKey(window));
            Require(!statusDeniedVaultUpdates.ContainsKey(window));
            Require(!statusDeniedPrivateConnectionDeletes.ContainsKey(window));
            Require(!statusDeniedPurges.ContainsKey(window));
            Require(!statusDeniedNotificationUpdate.ContainsKey(window));
            Require(!(NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationSelector(selector) &&
                    window.Binding.Operation == ManagementMutation.UpdateNotification) &&
                !(NotificationFixtureProvisioner.StatusUnknownNotificationUpdateSelector(selector) &&
                    window.Binding.Operation == ManagementMutation.UpdateNotification) &&
                !(NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentSelector(selector) &&
                    window.Binding.Operation == ManagementMutation.UpdateNotification) &&
                !(StatusPendingPurgeIndependentSelector(selector) &&
                    window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
                !(StatusCanceledPurgeCancellationSelector(selector) &&
                    window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
                !statusCanceledPurgeCancellations.ContainsKey(window) &&
                !(StatusPendingPurgeCancellationSelector(selector) &&
                    window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
                !(StatusFailedPurgeSelector(selector) &&
                    window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
                !(StatusFailedPurgeIndependentSelector(selector) &&
                    window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
                !(StatusFailedPurgeCancellationSelector(selector) &&
                    window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
                !(StatusCanceledPurgeSelector(selector) &&
                    window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
                !(StatusCanceledPurgeIndependentSelector(selector) &&
                    window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
                !statusCanceledPurgeIndependents.ContainsKey(window) &&
                !statusCanceledPurges.ContainsKey(window) &&
                !statusPendingPurges.ContainsKey(window) && !statusPendingPurgeIndependents.ContainsKey(window) &&
                !statusPendingPurgeCancellations.ContainsKey(window) && !statusFailedPurges.ContainsKey(window) &&
                !statusFailedPurgeIndependents.ContainsKey(window) && !statusFailedPurgeCancellations.ContainsKey(window) &&
                !deleteVaultWindows.Contains(window) && !purgeDeletedVaultWindows.Contains(window) &&
                !createVaultWindows.Contains(window) && !recoverVaultWindows.Contains(window) &&
                !privateUpdateWindows.ContainsKey(window));
            bool statusPrivateDelete = VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(selector);
            if (statusPrivateDelete)
            {
                Require(client is not null && receipt is not null && scope is PrivateConnectionScope &&
                    ReferenceEquals(window.Binding.Resource, scope));
                Require(!window.Closed && window.Start is null && startedWindows.Add(window));
            }
            Require(!window.Closed && window.Start is null && client is not null && scope is not null &&
                receipt is not null && (originalPrivateDelete
                    ? privateDeleteWindows.Contains(window) && ReferenceEquals(window.Binding.Resource, scope) &&
                        scope is PrivateConnectionScope
                    : !privateDeleteWindows.Contains(window) && InputMatches(window.Binding, input)) &&
                Route(window.Binding with { Resource = scope }) == Route(window.Binding) &&
                (statusPrivateDelete || !startedWindows.Contains(window)));
            invocation = window.Start = new();
            startedWindows.Add(window);
            originalReceipts.Add(invocation, receipt);
            if (VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(selector) ||
                VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(selector) ||
                VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(selector) ||
                VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(selector) ||
                VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector) ||
                VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector) ||
                RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(selector) ||
                NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(selector) ||
                NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector) ||
                NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector))
            {
                Require(VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(selector)
                    ? window.Binding.ApiRevision == "2026-02-01" &&
                        window.Binding.Operation == ManagementMutation.DeletePrivateConnection &&
                        scope is PrivateConnectionScope && ReferenceEquals(window.Binding.Resource, scope)
                    : VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(selector)
                    ? window.Binding.ApiRevision == "2026-02-01" &&
                        window.Binding.Operation == ManagementMutation.UpdatePrivateConnection &&
                        scope is PrivateConnectionScope && ReferenceEquals(window.Binding.Resource, scope)
                    : RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(selector)
                    ? window.Binding.ApiRevision == "2022-04-01" &&
                        window.Binding.Operation == ManagementMutation.DeleteRoleAssignment &&
                        scope is RoleAssignmentScope { Parent: VaultScope }
                    : NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(selector)
                    ? window.Binding.ApiRevision == "2025-02-15" &&
                        window.Binding.Operation == ManagementMutation.DeleteNotification && scope is NotificationScope
                    : NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector)
                    ? window.Binding.ApiRevision == "2025-02-15" &&
                        window.Binding.Operation == ManagementMutation.UpdateNotification && scope is NotificationScope
                    : NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector)
                    ? window.Binding.ApiRevision == "2025-02-15" &&
                        window.Binding.Operation == ManagementMutation.CreateOrUpdateNotification && scope is NotificationScope
                    : window.Binding.ApiRevision == "2026-02-01" &&
                    (VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(selector)
                        ? window.Binding.Operation == ManagementMutation.DeleteVault && scope is VaultScope
                        : VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector)
                        ? window.Binding.Operation == ManagementMutation.RecoverVault && scope is VaultScope
                        : VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector)
                        ? window.Binding.Operation == ManagementMutation.CreateOrUpdateVault && scope is VaultScope
                        : window.Binding.Operation == ManagementMutation.PurgeDeletedVault && scope is DeletedVaultScope));
                statusDeletion = new(window, invocation, client, scope, receipt, token);
                if (absentCreateWindows.TryGetValue(window, out var absentCreation))
                    statusDeletion.NotificationAbsentCreate = absentCreation;
                if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(selector) ||
                    VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(selector))
                    statusDeletion.PrivateBeforeSend = privateApprovalBeforeSend;
                if (VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector))
                    statusDeletion.RecoveryConfiguration = new(input!.Location, input.TenantId, input.Sku,
                        true, false, input.RetentionDays, true);
                if (VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector))
                    statusDeletion.UpdateConfiguration = new(input!.Location, input.TenantId, input.Sku,
                        true, false, input.RetentionDays, true);
                if (NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector) ||
                    NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector))
                    statusDeletion.NotificationUpdateConfiguration = new(input!.WebhookUrl,
                        [VaultNotificationEvent.SecretNewVersionCreated], []);
                statusVaultCancellations.Add(window, statusDeletion);
                statusVaultCancellationInvocations.Add(invocation, statusDeletion);
            }
            if (originalPrivateDelete)
            {
                privateDelete = new(window, invocation, client, (PrivateConnectionScope)scope, receipt,
                    token, privateApprovalBeforeSend);
                privateDeletes.Add(window, privateDelete);
                privateDeleteInvocations.Add(invocation, privateDelete);
            }
            if (window.Binding.Selector.Operation == ManagementOperationEffects.Members[0].Operation &&
                window.Binding.Selector.Case == "selected-contract")
            {
                SynchronousDeleteProfile? profile = (window.Binding.Operation, window.Binding.Selector.Variant,
                    window.Binding.ApiRevision, scope) switch
                {
                    (ManagementMutation.DeleteNotification, "operation.DeleteNotification", "2025-02-15", NotificationScope) =>
                        SynchronousDeleteProfile.Notification,
                    (ManagementMutation.DeleteRoleAssignment, "operation.DeleteRoleAssignment", "2022-04-01",
                        RoleAssignmentScope { Parent: VaultScope }) => SynchronousDeleteProfile.RoleAssignment,
                    _ => null
                };
                if (profile is { } admitted)
                {
                    synchronousDelete = new(window, invocation, client, scope, receipt, token, admitted);
                    synchronousDeletes.Add(invocation, synchronousDelete);
                }
                if (window.Binding.Operation == ManagementMutation.UpdatePrivateConnection &&
                    window.Binding.Selector.Variant == "operation.UpdatePrivateConnection" &&
                    window.Binding.ApiRevision == "2026-02-01" && scope is PrivateConnectionScope connection &&
                    ReferenceEquals(window.Binding.Resource, connection))
                {
                    privateApproval = new(window, invocation, client, connection, receipt, token, privateApprovalBeforeSend);
                    privateApprovals.Add(window, privateApproval);
                    privateApprovalInvocations.Add(invocation, privateApproval);
                }
            }
        }
        bool accepted = false;
        try
        {
            Task<SecretOutcome<ManagementOperation>> task;
            InvocationContext? previous = current.Value;
            current.Value = new(window, invocation, false);
            try
            {
                task = originalPrivateDelete
                    ? client.DeletePrivateConnectionAsync((PrivateConnectionScope)scope, receipt, token).AsTask()
                    : statusDeletion?.RecoveryConfiguration is { } recoveryConfiguration
                    ? client.RecoverVaultAsync((VaultScope)scope, recoveryConfiguration, receipt, token).AsTask()
                    : statusDeletion?.UpdateConfiguration is { } updateConfiguration
                    ? client.CreateOrUpdateVaultAsync((VaultScope)scope, updateConfiguration, receipt, token).AsTask()
                    : ManagementOperationEffects.StartAsync(client, scope, window.Binding.Operation, input!, receipt, token).AsTask();
            }
            finally { current.Value = previous; }
            lock (gate)
            {
                invocation.SdkTask = task;
                if (privateDelete is not null) privateDelete.StartTask = task;
                if (synchronousDelete is not null) synchronousDelete.Task = task;
                if (privateApproval is not null) privateApproval.StartTask = task;
                if (statusDeletion is not null) statusDeletion.StartTask = task;
            }
            // Even a throwing host hook cannot detach the already-started task.
            try
            {
                retained?.Invoke(task);
                lock (gate)
                {
                    if (synchronousDelete is not null) synchronousDelete.HookReturned = true;
                    if (privateApproval is not null) privateApproval.StartHookReturned = true;
                    if (privateDelete is not null) privateDelete.HookReturned = true;
                    if (statusDeletion is not null) statusDeletion.StartHookReturned = true;
                }
            }
            finally
            {
                var result = await task.ConfigureAwait(false);
                lock (gate)
                {
                    invocation.Outcome = result.Status;
                    if (statusDeletion is not null)
                    {
                        statusDeletion.StartReceipt = receipt.Evidence;
                        statusDeletion.StartState = result.IsSuccess ? result.Value.State : null;
                        statusDeletion.StartSucceeded = task.IsCompletedSuccessfully && result.IsSuccess &&
                            (VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(selector)
                                ? result.Value.State is NativeProvisioningState.Pending or NativeProvisioningState.Succeeded
                                : result.Value.State == (VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(selector) ||
                                VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector) ||
                                VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector) ||
                                NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector) ||
                                NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector)
                                ? NativeProvisioningState.Pending : NativeProvisioningState.Succeeded)) &&
                            (VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(selector) ||
                                RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(selector) ||
                                NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(selector)
                                ? receipt.Evidence == DispatchEvidence.Applied :
                                VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(selector) ||
                                receipt.Evidence == DispatchEvidence.Pending);
                        statusDeletion.Handle = result.IsSuccess ? result.Value : null;
                    }
                    if (privateDelete is not null)
                    {
                        privateDelete.StartReceipt = receipt.Evidence;
                        privateDelete.StartSucceeded = task.IsCompletedSuccessfully && result.IsSuccess;
                    }
                    if (result.IsSuccess)
                    {
                        if (privateDelete is not null) privateDelete.Handle = result.Value;
                        invocation.WrapperState = result.Value.State;
                        if (privateApproval is not null)
                        {
                            privateApproval.Handle = result.Value;
                            privateApproval.StartSucceeded = task.IsCompletedSuccessfully &&
                                result.Value.State == NativeProvisioningState.Succeeded;
                        }
                        if (synchronousDelete is not null)
                        {
                            synchronousDelete.Handle = result.Value;
                            synchronousDelete.SdkSucceeded = task.IsCompletedSuccessfully &&
                                result.Value.State == NativeProvisioningState.Succeeded;
                        }
                        if (invocation.Attempts is [{ Valid: true, ResponseObserved: true, HttpStatus: >= 200 and < 300 }])
                        {
                            handles.Add(window, result.Value);
                            invocation.HasNativeHandle = true;
                            accepted = true;
                        }
                    }
                }
            }
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            lock (gate)
            {
                if (synchronousDelete is not null) synchronousDelete.Invalid = true;
                if (privateApproval is not null) privateApproval.Invalid = true;
                if (privateDelete is not null) privateDelete.Invalid = true;
                if (statusDeletion is not null) statusDeletion.Invalid = true;
            }
            invocation.Canceled = true;
            throw new OperationCanceledException(token);
        }
        catch (Exception)
        {
            lock (gate)
            {
                if (synchronousDelete is not null) synchronousDelete.Invalid = true;
                if (privateApproval is not null) privateApproval.Invalid = true;
                if (privateDelete is not null) privateDelete.Invalid = true;
                if (statusDeletion is not null) statusDeletion.Invalid = true;
            }
            throw new InvalidOperationException("management-capture-invocation");
        }
        finally
        {
            await FinishAsync(invocation, accepted ? window : null).ConfigureAwait(false);
        }
    }

    internal async Task<SecretStatus> CheckStatusAsync(Window window, FixtureSelector selector,
        ManagementOperation handle, CancellationToken token = default, Action<Task>? retained = null,
        CancellationToken? originalCallerToken = null)
    {
        bool deniedVaultRecover;
        lock (gate) deniedVaultRecover = statusDeniedVaultRecovers.ContainsKey(window);
        if (deniedVaultRecover)
            return await CheckStatusDeniedVaultRecoverAsync(window, selector, handle, token, retained,
                originalCallerToken ?? token).ConfigureAwait(false);
        bool deniedVaultUpdate;
        lock (gate) deniedVaultUpdate = statusDeniedVaultUpdates.ContainsKey(window);
        if (deniedVaultUpdate)
            return await CheckStatusDeniedVaultUpdateAsync(window, selector, handle, token, retained,
                originalCallerToken ?? token).ConfigureAwait(false);
        bool deniedPrivateDelete;
        lock (gate) deniedPrivateDelete = statusDeniedPrivateConnectionDeletes.ContainsKey(window);
        if (deniedPrivateDelete)
            return await CheckStatusDeniedPrivateConnectionDeleteCoreAsync(window, selector, handle, token, retained,
                originalCallerToken ?? token).ConfigureAwait(false);
        bool deniedUpdate;
        lock (gate) deniedUpdate = statusDeniedNotificationUpdate.ContainsKey(window);
        if (deniedUpdate)
            return await CheckStatusDeniedNotificationUpdateCoreAsync(window, selector, handle, token, retained,
                originalCallerToken ?? token).ConfigureAwait(false);
        bool deniedPurge;
        lock (gate) deniedPurge = statusDeniedPurges.ContainsKey(window);
        if (deniedPurge)
            return await CheckStatusDeniedPurgeAsync(window, selector, handle, token, retained).ConfigureAwait(false);
        bool unknownCancellationUpdate;
        lock (gate) unknownCancellationUpdate = statusUnknownNotificationUpdateCancellation.ContainsKey(window);
        if (unknownCancellationUpdate)
        {
            if (token.IsCancellationRequested)
                return await CheckStatusUnknownNotificationUpdateCancellationCanceledAsync(window, selector, handle, token, retained).ConfigureAwait(false);
            return await CheckStatusUnknownNotificationUpdateCancellationAsync(window, selector, handle, token, retained,
                originalCallerToken ?? token).ConfigureAwait(false);
        }
        lock (gate) Require(!(NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationSelector(selector) &&
            window.Binding.Operation == ManagementMutation.UpdateNotification));
        bool unknownIndependentUpdate;
        lock (gate) unknownIndependentUpdate = statusUnknownNotificationUpdateIndependent.ContainsKey(window);
        if (unknownIndependentUpdate)
            return await CheckStatusUnknownNotificationUpdateIndependentAsync(window, selector, handle, token, retained,
                originalCallerToken ?? token).ConfigureAwait(false);
        lock (gate) Require(!(NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentSelector(selector) &&
            window.Binding.Operation == ManagementMutation.UpdateNotification));
        bool unknownUpdate;
        lock (gate) unknownUpdate = statusUnknownNotificationUpdate.ContainsKey(window);
        if (unknownUpdate)
            return await CheckStatusUnknownNotificationUpdateAsync(window, selector, handle, token, retained,
                originalCallerToken ?? token).ConfigureAwait(false);
        lock (gate) Require(!(NotificationFixtureProvisioner.StatusUnknownNotificationUpdateSelector(selector) &&
            window.Binding.Operation == ManagementMutation.UpdateNotification));
        lock (gate) Require(!(StatusPendingPurgeIndependentSelector(selector) &&
                window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
            !(StatusCanceledPurgeCancellationSelector(selector) &&
                window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
            !statusCanceledPurgeCancellations.ContainsKey(window) &&
            !(StatusPendingPurgeCancellationSelector(selector) &&
                window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
            !(StatusFailedPurgeSelector(selector) &&
                window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
            !(StatusFailedPurgeIndependentSelector(selector) &&
                window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
            !(StatusFailedPurgeCancellationSelector(selector) &&
                window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
            !(StatusCanceledPurgeSelector(selector) &&
                window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
            !(StatusCanceledPurgeIndependentSelector(selector) &&
                window.Binding.Operation == ManagementMutation.PurgeDeletedVault) &&
            !statusCanceledPurgeIndependents.ContainsKey(window) &&
            !statusCanceledPurges.ContainsKey(window) &&
            !statusPendingPurges.ContainsKey(window) && !statusPendingPurgeIndependents.ContainsKey(window) &&
            !statusPendingPurgeCancellations.ContainsKey(window) && !statusFailedPurges.ContainsKey(window) &&
            !statusFailedPurgeIndependents.ContainsKey(window) && !statusFailedPurgeCancellations.ContainsKey(window));
        bool independentPrivateUpdate;
        lock (gate) independentPrivateUpdate = statusPrivateUpdateIndependent.ContainsKey(window);
        if (independentPrivateUpdate)
            return await CheckStatusPrivateUpdateIndependentAsync(window, selector, handle, token, retained, originalCallerToken ?? token).ConfigureAwait(false);
        bool independentUpdate;
        lock (gate) independentUpdate = statusNotificationUpdateIndependent.ContainsKey(window);
        if (independentUpdate)
            return await CheckStatusNotificationUpdateIndependentAsync(window, selector, handle, token, retained).ConfigureAwait(false);
        bool independentCreate;
        lock (gate) independentCreate = statusNotificationCreateIndependent.ContainsKey(window);
        if (independentCreate)
            return await CheckStatusNotificationCreateIndependentAsync(window, selector, handle, token, retained).ConfigureAwait(false);
        bool independentPrivateDelete;
        lock (gate) independentPrivateDelete = statusPrivateDeleteIndependent.ContainsKey(window);
        if (independentPrivateDelete)
            return await CheckStatusPrivateDeleteIndependentAsync(window, selector, handle, token, retained).ConfigureAwait(false);
        bool cancellationSucceededDelete;
        lock (gate) cancellationSucceededDelete = statusSucceededDeleteVaultCancellation.ContainsKey(window);
        if (cancellationSucceededDelete)
            return await CheckStatusSucceededDeleteVaultCancellationAsync(window, selector, handle, token, retained, canceled: false).ConfigureAwait(false);
        bool independentSucceededDelete;
        lock (gate) independentSucceededDelete = statusSucceededDeleteVaultIndependent.ContainsKey(window);
        if (independentSucceededDelete)
            return await CheckStatusSucceededDeleteVaultIndependentAsync(window, selector, handle, token, retained).ConfigureAwait(false);
        bool succeededDelete;
        lock (gate) succeededDelete = statusSucceededDeleteVault.ContainsKey(window);
        if (succeededDelete)
            return await CheckStatusSucceededDeleteVaultAsync(window, selector, handle, token, retained).ConfigureAwait(false);
        bool independentNotificationDelete;
        bool independentRoleDelete;
        lock (gate) independentRoleDelete = statusRoleDeleteIndependent.ContainsKey(window);
        if (independentRoleDelete)
            return await CheckStatusRoleDeleteIndependentAsync(window, selector, handle, token, retained).ConfigureAwait(false);
        lock (gate) independentNotificationDelete = statusNotificationDeleteIndependent.ContainsKey(window);
        if (independentNotificationDelete)
            return await CheckStatusNotificationDeleteIndependentAsync(window, selector, handle, token, retained).ConfigureAwait(false);
        bool selectedPrivateDelete;
        lock (gate) selectedPrivateDelete = statusPrivateDeleteSelected.ContainsKey(window);
        if (selectedPrivateDelete)
            return await CheckStatusPrivateDeleteSelectedAsync(window, selector, handle, token, retained).ConfigureAwait(false);
        if (VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(selector) ||
            VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(selector) ||
            VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(selector) ||
            VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(selector) ||
            VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector) ||
            VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector) ||
            RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(selector) ||
            NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(selector) ||
            NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector) ||
            NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector))
            return await CheckStatusVaultCancellationAsync(window, selector, handle, token, retained,
                canceled: false).ConfigureAwait(false);
        bool originalPrivateUpdate;
        lock (gate) originalPrivateUpdate = privateUpdateWindows.ContainsKey(window);
        if (originalPrivateUpdate)
            return await CheckPrivateConnectionUpdateAsync(window, selector, handle, token, retained).ConfigureAwait(false);
        bool originalRecover;
        lock (gate) originalRecover = recoverVaultWindows.Contains(window);
        if (originalRecover)
            return await CheckCreateVaultAsync(window, selector, handle, token, retained).ConfigureAwait(false);
        bool originalCreate;
        lock (gate) originalCreate = createVaultWindows.Contains(window);
        if (originalCreate)
            return await CheckCreateVaultAsync(window, selector, handle, token, retained).ConfigureAwait(false);
        bool originalPurge;
        lock (gate) originalPurge = purgeDeletedVaultWindows.Contains(window);
        if (originalPurge)
            return await CheckPurgeDeletedVaultAsync(window, selector, handle, token, retained).ConfigureAwait(false);
        bool originalDelete;
        lock (gate) originalDelete = deleteVaultWindows.Contains(window);
        if (originalDelete)
            return await CheckDeleteVaultAsync(window, selector, handle, token, retained).ConfigureAwait(false);
        Invocation invocation;
        PrivateApprovalRegistration? privateApproval;
        lock (gate)
        {
            Own(window, selector);
            Require(!window.Closed && window.Start is { Terminated: true } &&
                window.Status is null && handles.TryGetValue(window, out var original) &&
                ReferenceEquals(handle, original));
            invocation = window.Status = new();
            if (privateDeletes.TryGetValue(window, out var deletion))
            {
                Require(!deletion.Sealed && !deletion.CheckClaimed && ReferenceEquals(deletion.Handle, handle) &&
                    deletion.Started.Task.IsCompletedSuccessfully &&
                    deletion.StartTask is { IsCompletedSuccessfully: true } &&
                    deletion.StartTask.Result.IsSuccess);
                deletion.CheckClaimed = true;
                deletion.CheckToken = token;
                privateDeleteInvocations.Add(invocation, deletion);
            }
            privateApprovals.TryGetValue(window, out privateApproval);
            if (privateApproval is not null)
            {
                Require(!privateApproval.Sealed && privateApproval.Status is null &&
                    privateApproval.StartFinalized.Task.IsCompletedSuccessfully &&
                    ReferenceEquals(privateApproval.Handle, handle));
                privateApproval.Status = invocation;
                privateApproval.StatusToken = token;
                privateApprovalInvocations.Add(invocation, privateApproval);
            }
        }
        try
        {
            Task<SecretStatus> task;
            InvocationContext? previous = current.Value;
            current.Value = new(window, invocation, true);
            try { task = handle.CheckStatusAsync(token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate)
            {
                invocation.SdkTask = task;
                if (privateDeletes.TryGetValue(window, out var deletion)) deletion.StatusTask = task;
                if (privateApproval is not null) privateApproval.StatusTask = task;
            }
            try
            {
                retained?.Invoke(task);
                lock (gate)
                {
                    if (privateApproval is not null) privateApproval.StatusHookReturned = true;
                    if (privateDeletes.TryGetValue(window, out var deletion)) deletion.CheckHookReturned = true;
                }
            }
            finally
            {
                var outcome = await task.ConfigureAwait(false);
                invocation.Outcome = outcome;
                invocation.WrapperState = handle.State;
                lock (gate)
                {
                    if (privateDeletes.TryGetValue(window, out var deletion))
                    {
                        deletion.CheckReceipt = deletion.Receipt.Evidence;
                        deletion.CheckSucceeded = task.IsCompletedSuccessfully &&
                            outcome == SecretStatus.Success && handle.State == NativeProvisioningState.Succeeded;
                        deletion.CheckCanceled = token.IsCancellationRequested;
                    }
                    if (privateApproval is not null)
                        privateApproval.StatusSucceeded = task.IsCompletedSuccessfully &&
                            outcome == SecretStatus.Success && handle.State == NativeProvisioningState.Succeeded;
                }
            }
            return invocation.Outcome!.Value;
        }
        catch (OperationCanceledException)
        {
            lock (gate)
            {
                if (privateApproval is not null) privateApproval.StatusInvalid = true;
                if (privateDeletes.TryGetValue(window, out var deletion))
                {
                    deletion.CheckCanceled = true;
                    deletion.Invalid = true;
                }
            }
            invocation.Canceled = true;
            throw new OperationCanceledException(token);
        }
        catch (Exception)
        {
            lock (gate)
            {
                if (privateApproval is not null) privateApproval.StatusInvalid = true;
                if (privateDeletes.TryGetValue(window, out var deletion)) deletion.Invalid = true;
            }
            throw new InvalidOperationException("management-capture-invocation");
        }
        finally { await FinishAsync(invocation, statusWindow: window).ConfigureAwait(false); }
    }

    private Task<Capture> SealStatusVaultCancellationAsync(Window window)
    {
        StatusVaultCancellationRegistration r;
        TaskCompletionSource ready;
        Task<Capture> task;
        lock (gate)
        {
            Own(window, window.Binding.Selector);
            window.Closed = true;
            if (!statusVaultCancellations.TryGetValue(window, out r!))
                return Task.FromResult(new Capture { Binding = window.Binding });
            if (r.SealTask is not null) return r.SealTask;
            r.Sealed = true;
            ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = r.SealTask = Drain(ready.Task);
        }
        ready.SetResult();
        return task;

        async Task<Capture> Drain(Task admission)
        {
            await admission.ConfigureAwait(false);
            await r.Started.Task.ConfigureAwait(false);
            if (r.PrivateCancel is not null) await r.Canceled.Task.ConfigureAwait(false);
            if (r.NormalStatus is not null) await r.Checked.Task.ConfigureAwait(false);
            bool failed = !DisposeStatusVaultCancellationStorage(r);
            r.NotificationUpdateConfiguration?.Dispose();
            lock (gate) r.Invalid |= failed;
            Require(!failed);
            return new() { Binding = r.Binding, Start = r.Start, Status = r.NormalStatus };
        }
    }

    private static bool DisposeStatusVaultCancellationStorage(StatusVaultCancellationRegistration r)
    {
        bool valid = true;
        try
        {
            try { r.ParserStorage.Dispose(); }
            catch { valid = false; }
            foreach (var snapshot in r.Snapshots)
                try { snapshot.Dispose(); }
                catch { valid = false; }
        }
        finally
        {
            foreach (var bytes in r.Owned) CryptographicOperations.ZeroMemory(bytes);
            r.Snapshots.Clear();
            r.Owned.Clear();
        }
        return valid;
    }

    // Closing prevents new calls but does not interrupt admitted SDK work.
    // No cancellation/timeout may turn a still-running SDK task into a drain.
    internal async Task<Capture> SealAsync(Window window)
    {
        bool deniedVaultRecover;
        lock (gate) deniedVaultRecover = statusDeniedVaultRecovers.ContainsKey(window);
        if (deniedVaultRecover) return await SealStatusDeniedVaultRecoverAsync(window).ConfigureAwait(false);
        bool deniedVaultUpdate;
        lock (gate) deniedVaultUpdate = statusDeniedVaultUpdates.ContainsKey(window);
        if (deniedVaultUpdate) return await SealStatusDeniedVaultUpdateAsync(window).ConfigureAwait(false);
        bool deniedPrivateDelete;
        lock (gate) deniedPrivateDelete = statusDeniedPrivateConnectionDeletes.ContainsKey(window);
        if (deniedPrivateDelete) return await SealStatusDeniedPrivateConnectionDeleteAsync(window).ConfigureAwait(false);
        bool deniedUpdate;
        lock (gate) deniedUpdate = statusDeniedNotificationUpdate.ContainsKey(window);
        if (deniedUpdate) return await SealStatusDeniedNotificationUpdateAsync(window).ConfigureAwait(false);
        bool deniedPurge;
        lock (gate) deniedPurge = statusDeniedPurges.ContainsKey(window);
        if (deniedPurge) return await SealStatusDeniedPurgeAsync(window).ConfigureAwait(false);
        bool unknownCancellationUpdate;
        lock (gate) unknownCancellationUpdate = statusUnknownNotificationUpdateCancellation.ContainsKey(window);
        if (unknownCancellationUpdate) return await SealStatusUnknownNotificationUpdateCancellationAsync(window).ConfigureAwait(false);
        lock (gate) Require(!(NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationSelector(window.Binding.Selector) &&
            window.Binding.Operation == ManagementMutation.UpdateNotification));
        bool unknownIndependentUpdate;
        lock (gate) unknownIndependentUpdate = statusUnknownNotificationUpdateIndependent.ContainsKey(window);
        if (unknownIndependentUpdate) return await SealStatusUnknownNotificationUpdateIndependentAsync(window).ConfigureAwait(false);
        bool unknownUpdate;
        lock (gate) unknownUpdate = statusUnknownNotificationUpdate.ContainsKey(window);
        if (unknownUpdate) return await SealStatusUnknownNotificationUpdateAsync(window).ConfigureAwait(false);
        bool pendingPurge;
        lock (gate) pendingPurge = TryGetStatusPendingPurgeRun(window, out _);
        if (pendingPurge) return await SealStatusPendingPurgeAsync(window).ConfigureAwait(false);
        bool independentPrivateUpdate;
        lock (gate) independentPrivateUpdate = statusPrivateUpdateIndependent.ContainsKey(window);
        if (independentPrivateUpdate) return await SealStatusPrivateUpdateIndependentAsync(window).ConfigureAwait(false);
        bool independentUpdate;
        lock (gate) independentUpdate = statusNotificationUpdateIndependent.ContainsKey(window);
        if (independentUpdate) return await SealStatusNotificationUpdateIndependentAsync(window).ConfigureAwait(false);
        bool independentCreate;
        lock (gate) independentCreate = statusNotificationCreateIndependent.ContainsKey(window);
        if (independentCreate) return await SealStatusNotificationCreateIndependentAsync(window).ConfigureAwait(false);
        Task<Capture>? independentSeal;
        bool independentPrivateDelete;
        lock (gate)
        {
            statusPrivateDeleteIndependentSeals.TryGetValue(window, out independentSeal);
            independentPrivateDelete = statusPrivateDeleteIndependent.ContainsKey(window);
        }
        if (independentSeal is not null) return await independentSeal.ConfigureAwait(false);
        if (independentPrivateDelete)
            return await SealStatusPrivateDeleteIndependentAsync(window).ConfigureAwait(false);
        bool cancellationSucceededDelete;
        lock (gate) cancellationSucceededDelete = statusSucceededDeleteVaultCancellation.ContainsKey(window);
        if (cancellationSucceededDelete) return await SealStatusSucceededDeleteVaultCancellationAsync(window).ConfigureAwait(false);
        bool independentSucceededDelete;
        lock (gate) independentSucceededDelete = statusSucceededDeleteVaultIndependent.ContainsKey(window);
        if (independentSucceededDelete) return await SealStatusSucceededDeleteVaultIndependentAsync(window).ConfigureAwait(false);
        bool succeededDelete;
        lock (gate) succeededDelete = statusSucceededDeleteVault.ContainsKey(window);
        if (succeededDelete) return await SealStatusSucceededDeleteVaultAsync(window).ConfigureAwait(false);
        bool independentNotificationDelete;
        bool independentRoleDelete;
        lock (gate) independentRoleDelete = statusRoleDeleteIndependent.ContainsKey(window);
        if (independentRoleDelete)
            return await SealStatusRoleDeleteIndependentAsync(window).ConfigureAwait(false);
        lock (gate) independentNotificationDelete = statusNotificationDeleteIndependent.ContainsKey(window);
        if (independentNotificationDelete)
            return await SealStatusNotificationDeleteIndependentAsync(window).ConfigureAwait(false);
        bool selectedPrivateDelete;
        lock (gate) selectedPrivateDelete = statusPrivateDeleteSelected.ContainsKey(window);
        if (selectedPrivateDelete)
            return await SealStatusPrivateDeleteSelectedAsync(window).ConfigureAwait(false);
        if (VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(window.Binding.Selector) ||
            VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(window.Binding.Selector) ||
            VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(window.Binding.Selector) ||
            VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(window.Binding.Selector) ||
            VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(window.Binding.Selector) ||
            VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(window.Binding.Selector) ||
            RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(window.Binding.Selector) ||
            NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(window.Binding.Selector) ||
            NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(window.Binding.Selector) ||
            NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(window.Binding.Selector))
            return await SealStatusVaultCancellationAsync(window).ConfigureAwait(false);
        bool originalPrivateDelete;
        lock (gate) originalPrivateDelete = privateDeleteWindows.Contains(window);
        if (originalPrivateDelete) return await SealPrivateConnectionDeleteAsync(window).ConfigureAwait(false);
        bool originalPrivateUpdate;
        lock (gate) originalPrivateUpdate = privateUpdateWindows.ContainsKey(window);
        if (originalPrivateUpdate) return await SealPrivateConnectionUpdateAsync(window).ConfigureAwait(false);
        bool originalRecover;
        lock (gate) originalRecover = recoverVaultWindows.Contains(window);
        if (originalRecover) return await SealCreateVaultAsync(window).ConfigureAwait(false);
        bool originalCreate;
        lock (gate) originalCreate = createVaultWindows.Contains(window);
        if (originalCreate) return await SealCreateVaultAsync(window).ConfigureAwait(false);
        bool originalPurge;
        lock (gate) originalPurge = purgeDeletedVaultWindows.Contains(window);
        if (originalPurge) return await SealPurgeDeletedVaultAsync(window).ConfigureAwait(false);
        bool originalDelete;
        lock (gate) originalDelete = deleteVaultWindows.Contains(window);
        if (originalDelete) return await SealDeleteVaultAsync(window).ConfigureAwait(false);
        Task[] tasks;
        PrivateApprovalRegistration? privateApproval;
        lock (gate)
        {
            Own(window, window.Binding.Selector);
            window.Closed = true;
            tasks = new[] { window.Start, window.Status }.OfType<Invocation>().Select(i => i.Drained.Task).ToArray();
            var original = synchronousDeletes.Values.FirstOrDefault(r => ReferenceEquals(r.Window, window));
            if (original is not null) tasks = tasks.Append(original.Finalized.Task).ToArray();
            privateApprovals.TryGetValue(window, out privateApproval);
            if (privateApproval is not null)
            {
                privateApproval.Sealed = true;
                privateApproval.Proof = null;
                tasks = tasks.Append(privateApproval.StartFinalized.Task).ToArray();
                if (privateApproval.Status is not null) tasks = tasks.Append(privateApproval.StatusFinalized.Task).ToArray();
            }
        }
        await Task.WhenAll(tasks).ConfigureAwait(false);
        lock (gate)
        {
            if (privateApproval is not null)
            {
                privateApproval.ResponseFacts = null;
                privateApproval.Proof = null;
                privateApprovalInvocations.Remove(privateApproval.Start);
                if (privateApproval.Status is not null) privateApprovalInvocations.Remove(privateApproval.Status);
                privateApprovals.Remove(window);
            }
        }
        return new() { Binding = window.Binding, Start = window.Start, Status = window.Status };
    }

    private async Task FinishAsync(Invocation invocation, Window? acceptedWindow = null, Window? statusWindow = null)
    {
        Task<Task>? borrower;
        SynchronousDeleteRegistration? synchronousDelete;
        PrivateApprovalRegistration? privateApproval;
        StatusVaultCancellationRegistration? statusDeletion;
        bool privateStatus;
        lock (gate)
        {
            synchronousDeletes.TryGetValue(invocation, out synchronousDelete);
            privateApprovalInvocations.TryGetValue(invocation, out privateApproval);
            statusVaultCancellationInvocations.TryGetValue(invocation, out statusDeletion);
            privateStatus = privateApproval is not null && ReferenceEquals(privateApproval.Status, invocation);
            Task? sdkTask = statusDeletion is not null
                ? ReferenceEquals(statusDeletion.Start, invocation) ? statusDeletion.StartTask :
                    ReferenceEquals(statusDeletion.PrivateCancel, invocation) ? statusDeletion.CanceledTask : statusDeletion.StatusTask
                : privateApproval is not null
                ? privateStatus ? privateApproval.StatusTask : privateApproval.StartTask
                : synchronousDelete is null ? invocation.SdkTask : synchronousDelete.Task;
            Require(sdkTask is null || sdkTask.IsCompleted);
            finishing.Add(invocation);
            borrower = borrowers.TryGetValue(invocation, out var outstanding) ? outstanding.Task : null;
        }
        if (borrower is not null)
        {
            Task actual = await borrower.ConfigureAwait(false);
            try { await actual.ConfigureAwait(false); }
            catch (Exception)
            {
                // Preserve the original SDK outcome, but never let a faulted
                // transport borrower contribute usable native wire proof.
                lock (gate)
                {
                    if (synchronousDelete is not null) synchronousDelete.Invalid = true;
                    if (statusDeletion is not null) statusDeletion.Invalid = true;
                    if (privateDeleteInvocations.TryGetValue(invocation, out var deletion)) deletion.Invalid = true;
                    if (privateApproval is not null)
                    {
                        if (privateStatus) privateApproval.StatusInvalid = true;
                        else privateApproval.Invalid = true;
                    }
                    foreach (var attempt in invocation.Attempts) attempt.Valid = false;
                }
            }
        }
        if (statusDeletion is not null)
        {
            // Both SDK checks and the original transport have drained. Dispose
            // outside gate, before freezing completion or signaling Checked.
            bool purge = VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(statusDeletion.Binding.Selector);
            bool recover = VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(statusDeletion.Binding.Selector);
            bool update = VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(statusDeletion.Binding.Selector);
            bool notification = NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(statusDeletion.Binding.Selector);
            bool notificationUpdate = NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(statusDeletion.Binding.Selector);
            bool notificationCreate = NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(statusDeletion.Binding.Selector);
            bool notificationMutation = notificationUpdate || notificationCreate;
            bool role = RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(statusDeletion.Binding.Selector);
            bool privateUpdate = VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(statusDeletion.Binding.Selector);
            bool privateDelete = VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(statusDeletion.Binding.Selector);
            bool emptyDelete = notification || role;
            bool parserValid = true;
            if (emptyDelete && ReferenceEquals(statusDeletion.Start, invocation))
                try { parserValid = statusDeletion.NotificationCustody is { Complete: true }; }
                catch { parserValid = false; }
            if (purge || recover || update)
                try
                {
                    parserValid = statusDeletion.Parsers.Count ==
                        (ReferenceEquals(statusDeletion.NormalStatus, invocation) ? 3 : 1) &&
                        statusDeletion.Parsers.All(p => p.Complete && !p.Invalid);
                }
                catch { parserValid = false; }
            if (privateUpdate && ReferenceEquals(statusDeletion.Start, invocation))
                try { parserValid = statusDeletion.Parsers is [var parser] && parser.Complete && !parser.Invalid; }
                catch { parserValid = false; }
            if (privateDelete)
                try
                {
                    parserValid = statusDeletion.Parsers is [var parser] && !parser.Invalid &&
                        (!ReferenceEquals(statusDeletion.NormalStatus, invocation) || parser.Complete);
                }
                catch { parserValid = false; }
            if (notificationMutation)
                try
                {
                    parserValid = statusDeletion.Parsers.Count ==
                        (ReferenceEquals(statusDeletion.NormalStatus, invocation) ? 2 : 1) &&
                        statusDeletion.Parsers.All(p => p.Complete && !p.Invalid);
                }
                catch { parserValid = false; }
            bool finalizationFailed = (ReferenceEquals(statusDeletion.NormalStatus, invocation) ||
                (emptyDelete || privateUpdate) && ReferenceEquals(statusDeletion.Start, invocation)) &&
                !DisposeStatusVaultCancellationStorage(statusDeletion);
            if (privateUpdate && ReferenceEquals(statusDeletion.Start, invocation))
                try { parserValid &= statusDeletion.Parsers is [var parser] && parser.Complete && !parser.Invalid; }
                catch { parserValid = false; }
            if (notificationMutation && ReferenceEquals(statusDeletion.NormalStatus, invocation))
                try { parserValid &= statusDeletion.Parsers.All(p => p.Complete && !p.Invalid); }
                catch { parserValid = false; }
            if (privateDelete && ReferenceEquals(statusDeletion.NormalStatus, invocation))
                try { parserValid &= statusDeletion.Parsers is [var parser] && parser.Complete && !parser.Invalid; }
                catch { parserValid = false; }
            lock (gate)
            {
                var r = statusDeletion;
                r.Invalid |= finalizationFailed || !parserValid;
                requestOwners.Remove(invocation);
                requestCandidates.Remove(invocation);
                originalReceipts.Remove(invocation);
                borrowers.Remove(invocation);
                finalReadEligible.Remove(invocation);
                nativeStatusReads.Remove(invocation);
                if (ReferenceEquals(r.Start, invocation))
                {
                    r.StartComplete = !r.Invalid && r.StartHookReturned && r.StartSucceeded &&
                        r.TransportSucceeded && r.WireQualified && r.Sends == 1 &&
                        r.StartTask is { IsCompletedSuccessfully: true } &&
                        (privateDelete ? r.PrivateDeleteFacts is not null && r.Target is null &&
                            r.StartReceipt == DispatchEvidence.Pending :
                            privateUpdate ? r.PrivateCandidate is not null && r.Target is null &&
                            r.StartReceipt == DispatchEvidence.Applied :
                            emptyDelete ? (role ? r.RoleCandidate is not null : r.NotificationCandidate is not null) && r.Target is null &&
                            r.StartReceipt == DispatchEvidence.Applied : r.Target is not null) &&
                        !r.StartToken.IsCancellationRequested && r.Handle?.State == r.StartState &&
                        (privateDelete ? r.StartState is NativeProvisioningState.Pending or NativeProvisioningState.Succeeded :
                            r.StartState == (purge || recover || update || notificationMutation
                                ? NativeProvisioningState.Pending : NativeProvisioningState.Succeeded)) &&
                        r.Receipt.Evidence == r.StartReceipt &&
                        (!purge || r.StartReceipt == DispatchEvidence.Pending &&
                            r.StartWire is { Ordinal: 0, HttpStatus: 202, State: WireState.Pending, Complete: true }) &&
                        (!recover || r.StartReceipt == DispatchEvidence.Pending && r.RecoveryConfiguration is not null &&
                            r.StartWire is
                            {
                                Ordinal: 0, HttpStatus: 201, State: WireState.Pending, Complete: true,
                                RequestSha256.Length: 64
                            }) &&
                        (!update || r.StartReceipt == DispatchEvidence.Pending && r.UpdateConfiguration is not null &&
                            r.RecoveryConfiguration is null &&
                            r.StartWire is
                            {
                                Ordinal: 0, HttpStatus: 201, State: WireState.Pending, Complete: true,
                                RequestSha256.Length: 64
                            }) &&
                        (!privateDelete || r.StartWire is
                        {
                            Ordinal: 0, HttpStatus: 200, State: WireState.Succeeded, Complete: true,
                            RequestSha256.Length: 64, RequestHeaders: not null
                        }) &&
                        (!notificationUpdate || r.NotificationUpdateCandidate is not null &&
                            r.StartReceipt == DispatchEvidence.Pending && r.StartState == NativeProvisioningState.Pending &&
                            r.StartWire is { Ordinal: 0, HttpStatus: 201, State: WireState.Pending, Complete: true }) &&
                        (!notificationCreate || r.NotificationCreateCandidate is not null &&
                            r.StartReceipt == DispatchEvidence.Pending && r.StartState == NativeProvisioningState.Pending &&
                            r.StartWire is { Ordinal: 0, HttpStatus: 201, State: WireState.Pending, Complete: true });
                    if (r.StartComplete)
                    {
                        if (notification) r.NotificationProof = r.NotificationCandidate;
                        if (notificationUpdate) r.NotificationUpdateProof = r.NotificationUpdateCandidate;
                        if (notificationCreate) r.NotificationCreateProof = r.NotificationCreateCandidate;
                        if (role) r.RoleProof = r.RoleCandidate;
                        if (privateUpdate) r.PrivateProof = r.PrivateCandidate;
                        if (privateDelete && r.StartWire is { } wire)
                            r.PrivateDeleteProof = new(r.Binding, wire.Dispatch, r.PrivateDeleteFacts!,
                                wire.RequestSha256!, wire.ResponseSha256, wire.NativeRequestId, r.StartState!.Value);
                        eligible.Add(r.Window);
                    }
                    r.Started.TrySetResult();
                }
                else if (ReferenceEquals(r.PrivateCancel, invocation))
                {
                    r.CancelComplete = StatusVaultCancellationStartValid(r) && r.CancelHookReturned &&
                        r.CancellationPropagated && r.CanceledTask is { IsCanceled: true } &&
                        r.CancelToken.IsCancellationRequested && r.Receipt.Evidence == r.StartReceipt &&
                        r.Handle?.State == r.StartState && r.CancelState == r.StartState &&
                        (!(purge || recover || update || emptyDelete || privateUpdate || privateDelete || notificationMutation) ||
                            r.StatusSends == 0 && r.StatusWires.Count == 0);
                    r.Canceled.TrySetResult();
                }
                else
                {
                    r.Complete = StatusVaultCancellationStartValid(r) && r.CancelComplete &&
                        r.Canceled.Task.IsCompletedSuccessfully && r.StatusHookReturned && r.StatusSucceeded &&
                        r.StatusTask is { IsCompletedSuccessfully: true } && !r.StatusToken.IsCancellationRequested &&
                        r.Receipt.Evidence == r.StartReceipt && r.Handle?.State == NativeProvisioningState.Succeeded &&
                        (!purge || StatusVaultPurgeWiresValid(r)) && (!recover || StatusVaultRecoverWiresValid(r)) &&
                        (!update || !ReferenceEquals(r.CanceledTask, r.StatusTask) && StatusVaultUpdateWiresValid(r)) &&
                        (!notificationUpdate || !ReferenceEquals(r.CanceledTask, r.StatusTask) &&
                            StatusNotificationUpdateWiresValid(r)) &&
                        (!notificationCreate || !ReferenceEquals(r.CanceledTask, r.StatusTask) &&
                            StatusNotificationCreateWiresValid(r)) &&
                        (!(emptyDelete || privateUpdate || privateDelete) || !ReferenceEquals(r.CanceledTask, r.StatusTask) &&
                            r.StatusSends == 0 && r.StatusWires.Count == 0);
                    if ((purge || recover || update || notificationMutation) && r.Complete) completedStatusReads.Add(r.Window);
                    r.Checked.TrySetResult();
                }
                invocation.Terminated = true;
                invocation.Drained.TrySetResult();
            }
            if (finalizationFailed) throw new InvalidOperationException("management-capture-finalization");
            return;
        }
        // Original private DELETE owns response storage through the actual
        // original check. Generic finalization may not erase its lazy response
        // or turn its diagnostic status into another profile's capability.
        lock (gate)
        {
            if (privateDeleteInvocations.TryGetValue(invocation, out var deletion))
            {
                bool start = ReferenceEquals(invocation, deletion.Start);
                Task? actual = start ? deletion.StartTask : deletion.StatusTask;
                Require(actual is null || actual.IsCompleted);
                requestOwners.Remove(invocation);
                requestCandidates.Remove(invocation);
                originalReceipts.Remove(invocation);
                borrowers.Remove(invocation);
                finalReadEligible.Remove(invocation);
                nativeStatusReads.Remove(invocation);
                deletion.Invalid |= invocation.Canceled;
                invocation.Terminated = true;
                invocation.Drained.TrySetResult();
                if (start) deletion.Started.TrySetResult();
                else deletion.Checked.TrySetResult();
                return;
            }
        }
        bool failed = false, snapshotsDisposed = false;
        lock (gate)
        {
            Task? sdkTask = privateApproval is not null
                ? privateStatus ? privateApproval.StatusTask : privateApproval.StartTask
                : synchronousDelete is null ? invocation.SdkTask : synchronousDelete.Task;
            Require(sdkTask is null || sdkTask.IsCompleted);
            requestOwners.Remove(invocation);
            requestCandidates.Remove(invocation);
            originalReceipts.Remove(invocation);
            borrowers.Remove(invocation);
            finalReadEligible.Remove(invocation);
            try
            {
                foreach (var snapshot in privateApproval is not null ?
                    privateApproval.Snapshots.Concat(invocation.Snapshots)
                        .Distinct<IDisposable>(ReferenceEqualityComparer.Instance) :
                    synchronousDelete is null ? invocation.Snapshots :
                    synchronousDelete.Snapshots.Concat(invocation.Snapshots)
                        .Distinct<IDisposable>(ReferenceEqualityComparer.Instance))
                    try { snapshot.Dispose(); }
                    catch (Exception) { failed = true; }
                snapshotsDisposed = true;
            }
            finally
            {
                foreach (byte[] bytes in invocation.Owned) CryptographicOperations.ZeroMemory(bytes);
                if (privateApproval is not null)
                {
                    foreach (byte[] bytes in privateApproval.Owned) CryptographicOperations.ZeroMemory(bytes);
                    privateApproval.Owned.Clear();
                    privateApproval.Snapshots.Clear();
                }
                if (synchronousDelete is not null)
                {
                    foreach (byte[] bytes in synchronousDelete.Owned) CryptographicOperations.ZeroMemory(bytes);
                    synchronousDelete.Owned.Clear();
                    synchronousDelete.Snapshots.Clear();
                }
                invocation.Snapshots.Clear();
                // Retain the zeroed arrays as in-process erasure evidence, not material.
                // SDK-owned copies and immutable configuration/model strings are not
                // ours to erase; this makes no claim that those strings were erased.
                invocation.Terminated = true;
                if (!failed && acceptedWindow is not null) eligible.Add(acceptedWindow);
                if (!failed && statusWindow is not null && invocation.SdkTask is { IsCompletedSuccessfully: true } &&
                    !invocation.Canceled && invocation.Outcome == SecretStatus.Success &&
                    invocation.WrapperState == NativeProvisioningState.Succeeded &&
                    nativeStatusReads.GetValueOrDefault(invocation) ==
                        (statusWindow.Binding.Operation is ManagementMutation.UpdateNotification or ManagementMutation.CreateOrUpdateNotification ? 1 : 2))
                    completedStatusReads.Add(statusWindow);
                nativeStatusReads.Remove(invocation);
                if (synchronousDelete is
                    {
                        Invalid: false,
                        HookReturned: true,
                        SdkSucceeded: true,
                        TransportSucceeded: true,
                        Sends: 1,
                        Candidate: not null,
                        Handle: not null,
                        Request: not null
                    } &&
                    synchronousDelete.Task is { IsCompletedSuccessfully: true } &&
                    synchronousDelete.Dispatch == synchronousDelete.Candidate.StartDispatch &&
                    !synchronousDelete.Token.IsCancellationRequested && snapshotsDisposed && !failed)
                    synchronousDelete.Proof = synchronousDelete.Candidate;
                if (privateApproval is not null)
                {
                    if (privateStatus)
                    {
                        privateApproval.StatusInvalid |= failed || !snapshotsDisposed;
                        privateApproval.Completed = PrivateApprovalValid(privateApproval) &&
                            !privateApproval.StatusInvalid && privateApproval.StatusHookReturned &&
                            privateApproval.StatusSucceeded && privateApproval.StatusSends == 0 &&
                            privateApproval.StatusTask is { IsCompletedSuccessfully: true } &&
                            !privateApproval.StatusToken.IsCancellationRequested;
                        privateApproval.StatusFinalized.TrySetResult();
                    }
                    else
                    {
                        privateApproval.Invalid |= failed || !snapshotsDisposed;
                        if (!privateApproval.Sealed && !privateApproval.Invalid &&
                            privateApproval.StartHookReturned && privateApproval.StartSucceeded &&
                            privateApproval.TransportSucceeded && privateApproval.Sends == 1 &&
                            privateApproval.StartTask is { IsCompletedSuccessfully: true } &&
                            privateApproval.Handle?.State == NativeProvisioningState.Succeeded &&
                            !privateApproval.Token.IsCancellationRequested && privateApproval.ResponseFacts is { } facts)
                            privateApproval.Proof = new(facts.EndpointId);
                        privateApproval.StartFinalized.TrySetResult();
                    }
                }
                invocation.Drained.TrySetResult();
                synchronousDelete?.Finalized.TrySetResult();
            }
        }
        if (failed) throw new InvalidOperationException("management-capture-finalization");
    }

    private void OwnBytes(Invocation invocation, byte[] bytes)
    {
        lock (gate)
        {
            invocation.Owned.Add(bytes);
            if (statusVaultCancellationInvocations.TryGetValue(invocation, out var statusDeletion)) statusDeletion.Owned.Add(bytes);
            if (privateDeleteInvocations.TryGetValue(invocation, out var deletion)) deletion.Storage.Own(bytes);
            if (synchronousDeletes.TryGetValue(invocation, out var registration)) registration.Owned.Add(bytes);
            if (privateApprovalInvocations.TryGetValue(invocation, out var approval)) approval.Owned.Add(bytes);
        }
    }

    private void OwnSnapshot(Invocation invocation, IDisposable snapshot)
    {
        lock (gate)
        {
            invocation.Snapshots.Add(snapshot);
            if (statusVaultCancellationInvocations.TryGetValue(invocation, out var statusDeletion)) statusDeletion.Snapshots.Add(snapshot);
            if (privateDeleteInvocations.TryGetValue(invocation, out var deletion)) deletion.Storage.Own(snapshot);
            if (synchronousDeletes.TryGetValue(invocation, out var registration)) registration.Snapshots.Add(snapshot);
            if (privateApprovalInvocations.TryGetValue(invocation, out var approval)) approval.Snapshots.Add(snapshot);
        }
    }

    private void Own(Window window, FixtureSelector selector) =>
        Require(window is not null && ReferenceEquals(window.Owner, owner) && targets.ContainsKey(window) &&
            window.Binding.Selector == selector);
    private static void Require([DoesNotReturnIf(false)] bool condition)
    {
        if (!condition) throw new InvalidOperationException("management-capture-boundary");
    }
    private static bool Segment(string? value, int limit) => value is { Length: > 0 } && value.Length <= limit &&
        value is not ("." or "..") && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');

    private static (string Path, RequestMethod Method, string Revision) Route(Binding binding)
    {
        string path = binding.Resource switch
        {
            VaultScope v when binding.Operation is ManagementMutation.CreateOrUpdateVault or
                ManagementMutation.RecoverVault or ManagementMutation.DeleteVault => v.ExportResourceId(),
            DeletedVaultScope d when binding.Operation == ManagementMutation.PurgeDeletedVault =>
                $"/subscriptions/{d.Subscription.SubscriptionId:D}/providers/Microsoft.KeyVault/locations/{d.Location}/deletedVaults/{d.VaultName}/purge",
            PrivateConnectionScope c when binding.Operation is ManagementMutation.UpdatePrivateConnection or
                ManagementMutation.DeletePrivateConnection => c.Vault.ExportResourceId() + "/privateEndpointConnections/" + c.ConnectionName,
            RoleAssignmentScope { Parent: VaultScope v } r when binding.Operation == ManagementMutation.DeleteRoleAssignment =>
                v.ExportResourceId() + $"/providers/Microsoft.Authorization/roleAssignments/{r.AssignmentId:D}",
            NotificationScope n when binding.Operation is ManagementMutation.CreateOrUpdateNotification or
                ManagementMutation.UpdateNotification or ManagementMutation.DeleteNotification =>
                n.Vault.ExportResourceId() + "/providers/Microsoft.EventGrid/eventSubscriptions/" + n.SubscriptionName,
            _ => throw new InvalidOperationException("management-capture-binding")
        };
        Require(binding.Resource is not DeletedVaultScope deleted || deleted.Location == binding.Location);
        var method = binding.Operation switch
        {
            ManagementMutation.PurgeDeletedVault => RequestMethod.Post,
            ManagementMutation.UpdateNotification => RequestMethod.Patch,
            ManagementMutation.CreateOrUpdateVault or ManagementMutation.RecoverVault or
                ManagementMutation.UpdatePrivateConnection or ManagementMutation.CreateOrUpdateNotification => RequestMethod.Put,
            _ => RequestMethod.Delete
        };
        return (path, method, binding.Resource is NotificationScope ? "2025-02-15" :
            binding.Resource is RoleAssignmentScope ? "2022-04-01" : "2026-02-01");
    }

    private static bool InputMatches(Binding binding, ManagementOperationEffects.Input? input)
    {
        if (input is null || input.Location != binding.Location ||
            binding.Selector.Variant.StartsWith("status.", StringComparison.Ordinal) &&
            input.StatusOperation != binding.Operation) return false;
        VaultScope? vault = binding.Resource switch
        {
            VaultScope v => v,
            PrivateConnectionScope c => c.Vault,
            RoleAssignmentScope { Parent: VaultScope v } => v,
            NotificationScope n => n.Vault,
            _ => null
        };
        return vault is not null ? vault.ResourceGroup.Subscription.SubscriptionId == input.SubscriptionId &&
            vault.ResourceGroup.ResourceGroup == input.ResourceGroup :
            binding.Resource is DeletedVaultScope d && d.Subscription.SubscriptionId == input.SubscriptionId;
    }

    private static bool Trusted(Uri uri) => uri.IsAbsoluteUri && uri.Scheme == "https" && uri.IsDefaultPort &&
        uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 && uri.GetLeftPart(UriPartial.Authority) == Origin &&
        uri.OriginalString == uri.AbsoluteUri;

    private static void Headers(IEnumerable<HttpHeader> headers)
    {
        int rows = 0, bytes = 0;
        foreach (var header in headers)
        {
            Require(++rows <= 32 && header.Name.Length <= 128 && header.Value.Length <= 4096 &&
                !header.Value.Any(c => !char.IsAscii(c) || char.IsControl(c) && c != '\t'));
            bytes = checked(bytes + header.Name.Length + header.Value.Length);
            Require(bytes <= 16384);
        }
    }

    private static void JsonRows(JsonElement node, ref int remaining)
    {
        Require(--remaining >= 0);
        if (node.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in node.EnumerateObject())
            {
                Require(names.Add(property.Name));
                JsonRows(property.Value, ref remaining);
            }
        }
        else if (node.ValueKind == JsonValueKind.Array)
            foreach (var child in node.EnumerateArray()) JsonRows(child, ref remaining);
    }

    // A closed, optional proof profile. Failure here never changes the ordinary
    // transport/parser contract or substitutes a response for the SDK.
    private static bool PrivateApprovalHeaders((string Name, string Value)[] headers, int count)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in headers)
            if (header.Name.Length == 0 ||
                !header.Name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') ||
                !names.Add(header.Name) ||
                new[] { "Location", "Azure-AsyncOperation", "Operation-Location", "Retry-After",
                    "Content-Encoding", "Content-Range", "Transfer-Encoding" }
                    .Contains(header.Name, StringComparer.OrdinalIgnoreCase))
                return false;
        string[] lengths = headers.Where(h => h.Name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
            .Select(h => h.Value).ToArray();
        if (lengths.Length != 0 && (lengths.Length != 1 ||
            !long.TryParse(lengths[0], NumberStyles.None, CultureInfo.InvariantCulture, out long length) ||
            length != count)) return false;
        string[] types = headers.Where(h => h.Name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
            .Select(h => h.Value).ToArray();
        if (types.Length != 1) return false;
        string[] pieces = types[0].Split(';', StringSplitOptions.TrimEntries);
        return pieces.Length is 1 or 2 && pieces[0].Equals("application/json", StringComparison.OrdinalIgnoreCase) &&
            (pieces.Length == 1 || pieces[1].Equals("charset=utf-8", StringComparison.OrdinalIgnoreCase));
    }

    private static void ValidateNotificationUpdate(StatusVaultCancellationRegistration r, JsonElement root,
        bool request, bool status)
    {
        var scope = (NotificationScope)r.ActualOriginalScope;
        var configuration = r.NotificationUpdateConfiguration!;
        bool create = NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(r.Binding.Selector);
        Require(OnlyApprovalFields(root, request ? create ? ["properties"] : ["destination", "filter"] :
            ["id", "name", "type", "properties"]));
        if (!request)
            Require(ApprovalText(root, "id") == r.Window.Path &&
                ApprovalText(root, "name") == scope.SubscriptionName &&
                ApprovalText(root, "type") == "Microsoft.EventGrid/eventSubscriptions");
        var properties = request && !create ? root : root.GetProperty("properties");
        Require(OnlyApprovalFields(properties, request ? ["destination", "filter"] :
            ["topic", "labels", "provisioningState", "destination", "filter"]));
        if (!request)
        {
            Require(ApprovalText(properties, "topic") == scope.Vault.ExportResourceId() &&
                ApprovalText(properties, "provisioningState") == (status ? "Succeeded" : "Updating"));
            if (r.NotificationAbsentCreate is not null)
                Require(create && (!properties.TryGetProperty("labels", out var emptyLabels) ||
                    emptyLabels.ValueKind == JsonValueKind.Array && emptyLabels.GetArrayLength() == 0));
            else
            {
                var labels = properties.GetProperty("labels");
                Require(labels.ValueKind == JsonValueKind.Array && labels.GetArrayLength() == 1 &&
                    labels[0].ValueKind == JsonValueKind.String &&
                    labels[0].GetString() == "secretkit-fixture-" + r.Binding.Selector.Nonce.ToString("N"));
            }
        }
        var filter = properties.GetProperty("filter");
        Require(OnlyApprovalFields(filter, "includedEventTypes", "advancedFilters"));
        var events = filter.GetProperty("includedEventTypes");
        Require(events.ValueKind == JsonValueKind.Array && events.GetArrayLength() == 1 &&
            events[0].GetString() == "Microsoft.KeyVault.SecretNewVersionCreated");
        if (filter.TryGetProperty("advancedFilters", out var advanced))
            Require(advanced.ValueKind == JsonValueKind.Array && advanced.GetArrayLength() == 0);
        var destination = properties.GetProperty("destination");
        Require(OnlyApprovalFields(destination, "endpointType", "properties") &&
            ApprovalText(destination, "endpointType") == "WebHook");
        var settings = destination.GetProperty("properties");
        Require(OnlyApprovalFields(settings, request ? ["endpointUrl"] :
            ["endpointUrl", "endpointBaseUrl", "deliveryAttributeMappings"]) &&
            ApprovalText(settings, "endpointUrl") == configuration.Endpoint.Reveal());
        var endpoint = new Uri(configuration.Endpoint.Reveal(), UriKind.Absolute);
        Require(endpoint.Scheme == "https" && endpoint.UserInfo.Length == 0 && endpoint.Fragment.Length == 0);
        if (!request)
        {
            var mappings = settings.GetProperty("deliveryAttributeMappings");
            Require(mappings.ValueKind == JsonValueKind.Array && mappings.GetArrayLength() == 0);
            if (settings.TryGetProperty("endpointBaseUrl", out var endpointBase))
                Require(endpointBase.ValueKind == JsonValueKind.String &&
                    endpointBase.GetString() == endpoint.GetLeftPart(UriPartial.Path));
        }
    }

    private static bool OnlyApprovalFields(JsonElement value, params string[] fields) =>
        value.ValueKind == JsonValueKind.Object &&
        value.EnumerateObject().All(p => fields.Contains(p.Name, StringComparer.Ordinal));

    private static string ApprovalText(JsonElement parent, string name)
    {
        var value = parent.GetProperty(name);
        Require(value.ValueKind == JsonValueKind.String);
        string? text = value.GetString();
        Require(!string.IsNullOrWhiteSpace(text) && text.Length <= 4096 && !text.Any(char.IsControl));
        return text;
    }

    private static void ApprovalOptionalText(JsonElement parent, params string[] names)
    {
        foreach (string name in names)
            if (parent.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null)
            {
                Require(value.ValueKind == JsonValueKind.String);
                string text = value.GetString()!;
                Require(text.Length <= 4096 && !text.Any(char.IsControl));
            }
    }

    private static bool PrivateApprovalRequest(byte[] bytes, (string Name, string Value)[] headers,
        PrivateConnectionState requested = PrivateConnectionState.Approved)
    {
        try
        {
            if (!PrivateApprovalHeaders(headers, bytes.Length)) return false;
            using var json = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int rows = 512;
            JsonRows(json.RootElement, ref rows);
            var root = json.RootElement;
            Require(OnlyApprovalFields(root, "properties"));
            var properties = root.GetProperty("properties");
            Require(OnlyApprovalFields(properties, "privateLinkServiceConnectionState"));
            var state = properties.GetProperty("privateLinkServiceConnectionState");
            Require(requested is PrivateConnectionState.Approved or PrivateConnectionState.Rejected &&
                OnlyApprovalFields(state, "status") && ApprovalText(state, "status") == requested.ToString());
            return true;
        }
        catch (Exception) { return false; }
    }

    private static PrivateApprovalFacts? PrivateApprovalResponse(PrivateApprovalRegistration registration,
        ReadOnlyMemory<byte> bytes, (string Name, string Value)[] headers, int status) =>
        PrivateConnectionResponse(registration.Scope, PrivateConnectionState.Approved, bytes, headers, status);

    internal static VaultAdministrationCollector.ConnectionRow ParsePrivateConnectionResource(
        PrivateConnectionScope scope, ReadOnlyMemory<byte> bytes, (string Name, string Value)[] headers, int status)
    {
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
        string? state = document.RootElement.GetProperty("properties")
            .GetProperty("privateLinkServiceConnectionState").GetProperty("status").GetString();
        Require(Enum.TryParse<PrivateConnectionState>(state, out var requested) && Enum.IsDefined(requested) &&
            requested.ToString() == state);
        var facts = PrivateConnectionResponse(scope, requested, bytes, headers, status);
        Require(facts is not null);
        return new(facts.Name, requested, NativeProvisioningState.Succeeded)
        { ResourceId = facts.Id, PrivateEndpointId = facts.EndpointId };
    }

    internal static void ValidatePrivateConnectionAbsentResponse(ReadOnlyMemory<byte> bytes,
        (string Name, string Value)[] headers, int status)
    {
        Require(status == 404 && bytes.Length != 0 && PrivateApprovalHeaders(headers, bytes.Length));
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
        int rows = 512;
        JsonRows(document.RootElement, ref rows);
        Require(OnlyApprovalFields(document.RootElement, "error"));
        var error = document.RootElement.GetProperty("error");
        Require(OnlyApprovalFields(error, "code", "message", "target", "details", "innererror"));
        Require(ApprovalText(error, "code") is "ResourceNotFound" or "NotFound");
        ApprovalOptionalText(error, "message", "target");
        if (error.TryGetProperty("details", out var details)) Require(details.ValueKind == JsonValueKind.Array);
        if (error.TryGetProperty("innererror", out var inner)) Require(inner.ValueKind == JsonValueKind.Object);
    }

    private static PrivateApprovalFacts? PrivateConnectionResponse(PrivateConnectionScope scope,
        PrivateConnectionState requested, ReadOnlyMemory<byte> bytes, (string Name, string Value)[] headers, int status)
    {
        try
        {
            if (status != 200 || bytes.Length == 0 || !PrivateApprovalHeaders(headers, bytes.Length)) return null;
            using var json = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
            int rows = 512;
            JsonRows(json.RootElement, ref rows);
            var root = json.RootElement;
            Require(OnlyApprovalFields(root, "id", "name", "type", "etag", "systemData", "properties"));
            ApprovalOptionalText(root, "etag");
            if (root.TryGetProperty("systemData", out var system) && system.ValueKind != JsonValueKind.Null)
            {
                Require(OnlyApprovalFields(system, "createdBy", "createdByType", "createdAt",
                    "lastModifiedBy", "lastModifiedByType", "lastModifiedAt"));
                ApprovalOptionalText(system, "createdBy", "createdByType", "createdAt",
                    "lastModifiedBy", "lastModifiedByType", "lastModifiedAt");
            }
            string id = ApprovalText(root, "id"), name = ApprovalText(root, "name"), type = ApprovalText(root, "type");
            Require(id == scope.Vault.ExportResourceId() + "/privateEndpointConnections/" +
                scope.ConnectionName && name == scope.ConnectionName &&
                type == "Microsoft.KeyVault/vaults/privateEndpointConnections");
            var properties = root.GetProperty("properties");
            Require(OnlyApprovalFields(properties, "provisioningState", "privateEndpoint", "privateLinkServiceConnectionState"));
            string provisioning = ApprovalText(properties, "provisioningState");
            var state = properties.GetProperty("privateLinkServiceConnectionState");
            Require(OnlyApprovalFields(state, "status", "description", "actionsRequired"));
            string approval = ApprovalText(state, "status");
            ApprovalOptionalText(state, "description", "actionsRequired");
            Require(provisioning == "Succeeded" && approval == requested.ToString());
            var endpoint = properties.GetProperty("privateEndpoint");
            Require(OnlyApprovalFields(endpoint, "id"));
            string endpointId = ApprovalText(endpoint, "id");
            string[] parts = endpointId.Split('/');
            Require(parts.Length == 9 && parts[0].Length == 0 &&
                parts[1].Equals("subscriptions", StringComparison.OrdinalIgnoreCase) &&
                Guid.TryParseExact(parts[2], "D", out var subscription) && subscription != Guid.Empty &&
                parts[3].Equals("resourceGroups", StringComparison.OrdinalIgnoreCase) && Segment(parts[4], 90) &&
                parts[5].Equals("providers", StringComparison.OrdinalIgnoreCase) &&
                parts[6].Equals("Microsoft.Network", StringComparison.OrdinalIgnoreCase) &&
                parts[7].Equals("privateEndpoints", StringComparison.OrdinalIgnoreCase) && Segment(parts[8], 256));
            // This installed native reader consumes the SAME original complete
            // bounded bytes, before FinishAsync erases them. No hidden LRO Value.
            var native = ModelReaderWriter.Read<KeyVaultPrivateEndpointConnectionData>(new BinaryData(bytes));
            Require(native is not null && native.Id?.ToString() == id && native.Name == name &&
                native.ResourceType.ToString() == type && native.PrivateEndpointId?.ToString() == endpointId &&
                native.ConnectionState?.Status?.ToString() == approval &&
                native.ProvisioningState?.ToString() == provisioning);
            return new(id, name, type, approval, provisioning, endpointId);
        }
        catch (Exception) { return null; }
    }

    private static WireState State(string? state) => state?.ToLowerInvariant() switch
    {
        "succeeded" => WireState.Succeeded,
        "failed" => WireState.Failed,
        "canceled" or "cancelled" => WireState.Canceled,
        "accepted" or "running" or "inprogress" or "creating" or "updating" or "deleting" => WireState.Pending,
        _ => WireState.Unknown
    };

    private static string? Continuation(Window window, HttpMessage message)
    {
        string? selected = null;
        foreach (string name in new[] { "Azure-AsyncOperation", "Operation-Location", "Location" })
        {
            if (!message.Response.Headers.TryGetValues(name, out var values)) continue;
            string[] targets = values.Take(3).ToArray();
            Require(targets.Length == 1 && targets[0].Length <= 2048 &&
                Uri.TryCreate(targets[0], UriKind.Absolute, out _));
            var uri = new Uri(targets[0], UriKind.Absolute);
            Require(Trusted(uri) && uri.Query == "?api-version=" + window.Binding.ApiRevision &&
                uri.OriginalString == uri.AbsoluteUri);
            bool allowed = window.Binding.Resource is NotificationScope
                ? uri.AbsolutePath == window.Path
                : window.Binding.Resource is not RoleAssignmentScope && OperationPath(window, uri.AbsolutePath);
            Require(allowed && (selected is null || selected == uri.AbsoluteUri));
            selected = uri.AbsoluteUri;
        }
        return selected;
    }

    private static bool OperationPath(Window window, string path)
    {
        string subscription = window.Path.Split('/')[2];
        string prefix = $"/subscriptions/{subscription}/providers/Microsoft.KeyVault/locations/{window.Binding.Location}/";
        if (!path.StartsWith(prefix, StringComparison.Ordinal)) return false;
        string[] tail = path[prefix.Length..].Split('/');
        return tail.Length == 2 && tail[0] is "operations" or "operationResults" &&
            Guid.TryParseExact(tail[1], "D", out var id) && id != Guid.Empty;
    }

    private sealed class InvocationTransport(ManagementOperationNativeCapture source) : HttpPipelineTransport
    {
        public override Request CreateRequest()
        {
            if (source.currentStatusDeniedVaultRecover.Value is { } deniedVaultRecover)
            {
                var r = deniedVaultRecover.Registration;
                var slot = deniedVaultRecover.Slot;
                lock (source.gate)
                {
                    bool valid = StatusDeniedVaultRecoverLive(r) && !slot.Token.IsCancellationRequested &&
                        !slot.Caller.IsCancellationRequested && !slot.Finished && !slot.FactoryActive && !slot.Sending &&
                        ++slot.Factories == 1 && slot.SendCount == 0;
                    r.Invalid |= !valid;
                    Require(valid);
                    slot.FactoryActive = true;
                }
                try
                {
                    var request = source.backend.CreateRequest();
                    lock (source.gate)
                    {
                        Require(StatusDeniedVaultRecoverLive(r) && !slot.Token.IsCancellationRequested &&
                            !slot.Caller.IsCancellationRequested && slot.Requests.Add(request));
                    }
                    return request;
                }
                catch { r.Invalid = true; throw; }
                finally { lock (source.gate) slot.FactoryActive = false; }
            }
            if (source.currentStatusDeniedVaultUpdate.Value is { } deniedVaultUpdate)
            {
                var r = deniedVaultUpdate.Registration;
                var slot = deniedVaultUpdate.Slot;
                lock (source.gate)
                {
                    bool valid = StatusDeniedVaultUpdateLive(r) && !slot.Token.IsCancellationRequested &&
                        !slot.Caller.IsCancellationRequested && !slot.Finished && !slot.FactoryActive && !slot.Sending &&
                        ++slot.Factories == 1 && slot.SendCount == 0;
                    r.Invalid |= !valid;
                    Require(valid);
                    slot.FactoryActive = true;
                }
                try
                {
                    var request = source.backend.CreateRequest();
                    lock (source.gate)
                    {
                        Require(StatusDeniedVaultUpdateLive(r) && !slot.Token.IsCancellationRequested &&
                            !slot.Caller.IsCancellationRequested && slot.Requests.Add(request));
                    }
                    return request;
                }
                catch { r.Invalid = true; throw; }
                finally { lock (source.gate) slot.FactoryActive = false; }
            }
            if (source.currentStatusDeniedPrivateConnectionDelete.Value is { } deniedPrivateDelete)
            {
                var r = deniedPrivateDelete.Registration;
                var slot = deniedPrivateDelete.Slot;
                lock (source.gate)
                {
                    bool valid = StatusDeniedPrivateConnectionDeleteLive(r) && !slot.Token.IsCancellationRequested &&
                        !slot.Finished && !slot.FactoryActive && !slot.Sending &&
                        ++slot.Factories == 1 && slot.SendCount == 0;
                    r.Invalid |= !valid;
                    Require(valid);
                    slot.FactoryActive = true;
                }
                try
                {
                    var request = source.backend.CreateRequest();
                    lock (source.gate)
                    {
                        Require(StatusDeniedPrivateConnectionDeleteLive(r) && !slot.Token.IsCancellationRequested &&
                            slot.Requests.Add(request));
                    }
                    return request;
                }
                catch { r.Invalid = true; throw; }
                finally { lock (source.gate) slot.FactoryActive = false; }
            }
            if (source.currentStatusDeniedPurge.Value is { } denied)
            {
                var r = denied.Registration;
                var slot = denied.Slot;
                lock (source.gate)
                {
                    bool valid = StatusDeniedPurgeLive(r) && !slot.Token.IsCancellationRequested &&
                        !slot.Finished && !slot.FactoryActive && !slot.Sending &&
                        ++slot.Factories == 1 && slot.SendCount == 0;
                    r.Invalid |= !valid;
                    Require(valid);
                    slot.FactoryActive = true;
                }
                try
                {
                    var request = source.backend.CreateRequest();
                    lock (source.gate)
                    {
                        Require(StatusDeniedPurgeLive(r) && !slot.Token.IsCancellationRequested &&
                            slot.Requests.Add(request));
                    }
                    return request;
                }
                catch { r.Invalid = true; throw; }
                finally { lock (source.gate) slot.FactoryActive = false; }
            }
            lock (source.gate)
            {
                if (source.current.Value is { } cancellationContext &&
                    source.statusUnknownNotificationUpdateCancellationInvocations.TryGetValue(cancellationContext.Invocation, out var r))
                {
                    if (ReferenceEquals(cancellationContext.Invocation, r.Canceled))
                    {
                        r.CanceledFactories++;
                        r.Invalid = true;
                    }
                    bool valid = !r.Invalid && !r.Sealed && !source.finishing.Contains(cancellationContext.Invocation);
                    r.Invalid |= !valid;
                    Require(valid);
                }
            }
            if (source.currentStatusPendingPurge.Value is { } pending)
            {
                var r = pending.Registration;
                var slot = pending.Slot;
                lock (source.gate)
                {
                    // The actual precanceled SDK gate must prevent factories.
                    // Reaching this boundary revokes C even without a send.
                    if (slot.Phase == StatusPendingPurgePhase.Canceled)
                    {
                        slot.Factories++;
                        r.Invalid = true;
                    }
                    bool valid = StatusPendingPurgeLive(r) && !slot.Token.IsCancellationRequested &&
                        !slot.Finished && !slot.FactoryActive && !slot.Sending &&
                        ++slot.Factories <= (slot.Phase == StatusPendingPurgePhase.Cleanup ? 2 : 1) &&
                        slot.Factories == slot.SendCount + 1 &&
                        (slot.Phase == StatusPendingPurgePhase.Cleanup ? r.SelectedRevoked && r.Window.Closed
                            : !r.SelectedRevoked && !r.Window.Closed);
                    r.Invalid |= !valid;
                    Require(valid);
                    slot.FactoryActive = true;
                }
                try
                {
                    var request = source.backend.CreateRequest();
                    lock (source.gate)
                    {
                        Require(StatusPendingPurgeLive(r) && !slot.Token.IsCancellationRequested &&
                            slot.Requests.TryAdd(request, TimeProvider.System.GetTimestamp()));
                    }
                    return request;
                }
                catch { r.Invalid = true; throw; }
                finally { lock (source.gate) slot.FactoryActive = false; }
            }
            if (source.currentStatusPrivateUpdateIndependent.Value is { } privateUpdateIndependent)
            {
                var r = privateUpdateIndependent.Registration;
                lock (source.gate)
                {
                    if (privateUpdateIndependent.Check) { r.CheckFactories++; r.Invalid = true; }
                    bool valid = !r.Invalid && !r.Sealed && !r.FactoryClaimed;
                    r.FactoryClaimed = true;
                    r.Invalid |= !valid;
                    Require(valid);
                }
                try
                {
                    var request = source.backend.CreateRequest();
                    lock (source.gate) r.Requests.Add(request);
                    return request;
                }
                catch { r.Invalid = true; throw; }
            }
            if (source.currentStatusSucceededDeleteVaultCancellation.Value is { } cancellationSucceeded)
            {
                var r = cancellationSucceeded.Registration;
                lock (source.gate)
                {
                    if (cancellationSucceeded.Stage != StatusSucceededDeleteVaultCancellationStage.Start)
                    {
                        if (cancellationSucceeded.Stage == StatusSucceededDeleteVaultCancellationStage.Canceled) r.CancelFactories++;
                        else r.CheckFactories++;
                        r.Invalid = true;
                    }
                    Require(!r.Invalid && !r.Sealed && r.Requests.Count == 0);
                }
                try
                {
                    var request = source.backend.CreateRequest();
                    lock (source.gate) r.Requests.Add(request);
                    return request;
                }
                catch { r.Invalid = true; throw; }
            }
            if (source.currentStatusSucceededDeleteVaultIndependent.Value is { } independentSucceeded)
            {
                var r = independentSucceeded.Registration;
                lock (source.gate)
                {
                    if (independentSucceeded.Check) { r.CheckFactories++; r.Invalid = true; }
                    Require(!r.Invalid && !r.Sealed && r.Requests.Count == 0);
                }
                try
                {
                    var request = source.backend.CreateRequest();
                    lock (source.gate) r.Requests.Add(request);
                    return request;
                }
                catch { r.Invalid = true; throw; }
            }
            if (source.currentStatusSucceededDeleteVault.Value is { } succeeded)
            {
                var r = succeeded.Registration;
                lock (source.gate)
                {
                    if (succeeded.Check) { r.CheckFactories++; r.Invalid = true; }
                    Require(!r.Invalid && !r.Sealed && r.Requests.Count == 0);
                }
                try
                {
                    var request = source.backend.CreateRequest();
                    lock (source.gate) r.Requests.Add(request);
                    return request;
                }
                catch { r.Invalid = true; throw; }
            }
            if (source.currentPrivateUpdate.Value is { } update)
            {
                lock (source.gate)
                {
                    Require(!update.Registration.Sealed);
                    if (update.Check)
                    {
                        update.Registration.CheckSends++;
                        update.Registration.Invalid = true;
                        throw new InvalidOperationException("private-update-cached-check");
                    }
                    Require(update.Registration.Requests.Count < 16);
                }
                var request = source.backend.CreateRequest();
                lock (source.gate) update.Registration.Requests.Add(request);
                return request;
            }
            if (source.currentCreateVault.Value is { } creation)
            {
                lock (source.gate) Require(!creation.Registration.Sealed && creation.Registration.Requests.Count < 16);
                var request = source.backend.CreateRequest();
                lock (source.gate) creation.Registration.Requests.Add(request);
                return request;
            }
            if (source.currentPurgeDeletedVault.Value is { } purge)
            {
                lock (source.gate) Require(!purge.Registration.Sealed && purge.Registration.Requests.Count < 16);
                var request = source.backend.CreateRequest();
                lock (source.gate) purge.Registration.Requests.Add(request);
                return request;
            }
            if (source.currentDeleteVault.Value is { } deletion)
            {
                lock (source.gate)
                {
                    Require(!deletion.Registration.Sealed);
                    if (deletion.Check)
                    {
                        deletion.Registration.CheckSends++;
                        deletion.Registration.Invalid = true;
                        throw new InvalidOperationException("delete-vault-cached-check");
                    }
                    Require(deletion.Registration.Requests.Count < 16);
                }
                var request = source.backend.CreateRequest();
                lock (source.gate) deletion.Registration.Requests.Add(request);
                return request;
            }
            InvocationContext context = source.current.Value ??
                throw new InvalidOperationException("management-capture-invocation");
            Invocation invocation = context.Invocation;
            lock (source.gate)
            {
                if (source.statusDeniedNotificationUpdateInvocations.TryGetValue(invocation, out var deniedUpdate) &&
                    (deniedUpdate.Invalid || deniedUpdate.Sealed || source.finishing.Contains(invocation)))
                {
                    deniedUpdate.Invalid = true;
                    throw new InvalidOperationException("status-denied-notification-update-check");
                }
                if (source.statusUnknownNotificationUpdateIndependentInvocations.TryGetValue(invocation, out var unknownIndependentUpdate) &&
                    (unknownIndependentUpdate.Sealed || source.finishing.Contains(invocation)))
                {
                    unknownIndependentUpdate.Invalid = true;
                    throw new InvalidOperationException("status-unknown-notification-update-independent-check");
                }
                if (source.statusUnknownNotificationUpdateInvocations.TryGetValue(invocation, out var unknownUpdate) &&
                    (unknownUpdate.Sealed || source.finishing.Contains(invocation)))
                {
                    unknownUpdate.Invalid = true;
                    throw new InvalidOperationException("status-unknown-notification-update-check");
                }
                if (source.statusNotificationUpdateIndependentInvocations.TryGetValue(invocation, out var independentUpdate) &&
                    (independentUpdate.Sealed || source.finishing.Contains(invocation)))
                {
                    independentUpdate.Invalid = true;
                    throw new InvalidOperationException("status-notification-update-independent-check");
                }
                if (source.statusNotificationCreateIndependentInvocations.TryGetValue(invocation, out var independentCreate) &&
                    (independentCreate.Sealed || source.finishing.Contains(invocation)))
                {
                    independentCreate.Invalid = true;
                    throw new InvalidOperationException("status-notification-create-independent-check");
                }
                if (source.statusRoleDeleteIndependentInvocations.TryGetValue(invocation, out var independentRoleDelete) &&
                    (!ReferenceEquals(independentRoleDelete.Start, invocation) || independentRoleDelete.Sealed ||
                        source.finishing.Contains(invocation)))
                {
                    independentRoleDelete.Invalid = true;
                    throw new InvalidOperationException("status-role-delete-independent-check");
                }
                if (source.statusNotificationDeleteIndependentInvocations.TryGetValue(invocation, out var independentDelete) &&
                    (!ReferenceEquals(independentDelete.Start, invocation) || source.finishing.Contains(invocation)))
                {
                    independentDelete.Invalid = true;
                    throw new InvalidOperationException("status-notification-delete-independent-check");
                }
                if (source.statusPrivateDeleteSelectedInvocations.TryGetValue(invocation, out var selectedDelete) &&
                    (!ReferenceEquals(selectedDelete.Start, invocation) || source.finishing.Contains(invocation)))
                {
                    selectedDelete.Invalid = true;
                    throw new InvalidOperationException("status-private-delete-selected-check");
                }
                if (source.statusPrivateDeleteIndependentInvocations.TryGetValue(invocation, out var independentPrivateDelete) &&
                    (!ReferenceEquals(independentPrivateDelete.Start, invocation) || source.finishing.Contains(invocation)))
                {
                    independentPrivateDelete.Invalid = true;
                    throw new InvalidOperationException("status-private-delete-independent-check");
                }
                if (source.statusVaultCancellationInvocations.TryGetValue(invocation, out var statusDeletion) &&
                    !ReferenceEquals(statusDeletion.Start, invocation) &&
                    (!(VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(statusDeletion.Binding.Selector) ||
                        VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(statusDeletion.Binding.Selector) ||
                        VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(statusDeletion.Binding.Selector) ||
                        NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(statusDeletion.Binding.Selector) ||
                        NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(statusDeletion.Binding.Selector)) ||
                        !ReferenceEquals(statusDeletion.NormalStatus, invocation)))
                {
                    statusDeletion.Invalid = true;
                    throw new InvalidOperationException("status-vault-cancellation-check");
                }
                if (source.synchronousDeletes.TryGetValue(invocation, out var registration) &&
                    (source.requestFactories.Contains(invocation) || source.finishing.Contains(invocation)))
                    registration.Invalid = true;
                Require(source.targets.ContainsKey(context.Window) &&
                    (registration is not null ? ReferenceEquals(registration.Window, context.Window) :
                        ReferenceEquals(invocation, context.Status ? context.Window.Status : context.Window.Start)) &&
                    (registration is not null || !invocation.Terminated) && !source.finishing.Contains(invocation) &&
                    !source.requestFactories.Contains(invocation));
                Require(!source.requestCandidates.TryGetValue(invocation, out var candidates) || candidates.Count < 16);
                source.requestFactories.Add(invocation);
            }
            try
            {
                Request request = source.backend.CreateRequest();
                lock (source.gate)
                {
                    Require((source.synchronousDeletes.ContainsKey(invocation) || !invocation.Terminated) &&
                        !source.finishing.Contains(invocation));
                    if (!source.requestCandidates.TryGetValue(invocation, out var candidates))
                        source.requestCandidates.Add(invocation, candidates = []);
                    candidates.Add(request);
                }
                return request;
            }
            catch (Exception)
            {
                lock (source.gate)
                {
                    if (source.synchronousDeletes.TryGetValue(invocation, out var registration))
                        registration.Invalid = true;
                    if (source.privateDeleteInvocations.TryGetValue(invocation, out var privateDeletion))
                        privateDeletion.Invalid = true;
                    if (source.statusPrivateDeleteSelectedInvocations.TryGetValue(invocation, out var selectedDelete))
                        selectedDelete.Invalid = true;
                    if (source.statusPrivateDeleteIndependentInvocations.TryGetValue(invocation, out var independentPrivateDelete))
                        independentPrivateDelete.Invalid = true;
                    if (source.statusNotificationDeleteIndependentInvocations.TryGetValue(invocation, out var independentDelete))
                        independentDelete.Invalid = true;
                    if (source.statusRoleDeleteIndependentInvocations.TryGetValue(invocation, out var independentRoleDelete))
                        independentRoleDelete.Invalid = true;
                    if (source.statusVaultCancellationInvocations.TryGetValue(invocation, out var statusDeletion))
                        statusDeletion.Invalid = true;
                    if (source.statusUnknownNotificationUpdateInvocations.TryGetValue(invocation, out var unknownUpdate))
                        unknownUpdate.Invalid = true;
                    if (source.statusDeniedNotificationUpdateInvocations.TryGetValue(invocation, out var deniedUpdate))
                        deniedUpdate.Invalid = true;
                    if (source.statusUnknownNotificationUpdateIndependentInvocations.TryGetValue(invocation, out var unknownIndependentUpdate))
                        unknownIndependentUpdate.Invalid = true;
                }
                throw;
            }
            finally { lock (source.gate) source.requestFactories.Remove(invocation); }
        }
        public override void Process(HttpMessage message)
        {
            if (source.currentStatusDeniedVaultRecover.Value is { } deniedVaultRecover)
                deniedVaultRecover.Registration.Invalid = true;
            if (source.currentStatusDeniedVaultUpdate.Value is { } deniedVaultUpdate)
                deniedVaultUpdate.Registration.Invalid = true;
            if (source.currentStatusDeniedPrivateConnectionDelete.Value is { } deniedPrivateDelete)
                deniedPrivateDelete.Registration.Invalid = true;
            lock (source.gate)
                if (source.current.Value is { } deniedContext &&
                    source.statusDeniedNotificationUpdateInvocations.TryGetValue(deniedContext.Invocation, out var deniedUpdate))
                    deniedUpdate.Invalid = true;
            if (source.currentStatusDeniedPurge.Value is { } denied)
                denied.Registration.Invalid = true;
            lock (source.gate)
                if (source.current.Value is { } unknownIndependent &&
                    source.statusUnknownNotificationUpdateIndependentInvocations.TryGetValue(unknownIndependent.Invocation, out var unknownIndependentUpdate))
                    unknownIndependentUpdate.Invalid = true;
            lock (source.gate)
                if (source.current.Value is { } unknown &&
                    source.statusUnknownNotificationUpdateInvocations.TryGetValue(unknown.Invocation, out var unknownUpdate))
                    unknownUpdate.Invalid = true;
            if (source.currentStatusPendingPurge.Value is { } pending)
                pending.Registration.Invalid = true;
            if (source.currentStatusPrivateUpdateIndependent.Value is { } privateUpdateIndependent)
                privateUpdateIndependent.Registration.Invalid = true;
            lock (source.gate)
                if (source.current.Value is { } update &&
                    source.statusNotificationUpdateIndependentInvocations.TryGetValue(update.Invocation, out var independentUpdate))
                    independentUpdate.Invalid = true;
            lock (source.gate)
                if (source.current.Value is { } create &&
                    source.statusNotificationCreateIndependentInvocations.TryGetValue(create.Invocation, out var independentCreate))
                    independentCreate.Invalid = true;
            lock (source.gate)
                if (source.current.Value is { } role &&
                    source.statusRoleDeleteIndependentInvocations.TryGetValue(role.Invocation, out var independentRole))
                    independentRole.Invalid = true;
            if (source.currentStatusSucceededDeleteVaultCancellation.Value is { } cancellationSucceeded)
                cancellationSucceeded.Registration.Invalid = true;
            if (source.currentStatusSucceededDeleteVaultIndependent.Value is { } independentSucceeded)
                independentSucceeded.Registration.Invalid = true;
            if (source.currentStatusSucceededDeleteVault.Value is { } succeeded)
                succeeded.Registration.Invalid = true;
            lock (source.gate)
                if (source.current.Value is { } independent &&
                    source.statusNotificationDeleteIndependentInvocations.TryGetValue(independent.Invocation, out var independentDelete))
                    independentDelete.Invalid = true;
            lock (source.gate)
                if (source.current.Value is { } selected &&
                    source.statusPrivateDeleteSelectedInvocations.TryGetValue(selected.Invocation, out var selectedDelete))
                    selectedDelete.Invalid = true;
            lock (source.gate)
                if (source.current.Value is { } independentPrivate &&
                    source.statusPrivateDeleteIndependentInvocations.TryGetValue(independentPrivate.Invocation, out var independentPrivateDelete))
                    independentPrivateDelete.Invalid = true;
            lock (source.gate)
                if (source.current.Value is { } context &&
                    source.statusVaultCancellationInvocations.TryGetValue(context.Invocation, out var r))
                    r.Invalid = true;
            throw new InvalidOperationException("management-capture-async");
        }
        public override ValueTask ProcessAsync(HttpMessage message)
        {
            if (source.currentStatusDeniedVaultRecover.Value is { } deniedVaultRecover)
            {
                var task = source.SendStatusDeniedVaultRecoverAsync(deniedVaultRecover, message);
                lock (source.gate) deniedVaultRecover.Slot.Sends.Add(task);
                return new(task);
            }
            if (source.currentStatusDeniedVaultUpdate.Value is { } deniedVaultUpdate)
            {
                var task = source.SendStatusDeniedVaultUpdateAsync(deniedVaultUpdate, message);
                lock (source.gate) deniedVaultUpdate.Slot.Sends.Add(task);
                return new(task);
            }
            if (source.currentStatusDeniedPrivateConnectionDelete.Value is { } deniedPrivateDelete)
            {
                var task = source.SendStatusDeniedPrivateConnectionDeleteAsync(deniedPrivateDelete, message);
                lock (source.gate) deniedPrivateDelete.Slot.Sends.Add(task);
                return new(task);
            }
            if (source.currentStatusDeniedPurge.Value is { } denied)
            {
                var task = source.SendStatusDeniedPurgeAsync(denied, message);
                lock (source.gate) denied.Slot.Sends.Add(task);
                return new(task);
            }
            lock (source.gate)
            {
                if (source.current.Value is { } cancellationContext &&
                    source.statusUnknownNotificationUpdateCancellationInvocations.TryGetValue(cancellationContext.Invocation, out var r) &&
                    ReferenceEquals(cancellationContext.Invocation, r.Canceled))
                {
                    r.CanceledSends++;
                    r.Invalid = true;
                    throw new InvalidOperationException("management-capture-boundary");
                }
            }
            if (source.currentStatusPendingPurge.Value is { } pending)
            {
                var task = source.SendStatusPendingPurgeAsync(pending, message);
                lock (source.gate) pending.Slot.Sends.Add(task);
                return new(task);
            }
            if (source.currentStatusPrivateUpdateIndependent.Value is { } privateUpdateIndependent)
            {
                var task = source.SendStatusPrivateUpdateIndependentAsync(privateUpdateIndependent, message);
                privateUpdateIndependent.Registration.SendTask = task;
                return new(task);
            }
            if (source.currentStatusSucceededDeleteVaultCancellation.Value is { } cancellationSucceeded)
            {
                var task = source.SendStatusSucceededDeleteVaultCancellationAsync(cancellationSucceeded, message);
                cancellationSucceeded.Registration.SendTask = task;
                return new(task);
            }
            if (source.currentStatusSucceededDeleteVaultIndependent.Value is { } independentSucceeded)
            {
                var task = source.SendStatusSucceededDeleteVaultIndependentAsync(independentSucceeded, message);
                independentSucceeded.Registration.SendTask = task;
                return new(task);
            }
            if (source.currentStatusSucceededDeleteVault.Value is { } succeeded)
            {
                var task = source.SendStatusSucceededDeleteVaultAsync(succeeded, message);
                succeeded.Registration.SendTask = task;
                return new(task);
            }
            if (source.currentPrivateUpdate.Value is { } update)
            {
                var task = source.SendPrivateConnectionUpdateAsync(update, message);
                lock (source.gate) update.Registration.Sends.Add(task);
                return new(task);
            }
            if (source.currentCreateVault.Value is { } creation)
            {
                var task = source.SendCreateVaultAsync(creation, message);
                lock (source.gate) creation.Registration.Sends.Add(task);
                return new(task);
            }
            if (source.currentPurgeDeletedVault.Value is { } purge)
            {
                var task = source.SendPurgeDeletedVaultAsync(purge, message);
                lock (source.gate) purge.Registration.Sends.Add(task);
                return new(task);
            }
            if (source.currentDeleteVault.Value is { } deletion)
            {
                var task = source.SendDeleteVaultAsync(deletion, message);
                deletion.Registration.SendTask = task;
                return new(task);
            }
            var borrower = new TaskCompletionSource<Task>(TaskCreationOptions.RunContinuationsAsynchronously);
            StatusPrivateDeleteSelectedRegistration? selectedDelete = null;
            StatusPrivateDeleteIndependentRegistration? independentPrivateDelete = null;
            StatusUnknownNotificationUpdateCancellationRegistration? unknownCancellationUpdate = null;
            StatusUnknownNotificationUpdateIndependentRegistration? unknownIndependentUpdate = null;
            StatusUnknownNotificationUpdateRegistration? unknownUpdate = null;
            StatusDeniedNotificationUpdateRegistration? deniedUpdate = null;
            StatusNotificationUpdateIndependentRegistration? independentUpdate = null;
            StatusNotificationCreateIndependentRegistration? independentCreate = null;
            StatusNotificationDeleteIndependentRegistration? independentDelete = null;
            StatusRoleDeleteIndependentRegistration? independentRoleDelete = null;
            var context = source.current.Value;
            lock (source.gate)
                if (context is not null)
                {
                    source.statusPrivateDeleteSelectedInvocations.TryGetValue(context.Invocation, out selectedDelete);
                    source.statusPrivateDeleteIndependentInvocations.TryGetValue(context.Invocation, out independentPrivateDelete);
                    source.statusUnknownNotificationUpdateCancellationInvocations.TryGetValue(context.Invocation, out unknownCancellationUpdate);
                    source.statusUnknownNotificationUpdateIndependentInvocations.TryGetValue(context.Invocation, out unknownIndependentUpdate);
                    source.statusUnknownNotificationUpdateInvocations.TryGetValue(context.Invocation, out unknownUpdate);
                    source.statusDeniedNotificationUpdateInvocations.TryGetValue(context.Invocation, out deniedUpdate);
                    source.statusNotificationUpdateIndependentInvocations.TryGetValue(context.Invocation, out independentUpdate);
                    source.statusNotificationCreateIndependentInvocations.TryGetValue(context.Invocation, out independentCreate);
                    source.statusNotificationDeleteIndependentInvocations.TryGetValue(context.Invocation, out independentDelete);
                    source.statusRoleDeleteIndependentInvocations.TryGetValue(context.Invocation, out independentRoleDelete);
                }
            Task actual = deniedUpdate is not null
                ? source.SendStatusDeniedNotificationUpdateAsync(deniedUpdate, context!, message, borrower)
                : unknownCancellationUpdate is not null
                ? source.SendStatusUnknownNotificationUpdateCancellationAsync(unknownCancellationUpdate, context!, message, borrower)
                : unknownIndependentUpdate is not null
                ? source.SendStatusUnknownNotificationUpdateIndependentAsync(unknownIndependentUpdate, context!, message, borrower)
                : unknownUpdate is not null
                ? source.SendStatusUnknownNotificationUpdateAsync(unknownUpdate, context!, message, borrower)
                : independentCreate is not null
                ? source.SendStatusNotificationCreateIndependentAsync(independentCreate, context!, message, borrower)
                : independentUpdate is not null
                ? source.SendStatusNotificationUpdateIndependentAsync(independentUpdate, context!, message, borrower)
                : independentRoleDelete is not null
                ? source.SendStatusRoleDeleteIndependentAsync(independentRoleDelete, context!, message, borrower)
                : independentPrivateDelete is not null
                ? source.SendStatusPrivateDeleteIndependentAsync(independentPrivateDelete, context!, message, borrower)
                : independentDelete is not null
                ? source.SendStatusNotificationDeleteIndependentAsync(independentDelete, context!, message, borrower)
                : selectedDelete is not null
                ? source.SendStatusPrivateDeleteSelectedAsync(selectedDelete, context!, message, borrower)
                : SendAsync(message, borrower);
            borrower.TrySetResult(actual);
            return new(actual);
        }
        private async Task SendAsync(HttpMessage message, TaskCompletionSource<Task> borrower)
        {
            InvocationContext context = source.current.Value ??
                throw new InvalidOperationException("management-capture-invocation");
            Window window = context.Window;
            Invocation invocation = context.Invocation;
            bool status = context.Status, finalResource;
            string? continuation;
            SynchronousDeleteRegistration? synchronousDelete;
            PrivateApprovalRegistration? privateApproval;
            PrivateConnectionDeleteRegistration? privateDelete;
            StatusVaultCancellationRegistration? statusDeletion;
            bool purgeCancellation, recoverCancellation, updateCancellation, configurationCancellation, notificationCancellation,
                notificationUpdateCancellation,
                roleCancellation, privateCancellation, privateDeleteCancellation;
            int statusOrdinal = 0;
            lock (source.gate)
            {
                source.synchronousDeletes.TryGetValue(invocation, out synchronousDelete);
                source.privateApprovalInvocations.TryGetValue(invocation, out privateApproval);
                source.privateDeleteInvocations.TryGetValue(invocation, out privateDelete);
                source.statusVaultCancellationInvocations.TryGetValue(invocation, out statusDeletion);
                purgeCancellation = statusDeletion is not null &&
                    VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(statusDeletion.Binding.Selector);
                recoverCancellation = statusDeletion is not null &&
                    VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(statusDeletion.Binding.Selector);
                updateCancellation = statusDeletion is not null &&
                    VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(statusDeletion.Binding.Selector);
                configurationCancellation = recoverCancellation || updateCancellation;
                privateDeleteCancellation = statusDeletion is not null &&
                    VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(statusDeletion.Binding.Selector);
                privateCancellation = privateDeleteCancellation || statusDeletion is not null &&
                    VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(statusDeletion.Binding.Selector);
                roleCancellation = statusDeletion is not null &&
                    RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(statusDeletion.Binding.Selector);
                notificationCancellation = roleCancellation || statusDeletion is not null &&
                    NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(statusDeletion.Binding.Selector);
                notificationUpdateCancellation = statusDeletion is not null &&
                    (NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(statusDeletion.Binding.Selector) ||
                        NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(statusDeletion.Binding.Selector));
                if (statusDeletion is not null)
                {
                    bool admitted = status
                        ? (purgeCancellation || configurationCancellation || notificationUpdateCancellation) &&
                            ReferenceEquals(statusDeletion.NormalStatus, invocation) &&
                            statusDeletion.CancelComplete && !statusDeletion.Invalid &&
                            ++statusDeletion.StatusSends <= (notificationUpdateCancellation ? 1 : 2) &&
                            statusDeletion.StatusSends == statusDeletion.StatusWires.Count + 1
                        : ReferenceEquals(statusDeletion.Start, invocation) && ++statusDeletion.Sends == 1;
                    if (!admitted)
                    {
                        statusDeletion.Invalid = true;
                        throw new InvalidOperationException("status-vault-cancellation-dispatch");
                    }
                    if (status) statusOrdinal = statusDeletion.StatusSends;
                }
                if (privateDelete is not null)
                {
                    if (status) privateDelete.CheckSends++;
                    Require(!privateDelete.Sealed && !privateDelete.Invalid);
                    if (!status)
                    {
                        Require(++privateDelete.Sends == 1 && ReferenceEquals(privateDelete.Start, invocation) &&
                            privateDelete.Receipt.Evidence == DispatchEvidence.PossiblyDispatched);
                        privateDelete.Request = message.Request;
                    }
                }
                if (privateApproval is not null)
                {
                    if (status)
                    {
                        privateApproval.StatusSends++;
                        privateApproval.StatusInvalid = true;
                    }
                    else
                    {
                        privateApproval.Sends++;
                        if (privateApproval.Sends != 1 || !ReferenceEquals(privateApproval.Start, invocation) ||
                            !ReferenceEquals(privateApproval.Window, window) ||
                            !source.originalReceipts.TryGetValue(invocation, out var originalReceipt) ||
                            !ReferenceEquals(originalReceipt, privateApproval.Receipt) ||
                            originalReceipt.Evidence != DispatchEvidence.PossiblyDispatched)
                            privateApproval.Invalid = true;
                    }
                }
                if (synchronousDelete is not null)
                {
                    synchronousDelete.Sends++;
                    if (synchronousDelete.Sends != 1 || status ||
                        !ReferenceEquals(synchronousDelete.Window, window) ||
                        !source.originalReceipts.TryGetValue(invocation, out var originalReceipt) ||
                        !ReferenceEquals(originalReceipt, synchronousDelete.Receipt) ||
                        originalReceipt.Evidence != DispatchEvidence.PossiblyDispatched)
                        synchronousDelete.Invalid = true;
                    synchronousDelete.Request = message.Request;
                }
                Require(source.targets.ContainsKey(window) &&
                    (synchronousDelete is not null ? ReferenceEquals(synchronousDelete.Window, window) :
                        ReferenceEquals(invocation, status ? window.Status : window.Start)) &&
                    !source.finishing.Contains(invocation) &&
                    source.requestCandidates.TryGetValue(invocation, out var candidates) &&
                    candidates.Contains(message.Request));
                // Some installed adapters allocate unused messages before their
                // real request. Bind the dispatched request, not the first factory
                // result. Only the original receipt can authorize its start.
                Require(status || source.originalReceipts.TryGetValue(invocation, out var receipt) &&
                    receipt.Evidence != DispatchEvidence.NotDispatched);
                Require(!source.requestOwners.ContainsKey(invocation) ||
                    status && (configurationCancellation
                        ? statusOrdinal == 2 && statusDeletion!.StatusWires is
                            [{ Ordinal: 1, HttpStatus: 200, State: WireState.Succeeded, Complete: true }]
                        : source.finalReadEligible.Remove(invocation)));
                continuation = source.continuations.GetValueOrDefault(window);
                finalResource = configurationCancellation
                    ? status && statusOrdinal == 2 && statusDeletion!.StatusWires is
                        [{ Ordinal: 1, HttpStatus: 200, State: WireState.Succeeded, Complete: true }]
                    : status && invocation.Attempts is
                        [{ Valid: true, TransportTerminated: true, HttpStatus: 200, State: WireState.Succeeded }] &&
                        (window.Method == RequestMethod.Put || window.Method == RequestMethod.Patch);
                // The purge SDK follows a successful poll with one final GET to
                // that same private continuation. Never admit a third request.
                bool finalContinuation = status && window.Binding.Operation == ManagementMutation.PurgeDeletedVault &&
                    (purgeCancellation
                        ? statusDeletion!.StatusWires is [{ Ordinal: 1, HttpStatus: 200, State: WireState.Succeeded, Complete: true }]
                        : invocation.Attempts is
                            [{ Valid: true, TransportTerminated: true, HttpStatus: 200, State: WireState.Succeeded }]);
                Require((synchronousDelete is not null || !invocation.Terminated) && !invocation.Sending &&
                    (configurationCancellation ? !status || statusOrdinal == 1 || finalResource :
                        invocation.Attempts.Count == 0 || finalResource || finalContinuation));
                if (source.borrowers.TryGetValue(invocation, out var previous))
                {
                    Require(previous.Task.IsCompletedSuccessfully && previous.Task.Result.IsCompleted);
                    source.borrowers.Remove(invocation);
                }
                invocation.Sending = true;
                source.requestOwners[invocation] = message.Request;
                source.requestCandidates.Remove(invocation);
                source.borrowers.Add(invocation, borrower);
            }
            RequestContent? original = null, snapshot = null;
            Attempt? attempt = null;
            string? requestHash = null;
            bool nativeStatusSucceeded = false;
            bool transportSucceeded = false;
            bool privateApprovalRequest = false;
            StatusVaultCancellationWire? purgeWire = null;
            try
            {
                original = message.Request.Content;
                message.CancellationToken.ThrowIfCancellationRequested();
                Uri uri = message.Request.Uri.ToUri();
                var method = status ? RequestMethod.Get : window.Method;
                Require(Trusted(uri) && message.Request.Method == method &&
                    (status ? finalResource
                        ? uri.AbsoluteUri == Origin + window.Path + "?api-version=" + window.Binding.ApiRevision
                        : continuation is not null && uri.AbsoluteUri == continuation :
                        uri.AbsolutePath == window.Path && uri.Query == "?api-version=" + window.Binding.ApiRevision));
                Headers(message.Request.Headers);
                var headers = message.Request.Headers.Select(h => (h.Name, h.Value)).ToArray();
                Request originalRequest = message.Request;
                void CheckNotificationRequest()
                {
                    if (!notificationCancellation) return;
                    Require(!status && ReferenceEquals(message.Request, originalRequest) &&
                        message.Request.Uri.ToUri().AbsoluteUri == uri.AbsoluteUri &&
                        message.Request.Method == RequestMethod.Delete && message.Request.Content is null &&
                        headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
                    if (roleCancellation)
                    {
                        Require(headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                            message.Request.Headers.TryGetValue("Authorization", out var auth) &&
                            auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7);
                        if (message.Request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
                    }
                }
                void CheckRecoveryRequest()
                {
                    if (!configurationCancellation && !privateCancellation && !notificationUpdateCancellation) return;
                    Require(ReferenceEquals(message.Request, originalRequest) &&
                        message.Request.Uri.ToUri().AbsoluteUri == uri.AbsoluteUri &&
                        message.Request.Method == method && ReferenceEquals(message.Request.Content, snapshot) &&
                        headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))) &&
                        message.Request.Headers.TryGetValue("Authorization", out var authorization) &&
                        authorization.StartsWith("Bearer ", StringComparison.Ordinal) && authorization.Length > 7 &&
                        !message.Request.Headers.Contains("Content-Encoding") &&
                        !message.Request.Headers.Contains("Transfer-Encoding") &&
                        !message.Request.Headers.Contains("Content-Range"));
                    if (message.Request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
                    if (privateDeleteCancellation)
                    {
                        Require(!status && method == RequestMethod.Delete && original is null &&
                            message.Request.Content is null && statusDeletion!.Receipt.Evidence == DispatchEvidence.PossiblyDispatched);
                        OriginalVaultRequest(message, window.Path, RequestMethod.Delete);
                    }
                    else if (status && notificationUpdateCancellation)
                    {
                        Require(message.Request.Content is null &&
                            headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length);
                        if (message.Request.Headers.TryGetValue("Content-Length", out var length)) Require(length == "0");
                    }
                    else if (status)
                        OriginalVaultRequest(message, window.Path, RequestMethod.Get,
                            finalResource ? Origin + window.Path + "?api-version=" + window.Binding.ApiRevision : continuation);
                    else
                        Require(message.Request.Headers.TryGetValue("Content-Type", out var type) &&
                            type.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase));
                    message.CancellationToken.ThrowIfCancellationRequested();
                    (status ? statusDeletion!.StatusToken : statusDeletion!.StartToken).ThrowIfCancellationRequested();
                }
                void CheckPrivateDeleteRequest()
                {
                    if (privateDelete is null) return;
                    OriginalVaultRequest(message, window.Path, method, status ? continuation : null);
                    Require(ReferenceEquals(message.Request, originalRequest) &&
                        headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
                    if (!status) privateDelete.Token.ThrowIfCancellationRequested();
                }
                CheckPrivateDeleteRequest();
                if (privateDelete is not null && !status)
                {
                    privateDelete.RequestUri = uri.OriginalString;
                    privateDelete.RequestHeaders = headers;
                }
                string[] requestLengths = headers
                    .Where(h => h.Name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                    .Select(h => h.Value).ToArray();
                bool synchronousRequestFraming = (synchronousDelete is not null || notificationCancellation) &&
                    !headers.Any(h => h.Name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) ||
                        h.Name.Equals("Content-Encoding", StringComparison.OrdinalIgnoreCase) ||
                        h.Name.Equals("Content-Range", StringComparison.OrdinalIgnoreCase)) &&
                    (requestLengths.Length == 0 || requestLengths.Length == 1 && requestLengths[0] == "0");
                bool body = !status && (method == RequestMethod.Put || method == RequestMethod.Patch);
                Require(body == (original is not null));
                if (privateDeleteCancellation)
                    requestHash = Convert.ToHexString(SHA256.HashData(ReadOnlySpan<byte>.Empty));
                if (original is not null)
                {
                    long declaredRequestLength = 0;
                    if (configurationCancellation || privateCancellation || notificationUpdateCancellation)
                        Require(original.TryComputeLength(out declaredRequestLength) &&
                            declaredRequestLength > 0 && declaredRequestLength <= source.maximumBytes);
                    byte[] staging = new byte[source.maximumBytes];
                    source.OwnBytes(invocation, staging);
                    using var stream = new MemoryStream(staging, 0, staging.Length, true, true);
                    await original.WriteToAsync(stream, message.CancellationToken).ConfigureAwait(false);
                    byte[] dispatch = staging.AsSpan(0, checked((int)stream.Position)).ToArray();
                    source.OwnBytes(invocation, dispatch);
                    if (configurationCancellation || privateCancellation || notificationUpdateCancellation)
                    {
                        Require(ReferenceEquals(message.Request, originalRequest) &&
                            ReferenceEquals(message.Request.Content, original) &&
                            dispatch.Length == declaredRequestLength);
                        if (notificationUpdateCancellation)
                        {
                            using var document = JsonDocument.Parse(dispatch);
                            int rows = 512;
                            JsonRows(document.RootElement, ref rows);
                            ValidateNotificationUpdate(statusDeletion!, document.RootElement, request: true, status: false);
                        }
                        else if (privateCancellation) Require(PrivateApprovalRequest(dispatch, headers));
                        else ValidateCreateVaultRequest(dispatch, updateCancellation
                                ? statusDeletion!.UpdateConfiguration! : statusDeletion!.RecoveryConfiguration!,
                                recover: recoverCancellation);
                        if (message.Request.Headers.TryGetValue("Content-Length", out var length))
                            Require(length == declaredRequestLength.ToString(CultureInfo.InvariantCulture));
                        source.OwnSnapshot(invocation, original);
                    }
                    requestHash = Convert.ToHexString(SHA256.HashData(dispatch));
                    using (var json = JsonDocument.Parse(dispatch, new JsonDocumentOptions { MaxDepth = 16 }))
                    {
                        int rows = 512;
                        JsonRows(json.RootElement, ref rows);
                    }
                    if (privateApproval is not null && !status)
                        privateApprovalRequest = PrivateApprovalRequest(dispatch, headers);
                    snapshot = RequestContent.Create(dispatch);
                    source.OwnSnapshot(invocation, snapshot);
                    message.Request.Content = snapshot;
                }
                message.CancellationToken.ThrowIfCancellationRequested();
                Require(message.Request.Uri.ToUri().AbsoluteUri == uri.AbsoluteUri && message.Request.Method == method &&
                    ReferenceEquals(message.Request.Content, snapshot) &&
                    headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
                CheckRecoveryRequest();
                CheckNotificationRequest();
                if (notificationCancellation)
                    Require(synchronousRequestFraming && statusDeletion!.Receipt.Evidence == DispatchEvidence.PossiblyDispatched);
                Guid dispatchId = Guid.NewGuid();
                attempt = new() { Dispatch = dispatchId, RequestSha256 = requestHash };
                if (synchronousDelete is not null)
                    lock (source.gate) synchronousDelete.Dispatch = dispatchId;
                lock (source.gate) invocation.Attempts.Add(attempt);
                message.BufferResponse = false;
                // Credential acquisition and immutable request snapshot checks
                // have completed. The host journal hook never runs under gate.
                if (privateApproval is not null && !status && privateApproval.Sends == 1)
                {
                    privateApproval.BeforeSend?.Invoke();
                    // Journal callbacks cannot change the authenticated
                    // request and still reach the host transport.
                    Require(message.Request.Uri.ToUri().AbsoluteUri == uri.AbsoluteUri &&
                        message.Request.Method == method && ReferenceEquals(message.Request.Content, snapshot) &&
                        headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
                }
                if (privateDelete is not null && !status)
                {
                    privateDelete.BeforeSend?.Invoke();
                    CheckPrivateDeleteRequest();
                }
                if (privateCancellation)
                {
                    statusDeletion!.PrivateBeforeSend?.Invoke();
                    CheckRecoveryRequest();
                }
                try { await source.backend.ProcessAsync(message).ConfigureAwait(false); }
                finally
                {
                    if (privateDelete is not null && message.HasResponse)
                        privateDelete.Storage.Own(message.Response);
                    if ((purgeCancellation || configurationCancellation || notificationCancellation ||
                        privateCancellation || notificationUpdateCancellation) && message.HasResponse)
                        statusDeletion!.ParserStorage.Own(message.Response);
                }
                CheckPrivateDeleteRequest();
                CheckRecoveryRequest();
                CheckNotificationRequest();
                OwnedArmResponse.Body? purgeBody = null;
                if (purgeCancellation || configurationCancellation || privateCancellation || notificationUpdateCancellation)
                {
                    Require(ReferenceEquals(message.Request, originalRequest) &&
                        message.Request.Uri.ToUri().AbsoluteUri == uri.AbsoluteUri &&
                        message.Request.Method == method && ReferenceEquals(message.Request.Content, snapshot) &&
                        headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
                    var capturedResponse = message.Response;
                    var capturedStream = capturedResponse.ContentStream;
                    purgeBody = await OwnedArmResponse.CaptureAsync(message, source.maximumBytes,
                        statusDeletion!.ParserStorage, allowContinuation: !privateCancellation).ConfigureAwait(false);
                    if (privateCancellation || notificationUpdateCancellation)
                        Require(ReferenceEquals(capturedResponse.ContentStream, capturedStream));
                    Require(ReferenceEquals(message.Request, originalRequest) &&
                        message.Request.Uri.ToUri().AbsoluteUri == uri.AbsoluteUri &&
                        message.Request.Method == method && ReferenceEquals(message.Request.Content, snapshot) &&
                        headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
                    CheckRecoveryRequest();
                }
                var originalResponse = message.Response;
                int responseStatus = message.Response.Status;
                string reason = privateDelete is null && !notificationCancellation ? "" : originalResponse.ReasonPhrase;
                string clientRequestId = privateDelete is null && !notificationCancellation ? "" : originalResponse.ClientRequestId;
                var responseHeaders = message.Response.Headers.Take(33).ToArray();
                attempt.HttpStatus = responseStatus;
                attempt.ResponseObserved = true;
                Headers(responseHeaders);
                Require(attempt.HttpStatus is not (>= 300 and < 400));
                string? next = Continuation(window, message);
                Require(!status || next is null || next == continuation);
                if (message.Response.Headers.TryGetValues("Content-Length", out var lengths))
                {
                    string[] values = lengths.Take(3).ToArray();
                    Require(values.Length == 1 && long.TryParse(values[0], NumberStyles.None,
                        CultureInfo.InvariantCulture, out long length) && length >= 0 && length <= source.maximumBytes);
                }
                byte[] storage = new byte[source.maximumBytes], chunk = new byte[1024];
                source.OwnBytes(invocation, storage);
                source.OwnBytes(invocation, chunk);
                int count = 0;
                Stream? input = purgeBody is null ? message.Response.ContentStream : null;
                if (notificationCancellation && input is not null) statusDeletion!.ParserStorage.Own(input);
                if (purgeBody is not null)
                {
                    purgeBody.Bytes.CopyTo(storage);
                    count = purgeBody.Bytes.Length;
                }
                else if (input is not null)
                {
                    int read;
                    while ((read = await input.ReadAsync(chunk, message.CancellationToken).ConfigureAwait(false)) != 0)
                    {
                        Require(count + read <= storage.Length);
                        chunk.AsSpan(0, read).CopyTo(storage.AsSpan(count));
                        count += read;
                    }
                    if (privateDelete is null && !notificationCancellation) input.Dispose();
                    else if (privateDelete is not null) privateDelete.Storage.Own(input);
                }
                var buffer = new MemoryStream(storage, 0, count, false, true);
                source.OwnSnapshot(invocation, buffer);
                if (purgeBody is not null)
                    statusDeletion!.Parsers.Add(OwnedArmResponse.ParserCustody.Install(message, purgeBody.Response,
                        // The Pending start retains its continuation, not a parsed
                        // resource. The non-generic final fetch likewise returns
                        // a Response without parsing its body. Require the adapter's
                        // actual EOF and exact rebuffer on all three responses,
                        // plus the native parser's byte read on the status poll
                        // and R/U's generic final-resource fetch.
                        purgeBody.Bytes, statusDeletion.ParserStorage, requireRebuffer: true,
                        requireDownstreamRead: privateCancellation || status &&
                            (notificationUpdateCancellation || configurationCancellation || statusOrdinal == 1)));
                else if (notificationCancellation)
                {
                    CheckNotificationRequest();
                    Require(ReferenceEquals(message.Response, originalResponse) &&
                        ReferenceEquals(originalResponse.ContentStream, input) && originalResponse.Status == responseStatus &&
                        responseHeaders.SequenceEqual(originalResponse.Headers) &&
                        originalResponse.ReasonPhrase == reason && originalResponse.ClientRequestId == clientRequestId &&
                        reason.Length <= 256 && !reason.Any(char.IsControl) &&
                        clientRequestId.Length <= 1024 && !clientRequestId.Any(char.IsControl) &&
                        EmptyDeleteResponse(responseStatus, count, responseHeaders, allow200: !roleCancellation));
                    var owned = new OwnedArmResponse(responseStatus, reason, clientRequestId, responseHeaders, buffer);
                    statusDeletion!.NotificationCustody = new(message, originalResponse, input, owned,
                        statusDeletion.ParserStorage);
                }
                else if (privateDelete is null) message.Response.ContentStream = buffer;
                else
                {
                    CheckPrivateDeleteRequest();
                    Require(ReferenceEquals(message.Response, originalResponse) && originalResponse.Status == responseStatus &&
                        responseHeaders.SequenceEqual(originalResponse.Headers) &&
                        originalResponse.ReasonPhrase == reason && originalResponse.ClientRequestId == clientRequestId &&
                        reason.Length <= 256 && !reason.Any(char.IsControl) &&
                        clientRequestId.Length <= 1024 && !clientRequestId.Any(char.IsControl));
                    if (originalResponse.Headers.TryGetValue("Content-Length", out var declared))
                        Require(long.TryParse(declared, NumberStyles.None, CultureInfo.InvariantCulture, out var length) &&
                            length == count);
                    var owned = new OwnedArmResponse(responseStatus, reason, clientRequestId, responseHeaders, buffer);
                    message.Response = owned;
                    // Empty 200/204 responses remain empty and retain their exact
                    // framing. ParserCustody deliberately requires nonempty bytes.
                    if (count != 0)
                        privateDelete.Parsers.Add(OwnedArmResponse.ParserCustody.Install(message, owned,
                            storage.AsMemory(0, count), privateDelete.Storage, requireRebuffer: true));
                    if (!status)
                    {
                        privateDelete.DeniedResponse = responseStatus == 403 && count != 0 &&
                            PrivateApprovalHeaders(responseHeaders.Select(h => (h.Name, h.Value)).ToArray(), count) &&
                            PrivateUpdateDenied(storage.AsMemory(0, count));
                        privateDelete.Facts = PrivateConnectionResponse(privateDelete.Scope,
                            PrivateConnectionState.Disconnected, storage.AsMemory(0, count),
                            responseHeaders.Select(h => (h.Name, h.Value)).ToArray(), responseStatus);
                    }
                }
                string responseHash = Convert.ToHexString(SHA256.HashData(storage.AsSpan(0, count)));
                attempt.ResponseSha256 = responseHash;
                if (privateDelete is not null)
                    privateDelete.Responses.Add(new(responseStatus,
                        responseHeaders.Select(h => (h.Name, h.Value)).ToArray(), responseHash,
                        responseHeaders.FirstOrDefault(h => h.Name.Equals("x-ms-request-id",
                            StringComparison.OrdinalIgnoreCase)).Value));
                if (privateApproval is not null && !status && privateApprovalRequest)
                {
                    var facts = PrivateApprovalResponse(privateApproval, storage.AsMemory(0, count),
                        responseHeaders.Select(h => (h.Name, h.Value)).ToArray(), responseStatus);
                    lock (source.gate) privateApproval.ResponseFacts = facts;
                }
                if (privateCancellation)
                {
                    var strict = PrivateConnectionResponse((PrivateConnectionScope)statusDeletion!.ActualOriginalScope,
                        privateDeleteCancellation ? PrivateConnectionState.Disconnected : PrivateConnectionState.Approved,
                        storage.AsMemory(0, count),
                        responseHeaders.Select(h => (h.Name, h.Value)).ToArray(), responseStatus);
                    if (strict is not null)
                    {
                        try
                        {
                            using var json = JsonDocument.Parse(storage.AsMemory(0, count));
                            var model = ModelReaderWriter.Read<KeyVaultPrivateEndpointConnectionData>(
                                new BinaryData(storage.AsMemory(0, count)));
                            Require(model is not null);
                            var facts = ManagementOperationResourceCollector.ValidateStatusPrivateConnectionResource(
                                json.RootElement, model, (PrivateConnectionScope)statusDeletion.ActualOriginalScope,
                                window.Binding.Location, allowLocation: false);
                            if (privateDeleteCancellation) statusDeletion.PrivateDeleteFacts = facts;
                            else
                                statusDeletion.PrivateCandidate = new(statusDeletion.Binding, dispatchId, facts,
                                    requestHash!, responseHash, purgeBody!.NativeRequestId);
                        }
                        catch (Exception) when (privateDeleteCancellation)
                        {
                            // Side decoding supplies eligibility, not the actual
                            // native operation outcome or parser consumption.
                            statusDeletion.PrivateDeleteFacts = null;
                        }
                    }
                }
                // Freeze eligibility from the actual original transport response.
                // These restrictions do not change the adapter's accepted statuses.
                if (synchronousRequestFraming && EmptyDeleteResponse(responseStatus, count, responseHeaders,
                    allow200: notificationCancellation && !roleCancellation ||
                        synchronousDelete?.Profile == SynchronousDeleteProfile.Notification))
                {
                    lock (source.gate)
                    {
                        if (synchronousDelete is not null)
                            synchronousDelete.Candidate = new(synchronousDelete.Binding, dispatchId,
                                responseStatus, count, responseHash);
                        if (notificationCancellation && !roleCancellation)
                            statusDeletion!.NotificationCandidate = new(statusDeletion.Binding, dispatchId,
                                responseStatus, responseHash);
                        if (roleCancellation)
                            statusDeletion!.RoleCandidate = new(statusDeletion.Binding, dispatchId, responseStatus, responseHash);
                    }
                }
                string? originalNativeState = null;
                bool statusDeleteBodyQualified = false;
                WireState state = status ? WireState.Unknown :
                    attempt.HttpStatus == 202 ? WireState.Pending : WireState.Unavailable;
                if (count != 0)
                {
                    using var json = JsonDocument.Parse(storage.AsMemory(0, count), new JsonDocumentOptions { MaxDepth = 16 });
                    int rows = 512;
                    JsonRows(json.RootElement, ref rows);
                    var root = json.RootElement;
                    Require(root.ValueKind == JsonValueKind.Object && !root.TryGetProperty("nextLink", out _));
                    if (root.TryGetProperty("id", out var id))
                        Require(id.ValueKind == JsonValueKind.String &&
                            (id.GetString() == (window.Binding.Operation == ManagementMutation.PurgeDeletedVault
                                ? window.Path[..^6] : window.Path) ||
                                status && id.GetString() == uri.AbsolutePath));
                    if (root.TryGetProperty("status", out var nativeState))
                    {
                        Require(nativeState.ValueKind == JsonValueKind.String);
                        originalNativeState = nativeState.GetString();
                        state = State(originalNativeState);
                    }
                    else if (root.TryGetProperty("properties", out var properties) &&
                        properties.ValueKind == JsonValueKind.Object &&
                        properties.TryGetProperty("provisioningState", out var provisioning))
                    {
                        Require(provisioning.ValueKind == JsonValueKind.String);
                        originalNativeState = provisioning.GetString();
                        state = State(originalNativeState);
                    }
                    if (statusDeletion is not null)
                        statusDeleteBodyQualified = originalNativeState == (status ? "Succeeded" : "InProgress") &&
                            !root.TryGetProperty("error", out _) && !root.TryGetProperty("errors", out _) &&
                            !root.TryGetProperty("partial", out _) &&
                            (!root.TryGetProperty("properties", out var deletionProperties) ||
                                deletionProperties.ValueKind == JsonValueKind.Object &&
                                !deletionProperties.TryGetProperty("error", out _) &&
                                !deletionProperties.TryGetProperty("errors", out _) &&
                                (!deletionProperties.TryGetProperty("provisioningState", out var deletionState) ||
                                    deletionState.ValueKind == JsonValueKind.String &&
                                    deletionState.GetString() == (status ? "Succeeded" : "InProgress")));
                    if (configurationCancellation)
                    {
                        Require(!root.TryGetProperty("error", out _) && !root.TryGetProperty("errors", out _) &&
                            !root.TryGetProperty("partial", out _) && !root.TryGetProperty("value", out _));
                        if (!status || finalResource)
                        {
                            Require(status ? originalNativeState == "Succeeded" && next is null :
                                originalNativeState is "Creating" or "Updating" && next is not null);
                            var recoveryProperties = root.GetProperty("properties");
                            Require(!new[] { "error", "errors", "partial", "status" }
                                .Any(n => recoveryProperties.TryGetProperty(n, out _)));
                            _ = VaultFixtureProvisioner.ParseOwnedVaultResource(window.Path, window.Binding.Selector.Nonce,
                                root, CreateVaultConfiguration(updateCancellation
                                    ? statusDeletion!.UpdateConfiguration! : statusDeletion!.RecoveryConfiguration!),
                                originalNativeState!, recover: recoverCancellation);
                            Require(!root.TryGetProperty("status", out _));
                        }
                        else
                            Require(OnlyApprovalFields(root, "id", "status") &&
                                root.GetProperty("status").GetString() == "Succeeded" && next is null &&
                                (!root.TryGetProperty("id", out var pollId) || pollId.GetString() == uri.AbsolutePath));
                        statusDeleteBodyQualified = true;
                    }
                    if (notificationUpdateCancellation)
                    {
                        ValidateNotificationUpdate(statusDeletion!, root, request: false, status);
                        var native = ModelReaderWriter.Read<EventGridSubscriptionData>(
                            new BinaryData(storage.AsMemory(0, count)));
                        Require(native is not null && native.Id?.ToString() == window.Path &&
                            native.Name == ((NotificationScope)statusDeletion!.ActualOriginalScope).SubscriptionName &&
                            native.Topic == ((NotificationScope)statusDeletion.ActualOriginalScope).Vault.ExportResourceId() &&
                            native.ProvisioningState?.ToString() == (status ? "Succeeded" : "Updating") &&
                            (statusDeletion.NotificationAbsentCreate is not null ? native.Labels.Count == 0 :
                                native.Labels.SequenceEqual(["secretkit-fixture-" + window.Binding.Selector.Nonce.ToString("N")])) &&
                            native.Filter is not null &&
                            native.Filter.IncludedEventTypes.SequenceEqual(["Microsoft.KeyVault.SecretNewVersionCreated"]) &&
                            native.Destination is WebHookEventSubscriptionDestination webhook &&
                            webhook.Endpoint?.OriginalString == statusDeletion.NotificationUpdateConfiguration!.Endpoint.Reveal() &&
                            webhook.DeliveryAttributeMappings.Count == 0);
                        Require(!responseHeaders.Any(h => h.Name.Equals("Retry-After", StringComparison.OrdinalIgnoreCase)) &&
                            responseHeaders.Count(h => new[] { "Location", "Azure-AsyncOperation", "Operation-Location" }
                                .Contains(h.Name, StringComparer.OrdinalIgnoreCase)) == (status ? 0 : 1) &&
                            (status ? responseStatus == 200 && next is null : responseStatus == 201 &&
                                next == Origin + window.Path + "?api-version=" + window.Binding.ApiRevision));
                        if (!status && NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(window.Binding.Selector))
                            Require(responseHeaders.Single(h => h.Name.Equals("Location",
                                StringComparison.OrdinalIgnoreCase)).Value ==
                                Origin + window.Path + "?api-version=" + window.Binding.ApiRevision);
                        statusDeleteBodyQualified = true;
                        if (!status)
                        {
                            if (NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(window.Binding.Selector))
                                statusDeletion.NotificationCreateCandidate = new(window.Binding, dispatchId, responseStatus,
                                    count, requestHash!, responseHash, purgeBody!.NativeRequestId,
                                    statusDeletion.NotificationAbsentCreate?.NamespaceEpoch ?? Guid.Empty,
                                    statusDeletion.NotificationAbsentCreate?.InvocationDispatch ?? Guid.Empty,
                                    statusDeletion.NotificationAbsentCreate is null ? null :
                                        root.GetProperty("properties").TryGetProperty("labels", out _) ? "empty-array" : "absent");
                            else
                                statusDeletion.NotificationUpdateCandidate = new(window.Binding, dispatchId, responseStatus,
                                    count, requestHash!, responseHash, purgeBody!.NativeRequestId);
                        }
                    }
                }
                // An async acceptance remains pending even when a resource body
                // or lazy wrapper already says Succeeded. A later wire read is distinct.
                if (!status && attempt.HttpStatus == 202) state = WireState.Pending;
                if (attempt.HttpStatus is 401 or 403) state = WireState.Denied;
                else if (attempt.HttpStatus >= 400) state = WireState.Unknown;
                attempt.State = state;
                attempt.Valid = true;
                nativeStatusSucceeded = status && attempt.HttpStatus == 200 && state == WireState.Succeeded;
                if (status && invocation.Attempts.Count == 1 && attempt.HttpStatus == 200 &&
                    state == WireState.Succeeded && (window.Method == RequestMethod.Put ||
                        window.Method == RequestMethod.Patch || window.Binding.Operation == ManagementMutation.PurgeDeletedVault))
                    lock (source.gate) source.finalReadEligible.Add(invocation);
                attempt.HasProviderContinuation = next is not null;
                if (!status && attempt.HttpStatus is >= 200 and < 300)
                {
                    window.Continuation = next;
                    lock (source.gate) source.continuations[window] = next;
                    if (next is not null && state == WireState.Pending)
                    {
                        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(next);
                        try
                        {
                            lock (source.gate)
                                source.targets[window] = new(window.Binding, configurationCancellation ? dispatchId : attempt.Dispatch,
                                    window.Binding.Resource is NotificationScope ? StatusTargetKind.SelectedResource : StatusTargetKind.Operation,
                                    new Uri(next), Convert.ToHexString(SHA256.HashData(bytes)),
                                    configurationCancellation ? responseHash : attempt.ResponseSha256);
                        }
                        finally { CryptographicOperations.ZeroMemory(bytes); }
                    }
                }
                if (statusDeletion is not null)
                {
                    string[] declaredLengths = responseHeaders
                        .Where(h => h.Name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                        .Select(h => h.Value).ToArray();
                    bool complete = (declaredLengths.Length == 0 || declaredLengths.Length == 1 &&
                        long.TryParse(declaredLengths[0], NumberStyles.None, CultureInfo.InvariantCulture,
                            out var declaredLength) && declaredLength == count) &&
                        !responseHeaders.Any(h => new[] { "Content-Encoding", "Content-Range", "Transfer-Encoding" }
                            .Contains(h.Name, StringComparer.OrdinalIgnoreCase));
                    lock (source.gate)
                    {
                        if (!status)
                        {
                            statusDeletion.WireQualified = privateCancellation
                                ? (privateDeleteCancellation ? statusDeletion.PrivateDeleteFacts is not null :
                                    statusDeletion.PrivateCandidate is not null) && next is null &&
                                    responseStatus == 200 && state == WireState.Succeeded
                                : notificationCancellation
                                ? synchronousRequestFraming &&
                                    (roleCancellation ? statusDeletion.RoleCandidate is not null :
                                        statusDeletion.NotificationCandidate is not null) &&
                                    next is null && state == WireState.Unavailable
                                : responseStatus == (configurationCancellation || notificationUpdateCancellation ? 201 :
                                    purgeCancellation ? 202 : 200) &&
                                count != 0 && complete && statusDeleteBodyQualified && next is not null &&
                                source.targets.TryGetValue(window, out var target) && target is not null &&
                                target.StartDispatch == dispatchId && target.StartResponseSha256 == responseHash;
                            statusDeletion.Target = statusDeletion.WireQualified && !notificationCancellation && !privateCancellation
                                ? source.targets[window] : null;
                        }
                        if (purgeBody is not null)
                        {
                            bool qualified = privateCancellation ? statusDeletion.WireQualified :
                                complete && statusDeleteBodyQualified &&
                                (status ? responseStatus == 200 && state == WireState.Succeeded &&
                                    uri.AbsoluteUri == (configurationCancellation && finalResource
                                        ? Origin + window.Path + "?api-version=" + window.Binding.ApiRevision
                                        : statusDeletion.Target?.TargetUri.AbsoluteUri)
                                    : statusDeletion.WireQualified);
                            purgeWire = new(statusOrdinal, originalRequest, uri.AbsoluteUri, dispatchId,
                                responseStatus, state, responseHash, purgeBody.NativeRequestId, qualified, requestHash,
                                configurationCancellation || privateDeleteCancellation ? Array.AsReadOnly(headers.ToArray()) : null);
                            statusDeletion.Invalid |= !qualified;
                        }
                    }
                }
                CheckRecoveryRequest();
                CheckNotificationRequest();
                transportSucceeded = true;
            }
            catch (OperationCanceledException)
            {
                lock (source.gate)
                {
                    if (synchronousDelete is not null) synchronousDelete.Invalid = true;
                    if (statusDeletion is not null) statusDeletion.Invalid = true;
                    if (privateDelete is not null) privateDelete.Invalid = true;
                    if (privateApproval is not null)
                    {
                        if (status) privateApproval.StatusInvalid = true;
                        else privateApproval.Invalid = true;
                    }
                }
                throw new OperationCanceledException(message.CancellationToken);
            }
            catch (Exception)
            {
                lock (source.gate)
                {
                    if (synchronousDelete is not null) synchronousDelete.Invalid = true;
                    if (statusDeletion is not null) statusDeletion.Invalid = true;
                    if (privateDelete is not null) privateDelete.Invalid = true;
                    if (privateApproval is not null)
                    {
                        if (status) privateApproval.StatusInvalid = true;
                        else privateApproval.Invalid = true;
                    }
                }
                if (attempt is { ResponseObserved: true }) attempt.State = WireState.Unknown;
                throw new IOException("management-capture-transport");
            }
            finally
            {
                message.Request.Content = original;
                lock (source.gate)
                {
                    if (synchronousDelete is not null)
                        synchronousDelete.TransportSucceeded = transportSucceeded;
                    if (statusDeletion is not null)
                    {
                        if (!status) statusDeletion.TransportSucceeded = transportSucceeded;
                        if (purgeWire is not null && transportSucceeded)
                        {
                            if (status) statusDeletion.StatusWires.Add(purgeWire);
                            else statusDeletion.StartWire = purgeWire;
                        }
                    }
                    if (privateDelete is not null && !status)
                        privateDelete.TransportSucceeded = transportSucceeded;
                    if (privateApproval is not null && !status)
                        privateApproval.TransportSucceeded = transportSucceeded;
                    if (attempt is not null) attempt.TransportTerminated = true;
                    if (nativeStatusSucceeded)
                    {
                        int reads = source.nativeStatusReads.GetValueOrDefault(invocation);
                        if (reads == 0 && !finalResource || reads == 1 && finalResource)
                            source.nativeStatusReads[invocation] = reads + 1;
                    }
                    invocation.Sending = false;
                }
                // Bytes and RequestContent snapshots belong to the invocation,
                // not this send. Finish clears them only after its SDK Task ends.
            }
        }
        public override string ToString() => "[ManagementOperationNativeTransport]";
    }

    public override string ToString() => "[ManagementOperationNativeSource]";

    private static bool EmptyDeleteResponse(int status, int count, Azure.Core.HttpHeader[] headers, bool allow200)
    {
        if (!(status == 204 || allow200 && status == 200) || count != 0 ||
            headers.Any(h => new[] { "Location", "Azure-AsyncOperation", "Operation-Location",
                "Retry-After", "Content-Encoding", "Content-Range", "Transfer-Encoding" }
                .Contains(h.Name, StringComparer.OrdinalIgnoreCase))) return false;
        string[] lengths = headers.Where(h => h.Name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
            .Select(h => h.Value).ToArray();
        return lengths.Length == 0 || lengths.Length == 1 &&
            long.TryParse(lengths[0], NumberStyles.None, CultureInfo.InvariantCulture, out long length) && length == 0;
    }
}
