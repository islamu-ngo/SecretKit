using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager;
using Azure.ResourceManager.Resources;
using SecretKit.Core;
using Authority = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector.Authority;
using Binding = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.PrivateEndpointResourceCollector.Binding;
using Limits = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector.Limits;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Original Generic ARM creation/deletion evidence only. The admission callback's dispatch
// is not a journal receipt, fixture ownership, or private-operation qualification.
internal sealed class PrivateEndpointNativeCapture : IAsyncDisposable
{
    private const string Origin = "https://management.azure.com";
    private const string Revision = PrivateEndpointResourceCollector.Revision;

    internal sealed class Window
    {
        private Window(Binding binding) => Binding = binding;
        [JsonIgnore] internal Binding Binding { get; }
        internal static Window Create(Binding binding) => new(binding);
        public override string ToString() => "[PrivateEndpointNativeWindow]";
    }

    internal sealed class CreationProof
    {
        private CreationProof(Binding binding, Guid dispatch)
        {
            Binding = binding;
            Dispatch = dispatch;
        }
        [JsonIgnore] internal Binding Binding { get; }
        [JsonIgnore] internal Guid Dispatch { get; }
        internal static CreationProof Create(Binding binding, Guid dispatch) => new(binding, dispatch);
        public override string ToString() => "[PrivateEndpointCreationProof]";
    }

    internal sealed class DeleteWindow
    {
        private DeleteWindow(Binding binding) => Binding = binding;
        [JsonIgnore] internal Binding Binding { get; }
        internal static DeleteWindow Create(Binding binding) => new(binding);
        public override string ToString() => "[PrivateEndpointNativeDeleteWindow]";
    }

    internal sealed class DeletionProof
    {
        private DeletionProof(Binding binding, Guid dispatch)
        {
            Binding = binding;
            Dispatch = dispatch;
        }
        [JsonIgnore] internal Binding Binding { get; }
        [JsonIgnore] internal Guid Dispatch { get; }
        internal static DeletionProof Create(Binding binding, Guid dispatch) => new(binding, dispatch);
        public override string ToString() => "[PrivateEndpointDeletionProof]";
    }

    private sealed class Invocation(CancellationToken caller)
    {
        internal readonly CancellationToken Caller = caller;
        internal readonly TaskCompletionSource Drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly List<TaskCompletionSource<Task>> Borrowers = [];
        internal readonly List<byte[]> Buffers = [];
        internal readonly List<IDisposable> Snapshots = [];
        internal readonly HashSet<Request> Requests = new(ReferenceEqualityComparer.Instance);
        internal CancellationTokenSource? Deadline, Linked;
        internal Task? ActualTask;
        internal bool Finishing, Sending;
        internal int Factories;
        internal byte[]? ResourceBody;
        internal int ResourceLength;
    }

    private class Registration(Binding binding)
    {
        internal readonly Binding Binding = binding;
        internal readonly CancellationTokenSource Stop = new();
        internal Invocation? Start, Check;
        internal Budget? Budget;
        internal ArmOperation<GenericResource>? Operation;
        internal Task<ArmOperation<GenericResource>>? StartTask;
        internal Task<Response>? StatusTask;
        internal byte[]? InitialBody;
        internal int InitialLength;
        internal Stream? InitialStream;
        internal CreationProof? Proof;
        internal TaskCompletionSource? Sealed;
        internal Guid Dispatch;
        internal string? Target;
        internal bool Closed, Invalid, Accepted, InitialSucceeded, PollSucceeded, FinalSucceeded;
        internal int Puts, Polls, Reads;
    }

    private sealed class DeleteRegistration(Binding binding) : Registration(binding)
    {
        internal ArmOperation? DeleteOperation;
        internal Task<ArmOperation>? DeleteStartTask;
        internal DeletionProof? DeleteProof;
        internal int Deletes;
    }

    private sealed record Context(Registration Registration, Invocation Invocation, bool Status);
    private readonly Authority authority;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly object gate = new();
    private readonly Dictionary<Window, Registration> windows = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<DeleteWindow, DeleteRegistration> deleteWindows = new(ReferenceEqualityComparer.Instance);
    private readonly HashSet<Guid> nonces = [], leases = [];
    private readonly AsyncLocal<Context?> current = new();
    private bool disposed;
    private TaskCompletionSource? disposal;

    internal PrivateEndpointNativeCapture(Authority authority, Limits limits, TimeProvider time)
    {
        if (authority is null || authority.Credential is null || authority.Transport is null ||
            string.IsNullOrWhiteSpace(authority.Label) || authority.Label.Length > 128 ||
            authority.Label.Any(char.IsControl) || limits is null || time is null ||
            limits.MaximumResponseBytes is < 1024 or > 1024 * 1024 ||
            limits.MaximumRowBytes < 256 || limits.MaximumRowBytes > limits.MaximumResponseBytes ||
            limits.MaximumNodes is < 8 or > 65536 || limits.MaximumRows is < 1 or > 4096 ||
            limits.MaximumDepth is < 2 or > 32 ||
            limits.Timeout <= TimeSpan.Zero || limits.Timeout > TimeSpan.FromMinutes(2))
            throw new ArgumentException("private-endpoint-native-input");
        this.authority = authority;
        this.limits = limits;
        this.time = time;
    }

    internal Window Arm(Binding binding)
    {
        try { PrivateEndpointResourceCollector.ValidateBinding(binding); }
        catch (Exception) { throw new ArgumentException("private-endpoint-native-binding"); }
        lock (gate)
        {
            Require(!disposed && windows.Count < 32 && !nonces.Contains(binding.Selector.Nonce) &&
                !leases.Contains(binding.LeaseId));
            var window = Window.Create(binding);
            windows.Add(window, new(binding));
            nonces.Add(binding.Selector.Nonce);
            leases.Add(binding.LeaseId);
            return window;
        }
    }

    internal DeleteWindow ArmDelete(Binding binding)
    {
        try { PrivateEndpointResourceCollector.ValidateBinding(binding); }
        catch (Exception) { throw new ArgumentException("private-endpoint-native-binding"); }
        lock (gate)
        {
            Require(!disposed && deleteWindows.Count < 32 &&
                !deleteWindows.Values.Any(r => r.Binding.Selector.Nonce == binding.Selector.Nonce ||
                    r.Binding.LeaseId == binding.LeaseId));
            var window = DeleteWindow.Create(binding);
            deleteWindows.Add(window, new(binding));
            return window;
        }
    }

    internal async ValueTask<SecretStatus> StartDeleteAsync(DeleteWindow window, Binding binding,
        Func<Guid> admitBeforeStart, CancellationToken cancellationToken = default)
    {
        DeleteRegistration registration;
        Invocation invocation;
        lock (gate)
        {
            registration = Own(window, binding);
            Require(!disposed && !registration.Closed && registration.Start is null && admitBeforeStart is not null);
            invocation = registration.Start = new(cancellationToken);
        }
        bool admitted = false, accepted = false;
        try
        {
            // Admission consumes this start before clocks, timers or borrowed callbacks.
            Guid dispatch = admitBeforeStart();
            Require(dispatch != Guid.Empty);
            lock (gate) registration.Dispatch = dispatch;
            admitted = true;
            Prepare(registration, invocation);
            var options = new ArmClientOptions
            {
                Environment = new(new Uri(Origin), Origin),
                Transport = new CaptureTransport(this)
            };
            options.Retry.MaxRetries = 0;
            options.Diagnostics.IsLoggingEnabled = false;
            options.Diagnostics.IsLoggingContentEnabled = false;
            options.Diagnostics.IsDistributedTracingEnabled = false;
            options.SetApiVersion("Microsoft.Network/privateEndpoints", Revision);
            var client = new ArmClient(new CaptureCredential(this), binding.EndpointId.Split('/')[2], options);
            Check(registration, invocation);
            Context? previous = current.Value;
            Task<ArmOperation> task;
            current.Value = new(registration, invocation, false);
            try
            {
                task = client.GetGenericResource(new ResourceIdentifier(binding.EndpointId))
                    .DeleteAsync(WaitUntil.Started, invocation.Linked!.Token);
            }
            finally { current.Value = previous; }
            lock (gate)
            {
                registration.DeleteStartTask = task;
                invocation.ActualTask = task;
            }
            ArmOperation operation = await task.ConfigureAwait(false);
            Check(registration, invocation);
            lock (gate)
            {
                Require(registration.Deletes == 1 && !registration.Invalid && operation is not null);
                registration.DeleteOperation = operation;
                Require(registration.InitialSucceeded || registration.Target is not null);
            }
            // Even a synchronous reply needs the original operation's cached Check.
            accepted = true;
        }
        catch (Exception) when (admitted) { Invalidate(registration); }
        finally
        {
            await FinishAsync(registration, invocation).ConfigureAwait(false);
            if (!accepted) ClearInitial(registration);
        }
        cancellationToken.ThrowIfCancellationRequested();
        if (!Fresh(registration)) accepted = false;
        lock (gate)
        {
            accepted &= !registration.Invalid && !registration.Closed && !disposed;
            registration.Accepted = accepted;
        }
        if (!accepted) ClearInitial(registration);
        return accepted ? SecretStatus.Success : SecretStatus.Unavailable;
    }

    internal async ValueTask<SecretStatus> CheckDeleteStatusAsync(DeleteWindow window, Binding binding,
        CancellationToken cancellationToken = default)
    {
        DeleteRegistration registration;
        Invocation invocation;
        ArmOperation operation;
        lock (gate)
        {
            registration = Own(window, binding);
            Require(!disposed && !registration.Closed && !registration.Invalid && registration.Accepted &&
                registration.Start is { Drained.Task.IsCompletedSuccessfully: true } &&
                registration.Check is null && registration.DeleteOperation is not null);
            operation = registration.DeleteOperation;
            invocation = registration.Check = new(cancellationToken);
        }
        bool succeeded = false;
        try
        {
            Prepare(registration, invocation);
            Context? previous = current.Value;
            Task<Response> task;
            current.Value = new(registration, invocation, true);
            try { task = operation.UpdateStatusAsync(invocation.Linked!.Token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate)
            {
                registration.StatusTask = task;
                invocation.ActualTask = task;
            }
            await task.ConfigureAwait(false);
            Check(registration, invocation);
            Require(task.IsCompletedSuccessfully && operation.HasCompleted && registration.Deletes == 1 &&
                registration.Reads == 0 && registration.InitialBody is not null && registration.InitialLength == 0);
            Require(registration.InitialSucceeded ? registration.Polls == 0 :
                registration.Target is not null && registration.Polls == 1 && registration.PollSucceeded);
            succeeded = true;
        }
        catch (Exception) { Invalidate(registration); }
        finally
        {
            await FinishAsync(registration, invocation).ConfigureAwait(false);
            ClearInitial(registration);
        }
        cancellationToken.ThrowIfCancellationRequested();
        if (!Fresh(registration)) succeeded = false;
        lock (gate)
        {
            succeeded &= Eligible(registration) && invocation.Drained.Task.IsCompletedSuccessfully;
            if (succeeded) registration.DeleteProof = DeletionProof.Create(binding, registration.Dispatch);
        }
        return succeeded ? SecretStatus.Success : SecretStatus.Unavailable;
    }

    internal bool TryGetDeletionProof(DeleteWindow window, Binding binding,
        [NotNullWhen(true)] out DeletionProof? proof)
    {
        proof = null;
        DeleteRegistration? registration;
        lock (gate)
        {
            if (window is null || !deleteWindows.TryGetValue(window, out registration) ||
                !ReferenceEquals(registration.Binding, binding) || !Eligible(registration) ||
                registration.DeleteProof is null) return false;
        }
        if (!Fresh(registration)) return false;
        lock (gate)
        {
            if (!Eligible(registration) || registration.DeleteProof is null) return false;
            proof = registration.DeleteProof;
            return true;
        }
    }

    internal bool OwnsDeletionProof(DeletionProof proof, DeleteWindow window, Binding binding, Guid originalDispatch) =>
        proof is not null && originalDispatch != Guid.Empty && TryGetDeletionProof(window, binding, out var original) &&
        ReferenceEquals(original, proof) && original.Dispatch == originalDispatch;

    internal async ValueTask<SecretStatus> StartAsync(Window window, Binding binding,
        Func<Guid> admitBeforeStart, CancellationToken cancellationToken = default)
    {
        Registration registration;
        Invocation invocation;
        lock (gate)
        {
            registration = Own(window, binding);
            Require(!disposed && !registration.Closed && registration.Start is null && admitBeforeStart is not null);
            invocation = registration.Start = new(cancellationToken);
        }
        bool admitted = false, accepted = false;
        try
        {
            // No clock, timer, credential or transport callback precedes this
            // mandatory admission. Exceptions consume this start and propagate.
            Guid dispatch = admitBeforeStart();
            Require(dispatch != Guid.Empty);
            lock (gate) registration.Dispatch = dispatch;
            admitted = true;
            Prepare(registration, invocation);
            var properties = JsonSerializer.SerializeToUtf8Bytes(new
            {
                subnet = new { id = binding.SubnetId },
                customNetworkInterfaceName = binding.NicId.Split('/')[^1],
                manualPrivateLinkServiceConnections = new[]
                {
                    new
                    {
                        name = binding.ConnectionName,
                        properties = new { privateLinkServiceId = binding.VaultId, groupIds = new[] { "vault" } }
                    }
                }
            });
            OwnBuffer(invocation, properties);
            Require(properties.Length <= limits.MaximumRowBytes);
            var data = new GenericResourceData(binding.Location) { Properties = new BinaryData(properties) };
            data.Tags.Add(binding.OwnerTagName, binding.OwnerTagValue);
            var options = new ArmClientOptions
            {
                Environment = new(new Uri(Origin), Origin),
                Transport = new CaptureTransport(this)
            };
            options.Retry.MaxRetries = 0;
            options.Diagnostics.IsLoggingEnabled = false;
            options.Diagnostics.IsLoggingContentEnabled = false;
            options.Diagnostics.IsDistributedTracingEnabled = false;
            options.SetApiVersion("Microsoft.Network/privateEndpoints", Revision);
            var client = new ArmClient(new CaptureCredential(this), binding.EndpointId.Split('/')[2], options);
            Check(registration, invocation);
            Context? previous = current.Value;
            Task<ArmOperation<GenericResource>> task;
            current.Value = new(registration, invocation, false);
            try
            {
                task = client.GetGenericResources().CreateOrUpdateAsync(WaitUntil.Started,
                    new ResourceIdentifier(binding.EndpointId), data, invocation.Linked!.Token);
            }
            finally { current.Value = previous; }
            lock (gate)
            {
                registration.StartTask = task;
                invocation.ActualTask = task;
            }
            ArmOperation<GenericResource> operation = await task.ConfigureAwait(false);
            Check(registration, invocation);
            lock (gate)
            {
                Require(registration.Puts == 1 && !registration.Invalid && operation is not null);
                registration.Operation = operation;
            }
            if (!registration.InitialSucceeded) Require(registration.Target is not null);
            accepted = true;
        }
        catch (Exception) when (admitted)
        {
            Invalidate(registration);
        }
        finally
        {
            await FinishAsync(registration, invocation).ConfigureAwait(false);
            if (!accepted) ClearInitial(registration);
        }
        cancellationToken.ThrowIfCancellationRequested();
        if (!Fresh(registration)) accepted = false;
        lock (gate)
        {
            accepted &= !registration.Invalid && !registration.Closed && !disposed;
            registration.Accepted = accepted;
        }
        if (!accepted) ClearInitial(registration);
        return accepted ? SecretStatus.Success : SecretStatus.Unavailable;
    }

    internal async ValueTask<SecretStatus> CheckStatusAsync(Window window, Binding binding,
        CancellationToken cancellationToken = default)
    {
        Registration registration;
        Invocation invocation;
        ArmOperation<GenericResource> operation;
        lock (gate)
        {
            registration = Own(window, binding);
            Require(!disposed && !registration.Closed && !registration.Invalid && registration.Accepted &&
                registration.Start is { Drained.Task.IsCompletedSuccessfully: true } &&
                registration.Check is null && registration.Operation is not null);
            operation = registration.Operation;
            invocation = registration.Check = new(cancellationToken);
        }
        bool succeeded = false;
        try
        {
            Prepare(registration, invocation);
            Context? previous = current.Value;
            Task<Response> task;
            current.Value = new(registration, invocation, true);
            try { task = operation.UpdateStatusAsync(invocation.Linked!.Token).AsTask(); }
            finally { current.Value = previous; }
            lock (gate)
            {
                registration.StatusTask = task;
                invocation.ActualTask = task;
            }
            await task.ConfigureAwait(false);
            Check(registration, invocation);
            Require(task.IsCompletedSuccessfully && operation.HasCompleted && operation.HasValue &&
                operation.Value.Id.ToString() == binding.EndpointId);
            if (registration.InitialSucceeded)
            {
                Require(registration.Polls == 0 && registration.Reads == 0 && registration.InitialBody is not null);
                Agree(registration.InitialBody, registration.InitialLength, binding, operation.Value.Data);
            }
            else
            {
                Require(registration.Polls == 1 && registration.Reads == 1 &&
                    registration.PollSucceeded && registration.FinalSucceeded);
                Require(invocation.ResourceBody is not null);
                Agree(invocation.ResourceBody, invocation.ResourceLength, binding, operation.Value.Data);
            }
            succeeded = true;
        }
        catch (Exception) { Invalidate(registration); }
        finally
        {
            await FinishAsync(registration, invocation).ConfigureAwait(false);
            ClearInitial(registration);
        }
        cancellationToken.ThrowIfCancellationRequested();
        if (!Fresh(registration)) succeeded = false;
        lock (gate)
        {
            succeeded &= Eligible(registration) && invocation.Drained.Task.IsCompletedSuccessfully;
            if (succeeded) registration.Proof = CreationProof.Create(binding, registration.Dispatch);
        }
        return succeeded ? SecretStatus.Success : SecretStatus.Unavailable;
    }

    internal bool TryGetCreationProof(Window window, Binding binding,
        [NotNullWhen(true)] out CreationProof? proof)
    {
        proof = null;
        Registration? registration;
        lock (gate)
        {
            if (window is null || !windows.TryGetValue(window, out registration) ||
                !ReferenceEquals(registration.Binding, binding) || !Eligible(registration) ||
                registration.Proof is null) return false;
        }
        if (!Fresh(registration)) return false;
        lock (gate)
        {
            if (!Eligible(registration) || registration.Proof is null) return false;
            proof = registration.Proof;
            return true;
        }
    }

    internal bool OwnsCreationProof(CreationProof proof, Window window, Binding binding, Guid dispatch) =>
        proof is not null && dispatch != Guid.Empty && TryGetCreationProof(window, binding, out var original) &&
        ReferenceEquals(original, proof) && original.Dispatch == dispatch;

    internal ValueTask SealAsync(Window window)
    {
        Registration registration;
        lock (gate)
        {
            Require(window is not null && windows.TryGetValue(window, out _));
            registration = windows[window];
        }
        return Seal(registration);
    }

    internal ValueTask SealAsync(DeleteWindow window)
    {
        DeleteRegistration registration;
        lock (gate)
        {
            Require(window is not null && deleteWindows.TryGetValue(window, out _));
            registration = deleteWindows[window];
        }
        return Seal(registration);
    }

    private ValueTask Seal(Registration registration)
    {
        TaskCompletionSource completion;
        Task[] tasks;
        lock (gate)
        {
            if (registration.Sealed is not null) return new(registration.Sealed.Task);
            registration.Closed = true;
            registration.Proof = null;
            if (registration is DeleteRegistration deletion) deletion.DeleteProof = null;
            completion = registration.Sealed = new(TaskCreationOptions.RunContinuationsAsynchronously);
            tasks = new[] { registration.Start, registration.Check }.OfType<Invocation>()
                .Select(i => i.Drained.Task).ToArray();
        }
        _ = SealCoreAsync(registration, tasks, completion);
        return new(completion.Task);
    }

    private async Task SealCoreAsync(Registration registration, Task[] tasks, TaskCompletionSource completion)
    {
        try
        {
            try { await registration.Stop.CancelAsync().ConfigureAwait(false); }
            catch (Exception) { Invalidate(registration); }
            await Task.WhenAll(tasks).ConfigureAwait(false);
            ClearInitial(registration);
            completion.TrySetResult();
        }
        catch (Exception)
        {
            Invalidate(registration);
            completion.TrySetException(new InvalidOperationException("private-endpoint-native-seal"));
        }
    }

    public ValueTask DisposeAsync()
    {
        TaskCompletionSource completion;
        Registration[] selected;
        lock (gate)
        {
            if (disposal is not null) return new(disposal.Task);
            disposed = true;
            completion = disposal = new(TaskCreationOptions.RunContinuationsAsynchronously);
            selected = windows.Values.Concat(deleteWindows.Values).ToArray();
        }
        _ = DisposeCoreAsync(selected, completion);
        return new(completion.Task);
    }

    private async Task DisposeCoreAsync(Registration[] selected, TaskCompletionSource completion)
    {
        try
        {
            await Task.WhenAll(selected.Select(r => Seal(r).AsTask())).ConfigureAwait(false);
            foreach (Registration registration in selected) registration.Stop.Dispose();
            // Borrowed authority credentials and transport are never disposed.
            completion.TrySetResult();
        }
        catch (Exception) { completion.TrySetException(new InvalidOperationException("private-endpoint-native-disposal")); }
    }

    private Registration Own(Window window, Binding binding)
    {
        Require(window is not null && windows.TryGetValue(window, out _) &&
            ReferenceEquals(windows[window].Binding, binding));
        return windows[window];
    }

    private DeleteRegistration Own(DeleteWindow window, Binding binding)
    {
        Require(window is not null && deleteWindows.TryGetValue(window, out _) &&
            ReferenceEquals(deleteWindows[window].Binding, binding));
        return deleteWindows[window];
    }

    private bool Eligible(Registration r) => !disposed && !r.Closed && !r.Invalid && r.Dispatch != Guid.Empty &&
        r.Start is { Caller.IsCancellationRequested: false, Drained.Task.IsCompletedSuccessfully: true } &&
        r.Check is { Caller.IsCancellationRequested: false, Drained.Task.IsCompletedSuccessfully: true } &&
        r.StartTask is { IsCompletedSuccessfully: true } && r.StatusTask is { IsCompletedSuccessfully: true };

    private bool Eligible(DeleteRegistration r) => !disposed && !r.Closed && !r.Invalid && r.Dispatch != Guid.Empty &&
        r.Start is { Caller.IsCancellationRequested: false, Drained.Task.IsCompletedSuccessfully: true } &&
        r.Check is { Caller.IsCancellationRequested: false, Drained.Task.IsCompletedSuccessfully: true } &&
        r.DeleteStartTask is { IsCompletedSuccessfully: true } && r.StatusTask is { IsCompletedSuccessfully: true };

    private bool Fresh(Registration registration)
    {
        try
        {
            Require(registration.Budget is not null);
            registration.Budget.Check();
            return true;
        }
        catch (Exception) { Invalidate(registration); return false; }
    }

    private void Invalidate(Registration registration)
    {
        lock (gate)
        {
            registration.Invalid = true;
            registration.Proof = null;
            if (registration is DeleteRegistration deletion) deletion.DeleteProof = null;
        }
    }

    private void Prepare(Registration registration, Invocation invocation)
    {
        lock (gate) Require(!registration.Closed && !disposed && !registration.Invalid);
        invocation.Caller.ThrowIfCancellationRequested();
        registration.Stop.Token.ThrowIfCancellationRequested();
        registration.Budget ??= new(time, limits.Timeout);
        registration.Budget.Check();
        invocation.Deadline = new(registration.Budget.Remaining, time);
        invocation.Linked = CancellationTokenSource.CreateLinkedTokenSource(
            invocation.Caller, invocation.Deadline.Token, registration.Stop.Token);
        Check(registration, invocation);
    }

    private void Check(Registration registration, Invocation invocation)
    {
        lock (gate) Require(!registration.Closed && !registration.Invalid && !disposed && !invocation.Finishing);
        Require(registration.Start is { Caller.IsCancellationRequested: false });
        invocation.Linked!.Token.ThrowIfCancellationRequested();
        registration.Budget!.Check();
        invocation.Deadline!.CancelAfter(registration.Budget.Remaining);
        invocation.Linked.Token.ThrowIfCancellationRequested();
    }

    private async Task FinishAsync(Registration registration, Invocation invocation)
    {
        TaskCompletionSource<Task>[] borrowers;
        lock (gate)
        {
            invocation.Finishing = true;
            borrowers = invocation.Borrowers.ToArray();
        }
        try
        {
            // These are the original tasks, never cancellation-raced surrogates.
            // An uncooperative credential/send/body borrower still has to finish.
            if (invocation.ActualTask is { } actual)
                try { await actual.ConfigureAwait(false); }
                catch (Exception) { Invalidate(registration); }
            foreach (var borrower in borrowers)
                try { await (await borrower.Task.ConfigureAwait(false)).ConfigureAwait(false); }
                catch (Exception) { Invalidate(registration); }
        }
        finally
        {
            try
            {
                foreach (var snapshot in invocation.Snapshots)
                    try { snapshot.Dispose(); }
                    catch (Exception) { Invalidate(registration); }
            }
            finally
            {
                foreach (byte[] bytes in invocation.Buffers) CryptographicOperations.ZeroMemory(bytes);
                invocation.Snapshots.Clear();
                invocation.Buffers.Clear();
                invocation.ResourceBody = null;
                try
                {
                    if (invocation.Linked?.IsCancellationRequested == true) Invalidate(registration);
                    invocation.Linked?.Dispose();
                    invocation.Deadline?.Dispose();
                }
                finally { invocation.Drained.TrySetResult(); }
            }
        }
        // Clearing our buffers does not clear SDK models or immutable strings.
    }

    private void OwnBuffer(Invocation invocation, byte[] buffer)
    {
        lock (gate) invocation.Buffers.Add(buffer);
    }

    private void ClearInitial(Registration registration)
    {
        byte[]? bytes;
        Stream? stream;
        lock (gate)
        {
            bytes = registration.InitialBody;
            stream = registration.InitialStream;
            registration.InitialBody = null;
            registration.InitialStream = null;
        }
        try { stream?.Dispose(); }
        finally { if (bytes is not null) CryptographicOperations.ZeroMemory(bytes); }
    }

    private TaskCompletionSource<Task> Borrow(Context context)
    {
        lock (gate)
        {
            Require(!context.Invocation.Finishing && context.Invocation.Borrowers.Count < 16 &&
                ReferenceEquals(context.Invocation, context.Status ? context.Registration.Check : context.Registration.Start));
            var borrower = new TaskCompletionSource<Task>(TaskCreationOptions.RunContinuationsAsynchronously);
            context.Invocation.Borrowers.Add(borrower);
            return borrower;
        }
    }

    private sealed class CaptureCredential(PrivateEndpointNativeCapture source) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("private-endpoint-native-async");
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken)
        {
            Context selected = source.current.Value ?? throw new InvalidOperationException("private-endpoint-native-context");
            var borrower = source.Borrow(selected);
            Task<AccessToken> actual = FetchAsync(selected, context, cancellationToken);
            borrower.TrySetResult(actual);
            return new(actual);
        }
        private async Task<AccessToken> FetchAsync(Context selected, TokenRequestContext context, CancellationToken token)
        {
            source.Check(selected.Registration, selected.Invocation);
            Require(context.Scopes.Length == 1 && context.Scopes[0] == Origin + "/.default");
            token.ThrowIfCancellationRequested();
            AccessToken value = await source.authority.Credential.GetTokenAsync(context, token).ConfigureAwait(false);
            source.Check(selected.Registration, selected.Invocation);
            token.ThrowIfCancellationRequested();
            return value;
        }
    }

    private sealed class CaptureTransport(PrivateEndpointNativeCapture source) : HttpPipelineTransport
    {
        public override Request CreateRequest()
        {
            Context context = source.current.Value ?? throw new InvalidOperationException("private-endpoint-native-context");
            lock (source.gate)
            {
                Require(!context.Invocation.Finishing && ++context.Invocation.Factories <= 16);
            }
            Request request = source.authority.Transport.CreateRequest();
            lock (source.gate)
            {
                Require(!context.Invocation.Finishing && context.Invocation.Requests.Add(request));
            }
            return request;
        }
        public override void Process(HttpMessage message) => throw new InvalidOperationException("private-endpoint-native-async");
        public override ValueTask ProcessAsync(HttpMessage message)
        {
            Context context = source.current.Value ?? throw new InvalidOperationException("private-endpoint-native-context");
            var borrower = source.Borrow(context);
            Task actual = source.SendAsync(context, message);
            borrower.TrySetResult(actual);
            return new(actual);
        }
    }

    private async Task SendAsync(Context context, HttpMessage message)
    {
        Registration r = context.Registration;
        DeleteRegistration? deletion = r as DeleteRegistration;
        Invocation invocation = context.Invocation;
        Binding binding = r.Binding;
        RequestContent? original = null, snapshot = null;
        bool acquired = false;
        try
        {
            Check(r, invocation);
            Uri uri = message.Request.Uri.ToUri();
            bool poll;
            lock (gate)
            {
                Require(!invocation.Sending && invocation.Requests.Remove(message.Request));
                Require(Trusted(uri) && uri.Query == "?api-version=" + Revision);
                if (!context.Status)
                {
                    Require(uri.AbsoluteUri == ResourceUri(binding));
                    if (deletion is null)
                        Require(r.Puts++ == 0 && message.Request.Method == RequestMethod.Put);
                    else
                        Require(deletion.Deletes++ == 0 && message.Request.Method == RequestMethod.Delete &&
                            message.Request.Content is null);
                    poll = false;
                }
                else
                {
                    Require(message.Request.Method == RequestMethod.Get && message.Request.Content is null && r.Target is not null);
                    poll = r.Polls == 0;
                    if (deletion is not null) Require(poll && !r.InitialSucceeded);
                    if (poll) Require(uri.AbsoluteUri == r.Target && r.Polls++ == 0 && r.Reads == 0);
                    else Require(r.PollSucceeded && r.Polls == 1 && r.Reads++ == 0 && uri.AbsoluteUri == ResourceUri(binding));
                }
                invocation.Sending = acquired = true;
            }
            original = message.Request.Content;
            Headers(message.Request.Headers);
            Framing(message.Request.Headers);
            Require(message.Request.Headers.TryGetValue("Authorization", out var authorization) &&
                authorization.StartsWith("Bearer ", StringComparison.Ordinal) && authorization.Length > 7);
            if (message.Request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
            var requestHeaders = message.Request.Headers.Select(h => (h.Name, h.Value)).ToArray();
            if (!context.Status && deletion is null)
            {
                Require(original is not null);
                byte[] staging = new byte[limits.MaximumResponseBytes + 1];
                OwnBuffer(invocation, staging);
                using var destination = new MemoryStream(staging, 0, staging.Length, true, true);
                await original.WriteToAsync(destination, message.CancellationToken).ConfigureAwait(false);
                Check(r, invocation);
                int count = checked((int)destination.Position);
                Require(count > 0 && count <= limits.MaximumRowBytes);
                byte[] dispatch = staging.AsSpan(0, count).ToArray();
                OwnBuffer(invocation, dispatch);
                using (var json = Parse(dispatch, count)) RequestBody(json.RootElement, binding);
                ContentLength(message.Request.Headers, count);
                snapshot = RequestContent.Create(dispatch);
                invocation.Snapshots.Add(snapshot);
                message.Request.Content = snapshot;
            }
            else ContentLength(message.Request.Headers, 0);
            Check(r, invocation);
            ValidateRequest();
            message.BufferResponse = false;
            await authority.Transport.ProcessAsync(message).ConfigureAwait(false);
            Check(r, invocation);
            message.CancellationToken.ThrowIfCancellationRequested();
            ValidateRequest();
            Response response = message.Response;
            Headers(response.Headers);
            Framing(response.Headers);
            Require(!response.Headers.Contains("Location") && !response.Headers.Contains("Operation-Location") &&
                !response.Headers.Contains("Retry-After") &&
                (context.Status ? response.Status == 200 :
                    deletion is null ? response.Status is 200 or 201 : response.Status is 204 or 202));
            if (context.Status || deletion is null || response.Headers.Contains("Content-Type"))
            {
                string[] type = Single(response.Headers, "Content-Type").Split(';', StringSplitOptions.TrimEntries);
                Require(type.Length is 1 or 2 && type[0].Equals("application/json", StringComparison.OrdinalIgnoreCase) &&
                    (type.Length == 1 || type[1].Equals("charset=utf-8", StringComparison.OrdinalIgnoreCase)));
            }
            string? continuation = null;
            if (response.Headers.Contains("Azure-AsyncOperation"))
            {
                Require(!context.Status && response.Status == (deletion is null ? 201 : 202));
                continuation = Single(response.Headers, "Azure-AsyncOperation");
                ValidateTarget(continuation, binding);
            }
            if (deletion is not null && !context.Status)
                Require(response.Status == 204 ? continuation is null : continuation is not null);
            long? declared = ContentLength(response.Headers);
            Require(declared is null || declared <= limits.MaximumResponseBytes);
            byte[] storage = new byte[limits.MaximumResponseBytes + 1];
            OwnBuffer(invocation, storage);
            int used = 0;
            Stream? input = response.ContentStream;
            if (input is not null)
            {
                // The SDK does not borrow the original stream: this task drains
                // it before installing its privately registered bounded snapshot.
                invocation.Snapshots.Add(input);
                while (true)
                {
                    Check(r, invocation);
                    int read = await input.ReadAsync(storage.AsMemory(used), message.CancellationToken).ConfigureAwait(false);
                    Check(r, invocation);
                    if (read == 0) break;
                    used += read;
                    Require(used <= limits.MaximumResponseBytes);
                }
            }
            Require(used <= limits.MaximumRowBytes && (declared is null || declared == used));
            Check(r, invocation);
            if (deletion is not null && !context.Status)
            {
                Require(used == 0);
                lock (gate)
                {
                    r.InitialSucceeded = response.Status == 204;
                    r.Target = continuation;
                }
            }
            else
            {
                Require(used > 0);
                using (var json = Parse(storage, used))
                {
                    JsonElement root = json.RootElement;
                    Require(root.ValueKind == JsonValueKind.Object);
                    if (context.Status && poll)
                    {
                        Require(root.EnumerateObject().Count() == 1 && Text(root, "status") == "Succeeded");
                        lock (gate) r.PollSucceeded = true;
                    }
                    else
                    {
                        string state = ResourceBody(root, binding);
                        Require(state == "Succeeded" || !context.Status && continuation is not null && state == "Updating");
                        if (!context.Status)
                        {
                            Require(continuation is null ? state == "Succeeded" : state == "Updating");
                            lock (gate)
                            {
                                r.InitialSucceeded = continuation is null;
                                r.Target = continuation;
                            }
                        }
                        else lock (gate) r.FinalSucceeded = true;
                        invocation.ResourceBody = storage;
                        invocation.ResourceLength = used;
                    }
                }
            }
            var frozen = new MemoryStream(storage, 0, used, false, true);
            lock (gate)
            {
                if (context.Status) invocation.Snapshots.Add(frozen);
                else
                {
                    invocation.Buffers.Remove(storage);
                    r.InitialBody = storage;
                    r.InitialLength = used;
                    r.InitialStream = frozen;
                }
            }
            response.ContentStream = frozen;
            Check(r, invocation);

            void ValidateRequest() => Require(message.Request.Uri.ToUri().AbsoluteUri == uri.AbsoluteUri &&
                message.Request.Method == (context.Status ? RequestMethod.Get :
                    deletion is null ? RequestMethod.Put : RequestMethod.Delete) &&
                ReferenceEquals(message.Request.Content, snapshot) &&
                requestHeaders.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
        }
        catch (Exception)
        {
            Invalidate(r);
            throw new IOException("private-endpoint-native-transport");
        }
        finally
        {
            if (acquired)
            {
                try { message.Request.Content = original; }
                finally { lock (gate) invocation.Sending = false; }
            }
        }
    }

    private static string ResourceUri(Binding binding) => Origin + binding.EndpointId + "?api-version=" + Revision;
    private static bool Trusted(Uri uri) => uri.IsAbsoluteUri && uri.Scheme == "https" && uri.IsDefaultPort &&
        uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 && uri.GetLeftPart(UriPartial.Authority) == Origin &&
        uri.OriginalString == uri.AbsoluteUri;

    private static void ValidateTarget(string target, Binding binding)
    {
        Require(target.Length <= 2048);
        Require(Uri.TryCreate(target, UriKind.Absolute, out var uri));
        Require(Trusted(uri) && uri.Query == "?api-version=" + Revision);
        string prefix = "/subscriptions/" + binding.EndpointId.Split('/')[2] +
            "/providers/Microsoft.Network/locations/" + binding.Location + "/operations/";
        Require(uri.AbsolutePath.StartsWith(prefix, StringComparison.Ordinal) &&
            Guid.TryParseExact(uri.AbsolutePath[prefix.Length..], "D", out var id) && id != Guid.Empty);
    }

    private static void RequestBody(JsonElement root, Binding b)
    {
        Require(root.ValueKind == JsonValueKind.Object && root.EnumerateObject().Count() == 3 &&
            Text(root, "location") == b.Location);
        JsonElement tags = root.GetProperty("tags"), properties = root.GetProperty("properties");
        Require(tags.ValueKind == JsonValueKind.Object && tags.EnumerateObject().Count() == 1 &&
            Text(tags, b.OwnerTagName) == b.OwnerTagValue &&
            properties.ValueKind == JsonValueKind.Object && properties.EnumerateObject().Count() == 3 &&
            Text(properties, "customNetworkInterfaceName") == b.NicId.Split('/')[^1]);
        JsonElement subnet = properties.GetProperty("subnet");
        Require(subnet.ValueKind == JsonValueKind.Object && subnet.EnumerateObject().Count() == 1 &&
            Text(subnet, "id") == b.SubnetId);
        JsonElement connections = properties.GetProperty("manualPrivateLinkServiceConnections");
        Require(connections.ValueKind == JsonValueKind.Array && connections.GetArrayLength() == 1);
        JsonElement connection = connections[0], configuration = connection.GetProperty("properties");
        Require(connection.EnumerateObject().Count() == 2 && Text(connection, "name") == b.ConnectionName &&
            configuration.ValueKind == JsonValueKind.Object && configuration.EnumerateObject().Count() == 2 &&
            Text(configuration, "privateLinkServiceId") == b.VaultId);
        JsonElement groups = configuration.GetProperty("groupIds");
        Require(groups.ValueKind == JsonValueKind.Array && groups.GetArrayLength() == 1 && groups[0].GetString() == "vault");
    }

    private static string ResourceBody(JsonElement root, Binding binding)
    {
        Require(Text(root, "id") == binding.EndpointId && Text(root, "name") == binding.EndpointId.Split('/')[^1] &&
            Text(root, "type") == "Microsoft.Network/privateEndpoints" && Text(root, "location") == binding.Location &&
            !root.TryGetProperty("status", out _));
        JsonElement properties = root.GetProperty("properties");
        Require(properties.ValueKind == JsonValueKind.Object && !properties.TryGetProperty("status", out _));
        return Text(properties, "provisioningState");
    }

    private void Agree(byte[] body, int length, Binding binding, GenericResourceData native)
    {
        using var raw = Parse(body, length);
        Require(ResourceBody(raw.RootElement, binding) == "Succeeded");
        NativeSucceeded(native, binding);
        Require(native.Name == Text(raw.RootElement, "name") &&
            native.ResourceType.ToString() == Text(raw.RootElement, "type") &&
            native.Location.Name == Text(raw.RootElement, "location") && native.Properties is not null);
        JsonElement tags = raw.RootElement.GetProperty("tags");
        Require(tags.ValueKind == JsonValueKind.Object && native.Tags.Count == tags.EnumerateObject().Count());
        foreach (var tag in tags.EnumerateObject())
            Require(native.Tags.Keys.Contains(tag.Name, StringComparer.Ordinal) &&
                native.Tags.TryGetValue(tag.Name, out var value) && tag.Value.ValueKind == JsonValueKind.String &&
                value == tag.Value.GetString());
        using var properties = Parse(native.Properties.ToMemory());
        Require(JsonElement.DeepEquals(raw.RootElement.GetProperty("properties"), properties.RootElement));
    }

    private void NativeSucceeded(GenericResourceData native, Binding binding)
    {
        Require(native.Id?.ToString() == binding.EndpointId && native.Properties is not null);
        using var properties = Parse(native.Properties.ToMemory());
        Require(properties.RootElement.ValueKind == JsonValueKind.Object &&
            Text(properties.RootElement, "provisioningState") == "Succeeded");
    }

    private JsonDocument Parse(byte[] bytes, int count) => Parse(bytes.AsMemory(0, count));
    private JsonDocument Parse(ReadOnlyMemory<byte> bytes)
    {
        Require(bytes.Length > 0 && bytes.Length <= limits.MaximumRowBytes);
        Shape(bytes.Span);
        return JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = limits.MaximumDepth });
    }

    private void Shape(ReadOnlySpan<byte> bytes)
    {
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = limits.MaximumDepth });
        var stack = new Stack<(HashSet<string>? Names, bool Tags)>();
        bool tags = false;
        int nodes = 0, rows = 0;
        while (reader.Read())
        {
            Require(++nodes <= limits.MaximumNodes);
            if (reader.TokenType == JsonTokenType.StartObject)
            {
                Require(++rows <= limits.MaximumRows);
                stack.Push((new(StringComparer.OrdinalIgnoreCase), tags));
                tags = false;
            }
            else if (reader.TokenType == JsonTokenType.StartArray)
            {
                stack.Push((null, false));
                tags = false;
            }
            else if (reader.TokenType is JsonTokenType.EndObject or JsonTokenType.EndArray)
            {
                stack.Pop();
                tags = false;
            }
            else if (reader.TokenType == JsonTokenType.PropertyName)
            {
                string name = reader.GetString()!;
                Require(stack.Count > 0 && stack.Peek().Names is { } names && names.Add(name));
                if (!stack.Peek().Tags)
                {
                    foreach (string reserved in Reserved)
                        if (name.Equals(reserved, StringComparison.OrdinalIgnoreCase)) Require(name == reserved);
                    Require(name is not ("error" or "errors" or "nextLink" or "value" or "partial"));
                }
                tags = stack.Count == 1 && name == "tags";
            }
            else
            {
                // Decode every string, including unknown fields; lazy JSON/SDK
                // readers must not hide malformed UTF-8 in an ignored value.
                if (reader.TokenType == JsonTokenType.String) _ = reader.GetString();
                tags = false;
            }
        }
        Require(nodes > 0 && stack.Count == 0);
    }

    private static readonly string[] Reserved =
    [
        "id", "name", "type", "location", "tags", "properties", "provisioningState", "subnet",
        "customNetworkInterfaceName", "networkInterfaces", "manualPrivateLinkServiceConnections",
        "privateLinkServiceConnections", "privateLinkServiceId", "groupIds", "privateLinkServiceConnectionState",
        "status", "error", "errors", "nextLink", "value", "partial"
    ];

    private static string Text(JsonElement parent, string field)
    {
        JsonElement value = parent.GetProperty(field);
        Require(value.ValueKind == JsonValueKind.String);
        return value.GetString()!;
    }

    private static void Headers(IEnumerable<HttpHeader> headers)
    {
        int rows = 0, bytes = 0;
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in headers)
        {
            Require(++rows <= 32 && header.Name.Length is > 0 and <= 128 && header.Value.Length <= 4096 &&
                names.Add(header.Name) && header.Name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') &&
                !header.Value.Any(c => !char.IsAscii(c) || char.IsControl(c) && c != '\t'));
            bytes += header.Name.Length + header.Value.Length;
            Require(bytes <= 16384);
        }
    }

    private static void Framing(IEnumerable<HttpHeader> headers)
    {
        foreach (var header in headers)
            Require(!new[] { "Content-Encoding", "Content-Range", "Transfer-Encoding" }
                .Contains(header.Name, StringComparer.OrdinalIgnoreCase));
    }

    private static string Single(ResponseHeaders headers, string name)
    {
        Require(headers.TryGetValues(name, out var values));
        string[] selected = values.Take(2).ToArray();
        Require(selected.Length == 1);
        return selected[0];
    }

    private static long? ContentLength(IEnumerable<HttpHeader> headers)
    {
        string[] lengths = headers.Where(h => h.Name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
            .Select(h => h.Value).Take(2).ToArray();
        if (lengths.Length == 0) return null;
        Require(lengths.Length == 1);
        Require(long.TryParse(lengths[0], NumberStyles.None, CultureInfo.InvariantCulture, out long length) && length >= 0);
        return length;
    }

    private static void ContentLength(IEnumerable<HttpHeader> headers, int count)
    {
        long? length = ContentLength(headers);
        Require(length is null || length == count);
    }

    private sealed class Budget
    {
        private readonly TimeProvider time;
        private readonly TimeSpan timeout;
        private readonly DateTimeOffset started;
        private readonly long timestamp;
        private readonly object gate = new();
        private DateTimeOffset lastWall;
        private long lastStamp;
        internal TimeSpan Remaining { get; private set; }
        internal Budget(TimeProvider time, TimeSpan timeout)
        {
            this.time = time;
            this.timeout = timeout;
            lastWall = started = time.GetUtcNow();
            lastStamp = timestamp = time.GetTimestamp();
        }
        internal void Check()
        {
            lock (gate)
            {
                DateTimeOffset wall = time.GetUtcNow();
                long stamp = time.GetTimestamp();
                Require(wall >= started && wall >= lastWall && stamp >= timestamp && stamp >= lastStamp);
                TimeSpan mono = time.GetElapsedTime(timestamp, stamp), elapsed = wall - started;
                Require(mono >= TimeSpan.Zero);
                Remaining = timeout - (mono > elapsed ? mono : elapsed);
                Require(Remaining > TimeSpan.Zero);
                lastWall = wall;
                lastStamp = stamp;
            }
        }
    }

    private static void Require([DoesNotReturnIf(false)] bool condition)
    {
        if (!condition) throw new InvalidOperationException("private-endpoint-native-boundary");
    }

    public override string ToString() => "[PrivateEndpointNativeCapture]";
}
