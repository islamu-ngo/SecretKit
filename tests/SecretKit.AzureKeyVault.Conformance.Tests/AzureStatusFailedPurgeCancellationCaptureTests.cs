using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    private static async Task<Task> ActualFailedCancellation(Fixture f)
    {
        using var operand = new CancellationTokenSource();
        operand.Cancel();
        Task? native = null;
        OperationCanceledException? actual = null;
        int requests = f.Backend.Requests.Count;
        try
        {
            await f.Source.CheckStatusFailedPurgeCancellationCanceledAsync(f.Window, f.Binding.Selector,
                f.Handle!, operand.Token, task => native = task);
        }
        catch (OperationCanceledException exception) { actual = exception; }
        await Assert.That(actual is not null && actual.CancellationToken == operand.Token).IsTrue();
        await Assert.That(native is { IsCanceled: true }).IsTrue();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(requests);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        return native!;
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusFailedPurgeCancellationRequiresCanceledOperandBeforeNormalCall(bool uncanceledOperand)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Failed", boundary: "cancellation-boundary",
            statusFailedPurgeCancellation: true);
        await f.Start();
        int before = f.Backend.Requests.Count;
        Task? leaked = null;
        await Assert.That(async () =>
        {
            if (uncanceledOperand)
                await f.Source.CheckStatusFailedPurgeCancellationCanceledAsync(f.Window, f.Binding.Selector,
                    f.Handle!, default, task => leaked = task);
            else
                await f.Source.CheckStatusFailedPurgeCancellationAsync(f.Window, f.Binding.Selector,
                    f.Handle!, default, task => leaked = task);
        }).Throws<InvalidOperationException>();
        await Assert.That(leaked is null).IsTrue();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(before);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusFailedPurgeCancellationHookOceCannotBecomeActualCanceledWitness()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Failed", boundary: "cancellation-boundary",
            statusFailedPurgeCancellation: true);
        Task? start = null, native = null;
        await f.Start(retained: task => start = task);
        using var operand = new CancellationTokenSource();
        operand.Cancel();
        await Assert.That(async () => await f.Source.CheckStatusFailedPurgeCancellationCanceledAsync(f.Window,
            f.Binding.Selector, f.Handle!, operand.Token, task =>
            {
                native = task;
                throw new OperationCanceledException();
            })).Throws<OperationCanceledException>();
        await Assert.That(native is { IsCanceled: true }).IsTrue();
        await Assert.That(f.Source.TryGetStatusFailedPurgeCancellationCanceled(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, native!, out _)).IsFalse();
        await Assert.That(async () => await f.Check()).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(0);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    public async Task StatusFailedPurgeCancellationCannotBorrowOtherFailedTaskAuthority(string boundary)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Failed", boundary: boundary,
            statusFailedPurge: boundary == "selected-contract",
            statusFailedPurgeIndependent: boundary == "independent-effect");
        f.Backend.StatusBody = "{\"status\":\"Failed\"}";
        Task? start = null, selected = null;
        await f.Start(retained: task => start = task);
        await f.Check(retained: task => selected = task);
        await Assert.That(f.Source.TryGetStatusFailedPurgeCancellationStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusFailedPurgeCancellationTerminalFailure(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected!, selected!, out _)).IsFalse();
        bool owned = boundary == "selected-contract"
            ? f.Source.TryGetStatusFailedPurgeTerminalFailure(f.Window, f.Binding, f.Client,
                (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected!, out _)
            : f.Source.TryGetStatusFailedPurgeIndependentTerminalFailure(f.Window, f.Binding, f.Client,
                (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected!, out _);
        await Assert.That(owned).IsTrue();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusFailedPurgeCancellationDoesNotBlockGenericNonPurgeNativeFacts()
    {
        using var f = new Fixture("CreateOrUpdateVault", "status.Failed", boundary: "cancellation-boundary");
        f.AsyncStart();
        f.Backend.StartStatus = 201;
        f.Backend.StartBody = f.Backend.FinalBody!.Replace("Succeeded", "Updating", StringComparison.Ordinal);
        f.Backend.StatusBody = "{\"status\":\"Succeeded\"}";
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsTrue();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusFailedPurgeCancellationProofRequiresActualTerminalFailureTaskNotCachedUnknown()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Failed", boundary: "cancellation-boundary", statusFailedPurgeCancellation: true);
        f.Backend.StatusBody = "{\"status\":\"Failed\"}";
        Task? start = null, selected = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        Task canceled = await ActualFailedCancellation(f);
        await Assert.That(f.Source.TryGetStatusFailedPurgeCancellationStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out var issued)).IsTrue();
        await Assert.That(f.Source.TryGetStatusFailedPurgeStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusFailedPurgeCancellationCanceled(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, canceled, out var rejection)).IsTrue();
        using var other = new CancellationTokenSource();
        other.Cancel();
        Task copiedCanceled = Task.FromCanceled<SecretStatus>(other.Token);
        await Assert.That(f.Source.TryGetStatusFailedPurgeCancellationCanceled(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, copiedCanceled, out _)).IsFalse();
        await Assert.That(await f.Check(retained: task => selected = task)).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(f.Source.TryGetStatusFailedPurgeCancellationTerminalFailure(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, canceled, selected!, out var failure)).IsTrue();
        await Assert.That(ReferenceEquals(failure!.Start, issued)).IsTrue();
        await Assert.That(ReferenceEquals(failure.Canceled, rejection)).IsTrue();
        await Assert.That(f.Source.TryGetStatusFailedPurgeCancellationTerminalFailure(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, copiedCanceled, selected!, out _)).IsFalse();
        await Assert.That(failure.Outcome).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(failure.State).IsEqualTo(NativeProvisioningState.Failed);
        await Assert.That(failure.ReceiptEvidence).IsEqualTo(DispatchEvidence.Pending);
        var fabricated = new TaskCompletionSource<SecretStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        fabricated.SetResult(SecretStatus.Unknown);
        await Assert.That(f.Source.TryGetStatusFailedPurgeCancellationTerminalFailure(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, canceled, fabricated.Task, out _)).IsFalse();
        await Assert.That(await f.Handle!.CheckStatusAsync()).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(f.Source.OwnsStatusFailedPurgeCancellationTerminalFailure(failure, f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle, canceled, selected!)).IsTrue();
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "POST")).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("InProgress")]
    [Arguments("Succeeded")]
    [Arguments("Canceled")]
    [Arguments("future-state")]
    [Arguments("malformed")]
    [Arguments("denied")]
    [Arguments("lost")]
    public async Task StatusFailedPurgeCancellationOtherOrUnavailableNativeResultCannotMintFailure(string state)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Failed", boundary: "cancellation-boundary", statusFailedPurgeCancellation: true);
        Task? start = null, selected = null;
        await f.Start(retained: task => start = task);
        Task canceled = await ActualFailedCancellation(f);
        f.Backend.StatusBody = state == "malformed" ? "{" : "{\"status\":\"" + state + "\"}";
        if (state == "denied") f.Backend.StatusStatus = 403;
        if (state == "lost") f.Backend.LoseStatus = true;
        try { await f.Check(retained: task => selected = task); }
        catch (InvalidOperationException) { }
        await Assert.That(f.Source.TryGetStatusFailedPurgeCancellationTerminalFailure(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, canceled, selected!, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("cancellation-boundary")]
    public async Task StatusFailedPurgeCancellationCannotBorrowPendingStartAuthority(string boundary)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: boundary,
            statusPendingPurge: boundary == "selected-contract",
            statusPendingPurgeIndependent: boundary == "independent-effect",
            statusPendingPurgeCancellation: boundary == "cancellation-boundary");
        Task? start = null;
        await f.Start(retained: task => start = task);
        await Assert.That(f.Source.TryGetStatusFailedPurgeCancellationStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusFailedPurgeCancellationRegistrationCannotAuthorizePendingOrGenericCompletion()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Failed", boundary: "cancellation-boundary", statusFailedPurgeCancellation: true);
        Task? start = null;
        await f.Start(retained: task => start = task);
        await Assert.That(f.Source.TryGetStatusPendingPurgeStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusPendingPurgeIndependentStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusPendingPurgeCancellationStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(async () => await f.Source.CheckStatusAsync(f.Window, f.Binding.Selector, f.Handle!))
            .Throws<InvalidOperationException>();
        await f.Source.SealAsync(f.Window);
    }

}
