using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    public async Task StatusCanceledPurgeIndependentCannotBorrowSelectedCancellationAuthority()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Canceled", statusCanceledPurge: true);
        f.Backend.StatusBody = "{\"status\":\"Canceled\"}";
        Task? start = null, selected = null;
        await f.Start(retained: task => start = task);
        await f.Check(retained: task => selected = task);
        await Assert.That(f.Source.TryGetStatusCanceledPurgeIndependentStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusCanceledPurgeIndependentTerminalCancellation(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusCanceledPurgeTerminalCancellation(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected!, out _)).IsTrue();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusCanceledPurgeIndependentCallerOceCannotMintProviderTerminalCancellation()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Canceled", boundary: "independent-effect", statusCanceledPurgeIndependent: true);
        Task? start = null, selected = null;
        await f.Start(retained: task => start = task);
        using var caller = new CancellationTokenSource();
        caller.Cancel();
        selected = f.Handle!.CheckStatusAsync(caller.Token).AsTask();
        await Assert.That(async () => await selected)
            .Throws<OperationCanceledException>();
        await Assert.That(f.Source.TryGetStatusCanceledPurgeIndependentTerminalCancellation(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected ?? Task.CompletedTask, out _)).IsFalse();
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(0);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("cancellation-boundary")]
    public async Task StatusCanceledPurgeIndependentCannotBorrowActualFailedTerminalAuthority(string boundary)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Failed", boundary: boundary,
            statusFailedPurge: boundary == "selected-contract",
            statusFailedPurgeIndependent: boundary == "independent-effect",
            statusFailedPurgeCancellation: boundary == "cancellation-boundary");
        f.Backend.StatusBody = "{\"status\":\"Failed\"}";
        Task? start = null, selected = null;
        await f.Start(retained: task => start = task);
        Task? canceled = boundary == "cancellation-boundary" ? await ActualFailedCancellation(f) : null;
        await f.Check(retained: task => selected = task);
        await Assert.That(f.Source.TryGetStatusCanceledPurgeIndependentStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusCanceledPurgeIndependentTerminalCancellation(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected!, out _)).IsFalse();
        bool owned = boundary switch
        {
            "selected-contract" => f.Source.TryGetStatusFailedPurgeTerminalFailure(f.Window, f.Binding, f.Client,
                (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected!, out _),
            "independent-effect" => f.Source.TryGetStatusFailedPurgeIndependentTerminalFailure(f.Window, f.Binding, f.Client,
                (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected!, out _),
            _ => f.Source.TryGetStatusFailedPurgeCancellationTerminalFailure(f.Window, f.Binding, f.Client,
                (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, canceled!, selected!, out _)
        };
        await Assert.That(owned).IsTrue();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusCanceledPurgeIndependentProofRequiresActualTerminalCancellationTaskNotCachedUnknown()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Canceled", boundary: "independent-effect", statusCanceledPurgeIndependent: true);
        f.Backend.StatusBody = "{\"status\":\"Canceled\"}";
        Task? start = null, selected = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusCanceledPurgeIndependentStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out var issued)).IsTrue();
        await Assert.That(f.Source.TryGetStatusCanceledPurgeStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusFailedPurgeStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusFailedPurgeIndependentStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusFailedPurgeCancellationStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(await f.Check(retained: task => selected = task)).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(f.Source.TryGetStatusCanceledPurgeIndependentTerminalCancellation(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected!, out var failure)).IsTrue();
        await Assert.That(ReferenceEquals(failure!.Start, issued)).IsTrue();
        await Assert.That(failure.Outcome).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(failure.State).IsEqualTo(NativeProvisioningState.Canceled);
        await Assert.That(failure.ReceiptEvidence).IsEqualTo(DispatchEvidence.Pending);
        var fabricated = new TaskCompletionSource<SecretStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        fabricated.SetResult(SecretStatus.Unknown);
        await Assert.That(f.Source.TryGetStatusCanceledPurgeIndependentTerminalCancellation(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, fabricated.Task, out _)).IsFalse();
        await Assert.That(await f.Handle!.CheckStatusAsync()).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(f.Source.OwnsStatusCanceledPurgeIndependentTerminalCancellation(failure, f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle, selected!)).IsTrue();
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "POST")).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("InProgress")]
    [Arguments("Succeeded")]
    [Arguments("Failed")]
    [Arguments("future-state")]
    [Arguments("malformed")]
    [Arguments("denied")]
    [Arguments("lost")]
    public async Task StatusCanceledPurgeIndependentOtherOrUnavailableNativeResultCannotMintFailure(string state)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Canceled", boundary: "independent-effect", statusCanceledPurgeIndependent: true);
        Task? start = null, selected = null;
        await f.Start(retained: task => start = task);
        f.Backend.StatusBody = state == "malformed" ? "{" : "{\"status\":\"" + state + "\"}";
        if (state == "denied") f.Backend.StatusStatus = 403;
        if (state == "lost") f.Backend.LoseStatus = true;
        try { await f.Check(retained: task => selected = task); }
        catch (InvalidOperationException) { }
        await Assert.That(f.Source.TryGetStatusCanceledPurgeIndependentTerminalCancellation(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, selected!, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("cancellation-boundary")]
    public async Task StatusCanceledPurgeIndependentCannotBorrowPendingStartAuthority(string boundary)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: boundary,
            statusPendingPurge: boundary == "selected-contract",
            statusPendingPurgeIndependent: boundary == "independent-effect",
            statusPendingPurgeCancellation: boundary == "cancellation-boundary");
        Task? start = null;
        await f.Start(retained: task => start = task);
        await Assert.That(f.Source.TryGetStatusCanceledPurgeIndependentStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusCanceledPurgeIndependentRegistrationCannotAuthorizePendingOrGenericCompletion()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Canceled", boundary: "independent-effect", statusCanceledPurgeIndependent: true);
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

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    public async Task StatusCanceledPurgeIndependentProfileDoesNotBlockGenericNonPurgeNativeFacts(string boundary)
    {
        using var f = new Fixture("CreateOrUpdateVault", "status.Canceled", boundary: boundary);
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
}
