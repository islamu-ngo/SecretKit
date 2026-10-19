using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    private static async Task<Task> ActualPendingCancellation(Fixture f)
    {
        using var operand = new CancellationTokenSource();
        operand.Cancel();
        Task? native = null;
        OperationCanceledException? actual = null;
        int requests = f.Backend.Requests.Count;
        try
        {
            await f.Source.CheckStatusPendingPurgeCancellationCanceledAsync(f.Window, f.Binding.Selector,
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
    public async Task StatusPendingPurgeCancellationActualCanceledTaskPrecedesNormalPendingAndCleanup()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: "cancellation-boundary",
            statusPendingPurgeCancellation: true);
        Task? start = null, selected = null, cleanup = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        var handle = f.Handle!;
        Task canceled = await ActualPendingCancellation(f);
        await Assert.That(f.Source.TryGetStatusPendingPurgeCancellationCanceled(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, handle, canceled, out var rejection)).IsTrue();
        await Assert.That(await f.Source.CheckStatusPendingPurgeCancellationAsync(f.Window, f.Binding.Selector,
            handle, default, task => selected = task)).IsEqualTo(SecretStatus.Pending);
        await Assert.That(f.Source.TryGetStatusPendingPurgeCancellationSelected(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, handle, canceled, selected!, out var observed)).IsTrue();
        await Assert.That(ReferenceEquals(observed!.Canceled, rejection)).IsTrue();
        var history = f.Window.Status;
        f.Source.RevokeStatusPendingPurgeCancellationSelected(f.Window);
        f.Backend.StatusBody = "{\"status\":\"Succeeded\"}";
        await Assert.That(await f.Source.CheckStatusPendingPurgeCancellationCleanupAsync(f.Window, f.Binding.Selector,
            handle, default, task => cleanup = task)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusPendingPurgeCancellationCleanup(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, handle, canceled, selected!, cleanup!, out var terminal)).IsTrue();
        await Assert.That(ReferenceEquals(terminal!.Selected, observed) &&
            ReferenceEquals(terminal.Canceled, rejection)).IsTrue();
        await Assert.That(ReferenceEquals(f.Window.Status, history)).IsTrue();
        await Assert.That(ReferenceEquals(canceled, selected) || ReferenceEquals(selected, cleanup)).IsFalse();
        await Assert.That(handle.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "POST")).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(3);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusPendingPurgeCancellationNormalCallRequiresActualPriorCancellation()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: "cancellation-boundary",
            statusPendingPurgeCancellation: true);
        await f.Start();
        int before = f.Backend.Requests.Count;
        Task? leaked = null;
        await Assert.That(async () => await f.Source.CheckStatusPendingPurgeCancellationAsync(f.Window,
            f.Binding.Selector, f.Handle!, default, task => leaked = task)).Throws<InvalidOperationException>();
        await Assert.That(leaked is null).IsTrue();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(before);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusPendingPurgeCancellationUncanceledOperandCannotBecomeCanceledWitness()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: "cancellation-boundary",
            statusPendingPurgeCancellation: true);
        await f.Start();
        int before = f.Backend.Requests.Count;
        Task? leaked = null;
        await Assert.That(async () => await f.Source.CheckStatusPendingPurgeCancellationCanceledAsync(f.Window,
            f.Binding.Selector, f.Handle!, default, task => leaked = task)).Throws<InvalidOperationException>();
        await Assert.That(leaked is null).IsTrue();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(before);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusPendingPurgeCancellationFabricatedCanceledTaskCannotReplaceActualTask()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: "cancellation-boundary",
            statusPendingPurgeCancellation: true);
        Task? start = null, selected = null;
        await f.Start(retained: task => start = task);
        Task canceled = await ActualPendingCancellation(f);
        using var other = new CancellationTokenSource();
        other.Cancel();
        Task fabricated = Task.FromCanceled<SecretStatus>(other.Token);
        await Assert.That(f.Source.TryGetStatusPendingPurgeCancellationCanceled(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, fabricated, out _)).IsFalse();
        await Assert.That(await f.Source.CheckStatusPendingPurgeCancellationAsync(f.Window, f.Binding.Selector,
            f.Handle!, default, task => selected = task)).IsEqualTo(SecretStatus.Pending);
        await Assert.That(f.Source.TryGetStatusPendingPurgeCancellationSelected(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, fabricated, selected!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusPendingPurgeCancellationSelected(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, canceled, selected!, out _)).IsTrue();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    public async Task StatusPendingPurgeCancellationStartAuthorityCannotCrossOtherProfiles(string boundary)
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: boundary,
            statusPendingPurge: boundary == "selected-contract", statusPendingPurgeIndependent: boundary == "independent-effect");
        Task? start = null;
        await f.Start(retained: task => start = task);
        await Assert.That(f.Source.TryGetStatusPendingPurgeCancellationStart(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        using var c = new Fixture("PurgeDeletedVault", "status.Pending", boundary: "cancellation-boundary",
            statusPendingPurgeCancellation: true);
        await c.Start(retained: task => start = task);
        await Assert.That(c.Source.TryGetStatusPendingPurgeStart(c.Window, c.Binding, c.Client,
            (DeletedVaultScope)c.Scope, c.Receipt, start!, c.Handle!, out _)).IsFalse();
        await Assert.That(c.Source.TryGetStatusPendingPurgeIndependentStart(c.Window, c.Binding, c.Client,
            (DeletedVaultScope)c.Scope, c.Receipt, start!, c.Handle!, out _)).IsFalse();
        await c.Source.SealAsync(c.Window);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusPendingPurgeCancellationHookCancellationCannotMintCanceledWitness()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: "cancellation-boundary",
            statusPendingPurgeCancellation: true);
        Task? start = null, native = null;
        await f.Start(retained: task => start = task);
        using var operand = new CancellationTokenSource();
        operand.Cancel();
        await Assert.That(async () => await f.Source.CheckStatusPendingPurgeCancellationCanceledAsync(f.Window,
            f.Binding.Selector, f.Handle!, operand.Token, task =>
            {
                native = task;
                throw new OperationCanceledException();
            })).Throws<OperationCanceledException>();
        await Assert.That(native is { IsCanceled: true }).IsTrue();
        await Assert.That(f.Source.TryGetStatusPendingPurgeCancellationCanceled(f.Window, f.Binding, f.Client,
            (DeletedVaultScope)f.Scope, f.Receipt, start!, f.Handle!, native!, out _)).IsFalse();
        await Assert.That(async () => await f.Source.CheckStatusPendingPurgeCancellationAsync(f.Window,
            f.Binding.Selector, f.Handle!, default)).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(0);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusPendingPurgeCancellationForeignHandleCannotConsumeCanceledSlot()
    {
        using var f = new Fixture("PurgeDeletedVault", "status.Pending", boundary: "cancellation-boundary",
            statusPendingPurgeCancellation: true);
        using var other = new Fixture("PurgeDeletedVault", "status.Pending", boundary: "cancellation-boundary",
            statusPendingPurgeCancellation: true);
        await f.Start();
        await other.Start();
        using var operand = new CancellationTokenSource();
        operand.Cancel();
        Task? leaked = null;
        await Assert.That(async () => await f.Source.CheckStatusPendingPurgeCancellationCanceledAsync(f.Window,
            f.Binding.Selector, other.Handle!, operand.Token, task => leaked = task)).Throws<InvalidOperationException>();
        await Assert.That(leaked is null).IsTrue();
        await ActualPendingCancellation(f);
        await Assert.That(await f.Source.CheckStatusPendingPurgeCancellationAsync(f.Window,
            f.Binding.Selector, f.Handle!, default)).IsEqualTo(SecretStatus.Pending);
        await f.Source.SealAsync(f.Window);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    public async Task StatusPendingPurgeCancellationDoesNotBlockGenericNonPurgePending(string boundary)
    {
        using var f = new Fixture("CreateOrUpdateVault", "status.Pending", boundary: boundary);
        f.AsyncStart();
        f.Backend.StartStatus = 201;
        f.Backend.StartBody = f.Backend.FinalBody!.Replace("Succeeded", "Updating", StringComparison.Ordinal);
        f.Backend.StatusBody = "{\"status\":\"Succeeded\"}";
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsTrue();
        await Assert.That(f.Backend.Requests.Any(r => r.Method == "PUT")).IsTrue();
        await f.Source.SealAsync(f.Window);
    }
}
