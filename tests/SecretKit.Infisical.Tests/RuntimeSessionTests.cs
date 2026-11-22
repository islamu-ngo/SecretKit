using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class RuntimeSessionTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(5);

    [Test]
    public async Task ExplicitOpenRetainsActualReceiptAndDoesNotStartMaintenance()
    {
        var clock = new Clock();
        using var wire = new Wire();
        using var bootstrap = SecretMaterial.FromText("bootstrap-canary");
        var attempt = new InfisicalRuntimeOpenAttempt();
        var result = await InfisicalRuntimeSession.OpenUniversalAsync(Options(wire, clock), bootstrap, attempt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await using var runtime = result.Value;
        await Assert.That(attempt.LoginReceipt!.Evidence).IsEqualTo(DispatchEvidence.Applied);
        bootstrap.Dispose();
        using var token = (await runtime.TokenSession.GetTokenAsync(default)).Value;
        await Assert.That(token.Material.Reveal()).IsEqualTo("runtime-token");
        await Assert.That(runtime.TokenSession.LastRenewal).IsNull();
        await Assert.That(wire.Paths.ToArray()).IsEquivalentTo(["/api/v1/auth/universal-auth/login"]);
        var repeated = await InfisicalRuntimeSession.OpenUniversalAsync(
            Options(wire, clock), bootstrap, attempt);
        await Assert.That(repeated.Status).IsEqualTo(SecretStatus.Invalid);
        await runtime.StopAsync();
        await Assert.That(token.Material.Reveal()).IsEqualTo("runtime-token");
        await Assert.That(wire.Disposed).IsFalse();
    }

    [Test]
    [Arguments(InfisicalTokenLifetime.Finite, 3600)]
    [Arguments(InfisicalTokenLifetime.Periodic, 0)]
    public async Task ExistingTokenCopiesAdmittedMaterialWithoutDispatch(
        InfisicalTokenLifetime lifetime, int maximum)
    {
        var clock = new Clock();
        using var wire = new Wire();
        using var supplied = SecretMaterial.FromText("supplied-token");
        var result = InfisicalRuntimeSession.CreateFromToken(
            Options(wire, clock, lifetime), supplied, Evidence(clock, lifetime, maximum));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await using var runtime = result.Value;
        supplied.Dispose();
        using var copy = (await runtime.TokenSession.GetTokenAsync(default)).Value;
        await Assert.That(copy.Material.Reveal()).IsEqualTo("supplied-token");
        await Assert.That(wire.Paths.IsEmpty).IsTrue();
        await runtime.StopAsync();
        await Assert.That(copy.Material.Reveal()).IsEqualTo("supplied-token");
        await Assert.That(wire.Disposed).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task MissingOrExpiredTokenTimingRequiresRecoveryWithoutDispatch(bool expired)
    {
        var clock = new Clock();
        using var wire = new Wire();
        using var supplied = SecretMaterial.FromText("supplied-token");
        var evidence = expired ? Evidence(clock, InfisicalTokenLifetime.Finite, 3600,
            clock.GetUtcNow().AddSeconds(-1)) : null;
        var result = InfisicalRuntimeSession.CreateFromToken(Options(wire, clock), supplied, evidence);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.RecoveryRequired);
        await Assert.That(wire.Paths.IsEmpty).IsTrue();
        await Assert.That(supplied.Reveal()).IsEqualTo("supplied-token");
    }

    [Test]
    public async Task CancellationBeforeDispatchConsumesAttemptWithoutAcquiringCredentials()
    {
        var clock = new Clock();
        using var wire = new Wire();
        using var bootstrap = SecretMaterial.FromText("bootstrap-canary");
        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        var attempt = new InfisicalRuntimeOpenAttempt();
        await Assert.That(async () => await InfisicalRuntimeSession.OpenUniversalAsync(
            Options(wire, clock), bootstrap, attempt, cancel.Token)).Throws<OperationCanceledException>();
        await Assert.That(wire.Paths.IsEmpty).IsTrue();
        var repeated = await InfisicalRuntimeSession.OpenUniversalAsync(Options(wire, clock), bootstrap, attempt);
        await Assert.That(repeated.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task CancellationAfterDispatchRetainsActualUncertainLoginReceipt()
    {
        var clock = new Clock();
        using var wire = new Wire { HoldLogin = true };
        using var bootstrap = SecretMaterial.FromText("bootstrap-canary");
        using var cancel = new CancellationTokenSource();
        var attempt = new InfisicalRuntimeOpenAttempt();
        var opening = InfisicalRuntimeSession.OpenUniversalAsync(
            Options(wire, clock), bootstrap, attempt, cancel.Token).AsTask();
        await wire.LoginEntered.Task.WaitAsync(Bound);
        await Assert.That(attempt.LoginReceipt!.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        cancel.Cancel();
        wire.LoginRelease.TrySetResult();
        await Assert.That(async () => await opening.WaitAsync(Bound)).Throws<OperationCanceledException>();
        await Assert.That(attempt.LoginReceipt.Evidence == DispatchEvidence.PossiblyDispatched ||
            attempt.LoginReceipt.Evidence == DispatchEvidence.Applied).IsTrue();
        await Assert.That(wire.Disposed).IsFalse();
    }

    [Test]
    public async Task ConcurrentOpenCannotReplaceAttemptReceiptOrDispatchTwice()
    {
        var clock = new Clock();
        using var wire = new Wire { HoldLogin = true };
        using var bootstrap = SecretMaterial.FromText("bootstrap-canary");
        var attempt = new InfisicalRuntimeOpenAttempt();
        var opening = InfisicalRuntimeSession.OpenUniversalAsync(
            Options(wire, clock), bootstrap, attempt).AsTask();
        await wire.LoginEntered.Task.WaitAsync(Bound);
        var receipt = attempt.LoginReceipt!;
        var repeated = await InfisicalRuntimeSession.OpenUniversalAsync(Options(wire, clock), bootstrap, attempt);
        await Assert.That(repeated.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(attempt.LoginReceipt!).IsSameReferenceAs(receipt);
        wire.LoginRelease.TrySetResult();
        await using var runtime = (await opening.WaitAsync(Bound)).Value;
        await Assert.That(wire.Paths.ToArray()).IsEquivalentTo(["/api/v1/auth/universal-auth/login"]);
    }

    [Test]
    public async Task LateLoginPublicationIsRejectedAfterCallerCancellation()
    {
        var clock = new Clock();
        using var cancel = new CancellationTokenSource();
        using var wire = new Wire { AfterLoginBody = cancel.Cancel };
        using var bootstrap = SecretMaterial.FromText("bootstrap-canary");
        var attempt = new InfisicalRuntimeOpenAttempt();
        await Assert.That(async () => await InfisicalRuntimeSession.OpenUniversalAsync(
            Options(wire, clock), bootstrap, attempt, cancel.Token)).Throws<OperationCanceledException>();
        await Assert.That(attempt.LoginReceipt!.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(wire.Paths.ToArray()).IsEquivalentTo(["/api/v1/auth/universal-auth/login"]);
        await Assert.That(bootstrap.Reveal()).IsEqualTo("bootstrap-canary");
    }

    [Test]
    [Arguments(InfisicalTokenLifetime.Unknown, 0, false)]
    [Arguments(InfisicalTokenLifetime.Finite, 0, true)]
    [Arguments(InfisicalTokenLifetime.Periodic, 0, true)]
    public async Task IndependentPolicyIsNotInventedFromLoginMaximum(
        InfisicalTokenLifetime lifetime, int maximum, bool dispatched)
    {
        var clock = new Clock();
        using var wire = new Wire { MaximumTtl = maximum };
        using var bootstrap = SecretMaterial.FromText("bootstrap-canary");
        var attempt = new InfisicalRuntimeOpenAttempt();
        // Periodic policy deliberately cannot cover the returned token's lifetime.
        var result = await InfisicalRuntimeSession.OpenUniversalAsync(
            Options(wire, clock, lifetime, TimeSpan.FromMinutes(5)), bootstrap, attempt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.RecoveryRequired);
        await Assert.That(!wire.Paths.IsEmpty).IsEqualTo(dispatched);
        if (dispatched)
            await Assert.That(attempt.LoginReceipt!.Evidence).IsEqualTo(DispatchEvidence.Applied);
    }

    [Test]
    public async Task IndependentlySelectedPeriodicPolicyAdmitsZeroMaximum()
    {
        var clock = new Clock();
        using var wire = new Wire { MaximumTtl = 0 };
        using var bootstrap = SecretMaterial.FromText("bootstrap-canary");
        var result = await InfisicalRuntimeSession.OpenUniversalAsync(
            Options(wire, clock, InfisicalTokenLifetime.Periodic), bootstrap, new());
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await using var runtime = result.Value;
        clock.Advance(TimeSpan.FromMinutes(9));
        await Assert.That(runtime.TokenSession.State).IsEqualTo(InfisicalTokenSessionState.RenewalDue);
        await Assert.That(runtime.TokenSession.LastRenewal).IsNull();
    }

    [Test]
    public async Task RejectedLoginPreservesEvidenceWithoutPublishingRuntime()
    {
        var clock = new Clock();
        using var wire = new Wire { LoginStatus = HttpStatusCode.Forbidden };
        using var bootstrap = SecretMaterial.FromText("bootstrap-canary");
        var attempt = new InfisicalRuntimeOpenAttempt();
        var result = await InfisicalRuntimeSession.OpenUniversalAsync(Options(wire, clock), bootstrap, attempt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(attempt.LoginReceipt!.Evidence).IsEqualTo(DispatchEvidence.Rejected);
        await Assert.That(bootstrap.Reveal()).IsEqualTo("bootstrap-canary");
    }

    [Test]
    public async Task InvalidLocalBudgetsFailBeforeBootstrapDispatch()
    {
        var clock = new Clock();
        using var wire = new Wire();
        using var bootstrap = SecretMaterial.FromText("bootstrap-canary");
        var options = new InfisicalRuntimeOptions
        {
            Origin = new("https://selected.test"),
            ClientId = "client",
            ProjectId = "project",
            Lifetime = InfisicalTokenLifetime.Finite,
            OriginalIssuedAt = clock.GetUtcNow(),
            RenewBefore = TimeSpan.Zero,
            TimeProvider = clock,
            Network = new() { Transport = InfisicalTransportOptions.HostControlled(wire) }
        };
        await Assert.That(async () => await InfisicalRuntimeSession.OpenUniversalAsync(
            options, bootstrap, new())).Throws<ArgumentException>();
        await Assert.That(wire.Paths.IsEmpty).IsTrue();
    }

    [Test]
    public async Task OpenFailureSanitizesExceptionGraphAndRetainsReceipt()
    {
        var clock = new Clock();
        using var wire = new Wire
        {
            AfterLoginBody = () => clock.Fail = true
        };
        using var bootstrap = SecretMaterial.FromText("bootstrap-canary");
        var attempt = new InfisicalRuntimeOpenAttempt();
        // Positive control: the same detector must observe a deliberate disclosure.
        await Assert.That(new Exception("bootstrap-canary").ToString().Contains(
            "bootstrap-canary", StringComparison.Ordinal)).IsTrue();
        InvalidOperationException? observed = null;
        try
        {
            await InfisicalRuntimeSession.OpenUniversalAsync(Options(wire, clock), bootstrap, attempt);
        }
        catch (InvalidOperationException error)
        {
            observed = error;
        }
        finally { clock.Fail = false; }
        await Assert.That(observed).IsNotNull();
        await Assert.That(observed!.InnerException).IsNull();
        await Assert.That(observed.ToString().Contains("bootstrap-canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That(attempt.LoginReceipt!.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(wire.Disposed).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RetirementClosesBothChildrenBeforeWaitingAndLatchesBound(bool throwingCallback)
    {
        var clock = new Clock();
        using var wire = new Wire { HoldRead = true, ThrowOnCancel = throwingCallback };
        using var supplied = SecretMaterial.FromText("supplied-token");
        var runtime = InfisicalRuntimeSession.CreateFromToken(
            Options(wire, clock), supplied, Evidence(clock, InfisicalTokenLifetime.Finite, 3600)).Value;
        Task read = runtime.Client.ReadAsync(Reference(runtime.Client)).AsTask();
        await wire.ReadEntered.Task.WaitAsync(Bound);
        Task deadlineArmed = clock.WatchTimer(TimeSpan.FromSeconds(3));
        Task stop = runtime.StopAsync();
        await deadlineArmed.WaitAsync(Bound);
        await wire.CancelEntered.Task.WaitAsync(Bound);
        await Assert.That(runtime.StopAsync()).IsSameReferenceAs(stop);
        await Assert.That(runtime.TokenSession.State).IsEqualTo(InfisicalTokenSessionState.Stopped);
        await Assert.That(async () => await runtime.TokenSession.GetTokenAsync(default))
            .Throws<ObjectDisposedException>();
        await Assert.That(async () => await runtime.Client.ReadAsync(Reference(runtime.Client)))
            .Throws<ObjectDisposedException>();
        clock.Advance(TimeSpan.FromSeconds(3));
        await Assert.That(async () => await stop.WaitAsync(Bound)).Throws<TimeoutException>();
        wire.ReadRelease.TrySetResult();
        await Assert.That(async () => await read.WaitAsync(Bound)).Throws<OperationCanceledException>();
        await Assert.That(async () => await runtime.DisposeAsync()).Throws<TimeoutException>();
        await Assert.That(wire.Disposed).IsFalse();
        await Assert.That(supplied.Reveal()).IsEqualTo("supplied-token");
    }

    [Test]
    public async Task ThrowingReentrantStopCallbackCannotLeakOrReplaceSharedResult()
    {
        var clock = new Clock();
        using var wire = new Wire { HoldRead = true, ThrowOnCancel = true };
        using var supplied = SecretMaterial.FromText("supplied-token");
        var runtime = InfisicalRuntimeSession.CreateFromToken(
            Options(wire, clock), supplied, Evidence(clock, InfisicalTokenLifetime.Finite, 3600)).Value;
        Task? reentrant = null;
        wire.OnCancel = () => reentrant = runtime.StopAsync();
        Task read = runtime.Client.ReadAsync(Reference(runtime.Client)).AsTask();
        await wire.ReadEntered.Task.WaitAsync(Bound);
        Task stop = runtime.StopAsync();
        await wire.CancelEntered.Task.WaitAsync(Bound);
        wire.ReadRelease.TrySetResult();
        await Assert.That(async () => await read.WaitAsync(Bound)).Throws<OperationCanceledException>();
        InvalidOperationException? observed = null;
        try
        {
            await stop.WaitAsync(Bound);
        }
        catch (InvalidOperationException error)
        {
            observed = error;
        }
        await Assert.That(observed).IsNotNull();
        await Assert.That(observed!.InnerException).IsNull();
        await Assert.That(observed.ToString().Contains("bootstrap-canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That(reentrant!).IsSameReferenceAs(stop);
        await Assert.That(runtime.StopAsync()).IsSameReferenceAs(stop);
        await Assert.That(runtime.TokenSession.State).IsEqualTo(InfisicalTokenSessionState.Stopped);
    }

    [Test]
    public async Task HeldReadAndRenewalRetireTogetherWithoutSequentialTimeoutBudgets()
    {
        var clock = new Clock();
        using var wire = new Wire { HoldRead = true, HoldRenewal = true };
        using var supplied = SecretMaterial.FromText("supplied-token");
        var runtime = InfisicalRuntimeSession.CreateFromToken(
            Options(wire, clock), supplied, Evidence(clock, InfisicalTokenLifetime.Finite, 3600)).Value;
        Task renewal = runtime.TokenSession.RenewAsync().AsTask();
        await wire.RenewalEntered.Task.WaitAsync(Bound);
        Task read = runtime.Client.ReadAsync(Reference(runtime.Client)).AsTask();
        await wire.ReadEntered.Task.WaitAsync(Bound);
        Task armed = clock.WatchTimer(TimeSpan.FromSeconds(3));
        Task stop = runtime.StopAsync();
        await armed.WaitAsync(Bound);
        await wire.CancelEntered.Task.WaitAsync(Bound);
        await wire.RenewalCancelEntered.Task.WaitAsync(Bound);
        await Assert.That(runtime.TokenSession.State).IsEqualTo(InfisicalTokenSessionState.Stopped);
        clock.Advance(TimeSpan.FromSeconds(3));
        await Assert.That(async () => await stop.WaitAsync(Bound)).Throws<TimeoutException>();
        wire.ReadRelease.TrySetResult();
        wire.RenewalRelease.TrySetResult();
        await Assert.That(async () => await read.WaitAsync(Bound)).Throws<OperationCanceledException>();
        await Assert.That(async () => await renewal.WaitAsync(Bound)).Throws<OperationCanceledException>();
        await Assert.That(runtime.TokenSession.LastRenewal!.Evidence)
            .IsEqualTo(InfisicalRenewalEvidence.PossiblyDispatched);
        await Assert.That(async () => await runtime.DisposeAsync()).Throws<TimeoutException>();
        await Assert.That(wire.Disposed).IsFalse();
    }

    [Test]
    public async Task TokenHandoffDoesNotRequireBootstrapIdentity()
    {
        var clock = new Clock();
        using var wire = new Wire();
        using var token = SecretMaterial.FromText("selected-token");
        var result = InfisicalRuntimeSession.CreateFromToken(
            Options(wire, clock, clientId: string.Empty), token,
            Evidence(clock, InfisicalTokenLifetime.Finite, 3600));
        await Assert.That(result.IsSuccess).IsTrue();
        await using var runtime = result.Value;
        using InfisicalAccessToken copy = (await runtime.TokenSession.GetTokenAsync(default)).Value;
        await Assert.That(copy.Material.Reveal()).IsEqualTo("selected-token");
        await Assert.That(wire.Paths.IsEmpty).IsTrue();
    }

    [Test]
    public async Task RenewalAfterTokenExpirationPreservesExpiredStateInsteadOfRecoveryRequired()
    {
        var clock = new Clock();
        using var wire = new Wire { HoldRenewal = true };
        using var bootstrap = SecretMaterial.FromText("bootstrap-canary");
        var opened = await InfisicalRuntimeSession.OpenUniversalAsync(Options(wire, clock), bootstrap, new());
        await Assert.That(opened.Status).IsEqualTo(SecretStatus.Success);
        await using var runtime = opened.Value;

        Task<SecretOutcome<InfisicalTokenRenewal>> renewTask = runtime.TokenSession.RenewAsync().AsTask();
        await wire.RenewalEntered.Task.WaitAsync(Bound);
        // Advance clock past the 600s token lifetime while renewal response is still in flight.
        clock.Advance(TimeSpan.FromSeconds(700));
        wire.RenewalRelease.TrySetResult();

        SecretOutcome<InfisicalTokenRenewal> renewal = await renewTask;
        await Assert.That(renewal.IsSuccess).IsFalse();
        await Assert.That(runtime.TokenSession.State).IsEqualTo(InfisicalTokenSessionState.Expired);
    }

    [Test]
    public async Task FatalBootstrapFaultSettlesBothWaitersWithoutAcquisitionReplay()
    {
        var clock = new Clock();
        using var wire = new Wire();
        var fault = new SyntheticMemoryFault();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int acquisitions = 0;
        var runtime = InfisicalRuntimeSession.CreateDeferred(Options(wire, clock), async _ =>
        {
            acquisitions++;
            await release.Task;
            throw fault;
        });
        var first = runtime.EnsureAuthenticatedAsync().AsTask();
        var second = runtime.EnsureAuthenticatedAsync().AsTask();
        release.SetResult();
        try
        {
            await ExpectOriginal(first, fault);
            await ExpectOriginal(second, fault);
            await ExpectOriginal(runtime.EnsureAuthenticatedAsync().AsTask(), fault);
            await Assert.That(acquisitions).IsEqualTo(1);
            await Assert.That(runtime.OpeningAttempt.LoginReceipt).IsNull();
            await Assert.That(wire.Paths.IsEmpty).IsTrue();
        }
        finally { await ExpectOriginal(runtime.StopAsync(), fault); }
    }

    [Test]
    public async Task FatalRenewalAfterDispatchRetainsReceiptAndCannotReplay()
    {
        var fault = new SyntheticMemoryFault();
        using var wire = new Wire { HoldRenewal = true, RenewalFault = fault };
        var clock = new Clock();
        using var material = SecretMaterial.FromText("selected-token");
        var runtime = InfisicalRuntimeSession.CreateFromToken(Options(wire, clock), material,
            Evidence(clock, InfisicalTokenLifetime.Finite, 3600)).Value;
        var session = runtime.TokenSession;
        var first = session.RenewAsync().AsTask();
        await wire.RenewalEntered.Task.WaitAsync(Bound);
        var second = session.RenewAsync().AsTask();
        wire.RenewalRelease.SetResult();
        try
        {
            await ExpectOriginal(first, fault);
            await ExpectOriginal(second, fault);
            await Assert.That(session.LastRenewal!.Evidence).IsEqualTo(InfisicalRenewalEvidence.PossiblyDispatched);
            await Assert.That((await session.RenewAsync()).Status).IsEqualTo(SecretStatus.RecoveryRequired);
            await Assert.That(wire.Paths.ToArray()).IsEquivalentTo(["/api/v1/auth/token/renew"]);
        }
        finally { await ExpectOriginal(runtime.StopAsync(), fault); }
    }

    [Test]
    public async Task DirectOpeningDoesNotWrapFatalPolicyClockFault()
    {
        using var wire = new Wire();
        var clock = new Clock();
        var options = Options(wire, clock);
        using var material = SecretMaterial.FromText("selected");
        var fault = new SyntheticMemoryFault();
        clock.Fatal = fault;
        await ExpectOriginal(InfisicalRuntimeSession.OpenUniversalAsync(options, material, new()).AsTask(), fault);
        await Assert.That(wire.Paths.IsEmpty).IsTrue();
    }

    [Test]
    [Arguments(3600, "3600.0000005", true)]
    [Arguments(3600, "3599.9999995", true)]
    [Arguments(3600, "3600.000002", false)]
    [Arguments(0, "-0.0000005", false)]
    [Arguments(0, "-0.0", true)]
    [Arguments(0, "1e500", false)]
    public async Task RenewalMaximumToleranceDoesNotRelaxLifetimePolicy(int selected, string reported, bool admitted)
    {
        using var wire = new Wire { RenewalMaximum = reported };
        var clock = new Clock();
        var lifetime = selected == 0 ? InfisicalTokenLifetime.Periodic : InfisicalTokenLifetime.Finite;
        using var original = SecretMaterial.FromText("selected-token");
        await using var runtime = InfisicalRuntimeSession.CreateFromToken(Options(wire, clock, lifetime), original,
            Evidence(clock, lifetime, selected)).Value;
        var result = await runtime.TokenSession.RenewAsync();
        if (admitted)
        {
            await Assert.That(result.Value.Evidence).IsEqualTo(InfisicalRenewalEvidence.Applied);
            using var copy = (await runtime.TokenSession.GetTokenAsync(default)).Value;
            await Assert.That(copy.Material.Reveal()).IsEqualTo("renewed");
        }
        else
        {
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
            await Assert.That(runtime.TokenSession.State).IsEqualTo(InfisicalTokenSessionState.RecoveryRequired);
            await Assert.That(runtime.TokenSession.LastRenewal!.Evidence).IsEqualTo(InfisicalRenewalEvidence.PossiblyDispatched);
        }
    }

    [Test]
    public async Task HeldBootstrapDoesNotLeaveClientAdmissionOpenAfterStopTimeout()
    {
        var clock = new Clock();
        using var wire = new Wire();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var runtime = InfisicalRuntimeSession.CreateDeferred(Options(wire, clock), async _ =>
        {
            entered.SetResult();
            await release.Task;
            return SecretMaterial.FromText("late-bootstrap");
        });
        var opening = runtime.EnsureAuthenticatedAsync().AsTask();
        try
        {
            await entered.Task.WaitAsync(Bound);
            var stop = runtime.StopAsync();
            clock.Advance(TimeSpan.FromSeconds(3));
            await Assert.That(async () => await stop.WaitAsync(Bound)).Throws<TimeoutException>();
            var foreign = new SecretReference(new SecretAuthority(), new InfisicalSecretAddress("project", "test", "/", "key"));
            await Assert.That(async () => await runtime.Client.ReadAsync(foreign)).Throws<ObjectDisposedException>();
            await Assert.That(wire.Paths.IsEmpty).IsTrue();
        }
        finally
        {
            release.TrySetResult();
            await Assert.That(async () => await opening.WaitAsync(Bound)).Throws<OperationCanceledException>();
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OpeningTimerDisposalFailureCannotPublishSession(bool fatal)
    {
        var clock = new Clock();
        using var wire = new Wire { HoldLogin = true };
        var runtime = InfisicalRuntimeSession.CreateDeferred(Options(wire, clock),
            _ => ValueTask.FromResult(SecretMaterial.FromText("bootstrap")));
        var memoryFault = new SyntheticMemoryFault();
        clock.NextTimerDisposalFault = fatal ? memoryFault : new InvalidOperationException("synthetic cleanup fault");
        var first = runtime.EnsureAuthenticatedAsync().AsTask();
        try
        {
            await wire.LoginEntered.Task.WaitAsync(Bound);
            var second = runtime.EnsureAuthenticatedAsync().AsTask();
            wire.LoginRelease.SetResult();
            if (fatal)
            {
                await ExpectOriginal(first, memoryFault);
                await ExpectOriginal(second, memoryFault);
                await ExpectOriginal(runtime.EnsureAuthenticatedAsync().AsTask(), memoryFault);
            }
            else
            {
                await Assert.That((await first.WaitAsync(Bound)).Status).IsEqualTo(SecretStatus.Unavailable);
                await Assert.That((await second.WaitAsync(Bound)).Status).IsEqualTo(SecretStatus.Unavailable);
                await Assert.That((await runtime.EnsureAuthenticatedAsync()).Status).IsEqualTo(SecretStatus.Unavailable);
            }
            await Assert.That(runtime.IsAuthenticated).IsFalse();
            await Assert.That(runtime.OpeningAttempt.LoginReceipt!.Evidence).IsEqualTo(DispatchEvidence.Applied);
            await Assert.That(wire.Paths.ToArray()).IsEquivalentTo(["/api/v1/auth/universal-auth/login"]);
        }
        finally
        {
            wire.LoginRelease.TrySetResult();
            if (fatal) await ExpectOriginal(runtime.StopAsync(), memoryFault);
            else await runtime.StopAsync().WaitAsync(Bound);
        }
    }

    private static async Task ExpectOriginal(Task task, SyntheticMemoryFault expected)
    {
        SyntheticMemoryFault? actual = null;
        try { await task.WaitAsync(Bound); }
        catch (SyntheticMemoryFault fault) { actual = fault; }
        await Assert.That(ReferenceEquals(actual, expected)).IsTrue();
    }

    private sealed class SyntheticMemoryFault : OutOfMemoryException;

    private static InfisicalRuntimeOptions Options(Wire wire, Clock clock,
        InfisicalTokenLifetime lifetime = InfisicalTokenLifetime.Finite, TimeSpan? period = null,
        string clientId = "client") => new()
        {
            Origin = new("https://selected.test"),
            ClientId = clientId,
            ProjectId = "project",
            Lifetime = lifetime,
            OriginalIssuedAt = clock.GetUtcNow(),
            Period = lifetime == InfisicalTokenLifetime.Periodic ? period ?? TimeSpan.FromMinutes(10) : null,
            RenewBefore = TimeSpan.FromMinutes(1),
            RequestTimeout = TimeSpan.FromSeconds(10),
            TimeProvider = clock,
            Network = new()
            {
                Transport = InfisicalTransportOptions.HostControlled(wire),
                ShutdownTimeout = TimeSpan.FromSeconds(3)
            }
        };

    private static InfisicalTokenLifetimeEvidence Evidence(Clock clock, InfisicalTokenLifetime lifetime,
        int maximum, DateTimeOffset? expires = null) => new()
        {
            OriginalIssuedAt = clock.GetUtcNow().AddMinutes(-1),
            ExpiresAt = expires ?? clock.GetUtcNow().AddMinutes(10),
            Lifetime = lifetime,
            ReportedMaximumTtl = TimeSpan.FromSeconds(maximum),
            Period = lifetime == InfisicalTokenLifetime.Periodic ? TimeSpan.FromMinutes(10) : null
        };

    private static SecretReference Reference(InfisicalClient client) =>
        new(client.Authority, new InfisicalSecretAddress("project", "test", "/", "key"));

    private sealed class Wire : HttpMessageHandler
    {
        internal System.Collections.Concurrent.ConcurrentQueue<string> Paths { get; } = new();
        internal TaskCompletionSource LoginEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource LoginRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource ReadEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource ReadRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource CancelEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource RenewalEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource RenewalRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource RenewalCancelEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool HoldLogin { get; init; }
        internal bool HoldRead { get; init; }
        internal bool HoldRenewal { get; init; }
        internal Exception? RenewalFault { get; init; }
        internal string RenewalMaximum { get; init; } = "3600";
        internal bool ThrowOnCancel { get; init; }
        internal bool Disposed { get; private set; }
        internal int MaximumTtl { get; init; } = 3600;
        internal HttpStatusCode LoginStatus { get; init; } = HttpStatusCode.OK;
        internal Action? AfterLoginBody { get; init; }
        internal Action? OnCancel { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string path = request.RequestUri!.AbsolutePath;
            Paths.Enqueue(path);
            if (path == "/api/v1/auth/universal-auth/login")
            {
                LoginEntered.TrySetResult();
                if (HoldLogin) await LoginRelease.Task;
                return new(LoginStatus)
                {
                    Content = new LoginContent(JsonSerializer.Serialize(new
                    {
                        accessToken = "runtime-token",
                        tokenType = "Bearer",
                        expiresIn = 600,
                        accessTokenMaxTTL = MaximumTtl
                    }), AfterLoginBody)
                };
            }
            if (path == "/api/v1/auth/token/renew")
            {
                using var renewalRegistration = cancellationToken.Register(
                    () => RenewalCancelEntered.TrySetResult());
                RenewalEntered.TrySetResult();
                if (HoldRenewal) await RenewalRelease.Task;
                if (RenewalFault is { } fault) throw fault;
                cancellationToken.ThrowIfCancellationRequested();
                return new(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        $$"""{"accessToken":"renewed","tokenType":"Bearer","expiresIn":600,"accessTokenMaxTTL":{{RenewalMaximum}}}""")
                };
            }
            using var registration = cancellationToken.Register(() =>
            {
                OnCancel?.Invoke();
                CancelEntered.TrySetResult();
                if (ThrowOnCancel) throw new InvalidOperationException("bootstrap-canary");
            });
            ReadEntered.TrySetResult();
            if (HoldRead) await ReadRelease.Task;
            cancellationToken.ThrowIfCancellationRequested();
            return new(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"secret":{"secretKey":"key","secretValue":"value","secretValueHidden":false}}""")
            };
        }

        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            LoginRelease.TrySetResult();
            ReadRelease.TrySetResult();
            RenewalRelease.TrySetResult();
            base.Dispose(disposing);
        }
    }

    private sealed class LoginContent(string json, Action? after) : ByteArrayContent(Encoding.UTF8.GetBytes(json))
    {
        private int _disposed;
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (Interlocked.Exchange(ref _disposed, 1) == 0) after?.Invoke();
        }
    }

    private sealed class Clock : TimeProvider
    {
        private readonly object _gate = new();
        private readonly List<ManualTimer> _timers = [];
        private readonly Dictionary<TimeSpan, TaskCompletionSource> _watches = [];
        private DateTimeOffset _now = new(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
        internal bool Fail { get; set; }
        internal Exception? Fatal { get; set; }
        internal Exception? NextTimerDisposalFault;
        public override DateTimeOffset GetUtcNow()
        {
            if (Fatal is { } fault) throw fault;
            if (Fail) throw new InvalidOperationException("bootstrap-canary");
            lock (_gate) return _now;
        }
        internal Task WatchTimer(TimeSpan due)
        {
            lock (_gate)
            {
                var signal = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                _watches[due] = signal;
                return signal.Task;
            }
        }
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new ManualTimer(this, callback, state, Interlocked.Exchange(ref NextTimerDisposalFault, null));
            lock (_gate)
            {
                _timers.Add(timer);
                timer.Change(dueTime, period);
                if (_watches.TryGetValue(dueTime, out var watch)) watch.TrySetResult();
            }
            return timer;
        }
        internal void Advance(TimeSpan elapsed)
        {
            List<ManualTimer> due;
            lock (_gate)
            {
                _now += elapsed;
                due = _timers.Where(timer => timer.Due <= _now).ToList();
                foreach (var timer in due) timer.Due = DateTimeOffset.MaxValue;
            }
            foreach (var timer in due) timer.Fire();
        }
        private sealed class ManualTimer(Clock owner, TimerCallback callback, object? state, Exception? disposalFault) : ITimer
        {
            internal DateTimeOffset Due { get; set; }
            private bool _disposed;
            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                lock (owner._gate)
                {
                    if (_disposed) return false;
                    Due = dueTime == Timeout.InfiniteTimeSpan ? DateTimeOffset.MaxValue : owner._now + dueTime;
                    return true;
                }
            }
            internal void Fire() => callback(state);
            public void Dispose()
            {
                lock (owner._gate)
                {
                    if (_disposed) return;
                    _disposed = true;
                    owner._timers.Remove(this);
                }
                if (disposalFault is not null) throw disposalFault;
            }
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
