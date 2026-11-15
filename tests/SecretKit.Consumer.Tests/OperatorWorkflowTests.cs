using SecretKit.Core;
using SecretKit.Samples.OperatorWorkflow;

namespace SecretKit.Consumer.Tests;

public sealed class OperatorWorkflowTests
{
    [Test]
    [Arguments("concealed", "INVENTORY_Unknown")]
    [Arguments("missing-route", "INVENTORY_Unknown")]
    [Arguments("incomplete", "INVENTORY_INCOMPLETE")]
    [Arguments("managed", "PREFLIGHT_BLOCKED")]
    [Arguments("unknown-rotation", "PREFLIGHT_BLOCKED")]
    [Arguments("imported", "PREFLIGHT_BLOCKED")]
    [Arguments("unknown-policy", "POLICY_UNESTABLISHED")]
    [Arguments("null-policy", "POLICY_UNESTABLISHED")]
    [Arguments("changed-revision", "REVIEW_CHANGED")]
    [Arguments("read-denied", "READINESS_Denied")]
    [Arguments("noncanonical", "PREFLIGHT_BLOCKED")]
    public async Task UnsafeObservationNeverReachesApply(string fault, string expected)
    {
        using var provider = new OfflineProvider { Fault = fault };
        using var output = new StringWriter();

        int code = await OperatorWorkflow.RunAsync(provider, output);

        await Assert.That(code).IsEqualTo(1);
        await Assert.That(output.ToString()).Contains(expected);
        await Assert.That(provider.ApplyAttempts).IsEqualTo(0);
        await Assert.That(provider.Values["FIRST"]).IsEqualTo("original");
        await Assert.That(provider.SignOuts).IsEqualTo(1);
    }

    [Test]
    [Arguments("pending", "APPLY_Pending", "original", "original", DispatchEvidence.Pending)]
    [Arguments("partial", "APPLY_PossiblyDispatched", "replacement", "original", DispatchEvidence.PossiblyDispatched)]
    [Arguments("lost-response", "APPLY_PossiblyDispatched", "replacement", "replacement", DispatchEvidence.PossiblyDispatched)]
    [Arguments("apply-denied", "APPLY_Rejected", "original", "original", DispatchEvidence.Rejected)]
    public async Task UnsettledApplyRetainsEvidenceWithoutReplay(string fault, string expected,
        string firstValue, string secondValue, DispatchEvidence evidence)
    {
        using var provider = new OfflineProvider { Fault = fault };
        using var output = new StringWriter();

        int code = await OperatorWorkflow.RunAsync(provider, output);

        await Assert.That(code).IsEqualTo(1);
        await Assert.That(output.ToString()).Contains(expected);
        await Assert.That(output.ToString()).Contains(evidence.ToString());
        await Assert.That(provider.ApplyAttempts).IsEqualTo(1);
        await Assert.That(provider.Values["FIRST"]).IsEqualTo(firstValue);
        await Assert.That(provider.Values["SECOND"]).IsEqualTo(secondValue);
        await Assert.That(provider.SignOuts).IsEqualTo(1);
    }

    [Test]
    public async Task ReviewedApplyVerifiesIntendedIdentityAndSignsOutWithoutDisclosure()
    {
        using var provider = new OfflineProvider();
        using var output = new StringWriter();

        int code = await OperatorWorkflow.RunAsync(provider, output);

        await Assert.That(code).IsEqualTo(0);
        await Assert.That(provider.Values["FIRST"]).IsEqualTo("replacement");
        await Assert.That(provider.Values["SECOND"]).IsEqualTo("replacement");
        await Assert.That(provider.ApplyAttempts).IsEqualTo(1);
        await Assert.That(provider.RuntimeReads).IsEqualTo(4);
        await Assert.That(provider.SignOuts).IsEqualTo(1);
        await Assert.That(output.ToString()).Contains("READY");
        foreach (string protectedText in new[] { "replacement", "original", "operator-runtime",
            "operator-admin", "project", "FIRST", "SECOND", "private-comment", "private-approval" })
            await Assert.That(output.ToString().Contains(protectedText, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task SignoutResponseLossReportsUncertaintyWithoutAnotherRevocation()
    {
        using var provider = new OfflineProvider { Fault = "signout-loss" };
        using var output = new StringWriter();

        int code = await OperatorWorkflow.RunAsync(provider, output);

        await Assert.That(code).IsEqualTo(1);
        await Assert.That(provider.SignOuts).IsEqualTo(1);
        await Assert.That(output.ToString()).Contains("SIGNOUT_PossiblyDispatched");
    }

    [Test]
    public async Task CancellationAfterCommitPreservesEvidenceAndSignsOutWithoutReplay()
    {
        using var provider = new OfflineProvider { Fault = "hold-apply" };
        using var output = new StringWriter();
        using var cancellation = new CancellationTokenSource();
        Task entered = provider.ApplyEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Task<int> run = OperatorWorkflow.RunAsync(provider, output, cancellationToken: cancellation.Token);
        try
        {
            await entered;
            cancellation.Cancel();
            int code = await run.WaitAsync(TimeSpan.FromSeconds(5));

            await Assert.That(code).IsEqualTo(1);
            await Assert.That(output.ToString()).Contains("APPLY_PossiblyDispatched");
            await Assert.That(output.ToString()).Contains("CANCELED");
            await Assert.That(provider.Values["FIRST"]).IsEqualTo("replacement");
            await Assert.That(provider.Values["SECOND"]).IsEqualTo("replacement");
            await Assert.That(provider.ApplyAttempts).IsEqualTo(1);
            await Assert.That(provider.SignOuts).IsEqualTo(1);
        }
        finally { provider.ApplyRelease.TrySetResult(); }
    }

    [Test]
    public async Task SignoutDeadlineRetainsObservableReceiptWithoutReplay()
    {
        using var provider = new OfflineProvider { Fault = "hold-signout" };
        using var output = new StringWriter();
        var clock = new SignoutClock();
        Task<int> pending = OperatorWorkflow.RunAsync(provider, output, clock);
        await provider.SignoutEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        clock.Expire();

        int code = await pending.WaitAsync(TimeSpan.FromSeconds(5));

        await Assert.That(code).IsEqualTo(1);
        await Assert.That(provider.SignOuts).IsEqualTo(1);
        await Assert.That(output.ToString()).Contains("SIGNOUT_PossiblyDispatched");
    }

    private sealed class SignoutClock : TimeProvider
    {
        private Timer? _timer;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            _timer = new Timer(callback, state);
            return _timer;
        }
        internal void Expire() => (_timer ?? throw new InvalidOperationException("Sign-out timer was not armed.")).Fire();
        private sealed class Timer(TimerCallback callback, object? state) : ITimer
        {
            private bool _disposed;
            public bool Change(TimeSpan dueTime, TimeSpan period) => !_disposed;
            internal void Fire() { if (!_disposed) callback(state); }
            public void Dispose() => _disposed = true;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
