using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Release.Tests;

public sealed class NativeCaseContractTests
{
    private static NativeCaseDefinition Definition(string variant = "selected") =>
        new(new("provider", "operation", variant, "scope", "selected-contract"), "Client.ReadAsync(Input,CancellationToken)");

    private static ValueTask Observe(NativeCaseProbe probe, CancellationToken _)
    {
        probe.Contract(true, NativeFailure.ContractMismatch);
        probe.Effect(NativeObservation.Matched);
        return ValueTask.CompletedTask;
    }

    [Test]
    public async Task DuplicateRegistrationIsRejected()
    {
        var registry = new NativeCaseRegistry();
        var registration = new NativeCaseRegistration(Definition(), Observe);
        registry.Add(registration);
        await Assert.That(() => registry.Add(registration)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task UnknownKeyOrWrongFullMemberIsRejected(bool wrongMember)
    {
        var registry = new NativeCaseRegistry();
        registry.Add(new(wrongMember ? Definition() with { Member = "Client.ReadAsync(Other,CancellationToken)" }
            : Definition("unknown"), Observe));
        await Assert.That(() => registry.ValidateAgainst([Definition()])).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task MissingRegistrationProducesFailedRow()
    {
        IReadOnlyList<NativeCaseResult> results = await NativeCaseRunner.RunAsync(new(), [Definition()], CancellationToken.None);
        await Assert.That(results.Count).IsEqualTo(1);
        await Assert.That(results[0].Passed).IsFalse();
        await Assert.That(results[0].ReasonCode).IsEqualTo("missing-registration");
    }

    [Test]
    [Arguments(false, false, "missing-contract")]
    [Arguments(false, true, "missing-contract")]
    [Arguments(true, false, "missing-effect")]
    [Arguments(true, true, "observed")]
    public async Task CompletionRequiresContractAndIndependentEffect(bool contract, bool effect, string reason)
    {
        var registry = new NativeCaseRegistry();
        registry.Add(new(Definition(), (probe, _) =>
        {
            if (contract) probe.Contract(true, NativeFailure.ContractMismatch);
            if (effect) probe.Effect(NativeObservation.Matched);
            return ValueTask.CompletedTask;
        }));
        NativeCaseResult result = (await NativeCaseRunner.RunAsync(registry, [Definition()], CancellationToken.None))[0];
        await Assert.That(result.Passed).IsEqualTo(contract && effect);
        await Assert.That(result.EffectObserved).IsEqualTo(effect);
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
    }

    [Test]
    [Arguments((int)NativeObservation.Unavailable, "observer-unavailable")]
    [Arguments((int)NativeObservation.Mismatched, "effect-mismatch")]
    public async Task FailedObserverCannotBeOverwritten(int observation, string reason)
    {
        var registry = new NativeCaseRegistry();
        registry.Add(new(Definition(), (probe, _) =>
        {
            probe.Contract(true, NativeFailure.ContractMismatch);
            try { probe.Effect((NativeObservation)observation); }
            catch (NativeCaseFailureException) { }
            probe.Effect(NativeObservation.Matched);
            return ValueTask.CompletedTask;
        }));
        NativeCaseResult result = (await NativeCaseRunner.RunAsync(registry, [Definition()], CancellationToken.None))[0];
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
    }

    [Test]
    [Arguments((int)NativeFailure.ContractMismatch, "contract-mismatch")]
    [Arguments((int)NativeFailure.MissingInput, "missing-input")]
    [Arguments((int)NativeFailure.MissingPrerequisite, "missing-prerequisite")]
    [Arguments((int)NativeFailure.DeadlineExceeded, "deadline-exceeded")]
    public async Task FailedContractThrowsAndRemainsFailed(int failure, string reason)
    {
        var registry = new NativeCaseRegistry();
        registry.Add(new(Definition(), (probe, _) =>
        {
            probe.Contract(false, (NativeFailure)failure);
            throw new InvalidOperationException("must-not-reach");
        }));
        NativeCaseResult result = (await NativeCaseRunner.RunAsync(registry, [Definition()], CancellationToken.None))[0];
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
    }

    [Test]
    public async Task CleanupFailureInvalidatesObservedEffect()
    {
        var registry = new NativeCaseRegistry();
        bool cleaned = false;
        registry.Add(new(Definition(), (probe, token) =>
        {
            try { return Observe(probe, token); }
            finally
            {
                cleaned = true;
                probe.Contract(false, NativeFailure.CleanupIncomplete);
            }
        }));
        NativeCaseResult result = (await NativeCaseRunner.RunAsync(registry, [Definition()], CancellationToken.None))[0];
        await Assert.That(cleaned).IsTrue();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.EffectObserved).IsTrue();
        await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
    }

    [Test]
    [Arguments("missing-input", "missing-input")]
    [Arguments("observer-unavailable", "observer-unavailable")]
    [Arguments("synthetic-sensitive-value", "unexpected-failure")]
    public async Task DirectBoundedFailureCannotPassAfterObservedEffect(string thrown, string reason)
    {
        var registry = new NativeCaseRegistry();
        registry.Add(new(Definition(), (probe, token) =>
        {
            Observe(probe, token);
            throw new NativeCaseFailureException(thrown);
        }));
        NativeCaseResult result = (await NativeCaseRunner.RunAsync(registry, [Definition()], CancellationToken.None))[0];
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(JsonSerializer.Serialize(result).Contains("synthetic-sensitive-value", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task RawExceptionDataIsNotReported()
    {
        var registry = new NativeCaseRegistry();
        registry.Add(new(Definition(), (_, _) => throw new InvalidOperationException("synthetic-sensitive-value")));
        NativeCaseResult result = (await NativeCaseRunner.RunAsync(registry, [Definition()], CancellationToken.None))[0];
        await Assert.That(result.ReasonCode).IsEqualTo("unexpected-failure");
        await Assert.That(JsonSerializer.Serialize(result).Contains("synthetic-sensitive-value", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task CancellationRetainsCompletedRowsAndFailsUnfinishedRows()
    {
        using var cancellation = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var registry = new NativeCaseRegistry();
        NativeCaseDefinition[] expected = [Definition("completed"), Definition("unfinished"), Definition("unstarted")];
        registry.Add(new(expected[0], Observe));
        registry.Add(new(expected[1], async (probe, _) =>
        {
            await Observe(probe, CancellationToken.None);
            entered.SetResult();
            try { await release.Task; }
            finally { finished.TrySetResult(); }
        }));
        bool unstartedExecuted = false;
        registry.Add(new(expected[2], (probe, token) =>
        {
            unstartedExecuted = true;
            return Observe(probe, token);
        }));
        Task<IReadOnlyList<NativeCaseResult>> run = NativeCaseRunner.RunAsync(registry, expected, cancellation.Token);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            cancellation.Cancel();
            IReadOnlyList<NativeCaseResult> results = await run.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(results.Count).IsEqualTo(3);
            await Assert.That(results[0].Passed).IsTrue();
            await Assert.That(results[1].Passed).IsFalse();
            await Assert.That(results[1].ReasonCode).IsEqualTo("incomplete-execution");
            await Assert.That(results[1].EffectObserved).IsTrue();
            await Assert.That(results[2].ReasonCode).IsEqualTo("unexpected-cancellation");
            await Assert.That(unstartedExecuted).IsFalse();
        }
        finally
        {
            release.TrySetResult();
            await finished.Task.WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    [Test]
    public async Task IdentityEscapesEveryComponentWithoutDelimiterCollisions()
    {
        var key = new NativeCaseKey("p|q", "read/one", "a%b", "scope space", "case#");
        await Assert.That(key.Identity).IsEqualTo("p%7Cq|read%2Fone|a%25b|scope%20space|case%23");
        await Assert.That(key.Identity == new NativeCaseKey("p", "q|read/one", "a%b", "scope space", "case#").Identity).IsFalse();
    }
}
