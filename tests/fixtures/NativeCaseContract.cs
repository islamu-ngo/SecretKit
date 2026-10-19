namespace SecretKit.TestFixtures;

internal readonly record struct NativeCaseKey(string Provider, string Operation, string Variant, string Scope, string Case)
{
    public string Identity => string.Join("|", new[] { Provider, Operation, Variant, Scope, Case }.Select(Uri.EscapeDataString));
}

internal sealed record NativeCaseDefinition(NativeCaseKey Key, string Member);

internal sealed record NativeCaseRegistration(NativeCaseDefinition Definition,
    Func<NativeCaseProbe, CancellationToken, ValueTask> Execute);

internal sealed class NativeCaseRegistry
{
    private readonly Dictionary<NativeCaseKey, NativeCaseRegistration> registrations = [];

    public void Add(NativeCaseRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(registration.Execute);
        if (!registrations.TryAdd(registration.Definition.Key, registration))
        {
            throw new InvalidOperationException("duplicate-registration");
        }
    }

    public void ValidateAgainst(IReadOnlyList<NativeCaseDefinition> expected)
    {
        var definitions = new Dictionary<NativeCaseKey, NativeCaseDefinition>();
        foreach (NativeCaseDefinition definition in expected)
        {
            if (!definitions.TryAdd(definition.Key, definition))
            {
                throw new InvalidOperationException("duplicate-expected-case");
            }
        }

        foreach (NativeCaseRegistration registration in registrations.Values)
        {
            if (!definitions.TryGetValue(registration.Definition.Key, out NativeCaseDefinition? definition))
            {
                throw new InvalidOperationException("unknown-registration");
            }

            if (!string.Equals(definition.Member, registration.Definition.Member, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("member-mismatch");
            }
        }
    }

    internal NativeCaseRegistration? Find(NativeCaseKey key) => registrations.GetValueOrDefault(key);
}

internal enum NativeObservation { Matched, Mismatched, Unavailable }

internal enum NativeFailure
{
    ContractMismatch,
    MissingInput,
    MissingPrerequisite,
    ObserverUnavailable,
    EffectMismatch,
    UnexpectedCancellation,
    DeadlineExceeded,
    CleanupIncomplete,
    UnexpectedFailure
}

internal sealed class NativeCaseProbe
{
    private readonly object gate = new();
    private bool contract;
    private bool effect;
    private string? failure;

    public void Contract(bool matched, NativeFailure reason)
    {
        lock (gate)
        {
            contract = true;
            if (!matched)
            {
                Fail(reason);
            }
        }
    }

    public void Effect(NativeObservation observation)
    {
        lock (gate)
        {
            switch (observation)
            {
                case NativeObservation.Matched:
                    effect = true;
                    break;
                case NativeObservation.Mismatched:
                    effect = false;
                    Fail(NativeFailure.EffectMismatch);
                    break;
                case NativeObservation.Unavailable:
                    effect = false;
                    Fail(NativeFailure.ObserverUnavailable);
                    break;
                default:
                    Fail(NativeFailure.UnexpectedFailure);
                    break;
            }
        }
    }

    private void Fail(NativeFailure reason)
    {
        string code = Reason(reason);
        if (failure is null || reason == NativeFailure.CleanupIncomplete)
        {
            failure = code;
        }

        throw new NativeCaseFailureException(code);
    }

    internal NativeCaseResult Result(NativeCaseKey key, string? executionFailure = null)
    {
        lock (gate)
        {
            string code = failure ?? executionFailure ?? (!contract ? "missing-contract" : !effect ? "missing-effect" : "observed");
            return new(key.Provider, key.Operation, key.Variant, key.Scope, key.Case,
                code == "observed", effect, code);
        }
    }

    internal static string Reason(NativeFailure reason) => reason switch
    {
        NativeFailure.ContractMismatch => "contract-mismatch",
        NativeFailure.MissingInput => "missing-input",
        NativeFailure.MissingPrerequisite => "missing-prerequisite",
        NativeFailure.ObserverUnavailable => "observer-unavailable",
        NativeFailure.EffectMismatch => "effect-mismatch",
        NativeFailure.UnexpectedCancellation => "unexpected-cancellation",
        NativeFailure.DeadlineExceeded => "deadline-exceeded",
        NativeFailure.CleanupIncomplete => "cleanup-incomplete",
        _ => "unexpected-failure"
    };
}

internal sealed class NativeCaseFailureException(string reasonCode) : Exception(reasonCode);

internal sealed record NativeCaseResult(string Provider, string Operation, string Variant, string Scope,
    string Case, bool Passed, bool EffectObserved, string ReasonCode);

internal static class NativeCaseRunner
{
    public static async Task<IReadOnlyList<NativeCaseResult>> RunAsync(NativeCaseRegistry registry,
        IReadOnlyList<NativeCaseDefinition> expected, CancellationToken token)
    {
        registry.ValidateAgainst(expected);
        var results = new List<NativeCaseResult>(expected.Count);
        foreach (NativeCaseDefinition definition in expected)
        {
            var probe = new NativeCaseProbe();
            NativeCaseRegistration? registration = registry.Find(definition.Key);
            string? failure = null;
            if (registration is null)
            {
                failure = "missing-registration";
            }
            else if (token.IsCancellationRequested)
            {
                failure = "unexpected-cancellation";
            }
            else
            {
                Task? execution = null;
                try
                {
                    execution = registration.Execute(probe, token).AsTask();
                    await execution.WaitAsync(token).ConfigureAwait(false);
                }
                catch (NativeCaseFailureException error)
                {
                    // Input/observer helpers can fail without touching the probe.
                    // Preserve only known material-free codes; never serialize arbitrary exception text.
                    failure = Enum.GetValues<NativeFailure>().Any(value => NativeCaseProbe.Reason(value) == error.Message)
                        ? error.Message : "unexpected-failure";
                }
                catch (OperationCanceledException)
                {
                    failure = execution is { IsCompleted: false } ? "incomplete-execution" : "unexpected-cancellation";
                    if (execution is { IsCompleted: false })
                    {
                        _ = execution.ContinueWith(task => _ = task.Exception, CancellationToken.None,
                            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                            TaskScheduler.Default);
                    }
                }
                catch (Exception)
                {
                    failure = "unexpected-failure";
                }
            }

            results.Add(probe.Result(definition.Key, failure));
        }

        return results;
    }
}
