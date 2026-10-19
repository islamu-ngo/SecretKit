using System.Diagnostics.Tracing;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class InfisicalImportPolicyFamilies
{
    public static void Register(NativeCaseRegistry registry, NativeEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected)
    {
        OrganizationEffects.Register(registry, env, expected);
        ImportsEffects.Register(registry, env, expected);
        ValidationPoliciesEffects.Register(registry, env, expected);
        ImportEffectObservationEffects.Register(registry, env, expected);
    }

    internal static void Add(NativeCaseRegistry registry, NativeEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected, string operation, string member,
        string[] variants, bool mutation,
        Func<NativeCaseDefinition, NativeCaseProbe, CancellationToken, ValueTask> execute)
    {
        foreach (NativeCaseDefinition definition in expected.Where(d =>
            d.Key.Provider == "Infisical" && d.Key.Operation == operation))
            registry.Add(new(definition, (probe, token) => InfisicalStaticFamilies.BoundedAsync(probe, token,
                bounded =>
                {
                    probe.Contract(definition.Member == member &&
                        variants.Contains(definition.Key.Variant, StringComparer.Ordinal) &&
                        InfisicalStaticFamilies.Case(definition.Key.Case, mutation), NativeFailure.ContractMismatch);
                    return execute(definition, probe, bounded);
                })));
    }

    internal static bool Denied(NativeCaseDefinition d) => d.Key.Case == "denied-authority";
    internal static bool Interrupted(NativeCaseDefinition d) =>
        d.Key.Case is "cancellation-boundary" or "lost-response-no-replay";

    internal static async ValueTask<StaticDispatch<T>> DispatchAsync<T>(NativeEnvironment env,
        NativeCaseDefinition d, NativeCaseProbe probe, string path, string method,
        Func<CancellationToken, ValueTask<SecretOutcome<T>>> call, CancellationToken token) where T : notnull
    {
        if (!Interrupted(d)) return new(await call(token), false);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        probe.Contract(method is "GET" or "POST" or "PATCH" or "DELETE", NativeFailure.ContractMismatch);
        using var barrier = new ImportPolicySendBoundary(env.Origin, path, cancellation,
            d.Key.Case == "lost-response-no-replay");
        bool cancelled = false;
        SecretOutcome<T>? result = null;
        try { result = await call(cancellation.Token); }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested && !token.IsCancellationRequested)
        { cancelled = true; }
        probe.Contract(barrier.Reached.Task.IsCompletedSuccessfully && cancelled, NativeFailure.ContractMismatch);
        return new(result, cancelled);
    }

    internal static void Result<T>(StaticDispatch<T> dispatch, MutationReceipt? receipt,
        SecretStatus status, DispatchEvidence evidence, NativeCaseProbe probe) where T : notnull
    {
        // A failed denial assertion must not strand material returned by an
        // unexpectedly successful read. Successful callers retain normal ownership.
        if (status != SecretStatus.Success && dispatch.Outcome is { IsSuccess: true } unexpected &&
            unexpected.Value is IDisposable owned) owned.Dispose();
        probe.Contract(dispatch.Cancelled || dispatch.Outcome!.Status == status, NativeFailure.ContractMismatch);
        if (receipt is not null) probe.Contract(receipt.Evidence == evidence, NativeFailure.ContractMismatch);
    }

}

// Subscribe before this exact public SDK dispatch. AsyncLocal selects the call,
// and origin and full path exclude setup, observer and unrelated requests.
// RequestStart does not expose the verb; the selected typed call owns that choice.
internal sealed class ImportPolicySendBoundary : EventListener
{
    private static readonly AsyncLocal<ImportPolicySendBoundary?> Current = new();
    private readonly ImportPolicySendBoundary? previous;
    private readonly Uri? origin;
    private readonly string? path;
    private readonly CancellationTokenSource? cancellation;
    private readonly bool lost;
    private bool selected;
    internal TaskCompletionSource Reached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal ImportPolicySendBoundary(Uri origin, string path,
        CancellationTokenSource cancellation, bool lost)
    {
        this.origin = origin;
        this.path = path;
        this.cancellation = cancellation;
        this.lost = lost;
        previous = Current.Value;
        Current.Value = this;
    }
    protected override void OnEventSourceCreated(EventSource source)
    {
        if (source.Name == "System.Net.Http") EnableEvents(source, EventLevel.Verbose, EventKeywords.All);
    }
    protected override void OnEventWritten(EventWrittenEventArgs e)
    {
        if (origin is null || cancellation is null || !ReferenceEquals(Current.Value, this)) return;
        if (e.EventName == "RequestStart" && e.Payload is { Count: >= 4 } p)
            selected = p[0] is string scheme && scheme == origin.Scheme &&
                p[1] is string host && host == origin.Host && p[2] is int port && port == origin.Port &&
                p[3] is string requestPath && requestPath.Split('?')[0] == path;
        if (selected && e.EventName == (lost ? "ResponseHeadersStop" : "RequestHeadersStart") &&
            Reached.TrySetResult()) cancellation.Cancel();
    }
    public override void Dispose()
    {
        if (ReferenceEquals(Current.Value, this)) Current.Value = previous;
        base.Dispose();
    }
}
