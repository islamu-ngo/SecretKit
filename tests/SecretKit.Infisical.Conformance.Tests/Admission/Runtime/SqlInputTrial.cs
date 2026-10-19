using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed record SqlInputWitnessInput(string DeploymentId, string SourceProfile,
    string RootNonce, int CaseTimeoutSeconds, DynamicSqlInput Baseline)
{
    public override string ToString() => "[SqlInputWitnessInput]";
}

// Injection is not a trust bypass: the host checks the original source facts too.
internal sealed class SqlInputTrial : IAsyncDisposable
{
    private readonly IInfisicalSqlInputObserver source;
    private readonly SqlInputRootAttempt root;
    private readonly SqlInputPrivateProfiles profiles;
    private readonly TimeSpan timeout;
    private readonly HashSet<string> registrations = new(StringComparer.Ordinal);
    private readonly HashSet<string> events = new(StringComparer.Ordinal);
    private readonly HashSet<string> requests = new(StringComparer.Ordinal);
    private readonly HashSet<string> attempts = new(StringComparer.Ordinal);
    private long sequence;
    private DateTimeOffset time;
    private SqlInputArm? pending;
    private bool closed;

    private SqlInputTrial(IInfisicalSqlInputObserver source, SqlInputRootAttempt root,
        SqlInputPrivateProfiles profiles, int seconds)
    {
        this.source = source;
        this.root = root;
        this.profiles = profiles;
        timeout = TimeSpan.FromSeconds(seconds);
    }

    internal SqlInputBinding Binding { get; private set; } = null!;
    internal SqlInputFence? Fence { get; private set; }

    internal static async ValueTask<SqlInputTrial> OpenAsync(NativeEnvironment env,
        NativeCaseDefinition row, InfisicalDynamicClientEffects.DynamicInput input,
        SqlInputWitnessInput settings, string folder, IInfisicalSqlInputObserver? injected,
        CancellationToken token)
    {
        var baseline = settings.Baseline ?? throw new NativeCaseFailureException("missing-input");
        var selected = input.Profile ?? throw new NativeCaseFailureException("missing-input");
        Require(settings.CaseTimeoutSeconds is >= 1 and <= 900 &&
            Text(settings.DeploymentId) && Text(settings.SourceProfile) && Text(settings.RootNonce) &&
            baseline.Engine == selected.Engine, "missing-input");
        bool controlled = settings.SourceProfile == "controlled-fixture";
        Require(injected is null || controlled, "missing-input");
        Require(!controlled || injected is not null, "observer-unavailable");
        var source = injected ?? InfisicalSqlInputObserver.FromInputs(env, InfisicalDynamicClientEffects.Family);
        Require(source is not null, "observer-unavailable");
        Require(baseline.Username != selected.Username ||
            baseline.Password != selected.Password ||
            baseline.Host != selected.Host ||
            baseline.Database != selected.Database, "missing-input");
        string method = row.Key.Operation["i.runtime.InfisicalDynamicClient.".Length..];
        string variant = InfisicalDynamicClientEffects.NormalizeSqlVariant(row.Key.Variant);
        var packet = new SqlInputPrivateProfiles(baseline, selected, method, variant,
            variant == "usernameTemplate.value" ? input.UsernameTemplate : null,
            variant == "metadata.omitted" ? null : variant == "metadata.value" ? input.Metadata : [],
            variant != "options.omitted", variant == "usernameTemplate.null");
        var root = new SqlInputRootAttempt(Guid.NewGuid().ToString("D"),
            row.Key.Operation + "/" + row.Key.Variant + "/" + row.Key.Case,
            "v0.166.3", settings.DeploymentId, settings.SourceProfile, settings.RootNonce,
            selected.Engine, input.Sandbox.ProjectId, input.Sandbox.Environment, folder,
            controlled ? SqlInputSource.ControlledFixture : SqlInputSource.NativeProvider);
        var trial = new SqlInputTrial(source!, root, packet, settings.CaseTimeoutSeconds);
        try
        {
            using var deadline = trial.Deadline(token);
            var binding = await source!.OpenAsync(root, packet, deadline.Token);
            Require(binding.Attempt == root && Unique(trial.registrations, binding.RegistrationId) &&
                Text(binding.SourceIdentity) &&
                binding.SourceIdentity is not ("setup" or "runtime" or "denied" or "administrative" or "observer") &&
                binding.ClockAuthority == "provider-application-clock" && Text(binding.ClockEpoch) &&
                Utc(binding.OpenedAt) && binding.Sequence >= 0 && binding.OwnedRootCreated &&
                binding.RootInitiallyAbsent && binding.BaselineAdminAccepted && binding.SelectedAdminAccepted &&
                binding.WrongAdminRejected && binding.DistinctContrasts && binding.IndependentStorageQualified &&
                binding.AdminSessionCaptureQualified && (!packet.TlsRequired || binding.TlsCaptureQualified) &&
                (!packet.RoutingRequired || binding.RoutingCaptureQualified));
            trial.Binding = binding;
            trial.sequence = binding.Sequence;
            trial.time = binding.OpenedAt;
            return trial;
        }
        catch
        {
            await trial.DisposeAsync();
            throw;
        }
    }

    internal async ValueTask ArmAsync(string name, Guid? definitionId, string operation,
        string variant, string boundary, SqlInputConfiguration configuration, CancellationToken token)
    {
        Require(!closed && pending is null);
        var attempt = new SqlInputAttempt(Binding, Guid.NewGuid().ToString("D"), name,
            definitionId, operation, variant, boundary, configuration);
        Require(Unique(attempts, attempt.Id));
        using var deadline = Deadline(token);
        var arm = await source.ArmAsync(attempt, deadline.Token);
        Require(arm.Attempt == attempt && Unique(registrations, arm.RegistrationId) &&
            arm.CaptureArmed && Next(arm.Cursor, arm.ArmedAt));
        pending = arm;
    }

    internal async ValueTask<SqlInputFence> CompleteAsync(DispatchEvidence receipt, CancellationToken token)
    {
        Require(pending is not null);
        var arm = pending!;
        pending = null;
        using var deadline = Deadline(token);
        var facts = await source.CompleteAsync(arm, receipt, deadline.Token);
        Require(facts.Arm == arm && facts.Disposition == receipt &&
            Unique(events, facts.EventId) && Next(facts.Sequence, facts.SettledAt) &&
            facts.IndependentStorageRead && facts.OriginalAttemptSettled &&
            facts.ExcludesLateCommit && facts.NoReplay &&
            (receipt == DispatchEvidence.PossiblyDispatched ?
                facts.MatchedRequests is >= 0 and <= 1 && (!facts.Applied || facts.MatchedRequests == 1) :
                facts.MatchedRequests == (receipt == DispatchEvidence.NotDispatched ? 0 : 1)) &&
            facts.MatchedCommits == (facts.Applied ? 1 : 0) &&
            !(receipt is DispatchEvidence.NotDispatched or DispatchEvidence.Rejected && facts.Applied) &&
            (receipt != DispatchEvidence.Applied || facts.Applied) &&
            (facts.MatchedRequests == 0 ? facts.ProviderRequestId is null :
                Unique(requests, facts.ProviderRequestId)) &&
            facts.DefinitionId != Guid.Empty &&
            (arm.Attempt.DefinitionId is null || arm.Attempt.DefinitionId == facts.DefinitionId) &&
            (facts.DefinitionId is not null || facts.DefinitionAbsent));
        Fence = facts;
        return facts;
    }

    internal async ValueTask ObserveAsync(Guid definitionId, SqlInputConfiguration configuration,
        CancellationToken token)
    {
        Require(Fence is { DefinitionAbsent: false } && Fence.DefinitionId == definitionId &&
            configuration == (Fence.Applied ? Fence.Arm.Attempt.Configuration : SqlInputConfiguration.Baseline));
        using var deadline = Deadline(token);
        var facts = await source.ObserveAsync(Binding, definitionId, configuration, deadline.Token);
        Require(facts.Binding == Binding && facts.DefinitionId == definitionId &&
            facts.Configuration == configuration && facts.Phase == Fence!.Arm.Attempt.Id &&
            Unique(events, facts.EventId) && Next(facts.Sequence, facts.ObservedAt));
        Require(facts.IndependentStorageRead && facts.PersistedMergeMatches && facts.OptionsMatch &&
            facts.AdminPrincipalMatches && facts.AdminTargetMatches && facts.WrongAdminRejected &&
            facts.ActualAdminSessionCaptured && facts.GatewayRouteMatches && facts.EngineQualifiedTlsMatches &&
            facts.FreshPublicLeaseObserved && facts.RetainedStatementsMatch &&
            (!(configuration == SqlInputConfiguration.Baseline ?
                profiles.BaselineCaRequired : profiles.SelectedCaRequired) ||
                facts.OwnedCaChain && facts.InvalidTrustRejected), "effect-mismatch");
    }

    public async ValueTask DisposeAsync()
    {
        if (closed) return;
        closed = true;
        try
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var facts = await source.CloseAsync(root, cleanup.Token);
            Require(facts.Attempt == root && facts.Closed && facts.OwnedRootRemoved &&
                facts.BorrowedStatePreserved && facts.DefinitionsAbsent && facts.LeasesAbsent &&
                facts.PrincipalsAbsent && facts.PrivateProfilesDestroyed && facts.OriginalAttemptsSettled &&
                facts.LateCreationFenced && facts.RemainingRegistrations == 0 && facts.PendingDeliveries == 0,
                "cleanup-incomplete");
        }
        finally { profiles.Dispose(); }
    }

    private CancellationTokenSource Deadline(CancellationToken token)
    {
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(timeout);
        return deadline;
    }
    private bool Next(long value, DateTimeOffset observed)
    {
        if (value <= sequence || !Utc(observed) || observed < time) return false;
        sequence = value;
        time = observed;
        return true;
    }
    private static bool Utc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;
    private static bool Text(string? value) => value is { Length: > 0 and <= 256 } &&
        !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl);
    private static bool Unique(HashSet<string> used, string? value) => Text(value) && used.Add(value!);
    private static void Require(bool condition, string reason = "observer-unavailable")
    {
        if (!condition) throw new NativeCaseFailureException(reason);
    }
}
