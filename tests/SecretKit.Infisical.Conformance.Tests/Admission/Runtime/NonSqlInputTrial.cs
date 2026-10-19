using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class NonSqlInputTrial : IAsyncDisposable
{
    private readonly IInfisicalNonSqlInputObserver source;
    private readonly NonSqlInputRootAttempt root;
    private readonly NonSqlInputPrivateProfiles profiles;
    private readonly NonSqlInputEvidenceGuard guard;
    private readonly TimeSpan timeout;
    private NonSqlInputArm? pending;
    private bool unavailable;
    private bool closed;
    private int busy;

    private NonSqlInputTrial(IInfisicalNonSqlInputObserver source, NonSqlInputRootAttempt root,
        NonSqlInputPrivateProfiles profiles, int seconds)
    {
        this.source = source;
        this.root = root;
        this.profiles = profiles;
        guard = new(root, profiles);
        timeout = TimeSpan.FromSeconds(seconds);
    }

    internal NonSqlInputBinding Binding => guard.Binding!;
    internal NonSqlInputFence? Fence => guard.Fence;

    internal static async ValueTask<NonSqlInputTrial> OpenAsync(NativeEnvironment env,
        NativeCaseDefinition row, InfisicalDynamicClientEffects.DynamicInput input,
        InfisicalDynamicProvider provider, InfisicalDynamicProfileInput? profile,
        InfisicalDynamicAlternativeProfileInput? alternative, string? alternativeVariant,
        string folder, IInfisicalNonSqlInputObserver? injected, CancellationToken token)
    {
        var settings = input.NonSqlInputWitness ?? throw new NativeCaseFailureException("missing-input");
        NonSqlInputEvidenceGuard.Require(settings.CaseTimeoutSeconds is >= 1 and <= 900 &&
            NonSqlInputEvidenceGuard.Text(settings.DeploymentId) &&
            NonSqlInputEvidenceGuard.Text(settings.SourceProfile) &&
            NonSqlInputEvidenceGuard.Text(settings.RootNonce), "missing-input");
        bool controlled = settings.SourceProfile == "controlled-fixture";
        NonSqlInputEvidenceGuard.Require(injected is null || controlled, "missing-input");
        NonSqlInputEvidenceGuard.Require(!controlled || injected is not null);
        var observer = injected ?? InfisicalNonSqlInputObserver.FromInputs(env, InfisicalDynamicClientEffects.Family);
        NonSqlInputEvidenceGuard.Require(observer is not null);
        const string prefix = "i.runtime.InfisicalDynamicClient.";
        NonSqlInputEvidenceGuard.Require(row.Key.Operation.StartsWith(prefix, StringComparison.Ordinal), "missing-input");
        string operation = row.Key.Operation[prefix.Length..];
        var packet = new NonSqlInputPrivateProfiles(provider, settings, profile, alternative,
            alternativeVariant, operation, row.Key.Variant, input);
        var root = new NonSqlInputRootAttempt(Guid.NewGuid().ToString("D"),
            row.Key.Operation + "/" + row.Key.Variant + "/" + row.Key.Case,
            "v0.166.3", settings.DeploymentId, settings.SourceProfile, settings.RootNonce,
            provider, NonSqlInputPrivateProfiles.Kind(provider), input.Sandbox.ProjectId,
            input.Sandbox.Environment, folder,
            controlled ? NonSqlInputSource.ControlledFixture : NonSqlInputSource.NativeProvider);
        NonSqlInputTrial trial;
        try { trial = new(observer!, root, packet, settings.CaseTimeoutSeconds); }
        catch { packet.Dispose(); throw; }
        try
        {
            using var deadline = trial.Deadline(token);
            trial.guard.Open(await observer!.OpenAsync(root, packet, deadline.Token));
            return trial;
        }
        catch
        {
            await trial.DisposeAsync();
            throw;
        }
    }

    internal async ValueTask ArmAsync(string name, Guid? definitionId, string operation,
        string variant, string boundary, NonSqlInputConfiguration configuration, CancellationToken token)
    {
        Enter();
        try
        {
            NonSqlInputEvidenceGuard.Require(pending is null);
            var attempt = new NonSqlInputAttempt(Binding, Guid.NewGuid().ToString("D"), name,
                definitionId, operation, variant, boundary, configuration);
            guard.CheckAttempt(attempt);
            unavailable = true;
            using var deadline = Deadline(token);
            pending = guard.Arm(attempt, await source.ArmAsync(attempt, deadline.Token));
            unavailable = false;
        }
        finally { Exit(); }
    }

    internal async ValueTask<NonSqlInputFence> CompleteAsync(DispatchEvidence receipt, CancellationToken token)
    {
        Enter();
        try
        {
            NonSqlInputEvidenceGuard.Require(pending is not null);
            var arm = pending!;
            pending = null;
            unavailable = true;
            using var deadline = Deadline(token);
            var facts = await source.CompleteAsync(arm, receipt, deadline.Token);
            guard.Complete(arm, receipt, facts);
            unavailable = false;
            return facts;
        }
        finally { Exit(); }
    }

    internal async ValueTask ObserveAsync(Guid? definitionId, NonSqlInputConfiguration configuration,
        CancellationToken token)
    {
        Enter();
        try
        {
            NonSqlInputEvidenceGuard.Require(pending is null);
            guard.CheckObservation(definitionId, configuration);
            unavailable = true;
            using var deadline = Deadline(token);
            guard.Observe(definitionId, configuration,
                await source.ObserveAsync(Binding, definitionId, configuration, deadline.Token));
            unavailable = false;
        }
        finally { Exit(); }
    }

    public async ValueTask DisposeAsync()
    {
        if (closed) return;
        NonSqlInputEvidenceGuard.Require(Interlocked.CompareExchange(ref busy, 1, 0) == 0, "cleanup-incomplete");
        closed = true;
        try
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            NonSqlInputEvidenceGuard.Cleanup(root, await source.CloseAsync(root, cleanup.Token));
        }
        catch (Exception error) when (error is NativeCaseFailureException or OperationCanceledException)
        { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { profiles.Dispose(); Exit(); }
    }

    private void Enter()
    {
        NonSqlInputEvidenceGuard.Require(!closed && !unavailable);
        NonSqlInputEvidenceGuard.Require(Interlocked.CompareExchange(ref busy, 1, 0) == 0);
    }
    private void Exit() => Volatile.Write(ref busy, 0);
    private CancellationTokenSource Deadline(CancellationToken token)
    {
        var result = CancellationTokenSource.CreateLinkedTokenSource(token);
        result.CancelAfter(timeout);
        return result;
    }
    public override string ToString() => "[NonSqlInputTrial]";
}

// Used independently by the channel adapter and trial: injection is not authority.
internal sealed class NonSqlInputEvidenceGuard
{
    private readonly NonSqlInputRootAttempt root;
    private readonly string operation;
    private readonly string variant;
    private readonly string? baselineAction;
    private readonly string? selectedAction;
    private readonly HashSet<string> registrations = new(StringComparer.Ordinal);
    private readonly HashSet<string> events = new(StringComparer.Ordinal);
    private readonly HashSet<string> requests = new(StringComparer.Ordinal);
    private readonly HashSet<string> attempts = new(StringComparer.Ordinal);
    private readonly HashSet<string> phases = new(StringComparer.Ordinal);
    private long sequence;
    private DateTimeOffset time;
    private NonSqlInputConfiguration savedConfiguration = NonSqlInputConfiguration.Baseline;

    internal NonSqlInputBinding? Binding { get; private set; }
    internal NonSqlInputFence? Fence { get; private set; }

    internal NonSqlInputEvidenceGuard(NonSqlInputRootAttempt root, NonSqlInputPrivateProfiles profiles)
    {
        this.root = root;
        operation = profiles.Operation;
        variant = profiles.Variant;
        Require(profiles.Provider == root.Provider && ValidRoot(root), "missing-input");
        using var buffer = new InfisicalLifecycleObservers.OwnedJsonBuffer(static size => new byte[size]);
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            profiles.Write(writer);
            writer.WriteEndObject();
        }
        using var document = JsonDocument.Parse(buffer.Buffer.AsMemory(0, buffer.WrittenCount));
        var packet = document.RootElement.GetProperty("profiles");
        Require(!JsonElement.DeepEquals(packet.GetProperty("baseline"), packet.GetProperty("selected")), "missing-input");
        baselineAction = Action(root.Provider, packet.GetProperty("baseline"));
        selectedAction = Action(root.Provider, packet.GetProperty("selected"));
    }

    internal static bool ValidRoot(NonSqlInputRootAttempt value) =>
        Text(value.Id) && Text(value.CaseIdentity) && value.ProviderVersion == "v0.166.3" &&
        Text(value.DeploymentId) && Text(value.SourceProfile) && Text(value.RootNonce) &&
        Enum.IsDefined(value.Provider) && value.Provider != InfisicalDynamicProvider.SqlDatabase &&
        value.ValidationKind == NonSqlInputPrivateProfiles.Kind(value.Provider) &&
        Guid.TryParseExact(value.ProjectId, "D", out Guid id) && id != Guid.Empty &&
        id.ToString("D") == value.ProjectId && Text(value.Environment) && Text(value.Folder) &&
        value.Folder.StartsWith('/') && Enum.IsDefined(value.Source) &&
        (value.Source == NonSqlInputSource.ControlledFixture) == (value.SourceProfile == "controlled-fixture");

    internal void Open(NonSqlInputBinding facts, string? identity = null)
    {
        Require(facts is not null && facts.Attempt == root && Unique(registrations, facts.RegistrationId) &&
            Text(facts.SourceIdentity) && (identity is null || facts.SourceIdentity == identity) &&
            facts.SourceIdentity is not ("setup" or "runtime" or "denied" or "administrative" or "observer") &&
            facts.ClockAuthority == "provider-application-clock" && Text(facts.ClockEpoch) &&
            Utc(facts.OpenedAt) && facts.Sequence >= 0 &&
            facts.OwnedRootCreated && facts.RootInitiallyAbsent && facts.DistinctContrasts &&
            facts.IndependentStorageQualified && facts.ProviderValidationCaptureQualified &&
            facts.UpstreamDispositionCaptureQualified && facts.DeploymentAuthorityQualified);
        Binding = facts;
        sequence = facts.Sequence;
        time = facts.OpenedAt;
    }

    internal void CheckAttempt(NonSqlInputAttempt value)
    {
        Require(value.Binding == Binding && Text(value.Id) && Unique(attempts, value.Id) &&
            Text(value.OriginalName) && value.DefinitionId != Guid.Empty && Text(value.Variant) &&
            Text(value.Case) && Enum.IsDefined(value.Configuration) &&
            value.Operation is "CreateDefinitionAsync" or "UpdateDefinitionAsync" or
                "UpdateDefinitionPolicyAsync" or "InspectDefinitionAsync" or "ListDefinitionsAsync" or "DeleteDefinitionAsync");
        Require(value.Configuration != NonSqlInputConfiguration.Selected ||
            value.Operation == operation && value.Variant == variant);
        Require(value.Operation != "DeleteDefinitionAsync" || value.DefinitionId is not null);
    }

    internal NonSqlInputArm Arm(NonSqlInputAttempt attempt, NonSqlInputArm facts)
    {
        Require(facts is not null && facts.Attempt == attempt && Unique(registrations, facts.RegistrationId) &&
            facts.CaptureArmed && Next(facts.Cursor, facts.ArmedAt));
        Fence = null;
        return facts;
    }

    internal void Complete(NonSqlInputArm arm, DispatchEvidence receipt, NonSqlInputFence facts)
    {
        Require(facts is not null && facts.Arm == arm && facts.Disposition == receipt &&
            receipt is DispatchEvidence.NotDispatched or DispatchEvidence.Rejected or
                DispatchEvidence.Applied or DispatchEvidence.PossiblyDispatched &&
            Unique(events, facts.EventId) && Next(facts.Sequence, facts.SettledAt));
        Require(facts.IndependentStorageRead && facts.OriginalAttemptSettled && facts.ExcludesLateCommit);
        bool read = IsRead(arm.Attempt.Operation);
        int expectedRequests = receipt == DispatchEvidence.NotDispatched ? 0 : 1;
        Require(facts.NoReplay && facts.UpstreamActionsTerminal && facts.PendingUpstreamActions == 0 &&
            (receipt == DispatchEvidence.PossiblyDispatched ?
                facts.MatchedRequests is >= 0 and <= 1 && (!facts.Applied || facts.MatchedRequests == 1) :
                facts.MatchedRequests == expectedRequests) &&
            facts.MatchedCommits == (facts.Applied ? 1 : 0) &&
            (!read || !facts.Applied && facts.MatchedCommits == 0) &&
            !(receipt is DispatchEvidence.NotDispatched or DispatchEvidence.Rejected && facts.Applied) &&
            (receipt != DispatchEvidence.Applied || read || facts.Applied), "effect-mismatch");
        Require(facts.MatchedRequests == 0 ? facts.ProviderRequestId is null : Unique(requests, facts.ProviderRequestId));
        Require(facts.DefinitionId != Guid.Empty &&
            (arm.Attempt.DefinitionId is null || arm.Attempt.DefinitionId == facts.DefinitionId) &&
            (facts.DefinitionId is not null || facts.DefinitionAbsent));
        Require(!facts.Applied || (arm.Attempt.Operation == "DeleteDefinitionAsync" ?
            facts.DefinitionAbsent && arm.Attempt.Configuration == NonSqlInputConfiguration.Absent :
            !facts.DefinitionAbsent && arm.Attempt.Configuration != NonSqlInputConfiguration.Absent), "effect-mismatch");
        if (facts.Applied && arm.Attempt.Operation != "DeleteDefinitionAsync")
            savedConfiguration = arm.Attempt.Configuration;
        Fence = facts;
    }

    internal void CheckObservation(Guid? definitionId, NonSqlInputConfiguration configuration)
    {
        Require(Fence is not null && Fence.DefinitionId == definitionId && definitionId != Guid.Empty &&
            Enum.IsDefined(configuration));
        Require(Fence!.DefinitionAbsent ? configuration == NonSqlInputConfiguration.Absent :
            configuration == (Fence.Applied || IsRead(Fence.Arm.Attempt.Operation) ?
                Fence.Arm.Attempt.Configuration : NonSqlInputConfiguration.Baseline));
        Require(phases.Add(Fence.Arm.Attempt.Id));
    }

    internal void Observe(Guid? definitionId, NonSqlInputConfiguration configuration, NonSqlInputObservation facts)
    {
        Require(facts is not null && facts.Binding == Binding && facts.DefinitionId == definitionId &&
            facts.Configuration == configuration && facts.Phase == Fence!.Arm.Attempt.Id &&
            Unique(events, facts.EventId) && Next(facts.Sequence, facts.ObservedAt));
        Require(facts.IndependentStorageRead && facts.PersistedMergeMatches && facts.OptionsMatch &&
            facts.ValidationKind == root.ValidationKind && facts.OriginalValidationMatched &&
            facts.BorrowedStatePreserved, "effect-mismatch");
        // Absent/read boundaries refer to the original save, never a new validation.
        var effective = configuration == NonSqlInputConfiguration.Absent ? savedConfiguration : configuration;
        string? action = effective == NonSqlInputConfiguration.Selected ? selectedAction : baselineAction;
        Require(root.ValidationKind == NonSqlValidationKind.LocalValidation ?
            facts.AdministrativeAction is null && facts.AdministrativePrincipal is null &&
            facts.AdministrativeTarget is null && !facts.ActualAdministrativeActionCaptured &&
            !facts.WrongAuthorityRejected && facts.LocalTransformationMatches &&
            (root.Provider != InfisicalDynamicProvider.Ssh || facts.LocalKeyLineageMatches) :
            facts.AdministrativeAction == action && Text(facts.AdministrativePrincipal) &&
            Text(facts.AdministrativeTarget) && facts.ActualAdministrativeActionCaptured &&
            facts.WrongAuthorityRejected && facts.ProviderSpecificTransportMatches &&
            facts.DeploymentAuthorityMatches && !facts.LocalTransformationMatches &&
            !facts.LocalKeyLineageMatches, "effect-mismatch");
    }

    internal static void Cleanup(NonSqlInputRootAttempt root, NonSqlInputCleanup facts) =>
        Require(facts is not null && facts.Attempt == root && facts.Closed && facts.OwnedRootRemoved &&
            facts.BorrowedStatePreserved && facts.DefinitionsAbsent && facts.PrivateProfilesDestroyed &&
            facts.OriginalAttemptsSettled && facts.LateCreationFenced && facts.OwnedUpstreamResourcesAbsent &&
            facts.OwnedUpstreamMaterialDisposed && facts.PendingUpstreamActions == 0 &&
            facts.RemainingRegistrations == 0 && facts.PendingDeliveries == 0, "cleanup-incomplete");

    internal static bool IsRead(string operation) => operation is "InspectDefinitionAsync" or "ListDefinitionsAsync";
    private bool Next(long value, DateTimeOffset observed)
    {
        if (value <= sequence || !Utc(observed) || observed <= time) return false;
        sequence = value;
        time = observed;
        return true;
    }
    private static bool Utc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;
    internal static bool Text(string? value) => !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 512 && !value.Any(char.IsControl);
    private static bool Unique(HashSet<string> values, string? value) => Text(value) && values.Add(value!);
    internal static void Require([DoesNotReturnIf(false)] bool condition, string code = "observer-unavailable")
    {
        if (!condition) throw new NativeCaseFailureException(code);
    }

    // Closed action codes describe pinned save validation, not SDK operation names.
    private static string? Action(InfisicalDynamicProvider provider, JsonElement packet)
    {
        var alternative = packet.GetProperty("alternative");
        bool alternate = alternative.ValueKind != JsonValueKind.Null;
        return provider switch
        {
            InfisicalDynamicProvider.Clickhouse => "clickhouse.select-1",
            InfisicalDynamicProvider.Cassandra => "cassandra.system-schema-keyspaces",
            InfisicalDynamicProvider.SapAse => "sap-ase.master-and-selected-version",
            InfisicalDynamicProvider.SapHana => "sap-hana.select-1-dummy",
            InfisicalDynamicProvider.Redis => "redis.auth-ping",
            InfisicalDynamicProvider.Vertica => "vertica.select-version",
            InfisicalDynamicProvider.AzureSqlDatabase => "azure-sql.selected-database-select-1",
            InfisicalDynamicProvider.Snowflake => "snowflake.connect-is-valid",
            InfisicalDynamicProvider.AwsIam => AwsAction(packet.GetProperty("profile").GetProperty("awsIam")),
            InfisicalDynamicProvider.AwsElasticache => "elasticache.describe-replication-groups",
            InfisicalDynamicProvider.AwsMemorydb => "memorydb.describe-clusters",
            InfisicalDynamicProvider.AzureEntraId => "entra.client-token-exchange",
            InfisicalDynamicProvider.GcpIam => "gcp.impersonation-token",
            InfisicalDynamicProvider.Github => "github.installation-token",
            InfisicalDynamicProvider.Milvus => "milvus.describe-user",
            InfisicalDynamicProvider.MongoDb => "mongodb.database-ping",
            InfisicalDynamicProvider.ElasticSearch => alternate ? "elasticsearch.info-api-key" : "elasticsearch.info-user",
            InfisicalDynamicProvider.RabbitMq => "rabbitmq.whoami",
            InfisicalDynamicProvider.Kubernetes => alternate ? "kubernetes.static-account-get" :
                "kubernetes.test-account-binding-token-delete",
            InfisicalDynamicProvider.Ldap => "ldap.admin-bind",
            InfisicalDynamicProvider.Totp or InfisicalDynamicProvider.Ssh => null,
            InfisicalDynamicProvider.IbmApiConnect => "ibm.api-token",
            InfisicalDynamicProvider.Oauth2 => "oauth.token-ttl-revoke",
            InfisicalDynamicProvider.Tailscale => alternate &&
                packet.GetProperty("alternativeVariant").GetString()!.EndsWith(".oauth", StringComparison.Ordinal) ?
                "tailscale.oauth-exchange" : "tailscale.api-list",
            InfisicalDynamicProvider.Couchbase => "couchbase.organization-get",
            InfisicalDynamicProvider.MongoDbAtlas => "atlas.digest-database-users-list",
            _ => throw new NativeCaseFailureException("missing-input")
        };
    }
    private static string AwsAction(JsonElement profile) =>
        profile.GetProperty("credentialKind").Deserialize<NativeAwsCredentialKind>(InfisicalLifecycleFamilies.Options) ==
            NativeAwsCredentialKind.IamUser ? "iam.get-user" : "sts.session-token-or-assume-role";

    public override string ToString() => "[NonSqlInputEvidenceGuard]";
}
