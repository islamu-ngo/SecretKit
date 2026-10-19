using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal enum NonSqlInputSource { NativeProvider, ControlledFixture }
internal enum NonSqlInputConfiguration { Baseline, Selected, Absent }
internal enum NonSqlValidationKind { AdministrativeConnection, LocalValidation }

internal sealed record NonSqlInputWitnessInput(string DeploymentId, string SourceProfile,
    string RootNonce, int CaseTimeoutSeconds, InfisicalDynamicProfileInput? Baseline = null,
    InfisicalDynamicAlternativeProfileInput? BaselineAlternative = null, string? BaselineAlternativeVariant = null)
{
    public override string ToString() => "[NonSqlInputWitnessInput]";
}

internal sealed record NonSqlInputRootAttempt(
    [property: JsonRequired] string Id,
    [property: JsonRequired] string CaseIdentity,
    [property: JsonRequired] string ProviderVersion,
    [property: JsonRequired] string DeploymentId,
    [property: JsonRequired] string SourceProfile,
    [property: JsonRequired] string RootNonce,
    [property: JsonRequired] InfisicalDynamicProvider Provider,
    [property: JsonRequired] NonSqlValidationKind ValidationKind,
    [property: JsonRequired] string ProjectId,
    [property: JsonRequired] string Environment,
    [property: JsonRequired] string Folder,
    [property: JsonRequired] NonSqlInputSource Source)
{
    public override string ToString() => "[NonSqlInputRootAttempt]";
}

// Owned private copies of closed host inputs. The source compares committed
// decrypted storage independently; these bytes are not report evidence.
internal sealed class NonSqlInputPrivateProfiles : IDisposable
{
    private static readonly JsonSerializerOptions PrivateJson = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private byte[] baseline = [];
    private byte[] selected = [];
    private byte[] options = [];
    private bool disposed;

    internal NonSqlInputPrivateProfiles(InfisicalDynamicProvider provider, NonSqlInputWitnessInput settings,
        InfisicalDynamicProfileInput? profile, InfisicalDynamicAlternativeProfileInput? alternative,
        string? alternativeVariant, string operation, string variant,
        InfisicalDynamicClientEffects.DynamicInput input)
    {
        Provider = provider;
        Operation = operation;
        Variant = variant;
        if (!Enum.IsDefined(provider) || provider == InfisicalDynamicProvider.SqlDatabase ||
            (profile is null) == (alternative is null) ||
            (settings.Baseline is null) == (settings.BaselineAlternative is null))
            throw new NativeCaseFailureException("missing-input");
        try
        {
            using var original = CreateBaseline(provider, settings);
            using var changed = alternative is null ?
                InfisicalDynamicProfileInputs.Create(provider, profile!) :
                InfisicalDynamicAlternativeProfileInputs.Create(alternativeVariant ??
                    throw new NativeCaseFailureException("missing-input"), alternative);
            if (original.Provider != provider || changed.Provider != provider)
                throw new NativeCaseFailureException("missing-input");
            baseline = JsonSerializer.SerializeToUtf8Bytes(new
            {
                profile = settings.Baseline,
                alternative = settings.BaselineAlternative,
                alternativeVariant = settings.BaselineAlternativeVariant
            }, PrivateJson);
            selected = JsonSerializer.SerializeToUtf8Bytes(new
            {
                profile,
                alternative,
                alternativeVariant = alternative is null ? null : alternativeVariant
            }, PrivateJson);
            options = JsonSerializer.SerializeToUtf8Bytes(new
            {
                input.DefaultSeconds,
                input.MaximumSeconds,
                input.UsernameTemplate,
                input.Metadata,
                operation,
                variant
            }, PrivateJson);
        }
        catch { Dispose(); throw; }
    }

    internal InfisicalDynamicProvider Provider { get; }
    internal string Operation { get; }
    internal string Variant { get; }
    internal static InfisicalDynamicProvider ProviderOf(InfisicalDynamicProfileInput value) => value switch
    {
        { Clickhouse: not null } => InfisicalDynamicProvider.Clickhouse,
        { Cassandra: not null } => InfisicalDynamicProvider.Cassandra,
        { SapAse: not null } => InfisicalDynamicProvider.SapAse,
        { SapHana: not null } => InfisicalDynamicProvider.SapHana,
        { Redis: not null } => InfisicalDynamicProvider.Redis,
        { Vertica: not null } => InfisicalDynamicProvider.Vertica,
        { AzureSqlDatabase: not null } => InfisicalDynamicProvider.AzureSqlDatabase,
        { Snowflake: not null } => InfisicalDynamicProvider.Snowflake,
        { AwsIam: not null } => InfisicalDynamicProvider.AwsIam,
        { AwsElasticache: not null } => InfisicalDynamicProvider.AwsElasticache,
        { AwsMemorydb: not null } => InfisicalDynamicProvider.AwsMemorydb,
        { AzureEntraId: not null } => InfisicalDynamicProvider.AzureEntraId,
        { GcpIam: not null } => InfisicalDynamicProvider.GcpIam,
        { Github: not null } => InfisicalDynamicProvider.Github,
        { Milvus: not null } => InfisicalDynamicProvider.Milvus,
        { MongoDb: not null } => InfisicalDynamicProvider.MongoDb,
        { ElasticSearch: not null } => InfisicalDynamicProvider.ElasticSearch,
        { RabbitMq: not null } => InfisicalDynamicProvider.RabbitMq,
        { Kubernetes: not null } => InfisicalDynamicProvider.Kubernetes,
        { Ldap: not null } => InfisicalDynamicProvider.Ldap,
        { Totp: not null } => InfisicalDynamicProvider.Totp,
        { Ssh: not null } => InfisicalDynamicProvider.Ssh,
        { IbmApiConnect: not null } => InfisicalDynamicProvider.IbmApiConnect,
        { Oauth2: not null } => InfisicalDynamicProvider.Oauth2,
        { Tailscale: not null } => InfisicalDynamicProvider.Tailscale,
        { Couchbase: not null } => InfisicalDynamicProvider.Couchbase,
        { MongoDbAtlas: not null } => InfisicalDynamicProvider.MongoDbAtlas,
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static NonSqlValidationKind Kind(InfisicalDynamicProvider provider) =>
        provider is InfisicalDynamicProvider.Totp or InfisicalDynamicProvider.Ssh ?
            NonSqlValidationKind.LocalValidation : NonSqlValidationKind.AdministrativeConnection;

    internal static InfisicalDynamicProfile CreateBaseline(InfisicalDynamicProvider provider,
        NonSqlInputWitnessInput settings) => settings.BaselineAlternative is null ?
        InfisicalDynamicProfileInputs.Create(provider, settings.Baseline ??
            throw new NativeCaseFailureException("missing-input")) :
        InfisicalDynamicAlternativeProfileInputs.Create(settings.BaselineAlternativeVariant ??
            throw new NativeCaseFailureException("missing-input"), settings.BaselineAlternative);

    internal void Write(Utf8JsonWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        byte[] first = baseline.ToArray();
        byte[] second = [];
        byte[] third = [];
        try
        {
            second = selected.ToArray();
            third = options.ToArray();
            writer.WriteStartObject("profiles");
            writer.WritePropertyName("baseline");
            writer.WriteRawValue(first);
            writer.WritePropertyName("selected");
            writer.WriteRawValue(second);
            writer.WritePropertyName("options");
            writer.WriteRawValue(third);
            writer.WriteEndObject();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(first);
            CryptographicOperations.ZeroMemory(second);
            CryptographicOperations.ZeroMemory(third);
        }
    }

    public void Dispose()
    {
        disposed = true;
        CryptographicOperations.ZeroMemory(baseline);
        CryptographicOperations.ZeroMemory(selected);
        CryptographicOperations.ZeroMemory(options);
    }
    public override string ToString() => "[NonSqlInputPrivateProfiles]";
}

internal sealed record NonSqlInputBinding(
    [property: JsonRequired] NonSqlInputRootAttempt Attempt,
    [property: JsonRequired] string RegistrationId,
    [property: JsonRequired] string SourceIdentity,
    [property: JsonRequired] string ClockAuthority,
    [property: JsonRequired] string ClockEpoch,
    [property: JsonRequired] DateTimeOffset OpenedAt,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] bool OwnedRootCreated,
    [property: JsonRequired] bool RootInitiallyAbsent,
    [property: JsonRequired] bool DistinctContrasts,
    [property: JsonRequired] bool IndependentStorageQualified,
    [property: JsonRequired] bool ProviderValidationCaptureQualified,
    [property: JsonRequired] bool UpstreamDispositionCaptureQualified,
    [property: JsonRequired] bool DeploymentAuthorityQualified)
{
    public override string ToString() => "[NonSqlInputBinding]";
}

internal sealed record NonSqlInputAttempt(
    [property: JsonRequired] NonSqlInputBinding Binding,
    [property: JsonRequired] string Id,
    [property: JsonRequired] string OriginalName,
    [property: JsonRequired] Guid? DefinitionId,
    [property: JsonRequired] string Operation,
    [property: JsonRequired] string Variant,
    [property: JsonRequired] string Case,
    [property: JsonRequired] NonSqlInputConfiguration Configuration)
{
    public override string ToString() => "[NonSqlInputAttempt]";
}

internal sealed record NonSqlInputArm(
    [property: JsonRequired] NonSqlInputAttempt Attempt,
    [property: JsonRequired] string RegistrationId,
    [property: JsonRequired] long Cursor,
    [property: JsonRequired] DateTimeOffset ArmedAt,
    [property: JsonRequired] bool CaptureArmed)
{
    public override string ToString() => "[NonSqlInputArm]";
}

internal sealed record NonSqlInputFence(
    [property: JsonRequired] NonSqlInputArm Arm,
    [property: JsonRequired] DispatchEvidence Disposition,
    [property: JsonRequired] string EventId,
    [property: JsonRequired] string? ProviderRequestId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset SettledAt,
    [property: JsonRequired] int MatchedRequests,
    [property: JsonRequired] int MatchedCommits,
    [property: JsonRequired] bool Applied,
    [property: JsonRequired] Guid? DefinitionId,
    [property: JsonRequired] bool IndependentStorageRead,
    [property: JsonRequired] bool DefinitionAbsent,
    [property: JsonRequired] bool OriginalAttemptSettled,
    [property: JsonRequired] bool ExcludesLateCommit,
    [property: JsonRequired] bool NoReplay,
    [property: JsonRequired] bool UpstreamActionsTerminal,
    [property: JsonRequired] int PendingUpstreamActions)
{
    public override string ToString() => "[NonSqlInputFence]";
}

internal sealed record NonSqlInputObservation(
    [property: JsonRequired] NonSqlInputBinding Binding,
    [property: JsonRequired] Guid? DefinitionId,
    [property: JsonRequired] NonSqlInputConfiguration Configuration,
    [property: JsonRequired] string Phase,
    [property: JsonRequired] string EventId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset ObservedAt,
    [property: JsonRequired] bool IndependentStorageRead,
    [property: JsonRequired] bool PersistedMergeMatches,
    [property: JsonRequired] bool OptionsMatch,
    [property: JsonRequired] NonSqlValidationKind ValidationKind,
    [property: JsonRequired] string? AdministrativeAction,
    [property: JsonRequired] string? AdministrativePrincipal,
    [property: JsonRequired] string? AdministrativeTarget,
    [property: JsonRequired] bool ActualAdministrativeActionCaptured,
    [property: JsonRequired] bool WrongAuthorityRejected,
    [property: JsonRequired] bool LocalTransformationMatches,
    [property: JsonRequired] bool LocalKeyLineageMatches,
    [property: JsonRequired] bool ProviderSpecificTransportMatches,
    [property: JsonRequired] bool DeploymentAuthorityMatches,
    [property: JsonRequired] bool OriginalValidationMatched,
    [property: JsonRequired] bool BorrowedStatePreserved)
{
    public override string ToString() => "[NonSqlInputObservation]";
}

internal sealed record NonSqlInputCleanup(
    [property: JsonRequired] NonSqlInputRootAttempt Attempt,
    [property: JsonRequired] bool Closed,
    [property: JsonRequired] bool OwnedRootRemoved,
    [property: JsonRequired] bool BorrowedStatePreserved,
    [property: JsonRequired] bool DefinitionsAbsent,
    [property: JsonRequired] bool PrivateProfilesDestroyed,
    [property: JsonRequired] bool OriginalAttemptsSettled,
    [property: JsonRequired] bool LateCreationFenced,
    [property: JsonRequired] bool OwnedUpstreamResourcesAbsent,
    [property: JsonRequired] bool OwnedUpstreamMaterialDisposed,
    [property: JsonRequired] int PendingUpstreamActions,
    [property: JsonRequired] int RemainingRegistrations,
    [property: JsonRequired] int PendingDeliveries)
{
    public override string ToString() => "[NonSqlInputCleanup]";
}

internal interface IInfisicalNonSqlInputObserver
{
    ValueTask<NonSqlInputBinding> OpenAsync(NonSqlInputRootAttempt attempt, NonSqlInputPrivateProfiles profiles, CancellationToken token);
    ValueTask<NonSqlInputArm> ArmAsync(NonSqlInputAttempt attempt, CancellationToken token);
    ValueTask<NonSqlInputFence> CompleteAsync(NonSqlInputArm arm, DispatchEvidence receipt, CancellationToken token);
    ValueTask<NonSqlInputObservation> ObserveAsync(NonSqlInputBinding binding, Guid? definitionId, NonSqlInputConfiguration configuration, CancellationToken token);
    ValueTask<NonSqlInputCleanup> CloseAsync(NonSqlInputRootAttempt attempt, CancellationToken token);
}
