using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal enum SqlInputSource { NativeProvider, ControlledFixture }
internal enum SqlInputConfiguration { Baseline, Selected }

internal sealed record SqlInputRootAttempt(
    [property: JsonRequired] string Id,
    [property: JsonRequired] string CaseIdentity,
    [property: JsonRequired] string ProviderVersion,
    [property: JsonRequired] string DeploymentId,
    [property: JsonRequired] string SourceProfile,
    [property: JsonRequired] string RootNonce,
    [property: JsonRequired] NativeSqlEngine Engine,
    [property: JsonRequired] string ProjectId,
    [property: JsonRequired] string Environment,
    [property: JsonRequired] string Folder,
    [property: JsonRequired] SqlInputSource Source)
{
    public override string ToString() => "[SqlInputRootAttempt]";
}

// Own serialized copies, not the caller's immutable input strings. No plaintext
// string exports are made. Acquisition and export are transactional.
internal sealed class SqlInputPrivateProfiles : IDisposable
{
    private static readonly JsonSerializerOptions PrivateOptionsJson = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private byte[] baseline = [];
    private byte[] selected = [];
    private byte[] options = [];
    private bool disposed;

    internal SqlInputPrivateProfiles(DynamicSqlInput baseline, DynamicSqlInput selected,
        string operation, string variant, string? usernameTemplate = null,
        InfisicalDynamicClientEffects.DynamicMetadata[]? metadata = null,
        bool optionsSupplied = false, bool clearUsernameTemplate = false)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(selected);
        Engine = baseline.Engine;
        Operation = operation;
        Variant = InfisicalDynamicClientEffects.NormalizeSqlVariant(variant);
        BaselineCaRequired = baseline.Ca is not null;
        SelectedCaRequired = Variant == "sql.ca.omitted" ?
            operation != "CreateDefinitionAsync" && BaselineCaRequired : selected.Ca is not null;
        TlsRequired = BaselineCaRequired || SelectedCaRequired ||
            Engine == NativeSqlEngine.SqlServer && (baseline.SslEnabled is not null || selected.SslEnabled is not null);
        RoutingRequired = Variant is "gatewayId.value" or "gatewayId.null" or
            "gatewayPoolId.value" or "gatewayPoolId.null";
        if (baseline.Engine != selected.Engine || !Enum.IsDefined(Engine) ||
            string.IsNullOrWhiteSpace(operation) || string.IsNullOrWhiteSpace(Variant))
            throw new ArgumentException("Invalid private SQL profile.");
        try
        {
            this.baseline = JsonSerializer.SerializeToUtf8Bytes(baseline, InfisicalLifecycleFamilies.Options);
            this.selected = JsonSerializer.SerializeToUtf8Bytes(selected, InfisicalLifecycleFamilies.Options);
            options = JsonSerializer.SerializeToUtf8Bytes(new
            {
                usernameTemplate,
                metadata,
                optionsSupplied,
                clearUsernameTemplate
            }, PrivateOptionsJson);
        }
        catch { Dispose(); throw; }
    }

    internal NativeSqlEngine Engine { get; }
    internal string Operation { get; }
    internal string Variant { get; }
    internal bool BaselineCaRequired { get; }
    internal bool SelectedCaRequired { get; }
    internal bool TlsRequired { get; }
    internal bool RoutingRequired { get; }

    internal void Write(Utf8JsonWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        byte[] first = baseline.ToArray();
        byte[] second = [];
        byte[] settings = [];
        try
        {
            second = selected.ToArray();
            settings = options.ToArray();
            writer.WriteStartObject("profiles");
            writer.WritePropertyName("baseline");
            writer.WriteRawValue(first);
            writer.WritePropertyName("selected");
            writer.WriteRawValue(second);
            writer.WritePropertyName("options");
            writer.WriteRawValue(settings);
            writer.WriteString("operation", Operation);
            writer.WriteString("variant", Variant);
            writer.WriteString("baselineVariant", "seed");
            writer.WriteEndObject();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(first);
            CryptographicOperations.ZeroMemory(second);
            CryptographicOperations.ZeroMemory(settings);
        }
    }

    public void Dispose()
    {
        disposed = true;
        CryptographicOperations.ZeroMemory(baseline);
        CryptographicOperations.ZeroMemory(selected);
        CryptographicOperations.ZeroMemory(options);
    }
    public override string ToString() => "[SqlInputPrivateProfiles]";
}

internal sealed record SqlInputBinding(
    [property: JsonRequired] SqlInputRootAttempt Attempt,
    [property: JsonRequired] string RegistrationId,
    [property: JsonRequired] string SourceIdentity,
    [property: JsonRequired] string ClockAuthority,
    [property: JsonRequired] string ClockEpoch,
    [property: JsonRequired] DateTimeOffset OpenedAt,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] bool OwnedRootCreated,
    [property: JsonRequired] bool RootInitiallyAbsent,
    [property: JsonRequired] bool BaselineAdminAccepted,
    [property: JsonRequired] bool SelectedAdminAccepted,
    [property: JsonRequired] bool WrongAdminRejected,
    [property: JsonRequired] bool DistinctContrasts,
    [property: JsonRequired] bool IndependentStorageQualified,
    [property: JsonRequired] bool AdminSessionCaptureQualified,
    [property: JsonRequired] bool TlsCaptureQualified,
    [property: JsonRequired] bool RoutingCaptureQualified)
{
    public override string ToString() => "[SqlInputBinding]";
}

internal sealed record SqlInputAttempt(
    [property: JsonRequired] SqlInputBinding Binding,
    [property: JsonRequired] string Id,
    [property: JsonRequired] string OriginalName,
    [property: JsonRequired] Guid? DefinitionId,
    [property: JsonRequired] string Operation,
    [property: JsonRequired] string Variant,
    [property: JsonRequired] string Case,
    [property: JsonRequired] SqlInputConfiguration Configuration)
{
    public override string ToString() => "[SqlInputAttempt]";
}

internal sealed record SqlInputArm(
    [property: JsonRequired] SqlInputAttempt Attempt,
    [property: JsonRequired] string RegistrationId,
    [property: JsonRequired] long Cursor,
    [property: JsonRequired] DateTimeOffset ArmedAt,
    [property: JsonRequired] bool CaptureArmed)
{
    public override string ToString() => "[SqlInputArm]";
}

internal sealed record SqlInputFence(
    [property: JsonRequired] SqlInputArm Arm,
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
    [property: JsonRequired] bool NoReplay)
{
    public override string ToString() => "[SqlInputFence]";
}

internal sealed record SqlInputObservation(
    [property: JsonRequired] SqlInputBinding Binding,
    [property: JsonRequired] Guid DefinitionId,
    [property: JsonRequired] SqlInputConfiguration Configuration,
    [property: JsonRequired] string Phase,
    [property: JsonRequired] string EventId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset ObservedAt,
    [property: JsonRequired] bool IndependentStorageRead,
    [property: JsonRequired] bool PersistedMergeMatches,
    [property: JsonRequired] bool OptionsMatch,
    [property: JsonRequired] bool AdminPrincipalMatches,
    [property: JsonRequired] bool AdminTargetMatches,
    [property: JsonRequired] bool WrongAdminRejected,
    [property: JsonRequired] bool ActualAdminSessionCaptured,
    [property: JsonRequired] bool GatewayRouteMatches,
    [property: JsonRequired] bool EngineQualifiedTlsMatches,
    [property: JsonRequired] bool OwnedCaChain,
    [property: JsonRequired] bool InvalidTrustRejected,
    [property: JsonRequired] bool FreshPublicLeaseObserved,
    [property: JsonRequired] bool RetainedStatementsMatch)
{
    public override string ToString() => "[SqlInputObservation]";
}

internal sealed record SqlInputCleanup(
    [property: JsonRequired] SqlInputRootAttempt Attempt,
    [property: JsonRequired] bool Closed,
    [property: JsonRequired] bool OwnedRootRemoved,
    [property: JsonRequired] bool BorrowedStatePreserved,
    [property: JsonRequired] bool DefinitionsAbsent,
    [property: JsonRequired] bool LeasesAbsent,
    [property: JsonRequired] bool PrincipalsAbsent,
    [property: JsonRequired] bool PrivateProfilesDestroyed,
    [property: JsonRequired] bool OriginalAttemptsSettled,
    [property: JsonRequired] bool LateCreationFenced,
    [property: JsonRequired] int RemainingRegistrations,
    [property: JsonRequired] int PendingDeliveries)
{
    public override string ToString() => "[SqlInputCleanup]";
}

internal interface IInfisicalSqlInputObserver
{
    ValueTask<SqlInputBinding> OpenAsync(SqlInputRootAttempt attempt, SqlInputPrivateProfiles profiles, CancellationToken token);
    ValueTask<SqlInputArm> ArmAsync(SqlInputAttempt attempt, CancellationToken token);
    ValueTask<SqlInputFence> CompleteAsync(SqlInputArm arm, DispatchEvidence receipt, CancellationToken token);
    ValueTask<SqlInputObservation> ObserveAsync(SqlInputBinding binding, Guid definitionId, SqlInputConfiguration configuration, CancellationToken token);
    ValueTask<SqlInputCleanup> CloseAsync(SqlInputRootAttempt attempt, CancellationToken token);
}
