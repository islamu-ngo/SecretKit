using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal enum RotationMaterialSource { NativeProvider, ControlledFixture }
internal enum RotationMaterialKind { AccountPassword, DirectoryPassword, ClientSecret, AccessKey, Token, IdentifiedToken, JsonKey, PemKey }

// Pinned interoperability names, not a vendor request schema.
internal sealed record RotationMaterialProfile(RotationMaterialKind Kind, string[] Fields, bool Overlap, bool Pinned)
{
    internal static RotationMaterialProfile For(InfisicalRotationProfile profile) => profile switch
    {
        InfisicalRotationProfile.Auth0ClientSecret => new(RotationMaterialKind.ClientSecret, ["clientId", "clientSecret"], false, true),
        InfisicalRotationProfile.AzureClientSecret or InfisicalRotationProfile.OktaClientSecret or
            InfisicalRotationProfile.DatabricksServicePrincipalSecret =>
            new(RotationMaterialKind.ClientSecret, ["clientId", "clientSecret"], true, true),
        InfisicalRotationProfile.AwsIamUserSecret or InfisicalRotationProfile.CloudflareR2AccessKey =>
            new(RotationMaterialKind.AccessKey, ["accessKeyId", "secretAccessKey"], true, true),
        InfisicalRotationProfile.CloudflareApiToken => new(RotationMaterialKind.IdentifiedToken, ["tokenId", "apiToken"], true, true),
        InfisicalRotationProfile.DatadogApiKey => new(RotationMaterialKind.IdentifiedToken, ["apiKeyId", "apiKey"], true, true),
        InfisicalRotationProfile.DatadogApplicationKeySecret => new(RotationMaterialKind.IdentifiedToken, ["applicationKeyId", "applicationKey"], true, true),
        InfisicalRotationProfile.ConvexAccessKey => new(RotationMaterialKind.Token, ["accessKey"], true, true),
        InfisicalRotationProfile.DbtServiceToken => new(RotationMaterialKind.Token, ["serviceToken"], true, true),
        InfisicalRotationProfile.FireworksApiKey or InfisicalRotationProfile.LitellmApiKey or
            InfisicalRotationProfile.OpenRouterApiKey or InfisicalRotationProfile.OpenaiServiceAccount or
            InfisicalRotationProfile.StripeApiKey or InfisicalRotationProfile.SupabaseApiKey =>
            new(RotationMaterialKind.Token, ["apiKey"], true, true),
        InfisicalRotationProfile.GcpServiceAccountKey => new(RotationMaterialKind.JsonKey, ["serviceAccountKey"], true, true),
        InfisicalRotationProfile.LdapPassword => new(RotationMaterialKind.DirectoryPassword, ["dn", "password"], false, true),
        InfisicalRotationProfile.HpIloLocalAccount or InfisicalRotationProfile.UnixLinuxLocalAccount or
            InfisicalRotationProfile.WindowsLocalAccount => new(RotationMaterialKind.AccountPassword, ["username", "password"], false, true),
        InfisicalRotationProfile.MongodbCredentials or InfisicalRotationProfile.MssqlCredentials or
            InfisicalRotationProfile.MysqlCredentials or InfisicalRotationProfile.OracledbCredentials or
            InfisicalRotationProfile.PostgresCredentials or InfisicalRotationProfile.RedisCredentials =>
            new(RotationMaterialKind.AccountPassword, ["username", "password"], true, true),
        InfisicalRotationProfile.SalesforceOauthCredentials => new(RotationMaterialKind.ClientSecret, ["consumerKey", "consumerSecret"], true, true),
        InfisicalRotationProfile.SnowflakeUserKeyPair => new(RotationMaterialKind.PemKey, ["privateKey", "publicKey"], true, true),
        _ => throw new NativeCaseFailureException("missing-input")
    };
    public override string ToString() => "[RotationMaterialProfile]";
}

internal sealed record RotationMaterialFieldInput(
    [property: JsonRequired] string Field,
    [property: JsonRequired] string Destination,
    [property: JsonRequired] string Version,
    [property: JsonRequired] string Value)
{
    public override string ToString() => "[RotationMaterialFieldInput]";
}

internal sealed record RotationMaterialInput(
    [property: JsonRequired] string DeploymentId,
    [property: JsonRequired] string SourceIdentity,
    [property: JsonRequired] string ClockEpoch,
    [property: JsonRequired] RotationMaterialSource Source,
    [property: JsonRequired] string ProjectId,
    [property: JsonRequired] string Environment,
    [property: JsonRequired] string Folder,
    [property: JsonRequired] string RotationId,
    [property: JsonRequired] InfisicalRotationProfile Profile,
    [property: JsonRequired] RotationMaterialKind Kind,
    [property: JsonRequired] long Generation,
    [property: JsonRequired] RotationMaterialFieldInput[] Fields,
    [property: JsonRequired] string SetupCapability,
    [property: JsonRequired] string[] AllowedActions,
    [property: JsonRequired] string[] DeniedActions,
    [property: JsonRequired] int MaximumItems,
    [property: JsonRequired] int TimeoutSeconds)
{
    public override string ToString() => "[RotationMaterialInput]";
}

internal sealed record RotationMaterialRoot(
    [property: JsonRequired] string Id,
    [property: JsonRequired] string Nonce,
    [property: JsonRequired] string CaseIdentity,
    [property: JsonRequired] string ProviderVersion,
    [property: JsonRequired] string DeploymentId,
    [property: JsonRequired] string SourceIdentity,
    [property: JsonRequired] string ClockEpoch,
    [property: JsonRequired] RotationMaterialSource Source,
    [property: JsonRequired] string ProjectId,
    [property: JsonRequired] string Environment,
    [property: JsonRequired] string Folder,
    [property: JsonRequired] string RotationId,
    [property: JsonRequired] InfisicalRotationProfile Profile,
    [property: JsonRequired] RotationMaterialKind Kind,
    [property: JsonRequired] long Generation)
{
    public override string ToString() => "[RotationMaterialRoot]";
}

// Only Write is a private export. Copies and writer capacity are cleared even
// when acquisition/serialization fails. Caller strings are not owned or erased.
internal sealed class RotationMaterialPacket : IDisposable
{
    private readonly List<(string Field, string Destination, string Version, SecretMaterial Material)> values = [];
    private bool disposed;
    [JsonIgnore] internal InfisicalRotationProfile Profile { get; }
    [JsonIgnore] internal RotationMaterialKind Kind { get; }
    [JsonIgnore] internal long Generation { get; }

    internal RotationMaterialPacket(InfisicalRotationProfile profile, RotationMaterialKind kind, long generation,
        IReadOnlyList<RotationMaterialFieldInput> fields)
    {
        Profile = profile;
        Kind = kind;
        Generation = generation;
        RotationMaterialProfile selection = RotationMaterialProfile.For(profile);
        if (!selection.Pinned) throw new NativeCaseFailureException("observer-unavailable");
        if (kind != selection.Kind || generation < 0 || fields is null ||
            !fields.Select(f => f.Field).SequenceEqual(selection.Fields) ||
            fields.Select(f => f.Destination).Distinct(StringComparer.Ordinal).Count() != fields.Count ||
            fields.Any(f => !RotationMaterialTrial.Text(f.Destination) || !RotationMaterialTrial.Text(f.Version) ||
                string.IsNullOrEmpty(f.Value) || f.Value.Length > 262144))
            throw new NativeCaseFailureException("missing-input");
        try
        {
            foreach (var field in fields)
                values.Add((field.Field, field.Destination, field.Version, SecretMaterial.FromText(field.Value)));
        }
        catch { Dispose(); throw; }
    }

    private RotationMaterialPacket(RotationMaterialPacket source, bool wrong)
    {
        ObjectDisposedException.ThrowIf(source.disposed, source);
        Profile = source.Profile;
        Kind = source.Kind;
        Generation = source.Generation;
        try
        {
            int contrast = Kind == RotationMaterialKind.PemKey ? 0 : source.values.Count - 1;
            for (int i = 0; i < source.values.Count; ++i)
            {
                var value = source.values[i];
                char[] chars = value.Material.ExportCharacters();
                try
                {
                    if (wrong && i == contrast) chars[0] = chars[0] == '!' ? '?' : '!';
                    values.Add((value.Field, value.Destination, value.Version, SecretMaterial.FromText(chars)));
                }
                finally { Array.Clear(chars); }
            }
        }
        catch { Dispose(); throw; }
    }

    internal RotationMaterialPacket Wrong() => new(this, true);
    internal bool Matches(RotationMaterialPacket expected)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ObjectDisposedException.ThrowIf(expected.disposed, expected);
        if (Profile != expected.Profile || Kind != expected.Kind || Generation != expected.Generation ||
            values.Count != expected.values.Count) return false;
        for (int i = 0; i < values.Count; ++i)
        {
            var actual = values[i];
            var wanted = expected.values[i];
            if (actual.Field != wanted.Field || actual.Destination != wanted.Destination ||
                actual.Version != wanted.Version) return false;
            char[] left = actual.Material.ExportCharacters();
            char[] right = [];
            try
            {
                right = wanted.Material.ExportCharacters();
                if (!left.AsSpan().SequenceEqual(right)) return false;
            }
            finally { Array.Clear(left); Array.Clear(right); }
        }
        return true;
    }

    internal void Write(Utf8JsonWriter writer, string name)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        writer.WriteStartObject(name);
        writer.WriteNumber("profile", (int)Profile);
        writer.WriteNumber("kind", (int)Kind);
        writer.WriteNumber("generation", Generation);
        writer.WriteStartArray("fields");
        foreach (var value in values)
        {
            char[] chars = value.Material.ExportCharacters();
            try
            {
                writer.WriteStartObject();
                writer.WriteString("field", value.Field);
                writer.WriteString("destination", value.Destination);
                writer.WriteString("version", value.Version);
                writer.WriteString("value", chars);
                writer.WriteEndObject();
            }
            finally { Array.Clear(chars); }
        }
        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    internal static async ValueTask<RotationMaterialPacket> ReadAsync(InfisicalClient consumer,
        RotationMaterialInput input, bool denied, CancellationToken token)
    {
        var reads = new List<SecretRead>();
        var packet = new RotationMaterialPacket(input.Profile, input.Kind, input.Generation, input.Fields);
        try
        {
            for (int i = 0; i < input.Fields.Length; ++i)
            {
                var field = input.Fields[i];
                var result = await consumer.ReadAsync(new(consumer.Authority,
                    new InfisicalSecretAddress(input.ProjectId, input.Environment, input.Folder, field.Destination)), token);
                if (denied)
                {
                    if (result.IsSuccess) result.Value.Dispose();
                    RotationMaterialTrial.Require(result.Status == SecretStatus.Denied, "effect-mismatch");
                    continue;
                }
                RotationMaterialTrial.Require(result.IsSuccess, "observer-unavailable");
                reads.Add(result.Value);
                RotationMaterialTrial.Require(result.Value.Observation.Version == field.Version, "effect-mismatch");
                // Keep the actual SDK result, never the expected source value.
                packet.values[i].Material.Dispose();
                packet.values[i] = (field.Field, field.Destination, field.Version, result.Value.Material.Copy());
            }
            return packet;
        }
        catch { packet.Dispose(); throw; }
        finally { foreach (var read in reads) read.Dispose(); }
    }

    public void Dispose()
    {
        disposed = true;
        foreach (var value in values) value.Material.Dispose();
    }
    public override string ToString() => "[RotationMaterialPacket]";
}

internal sealed record RotationMaterialStamp(
    [property: JsonRequired] RotationMaterialRoot Root,
    [property: JsonRequired] string RegistrationId,
    [property: JsonRequired] string ClockAuthority,
    [property: JsonRequired] string EventId,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset At)
{
    public override string ToString() => "[RotationMaterialStamp]";
}
internal sealed record RotationMaterialBinding(
    [property: JsonRequired] RotationMaterialStamp Stamp,
    [property: JsonRequired] bool OwnedSetup,
    [property: JsonRequired] bool NeverEnabled,
    [property: JsonRequired] bool SetupSettled,
    [property: JsonRequired] bool ConfigurationAndMappingMatch,
    [property: JsonRequired] bool ExactMaterialKnown,
    [property: JsonRequired] bool CompleteBackendInventory,
    [property: JsonRequired] bool IndependentJournals,
    [property: JsonRequired] bool AdminAccepted,
    [property: JsonRequired] bool WrongAdminRejected,
    [property: JsonRequired] bool ValidAdminRechecked)
{
    public override string ToString() => "[RotationMaterialBinding]";
}
internal sealed record RotationMaterialArm(
    [property: JsonRequired] RotationMaterialStamp Stamp,
    [property: JsonRequired] RotationMaterialBinding Binding,
    [property: JsonRequired] bool CaptureArmed)
{
    public override string ToString() => "[RotationMaterialArm]";
}
internal sealed record RotationMaterialAuthentication(
    [property: JsonRequired] RotationMaterialStamp Stamp,
    [property: JsonRequired] RotationMaterialArm Arm,
    [property: JsonRequired] bool ExactSuppliedMaterial,
    [property: JsonRequired] bool CoherentGeneration,
    [property: JsonRequired] BackendAuthentication Valid,
    [property: JsonRequired] BackendAuthentication Wrong,
    [property: JsonRequired] BackendAuthentication Recheck,
    [property: JsonRequired] string[] AllowedActions,
    [property: JsonRequired] string[] DeniedActions,
    [property: JsonRequired] bool FreshSessions,
    [property: JsonRequired] bool IndependentBackend)
{
    public override string ToString() => "[RotationMaterialAuthentication]";
}
internal sealed record RotationMaterialWindow(
    [property: JsonRequired] RotationMaterialStamp Stamp,
    [property: JsonRequired] RotationMaterialArm Arm,
    [property: JsonRequired] SecretStatus Status,
    [property: JsonRequired] int OriginalReads,
    [property: JsonRequired] bool OriginalSettled,
    [property: JsonRequired] bool ExcludesLateWork,
    [property: JsonRequired] bool ConfigurationUnchanged,
    [property: JsonRequired] bool MappingUnchanged,
    [property: JsonRequired] bool MaterialUnchanged,
    [property: JsonRequired] bool BackendInventoryUnchanged,
    [property: JsonRequired] bool IndependentReadWindow,
    [property: JsonRequired] bool NoReplay,
    [property: JsonRequired] int PendingDeliveries,
    [property: JsonRequired] int PendingWork)
{
    public override string ToString() => "[RotationMaterialWindow]";
}
internal sealed record RotationMaterialCleanup(
    [property: JsonRequired] RotationMaterialRoot Root,
    [property: JsonRequired] bool OriginalSettled,
    [property: JsonRequired] bool ExcludesLateWork,
    [property: JsonRequired] bool OwnedSetupAbsent,
    [property: JsonRequired] bool MappedSecretsAbsent,
    [property: JsonRequired] bool BackendResourcesAbsent,
    [property: JsonRequired] bool CapturedMaterialRetired,
    [property: JsonRequired] bool BorrowedPreserved,
    [property: JsonRequired] bool PrivateDestroyed,
    [property: JsonRequired] bool CompleteInventory,
    [property: JsonRequired] int Registrations,
    [property: JsonRequired] int PendingDeliveries,
    [property: JsonRequired] int PendingWork)
{
    public override string ToString() => "[RotationMaterialCleanup]";
}

internal interface IInfisicalRotationMaterialSource
{
    ValueTask<RotationMaterialBinding> OpenAsync(RotationMaterialRoot root, RotationMaterialPacket packet,
        SecretMaterial setupCapability, CancellationToken token);
    ValueTask<RotationMaterialArm> ArmAsync(RotationMaterialBinding binding, CancellationToken token);
    ValueTask<RotationMaterialAuthentication> AuthenticateAsync(RotationMaterialArm arm,
        RotationMaterialPacket actual, RotationMaterialPacket wrong, CancellationToken token);
    ValueTask<RotationMaterialWindow> CompleteAsync(RotationMaterialArm arm, SecretStatus status, CancellationToken token);
    ValueTask<RotationMaterialCleanup> CloseAsync(RotationMaterialRoot root, CancellationToken token);
}
