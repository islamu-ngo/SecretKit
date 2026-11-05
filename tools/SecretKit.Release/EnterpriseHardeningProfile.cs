using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretKit.Release;

public sealed record EnterpriseHardeningArchive(string PackageId, string Version, string Sha256);

public sealed record EnterpriseHardeningBinding(string ProfileSha256, string SourceRevision,
    string SourceContentSha256, string RunId, string Sdk, string Runtime, string Platform, string EvidenceSha256)
{
    public EnterpriseHardeningArchive[]? Archives { get; init; }
    public string? CohortSha256 { get; init; }
    public string? TransportSha256 { get; init; }
    public string? DeploymentSha256 { get; init; }
    public string? PrincipalSha256 { get; init; }
    public string? PolicySha256 { get; init; }
    public string? EffectSha256 { get; init; }
    public string? GraphSha256 { get; init; }
    public string? AuthorizationSha256 { get; init; }
}

public sealed record EnterpriseHardeningObservation(int SchemaVersion, string Profile, string Kind,
    string[] ScenarioIds, string Status, bool NativeQualified, EnterpriseHardeningBinding Binding);

// Selected by the caller independently of the observation. Matching these bytes
// establishes content consistency, never the truth of a report's assertions.
public sealed record EnterpriseHardeningExpectation(string Kind, string[] ScenarioIds, string? Provider,
    EnterpriseHardeningBinding Binding);

public sealed record EnterpriseHardeningAdmission(string Status, string? Gate)
{
    public bool NativeQualified => false;
}

public sealed record EnterpriseHardeningProofFiles(FileDigest Evidence)
{
    public FileDigest? Transport { get; init; }
    public FileDigest? Deployment { get; init; }
    public FileDigest? Principal { get; init; }
    public FileDigest? Policy { get; init; }
    public FileDigest? Effect { get; init; }
    public FileDigest? Graph { get; init; }
    public FileDigest? Authorization { get; init; }
}

public sealed record EnterpriseHardeningSelection(int SchemaVersion, string Profile, string Kind,
    string[] ScenarioIds, string PackageProfile, string SourceRevision, string RunId, string Sdk, string Runtime, string Platform,
    EnterpriseHardeningProofFiles Proofs)
{
    public string? Provider { get; init; }
}

public sealed record EnterpriseHardeningDenominators(string LocalProtocol, int DevelopmentFunctional,
    int FullNative, string IntegrationQuality);
public sealed record EnterpriseHardeningGate(string Id, string Owner, string Trigger, string Consequence);
public sealed record EnterpriseHardeningDeclaration(
    [property: JsonPropertyName("$schema")] string Schema, int SchemaVersion, string Profile, string Kind,
    bool NativeQualified, string[] ScenarioIds, string[] EvidenceKinds,
    Dictionary<string, string[]> InstalledModes,
    EnterpriseHardeningDenominators PreservedDenominators, EnterpriseHardeningGate[] Gates);

public static class EnterpriseHardeningProfile
{
    public const string Name = "enterprise-hardening";
    public const int MaximumBytes = 131072;
    private const string ProfileFile = "enterprise-hardening-profile.json";
    private static readonly Dictionary<string, string[]> InstalledCases = new(StringComparer.Ordinal)
    {
        ["minimal"] = ["S03", "S12", "S14", "S16", "S17"],
        ["configuration"] = ["S03", "S12", "S14", "S16", "S17", "S07", "S25"],
        ["hosting"] = ["S03", "S12", "S14", "S16", "S17", "S08", "S09"],
        ["full"] = ["S03", "S12", "S14", "S16", "S17", "S07", "S25", "S08", "S09"],
        ["seven-package"] = ["S02", "S03", "S05", "S06", "S10", "S11", "S12", "S13"]
    };
    private static readonly string[] Scenarios = Enumerable.Range(1, 28)
        .Select(number => "S" + number.ToString("D2", System.Globalization.CultureInfo.InvariantCulture)).ToArray();
    private static readonly string[] Kinds = ["source-offline", "controlled-installed-offline", "artifact-integrity",
        "native-observation", "platform-observation", "connected-advisory", "publication-authorization"];
    public static JsonSerializerOptions JsonOptions { get; } = new(Manifest.JsonOptions)
    {
        MaxDepth = 16,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static EnterpriseHardeningAdmission Admit(string directory, string file,
        EnterpriseHardeningExpectation expected)
    {
        EnterpriseHardeningObservation observation = Parse<EnterpriseHardeningObservation>(Read(directory, file));
        ValidateSelection(expected.Kind, expected.ScenarioIds, expected.Provider);
        Guard.Require(observation.SchemaVersion == 1 && observation.Profile == Name &&
            observation.Kind == expected.Kind && observation.Status is "passed" or "failed" or "unavailable",
            "enterprise-observation");
        // No existing native producer issues an enterprise principal/effect custody
        // receipt. A caller's Boolean cannot stand in for that missing contract.
        Guard.Require(!observation.NativeQualified, "enterprise-native-claim");
        Manifest.ExactSet(observation.ScenarioIds, expected.ScenarioIds, "enterprise-scenarios");
        ValidateBinding(expected.Binding, expected.Kind, observation.Status);
        ValidateBinding(observation.Binding, observation.Kind, observation.Status);
        var actual = observation.Binding;
        var wanted = expected.Binding;
        Guard.Require(actual.ProfileSha256 == wanted.ProfileSha256 &&
            actual.SourceRevision == wanted.SourceRevision &&
            actual.SourceContentSha256 == wanted.SourceContentSha256 &&
            actual.RunId == wanted.RunId && actual.Sdk == wanted.Sdk &&
            actual.Runtime == wanted.Runtime && actual.Platform == wanted.Platform &&
            actual.EvidenceSha256 == wanted.EvidenceSha256 &&
            actual.CohortSha256 == wanted.CohortSha256 &&
            actual.TransportSha256 == wanted.TransportSha256 &&
            actual.DeploymentSha256 == wanted.DeploymentSha256 &&
            actual.PrincipalSha256 == wanted.PrincipalSha256 &&
            actual.PolicySha256 == wanted.PolicySha256 && actual.EffectSha256 == wanted.EffectSha256 &&
            actual.GraphSha256 == wanted.GraphSha256 && actual.AuthorizationSha256 == wanted.AuthorizationSha256,
            "enterprise-binding");
        Guard.Require((actual.Archives is null) == (wanted.Archives is null), "enterprise-archives");
        if (actual.Archives is { } archives && wanted.Archives is { } originals)
            Guard.Require(archives.OrderBy(a => a.PackageId, StringComparer.Ordinal)
                .SequenceEqual(originals.OrderBy(a => a.PackageId, StringComparer.Ordinal)), "enterprise-archives");
        string? gate = expected.Provider switch { "Infisical" => "G1", "AzureKeyVault" => "G2", _ => null };
        return new(observation.Status != "passed" ? observation.Status :
            observation.Kind == "native-observation" ? "unavailable" : "bindings-matched", gate);
    }

    // This is the command boundary: expected records are selected separately from
    // the observation and source/archive values come from the existing owners.
    // It performs no provider operation and cannot turn bindings-matched into a
    // test, audit, platform, publication or native qualification pass.
    public static EnterpriseHardeningExpectation Select(string source, string? cohort,
        string selectionDirectory, string selectionFile)
    {
        EnterpriseHardeningSelection selection = Parse<EnterpriseHardeningSelection>(Read(selectionDirectory, selectionFile));
        Guard.Require(selection.SchemaVersion == 1 && selection.Profile == Name &&
            selection.PackageProfile is "infisical-runtime" or "seven-package", "enterprise-selection");
        ValidateSelection(selection.Kind, selection.ScenarioIds, selection.Provider);
        byte[] profile = Read(Path.Combine(source, "docs/internal/compatibility"), ProfileFile);
        ValidateDeclaration(profile);
        Guard.Require(cohort is not null || selection.Kind is "source-offline" or "connected-advisory",
            "enterprise-cohort-required");
        VerificationCohortRecord? record = cohort is null ? null : VerificationCohort.Check(source, cohort);
        Guard.Require(record is null || selection.Sdk == record.Sdk &&
            selection.SourceRevision == record.SourceCommit, "enterprise-cohort-binding");
        LocalSourceSnapshot snapshot = cohort is null ? LocalQualification.CaptureSource(source) :
            LocalQualification.Check(source, Path.Combine(cohort, "local"), Path.Combine(cohort, "qualification")).Source;
        string folder = selection.PackageProfile == "infisical-runtime" ? "local" : "family";
        var binding = new EnterpriseHardeningBinding(Manifest.Hash(profile), selection.SourceRevision,
            snapshot.Sha256, selection.RunId, selection.Sdk, selection.Runtime, selection.Platform,
            Proof(selection.Proofs.Evidence)!)
        {
            Archives = record is null ? null : record.Files.Where(f => f.File.StartsWith(folder + "/", StringComparison.Ordinal))
                .Select(f => new EnterpriseHardeningArchive(
                    Path.GetFileName(f.File)[..^($".{record.Version}.nupkg".Length)], record.Version, f.Sha256)).ToArray(),
            CohortSha256 = cohort is null ? null :
                Manifest.Hash(Manifest.ReadFile(cohort, VerificationCohort.RecordFile, 4 * 1024 * 1024)),
            TransportSha256 = Proof(selection.Proofs.Transport),
            DeploymentSha256 = Proof(selection.Proofs.Deployment),
            PrincipalSha256 = Proof(selection.Proofs.Principal),
            PolicySha256 = Proof(selection.Proofs.Policy),
            EffectSha256 = Proof(selection.Proofs.Effect),
            GraphSha256 = Proof(selection.Proofs.Graph),
            AuthorizationSha256 = Proof(selection.Proofs.Authorization)
        };
        ValidateBinding(binding, selection.Kind, "unavailable");
        return new(selection.Kind, selection.ScenarioIds, selection.Provider, binding);

        string? Proof(FileDigest? file)
        {
            if (file is null) return null;
            byte[] bytes = Read(selectionDirectory, file.File);
            string hash = Manifest.Hash(bytes);
            Guard.Require(Manifest.IsHash(file.Sha256) && hash == file.Sha256, "enterprise-proof-file");
            return hash;
        }
    }

    public static EnterpriseHardeningDeclaration ReadDeclaration(string directory)
    {
        byte[] bytes = Read(directory, ProfileFile);
        return ValidateDeclaration(bytes);
    }

    private static EnterpriseHardeningDeclaration ValidateDeclaration(byte[] bytes)
    {
        var declaration = Parse<EnterpriseHardeningDeclaration>(bytes);
        Guard.Require(declaration.Schema == "enterprise-hardening-profile.schema.json" &&
            declaration.SchemaVersion == 1 && declaration.Profile == Name &&
            declaration.Kind == "supplemental-declaration" && !declaration.NativeQualified &&
            declaration.ScenarioIds.SequenceEqual(Scenarios) && declaration.EvidenceKinds.SequenceEqual(Kinds) &&
            declaration.InstalledModes.Count == InstalledCases.Count &&
            InstalledCases.All(mode => declaration.InstalledModes.TryGetValue(mode.Key, out string[]? cases) &&
                cases is not null && cases.SequenceEqual(mode.Value)) &&
            declaration.PreservedDenominators == new EnterpriseHardeningDenominators("S01-S16", 17, 21, "unchanged") &&
            declaration.Gates.Select(g => g.Id).SequenceEqual(["G1", "G2", "G3", "G4", "G5"]) &&
            declaration.Gates.All(g => Text(g.Owner) && Text(g.Trigger) && Text(g.Consequence)),
            "enterprise-declaration");
        return declaration;
    }

    private static void ValidateSelection(string kind, string[] scenarios, string? provider)
    {
        Guard.Require(Kinds.Contains(kind, StringComparer.Ordinal) &&
            scenarios.Length is >= 1 and <= 28 &&
            scenarios.All(s => Scenarios.Contains(s, StringComparer.Ordinal)) &&
            scenarios.Distinct(StringComparer.Ordinal).Count() == scenarios.Length &&
            (kind == "native-observation" ? provider is "Infisical" or "AzureKeyVault" : provider is null),
            "enterprise-selection");
    }

    private static void ValidateBinding(EnterpriseHardeningBinding binding, string kind, string status)
    {
        Guard.Require(new[] { binding.ProfileSha256, binding.SourceContentSha256, binding.EvidenceSha256 }
            .All(Manifest.IsHash) && binding.SourceRevision.Length == 40 &&
            binding.SourceRevision.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f') &&
            Label(binding.RunId) && Version10(binding.Sdk) && Version10(binding.Runtime) &&
            Label(binding.Platform), "enterprise-binding-shape");
        Guard.Require(new[] { binding.CohortSha256, binding.TransportSha256, binding.DeploymentSha256,
            binding.PrincipalSha256, binding.PolicySha256, binding.EffectSha256, binding.GraphSha256,
            binding.AuthorizationSha256 }.All(hash => hash is null || Manifest.IsHash(hash)),
            "enterprise-digest-shape");
        if (binding.Archives is { } archives)
            Guard.Require(archives.Length is >= 1 and <= 7 &&
                archives.All(a => Label(a.PackageId) && Label(a.Version) && Manifest.IsHash(a.Sha256)) &&
                archives.Select(a => a.PackageId).Distinct(StringComparer.OrdinalIgnoreCase).Count() == archives.Length,
                "enterprise-archive-shape");
        if (status != "passed") return;
        if (kind is "controlled-installed-offline" or "artifact-integrity" or "native-observation" or
            "platform-observation" or "publication-authorization")
            Guard.Require(binding.Archives is not null && binding.CohortSha256 is not null,
                "enterprise-artifact-required");
        if (kind is "controlled-installed-offline" or "native-observation")
            Guard.Require(binding.TransportSha256 is not null, "enterprise-transport-required");
        if (kind == "native-observation")
            Guard.Require(binding.DeploymentSha256 is not null && binding.PrincipalSha256 is not null &&
                binding.PolicySha256 is not null && binding.EffectSha256 is not null &&
                binding.AuthorizationSha256 is not null, "enterprise-native-required");
        if (kind == "connected-advisory")
            Guard.Require(binding.GraphSha256 is not null, "enterprise-graph-required");
        if (kind == "publication-authorization")
            Guard.Require(binding.AuthorizationSha256 is not null, "enterprise-authority-required");
    }

    private static byte[] Read(string directory, string file)
    {
        try { return Manifest.ReadFile(directory, file, MaximumBytes); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException)
        { throw new ReleaseException("enterprise-file"); }
    }

    private static T Parse<T>(byte[] bytes)
    {
        try
        {
            using var document = JsonDocument.Parse(bytes, new() { MaxDepth = 16 });
            RejectNull(document.RootElement);
            return Manifest.Parse<T>(bytes, MaximumBytes);
        }
        catch (JsonException) { throw new ReleaseException("enterprise-json"); }
    }

    private static void RejectNull(JsonElement value)
    {
        Guard.Require(value.ValueKind != JsonValueKind.Null, "enterprise-json-null");
        if (value.ValueKind == JsonValueKind.Object)
            foreach (var property in value.EnumerateObject()) RejectNull(property.Value);
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray()) RejectNull(item);
    }

    private static bool Label(string value) => value.Length is > 0 and <= 128 &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');
    private static bool Text(string value) => value.Length is > 0 and <= 1024 && value.All(c => c is >= ' ' and <= '~');
    private static bool Version10(string value) => Label(value) && Version.TryParse(value, out var version) &&
        version.Major == 10 && version.Build >= 0;
}
