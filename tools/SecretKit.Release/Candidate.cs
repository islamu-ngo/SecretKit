using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace SecretKit.Release;

public sealed record CandidateProposal(int SchemaVersion, string Version, string Publisher,
    string Owner, ProviderScope[] ProviderScopes);
public sealed record CandidateInputs(int SchemaVersion, string Purpose, int RunAttempt, ReleaseManifest Manifest);
public sealed record CandidatePreparation(int SchemaVersion, string SourceCommit, long RunId, int RunAttempt,
    string ScopeSha256, string Issuer, string Reviewer, DateTimeOffset ObservedAt, DateTimeOffset RetainUntil,
    PrerequisiteObservation[] Prerequisites, AuthorityAttestation[] Attestations);

// Producer inputs describe work and measured results. None of these methods
// constructs approval, final artifact metadata, a journal or publication authority.
public static partial class Candidate
{
    public static CandidateProposal ReadProposal(string source)
    {
        CandidateProposal proposal = Manifest.Parse<CandidateProposal>(
            Manifest.ReadFile(Path.Combine(source, "docs/internal/releases"), "candidate.json", 1024 * 1024));
        Guard.Require(proposal.SchemaVersion == 1 && VersionPattern().IsMatch(proposal.Version) &&
            Manifest.SafeIdentity(proposal.Publisher) && Manifest.SafeIdentity(proposal.Owner),
            "candidate-proposal");
        Guard.Require(proposal.ProviderScopes.Length is > 0 and <= 64 &&
            proposal.ProviderScopes.All(s => Manifest.SafeLabel(s.Label) &&
                s.Provider is "Infisical" or "AzureKeyVault" && Manifest.SafeLabel(s.Deployment) &&
                Manifest.SafeLabel(s.ApiVersion) && Manifest.ValidScopeIdentities(s)) &&
            proposal.ProviderScopes.Select(s => s.Label).Distinct().Count() == proposal.ProviderScopes.Length,
            "candidate-provider-scopes");
        Manifest.ExactSet(proposal.ProviderScopes.Select(s => s.Provider).Distinct(),
            ["Infisical", "AzureKeyVault"], "candidate-providers");
        return proposal;
    }

    public static void Prepare(string source, string packages, string output, string commit, long run, int attempt)
    {
        CandidateProposal proposal = ReadProposal(source);
        Guard.Require(CommitPattern().IsMatch(commit) && run > 0 && attempt > 0, "candidate-source");
        var inventories = new List<(FileDigest File, byte[] Bytes, AdmissionInventory Inventory)>();
        foreach (string file in new[] { "infisical.json", "azure-key-vault.json" })
        {
            byte[] bytes = Manifest.ReadFile(Path.Combine(source, "docs/internal/releases/admission"),
                file, 4 * 1024 * 1024);
            AdmissionInventory inventory = Manifest.Parse<AdmissionInventory>(bytes);
            Admission.Validate(inventory, inventory.Operations.Select(o => o.Member).ToArray());
            Guard.Require(inventory.Provider == (file == "infisical.json" ? "Infisical" : "AzureKeyVault") &&
                inventory.Operations.All(o => o.Contract == "implemented-subset"), "candidate-contract-gaps");
            foreach (FileDigest input in inventory.Sources)
            {
                string path = Path.Combine(source, input.File);
                Guard.Require(Manifest.Hash(Manifest.ReadFile(Path.GetDirectoryName(path)!,
                    Path.GetFileName(path), 4 * 1024 * 1024)) == input.Sha256, "candidate-admission-source");
            }
            inventories.Add((new(file, Manifest.Hash(bytes)), bytes, inventory));
        }

        var scope = new ReleaseScope(proposal.Version, commit, Manifest.PackageIds.ToArray(),
            proposal.ProviderScopes.SelectMany(s => inventories.Single(i => i.Inventory.Provider == s.Provider)
                .Inventory.Operations.SelectMany(o => o.Variants.Select(v =>
                    new NativeOperation(s.Provider, o.Id, v, s.Label, "complete")))).ToArray(),
            GateSemantics.Platforms.ToArray(), inventories.Select(i => i.File).ToArray(), "complete-live",
            proposal.ProviderScopes);
        byte[] notices = Manifest.ReadFile(source, "THIRD-PARTY-NOTICES.md", 1024 * 1024);
        Manifest.ExactSet(Directory.EnumerateFiles(packages, "*.nupkg").Select(Path.GetFileName).Select(p => p!),
            Manifest.PackageIds.Select(id => $"{id}.{proposal.Version}.nupkg"), "candidate-original-family");
        PackageRecord[] originals = Manifest.PackageIds.Select(id =>
        {
            string file = $"{id}.{proposal.Version}.nupkg";
            return new PackageRecord(id, file, Manifest.Hash(Manifest.ReadFile(packages, file, PackageArchive.MaximumBytes)));
        }).ToArray();
        byte[] scopeBytes = JsonSerializer.SerializeToUtf8Bytes(scope, Manifest.JsonOptions);
        var manifest = new ReleaseManifest(2, "SecretKit", proposal.Version, commit, Manifest.Repository, run,
            proposal.Publisher, proposal.Owner, "SecretKit.", "release", Manifest.Hash(notices),
            new("scope.json", Manifest.Hash(scopeBytes)), originals, []);
        InspectOriginals(packages, manifest);
        NewDirectory(output);
        foreach (PackageRecord original in originals)
            WriteBytes(output, original.File, Manifest.ReadDigest(packages, new(original.File, original.Sha256)));
        foreach (var inventory in inventories)
            WriteBytes(output, inventory.File.File, inventory.Bytes);
        WriteBytes(output, "scope.json", scopeBytes);
        WriteBytes(output, "THIRD-PARTY-NOTICES.md", notices);
        Write(output, "candidate-inputs.json", new CandidateInputs(1, "candidate-inputs-not-approved", attempt, manifest));
    }

    public static CandidateInputs ReadInputs(string directory)
    {
        CandidateInputs inputs = Manifest.Parse<CandidateInputs>(
            Manifest.ReadFile(directory, "candidate-inputs.json", 4 * 1024 * 1024));
        Guard.Require(inputs.SchemaVersion == 1 && inputs.Purpose == "candidate-inputs-not-approved" &&
            inputs.RunAttempt > 0 && inputs.Manifest.SchemaVersion == 2 && inputs.Manifest.Gates.Length == 0,
            "candidate-inputs");
        return inputs;
    }

    public static void ValidatePreparation(string inputsDirectory, CandidatePreparation preparation,
        DateTimeOffset now)
    {
        CandidateInputs inputs = ReadInputs(inputsDirectory);
        ReleaseManifest manifest = inputs.Manifest;
        ReleaseScope scope = Scope(inputsDirectory, manifest);
        Guard.Require(preparation.SchemaVersion == 1 && preparation.SourceCommit == manifest.SourceCommit &&
            preparation.RunId == manifest.SourceRunId && preparation.RunAttempt == inputs.RunAttempt &&
            preparation.ScopeSha256 == manifest.Scope.Sha256 && Manifest.SafeIdentity(preparation.Issuer) &&
            Manifest.SafeIdentity(preparation.Reviewer) && preparation.Reviewer != preparation.Issuer &&
            preparation.Reviewer != manifest.Owner && preparation.Reviewer != manifest.Publisher &&
            preparation.ObservedAt <= now && preparation.RetainUntil >= now.AddDays(90), "candidate-preparation");
        ValidatePrerequisites(inputsDirectory, scope, preparation.Prerequisites);
        Manifest.ExactSet(preparation.Attestations.Select(a => a.Kind),
            Manifest.GateKinds.Except(GateSemantics.AutomatedKinds), "candidate-authority-coverage");
        foreach (AuthorityAttestation attestation in preparation.Attestations)
        {
            Guard.Require(attestation.Subject == manifest.Owner && Manifest.SafeIdentity(attestation.Issuer) &&
                Manifest.SafeIdentity(attestation.Reviewer) && attestation.Reviewer != attestation.Issuer &&
                attestation.Reviewer != manifest.Owner && attestation.Reviewer != manifest.Publisher &&
                attestation.ObservedAt <= preparation.ObservedAt && Manifest.SafeLabel(attestation.EvidenceLocator) &&
                Manifest.IsHash(attestation.EvidenceSha256), "candidate-authority");
            CheckResults(attestation.Checks, Checks(attestation.Kind, manifest, scope));
        }
    }

    public static MachineReport Measure(string directory, string kind, string platform, long jobId,
        string observations)
    {
        CandidateInputs inputs = ReadInputs(directory);
        ReleaseManifest manifest = inputs.Manifest;
        ReleaseScope scope = Scope(directory, manifest);
        Guard.Require(GateSemantics.AutomatedKinds.Contains(kind) &&
            GateSemantics.ReportPlatforms(kind).Contains(platform) && jobId > 0, "candidate-report-kind");
        DateTimeOffset started = DateTimeOffset.UtcNow;
        InspectOriginals(directory, manifest);
        CheckObservation[] checks;
        NativeCaseObservation[] cases = [];
        PrerequisiteObservation[] prerequisites = [];
        InstallationObservation? installation = null;
        DateTimeOffset completed;
        if (kind is "native-operations" or "live-conformance")
        {
            var raw = new List<MachineReport>();
            var inventories = scope.Inventories.Select(i =>
                Manifest.Parse<AdmissionInventory>(Manifest.ReadDigest(directory, i))).ToArray();
            foreach (string provider in new[] { "Infisical", "AzureKeyVault" })
            {
                Guard.Require(File.Exists(Path.Combine(observations, provider + ".json")),
                    "native-harness-report-missing");
                MachineReport report = Manifest.Parse<MachineReport>(
                    Manifest.ReadFile(observations, provider + ".json", EvidenceLimits.ReportBytes), EvidenceLimits.ReportBytes);
                ValidateBinding(report, inputs, scope, kind, platform, jobId);
                Guard.Require(report.NativeCases.All(c => c.Provider == provider) &&
                    report.Prerequisites.All(p => p.Provider == provider), "native-harness-provider");
                Guard.Require(raw.Count == 0 || report.Installation == raw[0].Installation,
                    "native-harness-installation");
                CheckResults(report.Checks, scope.NativeOperations.Where(o => o.Provider == provider).Select(o => o.Key));
                ValidatePrerequisites(directory,
                    scope with { ProviderScopes = scope.ProviderScopes.Where(s => s.Provider == provider).ToArray() },
                    report.Prerequisites);
                Manifest.ExactSet(report.NativeCases.Select(CaseKey),
                    scope.NativeOperations.Where(o => o.Provider == provider).SelectMany(o =>
                        inventories.Single(i => i.Provider == provider).Operations.Single(i => i.Id == o.Operation)
                            .RequiredCases.Select(c => CaseKey(new(provider, o.Operation, o.Variant, o.Scope, c,
                                true, true, "observed")))), "candidate-native-coverage");
                Guard.Require(report.NativeCases.All(c => c.Passed && c.EffectObserved && c.ReasonCode == "observed"),
                    "candidate-native-effect");
                raw.Add(report);
            }
            // Only measured facts are combined. Positive TRX test counts cannot
            // supply missing case effects, prerequisite observations or checks.
            checks = raw.SelectMany(r => r.Checks).ToArray();
            cases = raw.SelectMany(r => r.NativeCases).ToArray();
            prerequisites = raw.SelectMany(r => r.Prerequisites).ToArray();
            started = raw.Min(r => r.StartedAt);
            completed = raw.Max(r => r.CompletedAt);
            installation = raw[0].Installation;
        }
        else if (kind == "compatibility-install")
        {
            PlatformObservation observed = Manifest.Parse<PlatformObservation>(
                Manifest.ReadFile(observations, "installation.json", 4 * 1024 * 1024));
            installation = PlatformEvidence.Validate(observed, scope);
            PlatformEvidence.MatchOriginals(observed, manifest.Packages);
            Guard.Require($"{observed.OperatingSystem}-{observed.Architecture}-{observed.Framework}" == platform,
                "candidate-installed-platform");
            started = observed.StartedAt;
            completed = observed.CompletedAt;
            checks = [new(platform, true, "observed")];
        }
        else
        {
            // Archive metadata, source commit, original hashes and embedded
            // notices were actually checked above, not inferred from a test exit.
            checks = Checks(kind, manifest, scope).Select(c => new CheckObservation(c, true, "observed")).ToArray();
            completed = DateTimeOffset.UtcNow;
        }
        var result = new MachineReport(2, "release-observation", kind, manifest.Version, manifest.SourceCommit,
            manifest.SourceRunId, inputs.RunAttempt, jobId, platform, GateSemantics.ReportEnvironment(kind),
            manifest.Scope.Sha256, scope.Inventories, manifest.Packages, scope.ProviderScopes, started, completed,
            kind is "native-operations" or "live-conformance" ? cases.Length : checks.Length, 0, 0, 0,
            checks, cases, prerequisites, installation);
        ValidateBinding(result, inputs, scope, kind, platform, jobId);
        return result;
    }

    public static void Assemble(string inputsDirectory, string independentDirectory, string preparationDirectory,
        string output, DateTimeOffset now)
    {
        CandidateInputs inputs = ReadInputs(inputsDirectory);
        var independent = new IndependentEvidence(independentDirectory);
        CandidatePreparation preparation = Manifest.Parse<CandidatePreparation>(
            Manifest.ReadFile(preparationDirectory, "preparation.json", 4 * 1024 * 1024));
        ValidatePreparation(inputsDirectory, preparation, now);
        Guard.Require(independent.Index.RunAttempt == inputs.RunAttempt && independent.Index.ReviewedAt <= now &&
            preparation.ObservedAt <= independent.Index.ReviewedAt, "candidate-review");
        Manifest.ExactSet(independent.Index.Attestations.Select(a => JsonSerializer.Serialize(a, Manifest.JsonOptions)),
            preparation.Attestations.Select(a => JsonSerializer.Serialize(a, Manifest.JsonOptions)), "candidate-reviewed-authority");
        ReleaseManifest manifest = inputs.Manifest;
        ReleaseScope scope = Scope(inputsDirectory, manifest);
        independent.Validate(manifest, scope, candidate: true);
        foreach (ReportOrigin origin in independent.Index.Reports)
        {
            JsonElement metadata = Manifest.Parse<JsonElement>(Manifest.ReadFile(independentDirectory,
                $"{origin.ArtifactId}-artifact.json", 1024 * 1024));
            Guard.Require(metadata.GetProperty("expires_at").GetDateTimeOffset() >= now.AddDays(90),
                "candidate-report-retention");
        }
        NewDirectory(output);
        foreach (PackageRecord package in manifest.Packages)
            WriteBytes(output, package.File, Manifest.ReadDigest(inputsDirectory, new(package.File, package.Sha256)));
        foreach (FileDigest file in scope.Inventories.Append(manifest.Scope))
            WriteBytes(output, file.File, Manifest.ReadDigest(inputsDirectory, file));
        WriteBytes(output, "THIRD-PARTY-NOTICES.md", Manifest.ReadFile(inputsDirectory, "THIRD-PARTY-NOTICES.md", 1024 * 1024));
        Write(output, "preparation.json", preparation);
        var gates = new List<GateRecord>();
        foreach (string kind in Manifest.GateKinds)
        {
            MachineReport[] reports = independent.Index.Reports.Where(r => r.Kind == kind)
                .Select(r => Manifest.Parse<MachineReport>(Manifest.ReadDigest(independentDirectory, r.Report),
                    EvidenceLimits.ReportBytes)).ToArray();
            AuthorityAttestation? attestation = independent.Index.Attestations.SingleOrDefault(a => a.Kind == kind);
            FileDigest record = Write(output, kind + "-record.json", new SemanticGateRecord(2, reports, attestation));
            FileDigest gate = Write(output, kind + ".json", new GateEvidence(kind, "passed", manifest.Version,
                manifest.SourceCommit, manifest.Scope.Sha256, Manifest.PackageIds.ToArray(),
                Checks(kind, manifest, scope), record));
            gates.Add(new(kind, gate.File, gate.Sha256));
        }
        Write(output, "manifest.json", manifest with { Gates = gates.ToArray() });
        // This is the sole final content authority; all raw reports are checked
        // against independently fetched job/artifact metadata and source inputs.
        Manifest.CheckCandidate(output, independent);
    }

    public static void ValidateProducerContext(string repository, string eventName, string reference,
        string protectedRef, string workflowRef)
    {
        Guard.Require(repository == Manifest.RepositoryName && eventName == "push" &&
            reference == "refs/heads/main" && protectedRef == "true" &&
            workflowRef == $"{Manifest.RepositoryName}/.github/workflows/verify.yml@refs/heads/main",
            "candidate-protected-source");
    }

    public static FileDigest Write<T>(string directory, string file, T value) =>
        WriteBytes(directory, file, JsonSerializer.SerializeToUtf8Bytes(value, Manifest.JsonOptions));

    private static FileDigest WriteBytes(string directory, string file, byte[] bytes)
    {
        using var stream = new FileStream(Path.Combine(directory, file), FileMode.CreateNew, FileAccess.Write, FileShare.None);
        stream.Write(bytes);
        return new(file, Manifest.Hash(bytes));
    }

    private static void NewDirectory(string directory)
    {
        Guard.Require(!Directory.Exists(directory) && !File.Exists(directory), "candidate-output-exists");
        Directory.CreateDirectory(directory);
    }

    private static ReleaseScope Scope(string directory, ReleaseManifest manifest) =>
        Manifest.Parse<ReleaseScope>(Manifest.ReadDigest(directory, manifest.Scope));

    private static void ValidateBinding(MachineReport report, CandidateInputs inputs, ReleaseScope scope,
        string kind, string platform, long jobId)
    {
        ReleaseManifest manifest = inputs.Manifest;
        Guard.Require(report.SchemaVersion == 2 && report.Purpose == "release-observation" &&
            report.Kind == kind && report.Platform == platform && report.JobId == jobId &&
            report.SourceCommit == manifest.SourceCommit && report.Version == manifest.Version &&
            report.RunId == manifest.SourceRunId && report.RunAttempt == inputs.RunAttempt &&
            report.ScopeSha256 == manifest.Scope.Sha256 && report.Environment == GateSemantics.ReportEnvironment(kind) &&
            report.StartedAt.Offset == TimeSpan.Zero && report.CompletedAt.Offset == TimeSpan.Zero &&
            report.StartedAt <= report.CompletedAt && report.Discovered > 0 && report.Failed == 0 &&
            report.Skipped == 0 && report.ExitCode == 0 &&
            report.Discovered == (kind is "native-operations" or "live-conformance"
                ? report.NativeCases.Length : report.Checks.Length), "candidate-measured-report");
        GateSemantics.SameFiles(report.Inventories, scope.Inventories, "candidate-report-inventories");
        Manifest.ExactSet(report.Packages.Select(p => $"{p.Id}/{p.File}/{p.Sha256}"),
            manifest.Packages.Select(p => $"{p.Id}/{p.File}/{p.Sha256}"), "candidate-report-originals");
        Manifest.ExactSet(report.ProviderScopes.Select(s => JsonSerializer.Serialize(s, Manifest.JsonOptions)),
            scope.ProviderScopes.Select(s => JsonSerializer.Serialize(s, Manifest.JsonOptions)), "candidate-report-scopes");
        GateSemantics.ValidateInstallation(report);
    }

    private static void ValidatePrerequisites(string directory, ReleaseScope scope, PrerequisiteObservation[] observed)
    {
        AdmissionInventory[] inventories = scope.Inventories.Select(i =>
            Manifest.Parse<AdmissionInventory>(Manifest.ReadDigest(directory, i))).ToArray();
        Manifest.ExactSet(observed.Select(p => $"{p.Provider}/{p.Scope}/{p.Prerequisite}"),
            scope.ProviderScopes.SelectMany(s => inventories.Single(i => i.Provider == s.Provider)
                .Operations.SelectMany(o => o.Prerequisites).Distinct()
                .Select(p => $"{s.Provider}/{s.Label}/{p}")), "candidate-prerequisite-coverage");
        Guard.Require(observed.All(p => p.Confirmed), "candidate-prerequisite-unconfirmed");
    }

    private static void CheckResults(CheckObservation[] observed, IEnumerable<string> expected)
    {
        Manifest.ExactSet(observed.Select(c => c.Key), expected, "candidate-check-coverage");
        Guard.Require(observed.All(c => c.Passed && c.ReasonCode == "observed"), "candidate-check-failed");
    }

    private static string CaseKey(NativeCaseObservation c) =>
        $"{c.Provider}/{c.Operation}/{Uri.EscapeDataString(c.Variant)}/{c.Scope}/{c.Case}";

    private static string[] Checks(string kind, ReleaseManifest manifest, ReleaseScope scope) => kind switch
    {
        "native-operations" or "live-conformance" => scope.NativeOperations.Select(o => o.Key).ToArray(),
        "compatibility-install" => scope.Platforms,
        "provenance" => [manifest.SourceCommit, .. manifest.Packages.Select(p => p.Sha256)],
        "notices" => [manifest.NoticesSha256],
        "namespace-rights" => [.. Manifest.PackageIds, manifest.Prefix],
        "publisher-rights" => [$"publisher:{manifest.Publisher}", $"owner:{manifest.Owner}"],
        "oidc-registration" => [$"{Manifest.RepositoryName}/publish.yml/release", "https://www.nuget.org"],
        "protected-environment" => ["release", "required-reviewers", "prevent-self-review", "main-only"],
        _ => throw new ReleaseException("candidate-gate-kind")
    };

    private static void InspectOriginals(string directory, ReleaseManifest manifest)
    {
        Manifest.ExactSet(manifest.Packages.Select(p => p.Id), Manifest.PackageIds, "candidate-original-family");
        foreach (PackageRecord package in manifest.Packages)
        {
            Guard.Require(package.File == $"{package.Id}.{manifest.Version}.nupkg", "candidate-original-name");
            ArchiveContent archive = PackageArchive.Read(Manifest.ReadDigest(directory, new(package.File, package.Sha256)));
            Guard.Require(!archive.HasSignature && archive.Files.ContainsKey(package.Id + ".nuspec") &&
                archive.Files.ContainsKey("THIRD-PARTY-NOTICES.md") &&
                Manifest.Hash(archive.Files["THIRD-PARTY-NOTICES.md"]) == manifest.NoticesSha256,
                "candidate-original-notices");
            using var stream = new MemoryStream(archive.Files[package.Id + ".nuspec"]);
            using XmlReader reader = XmlReader.Create(stream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 1024 * 1024
            });
            XElement document = XDocument.Load(reader).Root ?? throw new ReleaseException("candidate-nuspec");
            XNamespace ns = document.Name.Namespace;
            XElement metadata = document.Elements(ns + "metadata").Single();
            Guard.Require(metadata.Elements(ns + "id").Single().Value == package.Id &&
                metadata.Elements(ns + "version").Single().Value == manifest.Version &&
                metadata.Elements(ns + "repository").Single().Attribute("commit")?.Value == manifest.SourceCommit &&
                metadata.Elements(ns + "repository").Single().Attribute("url")?.Value == Manifest.Repository &&
                metadata.Elements(ns + "repository").Single().Attribute("type")?.Value == "git",
                "candidate-original-source");
        }
    }

    [GeneratedRegex(@"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[a-z][a-z0-9-]*(\.(0|[1-9][0-9]*|[a-z][a-z0-9-]*))*)?$", RegexOptions.CultureInvariant)]
    private static partial Regex VersionPattern();
    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex CommitPattern();
}
