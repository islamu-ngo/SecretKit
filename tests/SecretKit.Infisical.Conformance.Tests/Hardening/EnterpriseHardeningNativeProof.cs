using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Release;

namespace SecretKit.Infisical.Conformance.Tests;

// This selection is a request, never proof. Native admission additionally requires
// this process's installed-child registration and actual sandbox inspection.
internal sealed record EnterpriseHardeningNativeSelection(string Profile, string Scenario,
    string ProfileSha256, string SourceRevision, string CohortSha256, string Sdk, string Runtime, string Platform);

internal sealed class EnterpriseHardeningNativeProof
{
    private readonly byte[] expected;
    internal EnterpriseHardeningNativeProof(EnterpriseHardeningExpectation expected) =>
        this.expected = JsonSerializer.SerializeToUtf8Bytes(expected, EnterpriseHardeningProfile.JsonOptions);
    internal EnterpriseHardeningExpectation Expectation =>
        JsonSerializer.Deserialize<EnterpriseHardeningExpectation>(expected, EnterpriseHardeningProfile.JsonOptions)!;
    internal bool Matches(EnterpriseHardeningExpectation candidate) =>
        expected.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(candidate, EnterpriseHardeningProfile.JsonOptions));
    internal static string ReportHash(LocalNativeReport report) => Hash(report with
    {
        // Cleanup is joined from the owner's completed task, never from the child.
        ProducerCleanup = new("unavailable", 0, 0)
    });
    internal static string Hash<T>(T value)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value, NativeWorkflow.JsonOptions);
        try { return Manifest.Hash(bytes); }
        finally { Array.Clear(bytes); }
    }
    public override string ToString() => "[EnterpriseHardeningNativeProof]";
}

// An observation returned after admission, not an importable authority.
internal sealed class EnterpriseHardeningNativeObservation(string kind, EnterpriseHardeningExpectation evidence)
{
    internal string Kind { get; } = kind;
    internal bool NativeQualified => Kind == "native-owner-observation";
    internal EnterpriseHardeningExpectation Evidence { get; } = evidence;
    public override string ToString() => "[EnterpriseHardeningNativeObservation]";
}

internal sealed partial class OwnedSandbox
{
    private sealed record NativeInspection(string Labels, string Image, string Ingress)
    {
        public override string ToString() => "[NativeInspection]";
    }
    private NativeInspection? nativeInspection;
    // Only VerifyAsync calls this, after its actual three successful child commands.
    // ObserveInspection remains useful to controlled fixtures and cannot issue it.
    private void RecordNativeInspection(string labels, string image, string ingress) =>
        nativeInspection = new(labels, image, ingress);
    internal void RequireNativeInspection()
    {
        NativeWorkflow.Require(nativeInspection is not null && Verified);
        ObserveInspection(nativeInspection!.Labels, nativeInspection.Image, nativeInspection.Ingress);
    }
}

internal sealed partial class LocalNativeProof
{
    private sealed record EnterpriseActor(string Identity, string Configuration, string Client, string? Role,
        string? Project, string? OtherProject, int Ttl, int Maximum, int Period, long Uses)
    {
        public override string ToString() => "[EnterpriseActor]";
    }
    private readonly Dictionary<string, EnterpriseActor> enterpriseActors = [];
    private EnterpriseHardeningNativeSelection? enterpriseSelection;
    private EnterpriseHardeningNativeProof? enterpriseProof;
    private Task<LocalProducerCleanup>? enterpriseCleanup = null;
    private bool enterpriseClosed = false;

    internal void SelectEnterprise(EnterpriseHardeningNativeSelection selected)
    {
        NativeWorkflow.Require(produced is null && enterpriseSelection is null && !enterpriseClosed &&
            selected.Profile == EnterpriseHardeningProfile.Name && selected.Scenario == "S24" &&
            Manifest.IsHash(selected.ProfileSha256) && Manifest.IsHash(selected.CohortSha256) &&
            selected.SourceRevision.Length == 40 &&
            selected.SourceRevision.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f') &&
            Version.TryParse(selected.Sdk, out var sdk) && sdk.Major == 10 &&
            Version.TryParse(selected.Runtime, out var runtime) && runtime.Major == 10 &&
            !string.IsNullOrWhiteSpace(selected.Platform) && selection.AllowLoopbackDevelopmentHttp);
        enterpriseSelection = selected with { };
    }

    private void RecordEnterpriseActor(TrialActor actor, string? role, string? project, string? otherProject)
    {
        if (enterpriseSelection is null) return;
        enterpriseActors.Add(actor.Purpose, new(actor.Identity, actor.ConfigurationId, actor.ClientId,
            role, project, otherProject, actor.Ttl, actor.Maximum, actor.Period, actor.Uses));
    }

    private void CaptureEnterpriseReport(LocalNativeReport report)
    {
        if (enterpriseSelection is not { } selected) return;
        // Failure to qualify must not prevent adoption of the original child
        // effects or the existing cleanup protocol.
        if (enterpriseClosed || enterpriseProof is not null || !childObserved ||
            produced is null || !challengesObserved || !report.ExecutionCompleted ||
            report.ProofRun != RunId || report.Platform != selected.Platform ||
            !LocalProfileConformance.SameBinding(report.Binding, binding) ||
            report.CreateEffect != DispatchEvidence.Applied || report.UpdateEffect != DispatchEvidence.Applied) return;
        string[] required = ["read", "read-native", "denied-read", "runtime-write-denied", "create",
            "update-value", "network", "deployment-binding", "actor-binding", "policy-binding"];
        if (!required.All(id => report.Cases.Single(c => c.Id == id).Status == "passed") ||
            !report.SupplementalCases.All(c => c.Status == "passed" && c.Reason == "observed") ||
            !new[] { "runtime", "denied", "writer", "observer" }.All(enterpriseActors.ContainsKey)) return;
        if (enterpriseActors["runtime"].Identity != produced.Runtime.Id ||
            enterpriseActors["denied"].Identity != produced.Denied.Id ||
            enterpriseActors["writer"].Identity != produced.Writer.Id ||
            enterpriseActors["observer"].Identity != produced.Observer.Id) return;
        var actors = enterpriseActors.OrderBy(pair => pair.Key, StringComparer.Ordinal).ToArray();
        var evidence = new EnterpriseHardeningBinding(selected.ProfileSha256, selected.SourceRevision,
            binding.SourceSha256, RunId, selected.Sdk, selected.Runtime, selected.Platform,
            EnterpriseHardeningNativeProof.ReportHash(report))
        {
            Archives = binding.Packages.OrderBy(package => package.Id, StringComparer.Ordinal)
                .Select(package => new EnterpriseHardeningArchive(package.Id, binding.Version, package.Sha256)).ToArray(),
            CohortSha256 = selected.CohortSha256,
            TransportSha256 = EnterpriseHardeningNativeProof.Hash(new
            {
                Profile = "owned-ipv4-loopback-http",
                Origin = sandbox.Origin.AbsoluteUri,
                selection.AllowLoopbackDevelopmentHttp,
                ConsumerTransport = "HostControlled-SocketsHttpHandler",
                AllowAutoRedirect = false,
                UseCookies = false,
                Propagation = "none",
                Proxy = "system-default"
            }),
            DeploymentSha256 = EnterpriseHardeningNativeProof.Hash(new
            {
                sandbox.Owner,
                Origin = sandbox.Origin.AbsoluteUri,
                Image = OwnedSandbox.AppDigest
            }),
            PrincipalSha256 = EnterpriseHardeningNativeProof.Hash(actors.Select(pair => new
            {
                Role = pair.Key,
                pair.Value.Identity,
                pair.Value.Configuration,
                pair.Value.Client
            }).ToArray()),
            PolicySha256 = EnterpriseHardeningNativeProof.Hash(actors),
            EffectSha256 = EnterpriseHardeningNativeProof.Hash(new
            {
                report.CreateEffect,
                report.UpdateEffect,
                report.Cases,
                report.SupplementalCases
            }),
            AuthorizationSha256 = EnterpriseHardeningNativeProof.Hash(new
            {
                Authority = "owned-local-native-execution",
                sandbox.Owner,
                RunId
            })
        };
        enterpriseProof = new(new("native-observation", ["S24"], "Infisical", evidence));
    }

    internal EnterpriseHardeningNativeProof EnterpriseProof =>
        !enterpriseClosed && enterpriseProof is { } proof ? proof :
            throw new InvalidOperationException("enterprise-owner-proof-unavailable");

    internal EnterpriseHardeningNativeObservation AdmitEnterprise(EnterpriseHardeningNativeProof proof,
        EnterpriseHardeningExpectation expected)
    {
        NativeWorkflow.Require(!enterpriseClosed && ReferenceEquals(enterpriseProof, proof) &&
            proof.Matches(expected) && enterpriseCleanup is { IsCompletedSuccessfully: true } &&
            enterpriseCleanup.Result == new LocalProducerCleanup("complete", 0, 0));
        return new(LocalProfileConformance.OwnsNativeEnterpriseExecution(this, proof)
            ? "native-owner-observation" : "controlled-owner-observation", proof.Expectation);
    }

    internal void RequireEnterpriseNativeOwner(EnterpriseHardeningNativeSelection selected,
        LocalNativeBinding archives, LocalNativeReport report)
    {
        NativeWorkflow.Require(!enterpriseClosed && enterpriseSelection == selected &&
            LocalProfileConformance.SameBinding(binding, archives) &&
            EnterpriseProof.Expectation.Binding.EvidenceSha256 == EnterpriseHardeningNativeProof.ReportHash(report));
        sandbox.RequireNativeInspection();
    }
}

internal static partial class LocalProfileConformance
{
    private static readonly ConditionalWeakTable<EnterpriseHardeningNativeProof, LocalNativeProof> enterpriseExecutions = new();

    internal static bool OwnsNativeEnterpriseExecution(LocalNativeProof owner, EnterpriseHardeningNativeProof proof) =>
        enterpriseExecutions.TryGetValue(proof, out var issuedBy) && ReferenceEquals(issuedBy, owner);

    private static EnterpriseHardeningNativeSelection SelectEnterpriseCohort(string root, string cohort,
        LocalNativeBinding archives, string observedSdk)
    {
        NativeWorkflow.Require(Path.IsPathFullyQualified(cohort) && OperatingSystem.IsLinux() &&
            RuntimeInformation.ProcessArchitecture == Architecture.X64);
        VerificationCohortRecord verified = VerificationCohort.Check(root, cohort);
        NativeWorkflow.Require(verified.Sdk == observedSdk &&
            SameBinding(archives, Freeze(root, Path.Combine(cohort, "local"), Path.Combine(cohort, "qualification"))));
        string directory = Path.Combine(root, "docs/internal/compatibility");
        _ = EnterpriseHardeningProfile.ReadDeclaration(directory);
        return new(EnterpriseHardeningProfile.Name, "S24",
            Manifest.Hash(Manifest.ReadFile(directory, "enterprise-hardening-profile.json", EnterpriseHardeningProfile.MaximumBytes)),
            verified.SourceCommit, Manifest.Hash(Manifest.ReadFile(cohort, VerificationCohort.RecordFile, 4 * 1024 * 1024)),
            observedSdk, Environment.Version.ToString(), RuntimeInformation.RuntimeIdentifier);
    }

    // Only the actual installed producer calls this after its launch, input
    // revalidation and cleanup. Neither an imported report nor a test flag can
    // enroll a certificate. The private table is the native execution authority.
    private static EnterpriseHardeningNativeObservation RegisterEnterpriseExecution(LocalNativeProof owner,
        EnterpriseHardeningNativeSelection selected, LocalNativeBinding archives, LocalNativeReport report)
    {
        owner.RequireEnterpriseNativeOwner(selected, archives, report);
        var proof = owner.EnterpriseProof;
        _ = owner.AdmitEnterprise(proof, proof.Expectation);
        enterpriseExecutions.Add(proof, owner);
        return owner.AdmitEnterprise(proof, proof.Expectation);
    }
}
