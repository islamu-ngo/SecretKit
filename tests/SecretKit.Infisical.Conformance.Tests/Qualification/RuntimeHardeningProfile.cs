using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace SecretKit.Infisical.Conformance.Tests;

// Native execution admission. It grants no provisioning or administrative authority.
internal static class RuntimeHardeningProfile
{
    internal const string Name = "runtime-hardening";
    internal static readonly string[] NativeCases =
    [
        "RH01", "RH02", "RH03", "RH04", "RH05", "RH06", "RH07", "RH08", "RH09"
    ];

    internal static RuntimeHardeningSelection Admit(byte[] bytes, RuntimeHardeningBinding expected)
    {
        try
        {
            NativeWorkflow.Require(bytes.Length is > 0 and <= 131072);
            using JsonDocument document = JsonDocument.Parse(bytes, new() { MaxDepth = 16 });
            Unique(document.RootElement);
            var selection = JsonSerializer.Deserialize<RuntimeHardeningSelection>(bytes, NativeWorkflow.JsonOptions)!;
            NativeWorkflow.Require(selection.SchemaVersion == 1 && selection.Profile == Name &&
                selection.PackageProfile == "infisical-runtime" &&
                selection.Authority == "selected-runtime-read-login-renew" &&
                Same(selection.Binding, expected));
            NativeWorkflow.ValidateBinding(selection.Binding.Archives);
            NativeWorkflow.Require(Hash(selection.Binding.SourceRevision, 40) &&
                Version10(selection.Binding.Sdk) && Version10(selection.Binding.Runtime) &&
                selection.Binding.Platform == "linux-x64");
            var provider = selection.Provider;
            NativeWorkflow.Require(Text(provider.Deployment) && Version.TryParse(provider.Version, out _) &&
                provider.Edition is "oss" or "enterprise" or "cloud");
            var policy = selection.Policy;
            NativeWorkflow.Require(Hash(policy.EvidenceSha256, 64) &&
                policy.Evidence is "declared" or "provider-observed" &&
                policy.TtlSeconds > 10 && policy.MaximumTtlSeconds >= 0 &&
                policy.UseLimit == 0 && policy.RenewBeforeSeconds > 0 &&
                policy.RenewBeforeSeconds < policy.TtlSeconds &&
                policy.RequestTimeoutSeconds is > 0 and <= 60 &&
                (policy.Lifetime == "finite" && policy.PeriodSeconds is null &&
                    policy.MaximumTtlSeconds >= policy.TtlSeconds ||
                 policy.Lifetime == "periodic" && policy.PeriodSeconds == policy.TtlSeconds));
            var network = selection.Network;
            NativeWorkflow.Require(Uri.TryCreate(network.Origin, UriKind.Absolute, out Uri? origin) &&
                origin.Scheme == "https" && origin.UserInfo.Length == 0 &&
                origin.AbsolutePath == "/" && origin.Query.Length == 0 && origin.Fragment.Length == 0 &&
                network.Mode is "SafeDefault" or "SafeWithPrivateTrust" or "HostControlled" &&
                network.Tls == "hostname-validity-chain" &&
                network.Proxy is "none" or "explicit" &&
                (network.Proxy == "explicit" ? Hash(network.ProxyEvidenceSha256, 64) :
                    network.ProxyEvidenceSha256 is null) &&
                (network.Mode == "SafeWithPrivateTrust" ? Hash(network.PrivateRootsSha256, 64) :
                    network.PrivateRootsSha256 is null) &&
                (network.Mode == "HostControlled" ? Hash(network.HostPipelineSha256, 64) :
                    network.HostPipelineSha256 is null));
            return selection;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or ArgumentException or
            NullReferenceException)
        {
            throw new InvalidOperationException("runtime-hardening-admission");
        }
    }

    internal static bool Same(RuntimeHardeningBinding left, RuntimeHardeningBinding right) =>
        left.SourceRevision == right.SourceRevision && left.Sdk == right.Sdk &&
        left.Runtime == right.Runtime && left.Platform == right.Platform &&
        LocalProfileConformance.SameBinding(left.Archives, right.Archives);

    internal static RuntimeHardeningReport EmptyReport(RuntimeHardeningSelection selection, string? runId = null) =>
        new(1, "REPORT", Name, "native-observation-not-public-approval", SelectionHash(selection),
            runId ?? Guid.NewGuid().ToString("N"), null, null, null, null, false,
            NativeCases.Select(id => new LocalNativeCase(id, "unavailable", "not-observed")).ToArray());

    internal static bool Accepts(RuntimeHardeningReport report, RuntimeHardeningSelection selected)
    {
        _ = Admit(JsonSerializer.SerializeToUtf8Bytes(selected, NativeWorkflow.JsonOptions), selected.Binding);
        return report.SchemaVersion == 1 && report.Record == "REPORT" && report.Profile == Name &&
            report.Kind == "native-observation-not-public-approval" &&
            report.SelectionSha256 == SelectionHash(selected) && report.ExecutionCompleted &&
            report.LoginEvidence == "applied" && report.RenewalEvidence == "applied" &&
            report.LossEvidence == "possibly-dispatched" && report.ResponseLossObserved &&
            report.RecoveryRequiredObserved && report.RecoveryLoginEvidence == "applied" && report.RecoveryReadObserved &&
            selected.Policy.Evidence == "provider-observed" &&
            report.ObservedPolicy is { } observed && PolicyMatches(observed, selected.Policy) &&
            report.PolicyObservationSha256 == PolicyHash(observed) &&
            report.PolicyObservationSha256 == selected.Policy.EvidenceSha256 &&
            Guid.TryParseExact(report.RunId, "N", out _) && report.FreshLoginRun == report.RunId &&
            report.CausalTokenHandoffRun == report.FreshLoginRun &&
            report.Cases.Length == NativeCases.Length &&
            report.Cases.Select(c => c.Id).Order(StringComparer.Ordinal)
                .SequenceEqual(NativeCases.Order(StringComparer.Ordinal)) &&
            report.Cases.All(c => c.Status == "passed" && c.Reason == "observed");
    }

    internal static void ValidateProduced(RuntimeHardeningReport report, RuntimeHardeningSelection selected, string runId)
    {
        NativeWorkflow.Require(report.SchemaVersion == 1 && report.Record == "REPORT" && report.Profile == Name &&
            report.Kind == "native-observation-not-public-approval" && report.RunId == runId &&
            Guid.TryParseExact(runId, "N", out _) && report.SelectionSha256 == SelectionHash(selected) &&
            (report.FreshLoginRun is null || report.FreshLoginRun == runId) &&
            (report.CausalTokenHandoffRun is null || report.CausalTokenHandoffRun == report.FreshLoginRun) &&
            new[] { report.LoginEvidence, report.RenewalEvidence, report.LossEvidence, report.RecoveryLoginEvidence }
                .All(e => e is "not-dispatched" or "possibly-dispatched" or "applied" or "rejected") &&
            report.Cases.Select(c => c.Id).SequenceEqual(NativeCases) &&
            report.Cases.All(c => c.Status is "passed" or "failed" or "unavailable" &&
                c.Reason is "observed" or "not-observed" or "observation-unavailable") &&
            (report.ObservedPolicy is null ? report.PolicyObservationSha256 is null :
                report.PolicyObservationSha256 == PolicyHash(report.ObservedPolicy)));
    }

    internal static RuntimeHardeningReport ReadProduced(byte[] bytes, RuntimeHardeningSelection selected, string runId)
    {
        try
        {
            NativeWorkflow.Require(bytes.Length is > 0 and <= 131072);
            using var document = JsonDocument.Parse(bytes, new() { MaxDepth = 16 });
            Unique(document.RootElement);
            var report = JsonSerializer.Deserialize<RuntimeHardeningReport>(bytes, NativeWorkflow.JsonOptions)!;
            ValidateProduced(report, selected, runId);
            return report;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or ArgumentException or NullReferenceException)
        {
            throw new InvalidOperationException("runtime-hardening-report-admission");
        }
    }

    internal static RuntimeHardeningInput AdmitInput(byte[] bytes, RuntimeHardeningSelection selected)
    {
        try
        {
            NativeWorkflow.Require(bytes.Length is > 0 and <= 131072);
            using var json = JsonDocument.Parse(bytes, new() { MaxDepth = 16 });
            Unique(json.RootElement);
            var input = JsonSerializer.Deserialize<RuntimeHardeningInput>(bytes, NativeWorkflow.JsonOptions)!;
            NativeWorkflow.Require(input.SchemaVersion == 1 && input.Profile == Name &&
                input.SelectionSha256 == SelectionHash(selected) &&
                input.Authority == "selected-runtime-read-login-renew" &&
                input.ReadAuthority == "owned-read-fixtures" &&
                input.AcknowledgeManagedStringExport && input.AcknowledgeResponseLoss &&
                input.DeadlineSeconds is >= 60 and <= 1800 &&
                input.DeadlineSeconds >= 2L * selected.Policy.TtlSeconds + 60 &&
                selected.Policy.TtlSeconds > 4L * selected.Policy.RequestTimeoutSeconds);
            foreach (var bootstrap in new[] { input.Bootstrap, input.RecoveryBootstrap })
                NativeWorkflow.Require(Guid.TryParseExact(bootstrap.IdentityId, "D", out _) &&
                    ProtectedText(bootstrap.ClientId, 1024) && ProtectedText(bootstrap.ClientSecret, 16384));
            NativeWorkflow.Require(input.Bootstrap.IdentityId == input.RecoveryBootstrap.IdentityId &&
                input.Bootstrap.ClientId == input.RecoveryBootstrap.ClientId &&
                input.Bootstrap.ClientSecret != input.RecoveryBootstrap.ClientSecret);
            NativeWorkflow.Require(input.AllowedReads.Length is >= 2 and <= 8 &&
                input.AllowedReads.Distinct().Count() == input.AllowedReads.Length);
            foreach (var read in input.AllowedReads.Concat([input.DeniedRead, input.CrossScopeRead]))
                NativeWorkflow.Require(Guid.TryParseExact(read.ProjectId, "D", out _) &&
                    Segment(read.Environment) && Segment(read.Key) &&
                    read.Folder.StartsWith('/') && read.Folder.Length <= 512 &&
                    (read.Folder == "/" || read.Folder[1..].Split('/').All(Segment)));
            NativeWorkflow.Require(!input.AllowedReads.Contains(input.DeniedRead) &&
                input.DeniedRead != input.CrossScopeRead &&
                input.AllowedReads.All(r => r.ProjectId != input.CrossScopeRead.ProjectId ||
                    r.Environment != input.CrossScopeRead.Environment || r.Folder != input.CrossScopeRead.Folder));
            NativeWorkflow.Require(selected.Network.Proxy == "none" ? input.ProxyUri is null :
                ProxyHash(input.ProxyUri!) == selected.Network.ProxyEvidenceSha256);
            NativeWorkflow.Require(selected.Network.Mode == "SafeWithPrivateTrust" ?
                RootsHash(input.PublicRootsDer) == selected.Network.PrivateRootsSha256 :
                input.PublicRootsDer.Length == 0);
            NativeWorkflow.Require(input.ResponseLossPipelineSha256 == PipelineHash(selected, input) &&
                (selected.Network.Mode != "HostControlled" ||
                    selected.Network.HostPipelineSha256 == PipelineHash(selected, input)));
            return input;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or ArgumentException or
            NullReferenceException or FormatException or CryptographicException)
        {
            throw new InvalidOperationException("runtime-hardening-input-admission");
        }
    }

    internal static string SelectionHash(RuntimeHardeningSelection selection) =>
        Digest(JsonSerializer.SerializeToUtf8Bytes(selection, NativeWorkflow.JsonOptions));

    // Only the four actual integral policy values are projected. Identity/client
    // correspondence is checked against the freshly used bootstrap before projection.
    internal static string PolicyHash(RuntimeHardeningObservedPolicy policy) => Digest(Encoding.UTF8.GetBytes(
        FormattableString.Invariant($"runtime-hardening-universal-policy-v1\n{policy.TtlSeconds}\n{policy.MaximumTtlSeconds}\n{policy.UseLimit}\n{policy.PeriodSeconds}\n")));

    internal static bool PolicyMatches(RuntimeHardeningObservedPolicy observed, RuntimeHardeningPolicy selected) =>
        observed.TtlSeconds == selected.TtlSeconds && observed.MaximumTtlSeconds == selected.MaximumTtlSeconds &&
        observed.UseLimit == selected.UseLimit && observed.PeriodSeconds == (selected.PeriodSeconds ?? 0);

    internal static string PipelineHash(RuntimeHardeningSelection selected, RuntimeHardeningInput input) => Digest(Encoding.UTF8.GetBytes(
        "runtime-hardening-validating-pipeline-v1\n" + new Uri(selected.Network.Origin).AbsoluteUri + "\n" +
        (selected.Network.ProxyEvidenceSha256 ?? "none") + "\n" +
        (selected.Network.PrivateRootsSha256 ?? "system") + "\n" +
        selected.Policy.RequestTimeoutSeconds.ToString(CultureInfo.InvariantCulture) + "\n" +
        "no-redirects;no-cookies;no-ambient-proxy;no-propagation;no-retry;pool-120;chain-hostname-validity;revocation-nocheck;fixed-routes;drop-one-successful-renewal\n" +
        input.Bootstrap.IdentityId + "\n" + string.Join("\n", input.AllowedReads.Concat([input.DeniedRead, input.CrossScopeRead])
            .Select(r => r.ProjectId + "\n" + r.Environment + "\n" + r.Folder + "\n" + r.Key)) + "\n"));

    internal static string ProxyHash(string uri)
    {
        NativeWorkflow.Require(Uri.TryCreate(uri, UriKind.Absolute, out var proxy) &&
            proxy.Scheme is "http" or "https" && proxy.UserInfo.Length == 0 && proxy.AbsolutePath == "/" &&
            proxy.Query.Length == 0 && proxy.Fragment.Length == 0);
        return Digest(Encoding.UTF8.GetBytes("runtime-hardening-proxy-v1\n" + proxy.AbsoluteUri + "\n"));
    }

    internal static string RootsHash(string[] roots)
    {
        NativeWorkflow.Require(roots.Length is >= 1 and <= 16);
        var hashes = new List<string>();
        foreach (string encoded in roots)
        {
            byte[] bytes = Convert.FromBase64String(encoded);
            NativeWorkflow.Require(bytes.Length is > 0 and <= 16384);
            using var certificate = X509CertificateLoader.LoadCertificate(bytes);
            NativeWorkflow.Require(!certificate.HasPrivateKey && certificate.RawData.AsSpan().SequenceEqual(bytes));
            hashes.Add(Digest(bytes));
        }
        NativeWorkflow.Require(hashes.Distinct(StringComparer.Ordinal).Count() == hashes.Count);
        return Digest(Encoding.UTF8.GetBytes("runtime-hardening-roots-v1\n" +
            string.Join("\n", hashes.Order(StringComparer.Ordinal)) + "\n"));
    }

    private static string Digest(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private static bool ProtectedText(string value, int maximum) =>
        value.Length > 0 && value.Length <= maximum && value.All(c => c > ' ' && c < 127);
    private static bool Segment(string value) =>
        value.Length is > 0 and <= 128 && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-');

    internal static RuntimeHardeningBinding CurrentBinding(LocalNativeBinding archives, string revision, string sdk) =>
        new(archives, revision, sdk, Environment.Version.ToString(),
            OperatingSystem.IsLinux() && RuntimeInformation.ProcessArchitecture == Architecture.X64 ?
                "linux-x64" : "unsupported");

    private static bool Version10(string? value) =>
        Version.TryParse(value, out Version? version) && version.Major == 10 && version.Build >= 0;
    private static bool Text(string? value) =>
        value is { Length: > 0 and <= 256 } && !string.IsNullOrWhiteSpace(value) &&
        value.All(c => !char.IsControl(c));
    private static bool Hash(string? value, int length) =>
        value is not null && value.Length == length && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static void Unique(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty property in element.EnumerateObject())
            {
                NativeWorkflow.Require(names.Add(property.Name));
                Unique(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (JsonElement item in element.EnumerateArray()) Unique(item);
    }
}

internal sealed record RuntimeHardeningBinding(LocalNativeBinding Archives, string SourceRevision,
    string Sdk, string Runtime, string Platform)
{
    public override string ToString() => "[RuntimeHardeningBinding]";
}
internal sealed record RuntimeHardeningProvider(string Deployment, string Version, string Edition)
{
    public override string ToString() => "[RuntimeHardeningProvider]";
}
internal sealed record RuntimeHardeningPolicy(string Lifetime, int TtlSeconds, int MaximumTtlSeconds,
    int? PeriodSeconds, int UseLimit, int RenewBeforeSeconds, int RequestTimeoutSeconds,
    string Evidence, string EvidenceSha256)
{
    public override string ToString() => "[RuntimeHardeningPolicy]";
}
internal sealed record RuntimeHardeningNetwork(string Origin, string Mode, string Tls, string Proxy,
    string? ProxyEvidenceSha256, string? PrivateRootsSha256, string? HostPipelineSha256)
{
    public override string ToString() => "[RuntimeHardeningNetwork]";
}
internal sealed record RuntimeHardeningSelection(int SchemaVersion, string Profile, string PackageProfile,
    string Authority, RuntimeHardeningBinding Binding, RuntimeHardeningProvider Provider,
    RuntimeHardeningPolicy Policy, RuntimeHardeningNetwork Network)
{
    public override string ToString() => "[RuntimeHardeningSelection]";
}
internal sealed record RuntimeHardeningReport(int SchemaVersion, string Record, string Profile, string Kind,
    string SelectionSha256, string RunId, string? FreshLoginRun, string? CausalTokenHandoffRun,
    string? PolicyObservationSha256, RuntimeHardeningObservedPolicy? ObservedPolicy,
    bool ExecutionCompleted, LocalNativeCase[] Cases)
{
    [System.Text.Json.Serialization.JsonRequired] public string LoginEvidence { get; init; } = "not-dispatched";
    [System.Text.Json.Serialization.JsonRequired] public string RenewalEvidence { get; init; } = "not-dispatched";
    [System.Text.Json.Serialization.JsonRequired] public string LossEvidence { get; init; } = "not-dispatched";
    [System.Text.Json.Serialization.JsonRequired] public bool ResponseLossObserved { get; init; }
    [System.Text.Json.Serialization.JsonRequired] public bool RecoveryRequiredObserved { get; init; }
    [System.Text.Json.Serialization.JsonRequired] public string RecoveryLoginEvidence { get; init; } = "not-dispatched";
    [System.Text.Json.Serialization.JsonRequired] public bool RecoveryReadObserved { get; init; }
    public override string ToString() => "[RuntimeHardeningReport]";
}
internal sealed record RuntimeHardeningObservedPolicy(int TtlSeconds, int MaximumTtlSeconds, int UseLimit, int PeriodSeconds)
{
    public override string ToString() => "[RuntimeHardeningObservedPolicy]";
}
internal sealed record RuntimeHardeningBootstrap(string IdentityId, string ClientId, string ClientSecret)
{
    public override string ToString() => "[RuntimeHardeningBootstrap]";
}
internal sealed record RuntimeHardeningRead(string ProjectId, string Environment, string Folder, string Key)
{
    public override string ToString() => "[RuntimeHardeningRead]";
}
internal sealed record RuntimeHardeningInput(int SchemaVersion, string Profile, string SelectionSha256,
    string Authority, string ReadAuthority, RuntimeHardeningBootstrap Bootstrap,
    RuntimeHardeningBootstrap RecoveryBootstrap, RuntimeHardeningRead[] AllowedReads,
    RuntimeHardeningRead DeniedRead, RuntimeHardeningRead CrossScopeRead,
    bool AcknowledgeManagedStringExport, bool AcknowledgeResponseLoss, string[] PublicRootsDer,
    string? ProxyUri, string ResponseLossPipelineSha256, int DeadlineSeconds)
{
    public override string ToString() => "[RuntimeHardeningInput]";
}
