using System.Text.Json;
using System.Text.Json.Nodes;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class RuntimeHardeningAdmissionTests
{
    internal static RuntimeHardeningSelection Selection => new(1, "runtime-hardening", "infisical-runtime",
        "selected-runtime-read-login-renew",
        new(LocalProfileAdmissionTests.Binding, new string('a', 40), "10.0.302", "10.0.10", "linux-x64"),
        new("owned-deployment", "1.2.3", "oss"),
        new("finite", 60, 120, null, 0, 10, 5, "provider-observed",
            RuntimeHardeningProfile.PolicyHash(new(60, 120, 0, 0))),
        new("https://provider.invalid/", "SafeDefault", "hostname-validity-chain", "none", null, null, null));

    private static byte[] Bytes(RuntimeHardeningSelection selection) =>
        JsonSerializer.SerializeToUtf8Bytes(selection, NativeWorkflow.JsonOptions);

    [Test]
    public async Task ExactFrozenBindingAdmitsWithoutCreatingNativeObservations()
    {
        RuntimeHardeningSelection selected = RuntimeHardeningProfile.Admit(Bytes(Selection), Selection.Binding);
        RuntimeHardeningReport report = RuntimeHardeningProfile.EmptyReport(selected);
        await Assert.That(report.Cases.Select(c => c.Id).SequenceEqual(
            new[] { "RH01", "RH02", "RH03", "RH04", "RH05", "RH06", "RH07", "RH08", "RH09" })).IsTrue();
        await Assert.That(report.Cases.All(c => c.Status == "unavailable")).IsTrue();
        await Assert.That(RuntimeHardeningProfile.Accepts(report, selected)).IsFalse();
    }

    [Test]
    [Arguments("sourceRevision")]
    [Arguments("sdk")]
    [Arguments("runtime")]
    [Arguments("platform")]
    [Arguments("archives")]
    public async Task MissingSourceArchiveOrExecutionBindingFails(string field)
    {
        JsonObject request = JsonNode.Parse(Bytes(Selection))!.AsObject();
        request["binding"]!.AsObject().Remove(field);
        await Assert.That(() => RuntimeHardeningProfile.Admit(
            JsonSerializer.SerializeToUtf8Bytes(request), Selection.Binding)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("profile", "infisical-runtime")]
    [Arguments("packageProfile", "runtime-hardening")]
    [Arguments("authority", "owned-local-native-execution")]
    [Arguments("binding.sourceRevision", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")]
    [Arguments("binding.sdk", "10.0.303")]
    [Arguments("binding.runtime", "10.0.11")]
    [Arguments("binding.platform", "win-x64")]
    [Arguments("provider.version", "")]
    [Arguments("provider.deployment", "")]
    [Arguments("provider.edition", "unknown")]
    [Arguments("network.origin", "http://provider.invalid/")]
    [Arguments("network.mode", "default")]
    [Arguments("network.tls", "accept-any")]
    [Arguments("network.proxy", "ambient")]
    [Arguments("network.privateRootsSha256", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")]
    [Arguments("network.hostPipelineSha256", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")]
    [Arguments("policy.lifetime", "unknown")]
    [Arguments("policy.evidence", "jwt-decoded")]
    [Arguments("policy.evidenceSha256", "")]
    public async Task ContradictorySelectionFailsClosed(string path, string value)
    {
        JsonObject request = JsonNode.Parse(Bytes(Selection))!.AsObject();
        string[] parts = path.Split('.');
        JsonObject owner = parts.Length == 1 ? request : request[parts[0]]!.AsObject();
        owner[parts[^1]] = value;
        await Assert.That(() => RuntimeHardeningProfile.Admit(
            JsonSerializer.SerializeToUtf8Bytes(request), Selection.Binding)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("binding")]
    [Arguments("provider")]
    [Arguments("policy")]
    [Arguments("network")]
    public async Task AbsentPrerequisiteNeverBecomesAnOptionalGate(string field)
    {
        JsonObject request = JsonNode.Parse(Bytes(Selection))!.AsObject();
        request.Remove(field);
        await Assert.That(() => RuntimeHardeningProfile.Admit(
            JsonSerializer.SerializeToUtf8Bytes(request), Selection.Binding)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("ttlSeconds", 0)]
    [Arguments("maximumTtlSeconds", 30)]
    [Arguments("periodSeconds", 60)]
    [Arguments("useLimit", 1)]
    [Arguments("renewBeforeSeconds", 60)]
    [Arguments("requestTimeoutSeconds", 0)]
    public async Task ContradictoryFinitePolicyRejectsBeforeDispatch(string field, int value)
    {
        JsonObject request = JsonNode.Parse(Bytes(Selection))!.AsObject();
        request["policy"]![field] = value;
        await Assert.That(() => RuntimeHardeningProfile.Admit(
            JsonSerializer.SerializeToUtf8Bytes(request), Selection.Binding)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("SafeDefault", "none")]
    [Arguments("SafeWithPrivateTrust", "explicit")]
    [Arguments("HostControlled", "explicit")]
    public async Task ExplicitNetworkSelectionsRequireTheirOwnEvidence(string mode, string proxy)
    {
        var network = Selection.Network with
        {
            Mode = mode,
            Proxy = proxy,
            ProxyEvidenceSha256 = proxy == "explicit" ? new string('c', 64) : null,
            PrivateRootsSha256 = mode == "SafeWithPrivateTrust" ? new string('d', 64) : null,
            HostPipelineSha256 = mode == "HostControlled" ? new string('e', 64) : null
        };
        RuntimeHardeningSelection selected = Selection with { Network = network };
        _ = RuntimeHardeningProfile.Admit(Bytes(selected), selected.Binding);
        if (mode != "SafeDefault")
        {
            selected = selected with { Network = network with { ProxyEvidenceSha256 = null } };
            await Assert.That(() => RuntimeHardeningProfile.Admit(Bytes(selected), selected.Binding))
                .Throws<InvalidOperationException>();
        }
    }

    [Test]
    [Arguments("archive")]
    [Arguments("source")]
    [Arguments("record")]
    public async Task ChangedOriginalArchiveOrSourceRecordRejects(string defect)
    {
        LocalNativeBinding archives = Selection.Binding.Archives;
        archives = defect switch
        {
            "archive" => archives with
            {
                Packages = archives.Packages.Select((p, i) =>
                i == 0 ? p with { Sha256 = new string('e', 64) } : p).ToArray()
            },
            "source" => archives with { SourceSha256 = new string('e', 64) },
            _ => archives with { RecordSha256 = new string('e', 64) }
        };
        var selected = Selection with { Binding = Selection.Binding with { Archives = archives } };
        await Assert.That(() => RuntimeHardeningProfile.Admit(Bytes(selected), Selection.Binding))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("RH01")]
    [Arguments("RH02")]
    [Arguments("RH03")]
    [Arguments("RH04")]
    [Arguments("RH05")]
    [Arguments("RH06")]
    [Arguments("RH07")]
    [Arguments("RH08")]
    [Arguments("RH09")]
    public async Task EachMissingOrFailedNativeObservationPreventsAcceptance(string id)
    {
        RuntimeHardeningReport report = Observed();
        foreach (string status in new[] { "failed", "unavailable" })
        {
            var changed = report with
            {
                Cases = report.Cases.Select(c =>
                c.Id == id ? c with { Status = status } : c).ToArray()
            };
            await Assert.That(RuntimeHardeningProfile.Accepts(changed, Selection)).IsFalse();
        }
        await Assert.That(RuntimeHardeningProfile.Accepts(report with
        { Cases = report.Cases.Where(c => c.Id != id).ToArray() }, Selection)).IsFalse();
    }

    [Test]
    public async Task DeclaredPolicyAndUnboundLoginNeverBecomeNativeProof()
    {
        var declared = Selection with { Policy = Selection.Policy with { Evidence = "declared" } };
        _ = RuntimeHardeningProfile.Admit(Bytes(declared), declared.Binding);
        RuntimeHardeningReport report = Observed();
        await Assert.That(RuntimeHardeningProfile.Accepts(report, Selection)).IsTrue();
        await Assert.That(RuntimeHardeningProfile.Accepts(report with
        { SelectionSha256 = RuntimeHardeningProfile.SelectionHash(declared) }, declared)).IsFalse();
        await Assert.That(RuntimeHardeningProfile.Accepts(report with { FreshLoginRun = null }, Selection)).IsFalse();
        await Assert.That(RuntimeHardeningProfile.Accepts(report with
        { CausalTokenHandoffRun = new string('c', 32) }, Selection)).IsFalse();
        await Assert.That(RuntimeHardeningProfile.Accepts(report with
        { PolicyObservationSha256 = new string('c', 64) }, Selection)).IsFalse();
    }

    [Test]
    public async Task DuplicateJsonAndExtraNativeCasesCannotMasqueradeAsComplete()
    {
        string json = JsonSerializer.Serialize(Selection, NativeWorkflow.JsonOptions);
        byte[] duplicate = System.Text.Encoding.UTF8.GetBytes("{\"schemaVersion\":1," + json[1..]);
        await Assert.That(() => RuntimeHardeningProfile.Admit(duplicate, Selection.Binding))
            .Throws<InvalidOperationException>();
        var report = Observed();
        await Assert.That(RuntimeHardeningProfile.Accepts(report with
        { Cases = [.. report.Cases, report.Cases[0]] }, Selection)).IsFalse();
    }

    [Test]
    public async Task PeriodicPolicyMustBindItsActualPeriod()
    {
        var selected = Selection with
        { Policy = Selection.Policy with { Lifetime = "periodic", MaximumTtlSeconds = 0, PeriodSeconds = 60 } };
        _ = RuntimeHardeningProfile.Admit(Bytes(selected), selected.Binding);
        selected = selected with { Policy = selected.Policy with { PeriodSeconds = 30 } };
        await Assert.That(() => RuntimeHardeningProfile.Admit(Bytes(selected), selected.Binding))
            .Throws<InvalidOperationException>();
    }

    internal static RuntimeHardeningInput Input(RuntimeHardeningSelection? selection = null)
    {
        selection ??= Selection;
        var input = new RuntimeHardeningInput(1, "runtime-hardening", RuntimeHardeningProfile.SelectionHash(selection),
            "selected-runtime-read-login-renew", "owned-read-fixtures",
            new("10000000-0000-0000-0000-000000000001", "runtime-client", "fresh-bootstrap-canary"),
            new("10000000-0000-0000-0000-000000000001", "runtime-client", "recovery-bootstrap-canary"),
            [new("20000000-0000-0000-0000-000000000001", "dev", "/owned", "FIRST"),
             new("20000000-0000-0000-0000-000000000001", "dev", "/owned", "SECOND")],
            new("20000000-0000-0000-0000-000000000001", "dev", "/owned", "DENIED"),
            new("20000000-0000-0000-0000-000000000002", "dev", "/owned", "FOREIGN"),
            true, true, [], null, "", 300);
        return input with { ResponseLossPipelineSha256 = RuntimeHardeningProfile.PipelineHash(selection, input) };
    }

    [Test]
    public async Task NativeWireBindsFrozenSelectionAndSeparateSamePrincipalRecovery()
    {
        var input = RuntimeHardeningProfile.AdmitInput(
            JsonSerializer.SerializeToUtf8Bytes(Input(), NativeWorkflow.JsonOptions), Selection);
        await Assert.That(input.Bootstrap.IdentityId == input.RecoveryBootstrap.IdentityId).IsTrue();
        await Assert.That(input.Bootstrap.ClientSecret != input.RecoveryBootstrap.ClientSecret).IsTrue();
        await Assert.That(input.ToString()).IsEqualTo("[RuntimeHardeningInput]");
        await Assert.That(input.Bootstrap.ToString()).IsEqualTo("[RuntimeHardeningBootstrap]");
        await Assert.That(input.AllowedReads[0].ToString()).IsEqualTo("[RuntimeHardeningRead]");
        await Assert.That(Selection.ToString()).IsEqualTo("[RuntimeHardeningSelection]");
    }

    [Test]
    [Arguments("selectionSha256")]
    [Arguments("authority")]
    [Arguments("readAuthority")]
    [Arguments("bootstrap")]
    [Arguments("recoveryBootstrap")]
    [Arguments("allowedReads")]
    [Arguments("deniedRead")]
    [Arguments("crossScopeRead")]
    [Arguments("acknowledgeManagedStringExport")]
    [Arguments("acknowledgeResponseLoss")]
    [Arguments("responseLossPipelineSha256")]
    public async Task MissingNativePrerequisiteFailsBeforeDispatch(string field)
    {
        var wire = JsonNode.Parse(JsonSerializer.Serialize(Input(), NativeWorkflow.JsonOptions))!.AsObject();
        wire.Remove(field);
        await Assert.That(() => RuntimeHardeningProfile.AdmitInput(
            JsonSerializer.SerializeToUtf8Bytes(wire), Selection)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("stale-selection")]
    [Arguments("recovery-principal")]
    [Arguments("recovery-client")]
    [Arguments("recovery-replay")]
    [Arguments("managed-strings")]
    [Arguments("response-loss")]
    [Arguments("arbitrary-pipeline")]
    [Arguments("ambient-proxy")]
    [Arguments("extra-roots")]
    [Arguments("cross-scope-alias")]
    [Arguments("denied-alias")]
    [Arguments("duplicate-required")]
    [Arguments("unsafe-path")]
    [Arguments("short-deadline")]
    [Arguments("supplied-token")]
    public async Task InvalidNativeProtocolCannotAcquireCredentials(string defect)
    {
        var wire = JsonNode.Parse(JsonSerializer.Serialize(Input(), NativeWorkflow.JsonOptions))!.AsObject();
        switch (defect)
        {
            case "stale-selection": wire["selectionSha256"] = new string('f', 64); break;
            case "recovery-principal": wire["recoveryBootstrap"]!["identityId"] = "10000000-0000-0000-0000-000000000002"; break;
            case "recovery-client": wire["recoveryBootstrap"]!["clientId"] = "other"; break;
            case "recovery-replay": wire["recoveryBootstrap"]!["clientSecret"] = "fresh-bootstrap-canary"; break;
            case "managed-strings": wire["acknowledgeManagedStringExport"] = false; break;
            case "response-loss": wire["acknowledgeResponseLoss"] = false; break;
            case "arbitrary-pipeline": wire["responseLossPipelineSha256"] = new string('e', 64); break;
            case "ambient-proxy": wire["proxyUri"] = "http://proxy.invalid:8080/"; break;
            case "extra-roots": wire["publicRootsDer"] = new JsonArray("ZmFrZQ=="); break;
            case "cross-scope-alias": wire["crossScopeRead"] = wire["allowedReads"]![0]!.DeepClone(); break;
            case "denied-alias": wire["deniedRead"] = wire["allowedReads"]![0]!.DeepClone(); break;
            case "duplicate-required": wire["allowedReads"]![1] = wire["allowedReads"]![0]!.DeepClone(); break;
            case "unsafe-path": wire["allowedReads"]![0]!["folder"] = "/owned/../other"; break;
            case "short-deadline": wire["deadlineSeconds"] = 1; break;
            case "supplied-token": wire["token"] = "never-admitted"; break;
        }
        await Assert.That(() => RuntimeHardeningProfile.AdmitInput(
            JsonSerializer.SerializeToUtf8Bytes(wire), Selection)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task PolicyDigestUsesReturnedIntegralProjectionNotSelectedEvidence()
    {
        var policy = new RuntimeHardeningObservedPolicy(60, 120, 0, 0);
        string expected = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes("runtime-hardening-universal-policy-v1\n60\n120\n0\n0\n"))).ToLowerInvariant();
        await Assert.That(RuntimeHardeningProfile.PolicyHash(policy)).IsEqualTo(expected);
        await Assert.That(RuntimeHardeningProfile.PolicyMatches(policy, Selection.Policy)).IsTrue();
        await Assert.That(RuntimeHardeningProfile.PolicyMatches(policy with { TtlSeconds = 59 }, Selection.Policy)).IsFalse();
        await Assert.That(RuntimeHardeningProfile.PolicyHash(policy with { PeriodSeconds = 60 }) == expected).IsFalse();
        var report = Observed();
        await Assert.That(report.PolicyObservationSha256 == Selection.Policy.EvidenceSha256).IsTrue();
        await Assert.That(RuntimeHardeningProfile.Accepts(report with
        { ObservedPolicy = policy with { MaximumTtlSeconds = 121 } }, Selection)).IsFalse();
    }

    [Test]
    public async Task NewProducerRunRejectsReplayedIncompleteAndUnboundEvidence()
    {
        var report = Observed();
        RuntimeHardeningProfile.ValidateProduced(report, Selection, report.RunId);
        await Assert.That(() => RuntimeHardeningProfile.ValidateProduced(report, Selection,
            new string('c', 32))).Throws<InvalidOperationException>();
        await Assert.That(RuntimeHardeningProfile.Accepts(report with { ExecutionCompleted = false }, Selection)).IsFalse();
        await Assert.That(() => RuntimeHardeningProfile.ValidateProduced(report with
        { SelectionSha256 = new string('f', 64) }, Selection, report.RunId)).Throws<InvalidOperationException>();
        await Assert.That(() => RuntimeHardeningProfile.ValidateProduced(report with
        { Cases = [.. report.Cases, report.Cases[0]] }, Selection, report.RunId)).Throws<InvalidOperationException>();
        string json = JsonSerializer.Serialize(report, NativeWorkflow.JsonOptions);
        await Assert.That(json.Contains("provider.invalid", StringComparison.Ordinal)).IsFalse();
        await Assert.That(json.Contains("bootstrap-canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task NativeHostPipelineHashBindsOriginRoutesProxyRootsAndTimeout()
    {
        var selected = Selection with { Network = Selection.Network with { Mode = "HostControlled" } };
        var input = Input(selected);
        selected = selected with
        { Network = selected.Network with { HostPipelineSha256 = RuntimeHardeningProfile.PipelineHash(selected, input) } };
        input = Input(selected);
        _ = RuntimeHardeningProfile.Admit(Bytes(selected), selected.Binding);
        _ = RuntimeHardeningProfile.AdmitInput(JsonSerializer.SerializeToUtf8Bytes(input, NativeWorkflow.JsonOptions), selected);
        foreach (var changed in new[]
        {
            selected with { Network = selected.Network with { Origin = "https://different.invalid/" } },
            selected with { Network = selected.Network with { ProxyEvidenceSha256 = new string('a', 64) } },
            selected with { Network = selected.Network with { PrivateRootsSha256 = new string('a', 64) } },
            selected with { Policy = selected.Policy with { RequestTimeoutSeconds = 6 } }
        })
            await Assert.That(RuntimeHardeningProfile.PipelineHash(changed, input) == input.ResponseLossPipelineSha256).IsFalse();
        var changedRead = input with { DeniedRead = input.DeniedRead with { Key = "OTHER" } };
        await Assert.That(RuntimeHardeningProfile.PipelineHash(selected, changedRead) == input.ResponseLossPipelineSha256).IsFalse();
        await Assert.That(() => RuntimeHardeningProfile.AdmitInput(
            JsonSerializer.SerializeToUtf8Bytes(changedRead, NativeWorkflow.JsonOptions), selected)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ExplicitProxyAdmissionRequiresItsCanonicalPublicConfiguration()
    {
        const string proxy = "http://proxy.invalid:8080/";
        var selected = Selection with
        {
            Network = Selection.Network with
            { Proxy = "explicit", ProxyEvidenceSha256 = RuntimeHardeningProfile.ProxyHash(proxy) }
        };
        var input = Input(selected) with { ProxyUri = proxy };
        _ = RuntimeHardeningProfile.AdmitInput(JsonSerializer.SerializeToUtf8Bytes(input, NativeWorkflow.JsonOptions), selected);
        await Assert.That(() => RuntimeHardeningProfile.AdmitInput(JsonSerializer.SerializeToUtf8Bytes(
            input with { ProxyUri = "http://different.invalid:8080/" }, NativeWorkflow.JsonOptions), selected))
            .Throws<InvalidOperationException>();
        await Assert.That(() => RuntimeHardeningProfile.ProxyHash("http://user:password@proxy.invalid:8080/"))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task PrivateTrustAdmissionHashesPublicDerAndRejectsChangedRoots()
    {
        using var key = System.Security.Cryptography.RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=offline-root",
            key, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddDays(1));
        string der = Convert.ToBase64String(certificate.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert));
        var selected = Selection with
        {
            Network = Selection.Network with
            { Mode = "SafeWithPrivateTrust", PrivateRootsSha256 = RuntimeHardeningProfile.RootsHash([der]) }
        };
        var input = Input(selected) with { PublicRootsDer = [der] };
        _ = RuntimeHardeningProfile.AdmitInput(JsonSerializer.SerializeToUtf8Bytes(input, NativeWorkflow.JsonOptions), selected);
        await Assert.That(() => RuntimeHardeningProfile.AdmitInput(JsonSerializer.SerializeToUtf8Bytes(
            input with { PublicRootsDer = [] }, NativeWorkflow.JsonOptions), selected)).Throws<InvalidOperationException>();
        await Assert.That(() => RuntimeHardeningProfile.RootsHash([der, der])).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("missing")]
    [Arguments("fractional")]
    [Arguments("string")]
    [Arguments("duplicate")]
    [Arguments("unknown")]
    public async Task ProducedPolicyMustHaveEveryIntegralObservedField(string defect)
    {
        var report = Observed();
        JsonObject json = JsonNode.Parse(JsonSerializer.Serialize(report, NativeWorkflow.JsonOptions))!.AsObject();
        switch (defect)
        {
            case "missing": json["observedPolicy"]!.AsObject().Remove("periodSeconds"); break;
            case "fractional": json["observedPolicy"]!["ttlSeconds"] = 60.5; break;
            case "string": json["observedPolicy"]!["ttlSeconds"] = "60"; break;
            case "unknown": json["observedPolicy"]!["selectedPolicyClaim"] = "never-proof"; break;
        }
        string text = json.ToJsonString();
        if (defect == "duplicate") text = "{\"schemaVersion\":1," + text[1..];
        await Assert.That(() => RuntimeHardeningProfile.ReadProduced(
            System.Text.Encoding.UTF8.GetBytes(text), Selection, report.RunId)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task NativeWireRejectsOversizeAndDuplicatesWithoutProtectedDiagnostics()
    {
        string json = JsonSerializer.Serialize(Input(), NativeWorkflow.JsonOptions);
        await Assert.That(() => RuntimeHardeningProfile.AdmitInput(
            System.Text.Encoding.UTF8.GetBytes("{\"schemaVersion\":1," + json[1..]), Selection))
            .Throws<InvalidOperationException>();
        await Assert.That(() => RuntimeHardeningProfile.AdmitInput(new byte[131073], Selection))
            .Throws<InvalidOperationException>();
        var report = RuntimeHardeningProfile.EmptyReport(Selection);
        string partial = JsonSerializer.Serialize(report, NativeWorkflow.JsonOptions);
        var parsed = RuntimeHardeningProfile.ReadProduced(System.Text.Encoding.UTF8.GetBytes(partial), Selection, report.RunId);
        await Assert.That(parsed.Cases.All(c => c.Status == "unavailable")).IsTrue();
        await Assert.That(RuntimeHardeningProfile.Accepts(parsed, Selection)).IsFalse();
    }

    [Test]
    public async Task FailedRecoveryRetainsRealRenewalUncertaintyWithoutQualifying()
    {
        var partial = Observed() with
        {
            ExecutionCompleted = false,
            RecoveryLoginEvidence = "rejected",
            RecoveryReadObserved = false,
            Cases = Observed().Cases.Select(c => c.Id == "RH06" ?
                c with { Status = "unavailable", Reason = "observation-unavailable" } : c).ToArray()
        };
        var reopened = RuntimeHardeningProfile.ReadProduced(
            JsonSerializer.SerializeToUtf8Bytes(partial, NativeWorkflow.JsonOptions), Selection, partial.RunId);
        await Assert.That(reopened.LossEvidence).IsEqualTo("possibly-dispatched");
        await Assert.That(reopened.ResponseLossObserved && reopened.RecoveryRequiredObserved).IsTrue();
        await Assert.That(reopened.RecoveryLoginEvidence).IsEqualTo("rejected");
        await Assert.That(RuntimeHardeningProfile.Accepts(reopened, Selection)).IsFalse();
        await Assert.That(RuntimeHardeningProfile.Accepts(Observed() with { ResponseLossObserved = false }, Selection)).IsFalse();
        await Assert.That(RuntimeHardeningProfile.Accepts(Observed() with { LoginEvidence = "possibly-dispatched" }, Selection)).IsFalse();
    }

    // Synthetic protocol fixtures are never written as native results.
    private static RuntimeHardeningReport Observed() => RuntimeHardeningProfile.EmptyReport(Selection, new string('a', 32)) with
    {
        FreshLoginRun = new string('a', 32),
        CausalTokenHandoffRun = new string('a', 32),
        PolicyObservationSha256 = RuntimeHardeningProfile.PolicyHash(new(60, 120, 0, 0)),
        ObservedPolicy = new(60, 120, 0, 0),
        ExecutionCompleted = true,
        LoginEvidence = "applied",
        RenewalEvidence = "applied",
        LossEvidence = "possibly-dispatched",
        ResponseLossObserved = true,
        RecoveryRequiredObserved = true,
        RecoveryLoginEvidence = "applied",
        RecoveryReadObserved = true,
        Cases = new[] { "RH01", "RH02", "RH03", "RH04", "RH05", "RH06", "RH07", "RH08", "RH09" }
            .Select(id => new LocalNativeCase(id, "passed", "observed")).ToArray()
    };
}
