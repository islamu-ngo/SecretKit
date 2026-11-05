using System.Text.Json;
using SecretKit.Release;

namespace SecretKit.Infisical.Conformance.Tests;

// Offline protocol controls only. No producer, credentials, installation or
// provider call is selected by this class.
public sealed class EnterpriseHardeningAdmissionTests
{
    [Test]
    public async Task AcceptedRuntimeMechanismDoesNotEstablishEnterpriseNativeCustody()
    {
        RuntimeHardeningSelection selected = RuntimeHardeningAdmissionTests.Selection;
        RuntimeHardeningReport report = Observed(selected);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(report, NativeWorkflow.JsonOptions);
        var parsed = RuntimeHardeningProfile.ReadProduced(bytes, selected, report.RunId);
        await Assert.That(RuntimeHardeningProfile.Accepts(parsed, selected)).IsTrue();

        string directory = Path.Combine(Path.GetTempPath(), "enterprise-native-control-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            string hash = Manifest.Hash(bytes);
            // This deliberately well-shaped declaration can bind every digest to
            // bytes, but those bytes contain no enterprise principal/effect receipt.
            var binding = new EnterpriseHardeningBinding(hash, selected.Binding.SourceRevision, hash,
                report.RunId, selected.Binding.Sdk, selected.Binding.Runtime, selected.Binding.Platform, hash)
            {
                Archives = selected.Binding.Archives.Packages.Select(p =>
                    new EnterpriseHardeningArchive(p.Id, selected.Binding.Archives.Version, p.Sha256)).ToArray(),
                CohortSha256 = hash,
                TransportSha256 = hash,
                DeploymentSha256 = hash,
                PrincipalSha256 = hash,
                PolicySha256 = hash,
                EffectSha256 = hash,
                AuthorizationSha256 = hash
            };
            var expected = new EnterpriseHardeningExpectation("native-observation", ["S24"], "Infisical", binding);
            var observation = new EnterpriseHardeningObservation(1, "enterprise-hardening",
                expected.Kind, expected.ScenarioIds, "passed", false, binding);
            File.WriteAllBytes(Path.Combine(directory, "observation.json"),
                JsonSerializer.SerializeToUtf8Bytes(observation, EnterpriseHardeningProfile.JsonOptions));

            var admitted = EnterpriseHardeningProfile.Admit(directory, "observation.json", expected);
            await Assert.That(admitted.Status).IsEqualTo("unavailable");
            await Assert.That(admitted.Gate).IsEqualTo("G1");
            await Assert.That(admitted.NativeQualified).IsFalse();
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Test]
    [Arguments("old-run")]
    [Arguments("deployment")]
    [Arguments("network")]
    [Arguments("source")]
    [Arguments("archive")]
    [Arguments("absent-effects")]
    [Arguments("declared-policy")]
    [Arguments("controlled-report")]
    public async Task ExistingTypedReportValidationRejectsSubstitutedNativeMechanisms(string defect)
    {
        RuntimeHardeningSelection selected = RuntimeHardeningAdmissionTests.Selection;
        RuntimeHardeningReport report = Observed(selected);
        string run = report.RunId;
        switch (defect)
        {
            case "old-run": run = Guid.Empty.ToString("N"); break;
            case "deployment": selected = selected with { Provider = selected.Provider with { Deployment = "other" } }; break;
            case "network": selected = selected with { Network = selected.Network with { Origin = "https://other.invalid/" } }; break;
            case "source": selected = selected with { Binding = selected.Binding with { SourceRevision = new string('b', 40) } }; break;
            case "archive":
                selected = selected with
                {
                    Binding = selected.Binding with
                    {
                        Archives = selected.Binding.Archives with { SourceSha256 = Manifest.Hash("other-content"u8.ToArray()) }
                    }
                };
                break;
            case "absent-effects": report = report with { RenewalEvidence = "not-dispatched", RecoveryReadObserved = false }; break;
            case "declared-policy":
                selected = selected with { Policy = selected.Policy with { Evidence = "declared" } };
                report = report with { SelectionSha256 = RuntimeHardeningProfile.SelectionHash(selected) };
                break;
            case "controlled-report": report = report with { Kind = "controlled-installed-offline" }; break;
        }
        bool accepted;
        try
        {
            var parsed = RuntimeHardeningProfile.ReadProduced(
                JsonSerializer.SerializeToUtf8Bytes(report, NativeWorkflow.JsonOptions), selected, run);
            accepted = RuntimeHardeningProfile.Accepts(parsed, selected);
        }
        catch (InvalidOperationException) { accepted = false; }
        await Assert.That(accepted).IsFalse();
    }

    [Test]
    public async Task SeparateRecoveryPrincipalCannotBeInferredFromTokenOrDeclarations()
    {
        RuntimeHardeningSelection selected = RuntimeHardeningAdmissionTests.Selection;
        RuntimeHardeningInput input = RuntimeHardeningAdmissionTests.Input(selected);
        input = input with
        {
            RecoveryBootstrap = input.RecoveryBootstrap with { IdentityId = "10000000-0000-0000-0000-000000000099" }
        };
        await Assert.That(() => RuntimeHardeningProfile.AdmitInput(
            JsonSerializer.SerializeToUtf8Bytes(input, NativeWorkflow.JsonOptions), selected))
            .Throws<InvalidOperationException>();
    }

    private static RuntimeHardeningReport Observed(RuntimeHardeningSelection selected)
    {
        const string run = "11111111111111111111111111111111";
        return RuntimeHardeningProfile.EmptyReport(selected, run) with
        {
            FreshLoginRun = run,
            CausalTokenHandoffRun = run,
            ObservedPolicy = new(60, 120, 0, 0),
            PolicyObservationSha256 = RuntimeHardeningProfile.PolicyHash(new(60, 120, 0, 0)),
            ExecutionCompleted = true,
            LoginEvidence = "applied",
            RenewalEvidence = "applied",
            LossEvidence = "possibly-dispatched",
            ResponseLossObserved = true,
            RecoveryRequiredObserved = true,
            RecoveryLoginEvidence = "applied",
            RecoveryReadObserved = true,
            Cases = RuntimeHardeningProfile.NativeCases.Select(id => new LocalNativeCase(id, "passed", "observed")).ToArray()
        };
    }
}
