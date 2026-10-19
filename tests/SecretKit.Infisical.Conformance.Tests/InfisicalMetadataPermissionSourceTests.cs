using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalMetadataPermissionSourceTests
{
    [Test]
    [Arguments("signature")]
    [Arguments("writer")]
    [Arguments("channel")]
    [Arguments("schema")]
    [Arguments("root")]
    [Arguments("nonce")]
    [Arguments("epoch")]
    [Arguments("deployment")]
    [Arguments("revision")]
    [Arguments("key")]
    [Arguments("inventory")]
    [Arguments("terminal")]
    [Arguments("replay")]
    public async Task HostPinsBindCompleteJournalContentAndOwnership(string change)
    {
        await using var fixture = new InfisicalMetadataPermissionFixture();
        var c = InfisicalMetadataPermissionGateTests.Cases().First();
        var root = fixture.Root(c.Operation, c.Variant, c.Boundary);
        using var capability = SecretMaterial.FromText("metadata-capability");
        var source = fixture.Source.CreateClient();
        var packet = await source.StepAsync(root, MetadataPermissionStep.Reserve, capability, CancellationToken.None);
        try
        {
            var selectedRoot = change switch
            {
                "root" => root with { Id = "other-root" },
                "nonce" => root with { Nonce = "other-nonce" },
                "epoch" => root with { Profile = root.Profile with { Epoch = "other-epoch" } },
                "deployment" => root with { Profile = root.Profile with { Deployment = "other-deployment" } },
                "revision" => root with { Profile = root.Profile with { ProviderRevision = "other-revision" } },
                _ => root
            };
            var signed = packet.Owner;
            if (change == "key")
            {
                using var replacement = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                selectedRoot = root with
                {
                    Profile = root.Profile with
                    {
                        Pins = root.Profile.Pins.Select(p => p.Journal == MetadataPermissionJournal.Ownership ?
                            p with { SubjectPublicKeyInfo = Convert.ToBase64String(replacement.ExportSubjectPublicKeyInfo()) } : p).ToArray()
                    }
                };
            }
            if (change == "signature")
            {
                using var coordinator = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                byte[] bytes = MetadataPermissionContract.Bytes(signed.Content);
                try
                {
                    signed = signed with
                    {
                        Signature = Convert.ToBase64String(coordinator.SignData(bytes,
                    HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                    };
                }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
            else if (change is "writer" or "channel" or "schema")
            {
                var h = signed.Content.Header;
                h = change switch
                {
                    "writer" => h with { Writer = "coordinator" },
                    "channel" => h with { Channel = "coordinator" },
                    _ => h with { Schema = "other-schema" }
                };
                signed = signed with { Content = signed.Content with { Header = h } };
            }
            else if (change == "inventory") signed = signed with { Content = signed.Content with { Enrolled = [] } };
            else if (change == "terminal") signed = signed with { Content = signed.Content with { Terminal = true } };
            using var verifier = new MetadataPermissionVerifier(selectedRoot);
            if (change == "replay") verifier.Verify(signed, MetadataPermissionJournal.Ownership, "Reserve");
            bool rejected = false;
            try { verifier.Verify(signed, MetadataPermissionJournal.Ownership, "Reserve"); }
            catch (NativeCaseFailureException) { rejected = true; }
            await Assert.That(rejected).IsTrue();
        }
        finally { await source.StepAsync(root, MetadataPermissionStep.Close, null, CancellationToken.None); }
        await InfisicalMetadataPermissionEffectTests.CheckClean(fixture);
    }
    [Test]
    [Arguments("shared-key")]
    [Arguments("shared-writer")]
    [Arguments("shared-channel")]
    [Arguments("remote-key")]
    [Arguments("missing-field")]
    public async Task OperatorAuthorityMustBeExplicitClosedAndDistinct(string change)
    {
        await using var fixture = new InfisicalMetadataPermissionFixture();
        var input = fixture.Input();
        if (change is "shared-key" or "shared-writer" or "shared-channel")
        {
            var first = input.Profile.Pins[0];
            var pins = input.Profile.Pins.ToArray();
            pins[1] = change switch
            {
                "shared-key" => pins[1] with { SubjectPublicKeyInfo = first.SubjectPublicKeyInfo },
                "shared-writer" => pins[1] with { Writer = first.Writer },
                _ => pins[1] with { Channel = first.Channel }
            };
            input = input with { Profile = input.Profile with { Pins = pins } };
        }
        var node = JsonSerializer.SerializeToNode(input, MetadataPermissionContract.Options)!.AsObject();
        if (change == "remote-key") node["announcedKey"] = "not-host-authority";
        if (change == "missing-field") node.Remove("profile");
        var scope = JsonSerializer.SerializeToElement(new JsonObject { ["metadataPermission"] = node });
        bool rejected = false;
        try { _ = MetadataPermissionInput.FromScope(scope); }
        catch (NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
        await Assert.That(fixture.Opens).IsEqualTo(0);
    }
    [Test]
    public async Task ClosedRootCannotReopenDispatchOrMeasureLateWork()
    {
        await using var fixture = new InfisicalMetadataPermissionFixture();
        var c = InfisicalMetadataPermissionGateTests.Cases().First();
        var root = fixture.Root(c.Operation, c.Variant, c.Boundary);
        var source = fixture.Source.CreateClient();
        using var capability = SecretMaterial.FromText("metadata-capability");
        await source.StepAsync(root, MetadataPermissionStep.Reserve, capability, CancellationToken.None);
        await source.StepAsync(root, MetadataPermissionStep.Close, null, CancellationToken.None);
        foreach (var step in new[] { MetadataPermissionStep.Open, MetadataPermissionStep.Arm, MetadataPermissionStep.Close })
        {
            bool rejected = false;
            try { await source.StepAsync(root, step, null, CancellationToken.None); }
            catch (NativeCaseFailureException) { rejected = true; }
            await Assert.That(rejected).IsTrue();
        }
        await InfisicalMetadataPermissionEffectTests.CheckClean(fixture);
    }
}
