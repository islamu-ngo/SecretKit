using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class OwnedSandboxTests
{
    // Docker Hub's linux/amd64 manifest for infisical/infisical:v0.167.12.
    private const string PinnedManifest = "sha256:44cf26b0b556bc340fd6f86c17404a2ae9ed73e783d3dcd3a53977c54c9c5e83";
    private const string OldManifest = "sha256:c063089e4525b033fe6ab9e6858c3afb395ad38d363dcbfa6cbb6122a99a4eea";
    private const string OwnedLabels = """{"secretkit-sdk-owned":"true"}""";
    private const string LoopbackIngress = "8080/tcp -> 127.0.0.1:12345";

    [Test]
    public async Task PinnedReleaseEstablishesVerifiedOwnership()
    {
        using var sandbox = CreateSandbox();

        sandbox.ObserveInspection(OwnedLabels, PinnedManifest, LoopbackIngress);

        await Assert.That(sandbox.Verified).IsTrue();
    }

    [Test]
    [Arguments(OwnedLabels, OldManifest, LoopbackIngress)]
    [Arguments("{}", PinnedManifest, LoopbackIngress)]
    [Arguments("""{"secretkit-sdk-owned":true}""", PinnedManifest, LoopbackIngress)]
    [Arguments("""{"secretkit-sdk-owned":"false","secretkit-sdk-owned":"true"}""", PinnedManifest, LoopbackIngress)]
    [Arguments(OwnedLabels, PinnedManifest, "8080/tcp -> 0.0.0.0:12345")]
    [Arguments(OwnedLabels, PinnedManifest, "8080/tcp -> 127.0.0.1:12346")]
    [Arguments(OwnedLabels, PinnedManifest, "8080/udp -> 127.0.0.1:12345")]
    [Arguments(OwnedLabels, PinnedManifest, "8081/tcp -> 127.0.0.1:12345")]
    [Arguments(OwnedLabels, PinnedManifest, LoopbackIngress + "\n5432/tcp -> 127.0.0.1:12346")]
    public async Task UntrustedInspectionDoesNotEstablishOwnership(string labels, string digest, string ingress)
    {
        using var sandbox = CreateSandbox();

        await Assert.That(() => sandbox.ObserveInspection(labels, digest, ingress)).Throws<InvalidOperationException>();
        await Assert.That(sandbox.Verified).IsFalse();
    }

    [Test]
    public async Task FailedReinspectionRevokesPreviouslyVerifiedOwnership()
    {
        using var sandbox = CreateSandbox();
        sandbox.ObserveInspection(OwnedLabels, OwnedSandbox.AppDigest, LoopbackIngress);

        await Assert.That(() => sandbox.ObserveInspection("{}", OwnedSandbox.AppDigest, LoopbackIngress))
            .Throws<InvalidOperationException>();
        await Assert.That(sandbox.Verified).IsFalse();
    }

    private static OwnedSandbox CreateSandbox()
    {
        using var token = SecretMaterial.FromText("generated");
        return new(new Uri("http://127.0.0.1:12345"), "secretkit-sdk-12345678",
            "10000000-0000-0000-0000-000000000001", token);
    }

    [Test]
    [Arguments("http://example.com:12345")]
    [Arguments("http://localhost:12345")]
    [Arguments("https://127.0.0.1:12345")]
    [Arguments("http://127.0.0.1")]
    [Arguments("http://127.0.0.1:12345/path")]
    [Arguments("http://127.0.0.1:12345?production=true")]
    [Arguments("http://user:password@127.0.0.1:12345")]
    public async Task UntrustedOriginsFailBeforeAnyProcessOrDispatch(string origin)
    {
        using var token = SecretMaterial.FromText("generated");
        await Assert.That(() => new OwnedSandbox(new Uri(origin), "secretkit-sdk-12345678",
            "10000000-0000-0000-0000-000000000001", token)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("unrelated")]
    [Arguments("secretkit-sdk-1234567z")]
    [Arguments("secretkit-sdk-12345678/other")]
    public async Task NonownedIdentifiersFailBeforeAnyProcessOrDispatch(string owner)
    {
        using var token = SecretMaterial.FromText("generated");
        await Assert.That(() => new OwnedSandbox(new Uri("http://127.0.0.1:12345"), owner,
            "10000000-0000-0000-0000-000000000001", token)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task FixtureFormattingAndSerializationDoNotExportAuthority()
    {
        string generated = Guid.NewGuid().ToString("N");
        using var token = SecretMaterial.FromText(generated);
        using var sandbox = new OwnedSandbox(new Uri("http://127.0.0.1:12345"), "secretkit-sdk-12345678",
            "10000000-0000-0000-0000-000000000001", token);
        token.Dispose();
        using var copied = sandbox.CopySetupToken();
        await Assert.That(copied.Reveal()).IsEqualTo(generated);
        await Assert.That(JsonSerializer.Serialize(sandbox)).IsEqualTo("{}");
        await Assert.That(sandbox.ToString()).IsEqualTo("[OwnedSandbox]");
    }
}
