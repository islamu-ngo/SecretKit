using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class OwnedSandboxTests
{
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
