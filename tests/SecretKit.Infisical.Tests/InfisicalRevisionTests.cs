using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class InfisicalRevisionTests
{
    [Test]
    public async Task RevisionsSurviveClientReplacementButNotResourceRecreation()
    {
        var firstWire = new Wire();
        var secondWire = new Wire();
        await using InfisicalClient first = Client(firstWire);
        await using InfisicalClient second = Client(secondWire);
        using InfisicalSecretRead original = (await first.ReadNativeAsync(Reference(first))).Value;
        using InfisicalSecretRead afterRestart = (await second.ReadNativeAsync(Reference(second))).Value;
        await Assert.That(original.Revision == afterRestart.Revision).IsTrue();
        await Assert.That(original.Revision.GetHashCode()).IsEqualTo(afterRestart.Revision.GetHashCode());
        await Assert.That((await second.ReadNativeAsync(Reference(first))).Status).IsEqualTo(SecretStatus.Invalid);
        secondWire.Fields["id"] = "recreated-resource";
        using InfisicalSecretRead recreated = (await second.ReadNativeAsync(Reference(second))).Value;
        await Assert.That(original.Revision == recreated.Revision).IsFalse();
        original.Dispose();
        await Assert.That(afterRestart.Material.Reveal()).IsEqualTo("owned-material");
        await Assert.That(recreated.Revision.Version).IsEqualTo(1);
        await Assert.That(firstWire.Requests).IsEqualTo(1);
        await Assert.That(secondWire.Requests).IsEqualTo(2);
    }

    [Test]
    [Arguments("id")]
    [Arguments("version")]
    [Arguments("workspace")]
    [Arguments("environment")]
    [Arguments("secretPath")]
    [Arguments("type")]
    [Arguments("secretKey")]
    [Arguments("secretValueHidden")]
    public async Task MissingEvidenceCannotProduceQualifiedMaterial(string field)
    {
        var wire = new Wire();
        wire.Fields.Remove(field);
        wire.Fields["_id"] = "legacy-identity-is-not-a-fallback";
        await using InfisicalClient client = Client(wire);
        SecretOutcome<InfisicalSecretRead> result = await client.ReadNativeAsync(Reference(client));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(() => result.Value).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("0")]
    [Arguments("-1")]
    [Arguments("1.5")]
    [Arguments("\"1\"")]
    [Arguments("null")]
    [Arguments("2147483648")]
    public async Task OnlyPositiveNativeIntegralVersionsQualify(string encoded)
    {
        var wire = new Wire();
        wire.Fields["version"] = JsonSerializer.Deserialize<JsonElement>(encoded);
        await using InfisicalClient client = Client(wire);
        var result = await client.ReadNativeAsync(Reference(client));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("id", "\"\"")]
    [Arguments("id", "null")]
    [Arguments("id", "12")]
    [Arguments("workspace", "null")]
    [Arguments("environment", "[]")]
    [Arguments("secretPath", "false")]
    [Arguments("type", "0")]
    public async Task MalformedEvidenceCannotProduceQualifiedMaterial(string field, string encoded)
    {
        var wire = new Wire();
        wire.Fields[field] = JsonSerializer.Deserialize<JsonElement>(encoded);
        await using InfisicalClient client = Client(wire);
        await Assert.That((await client.ReadNativeAsync(Reference(client))).Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("workspace", "foreign-project")]
    [Arguments("environment", "foreign-environment")]
    [Arguments("secretPath", "/foreign-folder")]
    [Arguments("type", "personal")]
    [Arguments("secretKey", "foreign-key")]
    public async Task ContradictoryReturnedCoordinatesAreInvalid(string field, string foreign)
    {
        var wire = new Wire();
        wire.Fields[field] = foreign;
        await using InfisicalClient client = Client(wire);
        await Assert.That((await client.ReadNativeAsync(Reference(client))).Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    [Arguments(InfisicalResolution.Raw, true)]
    [Arguments(InfisicalResolution.ExpandedReferences, false)]
    [Arguments(InfisicalResolution.ExpandedReferences, true)]
    public async Task ResolvedOrImportedMaterialHasNoResourceOnlyRevision(InfisicalResolution resolution, bool imports)
    {
        var wire = new Wire();
        await using InfisicalClient client = Client(wire, forbidCredentials: true);
        var reference = new SecretReference(client.Authority, new InfisicalSecretAddress(
            "project-canary", "environment-canary", "/folder-canary", "key-canary",
            resolution: resolution, includeImports: imports));
        await Assert.That((await client.ReadNativeAsync(reference)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Requests).IsEqualTo(0);
    }

    [Test]
    public async Task CommonAndNativeReadsHaveOneAcquisitionAndSeparateMaterialOwners()
    {
        var wire = new Wire();
        await using InfisicalClient client = Client(wire);
        using SecretRead common = (await client.ReadAsync(Reference(client))).Value;
        using InfisicalSecretRead native = (await client.ReadNativeAsync(Reference(client))).Value;
        common.Dispose();
        await Assert.That(native.Material.Reveal()).IsEqualTo("owned-material");
        await Assert.That(wire.Requests).IsEqualTo(2);
        string output = JsonSerializer.Serialize(native) + native + native.Revision;
        foreach (string canary in new[]
        {
            "resource-canary", "project-canary", "environment-canary", "folder-canary",
            "key-canary", "owned-material", "token-canary"
        })
            await Assert.That(output.Contains(canary, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task HiddenMaterialRemainsDeniedAndSelectedVersionCannotBeSubstituted()
    {
        var wire = new Wire();
        await using InfisicalClient client = Client(wire);
        wire.Fields["secretValueHidden"] = true;
        await Assert.That((await client.ReadNativeAsync(Reference(client))).Status).IsEqualTo(SecretStatus.Denied);
        wire.Fields["secretValueHidden"] = false;
        await Assert.That((await client.ReadNativeAsync(Reference(client, 2))).Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task RevisionEqualityIncludesOriginNamespaceAndVersion()
    {
        var wire = new Wire();
        await using InfisicalClient first = Client(wire);
        using InfisicalSecretRead original = (await first.ReadNativeAsync(Reference(first))).Value;
        wire.Fields["version"] = 2;
        using InfisicalSecretRead changed = (await first.ReadNativeAsync(Reference(first))).Value;
        await Assert.That(original.Revision == changed.Revision).IsFalse();
        await using var foreign = new InfisicalClient(new("https://other-origin.test"),
            new Tokens(false), new(), null, new Wire());
        using InfisicalSecretRead foreignRead = (await foreign.ReadNativeAsync(Reference(foreign))).Value;
        await Assert.That(original.Revision == foreignRead.Revision).IsFalse();
        wire.Fields["version"] = 1;
        wire.Fields["environment"] = "other-environment";
        var otherNamespace = new SecretReference(first.Authority, new InfisicalSecretAddress(
            "project-canary", "other-environment", "/folder-canary", "key-canary"));
        using InfisicalSecretRead namespaced = (await first.ReadNativeAsync(otherNamespace)).Value;
        await Assert.That(original.Revision == namespaced.Revision).IsFalse();
    }

    private static SecretReference Reference(InfisicalClient client, int? version = null) =>
        new(client.Authority, new InfisicalSecretAddress(
            "project-canary", "environment-canary", "/folder-canary", "key-canary", version));

    private static InfisicalClient Client(Wire wire, bool forbidCredentials = false) =>
        new(new Uri("https://infisical.test"), new Tokens(forbidCredentials), new(), null, wire);

    private sealed class Tokens(bool forbidden) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (forbidden) throw new InvalidOperationException("Invalid selection acquired credentials.");
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText("token-canary"))));
        }
    }

    private sealed class Wire : HttpMessageHandler
    {
        public int Requests { get; private set; }
        public Dictionary<string, object?> Fields { get; } = new()
        {
            ["id"] = "resource-canary",
            ["workspace"] = "project-canary",
            ["environment"] = "environment-canary",
            ["secretPath"] = "/folder-canary",
            ["type"] = "shared",
            ["secretKey"] = "key-canary",
            ["version"] = 1,
            ["secretValue"] = "owned-material",
            ["secretValueHidden"] = false
        };

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests++;
            if (request.Method != HttpMethod.Get || request.RequestUri!.AbsolutePath != "/api/v4/secrets/key-canary")
                throw new InvalidOperationException("Unexpected revision request.");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new { secret = Fields }), Encoding.UTF8,
                    "application/json")
            });
        }
    }
}
