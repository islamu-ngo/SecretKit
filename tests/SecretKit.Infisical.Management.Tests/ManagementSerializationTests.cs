using System.Net;
using System.Security.Cryptography;
using System.Text;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class ManagementSerializationTests
{
    private const string Organization = "11111111-1111-4111-8111-111111111111";
    private const string Group = "22222222-2222-4222-8222-222222222222";

    [Test]
    public async Task FingerprintIsUppercaseSha256OfTheExactSerializedBody()
    {
        static void Write(System.Text.Json.Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            writer.WriteString("name", "r\u00f4le");
            writer.WriteNumber("position", 2);
            writer.WriteEndObject();
        }

        byte[] body = ManagementJson.Serialize(Write, "test");
        string expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("""{"name":"r\u00F4le","position":2}""")));

        await Assert.That(Encoding.UTF8.GetString(body)).IsEqualTo("""{"name":"r\u00F4le","position":2}""");
        await Assert.That(ManagementJson.IntentFingerprint(Write, "test")).IsEqualTo(expected);
    }

    [Test]
    public async Task BodyBudgetIsInclusiveForSerializationAndFingerprint()
    {
        // Two quote bytes plus the payload fill the budget exactly.
        string fitting = new('x', ManagementJson.BodyBudget - 2);
        string oversized = new('x', ManagementJson.BodyBudget - 1);

        await Assert.That(ManagementJson.Serialize(writer => writer.WriteStringValue(fitting), "test").Length)
            .IsEqualTo(ManagementJson.BodyBudget);
        await Assert.That(ManagementJson.IntentFingerprint(writer => writer.WriteStringValue(fitting), "test").Length)
            .IsEqualTo(SHA256.HashSizeInBytes * 2);
        await Assert.That(() => ManagementJson.Serialize(writer => writer.WriteStringValue(oversized), "test"))
            .Throws<ArgumentException>();
        await Assert.That(() => ManagementJson.IntentFingerprint(writer => writer.WriteStringValue(oversized), "test"))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task OversizedOperationInputFailsAtConstructionWithoutDisclosingIt()
    {
        string canary = "body-canary" + new string('x', ManagementJson.BodyBudget);

        var error = await Assert.That(() => new ManagementRequest<GroupMetadata>("infisical.post.v1.groups",
                static (_, _, _) => throw new InvalidOperationException(), HttpMethod.Post, "/api/v1/groups",
                new(Organization), writer => writer.WriteStringValue(canary),
                static _ => throw new InvalidOperationException()))
            .Throws<ArgumentException>();

        await Assert.That(error!.Message).IsEqualTo("The management input exceeds its byte budget.");
    }

    [Test]
    [Arguments("token canary")]
    [Arguments("token\r\nX-Injected: 1")]
    [Arguments("ab=cd")]
    public async Task MalformedAdministrativeBearerFailsBeforeDispatch(string token)
    {
        using var wire = new CountingWire();
        using var transport = new ManagementTransport(new("https://management.test"), new()
        {
            Transport = InfisicalTransportOptions.HostControlled(wire)
        });
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new FixedTokens(token), Organization);
        using var request = ScopedAccessOperations.GetGroup(Organization, Group);

        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(Organization, resourceId: Group)));

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Requests).IsEqualTo(0);
    }

    private sealed class FixedTokens(string token) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText(token))));
    }

    private sealed class CountingWire : HttpMessageHandler
    {
        internal int Requests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError));
        }
    }
}
