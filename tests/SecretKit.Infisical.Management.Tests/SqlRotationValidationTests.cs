using System.Net;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class SqlRotationValidationTests
{
    private const string Organization = "organization-fixture";
    private const string Project = "project-fixture";
    private const string Id = "7b15ac64-78ee-4fa5-a7b4-eb2da9ac5796";
    private const string Requirements = """
        {"length":20.5,"required":{"digits":0.5,"lowercase":1.5,"symbols":2.5,"uppercase":3.5},"allowedSymbols":"!"}
        """;

    [Test]
    [Arguments("postgres", false)]
    [Arguments("postgres", true)]
    [Arguments("mysql", false)]
    [Arguments("mysql", true)]
    [Arguments("mssql", false)]
    [Arguments("mssql", true)]
    public async Task UnknownPasswordRequirementFieldsFailClosed(string provider, bool nested)
    {
        JsonObject requirements = JsonNode.Parse(Requirements)!.AsObject();
        (nested ? requirements["required"]!.AsObject() : requirements)["unexpected"] = true;
        await Execute(provider, requirements.ToJsonString(), SecretStatus.Unknown);
    }

    [Test]
    [Arguments("postgres")]
    [Arguments("mysql")]
    [Arguments("mssql")]
    public async Task FractionalRequirementsRemainExact(string provider) =>
        await Execute(provider, Requirements, SecretStatus.Success, (20.5, 0.5));

    [Test]
    [Arguments("postgres")]
    [Arguments("mysql")]
    [Arguments("mssql")]
    public async Task OmittedRequirementsRemainAbsent(string provider) =>
        await Execute(provider, null, SecretStatus.Success, (null, null));

    [Test]
    [Arguments("null")]
    [Arguments("[]")]
    [Arguments("{}")]
    [Arguments("{\"length\":20,\"length\":21,\"required\":{\"digits\":0,\"lowercase\":0,\"symbols\":0,\"uppercase\":0}}")]
    [Arguments("{\"length\":20,\"required\":{\"digits\":0,\"digits\":1,\"lowercase\":0,\"symbols\":0,\"uppercase\":0}}")]
    [Arguments("{\"length\":\"20\",\"required\":{\"digits\":0,\"lowercase\":0,\"symbols\":0,\"uppercase\":0}}")]
    [Arguments("{\"length\":0,\"required\":{\"digits\":0,\"lowercase\":0,\"symbols\":0,\"uppercase\":0}}")]
    [Arguments("{\"length\":251,\"required\":{\"digits\":0,\"lowercase\":0,\"symbols\":0,\"uppercase\":0}}")]
    [Arguments("{\"length\":20,\"required\":{\"digits\":-1,\"lowercase\":0,\"symbols\":0,\"uppercase\":0}}")]
    [Arguments("{\"length\":1e999,\"required\":{\"digits\":0,\"lowercase\":0,\"symbols\":0,\"uppercase\":0}}")]
    [Arguments("{\"length\":20,\"required\":null}")]
    [Arguments("{\"length\":20,\"required\":{\"digits\":0,\"lowercase\":0,\"symbols\":0,\"uppercase\":0},\"allowedSymbols\":null}")]
    [Arguments("{\"length\":20,\"required\":{\"digits\":0,\"lowercase\":0,\"symbols\":0,\"uppercase\":0},\"allowedSymbols\":\"letters\"}")]
    [Arguments("{")]
    public async Task MalformedRequirementsNeverProduceSuccessfulMaterial(string requirements)
    {
        foreach (string provider in new[] { "postgres", "mysql", "mssql" })
            await Execute(provider, requirements, SecretStatus.Unknown);
    }

    private static async Task Execute(string provider, string? requirements, SecretStatus expected,
        (double? Length, double? Digits)? numbers = null)
    {
        using var wire = new Wire(provider, Response(provider, requirements));
        using var transport = new ManagementTransport(new Uri("https://management.test"),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) });
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Organization, Project);
        InfisicalRotationProfile profile = provider switch
        {
            "postgres" => InfisicalRotationProfile.PostgresCredentials,
            "mysql" => InfisicalRotationProfile.MysqlCredentials,
            _ => InfisicalRotationProfile.MssqlCredentials
        };
        var address = new InfisicalRotationAddress(Project, "dev", "/", profile, Id);
        switch (provider)
        {
            case "postgres":
                await Read(PostgresSecretRotationOperations.Get(Organization, address),
                    PostgresSecretRotationOperations.SelectionTarget(Organization, address),
                    value => (value.Parameters.PasswordRequirements?.Length, value.Parameters.PasswordRequirements?.Digits));
                break;
            case "mysql":
                await Read(MySqlSecretRotationOperations.Get(Organization, address),
                    MySqlSecretRotationOperations.SelectionTarget(Organization, address),
                    value => (value.Parameters.PasswordRequirements?.Length, value.Parameters.PasswordRequirements?.Digits));
                break;
            default:
                await Read(MsSqlSecretRotationOperations.Get(Organization, address),
                    MsSqlSecretRotationOperations.SelectionTarget(Organization, address),
                    value => (value.Parameters.PasswordRequirements?.Length, value.Parameters.PasswordRequirements?.Digits));
                break;
        }

        async Task Read<T>(ManagementRequest<T> request, ManagementTarget independent,
            Func<T, (double? Length, double? Digits)> select) where T : notnull
        {
            using (request)
            {
                SecretOutcome<T> outcome = await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, independent));
                try
                {
                    await Assert.That(outcome.Status).IsEqualTo(expected);
                    if (numbers is { } values)
                    {
                        await Assert.That(select(outcome.Value)).IsEqualTo(values);
                    }
                }
                finally
                {
                    if (outcome.IsSuccess) (outcome.Value as IDisposable)?.Dispose();
                }
            }
        }
    }

    private static string Response(string provider, string? requirements) => $$"""
        {"secretRotation":{
        "id":"{{Id}}","projectId":"{{Project}}","name":"rotation-fixture","type":"{{provider}}-credentials",
        "connectionId":"{{Id}}","connection":{"id":"{{Id}}","app":"{{provider}}","name":"connection-fixture"},
        "environment":{"id":"{{Id}}","slug":"dev","name":"Development"},
        "folderId":"{{Id}}","folder":{"id":"{{Id}}","path":"/"},
        "createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z",
        "lastRotatedAt":"2026-10-10T00:00:00Z","lastRotationAttemptedAt":"2026-10-10T00:00:00Z",
        "rotationStatus":"future-provider-state","rotationInterval":2.5,
        "rotateAtUtc":{"hours":1.5,"minutes":2.5},"secretsMapping":{"username":"USERNAME","password":"PASSWORD"},
        "parameters":{"username1":"first-fixture","username2":"second-fixture","rotationStatement":"statement-fixture"
        {{(requirements is null ? "" : ",\"passwordRequirements\":" + requirements)}}
        }
        }
        }
        """;

    private sealed class Wire(string provider, string response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method != HttpMethod.Get || request.RequestUri!.AbsolutePath !=
                $"/api/v2/secret-rotations/{provider}-credentials/{Id}" || request.Headers.Authorization?.Scheme != "Bearer")
                throw new InvalidOperationException("Unexpected SQL rotation request.");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response) });
        }
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new InfisicalAccessToken(SecretMaterial.FromText("token-fixture"))));
    }
}
