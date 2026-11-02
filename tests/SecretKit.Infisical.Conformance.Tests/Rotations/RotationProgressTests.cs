using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class RotationProgressTests
{
    [Test]
    public async Task OwnedPostgresRotationConfigurationHasSeparateProgressAndBackendEvidence() =>
        await IdentitySetupTests.RunAsync(OwnedConformanceScenario.Rotation);

    internal static async Task VerifyAsync(Uri origin, IInfisicalTokenSource administrator,
        string organization, string project, Action<string, string> record, CancellationToken cancellationToken)
    {
        using var backend = new OwnedSqlBackend(Environment.GetEnvironmentVariable("SECRETKIT_LIVE_OWNER")!);
        await backend.StartAsync(record, cancellationToken);
        var roles = await backend.QueryAsync("postgres", backend.Password,
            "CREATE ROLE sdk_rotation_a LOGIN; CREATE ROLE sdk_rotation_b LOGIN; " +
                "GRANT SELECT ON sdk_probe TO sdk_rotation_a, sdk_rotation_b;", cancellationToken);
        await Assert.That(roles.ExitCode).IsEqualTo(0);
        using var transport = new ManagementTransport(origin, new() { AllowLoopbackDevelopmentHttp = true });
        var management = new ManagementClient(transport);
        var authority = new ManagementAuthority(management.Authority, administrator, organization, project);
        // Test-only prerequisite provisioning, not an SDK connector API or conformance claim.
        // The verified owner and separately selected administrator above own this resource.
        string connectionId;
        var tokenResult = await administrator.GetTokenAsync(cancellationToken);
        Require(tokenResult.Status, "fixture-authentication", DispatchEvidence.NotDispatched);
        using (var token = tokenResult.Value)
        using (var http = new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            ActivityHeadersPropagator = null
        })
        { Timeout = Timeout.InfiniteTimeSpan })
        {
            byte[] body = JsonSerializer.SerializeToUtf8Bytes(new
            {
                name = "sdk-owned-rotation-db",
                projectId = project,
                method = "username-and-password",
                credentials = new
                {
                    host = backend.Host,
                    port = backend.Port,
                    database = OwnedSqlBackend.Database,
                    username = "postgres",
                    password = backend.Password,
                    sslEnabled = false,
                    sslRejectUnauthorized = true
                }
            });
            byte[] responseBytes = new byte[64 * 1024 + 1];
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post,
                    new Uri(origin, "/api/v1/app-connections/postgres"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Material.Reveal());
                request.Content = new ByteArrayContent(body);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new InvalidOperationException($"Owned rotation prerequisite: HTTP {(int)response.StatusCode}.");
                using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
                int length = 0;
                while (length < responseBytes.Length)
                {
                    int count = await stream.ReadAsync(responseBytes.AsMemory(length), cancellationToken);
                    if (count == 0) break;
                    length += count;
                }
                if (length == responseBytes.Length)
                    throw new InvalidOperationException("Owned rotation prerequisite exceeded its response budget.");
                using var document = JsonDocument.Parse(responseBytes.AsMemory(0, length));
                connectionId = document.RootElement.GetProperty("appConnection").GetProperty("id").GetString()!;
                if (!Guid.TryParseExact(connectionId, "D", out _))
                    throw new InvalidOperationException("Owned rotation prerequisite returned an invalid identifier.");
            }
            finally
            {
                Array.Clear(body);
                Array.Clear(responseBytes);
            }
        }
        record("app-connection", connectionId);
        using var parameters = new PostgresRotationParameters("sdk_rotation_a", "sdk_rotation_b");
        var rotationCreation = new PostgresSecretRotationCreation("sdk-owned-progress-observation", project, "dev", "/",
            connectionId, 1, parameters, new("SDK_ROTATION_USERNAME", "SDK_ROTATION_PASSWORD"),
            isAutoRotationEnabled: false);
        using var createRotation = PostgresSecretRotationOperations.Create(organization, rotationCreation);
        using var rotation = await Apply(createRotation,
            PostgresSecretRotationOperations.CreationTarget(organization, rotationCreation), "rotation-create");
        record("secret-rotation", rotation.Id);
        var address = new InfisicalRotationAddress(project, "dev", "/",
            InfisicalRotationProfile.PostgresCredentials, rotation.Id);
        using var inspect = PostgresSecretRotationOperations.Get(organization, address);
        var result = await management.ExecuteAsync(inspect, authority,
            authority.IssueGrant(inspect.OperationId,
                PostgresSecretRotationOperations.SelectionTarget(organization, address)),
            cancellationToken: cancellationToken);
        Require(result.Status, "rotation-inspection", DispatchEvidence.NotDispatched);
        using var observed = result.Value;
        await Assert.That(observed.Id == rotation.Id).IsTrue();
        await Assert.That(observed.IsAutoRotationEnabled == false).IsTrue();
        // An open native status is only one observation, never an attributed
        // trigger completion or evidence that consumers now use new material.
        Console.WriteLine("OWNED_ROTATION_CONFIGURATION_AND_INITIAL_OBSERVATION_PASSED");

        async Task<T> Apply<T>(ManagementRequest<T> request, ManagementTarget target, string step) where T : notnull
        {
            var receipt = management.CreateReceipt(request);
            var result = await management.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, target), receipt, cancellationToken);
            Require(result.Status, step, receipt.Evidence);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            return result.Value;
        }
    }

    private static void Require(SecretStatus status, string step, DispatchEvidence evidence)
    {
        if (status != SecretStatus.Success)
            throw new InvalidOperationException($"Owned rotation {step}: {status}; evidence: {evidence}.");
    }
}
