using System.Net;
using System.Text.Json;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureRoleFixtureProvisionerTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> ServiceOriginalCases()
    {
        foreach (var member in RoleAdministrationEffects.Members)
            foreach (string variant in member.Variants)
                foreach (string boundary in new[] { "selected-contract", "independent-effect", "denied-authority",
                    "lost-response-no-replay", "cancellation-boundary" })
                {
                    if (!member.Mutation && boundary == "lost-response-no-replay") continue;
                    yield return (member.Operation, variant, boundary);
                }
    }

    public static IEnumerable<(string Operation, string Variant)> UnadmittedReadReplayCases() =>
        RoleAdministrationEffects.Members.Where(m => !m.Mutation)
            .SelectMany(m => m.Variants.Select(v => (m.Operation, v)));
    [Test]
    [MethodDataSource(nameof(UnadmittedReadReplayCases))]
    public async Task UnadmittedReadReplayCasesRemainRejectedBeforeEnrollment(string operation, string variant) =>
        await Assert.That(async () => await OriginalService(operation, variant, "lost-response-no-replay"))
            .Throws<InvalidOperationException>();

    [Test]
    [MethodDataSource(nameof(ServiceOriginalCases))]
    public async Task OriginalRoleEntrypointsUseIndependentlyCollectingOwnedService(
        string operation, string variant, string boundary)
    {
        var result = await OriginalService(operation, variant, boundary);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode + ":" + operation + ":" + variant + ":" + boundary);
    }

    [Test]
    public async Task OriginalRoleCreationRejectsSuccessfulSdkAcknowledgementWithoutNativeEffect()
    {
        string operation = RoleAdministrationEffects.Members.Single(m =>
            m.Operation.EndsWith(".CreateRoleAssignmentAsync", StringComparison.Ordinal)).Operation;
        var result = await OriginalService(operation, "scope.vault", "independent-effect", noOp: true);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
    }

    private static async Task<NativeCaseResult> OriginalService(string operation, string variant, string boundary, bool noOp = false)
    {
        await using var fixture = new ServiceFixture(borrowed: true);
        fixture.Native.State.SelectedAssignmentNoOp = noOp;
        using var settings = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            vaultUri = "https://owned-vault.vault.azure.net",
            setup = ServiceCredential("setup-secret"),
            runtime = ServiceCredential("intended-secret"),
            denied = ServiceCredential("denied-secret"),
            administrative = ServiceCredential("administrative-secret"),
            observer = ServiceCredential("observer-secret"),
            families = new Dictionary<string, object>
            {
                ["RoleAdministration"] = new RoleAdministrationEffects.Input(
                    new(new("https://fixture.invalid/"), "private-owner-capability", TimeSpan.FromSeconds(10)),
                    new(ServiceArm("setup-arm"), ServiceArm("administrative-arm"), ServiceArm("denied-arm"), ServiceArm("observer-arm")),
                    Subscription, "fixture-group", "eastus", Tenant, DefinitionId, PrincipalId, 10, 100, TimeSpan.FromSeconds(10))
            }
        }, new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
        using var environment = OwnedAzureEnvironment.Create(settings.RootElement);
        using var secretBackend = new OriginalNativeBackend(fixture.Native.State, secret: true);
        using var secretHttp = new HttpClient(secretBackend);
        var member = RoleAdministrationEffects.Members.Single(m => m.Operation == operation);
        var definition = new NativeCaseDefinition(new("AzureKeyVault", operation, variant, "owned-source", boundary), member.Member);
        var registry = new NativeCaseRegistry();
        RoleAdministrationEffects.Register(registry, environment, [definition], endpoint =>
            new(endpoint, new SourceForwarder(async (request, token) =>
            {
                if (request.RequestUri!.AbsolutePath == "/role/prepare")
                {
                    var input = JsonSerializer.Deserialize<RoleAdministrationEffects.Prepare>(
                        await request.Content!.ReadAsByteArrayAsync(token), ManagementAdmission.Json)!;
                    fixture.Native.Selector = input.Selection;
                }
                return await fixture.Service.DispatchAsync(request, token);
            })), fixture.SelectedTransport, new HttpClientTransport(secretHttp));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
        await Assert.That(fixture.Native.Read().Released).IsTrue();
        await Assert.That(fixture.Native.State.VaultExists || fixture.Native.State.DeletedVaultExists).IsFalse();
        await Assert.That(fixture.Native.Credentials.All(c => !c.Disposed)).IsTrue();
        return result;
    }

    private static object ServiceCredential(string token) => new { token, expiresAt = "2099-01-01T00:00:00Z" };
    private static AudienceToken ServiceArm(string token) =>
        new(token, new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero), "https://management.azure.com/.default");

    private sealed class SourceForwarder(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token);
    }
    private sealed class OriginalNativeBackend(WireState state, bool secret) : HttpMessageHandler
    {
        internal int Requests;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Interlocked.Increment(ref Requests);
            return state.Respond(request, request.Headers.Authorization?.Parameter ??
                (secret ? "intended-secret" : "administrative-arm"), token);
        }
    }
}
