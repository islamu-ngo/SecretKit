using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalSqlInputEffectTests
{
    internal static readonly JsonSerializerOptions Options = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };

    public static IEnumerable<(NativeSqlEngine Engine, string Method, string Variant, string Boundary)> ProtectedCases()
    {
        string[] variants =
        [
            "sql.ca.value", "sql.sslEnabled.true", "sql.sslEnabled.false",
            "gatewayId.value", "gatewayId.null", "gatewayPoolId.value", "gatewayPoolId.null",
            "metadata.value", "metadata.empty", "options.value", "usernameTemplate.null",
            "NativeSqlDefinitionProfile.renewalStatement.omitted", "NativeSqlDefinitionProfile.renewalStatement.value",
            "NativeSqlDefinitionProfile.ca.omitted", "NativeSqlDefinitionProfile.ca.value",
            "NativeSqlDefinitionProfile.sslEnabled.omitted", "NativeSqlDefinitionProfile.sslEnabled.false",
            "NativeSqlDefinitionProfile.sslEnabled.true", "NativeSqlDefinitionProfile.gatewayId.omitted",
            "NativeSqlDefinitionProfile.gatewayId.value", "NativeSqlDefinitionProfile.gatewayPoolId.omitted",
            "NativeSqlDefinitionProfile.gatewayPoolId.value", "NativeSqlDefinitionProfile.passwordRequirements.omitted",
            "NativeSqlDefinitionProfile.passwordRequirements.value",
            "NativeSqlDefinitionProfile.clearGatewayId.false", "NativeSqlDefinitionProfile.clearGatewayId.true",
            "NativeSqlDefinitionProfile.clearGatewayPoolId.false", "NativeSqlDefinitionProfile.clearGatewayPoolId.true"
        ];
        foreach (var engine in Enum.GetValues<NativeSqlEngine>())
            foreach (string method in new[] { "CreateDefinitionAsync", "UpdateDefinitionAsync" })
                foreach (string variant in variants)
                    foreach (string boundary in new[] { "selected-contract", "independent-effect",
                        "denied-authority", "cancellation-boundary", "lost-response-no-replay" })
                        if (InfisicalLifecycleFamilies.Catalog.Single(a =>
                            a.Operation == "i.runtime.InfisicalDynamicClient." + method).Variants.Contains(variant))
                            yield return (engine, method, variant, boundary);
        foreach (var engine in Enum.GetValues<NativeSqlEngine>())
            foreach (string variant in new[] { "inputs.omitted", "inputs.same-provider",
                "sql.ca.omitted", "sql.sslEnabled.omitted", "gatewayId.omitted", "gatewayPoolId.omitted",
                "sql.renewStatement.omitted", "sql.renewStatement.value", "passwordRequirements.omitted",
                "passwordRequirements.value", "metadata.omitted", "options.omitted" })
                foreach (string boundary in new[] { "selected-contract", "independent-effect",
                    "denied-authority", "cancellation-boundary", "lost-response-no-replay" })
                    if (InfisicalLifecycleFamilies.Catalog.Single(a =>
                        a.Operation == "i.runtime.InfisicalDynamicClient.UpdateDefinitionAsync").Variants.Contains(variant))
                        yield return (engine, "UpdateDefinitionAsync", variant, boundary);
    }

    [Test]
    [MethodDataSource(nameof(ProtectedCases))]
    public async Task ValidIndependentProtectedInputEvidenceMustPass(
        NativeSqlEngine engine, string method, string variant, string boundary)
    {
        await using var fixture = new InfisicalSqlInputEffectFixture(engine);
        // The backend is calibrated separately through real SDK issuance, wrong
        // credentials, authorization canaries and removal before the family runs.
        await CalibrateAsync(fixture);
        var result = await RunAsync(fixture, method, variant, boundary);
        await Assert.That(fixture.ResidualCount).IsEqualTo(0).Because(result.ReasonCode);
        await Assert.That(fixture.BorrowedRootIntact).IsTrue();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
    }

    [Test]
    [Arguments(NativeSqlEngine.Postgres)]
    [Arguments(NativeSqlEngine.Mysql)]
    [Arguments(NativeSqlEngine.Oracle)]
    [Arguments(NativeSqlEngine.SqlServer)]
    [Arguments(NativeSqlEngine.SapAse)]
    [Arguments(NativeSqlEngine.Vertica)]
    public async Task CalibrationMeasuresCommittedInputsAndActualIssuedCredentials(NativeSqlEngine engine)
    {
        await using var fixture = new InfisicalSqlInputEffectFixture(engine);
        await CalibrateAsync(fixture);
    }

    public static IEnumerable<(NativeSqlEngine Engine, string Variant)> OmissionCases()
    {
        foreach (var engine in Enum.GetValues<NativeSqlEngine>())
            foreach (string variant in new[] { "gatewayId.omitted", "gatewayId.null",
                "gatewayPoolId.omitted", "gatewayPoolId.null", "sql.ca.omitted",
                "sql.sslEnabled.omitted", "sql.renewStatement.omitted", "inputs.omitted" })
                yield return (engine, variant);
    }

    [Test]
    [MethodDataSource(nameof(OmissionCases))]
    public async Task NativePatchOmissionRetainsWhileExplicitClearRemoves(NativeSqlEngine engine, string variant)
    {
        await using var fixture = new InfisicalSqlInputEffectFixture(engine);
        await CalibrateAsync(fixture, variant);
    }

    [Test]
    [Arguments("echo-only", "effect-mismatch")]
    [Arguments("ignored-patch", "effect-mismatch")]
    [Arguments("admin-path-wrong", "effect-mismatch")]
    [Arguments("borrowed-root-damage", "cleanup-incomplete")]
    [Arguments("unsettled", "cleanup-incomplete")]
    [Arguments("replay", "effect-mismatch")]
    [Arguments("cleanup-orphan", "cleanup-incomplete")]
    public async Task IndependentSourceFaultsCannotBeCertified(string mode, string reason)
    {
        await using var fixture = new InfisicalSqlInputEffectFixture(NativeSqlEngine.Postgres, mode);
        var result = await RunAsync(fixture, "UpdateDefinitionAsync", "sql.ca.value",
            mode == "unsettled" ? "lost-response-no-replay" : "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
    }

    [Test]
    public async Task PersistedPasswordPolicyMustConstrainTheActualIssuedCredential()
    {
        // Given correct stored policy and administrative sessions but an unconstrained issuer.
        await using var fixture = new InfisicalSqlInputEffectFixture(NativeSqlEngine.Postgres, "password-policy-ignored");
        // When the selected update supplies password requirements through the public SDK.
        var result = await RunAsync(fixture, "UpdateDefinitionAsync",
            "NativeSqlDefinitionProfile.passwordRequirements.value", "independent-effect");
        // Then storage alone cannot certify the policy's credential effect.
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
    }

    [Test]
    public async Task MissingWitnessRetainsUnavailableGate()
    {
        await using var fixture = new InfisicalSqlInputEffectFixture(NativeSqlEngine.Postgres);
        var result = await RunAsync(fixture, "CreateDefinitionAsync", "sql.ca.value",
            "independent-effect", fixture.Input(witness: false));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
    }

    private static async Task<NativeCaseResult> RunAsync(InfisicalSqlInputEffectFixture fixture,
        string method, string variant, string boundary, JsonObject? input = null)
    {
        var admission = InfisicalLifecycleFamilies.Catalog.Single(a =>
            a.Operation == "i.runtime.InfisicalDynamicClient." + method);
        var row = new NativeCaseDefinition(new("Infisical", admission.Operation, variant, "offline", boundary),
            admission.Member);
        var families = new JsonObject
        {
            [InfisicalDynamicClientEffects.Family] = new JsonObject
            {
                ["scopes"] = new JsonObject
                {
                    ["offline"] = new JsonObject
                    {
                        [admission.Operation] = new JsonObject
                        {
                            [variant] = new JsonObject { [boundary] = input ?? fixture.Input() }
                        }
                    }
                }
            }
        };
        using var environment = Environment(fixture, families);
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, environment, [row], fixture,
            fixture.Source.CreateObserver());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        return (await NativeCaseRunner.RunAsync(registry, [row], deadline.Token)).Single();
    }

    private static NativeEnvironment Environment(InfisicalSqlInputEffectFixture fixture, JsonObject families) =>
        NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = fixture.Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families
        }, Options));

    private static async Task CalibrateAsync(InfisicalSqlInputEffectFixture fixture, string patchVariant = "full")
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var token = deadline.Token;
        using var environment = Environment(fixture, new());
        await using var native = environment.CreateClient(NativeIdentityRole.Setup);
        string name = "calibration-" + Guid.NewGuid().ToString("N");
        InfisicalSqlInputObserver? sourceObserver = patchVariant == "full" ? fixture.Source.CreateObserver() : null;
        var root = new SqlInputRootAttempt(Guid.NewGuid().ToString(), "calibration", "v0.166.3",
            "controlled-sql", "controlled-fixture", Guid.NewGuid().ToString(), fixture.Engine,
            InfisicalSqlInputEffectFixture.ProjectId, "env", "/borrowed/" + name, SqlInputSource.ControlledFixture);
        SqlInputBinding? binding = null;
        SqlInputArm? baselineArm = null;
        if (sourceObserver is not null)
        {
            using var profiles = new SqlInputPrivateProfiles(fixture.Baseline, fixture.Selected,
                "UpdateDefinitionAsync", "full");
            binding = await sourceObserver.OpenAsync(root, profiles, token);
            baselineArm = await sourceObserver.ArmAsync(new(binding, Guid.NewGuid().ToString(), name, null,
                "CreateDefinitionAsync", "seed", "selected-contract", SqlInputConfiguration.Baseline), token);
        }
        var folderTarget = new SecretReference(native.Authority,
            new InfisicalFolderAddress(InfisicalSqlInputEffectFixture.ProjectId, "env", InfisicalSqlInputEffectFixture.EnvironmentId,
                "/borrowed", name: name));
        var folder = await native.CreateFolderAsync(folderTarget,
            new InfisicalNativeAuthority(native.Authority, environment.Tokens(NativeIdentityRole.Setup),
                InfisicalSqlInputEffectFixture.ProjectId),
            new(folderTarget), cancellationToken: token);
        await Assert.That(folder.IsSuccess).IsTrue();
        var scope = new InfisicalDynamicScope("project-slug", "env", "/borrowed/" + name, Guid.Parse(folder.Value.Id));
        await using var client = new InfisicalDynamicClient(fixture.Origin,
            environment.Tokens(NativeIdentityRole.Setup), scope, new() { AllowLoopbackDevelopmentHttp = true });
        var target = client.Definition(name);
        using var baseline = new NativeSqlDefinitionProfile(fixture.Engine, fixture.Baseline.Host,
            fixture.Baseline.Port, fixture.Baseline.Username, fixture.Baseline.Password, fixture.Baseline.Database,
            fixture.Baseline.CreationStatement, fixture.Baseline.RevocationStatement, fixture.Baseline.RenewalStatement,
            fixture.Baseline.Ca, fixture.Baseline.SslEnabled, fixture.Baseline.GatewayId, fixture.Baseline.GatewayPoolId);
        var createReceipt = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.CreateDefinition);
        var created = await client.CreateDefinitionAsync(target, baseline, new(TimeSpan.FromSeconds(60)),
            new(TimeSpan.FromSeconds(300)), createReceipt, token);
        await Assert.That(created.IsSuccess).IsTrue();
        if (sourceObserver is not null)
            await sourceObserver.CompleteAsync(baselineArm!, createReceipt.Evidence, token);
        var retained = new List<(DynamicBackendCoordinate Coordinate, SecretMaterial User, SecretMaterial Password)>();
        try
        {
            await CaptureAsync(created.Value, fixture.Baseline);
            if (sourceObserver is not null)
                await sourceObserver.ObserveAsync(binding!, created.Value.Id, SqlInputConfiguration.Baseline, token);
            using var selected = new NativeSqlDefinitionProfile(fixture.Engine, fixture.Selected.Host,
                fixture.Selected.Port, fixture.Selected.Username, fixture.Selected.Password, fixture.Selected.Database,
                fixture.Selected.CreationStatement, fixture.Selected.RevocationStatement,
                patchVariant == "sql.renewStatement.omitted" ? null : fixture.Selected.RenewalStatement,
                patchVariant == "sql.ca.omitted" ? null : fixture.Selected.Ca,
                patchVariant == "sql.sslEnabled.omitted" ? null : fixture.Selected.SslEnabled,
                patchVariant.StartsWith("gatewayId.", StringComparison.Ordinal) ? null : fixture.Selected.GatewayId,
                patchVariant.StartsWith("gatewayPoolId.", StringComparison.Ordinal) ? null : fixture.Selected.GatewayPoolId,
                clearGatewayId: patchVariant == "gatewayId.null",
                clearGatewayPoolId: patchVariant == "gatewayPoolId.null");
            SqlInputArm? selectedArm = sourceObserver is null ? null : await sourceObserver.ArmAsync(
                new(binding!, Guid.NewGuid().ToString(), name, created.Value.Id, "UpdateDefinitionAsync", "full",
                    "independent-effect", SqlInputConfiguration.Selected), token);
            var updateReceipt = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.UpdateDefinition);
            var updated = await client.UpdateDefinitionAsync(created.Value,
                new(inputs: patchVariant == "inputs.omitted" ? null : selected),
                updateReceipt, token);
            await Assert.That(updated.IsSuccess).IsTrue();
            if (sourceObserver is not null)
                await sourceObserver.CompleteAsync(selectedArm!, updateReceipt.Evidence, token);
            var current = patchVariant == "inputs.omitted" ? fixture.Baseline : fixture.Selected;
            await CaptureAsync(updated.Value, current);
            if (sourceObserver is not null)
                await sourceObserver.ObserveAsync(binding!, updated.Value.Id, SqlInputConfiguration.Selected, token);
            using var source = new HttpClient(new SnapshotHandler(fixture));
            var snapshot = await source.GetFromJsonAsync<JsonObject>(
                "https://controlled.invalid/" + created.Value.Id, token);
            var stored = snapshot!["committedInputs"]!;
            await Assert.That(stored["host"]!.GetValue<string>()).IsEqualTo(current.Host);
            await Assert.That(stored["gatewayId"]?.GetValue<string>()).IsEqualTo(
                patchVariant == "gatewayId.null" ? null : patchVariant is "gatewayId.omitted" or "inputs.omitted" ?
                    fixture.Baseline.GatewayId : fixture.Selected.GatewayId);
            await Assert.That(stored["gatewayPoolId"]?.GetValue<string>()).IsEqualTo(
                patchVariant == "gatewayPoolId.null" ? null : patchVariant is "gatewayPoolId.omitted" or "inputs.omitted" ?
                    fixture.Baseline.GatewayPoolId : fixture.Selected.GatewayPoolId);
            await Assert.That(stored["ca"]?.GetValue<string>()).IsEqualTo(
                patchVariant is "sql.ca.omitted" or "inputs.omitted" ? fixture.Baseline.Ca : fixture.Selected.Ca);
            await Assert.That(stored["sslEnabled"]?.GetValue<bool>()).IsEqualTo(
                patchVariant is "sql.sslEnabled.omitted" or "inputs.omitted" ? fixture.Baseline.SslEnabled : fixture.Selected.SslEnabled);
            await Assert.That(stored["renewStatement"]?.GetValue<string>()).IsEqualTo(
                patchVariant is "sql.renewStatement.omitted" or "inputs.omitted" ?
                    fixture.Baseline.RenewalStatement : fixture.Selected.RenewalStatement);
            await Assert.That(fixture.Sessions.Where(s => s.Phase == "issue").Select(s => s.Admin).ToArray())
                .IsEquivalentTo(new[] { fixture.Baseline.Username, current.Username });
            await Assert.That(fixture.Sessions.Where(s => s.Phase == "issue").All(s =>
                s.MssqlEncryption == (fixture.Engine == NativeSqlEngine.SqlServer &&
                    s.Host == fixture.Selected.Host && patchVariant != "sql.sslEnabled.omitted"))).IsTrue();
            await Assert.That(fixture.AdminAccepted(fixture.Baseline, fixture.Baseline.Password)).IsTrue();
            await Assert.That(fixture.AdminAccepted(fixture.Selected, fixture.Selected.Password)).IsTrue();
            await Assert.That(fixture.AdminAccepted(fixture.Baseline, "wrong")).IsFalse();
            await Assert.That(fixture.AdminAccepted(fixture.Selected, "wrong")).IsFalse();
            await Assert.That(fixture.TrustAccepted(fixture.Baseline.Host, fixture.Baseline.Ca!)).IsTrue();
            await Assert.That(fixture.TrustAccepted(fixture.Selected.Host, fixture.Selected.Ca!)).IsTrue();
            await Assert.That(fixture.TrustAccepted(fixture.Baseline.Host, "invalid-trust")).IsFalse();
            await Assert.That(fixture.TrustAccepted(fixture.Selected.Host, "invalid-trust")).IsFalse();
        }
        finally
        {
            var inventory = await client.ListLeasesAsync(created.Value, token);
            await Assert.That(inventory.IsSuccess && inventory.Value.IsComplete).IsTrue();
            await Assert.That(inventory.Value.Items.Select(l => l.Reference.Id).Order().ToArray())
                .IsEquivalentTo(retained.Select(c => c.Coordinate.LeaseId).Order().ToArray());
            foreach (var lease in inventory.Value.Items)
            {
                var removed = await client.RevokeLeaseAsync(lease.Reference,
                    new(lease.Reference, InfisicalDynamicOperation.Revoke), cancellationToken: token);
                await Assert.That(removed.IsSuccess).IsTrue();
            }
            foreach (var captured in retained)
            {
                var absent = await fixture.MeasureAsync(captured.Coordinate, captured.User, captured.Password, token);
                await Assert.That(absent.Authentication).IsEqualTo(BackendAuthentication.Rejected);
                await Assert.That(await fixture.QueryAsync(captured.Coordinate, captured.User, captured.Password,
                    "select", token)).IsEqualTo(SecretStatus.Denied);
                captured.User.Dispose();
                captured.Password.Dispose();
            }
            var removedDefinition = await client.DeleteDefinitionAsync(created.Value,
                new(target, InfisicalDynamicOperation.DeleteDefinition), cancellationToken: token);
            await Assert.That(removedDefinition.IsSuccess).IsTrue();
            var removedFolder = await native.DeleteFolderAsync(folderTarget,
                new InfisicalNativeAuthority(native.Authority, environment.Tokens(NativeIdentityRole.Setup),
                    InfisicalSqlInputEffectFixture.ProjectId),
                new(folderTarget), cancellationToken: token);
            await Assert.That(removedFolder.IsSuccess).IsTrue();
            await Assert.That(fixture.ResidualCount).IsEqualTo(0);
            await Assert.That(fixture.BorrowedRootIntact).IsTrue();
            if (sourceObserver is not null)
            {
                await sourceObserver.CloseAsync(root, token);
                await Assert.That(fixture.Source.Observations).IsEqualTo(2);
                await Assert.That(fixture.Source.Closes).IsEqualTo(1);
            }
        }

        async Task CaptureAsync(InfisicalDynamicDefinition definition, DynamicSqlInput profile)
        {
            var acquired = await client.AcquireDatabaseAsync(definition,
                new(target, InfisicalDynamicOperation.Acquire), cancellationToken: token);
            await Assert.That(acquired.IsSuccess).IsTrue();
            using var lease = acquired.Value;
            using var credentials = lease.CopyCredentials().Value;
            var coordinate = new DynamicBackendCoordinate(fixture.Engine, profile.Host, profile.Port,
                profile.Database, definition.Id, lease.Reference.Id);
            var user = SecretMaterial.FromText(credentials.RevealUsername());
            var password = SecretMaterial.FromText(credentials.RevealPassword());
            retained.Add((coordinate, user, password));
            await Assert.That(await fixture.QueryAsync(coordinate, user, password, "select", token))
                .IsEqualTo(SecretStatus.Success);
            await Assert.That(await fixture.QueryAsync(coordinate, user, password, "write", token))
                .IsEqualTo(SecretStatus.Denied);
            var measured = await fixture.MeasureAsync(coordinate, user, password, token);
            await Assert.That(measured.Authentication).IsEqualTo(BackendAuthentication.Accepted);
            await Assert.That(measured.AllowedActions).IsEquivalentTo(new[] { "select" });
            await Assert.That(measured.DeniedActions).IsEquivalentTo(new[] { "write" });
            await Assert.That(measured.ExpiresAt).IsEqualTo(lease.Observation.ExpiresAt);
            using var wrong = SecretMaterial.FromText("wrong-issued-password");
            await Assert.That(await fixture.QueryAsync(coordinate, user, wrong, "select", token))
                .IsEqualTo(SecretStatus.Denied);
            var rejected = await fixture.MeasureAsync(coordinate, user, wrong, token);
            await Assert.That(rejected.Authentication).IsEqualTo(BackendAuthentication.Rejected);
            var acceptedAgain = await fixture.MeasureAsync(coordinate, user, password, token);
            await Assert.That(acceptedAgain.Authentication).IsEqualTo(BackendAuthentication.Accepted);
        }
    }

    private sealed class SnapshotHandler(InfisicalSqlInputEffectFixture fixture) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = JsonContent.Create(fixture.Snapshot(Guid.Parse(request.RequestUri!.Segments.Last())))
            });
        }
    }
}
