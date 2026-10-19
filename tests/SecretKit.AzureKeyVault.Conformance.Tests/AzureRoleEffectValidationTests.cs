using System.Net;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureRoleEffectValidationTests
{
    [Test]
    [Arguments("window")]
    [Arguments("selector")]
    [Arguments("sequence")]
    [Arguments("phase")]
    [Arguments("parent")]
    [Arguments("definition")]
    [Arguments("secret-version")]
    [Arguments("start")]
    [Arguments("finish")]
    [Arguments("request-id")]
    [Arguments("digest")]
    [Arguments("incomplete")]
    [Arguments("incomplete-metadata")]
    public async Task RoleMeasurementRequiresExactWindowCoordinatesAndNativeReads(string fault)
    {
        var measured = Measurement([], []);
        var facts = new LeaseFacts(measured.Nonce, measured.LeaseId, "observer", "https://management.azure.com",
            "2022-04-01", measured.StartedAt, [Vault().ExportResourceId()]);
        var lease = new RoleAdministrationEffects.Lease(facts, Vault().VaultName, AssignmentId, "canary",
            new string('1', 32), new string('0', 64), SecretStatus.Success);
        var armed = new ObservationSubscription(facts.LeaseId, facts.Nonce, measured.SubscriptionId, measured.StartedAt);
        FixtureSelector selector = measured.Selector;
        RoleAdministrationEffects.ValidateMeasurement(measured, lease, armed, selector, Vault(), Scope(), DefinitionId,
            RoleAdministrationCollector.Phase.After);
        measured = fault switch
        {
            "window" => measured with { SubscriptionId = Guid.NewGuid() },
            "selector" => measured with { Selector = selector with { Case = "foreign" } },
            "sequence" => measured with { Sequence = 0 },
            "phase" => measured with { Phase = RoleAdministrationCollector.Phase.Baseline },
            "parent" => measured with { Coordinates = measured.Coordinates with { TargetParentResourceId = "/foreign" } },
            "definition" => measured with { Coordinates = measured.Coordinates with { DefinitionId = OtherId } },
            "secret-version" => measured with { Coordinates = measured.Coordinates with { SecretVersion = new string('2', 32) } },
            "start" => measured with { StartedAt = measured.StartedAt.AddTicks(-1) },
            "finish" => measured with { ObservedAt = measured.StartedAt.AddTicks(-1) },
            "request-id" => measured with { Denied = measured.Denied with { NativeRequestId = "" } },
            "digest" => measured with { Observer = measured.Observer with { Sha256 = "not-a-digest" } },
            "incomplete-metadata" => measured with { DefinitionsComplete = false },
            _ => measured with { Intended = measured.Intended with { Complete = false } }
        };
        await Assert.That(() => RoleAdministrationEffects.ValidateMeasurement(measured, lease, armed, selector, Vault(),
            Scope(), DefinitionId, RoleAdministrationCollector.Phase.After)).Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("intended-digest")]
    [Arguments("denied-success")]
    [Arguments("denied-material")]
    [Arguments("observer-denied")]
    [Arguments("observer-digest")]
    public async Task AllThreeIndependentReadsMustMatchExpectedAuthorityAndActualDigest(string fault)
    {
        var measured = Measurement([], []);
        RoleAdministrationEffects.ValidateReads(measured, SecretStatus.Success, new string('0', 64));
        measured = fault switch
        {
            "intended-digest" => measured with { Intended = measured.Intended with { Sha256 = new string('2', 64) } },
            "denied-success" => measured with { Denied = measured.Denied with { Status = SecretStatus.Success, Sha256 = new string('0', 64) } },
            "denied-material" => measured with { Denied = measured.Denied with { Sha256 = new string('0', 64) } },
            "observer-denied" => measured with { Observer = measured.Observer with { Status = SecretStatus.Denied, Sha256 = null } },
            _ => measured with { Observer = measured.Observer with { Sha256 = new string('2', 64) } }
        };
        await Assert.That(() => RoleAdministrationEffects.ValidateReads(measured, SecretStatus.Success, new string('0', 64)))
            .Throws<NativeCaseFailureException>();
    }

    private static readonly Guid Subscription = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid AssignmentId = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly Guid DefinitionId = Guid.Parse("44444444-4444-4444-4444-444444444444");
    private static readonly Guid PrincipalId = Guid.Parse("55555555-5555-5555-5555-555555555555");
    private static readonly Guid OtherId = Guid.Parse("66666666-6666-6666-6666-666666666666");
    private static VaultScope Vault() => new(new(new(Subscription), "owned-group"), "owned-vault");
    private static RoleAssignmentScope Scope() => new(Vault(), AssignmentId);
    private static RoleDefinitionScope Role() => new(new(Subscription), DefinitionId);

    [Test]
    [Arguments(true, false)]
    [Arguments(false, false)]
    [Arguments(true, true)]
    [Arguments(false, true)]
    public async Task MutationRequiresContrastingIndependentBaseline(bool create, bool transition)
    {
        string? state = create == transition ? null : AssignmentJson(AssignmentId);
        using var backend = new Backend((request, _) =>
        {
            if (request.Method == HttpMethod.Put)
            {
                state = AssignmentJson(AssignmentId);
                return Task.FromResult(Json(201, state));
            }
            if (request.Method == HttpMethod.Delete)
            {
                state = null;
                return Task.FromResult(Json(204, ""));
            }
            return Task.FromResult(state is null ? Json(404, Error("RoleAssignmentNotFound")) : Json(200, state));
        });
        using var http = new HttpClient(backend);
        var transport = new HttpClientTransport(http);
        var observer = new VaultAdministration(new Credential("observer"), transport);
        RoleAdministrationEffects.Assignment[] baseline = await MeasureAsync(observer);
        if (transition)
            RoleAdministrationEffects.ValidateBaseline(create ? "CreateRoleAssignmentAsync" : "DeleteRoleAssignmentAsync",
                Scope(), PrincipalId, DefinitionId, baseline);
        else
            await Assert.That(() => RoleAdministrationEffects.ValidateBaseline(
                create ? "CreateRoleAssignmentAsync" : "DeleteRoleAssignmentAsync", Scope(), PrincipalId, DefinitionId, baseline))
                .Throws<NativeCaseFailureException>();
        var client = new VaultAdministration(new Credential("administrative"), transport);
        RoleAssignmentScope scope = Scope();
        string operation = create ? "CreateRoleAssignmentAsync" : "DeleteRoleAssignmentAsync";
        var receipt = client.PrepareReceipt(scope, create ?
            ManagementMutation.CreateRoleAssignment : ManagementMutation.DeleteRoleAssignment);
        if (create)
        {
            var outcome = await client.CreateRoleAssignmentAsync(scope, Role(), PrincipalId, receipt);
            await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Success);
            RoleAdministrationEffects.MatchAssignment(outcome.Value, await MeasureAsync(observer));
        }
        else
            await Assert.That((await client.DeleteRoleAssignmentAsync(scope, receipt)).Status).IsEqualTo(SecretStatus.Success);
        ManagementAdmission.Receipt(receipt, "independent-effect");
        var measured = await MeasureAsync(observer);
        if (transition)
            RoleAdministrationEffects.ValidateMutation(operation, false, Scope(), PrincipalId, DefinitionId, baseline, measured);
        else
            await Assert.That(() => RoleAdministrationEffects.ValidateMutation(operation, false, Scope(), PrincipalId,
                DefinitionId, baseline, measured)).Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments(true, false)]
    [Arguments(false, false)]
    [Arguments(true, true)]
    [Arguments(false, true)]
    public async Task DeniedMutationMustPreserveAssignmentMetadata(bool create, bool preserve)
    {
        string? state = create ? null : AssignmentJson(AssignmentId);
        using var backend = new Backend((request, _) =>
        {
            if (request.Method != HttpMethod.Get)
            {
                if (!preserve)
                    state = AssignmentJson(AssignmentId, description: "changed");
                return Task.FromResult(Json(403, Error("Forbidden")));
            }
            return Task.FromResult(state is null ? Json(404, Error("RoleAssignmentNotFound")) : Json(200, state));
        });
        using var http = new HttpClient(backend);
        var transport = new HttpClientTransport(http);
        var observer = new VaultAdministration(new Credential("observer"), transport);
        var baseline = await MeasureAsync(observer);
        RoleAdministrationEffects.ValidateBaseline(create ? "CreateRoleAssignmentAsync" : "DeleteRoleAssignmentAsync",
            Scope(), PrincipalId, DefinitionId, baseline);
        var client = new VaultAdministration(new Credential("denied"), transport);
        RoleAssignmentScope scope = Scope();
        string operation = create ? "CreateRoleAssignmentAsync" : "DeleteRoleAssignmentAsync";
        var receipt = client.PrepareReceipt(scope, create ?
            ManagementMutation.CreateRoleAssignment : ManagementMutation.DeleteRoleAssignment);
        SecretStatus status = create
            ? (await client.CreateRoleAssignmentAsync(scope, Role(), PrincipalId, receipt)).Status
            : (await client.DeleteRoleAssignmentAsync(scope, receipt)).Status;
        await Assert.That(status).IsEqualTo(SecretStatus.Denied);
        ManagementAdmission.Receipt(receipt, "denied-authority");
        var measured = await MeasureAsync(observer);
        if (preserve)
            RoleAdministrationEffects.ValidateMutation(operation, true, Scope(), PrincipalId, DefinitionId, baseline, measured);
        else
            await Assert.That(() => RoleAdministrationEffects.ValidateMutation(operation, true, Scope(), PrincipalId,
                DefinitionId, baseline, measured)).Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments(false, false, false)]
    [Arguments(true, false, false)]
    [Arguments(false, true, false)]
    [Arguments(true, true, false)]
    [Arguments(false, false, true)]
    [Arguments(true, false, true)]
    [Arguments(false, true, true)]
    [Arguments(true, true, true)]
    public async Task InventoryCannotSubstituteDuplicateIdentities(bool definitions, bool bounded, bool faithful)
    {
        string Row(Guid id) => definitions ? DefinitionJson(id) : AssignmentJson(id);
        using var backend = new Backend((request, _) =>
        {
            bool observer = request.Headers.Authorization?.Parameter == "observer";
            string rows = observer || faithful ? Row(AssignmentId) + "," + Row(OtherId) :
                Row(AssignmentId) + "," + Row(AssignmentId);
            if (bounded) rows += "," + Row(PrincipalId);
            return Task.FromResult(Json(200, """{"value":[""" + rows + "]}"));
        });
        using var http = new HttpClient(backend);
        var transport = new HttpClientTransport(http);
        var client = new VaultAdministration(new Credential("administrative"), transport);
        var observer = new VaultAdministration(new Credential("observer"), transport);
        var limits = new CollectionLimits(1, bounded ? 2 : 10, TimeSpan.FromSeconds(5));
        RoleAdministrationEffects.Result result;
        RoleAdministrationEffects.Measurement measured;
        if (definitions)
        {
            var observed = await observer.ListRoleDefinitionsAsync(new(Subscription), new(1, 10, TimeSpan.FromSeconds(5)));
            await Assert.That(observed.Status).IsEqualTo(SecretStatus.Success);
            var actual = await client.ListRoleDefinitionsAsync(new(Subscription), limits);
            result = new(actual.Status, Definitions: actual);
            measured = Measurement([], observed.Items.Select(Definition).ToArray());
        }
        else
        {
            var observed = await observer.ListRoleAssignmentsAsync(Vault(), new(1, 10, TimeSpan.FromSeconds(5)));
            await Assert.That(observed.Status).IsEqualTo(SecretStatus.Success);
            var actual = await client.ListRoleAssignmentsAsync(Vault(), limits);
            result = new(actual.Status, Assignments: actual);
            measured = Measurement(observed.Items.Select(Assignment).ToArray(), []);
        }
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        if (faithful)
            RoleAdministrationEffects.ValidateInventory(result, measured, limits.MaximumItems);
        else
            await Assert.That(() => RoleAdministrationEffects.ValidateInventory(result, measured, limits.MaximumItems))
                .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task IndependentInventoryAlsoRejectsDuplicateIdentities(bool definitions)
    {
        string row = definitions ? DefinitionJson(AssignmentId) : AssignmentJson(AssignmentId);
        using var backend = new Backend((request, _) => Task.FromResult(Json(200,
            """{"value":[""" + row + (request.Headers.Authorization?.Parameter == "observer" ? "," + row : "") + "]}")));
        using var http = new HttpClient(backend);
        var transport = new HttpClientTransport(http);
        var selected = new VaultAdministration(new Credential("administrative"), transport);
        var observer = new VaultAdministration(new Credential("observer"), transport);
        var limits = new CollectionLimits(1, 10, TimeSpan.FromSeconds(5));
        RoleAdministrationEffects.Result result;
        RoleAdministrationEffects.Measurement measured;
        if (definitions)
        {
            var actual = await selected.ListRoleDefinitionsAsync(new(Subscription), limits);
            var independent = await observer.ListRoleDefinitionsAsync(new(Subscription), limits);
            await Assert.That(independent.Status).IsEqualTo(SecretStatus.Success);
            result = new(actual.Status, Definitions: actual);
            measured = Measurement([], independent.Items.Select(Definition).ToArray());
        }
        else
        {
            var actual = await selected.ListRoleAssignmentsAsync(Vault(), limits);
            var independent = await observer.ListRoleAssignmentsAsync(Vault(), limits);
            await Assert.That(independent.Status).IsEqualTo(SecretStatus.Success);
            result = new(actual.Status, Assignments: actual);
            measured = Measurement(independent.Items.Select(Assignment).ToArray(), []);
        }
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(() => RoleAdministrationEffects.ValidateInventory(result, measured, 10))
            .Throws<NativeCaseFailureException>();
    }

    [Test]
    public async Task MissingBaselineFieldsNeverProveAbsence()
    {
        var measured = Measurement([], []);
        RoleAdministrationEffects.ValidateTargetMeasurement(measured, Scope());
        foreach (string property in new[] { "targetPresent", "assignmentsComplete", "assignments" })
        {
            var json = System.Text.Json.Nodes.JsonNode.Parse(JsonSerializer.Serialize(measured, ManagementAdmission.Json))!;
            json.AsObject().Remove(property);
            using var backend = new Backend((_, _) => Task.FromResult(Json(200, json.ToJsonString())));
            using var observer = new OwnedManagementObserver(new(new("https://observer.invalid/"), "offline",
                TimeSpan.FromSeconds(5)), backend);
            await Assert.That(async () =>
            {
                var incomplete = await observer.PostAsync<ObserveLease, RoleAdministrationEffects.Measurement>("role/observe",
                    new(measured.LeaseId, measured.Nonce, "assignment-baseline-before-dispatch"), CancellationToken.None);
                RoleAdministrationEffects.ValidateTargetMeasurement(incomplete, Scope());
            })
                .Throws<NativeCaseFailureException>();
        }
        await Assert.That(() => RoleAdministrationEffects.ValidateBaseline("CreateRoleAssignmentAsync",
            Scope(), PrincipalId, DefinitionId, null)).Throws<NativeCaseFailureException>();
        await Assert.That(() => RoleAdministrationEffects.ValidateTargetMeasurement(measured with { TargetPresent = true },
            Scope())).Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("principal")]
    [Arguments("definition")]
    [Arguments("principal-type")]
    [Arguments("description")]
    [Arguments("condition")]
    [Arguments("condition-version")]
    [Arguments("collateral")]
    public async Task DenialPreservesEveryIndependentlyMeasuredAssignmentField(string change)
    {
        bool mutated = false;
        string Rows()
        {
            string selected = AssignmentJson(AssignmentId);
            string collateral = AssignmentJson(OtherId);
            if (mutated)
            {
                var node = System.Text.Json.Nodes.JsonNode.Parse(change == "collateral" ? collateral : selected)!;
                var properties = node["properties"]!;
                switch (change)
                {
                    case "principal": properties["principalId"] = OtherId.ToString("D"); break;
                    case "definition":
                        properties["roleDefinitionId"] = $"/subscriptions/{Subscription:D}/providers/Microsoft.Authorization/roleDefinitions/{OtherId:D}";
                        break;
                    case "principal-type": properties["principalType"] = "User"; break;
                    case "condition": properties["condition"] = "changed"; break;
                    case "condition-version": properties["conditionVersion"] = "2.0"; break;
                    default: properties["description"] = "changed"; break;
                }
                if (change == "collateral") collateral = node.ToJsonString();
                else selected = node.ToJsonString();
            }
            return """{"value":[""" + selected + "," + collateral + "]}";
        }
        using var backend = new Backend((request, _) =>
        {
            if (request.Method == HttpMethod.Delete)
            {
                mutated = true;
                return Task.FromResult(Json(403, Error("Forbidden")));
            }
            return Task.FromResult(Json(200, Rows()));
        });
        using var http = new HttpClient(backend);
        var transport = new HttpClientTransport(http);
        var observer = new VaultAdministration(new Credential("observer"), transport);
        var limits = new CollectionLimits(1, 10, TimeSpan.FromSeconds(5));
        var before = await observer.ListRoleAssignmentsAsync(Vault(), limits);
        await Assert.That(before.Status).IsEqualTo(SecretStatus.Success);
        var baseline = before.Items.Select(Assignment).ToArray();
        RoleAdministrationEffects.ValidateBaseline("DeleteRoleAssignmentAsync", Scope(), PrincipalId, DefinitionId, baseline);
        var selected = new VaultAdministration(new Credential("denied"), transport);
        var scope = Scope();
        var receipt = selected.PrepareReceipt(scope, ManagementMutation.DeleteRoleAssignment);
        await Assert.That((await selected.DeleteRoleAssignmentAsync(scope, receipt)).Status).IsEqualTo(SecretStatus.Denied);
        var after = await observer.ListRoleAssignmentsAsync(Vault(), limits);
        await Assert.That(after.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(() => RoleAdministrationEffects.ValidateMutation("DeleteRoleAssignmentAsync", true, scope,
            PrincipalId, DefinitionId, baseline, after.Items.Select(Assignment).ToArray())).Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments(true, "lost-response-no-replay")]
    [Arguments(false, "lost-response-no-replay")]
    [Arguments(true, "cancellation-boundary")]
    [Arguments(false, "cancellation-boundary")]
    public async Task UncertainMutationStillRequiresIndependentTransition(bool create, string @case)
    {
        string? state = create ? null : AssignmentJson(AssignmentId);
        using var backend = new Backend((request, _) =>
        {
            if (request.Method == HttpMethod.Put)
            {
                state = AssignmentJson(AssignmentId);
                return Task.FromResult(Json(201, state));
            }
            if (request.Method == HttpMethod.Delete)
            {
                state = null;
                return Task.FromResult(Json(204, ""));
            }
            return Task.FromResult(state is null ? Json(404, Error("RoleAssignmentNotFound")) : Json(200, state));
        });
        using var http = new HttpClient(backend);
        var transport = new HttpClientTransport(http);
        var observer = new VaultAdministration(new Credential("observer"), transport);
        var baseline = await MeasureAsync(observer);
        string operation = create ? "CreateRoleAssignmentAsync" : "DeleteRoleAssignmentAsync";
        RoleAdministrationEffects.ValidateBaseline(operation, Scope(), PrincipalId, DefinitionId, baseline);
        using var cancellation = new CancellationTokenSource();
        var boundary = new ManagementBoundaryTransport(transport, @case, cancellation);
        Task subscribed = boundary.ResponseReceived;
        var client = new VaultAdministration(new Credential("administrative"), boundary);
        var scope = Scope();
        var receipt = client.PrepareReceipt(scope, create ?
            ManagementMutation.CreateRoleAssignment : ManagementMutation.DeleteRoleAssignment);
        SecretStatus? status = null;
        bool canceled = false;
        try
        {
            status = create
                ? (await client.CreateRoleAssignmentAsync(scope, Role(), PrincipalId, receipt, cancellation.Token)).Status
                : (await client.DeleteRoleAssignmentAsync(scope, receipt, cancellation.Token)).Status;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { canceled = true; }
        await subscribed.WaitAsync(TimeSpan.FromSeconds(5));
        if (@case == "lost-response-no-replay")
            await Assert.That(status).IsEqualTo(SecretStatus.Unknown);
        else
            await Assert.That(canceled).IsTrue();
        ManagementAdmission.Receipt(receipt, @case);
        RoleAdministrationEffects.ValidateMutation(operation, false, scope, PrincipalId, DefinitionId,
            baseline, await MeasureAsync(observer));
    }

    [Test]
    public async Task DefinitionPermissionsMustMatchWithMultiplicity()
    {
        using var backend = new Backend((_, _) => Task.FromResult(Json(200,
            DefinitionJson(DefinitionId, """{"actions":["read"],"notActions":[],"dataActions":[],"notDataActions":[]},{"actions":["read"],"notActions":[],"dataActions":[],"notDataActions":[]}"""))));
        using var http = new HttpClient(backend);
        var outcome = await new VaultAdministration(new Credential(), new HttpClientTransport(http)).GetRoleDefinitionAsync(Role());
        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Success);
        var correct = Definition(outcome.Value);
        RoleAdministrationEffects.ValidateInventory(new(SecretStatus.Success,
            Definitions: new([outcome.Value], true, SecretStatus.Success)), Measurement([], [correct]), 10);
        var changed = correct with { Permissions = [correct.Permissions[0], new(["write"], [], [], [])] };
        await Assert.That(() => RoleAdministrationEffects.ValidateInventory(new(SecretStatus.Success,
            Definitions: new([outcome.Value], true, SecretStatus.Success)), Measurement([], [changed]), 10))
            .Throws<NativeCaseFailureException>();
    }

    private static async Task<RoleAdministrationEffects.Assignment[]> MeasureAsync(VaultAdministration observer)
    {
        var result = await observer.GetRoleAssignmentAsync(Scope());
        if (result.Status == SecretStatus.Absent) return [];
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        return [Assignment(result.Value)];
    }

    private static RoleAdministrationEffects.Assignment Assignment(RoleAssignmentObservation value) =>
        new(value.Scope.AssignmentId, RoleAdministrationEffects.ParentId(value.Scope.Parent), value.Definition.DefinitionId,
            value.PrincipalId, value.PrincipalType, value.Description, value.Condition, value.ConditionVersion);
    private static RoleAdministrationEffects.Definition Definition(RoleDefinitionObservation value) =>
        new(value.Scope.DefinitionId, value.Name, value.Description, value.RoleType, value.AssignableScopes.ToArray(),
            value.Permissions.Select(p => new RoleAdministrationEffects.Permission(p.Actions.ToArray(), p.NotActions.ToArray(),
                p.DataActions.ToArray(), p.NotDataActions.ToArray())).ToArray());
    private static RoleAdministrationEffects.Measurement Measurement(RoleAdministrationEffects.Assignment[] assignments,
        RoleAdministrationEffects.Definition[] definitions)
    {
        Guid nonce = Guid.NewGuid();
        var observedAt = new DateTimeOffset(2026, 10, 14, 0, 0, 0, TimeSpan.Zero);
        return new(Guid.NewGuid(), nonce, new(nonce, "scope", "operation", "variant", "case"),
            "observer", observedAt, observedAt,
            Guid.NewGuid(), 1, RoleAdministrationCollector.Phase.After,
            new(Vault().ExportResourceId(), Vault().ExportResourceId(), AssignmentId, DefinitionId, "canary", new string('1', 32)),
            assignments, definitions, new(SecretStatus.Success, new string('0', 64), "intended-native", true),
            new(SecretStatus.Denied, null, "denied-native", true),
            new(SecretStatus.Success, new string('0', 64), "observer-native", true),
            assignments.Any(a => a.Id == AssignmentId), true, true);
    }
    private static string AssignmentJson(Guid id, string description = "baseline") =>
        $$$"""{"id":"{{{Vault().ExportResourceId()}}}/providers/Microsoft.Authorization/roleAssignments/{{{id:D}}}","name":"{{{id:D}}}","type":"Microsoft.Authorization/roleAssignments","properties":{"scope":"{{{Vault().ExportResourceId()}}}","roleDefinitionId":"/subscriptions/{{{Subscription:D}}}/providers/Microsoft.Authorization/roleDefinitions/{{{DefinitionId:D}}}","principalId":"{{{PrincipalId:D}}}","principalType":"ServicePrincipal","description":"{{{description}}}"}}""";
    private static string DefinitionJson(Guid id, string permissions = """{"actions":["read"],"notActions":[],"dataActions":[],"notDataActions":[]}""") =>
        $$$"""{"id":"/subscriptions/{{{Subscription:D}}}/providers/Microsoft.Authorization/roleDefinitions/{{{id:D}}}","name":"{{{id:D}}}","type":"Microsoft.Authorization/roleDefinitions","properties":{"roleName":"owned-role","description":"baseline","type":"CustomRole","assignableScopes":["/subscriptions/{{{Subscription:D}}}"],"permissions":[{{{permissions}}}]}}""";
    private static string Error(string code) => $$$"""{"error":{"code":"{{{code}}}","message":"withheld"}}""";
    private static HttpResponseMessage Json(int status, string body) =>
        new((HttpStatusCode)status) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };
    private sealed class Backend(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            send(request, cancellationToken);
    }
    private sealed class Credential(string token = "observer") : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken) =>
            new(token, DateTimeOffset.MaxValue);
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(context, cancellationToken));
    }
}
