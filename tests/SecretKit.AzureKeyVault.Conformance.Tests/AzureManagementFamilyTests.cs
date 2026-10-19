using System.Net;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureManagementFamilyTests
{
    [Test]
    [Arguments("vault")]
    [Arguments("notification")]
    [Arguments("attribute")]
    public async Task MissingBaselineMetadataCannotBecomeDefaultObservedValues(string kind)
    {
        await Assert.That(() =>
        {
            _ = kind switch
            {
                "vault" => (object?)JsonSerializer.Deserialize<VaultAdministrationEffects.Configuration>(
                    """{"location":"westus","tenantId":"11111111-1111-1111-1111-111111111111","sku":"Standard","purgeProtection":false,"retentionDays":7,"publicNetworkAccess":true,"policies":[]}""",
                    ManagementAdmission.Json),
                "notification" => JsonSerializer.Deserialize<NotificationAdministrationEffects.Configuration>(
                    """{"endpointUrl":"https://owned.invalid","events":[]}""", ManagementAdmission.Json),
                _ => JsonSerializer.Deserialize<NotificationAdministrationEffects.Attribute>(
                    """{"name":"owned","kind":"Static","value":"owned"}""", ManagementAdmission.Json)
            };
        }).Throws<JsonException>();
    }

    private const string Subscription = "11111111-1111-1111-1111-111111111111";
    private const string Tenant = "22222222-2222-2222-2222-222222222222";
    private static VaultScope Vault() => new(new(new(Guid.Parse(Subscription)), "owned-group"), "owned-vault");
    private static string VaultJson(bool rbac) =>
        $$$"""{"id":"{{{Vault().ExportResourceId()}}}","name":"owned-vault","type":"Microsoft.KeyVault/vaults","location":"eastus","properties":{"tenantId":"{{{Tenant}}}","sku":{"family":"A","name":"standard"},"accessPolicies":[],"enableRbacAuthorization":{{{(rbac ? "true" : "false")}}},"enablePurgeProtection":false,"softDeleteRetentionInDays":7,"provisioningState":"Succeeded"}}""";

    [Test]
    public async Task ExactInventoryRegistersAllManagementCasesButMissingInputsNeverPass()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        using JsonDocument inventory = JsonDocument.Parse(await File.ReadAllBytesAsync(
            Path.Combine(root, "docs/internal/releases/admission/azure-key-vault.json")));
        var definitions = new List<NativeCaseDefinition>();
        foreach (JsonElement operation in inventory.RootElement.GetProperty("operations").EnumerateArray())
        {
            string id = operation.GetProperty("id").GetString()!;
            if (!id.StartsWith("a.management.", StringComparison.Ordinal)) continue;
            foreach (JsonElement variant in operation.GetProperty("variants").EnumerateArray())
                foreach (JsonElement @case in operation.GetProperty("requiredCases").EnumerateArray())
                    definitions.Add(new(new("AzureKeyVault", id, variant.GetString()!, "offline-scope", @case.GetString()!),
                        operation.GetProperty("member").GetString()!));
        }
        using JsonDocument settings = JsonDocument.Parse("""
            {"vaultUri":"https://owned-vault.vault.azure.net",
             "setup":{"token":"setup-offline","expiresAt":"2099-01-01T00:00:00Z"},
             "runtime":{"token":"runtime-offline","expiresAt":"2099-01-01T00:00:00Z"},
             "denied":{"token":"denied-offline","expiresAt":"2099-01-01T00:00:00Z"},
             "administrative":{"token":"administrative-offline","expiresAt":"2099-01-01T00:00:00Z"},
             "observer":{"token":"observer-offline","expiresAt":"2099-01-01T00:00:00Z"},"families":{}}
            """);
        using OwnedAzureEnvironment env = OwnedAzureEnvironment.Create(settings.RootElement);
        var registry = new NativeCaseRegistry();
        AzureManagementFamilies.Register(registry, env, definitions);
        await Assert.That(definitions.Select(d => d.Key.Operation).Distinct().Count()).IsEqualTo(33);
        await Assert.That(definitions.Count).IsEqualTo(737);
        await Assert.That(definitions.All(d => registry.Find(d.Key) is not null)).IsTrue();
        IReadOnlyList<NativeCaseResult> results = await NativeCaseRunner.RunAsync(registry, definitions, CancellationToken.None);
        await Assert.That(results.All(r => !r.Passed && !r.EffectObserved && r.ReasonCode == "missing-input")).IsTrue();
    }

    [Test]
    public async Task MismatchedMemberAndUnknownVariantAreRejectedBeforeExecution()
    {
        var expected = new NativeCaseDefinition(new("AzureKeyVault", "a.management.ManagementOperation.CheckStatusAsync",
            "status.Succeeded", "offline", "selected-contract"), "wrong-member");
        await Assert.That(() => ManagementAdmission.Register(new(), null!, [expected], ManagementOperationEffects.Members,
            (_, _, _) => throw new InvalidOperationException())).Throws<InvalidOperationException>();
        expected = expected with
        {
            Member = ManagementOperationEffects.Members[0].Member,
            Key = expected.Key with { Variant = "status.fabricated" }
        };
        await Assert.That(() => ManagementAdmission.Register(new(), null!, [expected], ManagementOperationEffects.Members,
            (_, _, _) => throw new InvalidOperationException())).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("lost-response-no-replay")]
    [Arguments("cancellation-boundary")]
    public async Task ResponseBoundaryRetainsUncertaintyAndIndependentSdkState(string @case)
    {
        bool rbac = false;
        using var backend = new Backend(async (request, token) =>
        {
            if (request.Method == HttpMethod.Patch)
            {
                if (rbac) throw new InvalidOperationException("offline-mutation-replayed");
                using var payload = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(token));
                rbac = payload.RootElement.GetProperty("properties").GetProperty("enableRbacAuthorization").GetBoolean();
            }
            return Json(200, VaultJson(rbac));
        });
        using var http = new HttpClient(backend);
        var transport = new HttpClientTransport(http);
        using var cancellation = new CancellationTokenSource();
        var boundary = new ManagementBoundaryTransport(transport, @case, cancellation);
        Task subscribed = boundary.ResponseReceived;
        var client = new VaultAdministration(new OfflineCredential(), boundary);
        VaultScope scope = Vault();
        ManagementReceipt receipt = client.PrepareReceipt(scope, ManagementMutation.UpdateVault);
        SecretOutcome<VaultObservation>? outcome = null;
        bool canceled = false;
        try { outcome = await client.UpdateSettingsAsync(scope, new(enableRbacAuthorization: true), receipt, cancellation.Token); }
        catch (OperationCanceledException) { canceled = true; }
        await subscribed.WaitAsync(TimeSpan.FromSeconds(5));
        if (@case == "lost-response-no-replay")
            await Assert.That(outcome!.Status).IsEqualTo(SecretStatus.Unknown);
        else
            await Assert.That(canceled).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        var observer = new VaultAdministration(new OfflineCredential(), transport);
        SecretOutcome<VaultObservation> measured = await observer.GetVaultAsync(Vault());
        await Assert.That(measured.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(measured.Value.EnableRbacAuthorization).IsTrue();
        await Assert.That((await client.UpdateSettingsAsync(scope, new(enableRbacAuthorization: true), receipt)).Status)
            .IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task DeniedMutationCannotChangeIndependentState()
    {
        bool rbac = false;
        using var backend = new Backend((request, _) =>
        {
            if (request.Headers.Authorization?.Parameter == "denied")
                return Task.FromResult(Json(403, """{"error":{"code":"Forbidden","message":"withheld"}}"""));
            return Task.FromResult(Json(200, VaultJson(rbac)));
        });
        using var http = new HttpClient(backend);
        var transport = new HttpClientTransport(http);
        var client = new VaultAdministration(new OfflineCredential("denied"), transport);
        VaultScope scope = Vault();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.UpdateVault);
        var result = await client.UpdateSettingsAsync(scope, new(enableRbacAuthorization: true), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Rejected);
        var observed = await new VaultAdministration(new OfflineCredential(), transport).GetVaultAsync(Vault());
        await Assert.That(observed.Value.EnableRbacAuthorization).IsFalse();
    }

    [Test]
    public async Task VaultAudienceCannotBeSilentlyUsedForArm()
    {
        var token = new AudienceToken("offline", DateTimeOffset.MaxValue, "https://vault.azure.net/.default");
        using var credential = new SelectedAudienceCredential(token);
        await Assert.That(() => credential.GetToken(new TokenRequestContext(["https://management.azure.com/.default"]),
            CancellationToken.None)).Throws<NativeCaseFailureException>();
    }

    [Test]
    public async Task EmptyCollectionsAndSubstitutedPoliciesCannotProveEffects()
    {
        await Assert.That(() => VaultAdministrationEffects.MatchCollection([], ["owned"], 10, true))
            .Throws<NativeCaseFailureException>();
        var selected = new VaultAdministrationEffects.Policy(Guid.Parse(Tenant), Guid.Parse(Subscription),
            [SecretPermission.Get], null);
        var substituted = selected with { Permissions = [SecretPermission.Set] };
        await Assert.That(VaultAdministrationEffects.SamePolicies([selected], [substituted])).IsFalse();
        await Assert.That(() => VaultAdministrationEffects.Patch("purgeProtection.false.rejected"))
            .Throws<ArgumentException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ActualAuditSdkScopeAndPartialRowsRemainExplicit(bool partial)
    {
        DateTimeOffset start = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        string error = partial ? ""","error":{"code":"PartialError","message":"withheld","details":[{"code":"LimitsExceeded","message":"withheld"}]}""" : "";
        string body = $$$"""{"tables":[{"name":"PrimaryResult","columns":[{"name":"TimeGenerated","type":"datetime"},{"name":"OperationName","type":"string"},{"name":"ResultType","type":"string"},{"name":"_ResourceId","type":"string"},{"name":"Category","type":"string"}],"rows":[["2026-01-01T00:00:00Z","SecretGet","Success","{{{Vault().ExportResourceId()}}}","AuditEvent"]]}]{{{error}}}}""";
        using var backend = new Backend((_, _) => Task.FromResult(Json(200, body)));
        using var http = new HttpClient(backend);
        using var credential = new SelectedAudienceCredential(new("offline-monitoring", DateTimeOffset.MaxValue,
            "https://api.loganalytics.io//.default"));
        var result = await new AuditDiagnostics(credential, new HttpClientTransport(http))
            .QueryAsync(new(Vault(), start, start.AddHours(1)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Events.Count).IsEqualTo(1);
        AuditDiagnosticsEffects.ValidateResult(result, partial ? "result.partial-failure" : "result.complete");
        await Assert.That(() => AuditDiagnosticsEffects.ValidateResult(result,
            partial ? "result.complete" : "result.partial-failure")).Throws<NativeCaseFailureException>();
    }

    [Test]
    public async Task RoleSdkMetadataMustMatchIndependentPrincipalAndScope()
    {
        Guid assignmentId = Guid.Parse("33333333-3333-3333-3333-333333333333");
        Guid definitionId = Guid.Parse("44444444-4444-4444-4444-444444444444");
        Guid principalId = Guid.Parse("55555555-5555-5555-5555-555555555555");
        string id = Vault().ExportResourceId();
        string body = $$$"""{"id":"{{{id}}}/providers/Microsoft.Authorization/roleAssignments/{{{assignmentId:D}}}","name":"{{{assignmentId:D}}}","type":"Microsoft.Authorization/roleAssignments","properties":{"scope":"{{{id}}}","roleDefinitionId":"/subscriptions/{{{Subscription}}}/providers/Microsoft.Authorization/roleDefinitions/{{{definitionId:D}}}","principalId":"{{{principalId:D}}}","principalType":"ServicePrincipal"}}""";
        using var backend = new Backend((_, _) => Task.FromResult(Json(200, body)));
        using var http = new HttpClient(backend);
        var client = new VaultAdministration(new OfflineCredential(), new HttpClientTransport(http));
        var result = await client.GetRoleAssignmentAsync(new(Vault(), assignmentId));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var observed = new RoleAdministrationEffects.Assignment(assignmentId, id, definitionId, principalId,
            "ServicePrincipal", null, null, null);
        RoleAdministrationEffects.MatchAssignment(result.Value, [observed]);
        await Assert.That(() => RoleAdministrationEffects.MatchAssignment(result.Value,
            [observed with { PrincipalId = Guid.Parse(Tenant) }])).Throws<NativeCaseFailureException>();
        await Assert.That(() => RoleAdministrationEffects.MatchAssignment(result.Value,
            [observed with { ParentResourceId = "/subscriptions/" + Subscription }])).Throws<NativeCaseFailureException>();
    }

    [Test]
    public async Task WebhookAcknowledgementsCannotReplaceCorrelatedDelivery()
    {
        var facts = new LeaseFacts(Guid.NewGuid(), Guid.NewGuid(), "observer", "https://management.azure.com",
            "2025-02-15", DateTimeOffset.UtcNow, [Vault().ExportResourceId()]);
        var configuration = new NotificationAdministrationEffects.Configuration("https://observer.invalid/hook",
            [VaultNotificationEvent.SecretNewVersionCreated], []);
        var lease = new NotificationAdministrationEffects.Lease(facts, "owned-vault", "owned-notification",
            configuration, NotificationDestinationKind.WebHook, "selected", "wrong", "owned-secret");
        var measured = new NotificationAdministrationEffects.Measurement(facts.LeaseId, facts.Nonce, Guid.NewGuid(),
            "observer", facts.PreparedAt, facts.PreparedAt, [], [], [], ["wrong"], ["native"], [], []);
        await Assert.That(() => NotificationAdministrationEffects.ValidateDeliveries(measured, lease, Vault(),
            configuration, false)).Throws<NativeCaseFailureException>();
        var wrong = new NotificationAdministrationEffects.Delivery("native-event", "wrong", "owned-notification", Vault().ExportResourceId(),
            VaultNotificationEvent.SecretNewVersionCreated, facts.PreparedAt, []);
        await Assert.That(() => NotificationAdministrationEffects.ValidateDeliveries(measured with { Deliveries = [wrong] },
            lease, Vault(), configuration, false)).Throws<NativeCaseFailureException>();
    }

    [Test]
    public async Task CleanupRequiresEveryOwnedResourceIndependentlyAbsent()
    {
        var facts = new LeaseFacts(Guid.NewGuid(), Guid.NewGuid(), "observer", "https://management.azure.com",
            "2026-02-01", DateTimeOffset.UtcNow, [Vault().ExportResourceId()]);
        var measurement = new CleanupMeasurement(facts.LeaseId, facts.Nonce, facts.PreparedAt,
            facts.ObserverIdentity, [], facts.OwnedResourceIds);
        using var backend = new Backend((_, _) => Task.FromResult(Json(200,
            JsonSerializer.Serialize(measurement, ManagementAdmission.Json))));
        using var observer = new OwnedManagementObserver(new(new("https://observer.invalid/"), "offline",
            TimeSpan.FromSeconds(5)), backend);
        var probe = new NativeCaseProbe();
        probe.Contract(true, NativeFailure.ContractMismatch);
        probe.Effect(NativeObservation.Matched);
        await Assert.That(async () => await observer.CleanupAsync(facts, probe)).Throws<NativeCaseFailureException>();
        await Assert.That(probe.Result(new("AzureKeyVault", "operation", "variant", "offline", "independent-effect")).ReasonCode)
            .IsEqualTo("cleanup-incomplete");
    }

    [Test]
    [Arguments(SecretStatus.Denied)]
    [Arguments(SecretStatus.Success)]
    public async Task FailedPermissionReadAssertionStillDisposesReturnedMaterial(SecretStatus expected)
    {
        using var material = SecretMaterial.FromText("owned-offline-material");
        var reference = new SecretReference(new SecretAuthority(), new AzureSecretAddress("owned"));
        var read = new SecretRead(material, new(reference, null, DateTimeOffset.UtcNow, SecretValidity.Valid));
        var outcome = SecretOutcome<SecretRead>.Success(read);
        await Assert.That(() => RoleAdministrationEffects.CheckReadOutcome(outcome, new string('0', 64), expected))
            .Throws<NativeCaseFailureException>();
        await Assert.That(() => material.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments("revision")]
    [Arguments("resources")]
    [Arguments("timestamp")]
    [Arguments("origin")]
    public async Task ClaimedLeaseCanBeReleasedAfterFullContractValidationFails(string mode)
    {
        var selector = new FixtureSelector(Guid.NewGuid(), "offline", "operation", "variant", "selected-contract");
        var facts = new LeaseFacts(selector.Nonce, Guid.NewGuid(), "observer", "https://management.azure.com",
            "2026-02-01", DateTimeOffset.UtcNow, [Vault().ExportResourceId()]);
        facts = mode switch
        {
            "revision" => facts with { ApiRevision = "wrong" },
            "resources" => facts with { OwnedResourceIds = [Vault().ExportResourceId(), Vault().ExportResourceId()] },
            "timestamp" => facts with { PreparedAt = DateTimeOffset.UnixEpoch },
            _ => facts with { Origin = "https://wrong.invalid" }
        };
        bool released = false;
        using var backend = new Backend(async (request, token) =>
        {
            using var body = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(token));
            await Assert.That(body.RootElement.GetProperty("leaseId").GetGuid()).IsEqualTo(facts.LeaseId);
            await Assert.That(body.RootElement.GetProperty("nonce").GetGuid()).IsEqualTo(selector.Nonce);
            released = true;
            return Json(200, JsonSerializer.Serialize(new CleanupMeasurement(facts.LeaseId, facts.Nonce,
                DateTimeOffset.UtcNow, facts.ObserverIdentity, facts.OwnedResourceIds, []), ManagementAdmission.Json));
        });
        using var observer = new OwnedManagementObserver(new(new("https://observer.invalid/"), "offline",
            TimeSpan.FromSeconds(5)), backend);
        facts.Claim(selector);
        await Assert.That(() => facts.Validate(selector, "2026-02-01")).Throws<NativeCaseFailureException>();
        await observer.CleanupAsync(facts, new());
        await Assert.That(released).IsTrue();
        await Assert.That(() => facts.Claim(selector)).Throws<NativeCaseFailureException>();
    }

    [Test]
    public async Task UnboundLeaseCannotAcquireCleanupAuthority()
    {
        var selector = new FixtureSelector(Guid.NewGuid(), "offline", "operation", "variant", "selected-contract");
        var facts = new LeaseFacts(Guid.NewGuid(), Guid.NewGuid(), "observer", "https://management.azure.com",
            "2026-02-01", DateTimeOffset.UtcNow, [Vault().ExportResourceId()]);
        await Assert.That(() => facts.Claim(selector)).Throws<NativeCaseFailureException>();
        await Assert.That(() => (facts with { Nonce = selector.Nonce, LeaseId = Guid.Empty }).Claim(selector))
            .Throws<NativeCaseFailureException>();
    }

    private static HttpResponseMessage Json(int status, string body) =>
        new((HttpStatusCode)status) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };
    private sealed class Backend(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            send(request, cancellationToken);
    }
    private sealed class OfflineCredential(string token = "observer") : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken) =>
            new(token, DateTimeOffset.MaxValue);
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(context, cancellationToken));
    }
}
