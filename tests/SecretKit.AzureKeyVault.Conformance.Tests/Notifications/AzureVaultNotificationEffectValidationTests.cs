using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using MO = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationEffects;
using NA = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.NotificationAdministrationEffects;
using VA = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureVaultNotificationEffectValidationTests
{
    private static readonly Guid Subscription = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Tenant = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Guid Principal = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly Guid Other = Guid.Parse("44444444-4444-4444-4444-444444444444");
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static VaultScope Vault(string name = "owned-vault") => new(new(new(Subscription), "owned-group"), name);
    private static CollectionLimits Limits(int maximum = 10) => new(1, maximum, TimeSpan.FromSeconds(5));
    private static VA.Configuration Configuration(VA.Policy[]? policies = null) =>
        new("eastus", Tenant, VaultSku.Standard, true, false, 30, true, policies ?? []);
    private static NA.Configuration NotificationConfiguration() =>
        new("https://webhook.invalid/selected", [VaultNotificationEvent.SecretNewVersionCreated], []);

    [Test]
    [Arguments(false, false, false)]
    [Arguments(false, false, true)]
    [Arguments(false, true, false)]
    [Arguments(false, true, true)]
    [Arguments(true, false, false)]
    [Arguments(true, false, true)]
    [Arguments(true, true, false)]
    [Arguments(true, true, true)]
    public async Task VaultInventoryRequiresUniqueIndependentIdentities(bool subscription, bool bounded, bool faithful)
    {
        string[] persisted = [VaultJson("owned-vault"), VaultJson("other-vault"), VaultJson("third-vault")];
        using var backend = new Backend((request, _) =>
        {
            string[] rows = IsObserver(request) || faithful ? persisted :
                [persisted[0], persisted[0], persisted[2]];
            return Task.FromResult(Json(200, Inventory(bounded ? rows : rows[..2])));
        });
        using var session = new Session(backend);
        var actual = subscription
            ? await session.Selected.ListVaultsAsync(new SubscriptionScope(Subscription), Limits(bounded ? 2 : 10))
            : await session.Selected.ListVaultsAsync(Vault().ResourceGroup, Limits(bounded ? 2 : 10));
        var independent = subscription
            ? await session.Observer.ListVaultsAsync(new SubscriptionScope(Subscription), Limits())
            : await session.Observer.ListVaultsAsync(Vault().ResourceGroup, Limits());
        await Assert.That(actual.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(independent.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(actual.Complete).IsEqualTo(!bounded);
        var measured = Measurement(Configuration()) with { Vaults = independent.Items.Select(VaultRow).ToArray() };
        await ValidateAsync(() => VA.MatchResult(new(actual.Status, Vaults: actual), measured, Vault(),
            bounded ? 2 : 10), faithful);
    }

    [Test]
    [Arguments("vault", "provisioning")]
    [Arguments("vault", "rbac")]
    [Arguments("vault", "purge")]
    [Arguments("vault", "retention")]
    [Arguments("deleted", "deleted-on")]
    [Arguments("deleted", "purge-on")]
    [Arguments("deleted", "purge")]
    [Arguments("connection", "state")]
    [Arguments("connection", "provisioning")]
    [Arguments("link", "group")]
    [Arguments("link", "members")]
    [Arguments("link", "zones")]
    public async Task InventoryComparesEveryProjectedMetadataField(string kind, string field)
    {
        foreach (bool bounded in new[] { false, true })
        {
            foreach (bool faithful in new[] { false, true })
            {
                string Row(string name) => kind switch
                {
                    "vault" => VaultJson(name),
                    "deleted" => DeletedJson(name),
                    "connection" => ConnectionJson(name),
                    _ => LinkJson(name)
                };
                string[] persisted = [Row("owned-vault"), Row("other-vault")];
                using var backend = new Backend((request, _) =>
                {
                    string[] rows = [.. persisted];
                    if (!IsObserver(request) && !faithful)
                    {
                        var row = JsonNode.Parse(rows[0])!;
                        JsonNode properties = row["properties"]!;
                        switch (field)
                        {
                            case "provisioning": properties["provisioningState"] = "Updating"; break;
                            case "rbac": properties["enableRbacAuthorization"] = false; break;
                            case "purge":
                                properties[kind == "vault" ? "enablePurgeProtection" : "purgeProtectionEnabled"] = true;
                                break;
                            case "retention": properties["softDeleteRetentionInDays"] = 90; break;
                            case "deleted-on": properties["deletionDate"] = Start.AddDays(1).ToString("O"); break;
                            case "purge-on": properties["scheduledPurgeDate"] = Start.AddDays(40).ToString("O"); break;
                            case "state": properties["privateLinkServiceConnectionState"]!["status"] = "Rejected"; break;
                            case "group": properties["groupId"] = "other"; break;
                            case "members": properties["requiredMembers"] = new JsonArray("other"); break;
                            case "zones": properties["requiredZoneNames"] = new JsonArray("other.invalid"); break;
                        }
                        rows[0] = row.ToJsonString();
                    }
                    return Task.FromResult(Json(200, Inventory(rows)));
                });
                using var session = new Session(backend);
                var (result, _) = await InventoryAsync(session.Selected, kind, Limits(bounded ? 1 : 10));
                var (_, measured) = await InventoryAsync(session.Observer, kind, Limits());
                await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
                await ValidateAsync(() => VA.MatchResult(result, measured, Vault(), bounded ? 1 : 10), faithful);
            }
        }
    }

    [Test]
    [Arguments(AccessPolicyChange.Add, "valid")]
    [Arguments(AccessPolicyChange.Add, "collateral")]
    [Arguments(AccessPolicyChange.Replace, "valid")]
    [Arguments(AccessPolicyChange.Replace, "collateral")]
    [Arguments(AccessPolicyChange.Remove, "valid")]
    [Arguments(AccessPolicyChange.Remove, "collateral")]
    [Arguments(AccessPolicyChange.Remove, "empty-retained")]
    public async Task PolicyMutationPreservesUnrelatedIdentityAndRemovesTheSelectedIdentity(
        AccessPolicyChange change, string mode)
    {
        VA.Policy target = new(Tenant, Principal, [SecretPermission.Get], null);
        VA.Policy unrelated = new(Tenant, Other, [SecretPermission.List], null);
        VA.Policy[] initial = change == AccessPolicyChange.Add ? [unrelated] :
            [target with { Permissions = [SecretPermission.Set] }, unrelated];
        string state = VaultJson("owned-vault", Configuration(initial));
        using var backend = new Backend(async (request, token) =>
        {
            if (request.Method == HttpMethod.Put)
            {
                var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(token))!;
                VA.Policy[] selected = ParsePolicies(body["properties"]!["accessPolicies"]!);
                VA.Configuration before = ParseConfiguration(state);
                var retained = before.Policies.Where(p => selected.All(q =>
                    q.PrincipalId != p.PrincipalId || q.ApplicationId != p.ApplicationId || q.TenantId != p.TenantId));
                VA.Policy[] after = [.. retained, .. change == AccessPolicyChange.Remove ? [] : selected];
                if (mode == "collateral") after = after.Where(p => p.PrincipalId != Other).ToArray();
                if (mode == "empty-retained") after = [.. after, target with { Permissions = [] }];
                state = VaultJson("owned-vault", before with { Policies = after });
                return Json(200, JsonSerializer.Serialize(new
                {
                    id = Vault().ExportResourceId(),
                    properties = new { accessPolicies = PolicyObjects(after) }
                }));
            }
            return Json(200, state);
        });
        using var session = new Session(backend);
        var baseline = ParseConfiguration(state);
        var lease = Lease(baseline);
        VA.RequireMutationBaseline("ChangeAccessPoliciesAsync", "", Configuration(), lease, [target], change);
        var scope = Vault();
        var mutation = change switch
        {
            AccessPolicyChange.Add => ManagementMutation.AddAccessPolicy,
            AccessPolicyChange.Replace => ManagementMutation.ReplaceAccessPolicy,
            _ => ManagementMutation.RemoveAccessPolicy
        };
        var receipt = session.Selected.PrepareReceipt(scope, mutation);
        var actual = await session.Selected.ChangeAccessPoliciesAsync(scope, change, [target.Build()], receipt);
        await Assert.That(actual.Status).IsEqualTo(SecretStatus.Success);
        ManagementAdmission.Receipt(receipt, "selected-contract");
        await Assert.That((await session.Observer.GetVaultAsync(Vault())).Status).IsEqualTo(SecretStatus.Success);
        var afterState = ParseConfiguration(state);
        var measured = Measurement(afterState) with
        {
            PolicyEffects = Enum.GetValues<SecretPermission>().Select(permission =>
                new VA.PolicyEffect(Principal, permission,
                    afterState.Policies.Any(p => p.PrincipalId == Principal && p.Permissions.Contains(permission))
                        ? SecretStatus.Success : SecretStatus.Denied,
                    SecretStatus.Denied, "offline-policy-read")).ToArray()
        };
        VA.MatchResult(new(actual.Status, Policies: actual.Value), measured, scope, 10);
        await ValidateAsync(() => VA.ValidateEffect("ChangeAccessPoliciesAsync", "", Configuration(), lease,
            measured, [target], change, false), mode == "valid");
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task PolicyProjectionCannotSubstituteDuplicateIdentity(bool faithful)
    {
        VA.Policy first = new(Tenant, Principal, [SecretPermission.Get], null);
        VA.Policy second = new(Tenant, Other, [SecretPermission.List], null);
        string persisted = VaultJson("owned-vault", Configuration([first, second]));
        using var backend = new Backend((request, _) =>
        {
            var policies = IsObserver(request) || faithful ? new[] { first, second } : [first, first];
            return Task.FromResult(Json(200, JsonSerializer.Serialize(new
            {
                id = Vault().ExportResourceId(),
                properties = new { accessPolicies = PolicyObjects(policies) }
            })));
        });
        using var session = new Session(backend);
        var scope = Vault();
        var actual = await session.Selected.ChangeAccessPoliciesAsync(scope, AccessPolicyChange.Replace,
            [first.Build(), second.Build()], session.Selected.PrepareReceipt(scope, ManagementMutation.ReplaceAccessPolicy));
        await Assert.That(actual.Status).IsEqualTo(SecretStatus.Success);
        var measured = Measurement(ParseConfiguration(persisted));
        await ValidateAsync(() => VA.MatchResult(new(actual.Status, Policies: actual.Value), measured, scope, 10), faithful);
    }

    [Test]
    [Arguments("rbac.true", false)]
    [Arguments("rbac.true", true)]
    [Arguments("purgeProtection.true", false)]
    [Arguments("purgeProtection.true", true)]
    [Arguments("publicNetworkAccess.false", false)]
    [Arguments("publicNetworkAccess.false", true)]
    public async Task SettingsRequireAContrastingBaselineAndObservedTransition(string variant, bool transition)
    {
        var selected = Configuration() with { Rbac = true, PurgeProtection = true, PublicNetworkAccess = false };
        var baseline = selected with
        {
            Rbac = variant == "rbac.true" && transition ? false : selected.Rbac,
            PurgeProtection = variant == "purgeProtection.true" && transition ? false : selected.PurgeProtection,
            PublicNetworkAccess = variant == "publicNetworkAccess.false" && transition ? true : selected.PublicNetworkAccess
        };
        string state = VaultJson("owned-vault", baseline);
        using var backend = new Backend(async (request, token) =>
        {
            if (request.Method == HttpMethod.Patch)
            {
                var patch = JsonNode.Parse(await request.Content!.ReadAsStringAsync(token))!["properties"]!;
                var current = JsonNode.Parse(state)!;
                foreach (var property in patch.AsObject())
                    current["properties"]![property.Key] = property.Value?.DeepClone();
                state = current.ToJsonString();
            }
            return Json(200, state);
        });
        using var session = new Session(backend);
        await Assert.That((await session.Observer.GetVaultAsync(Vault())).Status).IsEqualTo(SecretStatus.Success);
        var lease = Lease(ParseConfiguration(state));
        await ValidateAsync(() => VA.RequireMutationBaseline("UpdateSettingsAsync", variant, selected, lease, [],
            AccessPolicyChange.Add), transition);
        var scope = Vault();
        var receipt = session.Selected.PrepareReceipt(scope, ManagementMutation.UpdateVault);
        var patch = variant switch
        {
            "rbac.true" => new VaultSettingsPatch(enableRbacAuthorization: true),
            "purgeProtection.true" => new VaultSettingsPatch(enablePurgeProtection: true),
            _ => new VaultSettingsPatch(publicNetworkAccess: false)
        };
        var actual = await session.Selected.UpdateSettingsAsync(scope, patch, receipt);
        await Assert.That(actual.Status).IsEqualTo(SecretStatus.Success);
        var observed = await session.Observer.GetVaultAsync(Vault());
        await Assert.That(observed.Status).IsEqualTo(SecretStatus.Success);
        var measured = Measurement(ParseConfiguration(state));
        VA.MatchResult(new(actual.Status, Vault: actual.Value), measured, scope, 10);
        VA.ValidateEffect("UpdateSettingsAsync", variant, selected, lease, measured, [], AccessPolicyChange.Add, false);
        ManagementAdmission.Receipt(receipt, "selected-contract");
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task VaultCreationRequiresDifferingPreState(bool transition)
    {
        var selected = Configuration();
        string state = VaultJson("owned-vault", selected with { Rbac = !transition });
        using var backend = new Backend(async (request, token) =>
        {
            if (request.Method == HttpMethod.Put)
            {
                var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(token))!;
                var current = JsonNode.Parse(state)!;
                current["location"] = body["location"]!.DeepClone();
                current["properties"] = body["properties"]!.DeepClone();
                current["properties"]!["provisioningState"] = "Succeeded";
                state = current.ToJsonString();
                return Json(201, state);
            }
            return Json(200, state);
        });
        using var session = new Session(backend);
        await Assert.That((await session.Observer.GetVaultAsync(Vault())).Status).IsEqualTo(SecretStatus.Success);
        var lease = Lease(ParseConfiguration(state));
        await ValidateAsync(() => VA.RequireMutationBaseline("CreateOrUpdateVaultAsync", "", selected,
            lease, [], AccessPolicyChange.Add), transition);
        await ValidateAsync(() => MO.RequireMutationBaseline(ManagementMutation.CreateOrUpdateVault, OperationInput(),
            OperationMeasurement(ManagementMutation.CreateOrUpdateVault, SecretStatus.Success) with
            { VaultConfiguration = lease.Baseline }), transition);
        var scope = Vault();
        var receipt = session.Selected.PrepareReceipt(scope, ManagementMutation.CreateOrUpdateVault);
        var actual = await session.Selected.CreateOrUpdateVaultAsync(scope, selected.Build(), receipt);
        await Assert.That(actual.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(await actual.Value.CheckStatusAsync()).IsEqualTo(SecretStatus.Success);
        await Assert.That((await session.Observer.GetVaultAsync(Vault())).Status).IsEqualTo(SecretStatus.Success);
        VA.ValidateEffect("CreateOrUpdateVaultAsync", "", selected, lease, Measurement(ParseConfiguration(state)),
            [], AccessPolicyChange.Add, false);
        MO.ValidatePersistedState(ManagementMutation.CreateOrUpdateVault, OperationInput(),
            OperationMeasurement(ManagementMutation.CreateOrUpdateVault, SecretStatus.Success) with
            { VaultConfiguration = ParseConfiguration(state) });
        ManagementAdmission.Receipt(receipt, "selected-contract");
    }

    [Test]
    [Arguments("destination", false)]
    [Arguments("destination", true)]
    [Arguments("provisioning", false)]
    [Arguments("provisioning", true)]
    [Arguments("duplicate", false)]
    [Arguments("duplicate", true)]
    public async Task NotificationInventoryMatchesDestinationStateAndIdentity(string field, bool faithful)
    {
        string[] persisted = [NotificationJson("owned-notification"), NotificationJson("other-notification")];
        using var backend = new Backend((request, _) =>
        {
            string[] rows = [.. persisted];
            if (!IsObserver(request) && !faithful)
            {
                if (field == "duplicate") rows[1] = rows[0];
                else
                {
                    var row = JsonNode.Parse(rows[0])!;
                    if (field == "destination") row["properties"]!["destination"] = null;
                    else row["properties"]!["provisioningState"] = "Updating";
                    rows[0] = row.ToJsonString();
                }
            }
            return Task.FromResult(Json(200, Inventory(rows)));
        });
        using var session = new Session(backend);
        var actual = await session.Selected.ListNotificationsAsync(Vault(), Limits());
        var independent = await session.Observer.ListNotificationsAsync(Vault(), Limits());
        await Assert.That(actual.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(independent.Status).IsEqualTo(SecretStatus.Success);
        var states = independent.Items.Select(n => new NA.SubscriptionState(n.Scope.SubscriptionName,
            n.Destination, n.ProvisioningState, SecretStatus.Success, null)).ToArray();
        var measured = NotificationMeasurement(states, []);
        await ValidateAsync(() => NA.MatchResult(new(actual.Status, Notifications: actual), states[0], measured, "", 10), faithful);
    }

    [Test]
    [Arguments("destination", false)]
    [Arguments("destination", true)]
    [Arguments("provisioning", false)]
    [Arguments("provisioning", true)]
    public async Task NotificationExactReadAlsoMatchesIndependentMetadata(string field, bool faithful)
    {
        string persisted = NotificationJson("owned-notification");
        using var backend = new Backend((request, _) =>
        {
            var row = JsonNode.Parse(persisted)!;
            if (!IsObserver(request) && !faithful)
            {
                if (field == "destination") row["properties"]!["destination"] = null;
                else row["properties"]!["provisioningState"] = "Updating";
            }
            return Task.FromResult(Json(200, row.ToJsonString()));
        });
        using var session = new Session(backend);
        var scope = new NotificationScope(Vault(), "owned-notification");
        var actual = await session.Selected.GetNotificationAsync(scope);
        var independent = await session.Observer.GetNotificationAsync(scope);
        await Assert.That(actual.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(independent.Status).IsEqualTo(SecretStatus.Success);
        var state = new NA.SubscriptionState(scope.SubscriptionName, independent.Value.Destination,
            independent.Value.ProvisioningState, independent.Status, null);
        await ValidateAsync(() => NA.MatchResult(new(actual.Status, Notification: actual.Value), state,
            NotificationMeasurement([state], []), "", 10), faithful);
    }

    [Test]
    [Arguments(false, false)]
    [Arguments(false, true)]
    [Arguments(true, false)]
    [Arguments(true, true)]
    public async Task NotificationAttributesCannotSubstituteDuplicateName(bool bounded, bool faithful)
    {
        string[] persisted = [AttributeJson("first", "one"), AttributeJson("second", "two"), AttributeJson("third", "three")];
        using var backend = new Backend((request, _) =>
        {
            string[] rows = IsObserver(request) || faithful ? persisted : [persisted[0], persisted[0], persisted[2]];
            return Task.FromResult(Json(200, Inventory(bounded ? rows : rows[..2])));
        });
        using var session = new Session(backend);
        var scope = new NotificationScope(Vault(), "owned-notification");
        var actual = await session.Selected.GetNotificationDeliveryAttributesAsync(scope, Limits(bounded ? 2 : 10));
        var observed = await session.Observer.GetNotificationDeliveryAttributesAsync(scope, Limits());
        try
        {
            await Assert.That(actual.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(observed.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(actual.Complete).IsEqualTo(!bounded);
            NA.Attribute[] attributes = observed.Items.Select(a => new NA.Attribute(a.Name, a.Kind, a.Value.Reveal(), a.IsSecret)).ToArray();
            var state = new NA.SubscriptionState(scope.SubscriptionName, NotificationDestinationKind.WebHook,
                NativeProvisioningState.Succeeded, SecretStatus.Success, NotificationConfiguration());
            await ValidateAsync(() => NA.MatchResult(new(actual.Status, Attributes: actual), state,
                NotificationMeasurement([state], attributes), bounded ? "page.bounded" : "page.complete", bounded ? 2 : 10), faithful);
            await Assert.That(NA.SameAttributes(actual.Items.Select(a =>
                new NA.Attribute(a.Name, a.Kind, a.Value.Reveal(), a.IsSecret)).ToArray(),
                attributes.Take(2).ToArray())).IsEqualTo(faithful);
        }
        finally
        {
            foreach (var attribute in actual.Items.Concat(observed.Items)) attribute.Dispose();
        }
    }

    [Test]
    [Arguments(ManagementMutation.CreateOrUpdateNotification, false)]
    [Arguments(ManagementMutation.CreateOrUpdateNotification, true)]
    [Arguments(ManagementMutation.UpdateNotification, false)]
    [Arguments(ManagementMutation.UpdateNotification, true)]
    [Arguments(ManagementMutation.DeleteNotification, false)]
    [Arguments(ManagementMutation.DeleteNotification, true)]
    public async Task NotificationMutationRequiresContrastingPersistedBaseline(ManagementMutation mutation, bool transition)
    {
        var desired = NotificationConfiguration();
        string? state = mutation == ManagementMutation.DeleteNotification && !transition ? null :
            NotificationJson("owned-notification", desired with
            {
                EndpointUrl = transition && mutation != ManagementMutation.DeleteNotification
                    ? "https://webhook.invalid/before" : desired.EndpointUrl
            });
        using var backend = new Backend(async (request, token) =>
        {
            string path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/getFullUrl", StringComparison.Ordinal))
                return Json(200, JsonSerializer.Serialize(new { endpointUrl = ParseNotification(state!).EndpointUrl }));
            if (request.Method == HttpMethod.Delete)
            {
                state = null;
                return Json(204, "");
            }
            if (request.Method == HttpMethod.Put || request.Method == HttpMethod.Patch)
            {
                var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(token))!;
                var row = JsonNode.Parse(NotificationJson("owned-notification"))!;
                var properties = request.Method == HttpMethod.Patch ? body : body["properties"]!;
                row["properties"]!["destination"] = properties["destination"]!.DeepClone();
                row["properties"]!["filter"] = properties["filter"]!.DeepClone();
                state = row.ToJsonString();
                var response = Json(201, state);
                response.Headers.TryAddWithoutValidation("Location",
                    "https://management.azure.com" + path + "?api-version=2025-02-15");
                return response;
            }
            return state is null ? Json(404, """{"error":{"code":"NotFound","message":"withheld"}}""") : Json(200, state);
        });
        using var session = new Session(backend);
        var scope = new NotificationScope(Vault(), "owned-notification");
        var before = await ObserveNotificationAsync(session.Observer, scope, state);
        string operation = mutation switch
        {
            ManagementMutation.CreateOrUpdateNotification => "CreateOrUpdateNotificationAsync",
            ManagementMutation.UpdateNotification => "UpdateNotificationAsync",
            _ => "DeleteNotificationAsync"
        };
        await ValidateAsync(() => NA.RequireMutationBaseline(operation, desired, before), transition);
        await ValidateAsync(() => MO.RequireMutationBaseline(mutation, OperationInput(),
            OperationMeasurement(mutation, before.Status, notification: before.Configuration)), transition);
        var receipt = session.Selected.PrepareReceipt(scope, mutation);
        using var configuration = desired.Build();
        var actual = mutation switch
        {
            ManagementMutation.CreateOrUpdateNotification =>
                await session.Selected.CreateOrUpdateNotificationAsync(scope, configuration, receipt),
            ManagementMutation.UpdateNotification => await session.Selected.UpdateNotificationAsync(scope, configuration, receipt),
            _ => await session.Selected.DeleteNotificationAsync(scope, receipt)
        };
        await Assert.That(actual.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(await actual.Value.CheckStatusAsync()).IsEqualTo(SecretStatus.Success);
        var after = await ObserveNotificationAsync(session.Observer, scope, state);
        MO.ValidatePersistedState(mutation, OperationInput(), OperationMeasurement(mutation, after.Status,
            notification: after.Configuration));
        ManagementAdmission.Receipt(receipt, "selected-contract");
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SuccessfulPrivateConnectionOperationMustPersistApprovedState(bool approved)
    {
        string state = ConnectionJson("owned-connection", PrivateConnectionState.Pending);
        using var backend = new Backend(async (request, token) =>
        {
            if (request.Method == HttpMethod.Put)
            {
                var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(token))!;
                var requested = Enum.Parse<PrivateConnectionState>(
                    body["properties"]!["privateLinkServiceConnectionState"]!["status"]!.GetValue<string>());
                state = ConnectionJson("owned-connection", approved ? requested : PrivateConnectionState.Rejected);
            }
            return Json(200, state);
        });
        using var session = new Session(backend);
        var scope = new PrivateConnectionScope(Vault(), "owned-connection");
        var baseline = await session.Observer.GetPrivateConnectionAsync(scope);
        await Assert.That(baseline.Status).IsEqualTo(SecretStatus.Success);
        MO.RequireMutationBaseline(ManagementMutation.UpdatePrivateConnection, OperationInput(),
            OperationMeasurement(ManagementMutation.UpdatePrivateConnection, baseline.Status, baseline.Value.State));
        var receipt = session.Selected.PrepareReceipt(scope, ManagementMutation.UpdatePrivateConnection);
        var actual = await session.Selected.UpdatePrivateConnectionAsync(scope, PrivateConnectionState.Approved, receipt);
        await Assert.That(actual.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(await actual.Value.CheckStatusAsync()).IsEqualTo(SecretStatus.Success);
        await Assert.That(actual.Value.State).IsEqualTo(NativeProvisioningState.Succeeded);
        var observed = await session.Observer.GetPrivateConnectionAsync(scope);
        await Assert.That(observed.Status).IsEqualTo(SecretStatus.Success);
        await ValidateAsync(() => MO.ValidatePersistedState(ManagementMutation.UpdatePrivateConnection, OperationInput(),
            OperationMeasurement(ManagementMutation.UpdatePrivateConnection, observed.Status, observed.Value.State)), approved);
        ManagementAdmission.Receipt(receipt, "selected-contract");
    }

    private static async Task<NA.SubscriptionState> ObserveNotificationAsync(VaultAdministration observer,
        NotificationScope scope, string? persisted)
    {
        var observation = await observer.GetNotificationAsync(scope);
        await Assert.That(observation.Status).IsEqualTo(persisted is null ? SecretStatus.Absent : SecretStatus.Success);
        if (persisted is null)
            return new(scope.SubscriptionName, NotificationDestinationKind.Unknown, NativeProvisioningState.Unknown,
                observation.Status, null);
        var full = await observer.GetNotificationFullUrlAsync(scope);
        await Assert.That(full.Status).IsEqualTo(SecretStatus.Success);
        using var url = full.Value;
        var parsed = ParseNotification(persisted) with { EndpointUrl = url.Endpoint.Reveal() };
        return new(scope.SubscriptionName, observation.Value.Destination, observation.Value.ProvisioningState,
            observation.Status, parsed);
    }
    private static NA.Configuration ParseNotification(string json)
    {
        var p = JsonNode.Parse(json)!["properties"]!;
        return new(p["destination"]!["properties"]!["endpointUrl"]!.GetValue<string>(),
            p["filter"]!["includedEventTypes"]!.AsArray().Select(e => Enum.Parse<VaultNotificationEvent>(
                e!.GetValue<string>()["Microsoft.KeyVault.".Length..])).ToArray(), []);
    }
    private static string NotificationJson(string name, NA.Configuration? configuration = null)
    {
        var c = configuration ?? NotificationConfiguration();
        return JsonSerializer.Serialize(new
        {
            id = Vault().ExportResourceId() + "/providers/Microsoft.EventGrid/eventSubscriptions/" + name,
            name,
            type = "Microsoft.EventGrid/eventSubscriptions",
            properties = new
            {
                topic = Vault().ExportResourceId(),
                provisioningState = "Succeeded",
                destination = new { endpointType = "WebHook", properties = new { endpointUrl = c.EndpointUrl } },
                filter = new { includedEventTypes = c.Events.Select(e => "Microsoft.KeyVault." + e).ToArray() }
            }
        });
    }
    private static string AttributeJson(string name, string value) =>
        JsonSerializer.Serialize(new { name, type = "Static", properties = new { value, isSecret = false } });
    private static NA.Measurement NotificationMeasurement(NA.SubscriptionState[] states, NA.Attribute[] attributes) =>
        new(Subscription, Other, Principal, "observer", Start, Start, states, attributes, [], [], [], [], []);
    private static MO.Input OperationInput()
    {
        AudienceToken Token(string token) => new(token, DateTimeOffset.MaxValue, "https://management.azure.com/.default");
        return new(new(new("https://observer.invalid"), "offline", TimeSpan.FromSeconds(5)),
            new(Token("setup"), Token("administrative"), Token("denied"), Token("observer")),
            Subscription, "owned-group", "eastus", Tenant, VaultSku.Standard, 30,
            ManagementMutation.UpdatePrivateConnection, NotificationConfiguration().EndpointUrl, Other);
    }
    private static MO.Measurement OperationMeasurement(ManagementMutation operation, SecretStatus status,
        PrivateConnectionState? connection = null, NA.Configuration? notification = null) =>
        new(Subscription, Other, "observer", Start, operation, NativeProvisioningState.Succeeded,
            Vault().ExportResourceId(), status, null, connection, notification);

    private static async Task<(VA.Result Result, VA.Measurement Measured)> InventoryAsync(
        VaultAdministration client, string kind, CollectionLimits limits)
    {
        var measured = Measurement(Configuration());
        switch (kind)
        {
            case "vault":
                var vaults = await client.ListVaultsAsync(Vault().ResourceGroup, limits);
                return (new(vaults.Status, Vaults: vaults),
                    measured with { Vaults = vaults.Items.Select(VaultRow).ToArray() });
            case "deleted":
                var deleted = await client.ListDeletedVaultsAsync(new(Subscription), limits);
                return (new(deleted.Status, DeletedVaults: deleted), measured with
                {
                    DeletedVaults = deleted.Items.Select(v => new VA.DeletedVaultRow(v.Scope.Subscription.SubscriptionId,
                        v.Scope.Location, v.Scope.VaultName, v.DeletedOn, v.ScheduledPurgeOn, v.PurgeProtected)).ToArray()
                });
            case "connection":
                var connections = await client.ListPrivateConnectionsAsync(Vault(), limits);
                return (new(connections.Status, Connections: connections), measured with
                {
                    Connections = connections.Items.Select(c => new VA.ConnectionRow(c.Scope.ConnectionName,
                        c.State, c.ProvisioningState)).ToArray()
                });
            default:
                var links = await client.ListPrivateLinkResourcesAsync(Vault(), limits);
                return (new(links.Status, Links: links), measured with
                {
                    PrivateLinks = links.Items.Select(l => new VA.PrivateLinkRow(l.Name, l.GroupId,
                        l.RequiredMembers.ToArray(), l.RequiredZoneNames.ToArray())).ToArray()
                });
        }
    }

    private static VA.VaultRow VaultRow(VaultObservation v) => new(v.Scope.ExportResourceId(),
        v.ProvisioningState, v.EnableRbacAuthorization, v.EnablePurgeProtection, v.RetentionDays);
    private static VA.Measurement Measurement(VA.Configuration configuration) => new(
        Subscription, Other, "observer", Start, Vault().ExportResourceId(), SecretStatus.Success, SecretStatus.Absent,
        configuration, configuration.Policies, PrivateConnectionState.Pending, SecretStatus.Success, [], null, [], [], [], [], null);
    private static VA.Lease Lease(VA.Configuration baseline) => new(
        new(Other, Subscription, "observer", "https://management.azure.com", "2026-02-01", Start, [Vault().ExportResourceId()]),
        "owned-vault", "owned-connection", "owned-secret", "offline-digest", baseline, PrivateConnectionState.Pending)
    {
        BaselineVaultStatus = SecretStatus.Success,
        BaselineDeletedVaultStatus = SecretStatus.Absent,
        BaselineConnectionStatus = SecretStatus.Success
    };
    private static string DeletedId(string name) =>
        $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/{name}";
    private static string ConnectionId(string name) => Vault().ExportResourceId() + "/privateEndpointConnections/" + name;
    private static object[] PolicyObjects(VA.Policy[] policies) => policies.Select(p => (object)new
    {
        tenantId = p.TenantId,
        objectId = p.PrincipalId,
        applicationId = p.ApplicationId,
        permissions = new { secrets = p.Permissions.Select(v => v.ToString().ToLowerInvariant()).ToArray() }
    }).ToArray();
    private static string VaultJson(string name, VA.Configuration? configuration = null)
    {
        var c = configuration ?? Configuration();
        return JsonSerializer.Serialize(new
        {
            id = Vault(name).ExportResourceId(),
            name,
            type = "Microsoft.KeyVault/vaults",
            location = c.Location,
            properties = new
            {
                tenantId = c.TenantId,
                sku = new { family = "A", name = c.Sku.ToString() },
                provisioningState = "Succeeded",
                enableRbacAuthorization = c.Rbac,
                enablePurgeProtection = c.PurgeProtection,
                softDeleteRetentionInDays = c.RetentionDays,
                publicNetworkAccess = c.PublicNetworkAccess ? "Enabled" : "Disabled",
                accessPolicies = PolicyObjects(c.Policies)
            }
        });
    }
    private static VA.Configuration ParseConfiguration(string json)
    {
        var row = JsonNode.Parse(json)!;
        var p = row["properties"]!;
        return new(row["location"]!.GetValue<string>(), Guid.Parse(p["tenantId"]!.GetValue<string>()),
            Enum.Parse<VaultSku>(p["sku"]!["name"]!.GetValue<string>(), true),
            p["enableRbacAuthorization"]!.GetValue<bool>(), p["enablePurgeProtection"]!.GetValue<bool>(),
            p["softDeleteRetentionInDays"]!.GetValue<int>(), p["publicNetworkAccess"]!.GetValue<string>() == "Enabled",
            ParsePolicies(p["accessPolicies"]!));
    }
    private static VA.Policy[] ParsePolicies(JsonNode rows) => rows.AsArray().Select(p => new VA.Policy(
        Guid.Parse(p!["tenantId"]!.GetValue<string>()), Guid.Parse(p["objectId"]!.GetValue<string>()),
        p["permissions"]!["secrets"]!.AsArray().Select(v =>
            Enum.Parse<SecretPermission>(v!.GetValue<string>(), true)).ToArray(),
        p["applicationId"] is { } application ? Guid.Parse(application.GetValue<string>()) : null)).ToArray();
    private static string DeletedJson(string name) => JsonSerializer.Serialize(new
    {
        id = DeletedId(name),
        name,
        properties = new
        {
            deletionDate = Start.ToString("O"),
            scheduledPurgeDate = Start.AddDays(30).ToString("O"),
            purgeProtectionEnabled = false
        }
    });
    private static string ConnectionJson(string name, PrivateConnectionState state = PrivateConnectionState.Approved) =>
        JsonSerializer.Serialize(new
        {
            id = ConnectionId(name),
            name,
            type = "Microsoft.KeyVault/vaults/privateEndpointConnections",
            properties = new
            {
                provisioningState = "Succeeded",
                privateLinkServiceConnectionState = new { status = state.ToString() }
            }
        });
    private static string LinkJson(string name) => JsonSerializer.Serialize(new
    {
        id = Vault().ExportResourceId() + "/privateLinkResources/" + name,
        name,
        properties = new { groupId = "vault", requiredMembers = new[] { "default" }, requiredZoneNames = new[] { "vault.invalid" } }
    });
    private static string Inventory(string[] rows) => """{"value":[""" + string.Join(",", rows) + "]}";
    private static bool IsObserver(HttpRequestMessage request) => request.Headers.Authorization?.Parameter == "observer";
    private static HttpResponseMessage Json(int status, string body) => new((HttpStatusCode)status)
    {
        Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json")
    };
    private static async Task ValidateAsync(Action validate, bool valid)
    {
        if (valid) validate();
        else
        {
            await Assert.That(validate).Throws<NativeCaseFailureException>();
        }
    }
    private sealed class Backend(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token);
    }
    private sealed class Session : IDisposable
    {
        private readonly HttpClient http;
        private readonly SelectedAudienceCredential selected = new(new("administrative", DateTimeOffset.MaxValue,
            "https://management.azure.com/.default"));
        private readonly SelectedAudienceCredential observer = new(new("observer", DateTimeOffset.MaxValue,
            "https://management.azure.com/.default"));
        internal Session(HttpMessageHandler backend)
        {
            http = new(backend);
            var transport = new HttpClientTransport(http);
            Selected = new(selected, transport);
            Observer = new(observer, transport);
        }
        internal VaultAdministration Selected { get; }
        internal VaultAdministration Observer { get; }
        public void Dispose() { http.Dispose(); selected.Dispose(); observer.Dispose(); }
    }
}
