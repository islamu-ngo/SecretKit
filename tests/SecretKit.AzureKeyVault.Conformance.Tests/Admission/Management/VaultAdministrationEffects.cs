using System.Text.Json.Serialization;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal static class VaultAdministrationEffects
{
    private const string Prefix = "a.management.VaultAdministration.";
    private const string Type = "SecretKit.AzureKeyVault.Management.";
    private const string Token = ",System.Threading.CancellationToken)";
    private const string Receipt = "," + Type + "ManagementReceipt";
    private const string Limits = "," + Type + "CollectionLimits";
    internal static readonly string[] ConfigurationVariants =
    [
        "sku.Standard", "sku.Premium", "authorization.rbac", "authorization.access-policy",
        "purgeProtection.false", "purgeProtection.true", "publicNetworkAccess.false", "publicNetworkAccess.true",
        "accessPolicies.empty", "accessPolicies.selected", "lro.started", "lro.completed"
    ];
    internal static readonly ManagementMember[] Members =
    [
        Member("ChangeAccessPoliciesAsync", Type + "VaultScope," + Type + "AccessPolicyChange,System.Collections.Generic.IReadOnlyList<" +
            Type + "SecretAccessPolicy>" + Receipt,
            ["change.Add", "change.Replace", "change.Remove", "permission.Get", "permission.List", "permission.Set", "permission.Delete",
                "permission.Recover", "permission.Backup", "permission.Restore", "permission.Purge", "applicationId.omitted",
                "applicationId.value", "permissions.empty", "policies.multiple"], true),
        Member("CheckNameAvailabilityAsync", Type + "SubscriptionScope,System.String", ["selector.exact"]),
        Member("CreateOrUpdateVaultAsync", Type + "VaultScope," + Type + "VaultConfiguration" + Receipt, ConfigurationVariants, true),
        Member("DeletePrivateConnectionAsync", Type + "PrivateConnectionScope" + Receipt, ["input.scope"], true),
        Member("DeleteVaultAsync", Type + "VaultScope" + Receipt, ["input.scope"], true),
        Member("GetDeletedVaultAsync", Type + "DeletedVaultScope", ["selector.exact"]),
        Member("GetPrivateConnectionAsync", Type + "PrivateConnectionScope", ["selector.exact"]),
        Member("GetVaultAsync", Type + "VaultScope", ["selector.exact"]),
        Member("ListDeletedVaultsAsync", Type + "SubscriptionScope" + Limits, ["collection.bounded"]),
        Member("ListPrivateConnectionsAsync", Type + "VaultScope" + Limits, ["collection.bounded"]),
        Member("ListPrivateLinkResourcesAsync", Type + "VaultScope" + Limits, ["collection.bounded"]),
        Member("ListVaultsAsync", Type + "ResourceGroupScope" + Limits, ["collection.bounded"], id: "ListVaultsAsync.ResourceGroup"),
        Member("ListVaultsAsync", Type + "SubscriptionScope" + Limits, ["collection.bounded"], id: "ListVaultsAsync.Subscription"),
        Member("PurgeDeletedVaultAsync", Type + "DeletedVaultScope" + Receipt, ["input.scope"], true),
        Member("RecoverVaultAsync", Type + "VaultScope," + Type + "VaultConfiguration" + Receipt, ConfigurationVariants, true),
        Member("UpdatePrivateConnectionAsync", Type + "PrivateConnectionScope," + Type + "PrivateConnectionState" + Receipt,
            ["state.Unknown.rejected", "state.Pending.rejected", "state.Approved", "state.Rejected", "state.Disconnected.rejected"], true),
        Member("UpdateSettingsAsync", Type + "VaultScope," + Type + "VaultSettingsPatch" + Receipt,
            ["rbac.omitted", "rbac.false", "rbac.true", "purgeProtection.omitted", "purgeProtection.true",
                "purgeProtection.false.rejected", "publicNetworkAccess.omitted", "publicNetworkAccess.false", "publicNetworkAccess.true"], true)
    ];
    private static ManagementMember Member(string name, string args, string[] variants, bool mutation = false, string? id = null) =>
        new(Prefix + (id ?? name), Type + "VaultAdministration." + name + "(" + args + Token, variants, mutation);

    internal sealed record Policy(Guid TenantId, Guid PrincipalId, SecretPermission[] Permissions, Guid? ApplicationId)
    {
        internal SecretAccessPolicy Build() => new(TenantId, PrincipalId, Permissions, ApplicationId);
        public override string ToString() => "[VaultPolicyInput]";
    }
    internal sealed record Configuration(
        [property: JsonRequired] string Location, [property: JsonRequired] Guid TenantId,
        [property: JsonRequired] VaultSku Sku, [property: JsonRequired] bool Rbac,
        [property: JsonRequired] bool PurgeProtection, [property: JsonRequired] int RetentionDays,
        [property: JsonRequired] bool PublicNetworkAccess, [property: JsonRequired] Policy[] Policies)
    {
        internal VaultConfiguration Build() => new(Location, TenantId, Sku, Rbac, PurgeProtection,
            RetentionDays, PublicNetworkAccess, Policies.Select(p => p.Build()));
        public override string ToString() => "[VaultConfigurationInput]";
    }
    internal sealed record Input(ObserverEndpoint Observer, ManagementIdentities Arm, Guid SubscriptionId,
        string ResourceGroup, Configuration Configuration, Policy[] IntendedPolicies, Guid ApplicationId,
        int MaximumPages, int MaximumItems, TimeSpan Timeout)
    {
        public override string ToString() => "[VaultInput]";
    }
    internal sealed record Prepare(FixtureSelector Selection, Guid SubscriptionId, string ResourceGroup,
        Configuration Configuration, Policy[] IntendedPolicies, Guid ApplicationId)
    {
        public override string ToString() => "[VaultPrepare]";
    }
    internal sealed record Lease(LeaseFacts Facts, string VaultName, string? PrivateConnectionName,
        string RuntimeSecretName, string RuntimeSecretSha256, Configuration Baseline,
        PrivateConnectionState BaselineConnectionState)
    {
        [JsonIgnore] internal SecretStatus BaselineVaultStatus { get; init; }
        [JsonIgnore] internal SecretStatus BaselineDeletedVaultStatus { get; init; }
        [JsonIgnore] internal SecretStatus BaselineConnectionStatus { get; init; }
        public override string ToString() => "[VaultLease]";
    }
    internal sealed record PolicyEffect(Guid PrincipalId, SecretPermission Permission,
        SecretStatus IntendedStatus, SecretStatus DeniedStatus, string NativeRequestId)
    {
        public override string ToString() => "[PolicyEffect]";
    }
    internal sealed record PrivateNetworkEffect(string ConnectionName, SecretStatus PrivateReadStatus,
        SecretStatus PublicReadStatus, string NativeRequestId)
    {
        public override string ToString() => "[PrivateNetworkEffect]";
    }
    internal sealed record VaultRow(
        [property: JsonRequired] string ResourceId,
        [property: JsonRequired] NativeProvisioningState ProvisioningState,
        [property: JsonRequired] bool? Rbac,
        [property: JsonRequired] bool? PurgeProtection,
        [property: JsonRequired] int? RetentionDays)
    {
        public override string ToString() => "[VaultRow]";
    }
    internal sealed record DeletedVaultRow(
        [property: JsonRequired] Guid SubscriptionId,
        [property: JsonRequired] string Location,
        [property: JsonRequired] string Name,
        [property: JsonRequired] DateTimeOffset? DeletedOn,
        [property: JsonRequired] DateTimeOffset? ScheduledPurgeOn,
        [property: JsonRequired] bool? PurgeProtected)
    {
        public override string ToString() => "[DeletedVaultRow]";
    }
    internal sealed record ConnectionRow(
        [property: JsonRequired] string Name,
        [property: JsonRequired] PrivateConnectionState State,
        [property: JsonRequired] NativeProvisioningState ProvisioningState)
    {
        public override string ToString() => "[ConnectionRow]";
    }
    internal sealed record PrivateLinkRow(
        [property: JsonRequired] string Name,
        [property: JsonRequired] string? GroupId,
        [property: JsonRequired] string[] RequiredMembers,
        [property: JsonRequired] string[] RequiredZoneNames)
    {
        public override string ToString() => "[PrivateLinkRow]";
    }
    internal sealed record Measurement(Guid LeaseId, Guid Nonce, string ObserverIdentity, DateTimeOffset ObservedAt,
        string VaultResourceId, [property: JsonRequired] SecretStatus VaultStatus,
        [property: JsonRequired] SecretStatus DeletedVaultStatus,
        [property: JsonRequired] Configuration? Configuration, Policy[] Policies,
        [property: JsonRequired] PrivateConnectionState ConnectionState,
        [property: JsonRequired] SecretStatus ConnectionStatus, PolicyEffect[] PolicyEffects, PrivateNetworkEffect? NetworkEffect,
        [property: JsonRequired] VaultRow[] Vaults,
        [property: JsonRequired] DeletedVaultRow[] DeletedVaults,
        [property: JsonRequired] ConnectionRow[] Connections,
        [property: JsonRequired] PrivateLinkRow[] PrivateLinks,
        bool? NameAvailable)
    {
        public override string ToString() => "[VaultMeasurement]";
    }
    internal sealed record Result(SecretStatus Status, ManagementOperation? Operation = null,
        VaultObservation? Vault = null, DeletedVaultObservation? DeletedVault = null,
        PrivateConnectionObservation? Connection = null, AccessPolicyObservation? Policies = null,
        VaultNameAvailability? Name = null, ManagementInventory<VaultObservation>? Vaults = null,
        ManagementInventory<DeletedVaultObservation>? DeletedVaults = null,
        ManagementInventory<PrivateConnectionObservation>? Connections = null,
        ManagementInventory<PrivateLinkObservation>? Links = null);

    public static void Register(NativeCaseRegistry registry, OwnedAzureEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected, Func<ObserverEndpoint, OwnedManagementObserver>? createObserver = null,
        HttpPipelineTransport? selectedTransport = null, HttpPipelineTransport? runtimeTransport = null,
        SelectedInvocation? selectedInvocation = null, ReadSelectedInvocation? readSelectedInvocation = null,
        DeleteSelectedInvocation? deleteSelectedInvocation = null, PurgeSelectedInvocation? purgeSelectedInvocation = null,
        CreateSelectedInvocation? createSelectedInvocation = null, RecoverSelectedInvocation? recoverSelectedInvocation = null,
        PrivateConnectionUpdateSelectedInvocation? privateConnectionUpdateSelectedInvocation = null,
        PrivateConnectionDeleteSelectedInvocation? privateConnectionDeleteSelectedInvocation = null)
    {
        // The retained read source additionally exercises actual response loss.
        // Do not label GetVault a mutation or broaden shared family admission.
        bool LostRead(NativeCaseDefinition d) => readSelectedInvocation is not null &&
            (d.Key.Operation == Prefix + "GetVaultAsync" || d.Key.Operation == Prefix + "GetDeletedVaultAsync" ||
                d.Key.Operation == Prefix + "CheckNameAvailabilityAsync" ||
                d.Key.Operation == Prefix + "GetPrivateConnectionAsync" ||
                d.Key.Operation == Prefix + "ListPrivateConnectionsAsync" ||
                d.Key.Operation == Prefix + "ListPrivateLinkResourcesAsync" ||
                (d.Key.Operation == Prefix + "ListVaultsAsync.ResourceGroup" ||
                    d.Key.Operation == Prefix + "ListVaultsAsync.Subscription" ||
                    d.Key.Operation == Prefix + "ListDeletedVaultsAsync") &&
                    d.Key.Variant == "collection.bounded") &&
            d.Key.Case == "lost-response-no-replay";
        ManagementAdmission.Register(registry, env, expected.Where(d => !LostRead(d)).ToArray(), Members,
            (d, p, t) => ExecuteAsync(env, d, p, t, createObserver, selectedTransport, runtimeTransport,
                selectedInvocation, readSelectedInvocation, deleteSelectedInvocation, purgeSelectedInvocation, createSelectedInvocation,
                recoverSelectedInvocation, privateConnectionUpdateSelectedInvocation, privateConnectionDeleteSelectedInvocation));
        foreach (var definition in expected.Where(LostRead))
        {
            var member = Members.Single(m => m.Operation == definition.Key.Operation);
            if (definition.Key.Provider != "AzureKeyVault" || definition.Member != member.Member ||
                definition.Key.Variant != (definition.Key.Operation == Prefix + "ListPrivateConnectionsAsync" ||
                    definition.Key.Operation == Prefix + "ListPrivateLinkResourcesAsync" ||
                    definition.Key.Operation == Prefix + "ListVaultsAsync.ResourceGroup" ||
                    definition.Key.Operation == Prefix + "ListVaultsAsync.Subscription" ||
                    definition.Key.Operation == Prefix + "ListDeletedVaultsAsync"
                    ? "collection.bounded" : "selector.exact"))
                throw new InvalidOperationException("management-registration-contract");
            registry.Add(new(definition, async (probe, token) =>
            {
                using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
                try
                {
                    await ExecuteAsync(env, definition, probe, linked.Token, createObserver, selectedTransport,
                        runtimeTransport, selectedInvocation, readSelectedInvocation, deleteSelectedInvocation,
                        purgeSelectedInvocation, createSelectedInvocation, recoverSelectedInvocation,
                        privateConnectionUpdateSelectedInvocation, privateConnectionDeleteSelectedInvocation).ConfigureAwait(false);
                }
                catch (NativeCaseFailureException failure)
                {
                    probe.Contract(false, failure.Message switch
                    {
                        "missing-input" => NativeFailure.MissingInput,
                        "missing-prerequisite" => NativeFailure.MissingPrerequisite,
                        "observer-unavailable" => NativeFailure.ObserverUnavailable,
                        "contract-mismatch" => NativeFailure.ContractMismatch,
                        "effect-mismatch" => NativeFailure.EffectMismatch,
                        "cleanup-incomplete" => NativeFailure.CleanupIncomplete,
                        _ => NativeFailure.UnexpectedFailure
                    });
                }
                catch (OperationCanceledException) when (!token.IsCancellationRequested)
                {
                    probe.Contract(false, NativeFailure.DeadlineExceeded);
                }
            }));
        }
    }

    internal interface ReadSelectedInvocation
    {
        ValueTask<ManagementInventory<DeletedVaultObservation>> RunListDeletedVaultsAsync(
            FixtureSelector selector, VaultAdministration originalClient, SubscriptionScope originalSubscriptionScope,
            CollectionLimits originalLimits, CancellationToken cancellationToken);
        ValueTask<ManagementInventory<VaultObservation>> RunListVaultsSubscriptionAsync(
            FixtureSelector selector, VaultAdministration originalClient, SubscriptionScope originalSubscriptionScope,
            CollectionLimits originalLimits, CancellationToken cancellationToken);
        ValueTask<ManagementInventory<VaultObservation>> RunListVaultsResourceGroupAsync(
            FixtureSelector selector, VaultAdministration client, ResourceGroupScope originalScope,
            CollectionLimits originalLimits, CancellationToken cancellationToken);
        ValueTask<ManagementInventory<PrivateLinkObservation>> RunListPrivateLinkResourcesAsync(
            FixtureSelector selector, VaultAdministration client, VaultScope originalVaultScope,
            CollectionLimits originalLimits, CancellationToken cancellationToken);
        ValueTask<ManagementInventory<PrivateConnectionObservation>> RunListPrivateConnectionsAsync(
            FixtureSelector selector, VaultAdministration client, VaultScope originalScope,
            CollectionLimits originalLimits, CancellationToken cancellationToken);
        ValueTask<SecretOutcome<PrivateConnectionObservation>> RunGetPrivateConnectionAsync(FixtureSelector selector,
            VaultAdministration client, PrivateConnectionScope scope, CancellationToken cancellationToken);
        ValueTask<SecretOutcome<VaultNameAvailability>> RunCheckNameAvailabilityAsync(FixtureSelector selector,
            VaultAdministration client, SubscriptionScope originalSubscription, string vaultName,
            CancellationToken cancellationToken);
        ValueTask<SecretOutcome<VaultObservation>> RunGetVaultAsync(FixtureSelector selector,
            VaultAdministration client, VaultScope scope, CancellationToken cancellationToken);
        ValueTask<SecretOutcome<DeletedVaultObservation>> RunGetDeletedVaultAsync(FixtureSelector selector,
            VaultAdministration client, DeletedVaultScope scope, CancellationToken cancellationToken);
    }

    internal interface DeleteSelectedInvocation
    {
        ValueTask<SecretOutcome<ManagementOperation>> RunDeleteVaultAsync(FixtureSelector selector,
            VaultAdministration client, VaultScope scope, ManagementReceipt receipt, CancellationToken cancellationToken);
    }

    internal interface PurgeSelectedInvocation
    {
        ValueTask<SecretOutcome<ManagementOperation>> RunPurgeDeletedVaultAsync(FixtureSelector selector,
            VaultAdministration client, DeletedVaultScope scope, ManagementReceipt receipt, CancellationToken cancellationToken);
    }

    internal interface CreateSelectedInvocation
    {
        ValueTask<SecretOutcome<ManagementOperation>> RunCreateOrUpdateVaultAsync(FixtureSelector selector,
            VaultAdministration client, VaultScope scope, VaultConfiguration configuration,
            ManagementReceipt receipt, CancellationToken cancellationToken);
        ValueTask<SecretStatus> CompleteCreateOrUpdateVaultAsync(FixtureSelector selector,
            ManagementOperation originalHandle, CancellationToken cancellationToken);
    }

    internal interface SelectedInvocation
    {
        ValueTask<SecretOutcome<VaultObservation>> RunUpdateSettingsAsync(FixtureSelector selector,
            VaultAdministration client, VaultScope scope, VaultSettingsPatch settings,
            ManagementReceipt receipt, CancellationToken cancellationToken);
        ValueTask<SecretOutcome<AccessPolicyObservation>> RunChangeAccessPoliciesAsync(FixtureSelector selector,
            VaultAdministration client, VaultScope scope, AccessPolicyChange change,
            IReadOnlyList<SecretAccessPolicy> policies, ManagementReceipt receipt, CancellationToken cancellationToken);
    }

    internal interface RecoverSelectedInvocation
    {
        ValueTask<SecretOutcome<ManagementOperation>> RunRecoverVaultAsync(FixtureSelector selector,
            VaultAdministration client, VaultScope scope, VaultConfiguration configuration,
            ManagementReceipt receipt, CancellationToken cancellationToken);
        ValueTask<SecretStatus> CompleteRecoverVaultAsync(FixtureSelector selector,
            ManagementOperation originalHandle, CancellationToken cancellationToken);
    }

    internal interface PrivateConnectionUpdateSelectedInvocation
    {
        ValueTask<SecretOutcome<ManagementOperation>> RunUpdatePrivateConnectionAsync(FixtureSelector selector,
            VaultAdministration client, PrivateConnectionScope scope, PrivateConnectionState state,
            ManagementReceipt receipt, CancellationToken cancellationToken);
        ValueTask<SecretStatus> CompleteUpdatePrivateConnectionAsync(FixtureSelector selector,
            ManagementOperation originalHandle, CancellationToken cancellationToken);
    }

    internal interface PrivateConnectionDeleteSelectedInvocation
    {
        ValueTask<SecretOutcome<ManagementOperation>> RunDeletePrivateConnectionAsync(FixtureSelector selector,
            VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt,
            CancellationToken cancellationToken);
        ValueTask<SecretStatus> CompleteDeletePrivateConnectionAsync(FixtureSelector selector,
            ManagementOperation originalHandle, CancellationToken cancellationToken);
    }

    private static async ValueTask ExecuteAsync(OwnedAzureEnvironment env, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token, Func<ObserverEndpoint, OwnedManagementObserver>? createObserver,
        HttpPipelineTransport? selectedTransport, HttpPipelineTransport? runtimeTransport, SelectedInvocation? selectedInvocation,
        ReadSelectedInvocation? readSelectedInvocation, DeleteSelectedInvocation? deleteSelectedInvocation,
        PurgeSelectedInvocation? purgeSelectedInvocation, CreateSelectedInvocation? createSelectedInvocation,
        RecoverSelectedInvocation? recoverSelectedInvocation,
        PrivateConnectionUpdateSelectedInvocation? privateConnectionUpdateSelectedInvocation,
        PrivateConnectionDeleteSelectedInvocation? privateConnectionDeleteSelectedInvocation)
    {
        Input input = ManagementAdmission.Input<Input>(env, "VaultAdministration");
        _ = input.Configuration.Build();
        _ = new CollectionLimits(input.MaximumPages, input.MaximumItems, input.Timeout);
        Configuration selected = definition.Key.Operation == Prefix + "UpdateSettingsAsync"
            ? SettingsConfiguration(input.Configuration, definition.Key.Variant)
            : SelectConfiguration(input.Configuration, input.IntendedPolicies, definition.Key.Variant);
        using var service = createObserver is null ? new OwnedManagementObserver(input.Observer) : createObserver(input.Observer);
        FixtureSelector selector = FixtureSelector.For(definition);
        LeaseFacts? known = null;
        try
        {
            Lease lease = await service.PostAsync<Prepare, Lease>("vault/prepare",
                new(selector, input.SubscriptionId, input.ResourceGroup, selected, input.IntendedPolicies,
                    input.ApplicationId), token).ConfigureAwait(false);
            lease.Facts.Claim(selector);
            lease.Facts.Validate(selector, "2026-02-01");
            known = lease.Facts;
            var vault = new VaultScope(new(new(input.SubscriptionId), input.ResourceGroup), lease.VaultName);
            var deleted = new DeletedVaultScope(new(input.SubscriptionId), input.Configuration.Location, lease.VaultName);
            ManagementAdmission.Require(lease.Facts.OwnedResourceIds.Contains(vault.ExportResourceId(), StringComparer.OrdinalIgnoreCase));
            string operation = definition.Key.Operation[Prefix.Length..];
            ManagementMember member = Members.Single(m => m.Operation == definition.Key.Operation);
            bool rejected = definition.Key.Variant.EndsWith(".rejected", StringComparison.Ordinal);
            using var clients = new ManagementClients(input.Arm, rejected ? "selected-contract" : definition.Key.Case,
                token, hostTransport: selectedTransport);
            ObservationSubscription subscription = await service.SubscribeAsync("vault", lease.Facts, token).ConfigureAwait(false);
            ManagementReceipt? receipt = null;
            Result? result = null;
            bool canceled = false;
            DateTimeOffset? baselineObservedAt = null;
            PrivateConnectionScope? connection = (operation.Contains("PrivateConnection", StringComparison.Ordinal) ||
                operation == "ListPrivateLinkResourcesAsync" && readSelectedInvocation is not null)
                ? new(vault, lease.PrivateConnectionName ?? throw new NativeCaseFailureException("missing-input")) : null;
            Policy[] policies = operation == "UpdateSettingsAsync" ? [] :
                SelectPolicies(input.IntendedPolicies, input.ApplicationId, definition.Key.Variant);
            AccessPolicyChange change = definition.Key.Variant switch
            {
                "change.Replace" => AccessPolicyChange.Replace,
                "change.Remove" => AccessPolicyChange.Remove,
                _ => AccessPolicyChange.Add
            };
            if ((operation == "GetVaultAsync" ||
                (operation == "ListVaultsAsync.ResourceGroup" || operation == "ListVaultsAsync.Subscription") &&
                    selector.Variant == "collection.bounded") &&
                readSelectedInvocation is not null)
            {
                var baseline = await service.PostAsync<ObserveLease, Measurement>("vault/observe",
                    new(lease.Facts.LeaseId, selector.Nonce, "baseline-before-dispatch", subscription.SubscriptionId),
                    token).ConfigureAwait(false);
                ValidateMeasurement(baseline, lease, vault, subscription);
                ManagementAdmission.Require(baseline.VaultStatus == SecretStatus.Success &&
                    baseline.DeletedVaultStatus == SecretStatus.Absent && baseline.Configuration is not null &&
                    baseline.ConnectionStatus == SecretStatus.Unknown &&
                    baseline.ConnectionState == PrivateConnectionState.Unknown,
                    NativeFailure.ObserverUnavailable);
                if (operation is "ListVaultsAsync.ResourceGroup" or "ListVaultsAsync.Subscription")
                    ManagementAdmission.Require(baseline.Configuration is not null &&
                        SameConfiguration(baseline.Configuration, lease.Baseline) &&
                        SamePolicies(baseline.Policies, baseline.Configuration.Policies) &&
                        baseline.Vaults.Length == 1 && baseline.Vaults[0].ResourceId == vault.ExportResourceId() &&
                        baseline.Vaults[0].ProvisioningState == NativeProvisioningState.Succeeded &&
                        baseline.Vaults[0].Rbac == baseline.Configuration.Rbac &&
                        baseline.Vaults[0].PurgeProtection == baseline.Configuration.PurgeProtection &&
                        baseline.Vaults[0].RetentionDays == baseline.Configuration.RetentionDays &&
                        baseline.DeletedVaults.Length == 0 && baseline.Connections.Length == 0 &&
                        baseline.PrivateLinks.Length == 0 && baseline.PolicyEffects.Length == 0 &&
                        baseline.NetworkEffect is null && baseline.NameAvailable is null,
                        NativeFailure.ObserverUnavailable);
                baselineObservedAt = baseline.ObservedAt;
                lease = lease with
                {
                    Baseline = baseline.Configuration!,
                    BaselineConnectionState = baseline.ConnectionState,
                    BaselineVaultStatus = baseline.VaultStatus,
                    BaselineDeletedVaultStatus = baseline.DeletedVaultStatus,
                    BaselineConnectionStatus = baseline.ConnectionStatus
                };
            }
            if ((operation == "GetDeletedVaultAsync" ||
                operation == "ListDeletedVaultsAsync" && selector.Variant == "collection.bounded") &&
                readSelectedInvocation is not null)
            {
                var baseline = await service.PostAsync<ObserveLease, Measurement>("vault/observe",
                    new(lease.Facts.LeaseId, selector.Nonce, "baseline-before-dispatch", subscription.SubscriptionId),
                    token).ConfigureAwait(false);
                ValidateMeasurement(baseline, lease, vault, subscription);
                ManagementAdmission.Require(baseline.VaultStatus == SecretStatus.Absent &&
                    baseline.DeletedVaultStatus == SecretStatus.Success && baseline.Configuration is null &&
                    baseline.Policies.Length == 0 && baseline.DeletedVaults.Length == 1 &&
                    baseline.Vaults.Length == 0 && baseline.Connections.Length == 0 && baseline.PrivateLinks.Length == 0 &&
                    baseline.PolicyEffects.Length == 0 && baseline.NetworkEffect is null && baseline.NameAvailable is null &&
                    baseline.ConnectionStatus == SecretStatus.Unknown &&
                    baseline.ConnectionState == PrivateConnectionState.Unknown,
                    NativeFailure.ObserverUnavailable);
                baselineObservedAt = baseline.ObservedAt;
                lease = lease with
                {
                    Baseline = lease.Baseline with { Policies = baseline.Policies },
                    BaselineConnectionState = baseline.ConnectionState,
                    BaselineVaultStatus = baseline.VaultStatus,
                    BaselineDeletedVaultStatus = baseline.DeletedVaultStatus,
                    BaselineConnectionStatus = baseline.ConnectionStatus
                };
            }
            if (operation == "CheckNameAvailabilityAsync" && readSelectedInvocation is not null)
            {
                var baseline = await service.PostAsync<ObserveLease, Measurement>("vault/observe",
                    new(lease.Facts.LeaseId, selector.Nonce, "baseline-before-dispatch", subscription.SubscriptionId),
                    token).ConfigureAwait(false);
                ValidateMeasurement(baseline, lease, vault, subscription);
                ManagementAdmission.Require(baseline.VaultStatus == SecretStatus.Success &&
                    baseline.DeletedVaultStatus == SecretStatus.Absent && baseline.Configuration is not null &&
                    SameConfiguration(baseline.Configuration, lease.Baseline) &&
                    SamePolicies(baseline.Policies, baseline.Configuration.Policies) &&
                    baseline.Vaults.Length == 0 && baseline.DeletedVaults.Length == 0 &&
                    baseline.Connections.Length == 0 && baseline.PrivateLinks.Length == 0 &&
                    baseline.PolicyEffects.Length == 0 && baseline.NetworkEffect is null &&
                    baseline.NameAvailable == false && baseline.ConnectionStatus == SecretStatus.Unknown &&
                    baseline.ConnectionState == PrivateConnectionState.Unknown,
                    NativeFailure.ObserverUnavailable);
                baselineObservedAt = baseline.ObservedAt;
                lease = lease with
                {
                    Baseline = baseline.Configuration!,
                    BaselineConnectionState = baseline.ConnectionState,
                    BaselineVaultStatus = baseline.VaultStatus,
                    BaselineDeletedVaultStatus = baseline.DeletedVaultStatus,
                    BaselineConnectionStatus = baseline.ConnectionStatus
                };
            }
            if (operation is "GetPrivateConnectionAsync" or "ListPrivateConnectionsAsync" or "ListPrivateLinkResourcesAsync" &&
                readSelectedInvocation is not null)
            {
                var baseline = await service.PostAsync<ObserveLease, Measurement>("vault/observe",
                    new(lease.Facts.LeaseId, selector.Nonce, "baseline-before-dispatch", subscription.SubscriptionId),
                    token).ConfigureAwait(false);
                ValidateMeasurement(baseline, lease, vault, subscription);
                ManagementAdmission.Require(baseline.VaultStatus == SecretStatus.Success &&
                    baseline.DeletedVaultStatus == SecretStatus.Absent && baseline.Configuration is not null &&
                    SameConfiguration(baseline.Configuration, lease.Baseline) &&
                    SamePolicies(baseline.Policies, baseline.Configuration.Policies) &&
                    baseline.Configuration.PublicNetworkAccess && !baseline.Configuration.PurgeProtection &&
                    baseline.ConnectionStatus == SecretStatus.Success &&
                    baseline.ConnectionState == PrivateConnectionState.Pending && baseline.Connections.Length == 1 &&
                    baseline.Connections[0].Name == connection!.ConnectionName &&
                    baseline.Connections[0].State == PrivateConnectionState.Pending &&
                    baseline.Connections[0].ProvisioningState == NativeProvisioningState.Succeeded &&
                    (operation != "ListPrivateLinkResourcesAsync" ||
                        baseline.PrivateLinks.Length == 1 && baseline.PrivateLinks[0].Name == "vault" &&
                        baseline.PrivateLinks[0].GroupId == "vault" &&
                        baseline.PrivateLinks[0].RequiredMembers is not null &&
                        baseline.PrivateLinks[0].RequiredZoneNames is not null) &&
                    baseline.NetworkEffect is
                    {
                        PrivateReadStatus: SecretStatus.Denied,
                        PublicReadStatus: SecretStatus.Success
                    } network &&
                    network.ConnectionName == connection.ConnectionName && !string.IsNullOrWhiteSpace(network.NativeRequestId),
                    NativeFailure.ObserverUnavailable);
                baselineObservedAt = baseline.ObservedAt;
                lease = lease with
                {
                    Baseline = baseline.Configuration!,
                    BaselineConnectionState = baseline.ConnectionState,
                    BaselineVaultStatus = baseline.VaultStatus,
                    BaselineDeletedVaultStatus = baseline.DeletedVaultStatus,
                    BaselineConnectionStatus = baseline.ConnectionStatus
                };
            }
            if (member.Mutation)
            {
                var baseline = await service.PostAsync<ObserveLease, Measurement>("vault/observe",
                    new(lease.Facts.LeaseId, selector.Nonce, "baseline-before-dispatch", subscription.SubscriptionId),
                    token).ConfigureAwait(false);
                ValidateMeasurement(baseline, lease, vault, subscription);
                baselineObservedAt = baseline.ObservedAt;
                ManagementAdmission.Require(baseline.VaultStatus is SecretStatus.Success or SecretStatus.Absent &&
                    baseline.DeletedVaultStatus is SecretStatus.Success or SecretStatus.Absent &&
                    baseline.ConnectionStatus is SecretStatus.Success or SecretStatus.Absent &&
                    (baseline.VaultStatus != SecretStatus.Success || baseline.Configuration is not null),
                    NativeFailure.ObserverUnavailable);
                lease = lease with
                {
                    Baseline = baseline.Configuration ?? lease.Baseline with { Policies = baseline.Policies },
                    BaselineConnectionState = baseline.ConnectionState,
                    BaselineVaultStatus = baseline.VaultStatus,
                    BaselineDeletedVaultStatus = baseline.DeletedVaultStatus,
                    BaselineConnectionStatus = baseline.ConnectionStatus
                };
                if (!rejected)
                    RequireMutationBaseline(operation, definition.Key.Variant, selected, lease, policies, change);
                ManagementMutation mutation = operation switch
                {
                    "CreateOrUpdateVaultAsync" => ManagementMutation.CreateOrUpdateVault,
                    "RecoverVaultAsync" => ManagementMutation.RecoverVault,
                    "DeleteVaultAsync" => ManagementMutation.DeleteVault,
                    "PurgeDeletedVaultAsync" => ManagementMutation.PurgeDeletedVault,
                    "UpdateSettingsAsync" => ManagementMutation.UpdateVault,
                    "UpdatePrivateConnectionAsync" => ManagementMutation.UpdatePrivateConnection,
                    "DeletePrivateConnectionAsync" => ManagementMutation.DeletePrivateConnection,
                    "ChangeAccessPoliciesAsync" => change switch
                    {
                        AccessPolicyChange.Add => ManagementMutation.AddAccessPolicy,
                        AccessPolicyChange.Replace => ManagementMutation.ReplaceAccessPolicy,
                        _ => ManagementMutation.RemoveAccessPolicy
                    },
                    _ => throw new NativeCaseFailureException("contract-mismatch")
                };
                ManagementScope scope = mutation == ManagementMutation.PurgeDeletedVault ? deleted :
                    connection is not null ? connection : vault;
                receipt = clients.Selected.PrepareReceipt(scope, mutation);
            }
            Task boundary = clients.Boundary.ResponseReceived;
            try
            {
                result = await InvokeAsync(clients.Selected, operation, vault, deleted, connection, selected,
                    input, policies, change, definition.Key.Variant, receipt, clients.Cancellation.Token,
                    selector, selectedInvocation, readSelectedInvocation, deleteSelectedInvocation,
                    purgeSelectedInvocation, createSelectedInvocation, recoverSelectedInvocation,
                    privateConnectionUpdateSelectedInvocation, privateConnectionDeleteSelectedInvocation).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (clients.Cancellation.IsCancellationRequested && !token.IsCancellationRequested)
            {
                canceled = true;
            }
            catch (ArgumentException) when (definition.Key.Variant == "purgeProtection.false.rejected")
            {
                result = new(SecretStatus.Invalid);
            }
            Measurement measured = await service.PostAsync<ObserveLease, Measurement>("vault/observe",
                new(lease.Facts.LeaseId, selector.Nonce, "post-operation", subscription.SubscriptionId), token).ConfigureAwait(false);
            ValidateMeasurement(measured, lease, vault, subscription);
            ManagementAdmission.Require(baselineObservedAt is null || measured.ObservedAt >= baselineObservedAt,
                NativeFailure.ObserverUnavailable);
            if (rejected)
            {
                ManagementAdmission.Require(result?.Status == SecretStatus.Invalid && !boundary.IsCompleted &&
                    receipt?.Evidence == DispatchEvidence.NotDispatched &&
                    measured.Configuration is not null && SameConfiguration(measured.Configuration, lease.Baseline) &&
                    measured.ConnectionState == lease.BaselineConnectionState, NativeFailure.ContractMismatch);
            }
            else if (definition.Key.Case == "cancellation-boundary")
                ManagementAdmission.Require(canceled && boundary.IsCompletedSuccessfully, NativeFailure.ContractMismatch);
            else if (definition.Key.Case == "lost-response-no-replay")
                ManagementAdmission.Require(result?.Status == SecretStatus.Unknown && boundary.IsCompletedSuccessfully,
                    NativeFailure.ContractMismatch);
            else if (definition.Key.Case == "denied-authority")
                ManagementAdmission.Require(result?.Status == SecretStatus.Denied, NativeFailure.ContractMismatch);
            else
            {
                ManagementAdmission.Require(result?.Status == SecretStatus.Success, NativeFailure.ContractMismatch);
                if (result!.Operation is { } lro)
                {
                    if (definition.Key.Variant == "lro.started")
                        ManagementAdmission.Require(lro.State == NativeProvisioningState.Pending, NativeFailure.ContractMismatch);
                    if (operation == "CreateOrUpdateVaultAsync" && createSelectedInvocation is not null)
                        ManagementAdmission.Require(await createSelectedInvocation.CompleteCreateOrUpdateVaultAsync(
                            selector, lro, token).ConfigureAwait(false) == SecretStatus.Success,
                            NativeFailure.ContractMismatch);
                    else if (operation == "RecoverVaultAsync" && recoverSelectedInvocation is not null)
                        ManagementAdmission.Require(await recoverSelectedInvocation.CompleteRecoverVaultAsync(
                            selector, lro, token).ConfigureAwait(false) == SecretStatus.Success,
                            NativeFailure.ContractMismatch);
                    else if (operation == "UpdatePrivateConnectionAsync" && privateConnectionUpdateSelectedInvocation is not null)
                        ManagementAdmission.Require(await privateConnectionUpdateSelectedInvocation.CompleteUpdatePrivateConnectionAsync(
                            selector, lro, token).ConfigureAwait(false) == SecretStatus.Success,
                            NativeFailure.ContractMismatch);
                    else if (operation == "DeletePrivateConnectionAsync" && privateConnectionDeleteSelectedInvocation is not null)
                        ManagementAdmission.Require(await privateConnectionDeleteSelectedInvocation.CompleteDeletePrivateConnectionAsync(
                            selector, lro, token).ConfigureAwait(false) == SecretStatus.Success,
                            NativeFailure.ContractMismatch);
                    else if (definition.Key.Variant == "lro.completed")
                        ManagementAdmission.Require(await lro.CheckStatusAsync(token).ConfigureAwait(false) == SecretStatus.Success,
                            NativeFailure.ContractMismatch);
                }
                MatchResult(result, measured, vault, input.MaximumItems);
            }
            if (receipt is not null && !rejected) ManagementAdmission.Receipt(receipt, definition.Key.Case);
            bool unchanged = rejected || definition.Key.Case == "denied-authority";
            ValidateEffect(operation, definition.Key.Variant, selected, lease, measured, policies, change, unchanged);
            // Runtime identities are selected explicitly even when the private-network
            // observer executes the permission-specific operation in its own network.
            if (operation == "ChangeAccessPoliciesAsync" && !unchanged)
            {
                PolicyEffect runtimeWitness = measured.PolicyEffects.Single(e =>
                    e.PrincipalId == policies[0].PrincipalId && e.Permission == SecretPermission.Get);
                var uri = new Uri("https://" + lease.VaultName + ".vault.azure.net");
                await RoleAdministrationEffects.CheckReadAsync(new(uri, env.Credential(NativeIdentityRole.Runtime), runtimeTransport),
                    lease.RuntimeSecretName, lease.RuntimeSecretSha256, runtimeWitness.IntendedStatus, token).ConfigureAwait(false);
                await RoleAdministrationEffects.CheckReadAsync(new(uri, env.Credential(NativeIdentityRole.Denied), runtimeTransport),
                    lease.RuntimeSecretName, lease.RuntimeSecretSha256, SecretStatus.Denied, token).ConfigureAwait(false);
                ManagementAdmission.Confirm(env, definition, "selected-runtime-identity");
            }
            // Private-network calls are measured by the separately owned observer;
            // a workstation read is not substituted for that network boundary.
            probe.Contract(true, NativeFailure.ContractMismatch);
            probe.Effect(NativeObservation.Matched);
            ManagementAdmission.ConfirmInfrastructure(env, definition, lease.Facts);
            if (result?.Status == SecretStatus.Success && definition.Key.Case != "denied-authority")
                ManagementAdmission.Confirm(env, definition, "selected-administrative-identity",
                    "scoped-administrative-rights", "azure-arm-public-cloud-rights");
            if (measured.PolicyEffects.Length > 0 && operation == "ChangeAccessPoliciesAsync" && !unchanged)
                ManagementAdmission.Confirm(env, definition, "intended-principal-permission-observer");
            if (measured.NetworkEffect is not null && connection is not null)
                ManagementAdmission.Confirm(env, definition, "owned-private-endpoint", "private-network-observer");
        }
        finally
        {
            await VaultFixtureRelease.ReleaseAsync(service, selector, known, probe, env, definition).ConfigureAwait(false);
        }
    }

    internal static PolicyEffect[] ComposePolicyEffects(VaultPolicyPermissionTrial source,
        VaultPolicyPermissionTrial.Window window, VaultAdministrationCollector.Binding binding,
        VaultPolicyPermissionTrial.PrincipalClaim principal, VaultPolicyPermissionTrial.Measurement measurement) =>
        source.ComposePolicyEffects(window, binding, principal, measurement);

    internal static Configuration SelectConfiguration(Configuration baseline, Policy[] policies, string variant) => variant switch
    {
        "sku.Standard" => baseline with { Sku = VaultSku.Standard },
        "sku.Premium" => baseline with { Sku = VaultSku.Premium },
        "authorization.rbac" => baseline with { Rbac = true, Policies = [] },
        "authorization.access-policy" => baseline with { Rbac = false, Policies = policies },
        "purgeProtection.false" => baseline with { PurgeProtection = false },
        "purgeProtection.true" => baseline with { PurgeProtection = true },
        "publicNetworkAccess.false" => baseline with { PublicNetworkAccess = false },
        "publicNetworkAccess.true" => baseline with { PublicNetworkAccess = true },
        "accessPolicies.empty" => baseline with { Policies = [] },
        "accessPolicies.selected" => baseline with { Rbac = false, Policies = policies },
        _ => baseline
    };

    internal static Policy[] SelectPolicies(Policy[] input, Guid applicationId, string variant)
    {
        ManagementAdmission.Require(input.Length is >= 1 and <= 16);
        Policy[] selected = variant == "policies.multiple" ? input : [input[0]];
        if (variant == "policies.multiple") ManagementAdmission.Require(selected.Length >= 2);
        selected = selected.Select(p => variant switch
        {
            "applicationId.omitted" => p with { ApplicationId = null },
            "applicationId.value" => p with { ApplicationId = applicationId },
            "permissions.empty" => p with { Permissions = [] },
            _ when variant.StartsWith("permission.", StringComparison.Ordinal) =>
                p with { Permissions = [Enum.Parse<SecretPermission>(variant["permission.".Length..])] },
            _ => p
        }).ToArray();
        foreach (Policy policy in selected) _ = policy.Build();
        return selected;
    }

    internal static VaultSettingsPatch Patch(string variant) => variant switch
    {
        "rbac.omitted" => new(publicNetworkAccess: true),
        "rbac.false" => new(enableRbacAuthorization: false),
        "rbac.true" => new(enableRbacAuthorization: true),
        "purgeProtection.omitted" => new(enableRbacAuthorization: true),
        "purgeProtection.true" => new(enablePurgeProtection: true),
        "purgeProtection.false.rejected" => new(enablePurgeProtection: false),
        "publicNetworkAccess.omitted" => new(enableRbacAuthorization: true),
        "publicNetworkAccess.false" => new(publicNetworkAccess: false),
        "publicNetworkAccess.true" => new(publicNetworkAccess: true),
        _ => throw new NativeCaseFailureException("missing-input")
    };

    internal static Configuration SettingsConfiguration(Configuration baseline, string variant) => variant switch
    {
        "rbac.omitted" or "publicNetworkAccess.true" => baseline with { PublicNetworkAccess = true },
        "rbac.false" => baseline with { Rbac = false },
        "rbac.true" or "purgeProtection.omitted" or "publicNetworkAccess.omitted" => baseline with { Rbac = true },
        "purgeProtection.true" => baseline with { PurgeProtection = true },
        "publicNetworkAccess.false" => baseline with { PublicNetworkAccess = false },
        "purgeProtection.false.rejected" => baseline,
        _ => throw new NativeCaseFailureException("missing-input")
    };

    private static async ValueTask<Result> InvokeAsync(VaultAdministration client, string operation, VaultScope vault,
        DeletedVaultScope deleted, PrivateConnectionScope? connection, Configuration configuration, Input input,
        Policy[] policies, AccessPolicyChange change, string variant, ManagementReceipt? receipt, CancellationToken token,
        FixtureSelector selector, SelectedInvocation? selectedInvocation, ReadSelectedInvocation? readSelectedInvocation,
        DeleteSelectedInvocation? deleteSelectedInvocation, PurgeSelectedInvocation? purgeSelectedInvocation,
        CreateSelectedInvocation? createSelectedInvocation, RecoverSelectedInvocation? recoverSelectedInvocation,
        PrivateConnectionUpdateSelectedInvocation? privateConnectionUpdateSelectedInvocation,
        PrivateConnectionDeleteSelectedInvocation? privateConnectionDeleteSelectedInvocation)
    {
        var limits = new CollectionLimits(input.MaximumPages, input.MaximumItems, input.Timeout);
        switch (operation)
        {
            case "CreateOrUpdateVaultAsync":
            case "RecoverVaultAsync":
                {
                    var originalConfiguration = configuration.Build();
                    var outcome = operation == "CreateOrUpdateVaultAsync"
                        ? createSelectedInvocation is null
                            ? await client.CreateOrUpdateVaultAsync(vault, originalConfiguration, receipt!, token).ConfigureAwait(false)
                            : await createSelectedInvocation.RunCreateOrUpdateVaultAsync(selector, client, vault,
                                originalConfiguration, receipt!, token).ConfigureAwait(false)
                        : recoverSelectedInvocation is null
                            ? await client.RecoverVaultAsync(vault, originalConfiguration, receipt!, token).ConfigureAwait(false)
                            : await recoverSelectedInvocation.RunRecoverVaultAsync(selector, client, vault,
                                originalConfiguration, receipt!, token).ConfigureAwait(false);
                    return new(outcome.Status, outcome.IsSuccess ? outcome.Value : null);
                }
            case "DeleteVaultAsync":
                {
                    var o = deleteSelectedInvocation is null
                        ? await client.DeleteVaultAsync(vault, receipt!, token).ConfigureAwait(false)
                        : await deleteSelectedInvocation.RunDeleteVaultAsync(selector, client, vault, receipt!, token).ConfigureAwait(false);
                    return new(o.Status, o.IsSuccess ? o.Value : null);
                }
            case "PurgeDeletedVaultAsync":
                {
                    var o = purgeSelectedInvocation is null
                        ? await client.PurgeDeletedVaultAsync(deleted, receipt!, token).ConfigureAwait(false)
                        : await purgeSelectedInvocation.RunPurgeDeletedVaultAsync(selector, client, deleted, receipt!, token).ConfigureAwait(false);
                    return new(o.Status, o.IsSuccess ? o.Value : null);
                }
            case "UpdatePrivateConnectionAsync":
                {
                    PrivateConnectionState state = Enum.Parse<PrivateConnectionState>(variant.Split('.')[1]);
                    var o = privateConnectionUpdateSelectedInvocation is null
                        ? await client.UpdatePrivateConnectionAsync(connection!, state, receipt!, token).ConfigureAwait(false)
                        : await privateConnectionUpdateSelectedInvocation.RunUpdatePrivateConnectionAsync(
                            selector, client, connection!, state, receipt!, token).ConfigureAwait(false);
                    return new(o.Status, o.IsSuccess ? o.Value : null);
                }
            case "DeletePrivateConnectionAsync":
                {
                    var o = privateConnectionDeleteSelectedInvocation is null
                        ? await client.DeletePrivateConnectionAsync(connection!, receipt!, token).ConfigureAwait(false)
                        : await privateConnectionDeleteSelectedInvocation.RunDeletePrivateConnectionAsync(
                            selector, client, connection!, receipt!, token).ConfigureAwait(false);
                    return new(o.Status, o.IsSuccess ? o.Value : null);
                }
            case "UpdateSettingsAsync":
                {
                    // Construction rejects purge=false before the source hook,
                    // task creation or any native dispatch.
                    var patch = Patch(variant);
                    var o = selectedInvocation is null
                        ? await client.UpdateSettingsAsync(vault, patch, receipt!, token).ConfigureAwait(false)
                        : await selectedInvocation.RunUpdateSettingsAsync(selector, client, vault, patch,
                            receipt!, token).ConfigureAwait(false);
                    return new(o.Status, Vault: o.IsSuccess ? o.Value : null);
                }
            case "ChangeAccessPoliciesAsync":
                {
                    var selectedPolicies = policies.Select(p => p.Build()).ToArray();
                    var o = selectedInvocation is null
                        ? await client.ChangeAccessPoliciesAsync(vault, change, selectedPolicies, receipt!, token).ConfigureAwait(false)
                        : await selectedInvocation.RunChangeAccessPoliciesAsync(selector, client, vault, change, selectedPolicies,
                            receipt!, token).ConfigureAwait(false);
                    return new(o.Status, Policies: o.IsSuccess ? o.Value : null);
                }
            case "GetVaultAsync":
                {
                    var o = readSelectedInvocation is null
                        ? await client.GetVaultAsync(vault, token).ConfigureAwait(false)
                        : await readSelectedInvocation.RunGetVaultAsync(selector, client, vault, token).ConfigureAwait(false);
                    return new(o.Status, Vault: o.IsSuccess ? o.Value : null);
                }
            case "GetDeletedVaultAsync":
                {
                    var o = readSelectedInvocation is null
                        ? await client.GetDeletedVaultAsync(deleted, token).ConfigureAwait(false)
                        : await readSelectedInvocation.RunGetDeletedVaultAsync(selector, client, deleted, token).ConfigureAwait(false);
                    return new(o.Status, DeletedVault: o.IsSuccess ? o.Value : null);
                }
            case "GetPrivateConnectionAsync":
                {
                    var o = readSelectedInvocation is null
                        ? await client.GetPrivateConnectionAsync(connection!, token).ConfigureAwait(false)
                        : await readSelectedInvocation.RunGetPrivateConnectionAsync(selector, client, connection!, token).ConfigureAwait(false);
                    return new(o.Status, Connection: o.IsSuccess ? o.Value : null);
                }
            case "CheckNameAvailabilityAsync":
                {
                    var o = readSelectedInvocation is null
                        ? await client.CheckNameAvailabilityAsync(vault.ResourceGroup.Subscription, vault.VaultName, token).ConfigureAwait(false)
                        : await readSelectedInvocation.RunCheckNameAvailabilityAsync(selector, client,
                            vault.ResourceGroup.Subscription, vault.VaultName, token).ConfigureAwait(false);
                    return new(o.Status, Name: o.IsSuccess ? o.Value : null);
                }
            case "ListVaultsAsync.ResourceGroup":
                {
                    var o = readSelectedInvocation is null
                        ? await client.ListVaultsAsync(vault.ResourceGroup, limits, token).ConfigureAwait(false)
                        : await readSelectedInvocation.RunListVaultsResourceGroupAsync(selector, client,
                            vault.ResourceGroup, limits, token).ConfigureAwait(false);
                    return new(o.Status, Vaults: o);
                }
            case "ListVaultsAsync.Subscription":
                {
                    var o = readSelectedInvocation is null
                        ? await client.ListVaultsAsync(vault.ResourceGroup.Subscription, limits, token).ConfigureAwait(false)
                        : await readSelectedInvocation.RunListVaultsSubscriptionAsync(selector, client,
                            vault.ResourceGroup.Subscription, limits, token).ConfigureAwait(false);
                    return new(o.Status, Vaults: o);
                }
            case "ListDeletedVaultsAsync":
                {
                    var o = readSelectedInvocation is null
                        ? await client.ListDeletedVaultsAsync(vault.ResourceGroup.Subscription, limits, token).ConfigureAwait(false)
                        : await readSelectedInvocation.RunListDeletedVaultsAsync(selector, client,
                            vault.ResourceGroup.Subscription, limits, token).ConfigureAwait(false);
                    return new(o.Status, DeletedVaults: o);
                }
            case "ListPrivateConnectionsAsync":
                {
                    var o = readSelectedInvocation is null
                        ? await client.ListPrivateConnectionsAsync(vault, limits, token).ConfigureAwait(false)
                        : await readSelectedInvocation.RunListPrivateConnectionsAsync(selector, client, vault, limits, token)
                            .ConfigureAwait(false);
                    return new(o.Status, Connections: o);
                }
            case "ListPrivateLinkResourcesAsync":
                {
                    var o = readSelectedInvocation is null
                        ? await client.ListPrivateLinkResourcesAsync(vault, limits, token).ConfigureAwait(false)
                        : await readSelectedInvocation.RunListPrivateLinkResourcesAsync(selector, client, vault, limits, token)
                            .ConfigureAwait(false);
                    return new(o.Status, Links: o);
                }
            default: throw new NativeCaseFailureException("contract-mismatch");
        }
    }

    internal static bool SameConfiguration(Configuration a, Configuration b) =>
        a.Location == b.Location && a.TenantId == b.TenantId && a.Sku == b.Sku && a.Rbac == b.Rbac &&
        a.PurgeProtection == b.PurgeProtection && a.RetentionDays == b.RetentionDays &&
        a.PublicNetworkAccess == b.PublicNetworkAccess && SamePolicies(a.Policies, b.Policies);

    internal static bool SamePolicies(Policy[] a, Policy[] b) => a.Length == b.Length &&
        a.Select(p => (p.TenantId, p.PrincipalId, p.ApplicationId)).Distinct().Count() == a.Length &&
        b.Select(p => (p.TenantId, p.PrincipalId, p.ApplicationId)).Distinct().Count() == b.Length &&
        a.All(p => b.Any(q => p.TenantId == q.TenantId && p.PrincipalId == q.PrincipalId &&
            p.ApplicationId == q.ApplicationId && p.Permissions.Order().SequenceEqual(q.Permissions.Order())));

    private static void ValidateMeasurement(Measurement m, Lease lease, VaultScope vault, ObservationSubscription subscription) =>
        ManagementAdmission.Require(m.LeaseId == lease.Facts.LeaseId && m.Nonce == lease.Facts.Nonce &&
            m.ObserverIdentity == lease.Facts.ObserverIdentity && m.ObservedAt >= subscription.ArmedAt &&
            m.VaultResourceId.Equals(vault.ExportResourceId(), StringComparison.OrdinalIgnoreCase),
            NativeFailure.ObserverUnavailable);

    internal static void MatchResult(Result r, Measurement m, VaultScope vault, int maximumItems)
    {
        if (r.Vault is { } v)
            ManagementAdmission.Require(ManagementAdmission.SameVault(v.Scope, vault) && m.Configuration is { } c &&
                v.EnableRbacAuthorization == c.Rbac && v.EnablePurgeProtection == c.PurgeProtection &&
                v.RetentionDays == c.RetentionDays, NativeFailure.ContractMismatch);
        if (r.DeletedVault is { } d)
            ManagementAdmission.Require(d.Scope.VaultName == vault.VaultName && m.DeletedVaultStatus == SecretStatus.Success &&
                d.DeletedOn is not null && d.ScheduledPurgeOn > d.DeletedOn, NativeFailure.ContractMismatch);
        if (r.Connection is { } connection)
            ManagementAdmission.Require(connection.State == m.ConnectionState &&
                connection.Scope.ConnectionName == m.NetworkEffect?.ConnectionName, NativeFailure.ContractMismatch);
        if (r.Policies is { } policies)
            ManagementAdmission.Require(SamePolicies(policies.Policies.Select(p =>
                new Policy(p.TenantId, p.ObjectId, p.Permissions.ToArray(), p.ApplicationId)).ToArray(), m.Policies),
                NativeFailure.ContractMismatch);
        if (r.Name is { } name)
            ManagementAdmission.Require(name.Available == m.NameAvailable && m.NameAvailable is not null, NativeFailure.ContractMismatch);
        if (r.Vaults is { } vs)
        {
            MatchCollection(vs.Items.Select(v => v.Scope.ExportResourceId()).ToArray(),
                m.Vaults.Select(v => v.ResourceId).ToArray(), maximumItems, vs.Complete);
            foreach (var item in vs.Items)
            {
                var observed = m.Vaults.Single(v => v.ResourceId.Equals(item.Scope.ExportResourceId(), StringComparison.OrdinalIgnoreCase));
                ManagementAdmission.Require(item.ProvisioningState == observed.ProvisioningState &&
                    item.EnableRbacAuthorization == observed.Rbac && item.EnablePurgeProtection == observed.PurgeProtection &&
                    item.RetentionDays == observed.RetentionDays, NativeFailure.ContractMismatch);
            }
        }
        if (r.DeletedVaults is { } ds)
        {
            MatchCollection(ds.Items.Select(v => $"{v.Scope.Subscription.SubscriptionId:D}/{v.Scope.Location}/{v.Scope.VaultName}").ToArray(),
                m.DeletedVaults.Select(v => $"{v.SubscriptionId:D}/{v.Location}/{v.Name}").ToArray(), maximumItems, ds.Complete);
            foreach (var item in ds.Items)
            {
                var observed = m.DeletedVaults.Single(v => v.SubscriptionId == item.Scope.Subscription.SubscriptionId &&
                    v.Location.Equals(item.Scope.Location, StringComparison.OrdinalIgnoreCase) &&
                    v.Name.Equals(item.Scope.VaultName, StringComparison.OrdinalIgnoreCase));
                ManagementAdmission.Require(item.DeletedOn == observed.DeletedOn && item.ScheduledPurgeOn == observed.ScheduledPurgeOn &&
                    item.PurgeProtected == observed.PurgeProtected, NativeFailure.ContractMismatch);
            }
        }
        if (r.Connections is { } cs)
        {
            MatchCollection(cs.Items.Select(v => v.Scope.ConnectionName).ToArray(),
                m.Connections.Select(v => v.Name).ToArray(), maximumItems, cs.Complete);
            foreach (var item in cs.Items)
            {
                var observed = m.Connections.Single(v => v.Name.Equals(item.Scope.ConnectionName, StringComparison.OrdinalIgnoreCase));
                ManagementAdmission.Require(ManagementAdmission.SameVault(item.Scope.Vault, vault) &&
                    item.State == observed.State && item.ProvisioningState == observed.ProvisioningState,
                    NativeFailure.ContractMismatch);
            }
        }
        if (r.Links is { } ls)
        {
            MatchCollection(ls.Items.Select(v => v.Name).ToArray(),
                m.PrivateLinks.Select(v => v.Name).ToArray(), maximumItems, ls.Complete);
            foreach (var item in ls.Items)
            {
                var observed = m.PrivateLinks.Single(v => v.Name.Equals(item.Name, StringComparison.OrdinalIgnoreCase));
                ManagementAdmission.Require(item.GroupId == observed.GroupId &&
                    item.RequiredMembers.SequenceEqual(observed.RequiredMembers) &&
                    item.RequiredZoneNames.SequenceEqual(observed.RequiredZoneNames), NativeFailure.ContractMismatch);
            }
        }
    }
    internal static void MatchCollection(string[] selected, string[] observed, int maximum, bool complete) =>
        ManagementAdmission.Require(selected.Length > 0 && selected.Length <= maximum &&
            selected.Distinct(StringComparer.OrdinalIgnoreCase).Count() == selected.Length &&
            observed.Distinct(StringComparer.OrdinalIgnoreCase).Count() == observed.Length &&
            selected.All(s => observed.Contains(s, StringComparer.OrdinalIgnoreCase)) &&
            (!complete || selected.Length == observed.Length), NativeFailure.EffectMismatch);

    internal static void RequireMutationBaseline(string operation, string variant, Configuration selected,
        Lease lease, Policy[] policies, AccessPolicyChange change)
    {
        bool valid = operation switch
        {
            "CreateOrUpdateVaultAsync" => lease.BaselineVaultStatus == SecretStatus.Absent ||
                lease.BaselineVaultStatus == SecretStatus.Success && !SameConfiguration(lease.Baseline, selected),
            "RecoverVaultAsync" => lease.BaselineVaultStatus == SecretStatus.Absent &&
                lease.BaselineDeletedVaultStatus == SecretStatus.Success,
            "DeleteVaultAsync" => lease.BaselineVaultStatus == SecretStatus.Success,
            "PurgeDeletedVaultAsync" => lease.BaselineDeletedVaultStatus == SecretStatus.Success,
            "UpdateSettingsAsync" => lease.BaselineVaultStatus == SecretStatus.Success &&
                (lease.Baseline.Rbac != selected.Rbac || lease.Baseline.PurgeProtection != selected.PurgeProtection ||
                    lease.Baseline.PublicNetworkAccess != selected.PublicNetworkAccess),
            "UpdatePrivateConnectionAsync" => lease.BaselineConnectionStatus == SecretStatus.Success &&
                lease.BaselineConnectionState != Enum.Parse<PrivateConnectionState>(variant.Split('.')[1]),
            "DeletePrivateConnectionAsync" => lease.BaselineConnectionStatus == SecretStatus.Success,
            "ChangeAccessPoliciesAsync" => lease.BaselineVaultStatus == SecretStatus.Success && policies.Length > 0 &&
                policies.All(p => change switch
                {
                    AccessPolicyChange.Add => lease.Baseline.Policies.All(q => !SamePolicyKey(p, q)),
                    AccessPolicyChange.Remove => lease.Baseline.Policies.Any(q => SamePolicyKey(p, q)),
                    _ => lease.Baseline.Policies.Any(q => SamePolicyKey(p, q) && !SamePolicies([p], [q]))
                }),
            _ => false
        };
        ManagementAdmission.Require(valid, NativeFailure.MissingPrerequisite);
    }

    private static bool SamePolicyKey(Policy a, Policy b) =>
        a.TenantId == b.TenantId && a.PrincipalId == b.PrincipalId && a.ApplicationId == b.ApplicationId;

    internal static void ValidateEffect(string operation, string variant, Configuration selected, Lease lease,
        Measurement m, Policy[] policies, AccessPolicyChange change, bool unchanged)
    {
        if (unchanged)
        {
            ManagementAdmission.Require(m.VaultStatus == lease.BaselineVaultStatus &&
                m.DeletedVaultStatus == lease.BaselineDeletedVaultStatus &&
                m.ConnectionStatus == lease.BaselineConnectionStatus &&
                (lease.BaselineVaultStatus == SecretStatus.Absent ? m.Configuration is null :
                    m.Configuration is { } c && SameConfiguration(c, lease.Baseline)) &&
                SamePolicies(m.Policies, lease.Baseline.Policies) &&
                m.ConnectionState == lease.BaselineConnectionState, NativeFailure.EffectMismatch);
            return;
        }
        switch (operation)
        {
            case "CreateOrUpdateVaultAsync":
            case "RecoverVaultAsync":
                ManagementAdmission.Require(m.VaultStatus == SecretStatus.Success && m.Configuration is { } c &&
                    SameConfiguration(c, selected), NativeFailure.EffectMismatch);
                break;
            case "DeleteVaultAsync":
                ManagementAdmission.Require(m.VaultStatus == SecretStatus.Absent && m.DeletedVaultStatus == SecretStatus.Success,
                    NativeFailure.EffectMismatch);
                break;
            case "PurgeDeletedVaultAsync":
                ManagementAdmission.Require(m.VaultStatus == SecretStatus.Absent && m.DeletedVaultStatus == SecretStatus.Absent,
                    NativeFailure.EffectMismatch);
                break;
            case "UpdateSettingsAsync":
                {
                    VaultSettingsPatch patch = Patch(variant);
                    Configuration expected = lease.Baseline with
                    {
                        Rbac = patch.EnableRbacAuthorization ?? lease.Baseline.Rbac,
                        PurgeProtection = patch.EnablePurgeProtection ?? lease.Baseline.PurgeProtection,
                        PublicNetworkAccess = patch.PublicNetworkAccess ?? lease.Baseline.PublicNetworkAccess
                    };
                    ManagementAdmission.Require(m.Configuration is { } updated && SameConfiguration(updated, expected), NativeFailure.EffectMismatch);
                    break;
                }
            case "ChangeAccessPoliciesAsync":
                Policy[] expectedPolicies = lease.Baseline.Policies.Where(p => policies.All(q =>
                    p.TenantId != q.TenantId || p.PrincipalId != q.PrincipalId || p.ApplicationId != q.ApplicationId))
                    .Concat(change == AccessPolicyChange.Remove ? [] : policies).ToArray();
                ManagementAdmission.Require(SamePolicies(m.Policies, expectedPolicies), NativeFailure.EffectMismatch);
                foreach (Policy policy in policies)
                {
                    bool present = m.Policies.Any(p => SamePolicies([p], [policy]));
                    ManagementAdmission.Require(present == (change != AccessPolicyChange.Remove), NativeFailure.EffectMismatch);
                    foreach (SecretPermission permission in Enum.GetValues<SecretPermission>())
                    {
                        PolicyEffect? witness = m.PolicyEffects.SingleOrDefault(e => e.PrincipalId == policy.PrincipalId &&
                            e.Permission == permission);
                        SecretStatus expected = change != AccessPolicyChange.Remove && policy.Permissions.Contains(permission)
                            ? SecretStatus.Success : SecretStatus.Denied;
                        ManagementAdmission.Require(witness is not null && witness.IntendedStatus == expected &&
                            witness.DeniedStatus == SecretStatus.Denied && !string.IsNullOrWhiteSpace(witness.NativeRequestId),
                            NativeFailure.EffectMismatch);
                    }
                }
                break;
            case "UpdatePrivateConnectionAsync":
            case "DeletePrivateConnectionAsync":
            case "GetPrivateConnectionAsync":
            case "ListPrivateConnectionsAsync":
            case "ListPrivateLinkResourcesAsync":
                PrivateNetworkEffect network = m.NetworkEffect ?? throw new NativeCaseFailureException("observer-unavailable");
                ManagementAdmission.Require(!string.IsNullOrWhiteSpace(network.NativeRequestId) &&
                    network.PrivateReadStatus == (m.ConnectionState == PrivateConnectionState.Approved &&
                        operation != "DeletePrivateConnectionAsync" ? SecretStatus.Success : SecretStatus.Denied),
                    NativeFailure.EffectMismatch);
                if (operation == "DeletePrivateConnectionAsync")
                    ManagementAdmission.Require(m.ConnectionStatus == SecretStatus.Absent, NativeFailure.EffectMismatch);
                if (operation == "UpdatePrivateConnectionAsync")
                    ManagementAdmission.Require(m.ConnectionState == Enum.Parse<PrivateConnectionState>(variant.Split('.')[1]),
                        NativeFailure.EffectMismatch);
                break;
            default:
                ManagementAdmission.Require(m.VaultStatus == SecretStatus.Success ||
                    m.DeletedVaultStatus == SecretStatus.Success, NativeFailure.EffectMismatch);
                break;
        }
    }
}
