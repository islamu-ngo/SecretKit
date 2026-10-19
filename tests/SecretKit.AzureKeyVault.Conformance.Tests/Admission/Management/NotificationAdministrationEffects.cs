using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal static class NotificationAdministrationEffects
{
    private const string Prefix = "a.management.VaultAdministration.";
    private const string Type = "SecretKit.AzureKeyVault.Management.";
    internal static readonly string[] ConfigurationVariants =
    [
        "event.SecretNewVersionCreated", "event.SecretNearExpiry", "event.SecretExpired", "events.multiple",
        "attributes.omitted", "attributes.empty", "attribute.Static.secret", "attribute.Static.nonsecret",
        "attribute.Dynamic", "lro.started", "lro.completed"
    ];
    internal static readonly ManagementMember[] Members =
    [
        Member("CreateOrUpdateNotificationAsync", Type + "NotificationConfiguration," + Type + "ManagementReceipt", ConfigurationVariants, true),
        Member("DeleteNotificationAsync", Type + "ManagementReceipt", ["input.scope"], true),
        Member("GetNotificationAsync", null, ["selector.exact", "response.destination.Unknown", "response.destination.WebHook", "response.destination.Other"]),
        Member("GetNotificationDeliveryAttributesAsync", Type + "CollectionLimits",
            ["selector.exact", "attribute.Static.secret", "attribute.Static.nonsecret", "attribute.Dynamic", "page.complete", "page.bounded"]),
        Member("GetNotificationFullUrlAsync", null, ["selector.exact"]),
        new(Prefix + "ListNotificationsAsync", Type + "VaultAdministration.ListNotificationsAsync(" + Type + "VaultScope," +
            Type + "CollectionLimits,System.Threading.CancellationToken)",
            ["collection.bounded", "response.destination.Unknown", "response.destination.WebHook", "response.destination.Other"], false),
        Member("UpdateNotificationAsync", Type + "NotificationConfiguration," + Type + "ManagementReceipt", ConfigurationVariants, true)
    ];
    private static ManagementMember Member(string name, string? arguments, string[] variants, bool mutation = false) =>
        new(Prefix + name, Type + "VaultAdministration." + name + "(" + Type + "NotificationScope" +
            (arguments is null ? "" : "," + arguments) + ",System.Threading.CancellationToken)", variants, mutation);

    internal sealed record Attribute([property: JsonRequired] string Name,
        [property: JsonRequired] NotificationAttributeKind Kind, [property: JsonRequired] string Value,
        [property: JsonRequired] bool IsSecret)
    {
        internal NotificationDeliveryAttribute Build() => new(Name, Kind, Value, IsSecret);
        public override string ToString() => "[NotificationAttributeInput]";
    }
    internal sealed record Configuration([property: JsonRequired] string EndpointUrl,
        [property: JsonRequired] VaultNotificationEvent[] Events, [property: JsonRequired] Attribute[]? Attributes)
    {
        internal NotificationConfiguration Build()
        {
            NotificationDeliveryAttribute[]? attributes = Attributes?.Select(a => a.Build()).ToArray();
            try { return new(EndpointUrl, Events, attributes); }
            finally { if (attributes is not null) foreach (var attribute in attributes) attribute.Dispose(); }
        }
        public override string ToString() => "[NotificationConfigurationInput]";
    }
    internal sealed record Input(ObserverEndpoint Observer, ManagementIdentities Arm, Guid SubscriptionId,
        string ResourceGroup, string Location, Guid TenantId, Configuration Configuration,
        Attribute StaticSecret, Attribute StaticNonsecret, Attribute Dynamic, int MaximumPages,
        int MaximumItems, TimeSpan Timeout, VaultNotificationEvent WrongEvent, string TriggerSecretValue)
    {
        public override string ToString() => "[NotificationInput]";
    }
    internal sealed record Prepare(FixtureSelector Selection, Guid SubscriptionId, string ResourceGroup,
        string Location, Guid TenantId, Configuration DesiredConfiguration)
    {
        public override string ToString() => "[NotificationPrepare]";
    }
    internal sealed record Lease(LeaseFacts Facts, string VaultName, string NotificationName,
        Configuration Baseline, NotificationDestinationKind BaselineDestination, string EventCorrelation,
        string WrongEventCorrelation, string RuntimeSecretName)
    {
        public override string ToString() => "[NotificationLease]";
    }
    internal sealed record Trigger(Guid LeaseId, Guid Nonce, Guid SubscriptionId,
        string SelectedCorrelation, string WrongCorrelation, VaultNotificationEvent[] SelectedEvents,
        VaultNotificationEvent WrongEvent, string RuntimeSecretName, string? SelectedVersion)
    {
        public override string ToString() => "[NotificationTrigger]";
    }
    internal sealed record TriggerReceipt(Guid LeaseId, Guid Nonce, Guid SubscriptionId,
        string[] NativeRequestIds)
    {
        public override string ToString() => "[NotificationTriggerReceipt]";
    }
    internal sealed record Header(string Name, string Value)
    {
        public override string ToString() => "[WebhookHeader]";
    }
    internal sealed record Delivery(string EventId, string Correlation, string SubscriptionName, string VaultResourceId,
        VaultNotificationEvent EventType, DateTimeOffset ReceivedAt, Header[] Headers)
    {
        public override string ToString() => "[WebhookDelivery]";
    }
    internal enum ExclusionKind { FilterNotMatched, SubscriptionRemoved }
    internal sealed record ExcludedDelivery(string EventId, string Correlation, string SubscriptionName,
        string VaultResourceId, VaultNotificationEvent EventType, string NativeTriggerRequestId,
        DateTimeOffset ObservedAt, ExclusionKind Kind)
    {
        public override string ToString() => "[ExcludedDelivery]";
    }
    internal sealed record SubscriptionState([property: JsonRequired] string Name,
        [property: JsonRequired] NotificationDestinationKind Destination,
        [property: JsonRequired] NativeProvisioningState ProvisioningState,
        [property: JsonRequired] SecretStatus Status, [property: JsonRequired] Configuration? Configuration)
    {
        public override string ToString() => "[NotificationState]";
    }
    internal sealed record Measurement(Guid LeaseId, Guid Nonce, Guid SubscriptionId, string ObserverIdentity,
        DateTimeOffset ObservedAt, DateTimeOffset FilterWindowClosedAt, SubscriptionState[] Subscriptions,
        Attribute[] DeliveryAttributes, Delivery[] Deliveries, string[] RejectedCorrelations,
        string[] NativeTriggerRequestIds, Header[] DynamicHeaderValues, ExcludedDelivery[] Exclusions)
    {
        public override string ToString() => "[NotificationMeasurement]";
    }
    internal sealed record Result(SecretStatus Status, ManagementOperation? Operation = null,
        NotificationObservation? Notification = null, ManagementInventory<NotificationObservation>? Notifications = null,
        ManagementInventory<NotificationDeliveryAttribute>? Attributes = null, NotificationFullUrl? FullUrl = null);

    public static void Register(NativeCaseRegistry registry, OwnedAzureEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected, Func<ObserverEndpoint, OwnedManagementObserver>? createObserver = null,
        HttpPipelineTransport? selectedTransport = null, HttpPipelineTransport? runtimeTransport = null,
        RuntimeInvocation? runtimeInvocation = null) =>
        ManagementAdmission.Register(registry, env, expected, Members,
            (d, p, t) => ExecuteAsync(env, d, p, t, createObserver, selectedTransport, runtimeTransport, runtimeInvocation));

    internal interface RuntimeInvocation
    {
        ValueTask<SecretOutcome<AzureSetSecretResult>> RunSetAsync(FixtureSelector selector,
            AzureKeyVaultClient client, AzureSetSecretRequest request, MutationReceipt receipt, CancellationToken cancellationToken);
    }

    private static async ValueTask ExecuteAsync(OwnedAzureEnvironment env, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token, Func<ObserverEndpoint, OwnedManagementObserver>? createObserver,
        HttpPipelineTransport? selectedTransport, HttpPipelineTransport? runtimeTransport, RuntimeInvocation? runtimeInvocation)
    {
        Input input = ManagementAdmission.Input<Input>(env, "NotificationAdministration");
        Configuration selected = Select(input, definition.Key.Variant);
        using (selected.Build()) { }
        using var service = createObserver is null ? new OwnedManagementObserver(input.Observer) : createObserver(input.Observer);
        FixtureSelector selector = FixtureSelector.For(definition);
        Result? result = null;
        LeaseFacts? known = null;
        try
        {
            Lease lease = await service.PostAsync<Prepare, Lease>("notification/prepare",
                new(selector, input.SubscriptionId, input.ResourceGroup, input.Location, input.TenantId, selected), token).ConfigureAwait(false);
            lease.Facts.Claim(selector);
            lease.Facts.Validate(selector, "2025-02-15");
            known = lease.Facts;
            var vault = new VaultScope(new(new(input.SubscriptionId), input.ResourceGroup), lease.VaultName);
            var scope = new NotificationScope(vault, lease.NotificationName);
            ManagementAdmission.Require(lease.EventCorrelation.Length > 0 && lease.WrongEventCorrelation.Length > 0 &&
                lease.EventCorrelation != lease.WrongEventCorrelation &&
                lease.Facts.OwnedResourceIds.Contains(vault.ExportResourceId(), StringComparer.OrdinalIgnoreCase));
            string operation = definition.Key.Operation[Prefix.Length..];
            ManagementMember member = Members.Single(m => m.Operation == definition.Key.Operation);
            using var clients = new ManagementClients(input.Arm, definition.Key.Case, token, hostTransport: selectedTransport);
            ManagementReceipt? receipt = member.Mutation ? clients.Selected.PrepareReceipt(scope, operation switch
            {
                "CreateOrUpdateNotificationAsync" => ManagementMutation.CreateOrUpdateNotification,
                "UpdateNotificationAsync" => ManagementMutation.UpdateNotification,
                "DeleteNotificationAsync" => ManagementMutation.DeleteNotification,
                _ => throw new NativeCaseFailureException("contract-mismatch")
            }) : null;
            ObservationSubscription subscription = await service.SubscribeAsync("notification", lease.Facts, token).ConfigureAwait(false);
            SubscriptionState? baseline = null;
            DateTimeOffset? baselineObservedAt = null;
            if (receipt is not null)
            {
                Measurement before = await service.PostAsync<ObserveLease, Measurement>("notification/observe",
                    new(lease.Facts.LeaseId, selector.Nonce, "baseline-before-dispatch", subscription.SubscriptionId),
                    token).ConfigureAwait(false);
                ValidateMeasurement(before, lease, subscription);
                baselineObservedAt = before.ObservedAt;
                ManagementAdmission.Require(before.Subscriptions.Count(s => s.Name.Equals(scope.SubscriptionName,
                    StringComparison.OrdinalIgnoreCase)) == 1, NativeFailure.ObserverUnavailable);
                baseline = before.Subscriptions.Single(s => s.Name.Equals(scope.SubscriptionName, StringComparison.OrdinalIgnoreCase));
                RequireMutationBaseline(operation, selected, baseline);
                if (baseline.Configuration is { } configuration)
                    lease = lease with { Baseline = configuration, BaselineDestination = baseline.Destination };
            }
            Task boundary = clients.Boundary.ResponseReceived;
            bool canceled = false;
            try
            {
                result = await InvokeAsync(clients.Selected, operation, scope, selected, receipt,
                    new(input.MaximumPages, definition.Key.Variant == "page.bounded" ? 1 : input.MaximumItems,
                        input.Timeout), clients.Cancellation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (clients.Cancellation.IsCancellationRequested && !token.IsCancellationRequested)
            {
                canceled = true;
            }
            bool unchanged = definition.Key.Case == "denied-authority";
            Configuration effectConfiguration = member.Mutation && !unchanged && operation != "DeleteNotificationAsync"
                ? selected : lease.Baseline;
            ManagementAdmission.Require(!effectConfiguration.Events.Contains(input.WrongEvent));
            string? selectedVersion = null;
            if (effectConfiguration.Events.Contains(VaultNotificationEvent.SecretNewVersionCreated))
            {
                ManagementAdmission.Require(!string.IsNullOrEmpty(input.TriggerSecretValue));
                var uri = new Uri("https://" + lease.VaultName + ".vault.azure.net");
                var runtime = new AzureKeyVaultClient(uri, env.Credential(NativeIdentityRole.Runtime), runtimeTransport);
                var reference = new SecretReference(runtime.Authority, new AzureSecretAddress(lease.RuntimeSecretName));
                using var material = SecretMaterial.FromText(input.TriggerSecretValue);
                var triggerReceipt = new MutationReceipt(reference);
                var request = new AzureSetSecretRequest(reference, material);
                var native = runtimeInvocation is null
                    ? await runtime.SetSecretAsync(request, triggerReceipt, token).ConfigureAwait(false)
                    : await runtimeInvocation.RunSetAsync(selector, runtime, request, triggerReceipt, token).ConfigureAwait(false);
                AzureSetSecretResult set = ManagementAdmission.Value(native);
                ManagementAdmission.Require(triggerReceipt.Evidence == DispatchEvidence.Applied, NativeFailure.EffectMismatch);
                selectedVersion = ((AzureSecretAddress)set.Reference.Address).Version;
                byte[] bytes = Encoding.UTF8.GetBytes(input.TriggerSecretValue);
                string digest;
                try { digest = Convert.ToHexString(SHA256.HashData(bytes)); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
                await RoleAdministrationEffects.CheckReadAsync(new(uri, env.Credential(NativeIdentityRole.Observer)),
                    lease.RuntimeSecretName, digest, SecretStatus.Success, token).ConfigureAwait(false);
                await RoleAdministrationEffects.CheckReadAsync(new(uri, env.Credential(NativeIdentityRole.Denied)),
                    lease.RuntimeSecretName, digest, SecretStatus.Denied, token).ConfigureAwait(false);
                ManagementAdmission.Confirm(env, definition, "selected-runtime-identity");
            }
            TriggerReceipt triggered = await service.PostAsync<Trigger, TriggerReceipt>("notification/trigger",
                new(lease.Facts.LeaseId, selector.Nonce, subscription.SubscriptionId,
                    lease.EventCorrelation, lease.WrongEventCorrelation, effectConfiguration.Events,
                    input.WrongEvent, lease.RuntimeSecretName, selectedVersion), token).ConfigureAwait(false);
            ManagementAdmission.Require(triggered.LeaseId == lease.Facts.LeaseId && triggered.Nonce == selector.Nonce &&
                triggered.SubscriptionId == subscription.SubscriptionId && triggered.NativeRequestIds.Length >= 2 &&
                triggered.NativeRequestIds.All(s => !string.IsNullOrWhiteSpace(s)), NativeFailure.ObserverUnavailable);
            Measurement measured = await service.PostAsync<ObserveLease, Measurement>("notification/observe",
                new(lease.Facts.LeaseId, selector.Nonce, "delivery-and-filter-window", subscription.SubscriptionId), token).ConfigureAwait(false);
            ValidateMeasurement(measured, lease, subscription);
            ManagementAdmission.Require(baselineObservedAt is null || measured.ObservedAt >= baselineObservedAt,
                NativeFailure.ObserverUnavailable);
            ManagementAdmission.Require(measured.FilterWindowClosedAt >= subscription.ArmedAt &&
                triggered.NativeRequestIds.All(id => measured.NativeTriggerRequestIds.Contains(id, StringComparer.Ordinal)),
                NativeFailure.ObserverUnavailable);
            SubscriptionState state = measured.Subscriptions.SingleOrDefault(s => s.Name == scope.SubscriptionName)
                ?? throw new NativeCaseFailureException("observer-unavailable");
            if (definition.Key.Case == "cancellation-boundary")
                ManagementAdmission.Require(canceled && boundary.IsCompletedSuccessfully, NativeFailure.ContractMismatch);
            else if (definition.Key.Case == "lost-response-no-replay")
                ManagementAdmission.Require(result?.Status == SecretStatus.Unknown && boundary.IsCompletedSuccessfully, NativeFailure.ContractMismatch);
            else if (unchanged)
                ManagementAdmission.Require(result?.Status == SecretStatus.Denied, NativeFailure.ContractMismatch);
            else
            {
                ManagementAdmission.Require(result?.Status == SecretStatus.Success, NativeFailure.ContractMismatch);
                if (result!.Operation is { } handle)
                {
                    if (definition.Key.Variant == "lro.started")
                        ManagementAdmission.Require(handle.State == NativeProvisioningState.Pending, NativeFailure.ContractMismatch);
                    if (definition.Key.Variant == "lro.completed")
                        ManagementAdmission.Require(await handle.CheckStatusAsync(token).ConfigureAwait(false) == SecretStatus.Success,
                            NativeFailure.ContractMismatch);
                }
                MatchResult(result, state, measured, definition.Key.Variant, input.MaximumItems);
            }
            if (receipt is not null) ManagementAdmission.Receipt(receipt, definition.Key.Case);
            bool deleted = operation == "DeleteNotificationAsync" && !unchanged;
            bool absent = deleted || unchanged && baseline?.Status == SecretStatus.Absent;
            if (unchanged)
                ManagementAdmission.Require(baseline is not null && state.Status == baseline.Status &&
                    state.Destination == baseline.Destination && state.ProvisioningState == baseline.ProvisioningState &&
                    (baseline.Configuration is null ? state.Configuration is null :
                        state.Configuration is { } c && SameConfiguration(c, baseline.Configuration)), NativeFailure.EffectMismatch);
            ManagementAdmission.Require(state.Status == (absent ? SecretStatus.Absent : SecretStatus.Success),
                NativeFailure.EffectMismatch);
            if (!absent && state.Destination == NotificationDestinationKind.WebHook)
                ManagementAdmission.Require(state.Configuration is { } observed && SameConfiguration(observed, effectConfiguration),
                    NativeFailure.EffectMismatch);
            else if (!absent)
                // The SDK deliberately withholds non-webhook destination settings.
                // Do not fabricate a webhook configuration projection for those rows.
                ManagementAdmission.Require(!member.Mutation && state.Configuration is null, NativeFailure.ContractMismatch);
            if (definition.Key.Variant.StartsWith("response.destination.", StringComparison.Ordinal) && !unchanged)
                ManagementAdmission.Require(state.Destination == Enum.Parse<NotificationDestinationKind>(
                    definition.Key.Variant["response.destination.".Length..]), NativeFailure.ContractMismatch);
            ValidateDeliveries(measured, lease, vault, effectConfiguration, absent);
            probe.Contract(true, NativeFailure.ContractMismatch);
            probe.Effect(NativeObservation.Matched);
            ManagementAdmission.ConfirmInfrastructure(env, definition, lease.Facts);
            if (result?.Status == SecretStatus.Success && !unchanged)
                ManagementAdmission.Confirm(env, definition, "selected-administrative-identity",
                    "scoped-administrative-rights", "azure-arm-public-cloud-rights", "event-grid-registration-rights");
            if (!deleted && measured.Deliveries.Length > 0)
                ManagementAdmission.Confirm(env, definition, "owned-https-webhook-observer", "event-grid-delivery-authority");
        }
        finally
        {
            result?.FullUrl?.Dispose();
            if (result?.Attributes is { } attributes) foreach (var attribute in attributes.Items) attribute.Dispose();
            await NotificationFixtureRelease.ReleaseAsync(service, selector, known, probe, env, definition).ConfigureAwait(false);
        }
    }

    internal static Configuration Select(Input input, string variant) => variant switch
    {
        "event.SecretNewVersionCreated" => input.Configuration with { Events = [VaultNotificationEvent.SecretNewVersionCreated] },
        "event.SecretNearExpiry" => input.Configuration with { Events = [VaultNotificationEvent.SecretNearExpiry] },
        "event.SecretExpired" => input.Configuration with { Events = [VaultNotificationEvent.SecretExpired] },
        "events.multiple" => input.Configuration with { Events = [VaultNotificationEvent.SecretNewVersionCreated, VaultNotificationEvent.SecretNearExpiry] },
        "attributes.omitted" => input.Configuration with { Attributes = null },
        "attributes.empty" => input.Configuration with { Attributes = [] },
        "attribute.Static.secret" => input.Configuration with
        { Attributes = [input.StaticSecret with { Kind = NotificationAttributeKind.Static, IsSecret = true }] },
        "attribute.Static.nonsecret" => input.Configuration with
        { Attributes = [input.StaticNonsecret with { Kind = NotificationAttributeKind.Static, IsSecret = false }] },
        "attribute.Dynamic" => input.Configuration with
        { Attributes = [input.Dynamic with { Kind = NotificationAttributeKind.Dynamic, IsSecret = false }] },
        "page.complete" => input.Configuration with
        { Attributes = [input.StaticNonsecret with { Kind = NotificationAttributeKind.Static, IsSecret = false }] },
        "page.bounded" => input.Configuration with
        {
            Attributes = [input.StaticSecret with { Kind = NotificationAttributeKind.Static, IsSecret = true },
                input.StaticNonsecret with { Kind = NotificationAttributeKind.Static, IsSecret = false },
                input.Dynamic with { Kind = NotificationAttributeKind.Dynamic, IsSecret = false }]
        },
        _ => input.Configuration
    };

    private static async ValueTask<Result> InvokeAsync(VaultAdministration client, string operation, NotificationScope scope,
        Configuration configuration, ManagementReceipt? receipt, CollectionLimits limits, CancellationToken token)
    {
        switch (operation)
        {
            case "CreateOrUpdateNotificationAsync":
            case "UpdateNotificationAsync":
                {
                    using var native = configuration.Build();
                    var outcome = operation == "CreateOrUpdateNotificationAsync"
                        ? await client.CreateOrUpdateNotificationAsync(scope, native, receipt!, token).ConfigureAwait(false)
                        : await client.UpdateNotificationAsync(scope, native, receipt!, token).ConfigureAwait(false);
                    return new(outcome.Status, outcome.IsSuccess ? outcome.Value : null);
                }
            case "DeleteNotificationAsync":
                {
                    var outcome = await client.DeleteNotificationAsync(scope, receipt!, token).ConfigureAwait(false);
                    return new(outcome.Status, outcome.IsSuccess ? outcome.Value : null);
                }
            case "GetNotificationAsync":
                {
                    var outcome = await client.GetNotificationAsync(scope, token).ConfigureAwait(false);
                    return new(outcome.Status, Notification: outcome.IsSuccess ? outcome.Value : null);
                }
            case "GetNotificationFullUrlAsync":
                {
                    var outcome = await client.GetNotificationFullUrlAsync(scope, token).ConfigureAwait(false);
                    return new(outcome.Status, FullUrl: outcome.IsSuccess ? outcome.Value : null);
                }
            case "GetNotificationDeliveryAttributesAsync":
                {
                    var outcome = await client.GetNotificationDeliveryAttributesAsync(scope, limits, token).ConfigureAwait(false);
                    return new(outcome.Status, Attributes: outcome);
                }
            case "ListNotificationsAsync":
                {
                    var outcome = await client.ListNotificationsAsync(scope.Vault, limits, token).ConfigureAwait(false);
                    return new(outcome.Status, Notifications: outcome);
                }
            default: throw new NativeCaseFailureException("contract-mismatch");
        }
    }

    internal static bool SameAttributes(Attribute[]? a, Attribute[]? b) =>
        (a ?? []).Length == (b ?? []).Length &&
        (a ?? []).Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == (a ?? []).Length &&
        (b ?? []).Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == (b ?? []).Length &&
        (a ?? []).All(p => (b ?? []).Any(q =>
            p.Name.Equals(q.Name, StringComparison.OrdinalIgnoreCase) && p.Kind == q.Kind &&
            p.Value == q.Value && p.IsSecret == q.IsSecret));
    internal static bool SameConfiguration(Configuration a, Configuration b) =>
        a.EndpointUrl == b.EndpointUrl && a.Events.Order().SequenceEqual(b.Events.Order()) && SameAttributes(a.Attributes, b.Attributes);

    private static void ValidateMeasurement(Measurement measured, Lease lease, ObservationSubscription subscription) =>
        ManagementAdmission.Require(measured.LeaseId == lease.Facts.LeaseId && measured.Nonce == lease.Facts.Nonce &&
            measured.SubscriptionId == subscription.SubscriptionId && measured.ObserverIdentity == lease.Facts.ObserverIdentity &&
            measured.ObservedAt >= subscription.ArmedAt, NativeFailure.ObserverUnavailable);

    internal static void RequireMutationBaseline(string operation, Configuration selected, SubscriptionState baseline) =>
        ManagementAdmission.Require(operation switch
        {
            "CreateOrUpdateNotificationAsync" => baseline.Status == SecretStatus.Absent ||
                baseline.Status == SecretStatus.Success && baseline.Configuration is { } existing &&
                !SameConfiguration(existing, selected),
            "UpdateNotificationAsync" => baseline.Status == SecretStatus.Success && baseline.Configuration is { } existing &&
                !SameConfiguration(existing, selected),
            "DeleteNotificationAsync" => baseline.Status == SecretStatus.Success,
            _ => false
        }, NativeFailure.MissingPrerequisite);

    internal static void MatchResult(Result result, SubscriptionState state, Measurement measured, string variant, int maximum)
    {
        if (result.Notification is { } notification)
            ManagementAdmission.Require(notification.Destination == state.Destination &&
                notification.ProvisioningState == state.ProvisioningState, NativeFailure.ContractMismatch);
        if (result.FullUrl is { } full)
            ManagementAdmission.Require(full.Endpoint.Reveal() == state.Configuration?.EndpointUrl, NativeFailure.ContractMismatch);
        if (result.Notifications is { } notifications)
        {
            VaultAdministrationEffects.MatchCollection(notifications.Items.Select(n => n.Scope.SubscriptionName).ToArray(),
                measured.Subscriptions.Where(s => s.Status == SecretStatus.Success).Select(s => s.Name).ToArray(),
                maximum, notifications.Complete);
            foreach (var listed in notifications.Items)
            {
                var observed = measured.Subscriptions.Single(s => s.Name.Equals(listed.Scope.SubscriptionName,
                    StringComparison.OrdinalIgnoreCase));
                ManagementAdmission.Require(listed.Destination == observed.Destination &&
                    listed.ProvisioningState == observed.ProvisioningState, NativeFailure.ContractMismatch);
            }
        }
        if (result.Attributes is { } attributes)
        {
            Attribute[] actual = attributes.Items.Select(a => new Attribute(a.Name, a.Kind, a.Value.Reveal(), a.IsSecret)).ToArray();
            ManagementAdmission.Require(actual.Length > 0 && actual.Length <= maximum && actual.All(a =>
                measured.DeliveryAttributes.Any(b => SameAttributes([a], [b]))) &&
                actual.Select(a => a.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == actual.Length &&
                measured.DeliveryAttributes.Select(a => a.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() ==
                    measured.DeliveryAttributes.Length &&
                (!attributes.Complete || actual.Length == measured.DeliveryAttributes.Length), NativeFailure.ContractMismatch);
            if (variant == "page.complete") ManagementAdmission.Require(attributes.Complete, NativeFailure.ContractMismatch);
            if (variant == "page.bounded") ManagementAdmission.Require(!attributes.Complete, NativeFailure.ContractMismatch);
        }
    }

    internal static void ValidateDeliveries(Measurement measured, Lease lease, VaultScope vault,
        Configuration configuration, bool deleted)
    {
        Delivery[] deliveries = measured.Deliveries.Where(d => d.Correlation == lease.EventCorrelation).ToArray();
        ManagementAdmission.Require(measured.RejectedCorrelations.Contains(lease.WrongEventCorrelation, StringComparer.Ordinal) &&
            !measured.Deliveries.Any(d => d.Correlation == lease.WrongEventCorrelation) &&
            measured.Exclusions.Any(e => ValidExclusion(e, measured, lease, vault) &&
                e.Correlation == lease.WrongEventCorrelation && e.Kind == ExclusionKind.FilterNotMatched &&
                !configuration.Events.Contains(e.EventType)), NativeFailure.EffectMismatch);
        if (deleted)
        {
            ManagementAdmission.Require(deliveries.Length == 0 &&
                measured.RejectedCorrelations.Contains(lease.EventCorrelation, StringComparer.Ordinal) &&
                measured.Exclusions.Any(e => ValidExclusion(e, measured, lease, vault) &&
                    e.Correlation == lease.EventCorrelation && e.Kind == ExclusionKind.SubscriptionRemoved),
                    NativeFailure.EffectMismatch);
            return;
        }
        foreach (VaultNotificationEvent expected in configuration.Events)
        {
            Delivery delivery = deliveries.FirstOrDefault(d => d.EventType == expected &&
                d.SubscriptionName == lease.NotificationName &&
                d.VaultResourceId.Equals(vault.ExportResourceId(), StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(d.EventId) && d.ReceivedAt >= lease.Facts.PreparedAt)
                ?? throw new NativeCaseFailureException("effect-mismatch");
            foreach (Attribute attribute in configuration.Attributes ?? [])
            {
                string expectedValue = attribute.Kind == NotificationAttributeKind.Static ? attribute.Value :
                    measured.DynamicHeaderValues.SingleOrDefault(h => h.Name == attribute.Name)?.Value
                        ?? throw new NativeCaseFailureException("observer-unavailable");
                ManagementAdmission.Require(delivery.Headers.Any(h => h.Name.Equals(attribute.Name, StringComparison.OrdinalIgnoreCase) &&
                    h.Value == expectedValue), NativeFailure.EffectMismatch);
            }
        }
    }

    private static bool ValidExclusion(ExcludedDelivery e, Measurement measured, Lease lease, VaultScope vault) =>
        !string.IsNullOrWhiteSpace(e.EventId) && e.SubscriptionName == lease.NotificationName &&
        e.VaultResourceId.Equals(vault.ExportResourceId(), StringComparison.OrdinalIgnoreCase) &&
        e.ObservedAt >= lease.Facts.PreparedAt &&
        measured.NativeTriggerRequestIds.Contains(e.NativeTriggerRequestId, StringComparer.Ordinal);
}
