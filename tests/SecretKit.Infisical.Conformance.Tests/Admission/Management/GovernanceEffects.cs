using System.Globalization;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal interface IAuditEventObserver
{
    ValueTask<OwnedAuditScope> ProvisionAsync(string ownedName, bool projectScope,
        IInfisicalTokenSource setup, IInfisicalTokenSource administrative, IInfisicalTokenSource observer,
        CancellationToken token);
    // Subscribe to the actual producer event before triggering under runtime authority.
    ValueTask<TriggeredAuditEvent> TriggerAsync(OwnedAuditScope scope, AuditEventClass eventClass,
        string correlation, IInfisicalTokenSource runtime, CancellationToken token);
    ValueTask<AuditEventFacts> ObserveAsync(OwnedAuditScope scope, TriggeredAuditEvent triggered,
        IInfisicalTokenSource observer, CancellationToken token);
    ValueTask<AuditCleanupFacts> RemoveOwnedAsync(string ownedName, IInfisicalTokenSource setup, CancellationToken token);
}

internal sealed record OwnedAuditScope([property: JsonIgnore] string OrganizationId,
    [property: JsonIgnore] string? ProjectId, [property: JsonIgnore] string OwnedName)
{
    public override string ToString() => "[OwnedAuditScope]";
}

internal sealed record TriggeredAuditEvent([property: JsonIgnore] string Id, [property: JsonIgnore] string Correlation,
    [property: JsonIgnore] string OrganizationId, [property: JsonIgnore] string? ProjectId,
    AuditEventClass EventClass, [property: JsonIgnore] string EventType, DateTimeOffset From, DateTimeOffset Until,
    [property: JsonIgnore] string Actor, [property: JsonIgnore] string ActorType, [property: JsonIgnore] string Environment,
    [property: JsonIgnore] string SecretKey, [property: JsonIgnore] string SecretPath,
    [property: JsonIgnore] string EventMetadata, [property: JsonIgnore] string UserAgentType)
{
    public override string ToString() => "[TriggeredAuditEvent]";
}

internal sealed record AuditEventFacts([property: JsonIgnore] string Correlation, int ProducedEvents,
    [property: JsonIgnore] IReadOnlyList<string> PersistedEventIds,
    IReadOnlyList<AuditEventClass> EnabledClasses)
{
    public override string ToString() => "[AuditEventFacts]";
}

internal sealed record AuditCleanupFacts([property: JsonIgnore] string OwnedName, int RemainingOrganizations, int RemainingProjects)
{
    public override string ToString() => "[AuditCleanupFacts]";
}

internal interface IShareRecipientObserver
{
    ValueTask<SecretOutcome<SharedSecretMetadata>> FindOwnedAsync(string organizationId, string name,
        IInfisicalTokenSource observer, CancellationToken token);
    ValueTask<ShareAccessFacts> ObserveViewsAsync(string shareId, IInfisicalTokenSource observer, CancellationToken token);
    // Access once with the actual recipient, then test a denied recipient and the exact expiry boundary.
    // Expiry uses a subscribed provider clock/state event, not a sleep or poll.
    ValueTask<ShareDeliveryFacts> DeliverAsync(string organizationId, string shareId, SecretMaterial? password,
        IInfisicalTokenSource runtime, IInfisicalTokenSource denied, CancellationToken token);
}

internal sealed record ShareAccessFacts([property: JsonIgnore] string ShareId, int ConsumedViews)
{
    public override string ToString() => "[ShareAccessFacts]";
}

internal sealed record ShareViewLimitFacts(
    [property: JsonRequired] int MaximumViews,
    [property: JsonRequired] int ViewsBeforeExhaustedAccess,
    [property: JsonRequired] int ViewsAfterExhaustedAccess,
    [property: JsonRequired] DateTimeOffset ExhaustedObservationTime,
    [property: JsonRequired] SecretStatus ExhaustedStatus,
    [property: JsonRequired] bool MaterialReturned);

internal sealed class ShareDeliveryFacts(string shareId, SecretStatus recipientStatus, SecretStatus deniedStatus,
    int viewsBefore, int viewsAfter, DateTimeOffset expiresAt, DateTimeOffset expiredObservationTime,
    SecretStatus expiredStatus, SecretMaterial? material, ShareAudience audience, int? maximumViews,
    bool? allowExternalEmails, IReadOnlyList<string>? authorizedEmails, ShareViewLimitFacts? viewLimit = null) : IDisposable
{
    [JsonIgnore] public string ShareId { get; } = shareId;
    public SecretStatus RecipientStatus { get; } = recipientStatus;
    public SecretStatus DeniedStatus { get; } = deniedStatus;
    public int ViewsBefore { get; } = viewsBefore;
    public int ViewsAfter { get; } = viewsAfter;
    public DateTimeOffset ExpiresAt { get; } = expiresAt;
    public DateTimeOffset ExpiredObservationTime { get; } = expiredObservationTime;
    public SecretStatus ExpiredStatus { get; } = expiredStatus;
    [JsonIgnore] public SecretMaterial? Material { get; } = material;
    public ShareAudience Audience { get; } = audience;
    public int? MaximumViews { get; } = maximumViews;
    public bool? AllowExternalEmails { get; } = allowExternalEmails;
    [JsonIgnore] public IReadOnlyList<string>? AuthorizedEmails { get; } = authorizedEmails;
    public ShareViewLimitFacts? ViewLimit { get; } = viewLimit;
    public void Dispose() => Material?.Dispose();
    public override string ToString() => "[ShareDeliveryFacts]";
}

internal static class GovernanceEffects
{
    internal static string? UnavailableReason(NativeCaseDefinition d) =>
        d.Key.Variant == "rows.partial-invalid" ? "owned-invalid-audit-row-contract" : null;

    internal static ValueTask ExecuteAsync(ProjectFamilyContext c, GovernanceObservers observers, CancellationToken token) =>
        c.Definition.Key.Operation.Split('.')[2] == "SharingOperations" ?
            SharingAsync(c, observers.Share ?? InfisicalShareObserver.FromInputs(c.Environment) ??
                throw new NativeCaseFailureException("missing-input"), token) :
            AuditAsync(c, observers.Audit ?? InfisicalAuditObserver.FromInputs(c.Environment) ??
                throw new NativeCaseFailureException("missing-input"), token);

    private static async ValueTask AuditAsync(ProjectFamilyContext c, IAuditEventObserver observer, CancellationToken token)
    {
        bool setting = c.Operation.StartsWith("Set", StringComparison.Ordinal);
        bool project = c.Operation.Contains("Project", StringComparison.Ordinal) ||
            c.Operation == "ReadAudit" && c.Variant is not ("projectId.omitted" or "selector.organization");
        AuditEventClass eventClass = c.Variant switch
        {
            "eventClass.Management" => AuditEventClass.Management,
            "eventClass.Authentication" => AuditEventClass.Authentication,
            "eventClass.Authorization" => AuditEventClass.Authorization,
            "eventClass.DataAccess" => AuditEventClass.DataAccess,
            _ => setting ? AuditEventClass.Authentication : AuditEventClass.Management
        };
        if (setting && eventClass is AuditEventClass.Management or AuditEventClass.DataAccess)
        {
            bool rejected = false;
            try
            {
                AuditClassSetting[] invalid = [new(eventClass, true), new(AuditEventClass.Authorization, false)];
                using var request = project ?
                    GovernanceOperations.SetProjectAuditSettings(c.OrganizationId, Guid.NewGuid().ToString("D"), invalid) :
                    GovernanceOperations.SetOrganizationAuditSettings(c.OrganizationId, invalid);
            }
            catch (ArgumentException error) when (error.ParamName == "settings") { rejected = true; }
            c.Probe.Contract(rejected, NativeFailure.ContractMismatch);
            // This variant is a local input rejection, not an observed native policy effect.
            c.Probe.Effect(NativeObservation.Matched);
            return;
        }
        string name = ProjectFamilyContext.FreshName();
        c.Cleanup(async ct =>
        {
            AuditCleanupFacts facts = await observer.RemoveOwnedAsync(name, c.Environment.Tokens(NativeIdentityRole.Setup), ct);
            return facts.OwnedName == name && facts.RemainingOrganizations == 0 && facts.RemainingProjects == 0;
        });
        OwnedAuditScope scope = await observer.ProvisionAsync(name, project,
            c.Environment.Tokens(NativeIdentityRole.Setup), c.Environment.Tokens(NativeIdentityRole.Administrative),
            c.Environment.Tokens(NativeIdentityRole.Observer), token);
        c.Probe.Contract(scope.OwnedName == name && !string.IsNullOrWhiteSpace(scope.OrganizationId) &&
            project == (scope.ProjectId is not null), NativeFailure.MissingPrerequisite);
        bool permanent = eventClass is AuditEventClass.Management or AuditEventClass.DataAccess;
        bool enabled = c.Variant != "isEnabled.false";
        Func<ManagementRequest<AuditSettings>> get = () => scope.ProjectId is null ?
            GovernanceOperations.GetOrganizationAuditSettings(scope.OrganizationId) :
            GovernanceOperations.GetProjectAuditSettings(scope.OrganizationId, scope.ProjectId);
        Func<bool, ManagementRequest<AuditSettings>> set = state => scope.ProjectId is null ?
            GovernanceOperations.SetOrganizationAuditSettings(scope.OrganizationId,
                [new(AuditEventClass.Authentication, eventClass == AuditEventClass.Authentication && state),
                    new(AuditEventClass.Authorization, eventClass == AuditEventClass.Authorization && state)]) :
            GovernanceOperations.SetProjectAuditSettings(scope.OrganizationId, scope.ProjectId,
                [new(AuditEventClass.Authentication, eventClass == AuditEventClass.Authentication && state),
                    new(AuditEventClass.Authorization, eventClass == AuditEventClass.Authorization && state)]);
        // Force an opposite baseline for writes so no-effect denial/cancellation is observable.
        if (!permanent)
            await c.NeedAsync(() => set(setting ? !enabled : true), NativeIdentityRole.Setup, token);
        bool Match(AuditSettings value, bool expected) =>
            value.Classes.Count(s => s.EventClass == eventClass && s.IsEnabled == expected) == 1;
        async ValueTask<bool> Observe(bool applied, CancellationToken ct)
        {
            bool expected = setting ? applied ? enabled : !enabled : true;
            AuditSettings settings = await c.NeedAsync(get, NativeIdentityRole.Observer, ct);
            if (!Match(settings, expected)) return false;
            TriggeredAuditEvent triggered = await observer.TriggerAsync(scope, eventClass,
                ProjectFamilyContext.FreshName(), c.Environment.Tokens(NativeIdentityRole.Runtime), ct);
            if (!TriggerMatches(scope, triggered, eventClass)) return false;
            AuditEventFacts facts = await observer.ObserveAsync(scope, triggered,
                c.Environment.Tokens(NativeIdentityRole.Observer), ct);
            return facts.Correlation == triggered.Correlation && facts.ProducedEvents == 1 &&
                facts.EnabledClasses.Contains(eventClass) == expected &&
                facts.PersistedEventIds.Count(id => id == triggered.Id) == (expected ? 1 : 0);
        }
        if (c.Operation != "ReadAudit")
        {
            await c.CaseAsync(setting ? () => set(enabled) : get, value => Match(value, setting ? enabled : true), Observe, token);
            return;
        }
        TriggeredAuditEvent selected = await observer.TriggerAsync(scope, eventClass, ProjectFamilyContext.FreshName(),
            c.Environment.Tokens(NativeIdentityRole.Runtime), token);
        c.Probe.Contract(TriggerMatches(scope, selected, eventClass), NativeFailure.MissingPrerequisite);
        AuditSelectors? selectors = Selectors(c.Variant, selected);
        var excluded = selected with
        {
            Actor = Guid.NewGuid().ToString(),
            ActorType = selected.ActorType == "user" ? "identity" : "user",
            Environment = ProjectFamilyContext.FreshName(),
            SecretKey = ProjectFamilyContext.FreshName(),
            SecretPath = "/" + ProjectFamilyContext.FreshName(),
            EventMetadata = ProjectFamilyContext.FreshName(),
            UserAgentType = selected.UserAgentType == "cli" ? "web" : "cli",
            EventClass = selected.EventClass == AuditEventClass.Management ? AuditEventClass.Authentication : AuditEventClass.Management,
            EventType = selected.EventType == "get-secret" ? "create-secret" : "get-secret"
        };
        AuditSelectors? negativeSelectors = Selectors(c.Variant, excluded);
        bool hasNegativeSelector = negativeSelectors is not null &&
            (negativeSelectors.Actor is not null || negativeSelectors.ActorType is not null ||
                negativeSelectors.Environment is not null || negativeSelectors.EventClass is not null ||
                negativeSelectors.EventMetadata is not null || negativeSelectors.EventType is not null ||
                negativeSelectors.SecretKey is not null || negativeSelectors.SecretPath is not null ||
                negativeSelectors.UserAgentType is not null) &&
            c.Variant is not ("eventClass.array.empty" or "eventType.array.empty");
        bool MatchPage(ManagementPage<AuditRow> page) => page.IsComplete &&
            page.Items.Select((row, index) => row.Ordinal == index).All(equal => equal) &&
            page.Items.All(row => row.Outcome.IsSuccess) &&
            page.Items.Count(row => row.Outcome.Value.Id == selected.Id &&
                row.Outcome.Value.EventClass == eventClass && row.Outcome.Value.EventType == selected.EventType &&
                row.Outcome.Value.ProjectId == scope.ProjectId) == 1;
        await c.CaseAsync(() => GovernanceOperations.ReadAudit(scope.OrganizationId, selected.From, selected.Until,
            scope.ProjectId, selectors: selectors), MatchPage, async (applied, ct) =>
            {
                foreach (var role in applied ? new[] { NativeIdentityRole.Administrative, NativeIdentityRole.Observer } :
                    new[] { NativeIdentityRole.Observer })
                {
                    if (hasNegativeSelector)
                    {
                        var filtered = await c.ExecuteAsync(() => GovernanceOperations.ReadAudit(scope.OrganizationId,
                            selected.From, selected.Until, scope.ProjectId, selectors: negativeSelectors), role, ct);
                        if (!filtered.IsSuccess || !filtered.Value.IsComplete ||
                            filtered.Value.Items.Any(r => !r.Outcome.IsSuccess || r.Outcome.Value.Id == selected.Id))
                            return false;
                    }
                    var outsideWindow = await c.ExecuteAsync(() => GovernanceOperations.ReadAudit(scope.OrganizationId,
                        selected.Until, selected.Until.AddMinutes(1), scope.ProjectId, selectors: selectors), role, ct);
                    if (!outsideWindow.IsSuccess || !outsideWindow.Value.IsComplete ||
                        outsideWindow.Value.Items.Any(r => !r.Outcome.IsSuccess || r.Outcome.Value.Id == selected.Id))
                        return false;
                }
                AuditEventFacts facts = await observer.ObserveAsync(scope, selected,
                    c.Environment.Tokens(NativeIdentityRole.Observer), ct);
                return facts.Correlation == selected.Correlation && facts.ProducedEvents == 1 &&
                    facts.PersistedEventIds.Count(id => id == selected.Id) == 1 &&
                    facts.EnabledClasses.Contains(eventClass);
            }, token);
    }

    private static bool TriggerMatches(OwnedAuditScope scope, TriggeredAuditEvent triggered, AuditEventClass eventClass) =>
        triggered.OrganizationId == scope.OrganizationId && triggered.ProjectId == scope.ProjectId &&
        triggered.EventClass == eventClass && !string.IsNullOrWhiteSpace(triggered.Id) &&
        !string.IsNullOrWhiteSpace(triggered.Correlation) && IsCatalogType(triggered.EventType) &&
        triggered.Until > triggered.From;

    private static bool IsCatalogType(string eventType)
    {
        try { _ = AuditEventFilter.Types([eventType]); return true; }
        catch (ArgumentException) { return false; }
    }

    private static AuditSelectors? Selectors(string v, TriggeredAuditEvent e) => v == "selectors.omitted" ? null :
        new(actor: v == "actor.value" ? e.Actor : null, actorType: v == "actorType.selected" ? e.ActorType : null,
            environment: v == "environment.value" ? e.Environment : null,
            eventClass: v == "eventClass.array.empty" ? AuditEventFilter.Classes([]) :
                v == "eventClass.array.values" ? AuditEventFilter.Classes([e.EventClass]) :
                v == "eventClass.scalar" || v.StartsWith("eventClass.", StringComparison.Ordinal) ?
                    AuditEventFilter.Class(ClassName(e.EventClass)) : null,
            eventMetadata: v == "eventMetadata.value" ? e.EventMetadata : null,
            eventType: v == "eventType.scalar" ? AuditEventFilter.Type(e.EventType) :
                v == "eventType.array.empty" ? AuditEventFilter.Types([]) :
                v == "eventType.array.catalog-values" ? AuditEventFilter.Types([e.EventType]) : null,
            secretKey: v == "secretKey.value" ? e.SecretKey : null, secretPath: v == "secretPath.value" ? e.SecretPath : null,
            userAgentType: v == "userAgentType.selected" ? e.UserAgentType : null);

    private static string ClassName(AuditEventClass value) => value switch
    {
        AuditEventClass.Management => "management",
        AuditEventClass.Authentication => "authentication",
        AuditEventClass.Authorization => "authorization",
        _ => "data-access"
    };

    private static async ValueTask SharingAsync(ProjectFamilyContext c, IShareRecipientObserver observer, CancellationToken token)
    {
        string name = ProjectFamilyContext.FreshName(), v = c.Variant;
        using SecretMaterial material = SecretMaterial.FromText(ProjectFamilyContext.FreshName());
        // An Anyone branch uses an explicit proof so the negative recipient has a real denied counterexample.
        using SecretMaterial? password = v is "password.value" or "audience.Anyone" ?
            SecretMaterial.FromText(ProjectFamilyContext.FreshName()) : null;
        ShareAudience audience = v == "audience.Anyone" ? ShareAudience.Anyone : ShareAudience.Organization;
        int? views = v == "maximumViews.value" ? 3 : null;
        bool? external = v == "allowExternalEmails.true" ? true : v == "allowExternalEmails.false" ? false : null;
        string[]? emails = v switch
        {
            "authorizedEmails.empty" => [],
            "authorizedEmails.value" => [c.Required("recipientEmail")],
            "authorizedEmails.values" => [c.Required("recipientEmail"), c.Required("secondRecipientEmail")],
            _ => null
        };
        string? id = null;
        c.Cleanup(async ct =>
        {
            SecretOutcome<SharedSecretMetadata> found = await observer.FindOwnedAsync(c.OrganizationId, name,
                c.Environment.Tokens(NativeIdentityRole.Observer), ct);
            if (found.Status == SecretStatus.Absent)
                return id is null || (await c.ExecuteAsync(
                    () => SharingOperations.GetShare(c.OrganizationId, id), NativeIdentityRole.Observer, ct)).Status == SecretStatus.Absent;
            if (!found.IsSuccess) return false;
            if (id is not null && found.Value.Id != id) return false;
            SecretOutcome<SharedSecretMetadata> removed = await c.ExecuteAsync(
                () => SharingOperations.DeleteShare(c.OrganizationId, found.Value.Id), NativeIdentityRole.Setup, ct);
            SecretOutcome<SharedSecretMetadata> absent = await observer.FindOwnedAsync(c.OrganizationId, name,
                c.Environment.Tokens(NativeIdentityRole.Observer), ct);
            return removed.IsSuccess && absent.Status == SecretStatus.Absent &&
                (await c.ExecuteAsync(() => SharingOperations.GetShare(c.OrganizationId, found.Value.Id),
                    NativeIdentityRole.Observer, ct)).Status == SecretStatus.Absent;
        });
        Func<ManagementRequest<CreatedShare>> create = () => SharingOperations.CreateShare(c.OrganizationId, name,
            material, 5, audience, views, password, external, emails);
        if (c.Operation != "CreateShare")
        {
            using CreatedShare seed = await c.NeedAsync(create, NativeIdentityRole.Setup, token);
            id = seed.Metadata.Id;
        }
        ShareAccessFacts? baseline = id is null ? null :
            await observer.ObserveViewsAsync(id, c.Environment.Tokens(NativeIdentityRole.Observer), token);
        bool Match(SharedSecretMetadata m) => m.Name == name && (id is null || m.Id == id) &&
            m.OrganizationId.IsPresent && !m.OrganizationId.IsNull && m.OrganizationId.Value == c.OrganizationId &&
            m.AccessType == (audience == ShareAudience.Organization ? "organization" : "anyone") &&
            (views is null || m.ExpiresAfterViews.IsPresent && !m.ExpiresAfterViews.IsNull && m.ExpiresAfterViews.Value == views) &&
            (external is null || m.AllowExternalEmails.IsPresent && !m.AllowExternalEmails.IsNull && m.AllowExternalEmails.Value == external);
        async ValueTask<bool> Observe(bool applied, CancellationToken ct)
        {
            SecretOutcome<SharedSecretMetadata> found = await observer.FindOwnedAsync(c.OrganizationId, name,
                c.Environment.Tokens(NativeIdentityRole.Observer), ct);
            bool absent = c.Operation == "CreateShare" && !applied || c.Operation == "DeleteShare" && applied;
            if (absent) return found.Status == SecretStatus.Absent;
            if (!found.IsSuccess || !Match(found.Value)) return false;
            if (c.Operation == "AccessShare")
            {
                ShareAccessFacts after = await observer.ObserveViewsAsync(found.Value.Id,
                    c.Environment.Tokens(NativeIdentityRole.Observer), ct);
                if (baseline is null || after.ShareId != id || baseline.ShareId != id ||
                    after.ConsumedViews != baseline.ConsumedViews + (applied ? 1 : 0)) return false;
            }
            using ShareDeliveryFacts delivered = await observer.DeliverAsync(c.OrganizationId, found.Value.Id, password,
                c.Environment.Tokens(NativeIdentityRole.Runtime), c.Environment.Tokens(NativeIdentityRole.Denied), ct);
            return delivered.ShareId == found.Value.Id && delivered.RecipientStatus == SecretStatus.Success &&
                delivered.DeniedStatus == SecretStatus.Denied && delivered.Material is not null &&
                ProxiedServiceAdministrationEffects.SameMaterial(delivered.Material, material) &&
                delivered.ViewsAfter == delivered.ViewsBefore + 1 &&
                delivered.Audience == audience && (views is null || delivered.MaximumViews == views) &&
                (views is null || delivered.ViewLimit is { } exhausted &&
                    exhausted.MaximumViews == views && exhausted.ViewsBeforeExhaustedAccess == views &&
                    exhausted.ViewsAfterExhaustedAccess == views && !exhausted.MaterialReturned &&
                    exhausted.ExhaustedObservationTime != default &&
                    exhausted.ExhaustedObservationTime < delivered.ExpiresAt &&
                    exhausted.ExhaustedStatus is SecretStatus.Denied or SecretStatus.Absent) &&
                (external is null || delivered.AllowExternalEmails == external) &&
                (emails is null || delivered.AuthorizedEmails is not null && delivered.AuthorizedEmails.SequenceEqual(emails)) &&
                delivered.ExpiresAt == DateTimeOffset.Parse(found.Value.ExpiresAt, CultureInfo.InvariantCulture) &&
                (views is not null || delivered.ExpiredObservationTime >= delivered.ExpiresAt &&
                    delivered.ExpiredStatus is SecretStatus.Denied or SecretStatus.Absent);
        }
        switch (c.Operation)
        {
            case "CreateShare":
                await c.CaseAsync(create, share =>
                {
                    if (!Match(share.Metadata)) return false;
                    id = share.Metadata.Id;
                    return true;
                }, Observe, token); break;
            case "AccessShare":
                await c.CaseAsync(() => SharingOperations.AccessShare(c.OrganizationId, id!, password),
                    value => Match(value.Metadata) && ProxiedServiceAdministrationEffects.SameMaterial(value.Material, material),
                    Observe, token); break;
            case "GetShare":
                await c.CaseAsync(() => SharingOperations.GetShare(c.OrganizationId, id!), Match, Observe, token); break;
            case "DeleteShare":
                await c.CaseAsync(() => SharingOperations.DeleteShare(c.OrganizationId, id!), Match, Observe, token); break;
            case "ListShares":
                await c.CaseAsync(() => SharingOperations.ListShares(c.OrganizationId),
                    page => page.IsComplete && page.Items.Count(Match) == 1, Observe, token); break;
            default: throw new NativeCaseFailureException("contract-mismatch");
        }
    }
}
