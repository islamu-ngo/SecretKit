using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Explicit client for an independently operated fixture service. Its replies
// are measurements, never a substitute for the family's actual SDK operations.
internal sealed class InfisicalAuditObserver(InfisicalLifecycleObservers channel) : IAuditEventObserver
{
    internal static InfisicalAuditObserver? FromInputs(NativeEnvironment environment)
    {
        var selected = InfisicalLifecycleObservers.FromInputs(environment, "C08-IM-Governance");
        return selected is null ? null : new(selected);
    }

    public async ValueTask<OwnedAuditScope> ProvisionAsync(string ownedName, bool projectScope,
        IInfisicalTokenSource setup, IInfisicalTokenSource administrative, IInfisicalTokenSource observer,
        CancellationToken token)
    {
        using var setupToken = await SelectedToken(setup, token);
        using var adminToken = await SelectedToken(administrative, token);
        using var observerToken = await SelectedToken(observer, token);
        ScopeFacts facts = await channel.PostAsync<ScopeFacts>("audit/provision", writer =>
        {
            writer.WriteString("ownedName", ownedName);
            writer.WriteBoolean("projectScope", projectScope);
            writer.WriteString("setupToken", setupToken.Material.Reveal());
            writer.WriteString("administrativeToken", adminToken.Material.Reveal());
            writer.WriteString("observerToken", observerToken.Material.Reveal());
        }, token);
        Require(facts.OwnedName == ownedName && !string.IsNullOrWhiteSpace(facts.OrganizationId) &&
            projectScope == !string.IsNullOrWhiteSpace(facts.ProjectId));
        return new(facts.OrganizationId, facts.ProjectId, facts.OwnedName);
    }

    public async ValueTask<TriggeredAuditEvent> TriggerAsync(OwnedAuditScope scope, AuditEventClass eventClass,
        string correlation, IInfisicalTokenSource runtime, CancellationToken token)
    {
        using var selected = await SelectedToken(runtime, token);
        TriggerFacts facts = await channel.PostAsync<TriggerFacts>("audit/trigger", writer =>
        {
            Scope(writer, scope);
            writer.WriteString("correlation", correlation);
            writer.WriteNumber("eventClass", (int)eventClass);
            writer.WriteString("runtimeToken", selected.Material.Reveal());
        }, token);
        Require(facts.Correlation == correlation && facts.OrganizationId == scope.OrganizationId &&
            facts.ProjectId == scope.ProjectId && facts.EventClass == eventClass &&
            !string.IsNullOrWhiteSpace(facts.Id) && facts.Until > facts.From);
        return new(facts.Id, facts.Correlation, facts.OrganizationId, facts.ProjectId, facts.EventClass,
            facts.EventType, facts.From, facts.Until, facts.Actor, facts.ActorType, facts.Environment,
            facts.SecretKey, facts.SecretPath, facts.EventMetadata, facts.UserAgentType);
    }

    public async ValueTask<AuditEventFacts> ObserveAsync(OwnedAuditScope scope, TriggeredAuditEvent triggered,
        IInfisicalTokenSource observer, CancellationToken token)
    {
        using var selected = await SelectedToken(observer, token);
        EventFacts facts = await channel.PostAsync<EventFacts>("audit/observe", writer =>
        {
            Scope(writer, scope);
            writer.WriteString("eventId", triggered.Id);
            writer.WriteString("correlation", triggered.Correlation);
            writer.WriteString("observerToken", selected.Material.Reveal());
        }, token);
        Require(facts.Correlation == triggered.Correlation && facts.PersistedEventIds is not null &&
            facts.EnabledClasses is not null);
        return new(facts.Correlation, facts.ProducedEvents, facts.PersistedEventIds, facts.EnabledClasses);
    }

    public async ValueTask<AuditCleanupFacts> RemoveOwnedAsync(string ownedName, IInfisicalTokenSource setup,
        CancellationToken token)
    {
        using var selected = await SelectedToken(setup, token);
        CleanupFacts facts = await channel.PostAsync<CleanupFacts>("audit/cleanup", writer =>
        {
            writer.WriteString("ownedName", ownedName);
            writer.WriteString("setupToken", selected.Material.Reveal());
        }, token);
        if (facts.OwnedName != ownedName || facts.RemainingOrganizations != 0 || facts.RemainingProjects != 0)
            throw new NativeCaseFailureException("cleanup-incomplete");
        return new(facts.OwnedName, facts.RemainingOrganizations, facts.RemainingProjects);
    }

    private static async ValueTask<InfisicalAccessToken> SelectedToken(IInfisicalTokenSource source, CancellationToken token)
    {
        var selected = await source.GetTokenAsync(token);
        if (!selected.IsSuccess) throw new NativeCaseFailureException("missing-input");
        return selected.Value;
    }

    private static void Scope(Utf8JsonWriter writer, OwnedAuditScope scope)
    {
        writer.WriteString("organizationId", scope.OrganizationId);
        writer.WriteString("projectId", scope.ProjectId);
        writer.WriteString("ownedName", scope.OwnedName);
    }
    private static void Require([DoesNotReturnIf(false)] bool matches)
    {
        if (!matches) throw new NativeCaseFailureException("observer-unavailable");
    }

    private sealed record ScopeFacts(string OrganizationId, string? ProjectId, string OwnedName)
    {
        public override string ToString() => "[AuditScopeFacts]";
    }
    private sealed record TriggerFacts(string Id, string Correlation, string OrganizationId, string? ProjectId,
        AuditEventClass EventClass, string EventType, DateTimeOffset From, DateTimeOffset Until,
        string Actor, string ActorType, string Environment, string SecretKey, string SecretPath,
        string EventMetadata, string UserAgentType)
    {
        public override string ToString() => "[AuditTriggerFacts]";
    }
    private sealed record EventFacts(string Correlation, int ProducedEvents, string[] PersistedEventIds,
        AuditEventClass[] EnabledClasses)
    {
        public override string ToString() => "[AuditEventFacts]";
    }
    private sealed record CleanupFacts(string OwnedName, int RemainingOrganizations, int RemainingProjects)
    {
        public override string ToString() => "[AuditCleanupFacts]";
    }
}
