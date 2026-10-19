using System.Globalization;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Implementations subscribe to enrollment/heartbeat events before starting their owned agent.
// Native lookup and cleanup are host capabilities: the SDK has no gateway list/delete factory.
internal interface IGatewayAgentObserver
{
    ValueTask<SecretOutcome<GatewaySummary>> FindOwnedAsync(string organizationId, string name,
        IInfisicalTokenSource observer, CancellationToken token);
    ValueTask<GatewayAgentFacts> AuthenticateAsync(string organizationId, GatewaySummary gateway,
        IInfisicalTokenSource runtime, CancellationToken token);
    ValueTask<GatewayAgentFacts> EnrollAsync(string organizationId, GatewaySummary gateway,
        SecretMaterial enrollmentToken, IInfisicalTokenSource runtime, CancellationToken token);
    ValueTask<GatewayEnrollmentFacts> ObserveEnrollmentAsync(string gatewayId, CancellationToken token);
    ValueTask<SecretStatus> RemoveOwnedAsync(string organizationId, string name,
        IInfisicalTokenSource setup, CancellationToken token);
}

internal sealed record GatewayAgentFacts([property: JsonIgnore] string GatewayId, [property: JsonIgnore] string IdentityId,
    GatewayAuthenticationMethod Authentication, DateTimeOffset Heartbeat, int AcceptedAuthentications)
{
    public override string ToString() => "[GatewayAgentFacts]";
}

internal sealed record GatewayEnrollmentFacts([property: JsonIgnore] string GatewayId, int IssuedTokens, int EnrolledAgents)
{
    public override string ToString() => "[GatewayEnrollmentFacts]";
}

internal static class GatewayAdministrationEffects
{
    internal static string? UnavailableReason(NativeCaseDefinition d) =>
        d.Key.Operation.EndsWith(".Update", StringComparison.Ordinal) &&
            d.Key.Variant is not ("auth.Token" or "response.auth.Token" or "name.value") ?
            "primary-patch-persistence-contract" :
        d.Key.Operation.EndsWith(".GenerateEnrollmentToken", StringComparison.Ordinal) &&
            d.Key.Case == "lost-response-no-replay" ? "lost-enrollment-token-recovery-contract" :
        d.Key.Variant == "response.auth.Identity" ? "identity-gateway-creation-contract" : null;

    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, GovernanceObservers observers,
        CancellationToken token)
    {
        IGatewayAgentObserver observer = observers.Gateway ?? InfisicalGatewayObserver.FromInputs(c.Environment) ??
            throw new NativeCaseFailureException("missing-input");
        string name = ProjectFamilyContext.FreshName();
        string originalName = name;
        string renamed = ProjectFamilyContext.FreshName();
        c.Cleanup(async ct =>
        {
            SecretStatus removed = await observer.RemoveOwnedAsync(c.OrganizationId, originalName,
                c.Environment.Tokens(NativeIdentityRole.Setup), ct);
            SecretOutcome<GatewaySummary> found = await observer.FindOwnedAsync(c.OrganizationId, originalName,
                c.Environment.Tokens(NativeIdentityRole.Observer), ct);
            return removed is SecretStatus.Success or SecretStatus.Absent && found.Status == SecretStatus.Absent;
        });
        if (c.Operation == "Update")
            c.Cleanup(async ct =>
            {
                SecretStatus removed = await observer.RemoveOwnedAsync(c.OrganizationId, renamed,
                    c.Environment.Tokens(NativeIdentityRole.Setup), ct);
                SecretOutcome<GatewaySummary> found = await observer.FindOwnedAsync(c.OrganizationId, renamed,
                    c.Environment.Tokens(NativeIdentityRole.Observer), ct);
                return removed is SecretStatus.Success or SecretStatus.Absent && found.Status == SecretStatus.Absent;
            });
        using GatewayAuthenticationInput authentication = Authentication(c);
        var creation = new GatewayCreation(name, authentication);
        GatewaySummary? seeded = null;
        if (c.Operation != "Create")
            seeded = await c.NeedAsync(() => GatewayAdministrationOperations.Create(c.OrganizationId, creation),
                NativeIdentityRole.Setup, token);

        bool Match(GatewaySummary gateway) => gateway.Name == name && AuthenticationMatches(c, gateway.Authentication);
        async ValueTask<bool> Observe(bool applied, CancellationToken ct)
        {
            name = c.Operation == "Update" && applied ? renamed : originalName;
            SecretOutcome<GatewaySummary> found = await observer.FindOwnedAsync(c.OrganizationId, name,
                c.Environment.Tokens(NativeIdentityRole.Observer), ct);
            if (!applied && c.Operation == "Create") return found.Status == SecretStatus.Absent;
            if (!found.IsSuccess || !Match(found.Value)) return false;
            GatewaySummary native = await c.NeedAsync(() => GatewayAdministrationOperations.Get(c.OrganizationId,
                found.Value.Id), NativeIdentityRole.Observer, ct);
            if (!SameMetadata(native, found.Value)) return false;
            GatewayAgentFacts facts = await observer.AuthenticateAsync(c.OrganizationId, native,
                c.Environment.Tokens(NativeIdentityRole.Runtime), ct);
            GatewaySummary heartbeat = await c.NeedAsync(() => GatewayAdministrationOperations.Get(
                c.OrganizationId, native.Id), NativeIdentityRole.Observer, ct);
            bool matched = AgentMatches(native, facts) && HeartbeatAdvanced(native, heartbeat, facts);
            if (matched) ConfirmAgent(c);
            return matched;
        }
        switch (c.Operation)
        {
            case "Create":
                await c.CaseAsync(() => GatewayAdministrationOperations.Create(c.OrganizationId, creation), Match, Observe, token);
                break;
            case "Get":
                string selectedId = (seeded ?? throw new NativeCaseFailureException("missing-prerequisite")).Id;
                await c.CaseAsync(() => GatewayAdministrationOperations.Get(c.OrganizationId, selectedId),
                    g => Match(g) && g.Id == selectedId, Observe, token);
                break;
            case "Update":
                var update = new GatewayUpdate(renamed, authentication);
                await c.CaseAsync(() => GatewayAdministrationOperations.Update(c.OrganizationId, seeded!.Id, update),
                    gateway => gateway.Id == seeded!.Id && gateway.Name == renamed &&
                        AuthenticationMatches(c, gateway.Authentication), Observe, token);
                break;
            case "GenerateEnrollmentToken":
                GatewaySummary selected = seeded ?? throw new NativeCaseFailureException("missing-prerequisite");
                GatewayEnrollmentFacts before = await observer.ObserveEnrollmentAsync(selected.Id, token);
                SecretMaterial? enrollment = null;
                try
                {
                    await c.CaseAsync(() => GatewayAdministrationOperations.GenerateEnrollmentToken(c.OrganizationId, selected.Id),
                    issued =>
                    {
                        enrollment = issued.Material.Copy();
                        return DateTimeOffset.Parse(issued.ExpiresAt, CultureInfo.InvariantCulture) > DateTimeOffset.UtcNow;
                    },
                    async (applied, ct) =>
                    {
                        GatewaySummary? baseline = applied && enrollment is not null ?
                            await c.NeedAsync(() => GatewayAdministrationOperations.Get(c.OrganizationId, selected.Id),
                                NativeIdentityRole.Observer, ct) : null;
                        GatewayAgentFacts? enrolled = applied && enrollment is not null ?
                            await observer.EnrollAsync(c.OrganizationId, selected, enrollment,
                                c.Environment.Tokens(NativeIdentityRole.Runtime), ct) : null;
                        GatewayEnrollmentFacts after = await observer.ObserveEnrollmentAsync(selected.Id, ct);
                        // The selected token must be issued exactly once, including response loss.
                        if (after.GatewayId != selected.Id || after.IssuedTokens != before.IssuedTokens + (applied ? 1 : 0))
                            return false;
                        if (!applied) return after.EnrolledAgents == before.EnrolledAgents;
                        if (enrolled is null || !AgentMatches(selected, enrolled) ||
                            after.EnrolledAgents != before.EnrolledAgents + 1) return false;
                        GatewaySummary native = await c.NeedAsync(() => GatewayAdministrationOperations.Get(
                            c.OrganizationId, selected.Id), NativeIdentityRole.Observer, ct);
                        bool matched = baseline is not null && HeartbeatAdvanced(baseline, native, enrolled);
                        if (matched) ConfirmAgent(c);
                        return matched;
                    }, token);
                }
                finally { enrollment?.Dispose(); }
                break;
            default: throw new NativeCaseFailureException("contract-mismatch");
        }
    }

    internal static bool AgentMatches(GatewaySummary gateway, GatewayAgentFacts facts) =>
        facts.GatewayId == gateway.Id && !string.IsNullOrWhiteSpace(facts.IdentityId) &&
        facts.Authentication == gateway.Authentication.Method && facts.AcceptedAuthentications > 0 &&
        facts.Heartbeat != default && (gateway.IdentityId is null || facts.IdentityId == gateway.IdentityId);

    private static bool HeartbeatAdvanced(GatewaySummary before, GatewaySummary after, GatewayAgentFacts facts)
    {
        // An agent reply (or nonce echo) alone cannot witness this invocation.
        // Explicit null is absence; an omitted native field is unavailable evidence.
        if (!before.HasHeartbeat || !after.HasHeartbeat)
            throw new NativeCaseFailureException("observer-unavailable");
        if (after.Heartbeat is null) return false;
        DateTimeOffset heartbeat = DateTimeOffset.Parse(after.Heartbeat, CultureInfo.InvariantCulture);
        return heartbeat == facts.Heartbeat && after.IdentityId == facts.IdentityId &&
            (before.Heartbeat is null ||
                heartbeat > DateTimeOffset.Parse(before.Heartbeat, CultureInfo.InvariantCulture));
    }

    private static void ConfirmAgent(ProjectFamilyContext c)
    {
        foreach (string prerequisite in new[] { "selected-runtime-identity", "host-owned-gateway-agent",
            "gateway-issuer-observer", "gateway-entitlement" })
            c.Environment.ConfirmPrerequisite(c.Definition.Key.Scope, prerequisite, NativeObservation.Matched);
    }

    private static bool SameMetadata(GatewaySummary a, GatewaySummary b) =>
        a.Id == b.Id && a.Name == b.Name && a.CanRevoke == b.CanRevoke &&
        a.HasDirectAddress == b.HasDirectAddress && a.DirectAddress == b.DirectAddress &&
        a.HasHeartbeat == b.HasHeartbeat && a.Heartbeat == b.Heartbeat &&
        a.HasDirectHeartbeat == b.HasDirectHeartbeat && a.DirectHeartbeat == b.DirectHeartbeat &&
        a.HasHeartbeatTTL == b.HasHeartbeatTTL && a.HeartbeatTTL == b.HeartbeatTTL &&
        a.HasIdentityId == b.HasIdentityId && a.IdentityId == b.IdentityId &&
        a.HasRelayId == b.HasRelayId && a.RelayId == b.RelayId &&
        a.Authentication.Method == b.Authentication.Method;

    private static GatewayAuthenticationInput Authentication(ProjectFamilyContext c)
    {
        string v = c.Variant;
        string? Field(string prefix, string field) => v == prefix + "." + field + ".empty" ? "" :
            v == prefix + "." + field + ".value" ? c.Required(field) : null;
        if (v.Contains("Aws", StringComparison.Ordinal))
            return GatewayAuthenticationInput.Aws(Field("Aws", "allowedAccountIds"), Field("Aws", "allowedPrincipalArns"));
        if (v.Contains("Gcp", StringComparison.Ordinal))
            return GatewayAuthenticationInput.Gcp(Field("Gcp", "allowedProjects"), Field("Gcp", "allowedServiceAccounts"),
                Field("Gcp", "allowedZones"), v == "auth.Gcp.Gce" ? GatewayGcpType.Gce :
                v == "auth.Gcp.Iam" ? GatewayGcpType.Iam : null);
        if (v.Contains("Kubernetes", StringComparison.Ordinal) || v.StartsWith("gateway", StringComparison.Ordinal) ||
            v.StartsWith("verifyTlsCertificate", StringComparison.Ordinal))
        {
            using SecretMaterial? jwt = v == "Kubernetes.tokenReviewerJwt.empty" ? SecretMaterial.FromText("") :
                v == "Kubernetes.tokenReviewerJwt.value" ? SecretMaterial.FromText(c.Required("tokenReviewerJwt")) : null;
            return GatewayAuthenticationInput.Kubernetes(c.Required("allowedNames"), c.Required("allowedNamespaces"),
                caCertificate: Field("Kubernetes", "caCertificate"),
                gatewayId: v == "gatewayId.null" ? new(null) : v == "gatewayId.value" ? new(c.Required("gatewayId")) : null,
                gatewayPoolId: v == "gatewayPoolId.null" ? new(null) : v == "gatewayPoolId.value" ? new(c.Required("gatewayPoolId")) : null,
                kubernetesHost: v == "Kubernetes.kubernetesHost.value" ? c.Required("kubernetesHost") : null,
                tokenReviewerJwt: jwt, tokenReviewMode: v == "auth.Kubernetes.Api" ? GatewayTokenReviewMode.Api :
                    v == "auth.Kubernetes.Gateway" ? GatewayTokenReviewMode.Gateway : null,
                verifyTlsCertificate: v == "verifyTlsCertificate.true" ? true : v == "verifyTlsCertificate.false" ? false : null);
        }
        return GatewayAuthenticationInput.Token();
    }

    private static bool AuthenticationMatches(ProjectFamilyContext c, GatewayAuthenticationSummary a)
    {
        string v = c.Variant;
        bool Field(string prefix, string field, string? actual) =>
            v == prefix + "." + field + ".value" ? actual == c.Required(field) :
            v != prefix + "." + field + ".empty" || actual == "";
        if (v.Contains("Aws", StringComparison.Ordinal))
            return a.Method == GatewayAuthenticationMethod.Aws && Field("Aws", "allowedAccountIds", a.AllowedAccountIds) &&
                Field("Aws", "allowedPrincipalArns", a.AllowedPrincipalArns);
        if (v.Contains("Gcp", StringComparison.Ordinal))
            return a.Method == GatewayAuthenticationMethod.Gcp && Field("Gcp", "allowedProjects", a.AllowedProjects) &&
                Field("Gcp", "allowedServiceAccounts", a.AllowedServiceAccounts) && Field("Gcp", "allowedZones", a.AllowedZones) &&
                (v != "auth.Gcp.Gce" || a.Type == "gce") && (v != "auth.Gcp.Iam" || a.Type == "iam");
        if (v.Contains("Kubernetes", StringComparison.Ordinal) || v.StartsWith("gateway", StringComparison.Ordinal) ||
            v.StartsWith("verifyTlsCertificate", StringComparison.Ordinal))
            return a.Method == GatewayAuthenticationMethod.Kubernetes && a.AllowedNames == c.Required("allowedNames") &&
                a.AllowedNamespaces == c.Required("allowedNamespaces") && Field("Kubernetes", "caCertificate", a.CaCertificate) &&
                (v != "gatewayId.null" || a.GatewayId is null) &&
                (v != "gatewayId.value" || a.GatewayId == c.Required("gatewayId")) &&
                (v != "gatewayPoolId.null" || a.GatewayPoolId is null) &&
                (v != "gatewayPoolId.value" || a.GatewayPoolId == c.Required("gatewayPoolId")) &&
                (v != "verifyTlsCertificate.true" || a.VerifyTlsCertificate == true) &&
                (v != "verifyTlsCertificate.false" || a.VerifyTlsCertificate == false) &&
                (v != "Kubernetes.kubernetesHost.value" || a.KubernetesHost == c.Required("kubernetesHost")) &&
                (v != "Kubernetes.tokenReviewerJwt.value" || a.HasTokenReviewerJwt == true) &&
                (v != "auth.Kubernetes.Api" || a.TokenReviewMode == "api") &&
                (v != "auth.Kubernetes.Gateway" || a.TokenReviewMode == "gateway");
        return a.Method == GatewayAuthenticationMethod.Token;
    }
}
