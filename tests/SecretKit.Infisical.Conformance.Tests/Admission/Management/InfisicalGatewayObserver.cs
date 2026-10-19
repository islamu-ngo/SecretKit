using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Measurements come from an explicitly selected fixture service. Configuration
// and service replies do not establish independently authenticated principals.
internal sealed class InfisicalGatewayObserver(InfisicalLifecycleObservers channel, ManagementClient client)
    : IGatewayAgentObserver
{
    internal static InfisicalGatewayObserver? FromInputs(NativeEnvironment environment)
    {
        var selected = InfisicalLifecycleObservers.FromInputs(environment, "C08-IM-GatewayAdministration");
        return selected is null ? null : new(selected, environment.CreateManagementClient());
    }

    public async ValueTask<SecretOutcome<GatewaySummary>> FindOwnedAsync(string organizationId, string name,
        IInfisicalTokenSource observer, CancellationToken token)
    {
        using var selected = await SelectedToken(observer, token);
        LookupFacts facts = await channel.PostAsync<LookupFacts>("gateway/find", writer =>
        {
            Owned(writer, organizationId, name);
            writer.WriteString("observerToken", selected.Material.Reveal());
        }, token);
        if (facts.OrganizationId != organizationId || facts.OwnedName != name ||
            facts.Status is not (SecretStatus.Success or SecretStatus.Absent) ||
            (facts.Status == SecretStatus.Absent ? facts.GatewayId is not null :
                !Guid.TryParseExact(facts.GatewayId, "D", out _)))
            throw new NativeCaseFailureException("observer-unavailable");
        if (facts.Status == SecretStatus.Absent) return SecretOutcome<GatewaySummary>.Failure(SecretStatus.Absent);
        using ManagementRequest<GatewaySummary> request = GatewayAdministrationOperations.Get(organizationId, facts.GatewayId!);
        var authority = new ManagementAuthority(client.Authority, observer, organizationId);
        SecretOutcome<GatewaySummary> result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, request.Target), cancellationToken: token);
        if (result.IsSuccess && result.Value.Name != name)
            throw new NativeCaseFailureException("observer-unavailable");
        return result;
    }

    public ValueTask<GatewayAgentFacts> AuthenticateAsync(string organizationId, GatewaySummary gateway,
        IInfisicalTokenSource runtime, CancellationToken token) =>
        AgentAsync("gateway/authenticate", organizationId, gateway, null, runtime, token);

    public ValueTask<GatewayAgentFacts> EnrollAsync(string organizationId, GatewaySummary gateway,
        SecretMaterial enrollmentToken, IInfisicalTokenSource runtime, CancellationToken token) =>
        AgentAsync("gateway/enroll", organizationId, gateway, enrollmentToken, runtime, token);

    private async ValueTask<GatewayAgentFacts> AgentAsync(string route, string organizationId, GatewaySummary gateway,
        SecretMaterial? enrollmentToken, IInfisicalTokenSource runtime, CancellationToken token)
    {
        using var selected = await SelectedToken(runtime, token);
        using SecretMaterial? enrollment = enrollmentToken?.Copy();
        char[]? characters = enrollment?.ExportCharacters();
        byte[]? bytes = null;
        string? fingerprint;
        try
        {
            bytes = characters is null ? null : Encoding.UTF8.GetBytes(characters);
            fingerprint = bytes is null ? null : Convert.ToHexString(SHA256.HashData(bytes));
        }
        finally
        {
            if (characters is not null) Array.Clear(characters);
            if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
        }
        DateTimeOffset started = DateTimeOffset.UtcNow;
        AgentFacts facts = await channel.PostAsync<AgentFacts>(route, writer =>
        {
            Owned(writer, organizationId, gateway.Name);
            writer.WriteString("gatewayId", gateway.Id);
            writer.WriteString("identityId", gateway.IdentityId ?? gateway.Authentication.IdentityId);
            writer.WriteNumber("authentication", (int)gateway.Authentication.Method);
            writer.WriteString("runtimeToken", selected.Material.Reveal());
            if (enrollment is not null) writer.WriteString("enrollmentToken", enrollment.Reveal());
        }, token);
        var measured = new GatewayAgentFacts(facts.GatewayId, facts.IdentityId, facts.Authentication,
            facts.Heartbeat, facts.AcceptedAuthentications);
        if (facts.OrganizationId != organizationId || facts.OwnedName != gateway.Name ||
            facts.EnrollmentFingerprint != fingerprint || !GatewayAdministrationEffects.AgentMatches(gateway, measured) ||
            !Guid.TryParseExact(facts.IdentityId, "D", out _) ||
            (gateway.Authentication.IdentityId is { } identity && facts.IdentityId != identity) ||
            facts.Heartbeat < started.AddSeconds(-30) || facts.Heartbeat > DateTimeOffset.UtcNow.AddSeconds(30))
            throw new NativeCaseFailureException("observer-unavailable");
        return measured;
    }

    public async ValueTask<GatewayEnrollmentFacts> ObserveEnrollmentAsync(string gatewayId, CancellationToken token)
    {
        EnrollmentFacts facts = await channel.PostAsync<EnrollmentFacts>("gateway/enrollment", writer =>
            writer.WriteString("gatewayId", gatewayId), token);
        if (facts.GatewayId != gatewayId || facts.IssuedTokens < 0 || facts.EnrolledAgents < 0)
            throw new NativeCaseFailureException("observer-unavailable");
        return new(facts.GatewayId, facts.IssuedTokens, facts.EnrolledAgents);
    }

    public async ValueTask<SecretStatus> RemoveOwnedAsync(string organizationId, string name,
        IInfisicalTokenSource setup, CancellationToken token)
    {
        using var selected = await SelectedToken(setup, token);
        CleanupFacts facts = await channel.PostAsync<CleanupFacts>("gateway/cleanup", writer =>
        {
            Owned(writer, organizationId, name);
            writer.WriteString("setupToken", selected.Material.Reveal());
        }, token);
        if (facts.OrganizationId != organizationId || facts.OwnedName != name ||
            facts.RemainingGateways != 0 || facts.RemainingAgents != 0 || facts.RemainingEnrollmentTokens != 0 ||
            facts.Status is not (SecretStatus.Success or SecretStatus.Absent))
            throw new NativeCaseFailureException("cleanup-incomplete");
        return facts.Status;
    }

    private static async ValueTask<InfisicalAccessToken> SelectedToken(IInfisicalTokenSource source, CancellationToken token)
    {
        var selected = await source.GetTokenAsync(token);
        if (!selected.IsSuccess) throw new NativeCaseFailureException("missing-input");
        return selected.Value;
    }

    private static void Owned(Utf8JsonWriter writer, string organizationId, string name)
    {
        writer.WriteString("organizationId", organizationId);
        writer.WriteString("ownedName", name);
    }

    private sealed record LookupFacts([property: JsonRequired] string OrganizationId,
        [property: JsonRequired] string OwnedName, [property: JsonRequired] SecretStatus Status,
        [property: JsonRequired] string? GatewayId)
    {
        public override string ToString() => "[GatewayLookupFacts]";
    }
    private sealed record AgentFacts([property: JsonRequired] string OrganizationId,
        [property: JsonRequired] string OwnedName, [property: JsonRequired] string GatewayId,
        [property: JsonRequired] string IdentityId, [property: JsonRequired] GatewayAuthenticationMethod Authentication,
        [property: JsonRequired] DateTimeOffset Heartbeat, [property: JsonRequired] int AcceptedAuthentications,
        [property: JsonRequired] string? EnrollmentFingerprint)
    {
        public override string ToString() => "[GatewayMeasurementFacts]";
    }
    private sealed record EnrollmentFacts([property: JsonRequired] string GatewayId,
        [property: JsonRequired] int IssuedTokens, [property: JsonRequired] int EnrolledAgents)
    {
        public override string ToString() => "[GatewayEnrollmentMeasurementFacts]";
    }
    private sealed record CleanupFacts([property: JsonRequired] string OrganizationId,
        [property: JsonRequired] string OwnedName, [property: JsonRequired] SecretStatus Status,
        [property: JsonRequired] int RemainingGateways, [property: JsonRequired] int RemainingAgents,
        [property: JsonRequired] int RemainingEnrollmentTokens)
    {
        public override string ToString() => "[GatewayCleanupFacts]";
    }
}
