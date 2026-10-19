using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalProxyObserver(InfisicalLifecycleObservers channel) : IProxyBackendObserver
{
    internal static InfisicalProxyObserver? FromInputs(NativeEnvironment environment)
    {
        var selected = InfisicalLifecycleObservers.FromInputs(environment, "C08-IM-ProxiedServiceAdministration");
        return selected is null ? null : new(selected);
    }

    public async ValueTask<ProxyCredentialFixture> PrepareAsync(string organizationId, string projectId,
        string environment, string ownedName, IInfisicalTokenSource setup, CancellationToken token)
    {
        using var selected = await SelectedToken(setup, token);
        FixtureFacts facts = await channel.PostAsync<FixtureFacts>("proxy/prepare", writer =>
        {
            writer.WriteString("organizationId", organizationId);
            writer.WriteString("projectId", projectId);
            writer.WriteString("environment", environment);
            writer.WriteString("ownedName", ownedName);
            writer.WriteString("setupToken", selected.Material.Reveal());
        }, token);
        if (facts.OrganizationId != organizationId || facts.ProjectId != projectId ||
            facts.Environment != environment || facts.OwnedName != ownedName ||
            string.IsNullOrWhiteSpace(facts.SecretKey) || string.IsNullOrWhiteSpace(facts.DynamicSecretName) ||
            string.IsNullOrWhiteSpace(facts.DynamicSecretField) || string.IsNullOrWhiteSpace(facts.HostPattern) ||
            string.IsNullOrEmpty(facts.ExpectedValue))
            throw new NativeCaseFailureException("observer-unavailable");
        return new(facts.SecretKey, facts.DynamicSecretName, facts.DynamicSecretField, facts.HostPattern,
            SecretMaterial.FromText(facts.ExpectedValue));
    }

    public async ValueTask<ProxyBackendFacts> SendThroughAsync(string serviceId, string challenge,
        ProxiedServiceCredentialRole role, ProxiedServiceSubstitutionSurface surface,
        IInfisicalTokenSource selectedIdentity, CancellationToken token)
    {
        using var selected = await SelectedToken(selectedIdentity, token);
        BackendFacts facts = await channel.PostAsync<BackendFacts>("proxy/send", writer =>
        {
            writer.WriteString("serviceId", serviceId);
            writer.WriteString("challenge", challenge);
            writer.WriteNumber("role", (int)role);
            writer.WriteNumber("surface", (int)surface);
            writer.WriteString("selectedToken", selected.Material.Reveal());
        }, token);
        if (facts.ServiceId != serviceId || facts.Challenge != challenge || !Enum.IsDefined(facts.Status) ||
            facts.BackendRequests < 0 ||
            facts.Status == SecretStatus.Success && (facts.SubstitutedValue is null ||
                facts.ObservedRole != role || facts.ObservedSurface != surface))
            throw new NativeCaseFailureException("observer-unavailable");
        return new(facts.ServiceId, facts.Challenge, facts.Status, facts.BackendRequests,
            facts.SubstitutedValue is null ? null : SecretMaterial.FromText(facts.SubstitutedValue),
            facts.ObservedRole, facts.ObservedSurface, facts.HeaderName);
    }

    public async ValueTask<SecretStatus> RemoveFixtureAsync(string projectId, string ownedName,
        IInfisicalTokenSource setup, CancellationToken token)
    {
        using var selected = await SelectedToken(setup, token);
        CleanupFacts facts = await channel.PostAsync<CleanupFacts>("proxy/cleanup", writer =>
        {
            writer.WriteString("projectId", projectId);
            writer.WriteString("ownedName", ownedName);
            writer.WriteString("setupToken", selected.Material.Reveal());
        }, token);
        if (facts.ProjectId != projectId || facts.OwnedName != ownedName || facts.RemainingResources != 0 ||
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
    private sealed record FixtureFacts(string OrganizationId, string ProjectId, string Environment,
        string OwnedName, string SecretKey, string DynamicSecretName, string DynamicSecretField,
        string HostPattern, string ExpectedValue)
    {
        public override string ToString() => "[ProxyFixtureFacts]";
    }
    private sealed record BackendFacts(string ServiceId, string Challenge, SecretStatus Status,
        int BackendRequests, string? SubstitutedValue, ProxiedServiceCredentialRole? ObservedRole,
        ProxiedServiceSubstitutionSurface? ObservedSurface, string? HeaderName)
    {
        public override string ToString() => "[ProxyBackendFacts]";
    }
    private sealed record CleanupFacts(string ProjectId, string OwnedName, SecretStatus Status, int RemainingResources)
    {
        public override string ToString() => "[ProxyCleanupFacts]";
    }
}
