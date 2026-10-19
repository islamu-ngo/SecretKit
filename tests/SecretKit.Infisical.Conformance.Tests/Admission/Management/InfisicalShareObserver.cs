using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalShareObserver(InfisicalLifecycleObservers channel, ManagementClient client)
    : IShareRecipientObserver
{
    internal static InfisicalShareObserver? FromInputs(NativeEnvironment environment)
    {
        var selected = InfisicalLifecycleObservers.FromInputs(environment, "C08-IM-Governance");
        return selected is null ? null : new(selected, environment.CreateManagementClient());
    }

    public async ValueTask<SecretOutcome<SharedSecretMetadata>> FindOwnedAsync(string organizationId, string name,
        IInfisicalTokenSource observer, CancellationToken token)
    {
        using var selected = await SelectedToken(observer, token);
        LookupFacts facts = await channel.PostAsync<LookupFacts>("share/find", writer =>
        {
            writer.WriteString("organizationId", organizationId);
            writer.WriteString("ownedName", name);
            writer.WriteString("observerToken", selected.Material.Reveal());
        }, token);
        if (facts.OrganizationId != organizationId || facts.OwnedName != name ||
            facts.Status is not (SecretStatus.Success or SecretStatus.Absent) ||
            (facts.Status == SecretStatus.Absent ? facts.ShareId is not null : string.IsNullOrWhiteSpace(facts.ShareId)))
            throw new NativeCaseFailureException("observer-unavailable");
        if (facts.Status == SecretStatus.Absent) return SecretOutcome<SharedSecretMetadata>.Failure(SecretStatus.Absent);
        using var request = SharingOperations.GetShare(organizationId, facts.ShareId!);
        var authority = new ManagementAuthority(client.Authority, observer, organizationId);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, request.Target), cancellationToken: token);
        if (result.IsSuccess && (result.Value.Name != name || !result.Value.OrganizationId.IsPresent ||
            result.Value.OrganizationId.IsNull || result.Value.OrganizationId.Value != organizationId))
            throw new NativeCaseFailureException("observer-unavailable");
        return result;
    }

    public async ValueTask<ShareAccessFacts> ObserveViewsAsync(string shareId, IInfisicalTokenSource observer,
        CancellationToken token)
    {
        using var selected = await SelectedToken(observer, token);
        ViewFacts facts = await channel.PostAsync<ViewFacts>("share/views", writer =>
        {
            writer.WriteString("shareId", shareId);
            writer.WriteString("observerToken", selected.Material.Reveal());
        }, token);
        if (facts.ShareId != shareId || facts.ConsumedViews < 0)
            throw new NativeCaseFailureException("observer-unavailable");
        return new(facts.ShareId, facts.ConsumedViews);
    }

    public async ValueTask<ShareDeliveryFacts> DeliverAsync(string organizationId, string shareId, SecretMaterial? password,
        IInfisicalTokenSource runtime, IInfisicalTokenSource denied, CancellationToken token)
    {
        using var intended = await SelectedToken(runtime, token);
        using var rejected = await SelectedToken(denied, token);
        DeliveryFacts facts = await channel.PostAsync<DeliveryFacts>("share/deliver", writer =>
        {
            writer.WriteString("organizationId", organizationId);
            writer.WriteString("shareId", shareId);
            writer.WriteString("password", password?.Reveal());
            writer.WriteString("runtimeToken", intended.Material.Reveal());
            writer.WriteString("deniedToken", rejected.Material.Reveal());
        }, token);
        if (facts.OrganizationId != organizationId || facts.ShareId != shareId || !Enum.IsDefined(facts.Audience) ||
            facts.RecipientStatus != SecretStatus.Success || facts.DeniedStatus != SecretStatus.Denied ||
            facts.Material is null || facts.ViewsBefore < 0 || (long)facts.ViewsAfter != (long)facts.ViewsBefore + 1 ||
            facts.ExpiresAt == default || facts.ExpiredObservationTime < facts.ExpiresAt ||
            facts.ExpiredStatus is not (SecretStatus.Denied or SecretStatus.Absent))
            throw new NativeCaseFailureException("observer-unavailable");
        if (facts.MaximumViews is { } maximum &&
            (maximum <= 0 || facts.ViewLimit is not { } exhausted ||
                exhausted.MaximumViews != maximum || exhausted.ViewsBeforeExhaustedAccess != maximum ||
                exhausted.ViewsAfterExhaustedAccess != maximum || exhausted.MaterialReturned ||
                exhausted.ExhaustedObservationTime == default || exhausted.ExhaustedObservationTime >= facts.ExpiresAt ||
                exhausted.ExhaustedStatus is not (SecretStatus.Denied or SecretStatus.Absent)))
            throw new NativeCaseFailureException("observer-unavailable");
        return new(facts.ShareId, facts.RecipientStatus, facts.DeniedStatus, facts.ViewsBefore, facts.ViewsAfter,
            facts.ExpiresAt, facts.ExpiredObservationTime, facts.ExpiredStatus, SecretMaterial.FromText(facts.Material),
            facts.Audience, facts.MaximumViews, facts.AllowExternalEmails, facts.AuthorizedEmails, facts.ViewLimit);
    }

    private static async ValueTask<InfisicalAccessToken> SelectedToken(IInfisicalTokenSource source, CancellationToken token)
    {
        var selected = await source.GetTokenAsync(token);
        if (!selected.IsSuccess) throw new NativeCaseFailureException("missing-input");
        return selected.Value;
    }
    private sealed record LookupFacts(string OrganizationId, string OwnedName, SecretStatus Status, string? ShareId)
    {
        public override string ToString() => "[ShareLookupFacts]";
    }
    private sealed record ViewFacts(string ShareId, int ConsumedViews)
    {
        public override string ToString() => "[ShareViewFacts]";
    }
    private sealed record DeliveryFacts(string OrganizationId, string ShareId, SecretStatus RecipientStatus,
        SecretStatus DeniedStatus, int ViewsBefore, int ViewsAfter, DateTimeOffset ExpiresAt,
        DateTimeOffset ExpiredObservationTime, SecretStatus ExpiredStatus, string? Material, ShareAudience Audience,
        int? MaximumViews, bool? AllowExternalEmails, string[]? AuthorizedEmails, ShareViewLimitFacts? ViewLimit = null)
    {
        public override string ToString() => "[ShareDeliveryMeasurement]";
    }
}
