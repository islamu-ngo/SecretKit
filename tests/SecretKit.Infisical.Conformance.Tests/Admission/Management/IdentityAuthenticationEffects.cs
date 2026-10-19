using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class IdentityAuthenticationEffects
{
    internal static string? UnavailableReason(NativeCaseDefinition d) =>
        d.Key.Case == "lost-response-no-replay" &&
        d.Key.Operation is "i.management.IdentityAuthenticationOperations.CreateToken" or
            "i.management.IdentityAuthenticationOperations.CreateUniversalClientSecret" ?
            "lost-credential-material-cannot-be-recovered-or-replayed" : null;

    internal static async ValueTask ExecuteAsync(IdentityAuthContext c, CancellationToken token)
    {
        await c.EnsureIdentityAsync(token);
        await c.EnsureConsumerAsync(token);
        if (c.Operation == "ClearUniversalAuthLockouts")
            await LockoutAsync(c, token);
        else if (c.Operation.EndsWith("Auth", StringComparison.Ordinal))
            await ConfigurationAsync(c, token);
        else if (c.Operation.Contains("ClientSecret", StringComparison.Ordinal))
            await CredentialAsync(c, token);
        else await TokenAsync(c, token);
    }

    private static TokenAuthConfigurationInput Policy(IdentityAuthContext c, bool before)
    {
        string v = c.Variant;
        bool Omitted(string field) => !before && v.EndsWith(field + ".omitted", StringComparison.Ordinal);
        int? ttl = Omitted("accessTokenTTL") ? null : before ? 300 : v == "tokenTTL.zero" ? 0 : 600;
        int? maximum = Omitted("accessTokenMaxTTL") ? null : before ? 1200 : v == "tokenMaxTTL.zero" ? 0 : 1800;
        long? uses = Omitted("accessTokenNumUsesLimit") ? null : before ? 1000 : 2000;
        return new(ttl, maximum, uses);
    }

    private static UniversalAuthConfigurationInput Universal(IdentityAuthContext c, bool before, bool lockout = false)
    {
        TokenAuthConfigurationInput policy = Policy(c, before);
        string v = c.Variant;
        bool Omitted(string field) => !before && v.EndsWith(field + ".omitted", StringComparison.Ordinal);
        bool Contrast(string field) => before && c.Operation.StartsWith("Update", StringComparison.Ordinal) &&
            v.EndsWith(field + ".value", StringComparison.Ordinal);
        bool enabled = v.EndsWith("lockoutEnabled.true", StringComparison.Ordinal);
        if (before && c.Operation.StartsWith("Update", StringComparison.Ordinal) &&
            (v.EndsWith("lockoutEnabled.true", StringComparison.Ordinal) ||
                v.EndsWith("lockoutEnabled.false", StringComparison.Ordinal))) enabled = !enabled;
        return new(policy.AccessTokenTTL, policy.AccessTokenMaxTTL, policy.AccessTokenNumUsesLimit,
            Omitted("accessTokenPeriod") ? null : !before && v is "tokenPeriod.positive" or
                "UniversalAuthConfigurationInput.accessTokenPeriod.value" ? 600 : 0,
            lockoutEnabled: lockout ? true : Omitted("lockoutEnabled") ? null : enabled,
            lockoutThreshold: lockout ? 1 : Omitted("lockoutThreshold") ? null : Contrast("lockoutThreshold") ? 4 : 5,
            lockoutDurationSeconds: Omitted("lockoutDurationSeconds") ? null : Contrast("lockoutDurationSeconds") ? 43200 : 86400,
            lockoutCounterResetSeconds: Omitted("lockoutCounterResetSeconds") ? null : Contrast("lockoutCounterResetSeconds") ? 1800 : 3600);
    }

    private static bool Matches(IdentityAuthContext c, IdentityAuthenticationConfiguration config,
        TokenAuthConfigurationInput policy, bool update)
    {
        double Expected(string name, long? value, long before) => value ??
            (update ? before : double.Parse(c.Required(name), System.Globalization.CultureInfo.InvariantCulture));
        return config.IdentityId == c.IdentityId &&
            config.AccessTokenTTL == Expected("defaultTokenTTL", policy.AccessTokenTTL, 300) &&
            config.AccessTokenMaxTTL == Expected("defaultTokenMaxTTL", policy.AccessTokenMaxTTL, 1200) &&
            config.AccessTokenNumUsesLimit == Expected("defaultTokenUses", policy.AccessTokenNumUsesLimit, 1000);
    }

    private static async ValueTask ConfigurationAsync(IdentityAuthContext c, CancellationToken token)
    {
        string org = c.OrganizationId, id = c.IdentityId;
        bool universal = c.Operation.Contains("Universal", StringComparison.Ordinal);
        bool attach = c.Operation.StartsWith("Attach", StringComparison.Ordinal);
        bool update = c.Operation.StartsWith("Update", StringComparison.Ordinal);
        bool delete = c.Operation.StartsWith("Delete", StringComparison.Ordinal);
        TokenAuthConfigurationInput initialToken = Policy(c, !attach), changedToken = Policy(c, false);
        UniversalAuthConfigurationInput initialUniversal = Universal(c, !attach), changedUniversal = Universal(c, false);
        Func<ManagementRequest<IdentityAuthenticationConfiguration>> get = () => universal ?
            IdentityAuthenticationOperations.GetUniversalAuth(org, id) : IdentityAuthenticationOperations.GetTokenAuth(org, id);
        Func<ManagementRequest<IdentityAuthenticationConfiguration>> configure = () => universal ?
            IdentityAuthenticationOperations.AttachUniversalAuth(org, id, initialUniversal) :
            IdentityAuthenticationOperations.AttachTokenAuth(org, id, initialToken);
        bool Match(IdentityAuthenticationConfiguration value, bool changed)
        {
            TokenAuthConfigurationInput policy = universal ? (changed ? changedUniversal : initialUniversal).Policy :
                changed ? changedToken : initialToken;
            bool matches = Matches(c, value, policy, update);
            if (universal)
            {
                UniversalAuthConfigurationInput input = changed ? changedUniversal : initialUniversal;
                matches &= value.AccessTokenPeriod == (input.AccessTokenPeriod ?? (update ? 0 :
                    double.Parse(c.Required("defaultTokenPeriod"), System.Globalization.CultureInfo.InvariantCulture))) &&
                    value.LockoutEnabled == (input.LockoutEnabled ?? false) &&
                    value.LockoutThreshold == (input.LockoutThreshold ?? (update ? 5 :
                        double.Parse(c.Required("defaultLockoutThreshold"), System.Globalization.CultureInfo.InvariantCulture))) &&
                    value.LockoutDurationSeconds == (input.LockoutDurationSeconds ?? (update ? 86400 :
                        double.Parse(c.Required("defaultLockoutDurationSeconds"), System.Globalization.CultureInfo.InvariantCulture))) &&
                    value.LockoutCounterResetSeconds == (input.LockoutCounterResetSeconds ?? (update ? 3600 :
                        double.Parse(c.Required("defaultLockoutCounterResetSeconds"), System.Globalization.CultureInfo.InvariantCulture)));
            }
            return matches;
        }
        UniversalAuthClientSecretCreation? credential = null;
        string clientId = "unconfigured-" + Guid.NewGuid().ToString("N");
        try
        {
            async ValueTask<bool> Authentication(bool present, CancellationToken ct)
            {
                IdentityAuthenticationConfiguration? configuration = present ?
                    await c.NeedAsync(get, NativeIdentityRole.Observer, ct) : null;
                if (!universal)
                {
                    SecretOutcome<TokenAuthTokenCreation> result = await c.ExecuteAsync(
                        () => IdentityAuthenticationOperations.CreateToken(org, id), NativeIdentityRole.Setup, ct);
                    using TokenAuthTokenCreation? issued = result.IsSuccess ? result.Value : null;
                    if (!present) return result.Status == SecretStatus.Denied;
                    if (!result.IsSuccess || issued is null || configuration is null ||
                        !c.TokenMatchesPolicy(issued.Metadata, configuration) ||
                        issued.ExpiresIn != configuration.AccessTokenTTL ||
                        issued.AccessTokenMaxTTL != configuration.AccessTokenMaxTTL ||
                        !await c.UseTokenAsync(issued.AccessToken, true, ct)) return false;
                    await c.NeedAsync(() => IdentityAuthenticationOperations.RevokeToken(org, issued.Metadata.Id), NativeIdentityRole.Setup, ct);
                    return await c.UseTokenAsync(issued.AccessToken, false, ct);
                }
                if (present && credential is null)
                {
                    clientId = configuration!.ClientId!;
                    credential = await c.NeedAsync(() => IdentityAuthenticationOperations.CreateUniversalClientSecret(org, id),
                        NativeIdentityRole.Setup, ct);
                }
                using SecretMaterial unknown = SecretMaterial.FromText(Guid.NewGuid().ToString("N"));
                foreach (bool denied in new[] { false, true })
                {
                    using SecretMaterial secret = !denied && credential is not null ? credential.ClientSecret.Copy() : unknown.Copy();
                    if (!await UniversalLoginAsync(c, clientId, secret, present && !denied, configuration, ct)) return false;
                }
                return true;
            }
            if (!attach)
            {
                await c.NeedAsync(configure, NativeIdentityRole.Setup, token);
                IdentityAuthenticationConfiguration baseline = await c.NeedAsync(get, NativeIdentityRole.Observer, token);
                c.Probe.Contract(Match(baseline, false) && await Authentication(true, token), NativeFailure.MissingPrerequisite);
            }
            else
            {
                SecretOutcome<IdentityAuthenticationConfiguration> absent = await c.ExecuteAsync(get, NativeIdentityRole.Observer, token);
                c.Probe.Contract(absent.Status == SecretStatus.Absent, NativeFailure.MissingPrerequisite);
            }
            Func<ManagementRequest<IdentityAuthenticationConfiguration>> request = attach ? configure : update ? () => universal ?
                IdentityAuthenticationOperations.UpdateUniversalAuth(org, id, changedUniversal) :
                IdentityAuthenticationOperations.UpdateTokenAuth(org, id, changedToken) : delete ? () => universal ?
                IdentityAuthenticationOperations.DeleteUniversalAuth(org, id) : IdentityAuthenticationOperations.DeleteTokenAuth(org, id) : get;
            await c.CaseAsync(request, value => Match(value, attach || update), async (applied, ct) =>
            {
                bool present = attach ? applied : !(delete && applied);
                SecretOutcome<IdentityAuthenticationConfiguration> observed = await c.ExecuteAsync(get, NativeIdentityRole.Observer, ct);
                return (present ? observed.IsSuccess && Match(observed.Value, applied && (attach || update)) :
                    observed.Status == SecretStatus.Absent) && await Authentication(present, ct);
            }, token);
        }
        finally { credential?.Dispose(); }
    }

    private static async ValueTask<bool> UniversalLoginAsync(IdentityAuthContext c, string clientId, SecretMaterial secret,
        bool enabled, IdentityAuthenticationConfiguration? configuration, CancellationToken token)
    {
        ManagementPage<TokenAuthToken> before = await c.NeedAsync(
            () => IdentityAuthenticationOperations.ListTokens(c.OrganizationId, c.IdentityId), NativeIdentityRole.Observer, token);
        if (!before.IsComplete) return false;
        using var authentication = new InfisicalUniversalAuthentication(c.Environment.Origin, c.Network);
        InfisicalUniversalLoginReceipt receipt = authentication.CreateReceipt();
        SecretOutcome<InfisicalUniversalLogin> outcome = await authentication.LoginAsync(clientId, secret, receipt,
            cancellationToken: token);
        using InfisicalUniversalLogin? login = outcome.IsSuccess ? outcome.Value : null;
        if (enabled)
        {
            if (configuration is null || !outcome.IsSuccess || receipt.Evidence != DispatchEvidence.Applied ||
                login!.ExpiresIn != (configuration.AccessTokenPeriod > 0 ? configuration.AccessTokenPeriod : configuration.AccessTokenTTL) ||
                login.AccessTokenMaxTTL != (configuration.AccessTokenPeriod > 0 ? 0 : configuration.AccessTokenMaxTTL) ||
                !await c.UseTokenAsync(login.Token.Material, true, token)) return false;
        }
        else if (outcome.Status != SecretStatus.Denied || receipt.Evidence != DispatchEvidence.Rejected) return false;
        ManagementPage<TokenAuthToken> after = await c.NeedAsync(
            () => IdentityAuthenticationOperations.ListTokens(c.OrganizationId, c.IdentityId), NativeIdentityRole.Observer, token);
        if (!after.IsComplete || after.Items.Count != before.Items.Count + (enabled ? 1 : 0)) return false;
        TokenAuthToken[] issued = after.Items.Where(t => before.Items.All(b => b.Id != t.Id)).ToArray();
        return enabled ? issued.Length == 1 && issued[0].IdentityId == c.IdentityId &&
            issued[0].AuthMethod == "universal-auth" && issued[0].IsAccessTokenRevoked == false &&
            c.TokenMatchesPolicy(issued[0], configuration!) : issued.Length == 0;
    }

    private static async ValueTask TokenAsync(IdentityAuthContext c, CancellationToken token)
    {
        string org = c.OrganizationId, id = c.IdentityId;
        bool create = c.Operation == "CreateToken", revoke = c.Operation == "RevokeToken", rename = c.Operation == "RenameToken";
        await c.NeedAsync(() => IdentityAuthenticationOperations.AttachTokenAuth(org, id, new(600, 1800, 2000)),
            NativeIdentityRole.Setup, token);
        IdentityAuthenticationConfiguration configuration = await c.NeedAsync(
            () => IdentityAuthenticationOperations.GetTokenAuth(org, id), NativeIdentityRole.Observer, token);
        c.Probe.Contract(configuration.AccessTokenTTL == 600 && configuration.AccessTokenMaxTTL == 1800 &&
            configuration.AccessTokenNumUsesLimit == 2000, NativeFailure.MissingPrerequisite);
        TokenAuthTokenCreation? seeded = create ? null : await c.NeedAsync(
            () => IdentityAuthenticationOperations.CreateToken(org, id, "before"), NativeIdentityRole.Setup, token);
        SecretMaterial? issuedMaterial = null;
        string? tokenId = seeded?.Metadata.Id;
        string? name = c.Variant == "name.omitted" ? null : "after-" + Guid.NewGuid().ToString("N");
        string? slug = c.Variant == "organizationSlug.value" ? c.Required("organizationSlug") : null;
        try
        {
            if (seeded is not null) c.Probe.Contract(c.TokenMatchesPolicy(seeded.Metadata, configuration) &&
                seeded.ExpiresIn == configuration.AccessTokenTTL && seeded.AccessTokenMaxTTL == configuration.AccessTokenMaxTTL &&
                await c.UseTokenAsync(seeded.AccessToken, true, token), NativeFailure.MissingPrerequisite);
            async ValueTask<bool> Observe(bool applied, CancellationToken ct)
            {
                ManagementPage<TokenAuthToken> page = await c.NeedAsync(() => IdentityAuthenticationOperations.ListTokens(org, id),
                    NativeIdentityRole.Observer, ct);
                if (!page.IsComplete || page.Items.Count != (create && !applied ? 0 : 1)) return false;
                if (create && !applied) return true;
                TokenAuthToken row = page.Items.Single();
                if (tokenId is not null && row.Id != tokenId || row.IdentityId != id ||
                    row.AuthMethod != "token-auth" || row.IsAccessTokenRevoked != (revoke && applied) ||
                    !c.TokenMatchesPolicy(row, configuration)) return false;
                string? expectedName = create ? name : rename && applied ? name ?? "before" : "before";
                if (expectedName is not null && (!row.Name.IsPresent || row.Name.IsNull || row.Name.Value != expectedName)) return false;
                SecretOutcome<TokenAuthToken> exact = await c.ExecuteAsync(
                    () => IdentityAuthenticationOperations.GetToken(org, row.Id), NativeIdentityRole.Observer, ct);
                if (!exact.IsSuccess || exact.Value.IdentityId != id || exact.Value.IsAccessTokenRevoked != row.IsAccessTokenRevoked)
                    return false;
                return await c.UseTokenAsync(create ? issuedMaterial! : seeded!.AccessToken, !(revoke && applied), ct);
            }
            if (create)
                await c.CaseAsync(() => IdentityAuthenticationOperations.CreateToken(org, id, name, slug), value =>
                {
                    tokenId = value.Metadata.Id;
                    issuedMaterial = value.AccessToken.Copy();
                    return value.Metadata.IdentityId == id && value.Metadata.AuthMethod == "token-auth" &&
                        c.TokenMatchesPolicy(value.Metadata, configuration) && value.ExpiresIn == configuration.AccessTokenTTL &&
                        value.AccessTokenMaxTTL == configuration.AccessTokenMaxTTL;
                }, Observe, token);
            else if (revoke)
                await c.CaseAsync(() => IdentityAuthenticationOperations.RevokeToken(org, tokenId!), _ => true, Observe, token);
            else if (rename)
                await c.CaseAsync(() => IdentityAuthenticationOperations.RenameToken(org, tokenId!, name),
                    value => value.Id == tokenId && value.IdentityId == id, Observe, token);
            else if (c.Operation == "GetToken")
                await c.CaseAsync(() => IdentityAuthenticationOperations.GetToken(org, tokenId!),
                    value => value.Id == tokenId && value.IdentityId == id, Observe, token);
            else
                await c.CaseAsync(() => IdentityAuthenticationOperations.ListTokens(org, id),
                    page => page.IsComplete && page.Items.Count == 1 && page.Items[0].Id == tokenId, Observe, token);
        }
        finally { issuedMaterial?.Dispose(); seeded?.Dispose(); }
    }

    private static async ValueTask CredentialAsync(IdentityAuthContext c, CancellationToken token)
    {
        string org = c.OrganizationId, id = c.IdentityId;
        bool create = c.Operation == "CreateUniversalClientSecret", revoke = c.Operation == "RevokeUniversalClientSecret";
        IdentityAuthenticationConfiguration configuration = await c.NeedAsync(
            () => IdentityAuthenticationOperations.AttachUniversalAuth(org, id, new(600, 1800, 2000, 0)),
            NativeIdentityRole.Setup, token);
        UniversalAuthClientSecretCreation? seeded = create ? null : await c.NeedAsync(
            () => IdentityAuthenticationOperations.CreateUniversalClientSecret(org, id, "before", 1000, 3600),
            NativeIdentityRole.Setup, token);
        SecretMaterial? issuedMaterial = null;
        string? credentialId = seeded?.Metadata.Id;
        string? description = c.Variant == "description.omitted" ? null : "owned-" + Guid.NewGuid().ToString("N");
        double? uses = c.Variant == "numUsesLimit.omitted" ? null : 1000;
        double? ttl = c.Variant == "ttl.omitted" ? null : 3600;
        try
        {
            async ValueTask<bool> Login(SecretMaterial secret, bool enabled, CancellationToken ct)
            {
                IdentityAuthenticationConfiguration observed = await c.NeedAsync(
                    () => IdentityAuthenticationOperations.GetUniversalAuth(org, id), NativeIdentityRole.Observer, ct);
                return observed.AccessTokenTTL == 600 && observed.AccessTokenMaxTTL == 1800 &&
                    observed.AccessTokenNumUsesLimit == 2000 && observed.AccessTokenPeriod == 0 &&
                    await UniversalLoginAsync(c, configuration.ClientId!, secret, enabled, observed, ct);
            }
            if (seeded is not null) c.Probe.Contract(await Login(seeded.ClientSecret, true, token), NativeFailure.MissingPrerequisite);
            async ValueTask<bool> Observe(bool applied, CancellationToken ct)
            {
                ManagementPage<UniversalAuthClientSecret> page = await c.NeedAsync(
                    () => IdentityAuthenticationOperations.ListUniversalClientSecrets(org, id), NativeIdentityRole.Observer, ct);
                if (!page.IsComplete || page.Items.Count != (create && !applied ? 0 : 1)) return false;
                if (create && !applied) return true;
                UniversalAuthClientSecret row = page.Items.Single();
                if (row.Id != credentialId || row.IdentityUAId != configuration.Id || row.IsClientSecretRevoked != (revoke && applied) ||
                    create && (description is not null && row.Description != description ||
                        uses is not null && row.ClientSecretNumUsesLimit != uses || ttl is not null && row.ClientSecretTTL != ttl)) return false;
                SecretOutcome<UniversalAuthClientSecret> exact = await c.ExecuteAsync(
                    () => IdentityAuthenticationOperations.GetUniversalClientSecret(org, id, row.Id), NativeIdentityRole.Observer, ct);
                if (!exact.IsSuccess || exact.Value.IdentityUAId != configuration.Id ||
                    exact.Value.IsClientSecretRevoked != row.IsClientSecretRevoked) return false;
                using SecretMaterial wrong = SecretMaterial.FromText(Guid.NewGuid().ToString("N"));
                return await Login(create ? issuedMaterial! : seeded!.ClientSecret, !(revoke && applied), ct) &&
                    await Login(wrong, false, ct);
            }
            if (create)
                await c.CaseAsync(() => IdentityAuthenticationOperations.CreateUniversalClientSecret(org, id, description, uses, ttl), value =>
                {
                    credentialId = value.Metadata.Id;
                    issuedMaterial = value.ClientSecret.Copy();
                    return value.Metadata.IdentityUAId == configuration.Id;
                }, Observe, token);
            else if (revoke)
                await c.CaseAsync(() => IdentityAuthenticationOperations.RevokeUniversalClientSecret(org, id, credentialId!),
                    value => value.Id == credentialId && value.IsClientSecretRevoked == true, Observe, token);
            else if (c.Operation == "GetUniversalClientSecret")
                await c.CaseAsync(() => IdentityAuthenticationOperations.GetUniversalClientSecret(org, id, credentialId!),
                    value => value.Id == credentialId && value.IdentityUAId == configuration.Id, Observe, token);
            else
                await c.CaseAsync(() => IdentityAuthenticationOperations.ListUniversalClientSecrets(org, id),
                    page => page.IsComplete && page.Items.Count == 1 && page.Items[0].Id == credentialId, Observe, token);
        }
        finally { issuedMaterial?.Dispose(); seeded?.Dispose(); }
    }

    private static async ValueTask LockoutAsync(IdentityAuthContext c, CancellationToken token)
    {
        string org = c.OrganizationId, id = c.IdentityId;
        IdentityAuthenticationConfiguration config = await c.NeedAsync(
            () => IdentityAuthenticationOperations.AttachUniversalAuth(org, id, Universal(c, true, true)),
            NativeIdentityRole.Setup, token);
        using UniversalAuthClientSecretCreation credential = await c.NeedAsync(
            () => IdentityAuthenticationOperations.CreateUniversalClientSecret(org, id), NativeIdentityRole.Setup, token);
        using var authentication = new InfisicalUniversalAuthentication(c.Environment.Origin, c.Network);
        using SecretMaterial wrong = SecretMaterial.FromText(Guid.NewGuid().ToString("N"));
        SecretOutcome<InfisicalUniversalLogin> induced = await authentication.LoginAsync(config.ClientId!, wrong,
            authentication.CreateReceipt(), cancellationToken: token);
        if (induced.IsSuccess) induced.Value.Dispose();
        IdentitySummary baseline = await c.NeedAsync(() => IdentityOperations.GetOrganizationIdentity(org, id),
            NativeIdentityRole.Observer, token);
        c.Probe.Contract(induced.Status == SecretStatus.Denied && baseline.ActiveLockoutAuthMethods.IsPresent &&
            baseline.ActiveLockoutAuthMethods.Value.Contains("universal-auth", StringComparer.Ordinal), NativeFailure.MissingPrerequisite);
        await c.CaseAsync(() => IdentityAuthenticationOperations.ClearUniversalAuthLockouts(org, id),
            result => result.Deleted > 0, async (applied, ct) =>
            {
                IdentitySummary observed = await c.NeedAsync(() => IdentityOperations.GetOrganizationIdentity(org, id),
                    NativeIdentityRole.Observer, ct);
                if (!observed.ActiveLockoutAuthMethods.IsPresent ||
                    observed.ActiveLockoutAuthMethods.Value.Contains("universal-auth", StringComparer.Ordinal) == applied) return false;
                IdentityAuthenticationConfiguration configuration = await c.NeedAsync(
                    () => IdentityAuthenticationOperations.GetUniversalAuth(org, id), NativeIdentityRole.Observer, ct);
                return await UniversalLoginAsync(c, config.ClientId!, credential.ClientSecret, applied, configuration, ct);
            }, token);
    }
}
