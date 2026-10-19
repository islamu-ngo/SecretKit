using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// The host validates source facts too: an injected observer is not a trust bypass.
internal sealed class LdapLoginTrial
{
    private readonly ProjectFamilyContext c;
    private readonly ILdapLoginObserver source;
    private readonly LdapDirectoryCredentials credentials;
    private readonly Canary allowed;
    private readonly Canary denied;
    private readonly string canaryValue;
    private readonly string filter;
    private readonly TimeSpan timeout;
    private readonly HashSet<string> registrations = new(StringComparer.Ordinal);
    private readonly HashSet<string> events = new(StringComparer.Ordinal);
    private readonly HashSet<string> requests = new(StringComparer.Ordinal);
    private readonly HashSet<string> tokenIds = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTimeOffset> lastLogins = new(StringComparer.Ordinal);
    private long sequence;
    private DateTimeOffset time;
    private int loginEvents;
    private bool rotated;
    private bool sealedVisibility;
    private bool outstanding;

    private LdapLoginTrial(ProjectFamilyContext context, ILdapLoginObserver observer,
        LdapDirectoryCredentials packet, Canary permitted, Canary forbidden, string value,
        string searchFilter, TimeSpan caseTimeout)
    {
        c = context;
        source = observer;
        credentials = packet;
        allowed = permitted;
        denied = forbidden;
        canaryValue = value;
        filter = searchFilter;
        timeout = caseTimeout;
    }

    internal LdapDirectoryBinding Directory { get; private set; } = null!;
    internal LdapLoginFence? LastLogin { get; private set; }

    internal static async ValueTask<LdapLoginTrial?> CreateAsync(ProjectFamilyContext c, CancellationToken token)
    {
        if (!c.Input.TryGetProperty("ldapWitness", out JsonElement profile))
        {
            if (c.LdapObserver is not null) throw new NativeCaseFailureException("missing-input");
            return null;
        }
        if (profile.ValueKind != JsonValueKind.Object ||
            !profile.TryGetProperty("caseTimeoutSeconds", out JsonElement seconds) ||
            seconds.ValueKind != JsonValueKind.Number ||
            !seconds.TryGetInt32(out int duration) || duration is < 1 or > 900)
            throw new NativeCaseFailureException("missing-input");
        string deployment = Text(profile, "deploymentId");
        string selected = Text(profile, "sourceProfile");
        bool controlled = selected == "controlled-fixture";
        ILdapLoginObserver? observer = c.LdapObserver;
        if (observer is not null && !controlled) throw new NativeCaseFailureException("missing-input");
        if (observer is null)
        {
            if (controlled) throw new NativeCaseFailureException("observer-unavailable");
            observer = InfisicalLdapLoginObserver.FromInputs(c.Environment,
                "C08-IM-" + InfisicalIdentityFamilies.Family(c.Definition));
        }
        if (observer is null) throw new NativeCaseFailureException("observer-unavailable");
        string nonce = c.Required("ldapRootNonce");
        string url = c.Required("ldapUrl"), dn = c.Required("bindDn"), search = c.Required("searchBase");
        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri) || uri.Scheme is not ("ldap" or "ldaps") ||
            uri.Host.Length == 0 || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0 ||
            !url.Contains(nonce, StringComparison.Ordinal) || !dn.Contains(nonce, StringComparison.Ordinal) ||
            !search.Contains(nonce, StringComparison.Ordinal))
            throw new NativeCaseFailureException("missing-input");
        if (!c.Input.TryGetProperty("ldapCanaries", out JsonElement canaries) ||
            canaries.ValueKind != JsonValueKind.Object)
            throw new NativeCaseFailureException("missing-input");
        Canary allowed = ReadCanary(canaries, "allowed"), denied = ReadCanary(canaries, "denied");
        if (allowed.Project == denied.Project) throw new NativeCaseFailureException("missing-input");
        string value = c.Required("ldapCanaryValue"), filter = c.Required("ldapSearchFilter");
        string username = c.Required("ldapUsername");
        if (!Id(c.OrganizationId)) throw new NativeCaseFailureException("missing-input");
        string[] passwords = [c.Required("originalBindPassword"), c.Required("bindPassword"),
            c.Required("wrongBindPassword"), c.Required("ldapUserPassword"), c.Required("ldapWrongUserPassword")];
        if (passwords.Distinct(StringComparer.Ordinal).Count() != 5)
            throw new NativeCaseFailureException("missing-input");
        using var original = SecretMaterial.FromText(passwords[0]);
        using var next = SecretMaterial.FromText(passwords[1]);
        using var wrong = SecretMaterial.FromText(passwords[2]);
        using var user = SecretMaterial.FromText(passwords[3]);
        using var wrongUser = SecretMaterial.FromText(passwords[4]);
        var packet = new LdapDirectoryCredentials(original, next, wrong, user, wrongUser);
        var trial = new LdapLoginTrial(c, observer, packet, allowed, denied, value, filter,
            TimeSpan.FromSeconds(duration));
        var attempt = new LdapDirectoryAttempt(Guid.NewGuid().ToString("D"),
            c.Definition.Key.Operation + "/" + c.Variant + "/" + c.Definition.Key.Case,
            "v0.166.3", deployment, c.OrganizationId, nonce, url, dn, search, username,
            controlled ? LdapLoginSource.ControlledFixture : LdapLoginSource.NativeProvider);
        // Registered first, so all later token/binding/identity/template ownership
        // is cleaned before the directory closes, even when Open loses its reply.
        c.Cleanup(async cleanupToken =>
        {
            try
            {
                var closed = await observer.CloseAsync(attempt, cleanupToken);
                return closed.Attempt == attempt && closed.Closed && closed.OwnedRootRemoved &&
                    closed.UnrelatedRootsPreserved && closed.CredentialsDestroyed && closed.MutationSettled &&
                    closed.LateCreationFenced && closed.RemainingRegistrations == 0 && closed.PendingDeliveries == 0;
            }
            finally { packet.Dispose(); }
        });
        using var deadline = trial.Deadline(token);
        var opened = await observer.OpenAsync(attempt, packet, deadline.Token);
        Require(opened.Attempt == attempt && Unique(trial.registrations, opened.RegistrationId) &&
            ValidText(opened.SourceIdentity) &&
            opened.SourceIdentity is not ("setup" or "administrative" or "observer" or "runtime" or "denied") &&
            opened.ClockAuthority == "provider-application-clock" && ValidText(opened.ClockEpoch) &&
            Utc(opened.OpenedAt) && opened.Sequence >= 0 && opened.OwnedRootCreated &&
            opened.RootInitiallyAbsent && opened.ServiceBindAccepted && opened.WrongServiceBindRejected &&
            opened.UserBindAccepted && opened.WrongUserBindRejected);
        trial.Directory = opened;
        trial.sequence = opened.Sequence;
        trial.time = opened.OpenedAt;
        return trial;
    }

    internal async ValueTask RotateAsync(CancellationToken token)
    {
        Require(!rotated && !sealedVisibility && !outstanding);
        rotated = true; // No replay after a lost source reply.
        using var deadline = Deadline(token);
        var facts = await source.RotateAsync(Directory, deadline.Token);
        Require(facts.Binding == Directory && Next(facts.Sequence) && Unique(events, facts.EventId) &&
            facts.OriginalServiceRejected && facts.RotatedServiceAccepted &&
            facts.UserCredentialUnchanged && facts.OwnedRootOnly);
    }

    internal async ValueTask<string> CreateTemplateAsync(string name, LdapServiceCredential credential,
        CancellationToken token)
    {
        Action<string> acknowledge = IdentityTemplatesEffects.Own(c, IdentityTemplateAuthMethod.Ldap, [name]);
        using var fields = new IdentityTemplateLdapFields(Directory.Attempt.Url, Directory.Attempt.BindDn,
            credential == LdapServiceCredential.Original ? credentials.Original : credentials.Rotated,
            Directory.Attempt.SearchBase, c.Optional("ldapCaCertificate"));
        var template = await c.NeedAsync(() => IdentityTemplatesEffects.Create(c, name, fields),
            NativeIdentityRole.Setup, token);
        acknowledge(template.Id);
        return template.Id;
    }

    internal async ValueTask AttachAsync(string template, string identity, CancellationToken token)
    {
        // Remove only this owned attachment before the identity/template cleanup.
        c.Cleanup(async cleanupToken =>
        {
            var read = await c.ExecuteAsync(() => ExternalIdentityAuthenticationOperations.GetLdapAuth(
                c.OrganizationId, identity), NativeIdentityRole.Observer, cleanupToken);
            if (read.Status == SecretStatus.Absent) return true;
            if (!read.IsSuccess) return false;
            using var config = read.Value;
            if (!config.TemplateId.IsPresent || config.TemplateId.IsNull || config.TemplateId.Value != template)
                return false;
            using var removed = await c.NeedAsync(() => ExternalIdentityAuthenticationOperations.DeleteLdapAuth(
                c.OrganizationId, identity), NativeIdentityRole.Setup, cleanupToken);
            var absent = await c.ExecuteAsync(() => ExternalIdentityAuthenticationOperations.GetLdapAuth(
                c.OrganizationId, identity), NativeIdentityRole.Observer, cleanupToken);
            return absent.Status == SecretStatus.Absent;
        });
        using var input = LdapAuthConfigurationInput.FromTemplate(template, settings: new(searchFilter: filter));
        using var result = await c.NeedAsync(() => ExternalIdentityAuthenticationOperations.AttachLdapAuth(
            c.OrganizationId, identity, input), NativeIdentityRole.Setup, token);
        Require(result.IdentityId == identity && result.TemplateId.IsPresent &&
            !result.TemplateId.IsNull && result.TemplateId.Value == template);
    }

    internal async ValueTask GrantCanaryAsync(string identity, CancellationToken token)
    {
        var before = await c.ExecuteAsync(() => MembershipOperations.GetProjectIdentityMembership(
            c.OrganizationId, allowed.Project, identity), NativeIdentityRole.Observer, token);
        Require(before.Status == SecretStatus.Absent);
        var grant = await c.NeedAsync(() => MembershipOperations.AddProjectIdentity(c.OrganizationId,
            allowed.Project, identity, new MembershipRoleSelection(roles: [new("viewer")])),
            NativeIdentityRole.Setup, token);
        Require(grant.PrincipalId == identity);
        // Organization identity ownership removes this exact membership as well.
        var observed = await c.NeedAsync(() => MembershipOperations.GetProjectIdentityMembership(
            c.OrganizationId, allowed.Project, identity), NativeIdentityRole.Observer, token);
        Require(observed.IdentityId == identity && observed.Roles.Count == 1 &&
            observed.Roles[0].Role == "viewer" && observed.Roles[0].IsTemporary != true);
        var outside = await c.ExecuteAsync(() => MembershipOperations.GetProjectIdentityMembership(
            c.OrganizationId, denied.Project, identity), NativeIdentityRole.Observer, token);
        Require(outside.Status == SecretStatus.Absent);
    }

    internal async ValueTask<LdapLoginFence> LoginAsync(string identity, string template,
        LdapServiceCredential credential, bool wrongUser, bool expectedSuccess, CancellationToken token)
    {
        Require(!sealedVisibility && !outstanding);
        var membership = await c.NeedAsync(() => IdentityOperations.GetOrganizationIdentity(
            c.OrganizationId, identity), NativeIdentityRole.Observer, token);
        Require(membership.Id == identity && Id(identity) && Id(template) && membership.Membership.IsPresent &&
            Id(membership.Membership.Value.Id));
        var attempt = new LdapLoginAttempt(Directory, Guid.NewGuid().ToString("D"), identity,
            membership.Membership.Value.Id, template, credential, wrongUser);
        outstanding = true;
        using var deadline = Deadline(token);
        var arm = await source.ArmAsync(attempt, deadline.Token);
        Require(arm.Attempt == attempt && Unique(registrations, arm.RegistrationId) &&
            arm.Cursor >= sequence && Utc(arm.ArmedAt) && arm.ArmedAt >= time && arm.CaptureArmed);
        sequence = arm.Cursor;
        time = arm.ArmedAt;
        using var authentication = new InfisicalProofAuthentication(c.Environment.Origin,
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = c.Environment.AllowLoopbackDevelopmentHttp });
        using var proof = InfisicalLoginProof.Ldap(identity, Directory.Attempt.Username,
            wrongUser ? credentials.WrongUser : credentials.User);
        var receipt = authentication.CreateReceipt();
        SecretOutcome<InfisicalProofLogin>? outcome = null;
        LdapLoginFence facts;
        try
        {
            try { outcome = await authentication.LoginAsync(proof, receipt, deadline.Token); }
            finally
            {
                // Settle the original attempt even if the SDK operation was cancelled.
                using var settle = new CancellationTokenSource(timeout);
                facts = await source.CompleteAsync(arm, receipt.Evidence,
                    outcome?.Status ?? SecretStatus.Unknown, settle.Token);
            }
            Require(facts.Arm == arm && Compatible(receipt.Evidence, facts.Disposition) &&
                facts.Status == outcome!.Status && Next(facts.Sequence) && Unique(events, facts.EventId) &&
                Unique(requests, facts.ProviderRequestId) && facts.MatchedRequests == 1 &&
                facts.ProviderClockObserved && facts.ExcludesLateCommit);
            loginEvents += facts.MatchedRequests;
            outstanding = false;
            bool serviceAccepted = credential == (rotated ? LdapServiceCredential.Rotated : LdapServiceCredential.Original);
            Require(facts.ServiceBindAccepted == serviceAccepted && facts.UserBindAttempted == serviceAccepted &&
                facts.UserBindAccepted == (serviceAccepted && !wrongUser));
            if (!expectedSuccess)
            {
                Require(outcome.Status == SecretStatus.Denied && !facts.TokenIssued &&
                    facts.MatchedIssuances == 0 && facts.TokenMetadataId is null &&
                    facts.LastLoginAt is null && facts.LastLoginAuthMethod is null && facts.CredentialWitness is null);
                return facts;
            }
            Require(!wrongUser && outcome.IsSuccess && facts.TokenIssued && facts.MatchedIssuances == 1 &&
                Id(facts.TokenMetadataId) && Unique(tokenIds, facts.TokenMetadataId) &&
                facts.LastLoginAt is { } at && Utc(at) &&
                (at >= time || lastLogins.TryGetValue(identity, out DateTimeOffset prior) && at == prior &&
                    arm.ArmedAt >= prior && arm.ArmedAt - prior < TimeSpan.FromSeconds(10)) &&
                facts.LastLoginAuthMethod == "ldap-auth");
            Require(MatchesWitness(facts.CredentialWitness, attempt, facts.TokenMetadataId!,
                outcome.Value.Token.Material));
            lastLogins[identity] = facts.LastLoginAt!.Value;
            if (facts.LastLoginAt.Value > time) time = facts.LastLoginAt.Value;
            var login = outcome.Value;
            await using var consumer = new InfisicalClient(c.Environment.Origin,
                new AuthenticationTokenSource(login.Token.Material),
                new() { AllowLoopbackDevelopmentHttp = c.Environment.AllowLoopbackDevelopmentHttp });
            var permitted = await consumer.ReadAsync(new(consumer.Authority,
                new InfisicalSecretAddress(allowed.Project, allowed.Environment, allowed.Path, allowed.Key)), deadline.Token);
            try { Require(permitted.IsSuccess && permitted.Value.Material.Reveal() == canaryValue); }
            finally { if (permitted.IsSuccess) permitted.Value.Dispose(); }
            var forbidden = await consumer.ReadAsync(new(consumer.Authority,
                new InfisicalSecretAddress(denied.Project, denied.Environment, denied.Path, denied.Key)), deadline.Token);
            try { Require(forbidden.Status == SecretStatus.Denied); }
            finally { if (forbidden.IsSuccess) forbidden.Value.Dispose(); }
            // Provider-clock facts are compared to an independent non-search exact read.
            var observed = await c.NeedAsync(() => IdentityOperations.GetOrganizationIdentity(
                c.OrganizationId, identity), NativeIdentityRole.Observer, deadline.Token);
            var metadata = observed.Membership.Value;
            Require(metadata.Id == attempt.MembershipId && metadata.LastLoginTime.IsPresent &&
                !metadata.LastLoginTime.IsNull && DateTimeOffset.TryParse(metadata.LastLoginTime.Value,
                    CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTimeOffset actual) &&
                actual == facts.LastLoginAt && metadata.LastLoginAuthMethod.IsPresent &&
                !metadata.LastLoginAuthMethod.IsNull && metadata.LastLoginAuthMethod.Value == "ldap-auth");
            LastLogin = facts;
            return facts;
        }
        finally { if (outcome is { IsSuccess: true }) outcome.Value.Dispose(); }
    }

    internal async ValueTask<LdapTemplateArm> ArmTemplateAsync(string name, string? template,
        LdapServiceCredential? credential, CancellationToken token)
    {
        Require(!sealedVisibility && !outstanding);
        outstanding = true;
        var attempt = new LdapTemplateAttempt(Directory, Guid.NewGuid().ToString("D"), c.Operation,
            c.Definition.Member, c.Variant, c.Definition.Key.Case, name, template, credential);
        using var deadline = Deadline(token);
        var arm = await source.ArmTemplateAsync(attempt, deadline.Token);
        Require(arm.Attempt == attempt && Unique(registrations, arm.RegistrationId) &&
            arm.Cursor >= sequence && arm.CaptureArmed);
        sequence = arm.Cursor;
        return arm;
    }

    internal async ValueTask CompleteTemplateAsync(LdapTemplateArm arm, DispatchEvidence receipt,
        CancellationToken token)
    {
        Require(outstanding);
        using var deadline = Deadline(token);
        var facts = await source.CompleteTemplateAsync(arm, receipt, deadline.Token);
        Require(facts.Arm == arm && Compatible(receipt, facts.Disposition) && Next(facts.Sequence) &&
            facts.ExcludesLateCommit && facts.NoReplay &&
            facts.MatchedMutations == (receipt == DispatchEvidence.NotDispatched ? 0 : 1) &&
            (facts.MatchedMutations == 0 ? facts.ProviderRequestId is null : Unique(requests, facts.ProviderRequestId)) &&
            (receipt is not (DispatchEvidence.NotDispatched or DispatchEvidence.Rejected) || !facts.Applied) &&
            (receipt != DispatchEvidence.Applied || facts.Applied) &&
            (facts.Disposition != DispatchEvidence.Applied || facts.Applied) &&
            (arm.Attempt.TemplateId is null || facts.TemplateId == arm.Attempt.TemplateId) &&
            (facts.TemplateId is null || Id(facts.TemplateId)) &&
            (!facts.Applied || Id(facts.TemplateId)));
        outstanding = false;
    }

    internal async ValueTask SealAsync(CancellationToken token)
    {
        Require(!sealedVisibility && !outstanding);
        using var deadline = Deadline(token);
        var facts = await source.SealAsync(Directory, deadline.Token);
        Require(facts.Directory == Directory && Next(facts.Sequence) && Utc(facts.ClosedAt) &&
            facts.ClosedAt >= time && ValidText(facts.Watermark) &&
            facts.LoginEvents == loginEvents && facts.Complete && facts.NoFurtherLogins &&
            facts.SearchVisibilityEstablished);
        sealedVisibility = true;
    }

    private CancellationTokenSource Deadline(CancellationToken token)
    {
        var result = CancellationTokenSource.CreateLinkedTokenSource(token);
        result.CancelAfter(timeout);
        return result;
    }
    private bool MatchesWitness(string? witness, LdapLoginAttempt attempt, string metadata,
        SecretMaterial material)
    {
        char[] characters = material.ExportCharacters();
        byte[]? encoded = null;
        byte[]? domain = null;
        byte[]? digest = null;
        byte[] decoded = new byte[32];
        try
        {
            if (witness is not { Length: 44 } ||
                !Convert.TryFromBase64String(witness, decoded, out int count) || count != decoded.Length)
                return false;
            encoded = new byte[Encoding.UTF8.GetByteCount(characters)];
            Encoding.UTF8.GetBytes(characters, encoded);
            domain = Encoding.UTF8.GetBytes("secretkit-ldap-login-v1\0" + attempt.Directory.Attempt.Id + "\0" +
                attempt.Id + "\0" + attempt.Directory.Attempt.OrganizationId + "\0" + attempt.IdentityId + "\0" +
                attempt.MembershipId + "\0" + attempt.TemplateId + "\0" + metadata + "\0");
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, credentials.CorrelationKey);
            hmac.AppendData(domain);
            hmac.AppendData(encoded);
            digest = hmac.GetHashAndReset();
            return CryptographicOperations.FixedTimeEquals(decoded, digest);
        }
        finally
        {
            Array.Clear(characters);
            CryptographicOperations.ZeroMemory(decoded);
            if (encoded is not null) CryptographicOperations.ZeroMemory(encoded);
            if (domain is not null) CryptographicOperations.ZeroMemory(domain);
            if (digest is not null) CryptographicOperations.ZeroMemory(digest);
        }
    }
    private bool Next(long value)
    {
        if (value <= sequence) return false;
        sequence = value;
        return true;
    }
    private static bool Compatible(DispatchEvidence receipt, DispatchEvidence terminal) =>
        receipt == terminal || receipt == DispatchEvidence.PossiblyDispatched &&
            terminal is DispatchEvidence.Applied or DispatchEvidence.Rejected or DispatchEvidence.NotDispatched;
    private static bool Unique(HashSet<string> values, string? value) =>
        ValidText(value) && values.Add(value!);
    private static bool ValidText(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(char.IsControl);
    private static bool Id(string? value) => ValidText(value) && Guid.TryParseExact(value, "D", out Guid id) &&
        id != Guid.Empty && id.ToString("D") == value;
    private static bool Utc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;
    private static void Require(bool condition)
    {
        if (!condition) throw new NativeCaseFailureException("effect-mismatch");
    }
    private static string Text(JsonElement input, string key)
    {
        if (!input.TryGetProperty(key, out JsonElement value) || value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()) || value.GetString()!.Length > 1024 ||
            value.GetString()!.Any(char.IsControl)) throw new NativeCaseFailureException("missing-input");
        return value.GetString()!;
    }
    private static Canary ReadCanary(JsonElement input, string key)
    {
        if (!input.TryGetProperty(key, out JsonElement value) || value.ValueKind != JsonValueKind.Object)
            throw new NativeCaseFailureException("missing-input");
        var result = new Canary(Text(value, "projectId"), Text(value, "environment"),
            Text(value, "path"), Text(value, "key"));
        if (!Id(result.Project) || !result.Path.StartsWith('/'))
            throw new NativeCaseFailureException("missing-input");
        return result;
    }
    private sealed record Canary(string Project, string Environment, string Path, string Key)
    {
        public override string ToString() => "[LdapCanary]";
    }
    public override string ToString() => "[LdapLoginTrial]";
}
