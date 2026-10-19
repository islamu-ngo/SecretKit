using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed record RotationCredentialFacts(RotationBackendCoordinate Coordinate,
    BackendAuthentication Authentication, string? AuthenticatedUsername, string[] AllowedActions, string[] DeniedActions,
    RotationCredentialIdentity? Identity = null)
{
    public override string ToString() => "[RotationCredentialFacts]";
}

internal interface IInfisicalRotationCredentialObserver
{
    ValueTask<RotationCredentialFacts> MeasureCredentialsAsync(RotationBackendCoordinate coordinate,
        SecretMaterial username, SecretMaterial password, CancellationToken token);
}

internal interface IInfisicalRotationValidationAccounts : IAsyncDisposable
{
    string Username1 { get; }
    string Username2 { get; }
    RotationBackendCoordinate Coordinate { get; }
}

internal interface IInfisicalRotationValidationAccountFactory
{
    ValueTask<IInfisicalRotationValidationAccounts> CreateAsync(string projectId,
        ValidationPoliciesEffects.RotationValidationInput input, CancellationToken token);
}

// A separate owner service provisions only nonce-owned roles on a borrowed
// connection. Measurement credentials never confer provisioning authority.
internal sealed class InfisicalRotationValidationAccounts(InfisicalLifecycleObservers owner,
    IInfisicalRotationIdentityCatalogObserver? catalog = null)
    : IInfisicalRotationValidationAccountFactory
{
    internal static InfisicalRotationValidationAccounts? FromInputs(NativeEnvironment env)
    {
        var family = env.RequireFamilyInput("C08-IR-ValidationPolicies");
        if (!family.TryGetProperty("rotationFixture", out var supplied)) return null;
        try
        {
            var settings = supplied.Deserialize<InfisicalLifecycleObservers.Settings>(InfisicalLifecycleFamilies.Options)
                ?? throw new NativeCaseFailureException("missing-input");
            return new(new(settings), InfisicalLifecycleObservers.FromInputs(env, "C08-IR-ValidationPolicies"));
        }
        catch (JsonException) { throw new NativeCaseFailureException("missing-input"); }
    }

    public async ValueTask<IInfisicalRotationValidationAccounts> CreateAsync(string projectId,
        ValidationPoliciesEffects.RotationValidationInput input, CancellationToken token)
    {
        if (input.Profile is not (InfisicalRotationProfile.PostgresCredentials or
            InfisicalRotationProfile.MysqlCredentials or InfisicalRotationProfile.MssqlCredentials))
            throw new NativeCaseFailureException("missing-input");
        if (input.Profile != InfisicalRotationProfile.PostgresCredentials && catalog is null)
            throw new NativeCaseFailureException("observer-unavailable");
        var accounts = new Accounts(owner, catalog, projectId, input);
        try
        {
            await accounts.ClaimAsync(token);
            return accounts;
        }
        catch
        {
            await accounts.DisposeAsync();
            throw;
        }
    }

    internal sealed record Facts(string OwnershipNonce, string OrganizationId, string ProjectId, string ConnectionId,
        RotationBackendCoordinate Coordinate, string[] OwnedUsernames, string[] UnownedUsernames,
        int RemainingOwnedAccounts, bool ConnectionRetained)
    {
        public override string ToString() => "[RotationAccountFacts]";
    }

    private sealed class Accounts : IInfisicalRotationValidationAccounts
    {
        private readonly InfisicalLifecycleObservers owner;
        private readonly IInfisicalRotationIdentityCatalogObserver? catalog;
        private readonly string projectId;
        private readonly ValidationPoliciesEffects.RotationValidationInput input;
        private readonly string ownership = Guid.NewGuid().ToString("N");
        private bool attempted;
        private RotationIdentityCatalogFacts? preflight;
        public string Username1 { get; }
        public string Username2 { get; }
        public RotationBackendCoordinate Coordinate { get; }

        internal Accounts(InfisicalLifecycleObservers owner, IInfisicalRotationIdentityCatalogObserver? catalog, string projectId,
            ValidationPoliciesEffects.RotationValidationInput input)
        {
            this.owner = owner;
            this.catalog = catalog;
            this.projectId = projectId;
            this.input = input;
            Username1 = "sk_rv_" + ownership[..16] + "_a";
            Username2 = "sk_rv_" + ownership[..16] + "_b";
            Coordinate = new(input.Profile, input.Host, input.Port,
                input.Database, Username1);
        }

        private void Owned(Utf8JsonWriter writer)
        {
            writer.WriteString("ownershipNonce", ownership);
            writer.WriteString("projectId", projectId);
            writer.WriteString("organizationId", input.OrganizationId);
            writer.WriteString("connectionId", input.ConnectionId);
            writer.WriteString("username1", Username1);
            writer.WriteString("username2", Username2);
            writer.WritePropertyName("coordinate");
            JsonSerializer.Serialize(writer, Coordinate, InfisicalLifecycleFamilies.Options);
        }

        private bool Matches(Facts facts, int remaining) =>
            facts.OwnershipNonce == ownership && facts.OrganizationId == input.OrganizationId && facts.ProjectId == projectId &&
            facts.ConnectionId == input.ConnectionId && facts.Coordinate == Coordinate &&
            facts.RemainingOwnedAccounts == remaining && facts.ConnectionRetained &&
            facts.UnownedUsernames is { Length: 0 } && facts.OwnedUsernames is not null &&
            facts.OwnedUsernames.SequenceEqual(remaining == 0 ? [] : new[] { Username1, Username2 });

        internal async ValueTask ClaimAsync(CancellationToken token)
        {
            if (input.Profile != InfisicalRotationProfile.PostgresCredentials)
            {
                string[] names = [Username1, Username2];
                var before = await catalog!.InspectIdentityCatalogAsync(Coordinate, names, token);
                if (!RotationSqlIdentityEvidence.Bound(before, Coordinate, names) ||
                    !RotationSqlIdentityEvidence.PolicyEstablished(before))
                    throw new NativeCaseFailureException("observer-unavailable");
                if (!RotationSqlIdentityEvidence.IsAbsent(before) || !RotationSqlIdentityEvidence.PolicyCompatible(before))
                    throw new NativeCaseFailureException("missing-prerequisite");
                // Pin mutable discovery vectors so a later observation cannot rewrite
                // the pre-claim policy snapshot used for drift and cleanup checks.
                preflight = before.Mysql is { } mysql ? before with
                {
                    Mysql = mysql with
                    {
                        PasswordPolicy = mysql.PasswordPolicy with
                        {
                            ActiveValidationPlugins = [.. mysql.PasswordPolicy.ActiveValidationPlugins],
                            InstalledValidationComponents = [.. mysql.PasswordPolicy.InstalledValidationComponents]
                        }
                    }
                } : before;
            }
            attempted = true;
            var facts = await owner.PostAsync<Facts>("rotation-accounts/claim", Owned, token);
            if (!Matches(facts, 2)) throw new NativeCaseFailureException("observer-unavailable");
            if (preflight is not null)
            {
                var claimed = await catalog!.InspectIdentityCatalogAsync(Coordinate, [Username1, Username2], token);
                if (!RotationSqlIdentityEvidence.Bound(claimed, Coordinate, [Username1, Username2]) ||
                    !RotationSqlIdentityEvidence.Owned(claimed, [Username1, Username2]) ||
                    !RotationSqlIdentityEvidence.PolicyCompatible(claimed) ||
                    input.Profile == InfisicalRotationProfile.MysqlCredentials &&
                        !RotationSqlIdentityEvidence.SameMysqlPolicy(preflight, claimed))
                    throw new NativeCaseFailureException("observer-unavailable");
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (!attempted) return;
            bool clean = true;
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            try
            {
                var release = await owner.PostAsync<Facts>("rotation-accounts/release", Owned, deadline.Token);
                clean &= Matches(release, 0);
            }
            catch (Exception) { clean = false; }
            try
            {
                var remaining = await owner.PostAsync<Facts>("rotation-accounts/remaining", Owned, deadline.Token);
                clean &= Matches(remaining, 0);
            }
            catch (Exception) { clean = false; }
            if (preflight is not null)
            {
                try
                {
                    var final = await catalog!.InspectIdentityCatalogAsync(Coordinate, [Username1, Username2], deadline.Token);
                    clean &= RotationSqlIdentityEvidence.Bound(final, Coordinate, [Username1, Username2]) &&
                        RotationSqlIdentityEvidence.IsAbsent(final) && RotationSqlIdentityEvidence.PolicyCompatible(final) &&
                        (input.Profile != InfisicalRotationProfile.MysqlCredentials ||
                            RotationSqlIdentityEvidence.SameMysqlPolicy(preflight, final));
                }
                catch (Exception) { clean = false; }
            }
            if (!clean) throw new NativeCaseFailureException("cleanup-incomplete");
        }
    }
}
