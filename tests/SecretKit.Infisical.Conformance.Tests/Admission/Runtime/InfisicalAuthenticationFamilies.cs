using System.Diagnostics.Tracing;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class InfisicalAuthenticationFamilies
{
    public static void Register(NativeCaseRegistry registry, NativeEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected, IAuthenticationExpiryObserver? expiryObserver = null,
        IAuthenticationIssuanceSource? issuanceSource = null, Action<SocketsHttpHandler>? configureProofTransport = null)
    {
        InfisicalProofAuthenticationEffects.Register(registry, environment, expected, expiryObserver, issuanceSource, configureProofTransport);
        InfisicalUniversalAuthenticationEffects.Register(registry, environment, expected, expiryObserver, issuanceSource);
        InfisicalTokenRevocationEffects.Register(registry, environment, expected);
    }

    internal static void RegisterFamily(NativeCaseRegistry registry, NativeEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected, string operation, string member, string[] variants,
        Func<NativeCaseDefinition, NativeCaseProbe, CancellationToken, ValueTask> execute,
        IAuthenticationExpiryObserver? expiryObserver = null)
    {
        foreach (NativeCaseDefinition definition in expected.Where(d =>
            d.Key.Provider == "Infisical" && d.Key.Operation == operation))
            registry.Add(new(definition, async (probe, token) =>
            {
                probe.Contract(definition.Member == member && variants.Contains(definition.Key.Variant,
                    StringComparer.Ordinal) && definition.Key.Case is "selected-contract" or
                    "denied-authority" or "independent-effect" or "cancellation-boundary" or
                    "lost-response-no-replay", NativeFailure.ContractMismatch);
                try
                {
                    AuthenticationExpiryProfile? profile = AuthenticationExpiryTrial.Profile(
                        environment, definition, expiryObserver is not null);
                    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
                    deadline.CancelAfter(TimeSpan.FromSeconds(profile?.CaseTimeoutSeconds ?? 40));
                    await execute(definition, probe, deadline.Token);
                }
                catch (NativeCaseFailureException error)
                {
                    probe.Contract(false, error.Message switch
                    {
                        "missing-input" => NativeFailure.MissingInput,
                        "observer-unavailable" => NativeFailure.ObserverUnavailable,
                        "effect-mismatch" => NativeFailure.EffectMismatch,
                        "cleanup-incomplete" => NativeFailure.CleanupIncomplete,
                        _ => NativeFailure.ContractMismatch
                    });
                }
                catch (OperationCanceledException)
                {
                    probe.Contract(false, token.IsCancellationRequested ?
                        NativeFailure.UnexpectedCancellation : NativeFailure.DeadlineExceeded);
                }
                catch (Exception error) when (error is ArgumentException or JsonException or
                    InvalidOperationException or KeyNotFoundException)
                {
                    probe.Contract(false, NativeFailure.MissingInput);
                }
            }));
    }

    internal static T Input<T>(NativeEnvironment environment, string family, NativeCaseDefinition definition)
    {
        try
        {
            return environment.RequireFamilyInput(family).GetProperty("scopes")
                .GetProperty(definition.Key.Scope).GetProperty(definition.Key.Operation)
                .GetProperty(definition.Key.Variant).GetProperty(definition.Key.Case)
                .Deserialize<T>(Options)
                ?? throw new NativeCaseFailureException("missing-input");
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException)
        { throw new NativeCaseFailureException("missing-input"); }
    }

    private static JsonSerializerOptions Options { get; } = new(NativeRunProtocol.JsonOptions)
    {
        Converters = { new JsonStringEnumConverter<AuthenticationApiRevision>() }
    };
}

internal enum AuthenticationApiRevision { AuthV1IdentitiesV1SecretsV4 }

internal sealed record AuthenticationFixtureInput(string OrganizationId, string IdentityId, string OwnedName,
    string ProjectId, string Environment, string Folder, string AllowedKey, string DeniedKey,
    string ExpectedValue, double ExpectedTtl, double ExpectedMaximumTtl, double ExpectedPeriod,
    double ExpectedExpiresIn, double ExpectedReportedMaximumTtl, AuthenticationApiRevision ApiRevision,
    double ExpectedMaximumUses = 0)
{
    public override string ToString() => "[AuthenticationFixtureInput]";
}

// The host supplies a newly provisioned, exclusively caller-owned identity for EACH case.
// Its random name and empty credential baseline are checked before cleanup authority is acquired.
// These packets do not provision issuers, policies, certificates or external proof material.
internal sealed class AuthenticationFixture : IAsyncDisposable
{
    private readonly NativeEnvironment environment;
    private readonly AuthenticationFixtureInput input;
    private readonly NativeCaseProbe probe;
    private readonly string scope;
    private readonly ManagementClient management;
    private readonly InfisicalClient[] clients;
    private bool owned;
    internal string IdentityId => input.IdentityId;
    internal InfisicalNetworkOptions Network => new()
    { AllowLoopbackDevelopmentHttp = environment.AllowLoopbackDevelopmentHttp };

    internal AuthenticationFixture(NativeEnvironment environment, AuthenticationFixtureInput input,
        NativeCaseProbe probe, string scope)
    {
        if (!Guid.TryParseExact(input.IdentityId, "D", out _) ||
            !input.OwnedName.StartsWith("sk-auth-", StringComparison.Ordinal) ||
            !Guid.TryParseExact(input.OwnedName["sk-auth-".Length..], "N", out _) ||
            input.AllowedKey == input.DeniedKey || !double.IsFinite(input.ExpectedTtl) ||
            input.ExpectedTtl <= 0 || !double.IsFinite(input.ExpectedMaximumTtl) ||
            input.ExpectedMaximumTtl < 0 || !double.IsFinite(input.ExpectedPeriod) || input.ExpectedPeriod < 0 ||
            !double.IsFinite(input.ExpectedExpiresIn) || input.ExpectedExpiresIn <= 0 ||
            !double.IsFinite(input.ExpectedReportedMaximumTtl) || input.ExpectedReportedMaximumTtl < 0 ||
            !double.IsFinite(input.ExpectedMaximumUses) || input.ExpectedMaximumUses < 0 ||
            input.ApiRevision != AuthenticationApiRevision.AuthV1IdentitiesV1SecretsV4)
            throw new NativeCaseFailureException("missing-input");
        this.environment = environment;
        this.input = input;
        this.probe = probe;
        this.scope = scope;
        management = environment.CreateManagementClient();
        clients = Enum.GetValues<NativeIdentityRole>().Select(environment.CreateClient).ToArray();
    }

    internal async ValueTask InitializeAsync(CancellationToken token)
    {
        using var identityRequest = IdentityOperations.GetOrganizationIdentity(input.OrganizationId, input.IdentityId);
        SecretOutcome<IdentitySummary> identity = await ReadAsync(identityRequest, NativeIdentityRole.Observer, token);
        probe.Contract(identity.IsSuccess && identity.Value.Name == input.OwnedName &&
            identity.Value.HasDeleteProtection is { IsPresent: true, Value: false },
            NativeFailure.MissingPrerequisite);
        // Only the independently identified, cleanup-authorized resource is ever deleted.
        ManagementPage<TokenAuthToken> baseline = await TokensAsync(token);
        probe.Contract(baseline.IsComplete && baseline.Items.Count == 0, NativeFailure.MissingPrerequisite);
        owned = true;
        await ReadSecretAsync(clients[(int)NativeIdentityRole.Setup], input.AllowedKey,
            SecretStatus.Success, token);
        await ReadSecretAsync(clients[(int)NativeIdentityRole.Runtime], input.AllowedKey,
            SecretStatus.Success, token);
        await ReadSecretAsync(clients[(int)NativeIdentityRole.Observer], input.AllowedKey,
            SecretStatus.Success, token);
        await ReadSecretAsync(clients[(int)NativeIdentityRole.Denied], input.AllowedKey,
            SecretStatus.Denied, token);
    }

    internal async ValueTask<SecretOutcome<T>> ReadAsync<T>(ManagementRequest<T> request,
        NativeIdentityRole role, CancellationToken token) where T : notnull
    {
        ManagementAuthority authority = environment.CreateManagementAuthority(management, role, input.OrganizationId);
        return await management.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(input.OrganizationId, resourceId: input.IdentityId)),
            cancellationToken: token);
    }

    internal async ValueTask<ManagementPage<TokenAuthToken>> TokensAsync(CancellationToken token)
    {
        using var request = IdentityAuthenticationOperations.ListTokens(input.OrganizationId, input.IdentityId);
        SecretOutcome<ManagementPage<TokenAuthToken>> result = await ReadAsync(request, NativeIdentityRole.Observer, token);
        probe.Contract(result.IsSuccess && result.Value.IsComplete, NativeFailure.ObserverUnavailable);
        return result.Value;
    }

    internal async ValueTask ObserveLoginAsync(InfisicalAccessToken issued, double ttl, double maximum,
        string method, CancellationToken token, AuthenticationExpiryTrial? trial = null,
        DispatchEvidence receipt = DispatchEvidence.NotDispatched)
    {
        probe.Contract(ttl == input.ExpectedExpiresIn && maximum == input.ExpectedReportedMaximumTtl,
            NativeFailure.ContractMismatch);
        if (trial is not null)
        {
            await trial.ObserveAsync(issued.Material, ttl, maximum, receipt,
                (binding, phase, ct) => SampleExpiryAsync(issued.Material, binding, phase, ct), token);
            probe.Effect(NativeObservation.Matched);
            return;
        }
        await using var consumer = new InfisicalClient(environment.Origin, new AuthenticationTokenSource(issued.Material), Network);
        await ReadSecretAsync(consumer, input.AllowedKey, SecretStatus.Success, token);
        await ReadSecretAsync(consumer, input.DeniedKey, SecretStatus.Denied, token);
        ManagementPage<TokenAuthToken> rows = await TokensAsync(token);
        probe.Contract(rows.Items.Count == 1 && rows.Items[0].IdentityId == input.IdentityId &&
            rows.Items[0].AuthMethod == method && rows.Items[0].AccessTokenTTL == input.ExpectedTtl &&
            rows.Items[0].AccessTokenMaxTTL == input.ExpectedMaximumTtl &&
            rows.Items[0].AccessTokenPeriod == input.ExpectedPeriod &&
            rows.Items[0].IsAccessTokenRevoked == false, NativeFailure.EffectMismatch);
        // Independently fetched lifetime metadata is NOT server expiry enforcement.
        // No exact expiry/event observer exists in the selected SDK contract. Never
        // wait by polling, infer a finite ceiling from periodic max=0, or report a pass.
        probe.Effect(NativeObservation.Unavailable);
    }

    private async ValueTask<bool> SampleExpiryAsync(SecretMaterial material, AuthenticationExpiryFence binding,
        AuthenticationExpiryPhase phase, CancellationToken token)
    {
        await using var consumer = new InfisicalClient(environment.Origin, new AuthenticationTokenSource(material), Network);
        bool allowed = await ReadSecretAsync(consumer, input.AllowedKey,
            phase == AuthenticationExpiryPhase.Active ? SecretStatus.Success : SecretStatus.Denied, token);
        bool denied = await ReadSecretAsync(consumer, input.DeniedKey, SecretStatus.Denied, token);
        // Fresh, explicitly selected authority reads the unchanged canary inside each callback.
        await using InfisicalClient observer = environment.CreateClient(NativeIdentityRole.Observer);
        bool unchanged = await ReadSecretAsync(observer, input.AllowedKey, SecretStatus.Success, token);
        ManagementPage<TokenAuthToken> rows = await TokensAsync(token);
        TokenAuthToken[] matches = rows.Items.Where(t => t.Id == binding.TokenMetadataId).ToArray();
        bool metadata = matches.Length == 1 && matches[0].IdentityId == input.IdentityId &&
            matches[0].AuthMethod == binding.Arm.Attempt.AuthenticationMethod &&
            matches[0].AccessTokenTTL == input.ExpectedTtl &&
            matches[0].AccessTokenMaxTTL == input.ExpectedMaximumTtl &&
            matches[0].AccessTokenPeriod == input.ExpectedPeriod &&
            matches[0].AccessTokenNumUsesLimit == input.ExpectedMaximumUses &&
            matches[0].AccessTokenNumUses is { } uses && double.IsFinite(uses) && uses >= 0 &&
            (input.ExpectedMaximumUses == 0 || uses < input.ExpectedMaximumUses) &&
            matches[0].IsAccessTokenRevoked == false;
        return allowed && denied && unchanged && metadata;
    }

    internal async ValueTask ObserveRejectedAsync(CancellationToken token)
    {
        ManagementPage<TokenAuthToken> rows = await TokensAsync(token);
        probe.Effect(rows.Items.Count == 0 ? NativeObservation.Matched : NativeObservation.Mismatched);
    }

    internal async ValueTask ObserveInterruptedAsync(CancellationToken token)
    {
        _ = await TokensAsync(token);
        // A token row cannot identify an inaccessible response's exact credential.
        probe.Effect(NativeObservation.Unavailable);
    }

    internal async ValueTask ReadWithTokenAsync(SecretMaterial material, SecretStatus expected,
        CancellationToken token)
    {
        await using var client = new InfisicalClient(environment.Origin, new AuthenticationTokenSource(material), Network);
        await ReadSecretAsync(client, input.AllowedKey, expected, token);
    }

    internal async ValueTask<TokenAuthTokenCreation> IssueTokenAsync(CancellationToken token)
    {
        string name = "sk-token-" + Guid.NewGuid().ToString("N");
        using var request = IdentityAuthenticationOperations.CreateToken(input.OrganizationId, input.IdentityId, name);
        ManagementAuthority authority = environment.CreateManagementAuthority(management, NativeIdentityRole.Setup,
            input.OrganizationId);
        var receipt = management.CreateReceipt(request);
        SecretOutcome<TokenAuthTokenCreation> result = await management.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, IdentityAuthenticationOperations.TokenCreateTarget(
                input.OrganizationId, input.IdentityId, name)), receipt, token);
        if (!result.IsSuccess || receipt.Evidence != DispatchEvidence.Applied)
        {
            if (result.IsSuccess) result.Value.Dispose();
            probe.Contract(false, NativeFailure.MissingPrerequisite);
        }
        return result.Value;
    }

    internal async ValueTask InvalidateAsync(string tokenId, CancellationToken token)
    {
        using var request = IdentityAuthenticationOperations.RevokeToken(input.OrganizationId, tokenId);
        ManagementAuthority authority = environment.CreateManagementAuthority(management,
            NativeIdentityRole.Administrative, input.OrganizationId);
        var receipt = management.CreateReceipt(request);
        SecretOutcome<IdentityAuthenticationAcknowledgement> result = await management.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(input.OrganizationId, resourceId: tokenId)), receipt, token);
        probe.Contract(result.IsSuccess && receipt.Evidence == DispatchEvidence.Applied, NativeFailure.MissingPrerequisite);
    }

    internal async ValueTask ObserveRevocationAsync(TokenAuthTokenCreation issued, bool? revoked,
        CancellationToken token, bool recordEffect = true)
    {
        ManagementPage<TokenAuthToken> rows = await TokensAsync(token);
        TokenAuthToken? row = rows.Items.SingleOrDefault(t => t.Id == issued.Metadata.Id);
        probe.Contract(rows.Items.Count == 1 && row is not null && row.IdentityId == input.IdentityId &&
            row.IsAccessTokenRevoked is not null && (revoked is null || row.IsAccessTokenRevoked == revoked),
            NativeFailure.EffectMismatch);
        await ReadWithTokenAsync(issued.AccessToken, row!.IsAccessTokenRevoked == true ?
            SecretStatus.Denied : SecretStatus.Success, token);
        if (recordEffect) probe.Effect(NativeObservation.Matched);
    }

    private async ValueTask<bool> ReadSecretAsync(InfisicalClient client, string key, SecretStatus expected,
        CancellationToken token)
    {
        var reference = new SecretReference(client.Authority,
            new InfisicalSecretAddress(input.ProjectId, input.Environment, input.Folder, key));
        SecretOutcome<SecretRead> read = await client.ReadAsync(reference, token);
        bool match = read.Status == expected;
        if (read.IsSuccess)
        {
            using SecretRead value = read.Value;
            match &= value.Material.Reveal() == input.ExpectedValue;
        }
        if (!match)
            probe.Effect(read.Status is SecretStatus.Unknown or SecretStatus.Unavailable ?
                NativeObservation.Unavailable : NativeObservation.Mismatched);
        return match;
    }

    public async ValueTask DisposeAsync()
    {
        bool clean = true;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            if (owned)
            {
                using var request = IdentityOperations.DeleteOrganizationIdentity(input.OrganizationId, input.IdentityId);
                ManagementAuthority authority = environment.CreateManagementAuthority(management,
                    NativeIdentityRole.Administrative, input.OrganizationId);
                var receipt = management.CreateReceipt(request);
                SecretOutcome<IdentitySummary> deleted = await management.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, new(input.OrganizationId, resourceId: input.IdentityId)),
                    receipt, deadline.Token);
                using var inspect = IdentityOperations.GetOrganizationIdentity(input.OrganizationId, input.IdentityId);
                SecretOutcome<IdentitySummary> remaining = await ReadAsync(inspect, NativeIdentityRole.Observer, deadline.Token);
                clean = (deleted.IsSuccess || deleted.Status == SecretStatus.Absent) &&
                    remaining.Status == SecretStatus.Absent;
            }
        }
        catch (Exception) { clean = false; }
        finally
        {
            foreach (InfisicalClient client in clients)
                try { await client.DisposeAsync(); } catch (Exception) { clean = false; }
        }
        if (owned)
            environment.ConfirmPrerequisite(scope, "approved-sandbox-cleanup",
                clean ? NativeObservation.Matched : NativeObservation.Mismatched);
        if (!clean) probe.Contract(false, NativeFailure.CleanupIncomplete);
    }

    public override string ToString() => "[AuthenticationFixture]";
}

internal sealed class AuthenticationTokenSource(SecretMaterial material) : IInfisicalTokenSource
{
    public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(material.Copy())));
    }
    public override string ToString() => "[AuthenticationTokenSource]";
}

internal sealed record AuthenticationDispatchResult<T>(SecretOutcome<T>? Outcome, bool Interrupted) where T : notnull;

internal static class AuthenticationDispatch
{
    internal static async ValueTask<AuthenticationDispatchResult<T>> InvokeAsync<T>(NativeEnvironment environment,
        NativeCaseDefinition definition, NativeCaseProbe probe, string path,
        Func<CancellationToken, ValueTask<SecretOutcome<T>>> call, CancellationToken token) where T : notnull
    {
        if (definition.Key.Case is not ("cancellation-boundary" or "lost-response-no-replay"))
            return new(await call(token), false);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        using var boundary = new AuthenticationSendBoundary(environment.Origin, path, cancellation,
            definition.Key.Case == "lost-response-no-replay");
        SecretOutcome<T>? outcome = null;
        bool interrupted = false;
        try { outcome = await call(cancellation.Token); }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested && !token.IsCancellationRequested)
        { interrupted = true; }
        probe.Contract(boundary.Reached.Task.IsCompletedSuccessfully && interrupted, NativeFailure.ContractMismatch);
        return new(outcome, interrupted);
    }
}

internal sealed class AuthenticationSendBoundary : EventListener
{
    private static readonly AsyncLocal<AuthenticationSendBoundary?> Current = new();
    private readonly AuthenticationSendBoundary? previous;
    private readonly Uri? origin;
    private readonly string? path;
    private readonly CancellationTokenSource? cancellation;
    private readonly bool loseResponse;
    private bool selected;
    internal TaskCompletionSource Reached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal AuthenticationSendBoundary(Uri origin, string path, CancellationTokenSource cancellation, bool loseResponse)
    {
        this.origin = origin;
        this.path = path;
        this.cancellation = cancellation;
        this.loseResponse = loseResponse;
        previous = Current.Value;
        Current.Value = this;
    }
    protected override void OnEventSourceCreated(EventSource source)
    {
        if (source.Name == "System.Net.Http") EnableEvents(source, EventLevel.Verbose, EventKeywords.All);
    }
    protected override void OnEventWritten(EventWrittenEventArgs value)
    {
        if (origin is null || cancellation is null || !ReferenceEquals(Current.Value, this)) return;
        if (value.EventName == "RequestStart" && value.Payload is { Count: >= 4 } fields &&
            fields[0] is string scheme && scheme == origin.Scheme && fields[1] is string host &&
            host == origin.Host && fields[2] is int port && port == origin.Port && fields[3] is string target)
            selected = target == path;
        if (selected && value.EventName == (loseResponse ? "ResponseHeadersStop" : "RequestHeadersStart") &&
            Reached.TrySetResult()) cancellation.Cancel();
    }
    public override void Dispose()
    {
        if (ReferenceEquals(Current.Value, this)) Current.Value = previous;
        base.Dispose();
    }
}
