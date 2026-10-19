using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed record AuthenticationExpiryProfile(string DeploymentId, AuthenticationExpirySource Source,
    int CaseTimeoutSeconds)
{
    public override string ToString() => "[AuthenticationExpiryProfile]";
}

// The trial owns only private correlation material. The original public receipt and
// returned SDK material stay with the caller; neither is synthesized or replayed.
internal sealed class AuthenticationExpiryTrial(
    IAuthenticationExpiryObserver observer, AuthenticationExpiryAttempt attempt) : IAsyncDisposable
{
    private byte[]? key;
    private AuthenticationExpiryArm? arm;
    private bool started;

    internal static AuthenticationExpiryProfile? Profile(NativeEnvironment environment,
        NativeCaseDefinition definition, bool required)
    {
        if (definition.Key.Case is not ("selected-contract" or "independent-effect") ||
            definition.Key.Operation is not (InfisicalUniversalAuthenticationEffects.Operation or
                InfisicalProofAuthenticationEffects.Operation)) return null;
        string family = definition.Key.Operation == InfisicalUniversalAuthenticationEffects.Operation ?
            "C08-IR-InfisicalUniversalAuthentication" : "C08-IR-InfisicalProofAuthentication";
        JsonElement scope = environment.RequireFamilyInput(family).GetProperty("scopes")
            .GetProperty(definition.Key.Scope);
        if (!scope.TryGetProperty("authLifetime", out JsonElement profile))
        {
            if (required) throw new NativeCaseFailureException("missing-input");
            return null;
        }
        if (profile.ValueKind != JsonValueKind.Object ||
            !profile.TryGetProperty("deploymentId", out JsonElement deployment) ||
            deployment.ValueKind != JsonValueKind.String || !Text(deployment.GetString()) ||
            !profile.TryGetProperty("sourceProfile", out JsonElement source) ||
            source.ValueKind != JsonValueKind.String ||
            source.GetString() is not ("NativeProvider" or "ControlledFixture") ||
            !profile.TryGetProperty("caseTimeoutSeconds", out JsonElement timeout) ||
            timeout.ValueKind != JsonValueKind.Number || !timeout.TryGetInt32(out int seconds) ||
            seconds is < 1 or > 900)
            throw new NativeCaseFailureException("missing-input");
        return new(deployment.GetString()!, source.GetString() == "NativeProvider" ?
            AuthenticationExpirySource.NativeProvider : AuthenticationExpirySource.ControlledFixture, seconds);
    }

    internal static AuthenticationExpiryTrial? Create(NativeEnvironment environment, NativeCaseDefinition definition,
        AuthenticationFixtureInput input, string method, IAuthenticationExpiryObserver? supplied)
    {
        AuthenticationExpiryProfile? profile = Profile(environment, definition, supplied is not null);
        if (profile is null) return null;
        string family = definition.Key.Operation == InfisicalUniversalAuthenticationEffects.Operation ?
            "C08-IR-InfisicalUniversalAuthentication" : "C08-IR-InfisicalProofAuthentication";
        // Family-root configuration is a separate native channel, never a controlled fallback.
        IAuthenticationExpiryObserver? native = InfisicalAuthenticationExpiryObserver.FromInputs(environment, family);
        IAuthenticationExpiryObserver? selected = supplied ??
            (profile.Source == AuthenticationExpirySource.NativeProvider ? native : null);
        if (selected is null) throw Unavailable();
        if (!double.IsFinite(input.ExpectedExpiresIn) || input.ExpectedExpiresIn <= 0 ||
            !double.IsFinite(input.ExpectedMaximumUses) || input.ExpectedMaximumUses < 0 ||
            profile.Source == AuthenticationExpirySource.NativeProvider &&
                profile.CaseTimeoutSeconds < input.ExpectedExpiresIn + 20)
            throw new NativeCaseFailureException("missing-input");
        return new(selected, new(Guid.NewGuid().ToString("N"),
            string.Join("/", definition.Key.Provider, definition.Key.Operation, definition.Key.Variant,
                definition.Key.Scope, definition.Key.Case),
            definition.Key.Operation, definition.Member, "v0.166.3", profile.DeploymentId,
            input.OrganizationId, input.IdentityId, method,
            new(input.ExpectedTtl, input.ExpectedMaximumTtl, input.ExpectedPeriod, input.ExpectedMaximumUses),
            input.ExpectedExpiresIn, input.ExpectedReportedMaximumTtl, profile.Source));
    }

    internal async ValueTask ArmAsync(CancellationToken token)
    {
        key = RandomNumberGenerator.GetBytes(32);
        // Close the original attempt even when Arm commits but loses its reply.
        started = true;
        arm = await observer.ArmAsync(attempt, key, token);
        if (arm is null || arm.Attempt != attempt || !Text(arm.RegistrationId) ||
            !Text(arm.SourceIdentity) || arm.SourceIdentity is "setup" or "runtime" or "denied" or
                "administrative" or "observer" ||
            !Text(arm.ClockAuthority) || !Text(arm.ClockEpoch) || !Utc(arm.ArmedAt) ||
            arm.Cursor < 0 || !Text(arm.PolicyWitness) || !arm.CaptureArmed)
            throw Unavailable();
    }

    internal async ValueTask ObserveAsync(SecretMaterial material, double expiresIn, double maximum,
        DispatchEvidence receipt,
        Func<AuthenticationExpiryFence, AuthenticationExpiryPhase, CancellationToken, ValueTask<bool>> sample,
        CancellationToken token)
    {
        if (arm is null || key is null || receipt != DispatchEvidence.Applied) throw Unavailable();
        AuthenticationExpiryFence binding = await observer.CompleteAsync(arm, receipt, token);
        if (binding is null || binding.Arm != arm || binding.Disposition != DispatchEvidence.Applied ||
            !Text(binding.ProviderRequestId) || !Id(binding.TokenMetadataId) || !Text(binding.CredentialHandle) ||
            binding.ObservedPolicy != attempt.Policy || binding.ResponseExpiresIn != expiresIn ||
            binding.ResponseMaximumTtl != maximum || expiresIn != attempt.ExpectedExpiresIn ||
            maximum != attempt.ExpectedReportedMaximumTtl || !Utc(binding.IssuedAt) || !Utc(binding.ExpiresAt) ||
            binding.IssuedAt < arm.ArmedAt || binding.ExpiresAt <= binding.IssuedAt ||
            (binding.ExpiresAt - binding.IssuedAt).TotalSeconds != expiresIn ||
            binding.Sequence <= arm.Cursor || binding.MatchedIssuances != 1 ||
            !binding.IssueEventObserved || !binding.NativeScheduleObserved || !binding.ExcludesLateCommit ||
            !MatchesWitness(binding.CredentialWitness, material))
            throw Unavailable();
        long sequence = binding.Sequence;
        DateTimeOffset lastClosed = binding.IssuedAt;
        var windows = new HashSet<string>(StringComparer.Ordinal);
        var events = new HashSet<string>(StringComparer.Ordinal);
        foreach (AuthenticationExpiryPhase phase in Enum.GetValues<AuthenticationExpiryPhase>())
        {
            int callbacks = 0;
            bool localMatch = false;
            AuthenticationExpiryObservation<bool> observation = await observer.ObserveAsync(binding, phase,
                async ct =>
                {
                    if (++callbacks != 1) throw Unavailable();
                    localMatch = await sample(binding, phase, ct);
                    return localMatch;
                }, token);
            AuthenticationExpiryWindow window = observation.Window;
            if (callbacks != 1 || !localMatch || !observation.Sample || window is null ||
                window.Binding != binding || window.Phase != phase || !Text(window.WindowId) ||
                !Text(window.EventId) || !windows.Add(window.WindowId) || !events.Add(window.EventId) ||
                window.Sequence <= sequence || !Utc(window.OpenedAt) || !Utc(window.ClosedAt) ||
                window.OpenedAt < lastClosed || window.ClosedAt < window.OpenedAt ||
                !InPhase(window.OpenedAt, binding, phase) || !InPhase(window.ClosedAt, binding, phase) ||
                !window.Authoritative || !window.EventObserved ||
                window.NaturalExpiryObserved != (phase == AuthenticationExpiryPhase.Expired) ||
                !window.PolicyUnchanged || !window.IpPathUnchanged || !window.NoRenewal ||
                !window.NoRevocation || !window.UseLimitNotExhausted)
                throw Unavailable();
            sequence = window.Sequence;
            lastClosed = window.ClosedAt;
        }
    }

    private bool MatchesWitness(string witness, SecretMaterial material)
    {
        char[] characters = material.ExportCharacters();
        byte[]? credential = null;
        byte[]? domain = null;
        byte[]? digest = null;
        byte[] decoded = new byte[32];
        try
        {
            if (witness is not { Length: 44 } ||
                !Convert.TryFromBase64String(witness, decoded, out int count) || count != 32) return false;
            credential = new byte[Encoding.UTF8.GetByteCount(characters)];
            Encoding.UTF8.GetBytes(characters, credential);
            domain = Encoding.UTF8.GetBytes("secretkit-issued-token-v1\0" + attempt.Id + "\0" +
                attempt.Operation + "\0" + attempt.IdentityId + "\0");
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key!);
            hmac.AppendData(domain);
            hmac.AppendData(credential);
            digest = hmac.GetHashAndReset();
            return CryptographicOperations.FixedTimeEquals(decoded, digest);
        }
        finally
        {
            Array.Clear(characters);
            CryptographicOperations.ZeroMemory(decoded);
            if (credential is not null) CryptographicOperations.ZeroMemory(credential);
            if (domain is not null) CryptographicOperations.ZeroMemory(domain);
            if (digest is not null) CryptographicOperations.ZeroMemory(digest);
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (!started) return;
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            AuthenticationExpiryCleanup cleanup;
            try { cleanup = await observer.CloseAsync(attempt, deadline.Token); }
            catch (Exception error) when (error is NativeCaseFailureException or OperationCanceledException)
            { throw new NativeCaseFailureException("cleanup-incomplete"); }
            if (cleanup is null || cleanup.Attempt != attempt || !cleanup.Closed ||
                !cleanup.LateCreationFenced || !cleanup.MutationSettled || !cleanup.InventoryComplete ||
                !cleanup.CorrelationKeyDestroyed || cleanup.RemainingRegistrations != 0 || cleanup.PendingDeliveries != 0)
                throw new NativeCaseFailureException("cleanup-incomplete");
        }
        finally
        {
            if (key is not null) CryptographicOperations.ZeroMemory(key);
        }
    }

    private static bool InPhase(DateTimeOffset time, AuthenticationExpiryFence binding, AuthenticationExpiryPhase phase) =>
        phase == AuthenticationExpiryPhase.Active ? time >= binding.IssuedAt && time < binding.ExpiresAt :
            time >= binding.ExpiresAt;
    private static bool Text(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(char.IsControl);
    private static bool Id(string? value) => Text(value) && Guid.TryParseExact(value, "D", out Guid id) && id != Guid.Empty;
    private static bool Utc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;
    private static NativeCaseFailureException Unavailable() => new("observer-unavailable");
    public override string ToString() => "[AuthenticationExpiryTrial]";
}
