using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed record AuthenticationIssuanceInput(InfisicalLifecycleObservers.Settings Observer,
    AuthenticationIssuanceProfile Profile, string Capability, string ObserverIdentity)
{
    public override string ToString() => "[AuthenticationIssuanceInput]";
}

// Optional parent hook. Return null preserves the existing source-absent gate.
// Non-interrupted cases are left with their existing expiry/denial paths.
internal static class AuthenticationIssuanceEffects
{
    internal static async ValueTask<AuthenticationIssuanceTrial?> OpenAsync(NativeEnvironment environment,
        NativeCaseDefinition definition, AuthenticationFixtureInput fixture, string method,
        IAuthenticationIssuanceSource? supplied, Action<AuthenticationIssuanceTrial> retain, CancellationToken token)
    {
        if (!AuthenticationIssuanceContract.Owns(definition) ||
            !AuthenticationIssuanceContract.Interrupted(definition.Key.Case)) return null;
        string family = definition.Key.Operation == InfisicalUniversalAuthenticationEffects.Operation ?
            "C08-IR-InfisicalUniversalAuthentication" : "C08-IR-InfisicalProofAuthentication";
        var scope = environment.RequireFamilyInput(family).GetProperty("scopes").GetProperty(definition.Key.Scope);
        if (!scope.TryGetProperty("authIssuance", out var selected))
        {
            AuthenticationIssuanceContract.Require(supplied is null, "missing-input");
            return null;
        }
        NativeRunProtocol.RejectDuplicates(selected);
        var input = selected.Deserialize<AuthenticationIssuanceInput>(AuthenticationIssuanceContract.Options)
            ?? throw new NativeCaseFailureException("missing-input");
        AuthenticationIssuanceContract.ValidateProfile(input.Profile);
        AuthenticationIssuanceContract.Require(AuthenticationIssuanceContract.Text(input.Capability) &&
            AuthenticationIssuanceContract.Text(input.ObserverIdentity), "missing-input");
        var source = supplied ?? new InfisicalAuthenticationIssuanceSource(
            new(input.Observer), input.Observer.Identity);
        var root = new AuthenticationIssuanceRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            environment.Origin.AbsoluteUri, definition.Key.Operation, definition.Member, definition.Key.Variant,
            definition.Key.Case, definition.Key.Scope, source.Identity, source.Kind, input.Profile,
            fixture.OrganizationId, fixture.IdentityId, method, input.ObserverIdentity, fixture.ProjectId,
            fixture.Environment, fixture.Folder, fixture.AllowedKey, fixture.DeniedKey,
            new(fixture.ExpectedTtl, fixture.ExpectedMaximumTtl, fixture.ExpectedPeriod, fixture.ExpectedMaximumUses));
        using var capability = SecretMaterial.FromText(input.Capability);
        return await AuthenticationIssuanceTrial.OpenAsync(source, root, capability, retain, token);
    }
    internal static async ValueTask ObserveAsync(AuthenticationIssuanceTrial trial, NativeEnvironment environment,
        AuthenticationFixtureInput fixture, NativeCaseProbe probe, CancellationToken token)
    {
        await trial.SettleAsync(token);
        using var expected = SecretMaterial.FromText(fixture.ExpectedValue);
        await trial.ObserveAsync(environment, expected, token);
        probe.Effect(NativeObservation.Matched);
    }
}
