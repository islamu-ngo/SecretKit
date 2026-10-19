using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class InfisicalUniversalAuthenticationEffects
{
    internal const string Operation = "i.runtime.InfisicalUniversalAuthentication.LoginAsync";
    internal const string Member = "SecretKit.Infisical.InfisicalUniversalAuthentication.LoginAsync(System.String,SecretKit.Core.SecretMaterial,SecretKit.Infisical.InfisicalUniversalLoginReceipt,System.String,System.Threading.CancellationToken)";
    internal static readonly string[] Variants = ["organizationSlug.omitted", "organizationSlug.value"];

    internal static void Register(NativeCaseRegistry registry, NativeEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected, IAuthenticationExpiryObserver? expiryObserver = null,
        IAuthenticationIssuanceSource? issuanceSource = null) =>
        InfisicalAuthenticationFamilies.RegisterFamily(registry, environment, expected, Operation, Member,
            Variants, (definition, probe, token) => ExecuteAsync(environment, definition, probe, expiryObserver, issuanceSource, token),
            expiryObserver);

    private static async ValueTask ExecuteAsync(NativeEnvironment environment, NativeCaseDefinition definition,
        NativeCaseProbe probe, IAuthenticationExpiryObserver? expiryObserver,
        IAuthenticationIssuanceSource? issuanceSource, CancellationToken token)
    {
        UniversalInput input = InfisicalAuthenticationFamilies.Input<UniversalInput>(environment,
            "C08-IR-InfisicalUniversalAuthentication", definition);
        probe.Contract(definition.Key.Variant == (input.OrganizationSlug is null ?
            "organizationSlug.omitted" : "organizationSlug.value") &&
            !string.IsNullOrWhiteSpace(input.ClientId) && input.ClientSecret != input.DeniedClientSecret,
            NativeFailure.MissingInput);
        AuthenticationExpiryTrial? trial = AuthenticationExpiryTrial.Create(environment, definition, input.Fixture,
            "universal-auth", expiryObserver);
        await using var fixture = new AuthenticationFixture(environment, input.Fixture, probe, definition.Key.Scope);
        AuthenticationIssuanceTrial? issuance = null;
        try
        {
            await AuthenticationIssuanceEffects.OpenAsync(environment, definition, input.Fixture, "universal-auth",
                issuanceSource, value => issuance = value, token);
            await fixture.InitializeAsync(token);
            await using AuthenticationExpiryTrial? ownedTrial = trial;
            if (trial is not null) await trial.ArmAsync(token);
            bool denied = definition.Key.Case == "denied-authority";
            using SecretMaterial secret = SecretMaterial.FromText(denied ? input.DeniedClientSecret : input.ClientSecret);
            using var authentication = new InfisicalUniversalAuthentication(environment.Origin, fixture.Network);
            InfisicalUniversalLoginReceipt receipt = authentication.CreateReceipt();
            if (issuance is not null) await issuance.ArmAsync(receipt, token);
            AuthenticationDispatchResult<InfisicalUniversalLogin> dispatch = await AuthenticationDispatch.InvokeAsync(
                environment, definition, probe, "/api/v1/auth/universal-auth/login",
                ct => authentication.LoginAsync(input.ClientId, secret, receipt, input.OrganizationSlug, ct), token);
            if (dispatch.Interrupted)
            {
                probe.Contract(receipt.Evidence == DispatchEvidence.PossiblyDispatched, NativeFailure.ContractMismatch);
                if (issuance is not null)
                    await AuthenticationIssuanceEffects.ObserveAsync(issuance, environment, input.Fixture, probe, token);
                else await fixture.ObserveInterruptedAsync(token);
                return;
            }
            SecretOutcome<InfisicalUniversalLogin> outcome = dispatch.Outcome!;
            using InfisicalUniversalLogin? issued = outcome.IsSuccess ? outcome.Value : null;
            probe.Contract(outcome.Status == (denied ? SecretStatus.Denied : SecretStatus.Success) &&
                receipt.Evidence == (denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied),
                NativeFailure.ContractMismatch);
            if (denied) await fixture.ObserveRejectedAsync(token);
            else await fixture.ObserveLoginAsync(issued!.Token, issued.ExpiresIn, issued.AccessTokenMaxTTL,
                "universal-auth", token, trial, receipt.Evidence);
        }
        finally { if (issuance is not null) await issuance.DisposeAsync(); }
    }

    private sealed record UniversalInput(AuthenticationFixtureInput Fixture, string ClientId, string ClientSecret,
        string DeniedClientSecret, string? OrganizationSlug)
    {
        public override string ToString() => "[UniversalInput]";
    }
}
