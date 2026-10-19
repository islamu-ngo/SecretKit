using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class InfisicalTokenRevocationEffects
{
    internal const string Operation = "i.runtime.InfisicalProofAuthentication.RevokeTokenAsync";
    internal const string Member = "SecretKit.Infisical.InfisicalProofAuthentication.RevokeTokenAsync(SecretKit.Core.SecretMaterial,SecretKit.Infisical.InfisicalTokenRevocationReceipt,System.Threading.CancellationToken)";
    internal static readonly string[] Variants = ["input.token"];

    internal static void Register(NativeCaseRegistry registry, NativeEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected) =>
        InfisicalAuthenticationFamilies.RegisterFamily(registry, environment, expected, Operation, Member,
            Variants, (definition, probe, token) => ExecuteAsync(environment, definition, probe, token));

    private static async ValueTask ExecuteAsync(NativeEnvironment environment, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token)
    {
        RevocationInput input = InfisicalAuthenticationFamilies.Input<RevocationInput>(environment,
            "C08-IR-InfisicalTokenRevocation", definition);
        await using var fixture = new AuthenticationFixture(environment, input.Fixture, probe, definition.Key.Scope);
        await fixture.InitializeAsync(token);
        using TokenAuthTokenCreation issued = await fixture.IssueTokenAsync(token);
        await fixture.ObserveRevocationAsync(issued, false, token, recordEffect: false);
        bool denied = definition.Key.Case == "denied-authority";
        if (denied)
        {
            // Revoke only the fresh owned credential, never one of the five host role
            // tokens. A separately invalidated credential supplies the denied principal.
            await fixture.InvalidateAsync(issued.Metadata.Id, token);
            await fixture.ObserveRevocationAsync(issued, true, token, recordEffect: false);
        }
        using var authentication = new InfisicalProofAuthentication(environment.Origin, fixture.Network);
        InfisicalTokenRevocationReceipt receipt = authentication.CreateRevocationReceipt();
        AuthenticationDispatchResult<SecretStatus> dispatch = await AuthenticationDispatch.InvokeAsync(
            environment, definition, probe, "/api/v1/auth/token/revoke", async ct =>
            {
                SecretStatus status = await authentication.RevokeTokenAsync(issued.AccessToken, receipt, ct);
                return SecretOutcome<SecretStatus>.Success(status);
            }, token);
        if (dispatch.Interrupted)
        {
            probe.Contract(receipt.Evidence == DispatchEvidence.PossiblyDispatched, NativeFailure.ContractMismatch);
            if (definition.Key.Case == "lost-response-no-replay")
                await fixture.ObserveRevocationAsync(issued, true, token);
            else
            {
                // HeadersStart precedes native receipt. Observe either actual state
                // without asserting that cancellation rolled back the mutation.
                await fixture.ObserveRevocationAsync(issued, null, token);
            }
            return;
        }
        probe.Contract(dispatch.Outcome!.Value == (denied ? SecretStatus.Denied : SecretStatus.Success) &&
            receipt.Evidence == (denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied),
            NativeFailure.ContractMismatch);
        await fixture.ObserveRevocationAsync(issued, true, token);
    }

    private sealed record RevocationInput(AuthenticationFixtureInput Fixture)
    {
        public override string ToString() => "[RevocationInput]";
    }
}
