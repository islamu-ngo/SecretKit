using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class InfisicalStaticChangesEffects
{
    private const string Create = "i.runtime.InfisicalClient.CreateAsync";
    private const string Update = "i.runtime.InfisicalClient.UpdateValueAsync";
    private const string CreateMember = "SecretKit.Infisical.InfisicalClient.CreateAsync(SecretKit.Core.SecretReference,SecretKit.Core.SecretMaterial,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)";
    private const string UpdateMember = "SecretKit.Infisical.InfisicalClient.UpdateValueAsync(SecretKit.Core.SecretReference,SecretKit.Core.SecretMaterial,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)";

    internal static void Register(NativeCaseRegistry registry, NativeEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected)
    {
        foreach (NativeCaseDefinition definition in expected.Where(d =>
            d.Key.Provider == "Infisical" && d.Key.Operation is Create or Update))
        {
            registry.Add(new(definition, (probe, token) => InfisicalStaticFamilies.BoundedAsync(probe, token,
                bounded => ExecuteAsync(env, definition, probe, bounded))));
        }
    }

    private static async ValueTask ExecuteAsync(NativeEnvironment env, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token)
    {
        bool update = definition.Key.Operation == Update;
        probe.Contract(definition.Member == (update ? UpdateMember : CreateMember) &&
            definition.Key.Variant is "shared.raw.unversioned.Applied" or
                "shared.raw.unversioned.SubmittedForApproval" &&
            InfisicalStaticFamilies.Case(definition.Key.Case, true), NativeFailure.ContractMismatch);
        StaticChangeInput input = InfisicalStaticFamilies.Input<StaticChangeInput>(
            env, "C08-IR-InfisicalStaticChanges", definition);
        bool denied = definition.Key.Case == "denied-authority";
        bool interrupted = definition.Key.Case is "cancellation-boundary" or "lost-response-no-replay";
        bool approval = definition.Key.Variant.EndsWith(".SubmittedForApproval", StringComparison.Ordinal);
        probe.Contract(!string.IsNullOrWhiteSpace(input.Key) && input.ExpectedState is { Length: > 0 } &&
            input.ExpectedState.Any(s => s.Key == input.Key) &&
            (update ? input.Fixture.Seeds.Any(s => s.Key == input.Key) :
                !input.Fixture.Seeds.Any(s => s.Key == input.Key)) &&
            input.ExpectedStatus == (denied ? SecretStatus.Denied : SecretStatus.Success) &&
            input.ExpectedReceipt == (denied ? DispatchEvidence.Rejected : interrupted ?
                DispatchEvidence.PossiblyDispatched : approval ? DispatchEvidence.Pending : DispatchEvidence.Applied) &&
            input.ExpectedDisposition == (approval ? InfisicalChangeDisposition.SubmittedForApproval :
                InfisicalChangeDisposition.Applied), NativeFailure.MissingInput);
        if (denied || approval)
            probe.Contract(InfisicalStaticFamilies.Unchanged(input.ExpectedState, input.Fixture.Seeds),
                NativeFailure.MissingInput);
        else if (!interrupted)
            probe.Contract(input.ExpectedState.Single(s => s.Key == input.Key) is
            { Status: SecretStatus.Success } state && state.Value == input.Value, NativeFailure.MissingInput);

        await using var fixture = new StaticOwnedFixture(env, input.Fixture, probe, definition.Key.Scope);
        await fixture.InitializeAsync(token);
        InfisicalClient client = denied ? fixture.Denied : fixture.Runtime;
        SecretReference target = fixture.Secret(client, input.Key);
        var receipt = new MutationReceipt(target);
        using SecretMaterial material = SecretMaterial.FromText(input.Value);
        StaticDispatch<InfisicalStaticChange> dispatch = await InfisicalStaticFamilies.DispatchAsync(env,
            definition, probe, ct => update ? client.UpdateValueAsync(target, material, receipt, ct) :
                client.CreateAsync(target, material, receipt, ct), token);
        probe.Contract(receipt.Evidence == input.ExpectedReceipt, NativeFailure.ContractMismatch);
        if (!dispatch.Cancelled)
        {
            SecretOutcome<InfisicalStaticChange> result = dispatch.Outcome!;
            probe.Contract(result.Status == input.ExpectedStatus &&
                (!result.IsSuccess || result.Value.Disposition == input.ExpectedDisposition),
                NativeFailure.ContractMismatch);
        }
        await fixture.ObserveAsync(input.ExpectedState, token, denied: denied);
        // Read absence/old material does not independently establish a pending approval.
        // The SDK intentionally has no established approval administration/status contract.
        if (approval && !denied) probe.Effect(NativeObservation.Unavailable);
    }

    internal sealed record StaticChangeInput(StaticFixtureInput Fixture, string Key, string Value,
        SecretStatus ExpectedStatus, DispatchEvidence ExpectedReceipt,
        InfisicalChangeDisposition ExpectedDisposition, StaticExpectedSecret[] ExpectedState)
    {
        public override string ToString() => "[StaticChangeInput]";
    }
}
