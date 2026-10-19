using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class ImportEffectObservationEffects
{
    internal static void Register(NativeCaseRegistry registry, NativeEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected) =>
        InfisicalImportPolicyFamilies.Add(registry, env, expected,
            "i.runtime.InfisicalClient.ObserveImportEffectsAsync",
            "SecretKit.Infisical.InfisicalClient.ObserveImportEffectsAsync(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalClient,SecretKit.Core.SecretReference,System.Threading.CancellationToken)",
            ["selector.exact", "import-visible.delivery-success", "import-visible.delivery-denied",
                "import-absent", "destination-state.Unknown"], false,
            (d, p, t) => ExecuteAsync(env, d, p, t));

    internal sealed record EffectInput(ImportsEffects.ImportInput Fixture, bool RemoveImport, bool DeliveryDenied)
    {
        public override string ToString() => "[EffectInput]";
    }

    private static async ValueTask ExecuteAsync(NativeEnvironment env, NativeCaseDefinition d,
        NativeCaseProbe p, CancellationToken token)
    {
        var i = InfisicalStaticFamilies.Input<EffectInput>(env, "C08-IR-ImportEffectObservation", d);
        if (i.Fixture is null || i.Fixture.Source is null || i.Fixture.Destination is null ||
            i.Fixture.Replacement is null || i.Fixture.Source.Seeds is null || i.Fixture.Destination.Seeds is null)
            throw new NativeCaseFailureException("missing-input");
        p.Contract(i.Fixture.Source.Seeds is { Length: > 0 } && i.Fixture.Destination.Seeds.Length == 0 &&
            !i.Fixture.TwoGroups && i.Fixture.Source.ProjectId == i.Fixture.Destination.ProjectId &&
            i.Fixture.Replacement.ProjectId == i.Fixture.Source.ProjectId, NativeFailure.MissingInput);
        p.Contract(d.Key.Variant != "import-absent" || i.RemoveImport, NativeFailure.MissingInput);
        p.Contract(d.Key.Variant != "import-visible.delivery-denied" || i.DeliveryDenied && !i.RemoveImport,
            NativeFailure.MissingInput);
        p.Contract(d.Key.Variant != "import-visible.delivery-success" || !i.DeliveryDenied && !i.RemoveImport,
            NativeFailure.MissingInput);
        await using var f = new ImportsEffects.OwnedImports(env, i.Fixture, p, d.Key.Scope);
        await f.InitializeAsync(true, token);
        if (i.RemoveImport)
        {
            var target = f.Target(f.Destination.Setup, f.ImportId);
            var receipt = new MutationReceipt(target);
            var removed = await f.Destination.Setup.DeleteImportAsync(target,
                f.Destination.Authority(f.Destination.Setup, NativeIdentityRole.Setup), receipt, token);
            p.Contract(removed.IsSuccess && receipt.Evidence == DispatchEvidence.Applied, NativeFailure.MissingPrerequisite);
            var absence = await f.Destination.Observer.GetImportAsync(f.Target(f.Destination.Observer, f.ImportId), token);
            p.Contract(absence.Status == SecretStatus.Absent, NativeFailure.ObserverUnavailable);
        }
        InfisicalClient c = InfisicalImportPolicyFamilies.Denied(d) ? f.Destination.Denied : f.Destination.Runtime;
        InfisicalClient intended = i.DeliveryDenied ? f.Destination.Denied : f.Destination.Runtime;
        var selected = f.Target(c, f.ImportId);
        var seed = i.Fixture.Source.Seeds[0];
        var intendedSecret = f.Destination.Secret(intended, seed.Key, imports: true);
        var dispatch = await InfisicalImportPolicyFamilies.DispatchAsync(env, d, p,
            "/api/v2/secret-imports/" + f.ImportId, "GET",
            ct => c.ObserveImportEffectsAsync(selected, intended, intendedSecret, ct), token);
        if (!dispatch.Cancelled)
        {
            p.Contract(dispatch.Outcome!.IsSuccess, NativeFailure.ContractMismatch);
            var observed = dispatch.Outcome.Value;
            SecretStatus visibility = InfisicalImportPolicyFamilies.Denied(d) ? SecretStatus.Denied :
                i.RemoveImport ? SecretStatus.Absent : SecretStatus.Success;
            SecretStatus delivery = i.DeliveryDenied ? SecretStatus.Denied :
                i.RemoveImport ? SecretStatus.Absent : SecretStatus.Success;
            p.Contract(observed.VisibilityStatus == visibility && observed.DeliveryStatus == delivery &&
                observed.ImportCreated == (visibility == SecretStatus.Success ?
                    InfisicalEffectEvidence.Observed : InfisicalEffectEvidence.Unknown) &&
                observed.Destination == InfisicalDestinationEvidence.Unknown &&
                observed.FreshIntendedReadSucceeded == (delivery == SecretStatus.Success) &&
                (delivery != SecretStatus.Success || observed.DeliveredAt is not null &&
                    observed.DeliveredVersion is not null), NativeFailure.ContractMismatch);
        }
        await f.Source.ObserveAsync([new(seed.Key, SecretStatus.Success, seed.Value, null)], token);
        await f.Destination.ObserveAsync([new(seed.Key, i.RemoveImport ? SecretStatus.Absent : SecretStatus.Success,
            i.RemoveImport ? null : seed.Value, null)], token, imports: true, denied: i.DeliveryDenied);
        // Actual source and fresh delivery are measured above. They cannot establish
        // destination approval, application or replication causality. G01 remains open.
        env.ConfirmPrerequisite(d.Key.Scope, "destination-approval-primary-contract", NativeObservation.Unavailable);
        p.Effect(NativeObservation.Unavailable);
    }
}
