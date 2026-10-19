using System.Globalization;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class InfisicalClientEffects
{
    private const string Read = "i.runtime.InfisicalClient.ReadAsync";
    private const string Inspect = "i.runtime.InfisicalClient.InspectAsync";
    private const string ReadMember = "SecretKit.Infisical.InfisicalClient.ReadAsync(SecretKit.Core.SecretReference,System.Threading.CancellationToken)";
    private const string InspectMember = "SecretKit.Infisical.InfisicalClient.InspectAsync(SecretKit.Core.SecretInventoryScope,System.Threading.CancellationToken)";

    internal static void Register(NativeCaseRegistry registry, NativeEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected)
    {
        foreach (NativeCaseDefinition definition in expected.Where(d =>
            d.Key.Provider == "Infisical" && d.Key.Operation is Read or Inspect))
            registry.Add(new(definition, (probe, token) => InfisicalStaticFamilies.BoundedAsync(probe, token,
                bounded => ExecuteAsync(env, definition, probe, bounded))));
    }

    private static async ValueTask ExecuteAsync(NativeEnvironment env, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token)
    {
        bool inventory = definition.Key.Operation == Inspect;
        probe.Contract(definition.Member == (inventory ? InspectMember : ReadMember) &&
            InfisicalStaticFamilies.Case(definition.Key.Case, false), NativeFailure.ContractMismatch);
        if (inventory) await InspectAsync(env, definition, probe, token);
        else await ReadAsync(env, definition, probe, token);
    }

    private static async ValueTask ReadAsync(NativeEnvironment env, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token)
    {
        (bool pinned, InfisicalResolution resolution, bool imports) = definition.Key.Variant switch
        {
            "latest.Raw.direct" => (false, InfisicalResolution.Raw, false),
            "latest.Raw.imports" => (false, InfisicalResolution.Raw, true),
            "latest.ExpandedReferences.direct" => (false, InfisicalResolution.ExpandedReferences, false),
            "latest.ExpandedReferences.imports" => (false, InfisicalResolution.ExpandedReferences, true),
            "version.Raw.direct" => (true, InfisicalResolution.Raw, false),
            "version.Raw.imports" => (true, InfisicalResolution.Raw, true),
            "version.ExpandedReferences.direct" => (true, InfisicalResolution.ExpandedReferences, false),
            "version.ExpandedReferences.imports" => (true, InfisicalResolution.ExpandedReferences, true),
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        StaticReadInput input = InfisicalStaticFamilies.Input<StaticReadInput>(
            env, "C08-IR-InfisicalClient", definition);
        bool denied = definition.Key.Case == "denied-authority";
        probe.Contract(input.ExpectedState is { Length: 1 } && input.ExpectedState[0].Key == input.Key &&
            input.ExpectedState[0].Status == SecretStatus.Success &&
            input.ExpectedStatus == (denied ? SecretStatus.Denied : SecretStatus.Success) &&
            (pinned ? input.Version == 1 && input.LatestValue is not null : input.Version is null) &&
            (imports ? input.ImportSeeds.Any(s => s.Key == input.Key) &&
                !input.Fixture.Seeds.Any(s => s.Key == input.Key) :
                input.ImportSeeds.Length == 0 && input.Fixture.Seeds.Any(s => s.Key == input.Key)),
            NativeFailure.MissingInput);
        StaticSeed selected = (imports ? input.ImportSeeds : input.Fixture.Seeds).Single(s => s.Key == input.Key);
        probe.Contract(!pinned || selected.Value != input.LatestValue, NativeFailure.MissingInput);
        if (resolution == InfisicalResolution.ExpandedReferences)
            probe.Contract(selected.Value != input.ExpectedState[0].Value &&
                (imports ? input.ImportSeeds : input.Fixture.Seeds).Length >= 2, NativeFailure.MissingInput);

        await using var fixture = new StaticOwnedFixture(env, input.Fixture, probe, definition.Key.Scope);
        await fixture.InitializeAsync(token);
        string sourceFolder = fixture.Folder;
        if (imports)
        {
            (sourceFolder, _) = await fixture.AddFolderAsync(token);
            foreach (StaticSeed seed in input.ImportSeeds)
                await fixture.SeedAsync(seed.Key, seed.Value, sourceFolder, token);
        }
        if (pinned)
        {
            SecretReference updateTarget = fixture.Secret(fixture.Setup, input.Key, sourceFolder);
            var receipt = new MutationReceipt(updateTarget);
            using SecretMaterial material = SecretMaterial.FromText(input.LatestValue!);
            SecretOutcome<InfisicalStaticChange> updated = await fixture.Setup.UpdateValueAsync(
                updateTarget, material, receipt, token);
            probe.Contract(updated.IsSuccess && updated.Value.Disposition == InfisicalChangeDisposition.Applied,
                NativeFailure.MissingPrerequisite);
            await fixture.ObserveAsync([new(input.Key, SecretStatus.Success, input.LatestValue, 2)], token,
                sourceFolder, recordEffect: false);
        }
        if (imports)
        {
            var target = new SecretReference(fixture.Setup.Authority, new InfisicalImportAddress(
                input.Fixture.ProjectId, input.Fixture.Environment, fixture.Folder, fixture.FolderId));
            var receipt = new MutationReceipt(target);
            SecretOutcome<InfisicalImport> created = await fixture.Setup.CreateImportAsync(target,
                new(input.Fixture.Environment, sourceFolder), false,
                fixture.Authority(fixture.Setup, NativeIdentityRole.Setup), receipt, token);
            probe.Contract(created.IsSuccess && receipt.Evidence == DispatchEvidence.Applied,
                NativeFailure.MissingPrerequisite);
            var observedTarget = new SecretReference(fixture.Observer.Authority, new InfisicalImportAddress(
                input.Fixture.ProjectId, input.Fixture.Environment, fixture.Folder, fixture.FolderId, created.Value.Id));
            SecretOutcome<InfisicalImport> observed = await fixture.Observer.GetImportAsync(observedTarget, token);
            probe.Contract(observed.IsSuccess && observed.Value.SourcePath == sourceFolder &&
                observed.Value.SourceEnvironment == input.Fixture.Environment &&
                observed.Value.FolderId == fixture.FolderId, NativeFailure.ObserverUnavailable);
        }
        InfisicalClient client = denied ? fixture.Denied : fixture.Runtime;
        StaticDispatch<SecretRead> dispatch = await InfisicalStaticFamilies.DispatchAsync(env, definition, probe,
            ct => client.ReadAsync(fixture.Secret(client, input.Key, version: input.Version,
                resolution: resolution, imports: imports), ct), token);
        if (!dispatch.Cancelled)
        {
            SecretOutcome<SecretRead> result = dispatch.Outcome!;
            if (result.IsSuccess)
            {
                using SecretRead read = result.Value;
                probe.Contract(input.ExpectedStatus == SecretStatus.Success &&
                    read.Material.Reveal() == input.ExpectedState[0].Value &&
                    (!pinned || read.Observation.Version == input.Version!.Value.ToString(CultureInfo.InvariantCulture)),
                    NativeFailure.ContractMismatch);
            }
            else probe.Contract(result.Status == input.ExpectedStatus, NativeFailure.ContractMismatch);
        }
        // Independent source and destination reads distinguish import delivery from a local shadow.
        await fixture.ObserveAsync(input.ExpectedState, token, sourceFolder, input.Version, resolution);
        await fixture.ObserveAsync(input.ExpectedState, token, version: input.Version,
            resolution: resolution, imports: imports, denied: denied);
    }

    private static async ValueTask InspectAsync(NativeEnvironment env, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token)
    {
        bool budget = definition.Key.Variant switch
        {
            "direct-folder.metadata.complete" => false,
            "direct-folder.metadata.item-budget" => true,
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        StaticInventoryInput input = InfisicalStaticFamilies.Input<StaticInventoryInput>(
            env, "C08-IR-InfisicalClient", definition);
        bool denied = definition.Key.Case == "denied-authority";
        probe.Contract(input.ExpectedState is { Length: > 0 } &&
            input.Fixture.Seeds.Length == input.ExpectedState.Length &&
            input.Fixture.Seeds.Select(s => s.Key).Order(StringComparer.Ordinal).SequenceEqual(
                input.ExpectedState.Select(s => s.Key).Order(StringComparer.Ordinal)) &&
            input.ExpectedState.All(s => s.Status == SecretStatus.Success) &&
            input.ExpectedStatus == (denied ? SecretStatus.Denied : SecretStatus.Success) &&
            input.ExpectedComplete == !budget && input.MaximumItems is > 0 and <= 10000 &&
            (budget ? input.MaximumItems < input.ExpectedState.Length : input.MaximumItems >= input.ExpectedState.Length) &&
            input.ExpectedKeys.Length == (budget ? input.MaximumItems : input.ExpectedState.Length),
            NativeFailure.MissingInput);
        await using var fixture = new StaticOwnedFixture(env, input.Fixture, probe, definition.Key.Scope);
        await fixture.InitializeAsync(token);
        InfisicalClient client = denied ? fixture.Denied : fixture.Runtime;
        var scope = new InfisicalInventoryScope(client.Authority, input.Fixture.ProjectId,
            input.Fixture.Environment, fixture.Folder, input.MaximumItems);
        StaticDispatch<SecretInventory> dispatch = await InfisicalStaticFamilies.DispatchAsync(env,
            definition, probe, ct => client.InspectAsync(scope, ct), token);
        if (!dispatch.Cancelled)
        {
            SecretOutcome<SecretInventory> result = dispatch.Outcome!;
            probe.Contract(result.Status == input.ExpectedStatus, NativeFailure.ContractMismatch);
            if (result.IsSuccess)
                probe.Contract(result.Value.IsComplete == input.ExpectedComplete &&
                    Keys(result.Value).SequenceEqual(input.ExpectedKeys.Order(StringComparer.Ordinal)) &&
                    result.Value.Items.All(s => s.Reference.Address is InfisicalSecretAddress address &&
                        address.ProjectId == input.Fixture.ProjectId && address.Environment == input.Fixture.Environment &&
                        address.Folder == fixture.Folder), NativeFailure.ContractMismatch);
        }
        var observerScope = new InfisicalInventoryScope(fixture.Observer.Authority, input.Fixture.ProjectId,
            input.Fixture.Environment, fixture.Folder);
        SecretOutcome<SecretInventory> observed = await fixture.Observer.InspectAsync(observerScope, token);
        if (!observed.IsSuccess) probe.Effect(NativeObservation.Unavailable);
        probe.Effect(observed.Value.IsComplete && Keys(observed.Value).SequenceEqual(
            input.ExpectedState.Select(s => s.Key).Order(StringComparer.Ordinal)) ?
            NativeObservation.Matched : NativeObservation.Mismatched);
        await fixture.ObserveAsync(input.ExpectedState, token, denied: denied);
    }

    private static IEnumerable<string> Keys(SecretInventory inventory) => inventory.Items
        .Select(s => s.Reference.Address is InfisicalSecretAddress address ? address.Key : "")
        .Order(StringComparer.Ordinal);

    internal sealed record StaticReadInput(StaticFixtureInput Fixture, string Key, int? Version,
        string? LatestValue, StaticSeed[] ImportSeeds, SecretStatus ExpectedStatus,
        StaticExpectedSecret[] ExpectedState)
    {
        public override string ToString() => "[StaticReadInput]";
    }

    internal sealed record StaticInventoryInput(StaticFixtureInput Fixture, int MaximumItems,
        SecretStatus ExpectedStatus, bool ExpectedComplete, string[] ExpectedKeys,
        StaticExpectedSecret[] ExpectedState)
    {
        public override string ToString() => "[StaticInventoryInput]";
    }
}
