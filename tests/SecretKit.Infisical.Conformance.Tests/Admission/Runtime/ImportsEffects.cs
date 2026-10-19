using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class ImportsEffects
{
    internal static void Register(NativeCaseRegistry registry, NativeEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected)
    {
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.CreateImportAsync",
            "SecretKit.Infisical.InfisicalClient.CreateImportAsync(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalImportSource,System.Boolean,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)",
            ["replication.false", "replication.true", "source.same-project", "source.selected-other-project"], true,
            (d, p, t) => ExecuteAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.DeleteImportAsync",
            "SecretKit.Infisical.InfisicalClient.DeleteImportAsync(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)",
            ["input.target"], true,
            (d, p, t) => ExecuteAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.GetImportAsync",
            "SecretKit.Infisical.InfisicalClient.GetImportAsync(SecretKit.Core.SecretReference,System.Threading.CancellationToken)",
            ["selector.exact", "source.same-project", "source.selected-other-project", "replication.false", "replication.true"], false,
            (d, p, t) => ExecuteAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.ListImportsAsync",
            "SecretKit.Infisical.InfisicalClient.ListImportsAsync(SecretKit.Core.SecretReference,System.Int32,System.Threading.CancellationToken)",
            ["collection.bounded", "source.same-project", "source.selected-other-project", "replication.false", "replication.true"], false,
            (d, p, t) => ExecuteAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.ReadImportedSecretsAsync",
            "SecretKit.Infisical.InfisicalClient.ReadImportedSecretsAsync(SecretKit.Core.SecretReference,System.Int32,System.Threading.CancellationToken)",
            ["selector.exact", "group-order.preserved", "collection.complete", "collection.item-budget"], false,
            (d, p, t) => ExecuteAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.UpdateImportAsync",
            "SecretKit.Infisical.InfisicalClient.UpdateImportAsync(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.String,System.String,System.Nullable<System.Double>,System.Threading.CancellationToken)",
            ["sourceEnvironment.omitted", "sourceEnvironment.value", "sourcePath.omitted", "sourcePath.value", "position.omitted", "position.value"], true,
            (d, p, t) => ExecuteAsync(env, d, p, t));
    }
    internal sealed record ImportInput(StaticFixtureInput Destination, StaticFixtureInput Source,
        StaticFixtureInput Replacement, bool Replication, bool ExplicitSourceProject,
        bool SupplySourceEnvironment, bool SupplySourcePath, double? Position,
        int MaximumItems, bool ExpectedApplied, bool TwoGroups)
    {
        public override string ToString() => "[ImportInput]";
    }

    internal sealed class OwnedImports : IAsyncDisposable
    {
        internal StaticOwnedFixture Source { get; }
        internal StaticOwnedFixture Replacement { get; }
        internal StaticOwnedFixture Destination { get; }
        internal ImportInput Input { get; }
        private readonly NativeCaseProbe probe;
        internal string? ImportId { get; private set; }
        internal double? SourcePosition { get; private set; }
        internal OwnedImports(NativeEnvironment env, ImportInput input, NativeCaseProbe probe, string scope)
        {
            Input = input;
            this.probe = probe;
            Source = new(env, input.Source, probe, scope);
            Replacement = new(env, input.Replacement, probe, scope);
            Destination = new(env, input.Destination, probe, scope);
        }
        internal async ValueTask InitializeAsync(bool seedImport, CancellationToken token)
        {
            await Source.InitializeAsync(token);
            bool environmentOnly = Input.SupplySourceEnvironment && !Input.SupplySourcePath;
            await Replacement.InitializeAsync(token, environmentOnly ?
                Source.Folder[(Source.Folder.LastIndexOf('/') + 1)..] : null);
            await Destination.InitializeAsync(token);
            if (seedImport) ImportId = await CreateAsync(Source, token);
            if (Input.TwoGroups) await CreateAsync(Replacement, token);
            foreach (StaticSeed seed in Input.Source.Seeds)
                await Destination.ObserveAsync([new(seed.Key, seedImport ? SecretStatus.Success : SecretStatus.Absent,
                    seedImport ? seed.Value : null, null)], token, imports: true, recordEffect: false);
        }
        internal SecretReference Target(InfisicalClient c, string? id = null) => new(c.Authority,
            new InfisicalImportAddress(Input.Destination.ProjectId, Input.Destination.Environment,
                Destination.Folder, Destination.FolderId, id));
        internal InfisicalImportSource SourceAddress(StaticOwnedFixture source) =>
            new(source.Input.Environment, source.Folder,
                Input.ExplicitSourceProject ? source.Input.ProjectId : null);
        internal async ValueTask<string> CreateAsync(StaticOwnedFixture source, CancellationToken token)
        {
            var target = Target(Destination.Setup);
            var receipt = new MutationReceipt(target);
            var created = await Destination.Setup.CreateImportAsync(target, SourceAddress(source), Input.Replication,
                Destination.Authority(Destination.Setup, NativeIdentityRole.Setup), receipt, token);
            probe.Contract(created.IsSuccess && receipt.Evidence == DispatchEvidence.Applied,
                NativeFailure.MissingPrerequisite);
            var observed = await Destination.Observer.GetImportAsync(Target(Destination.Observer, created.Value.Id), token);
            probe.Contract(observed.IsSuccess && observed.Value.SourcePath == source.Folder &&
                observed.Value.SourceEnvironment == source.Input.Environment, NativeFailure.ObserverUnavailable);
            if (ReferenceEquals(source, Source)) SourcePosition = observed.Value.Position;
            return created.Value.Id;
        }
        public async ValueTask DisposeAsync()
        {
            // Destination imports must be gone before removing either source. Even an
            // unacknowledged create is covered by name-scoped owned-folder cleanup.
            try { await Destination.DisposeAsync(); }
            finally
            {
                try { await Replacement.DisposeAsync(); }
                finally { await Source.DisposeAsync(); }
            }
        }
    }

    internal static ImportInput Input(NativeEnvironment env, string family,
        NativeCaseDefinition d, NativeCaseProbe p)
    {
        var i = InfisicalStaticFamilies.Input<ImportInput>(env, family, d);
        if (i.Source is null || i.Replacement is null || i.Destination is null ||
            i.Source.Seeds is null || i.Replacement.Seeds is null || i.Destination.Seeds is null)
            throw new NativeCaseFailureException("missing-input");
        p.Contract(i.Source.Seeds is { Length: > 0 } && i.Replacement.Seeds is { Length: > 0 } &&
            i.Destination.Seeds.Length == 0 && i.MaximumItems is >= 1 and <= 1000 &&
            (!InfisicalImportPolicyFamilies.Denied(d) || !i.ExpectedApplied) &&
            (InfisicalImportPolicyFamilies.Interrupted(d) || InfisicalImportPolicyFamilies.Denied(d) || i.ExpectedApplied) &&
            (i.Source.ProjectId == i.Destination.ProjectId || i.ExplicitSourceProject) &&
            (i.Replacement.ProjectId == i.Source.ProjectId), NativeFailure.MissingInput);
        if (i.SupplySourceEnvironment && !i.SupplySourcePath)
            p.Contract(i.Source.Environment != i.Replacement.Environment &&
                i.Source.OwnedNamespace.TrimEnd('/') == i.Replacement.OwnedNamespace.TrimEnd('/') &&
                i.Source.Seeds.Length == i.Replacement.Seeds.Length &&
                i.Source.Seeds.All(seed => i.Replacement.Seeds.Any(other => other.Key == seed.Key &&
                    other.Value != seed.Value)), NativeFailure.MissingInput);
        string v = d.Key.Variant;
        p.Contract(v != "source.same-project" || i.Source.ProjectId == i.Destination.ProjectId, NativeFailure.MissingInput);
        p.Contract(v != "source.selected-other-project" || i.Source.ProjectId != i.Destination.ProjectId &&
            i.ExplicitSourceProject, NativeFailure.MissingInput);
        p.Contract(v != "replication.true" || i.Replication, NativeFailure.MissingInput);
        p.Contract(v != "replication.false" || !i.Replication, NativeFailure.MissingInput);
        p.Contract(v != "group-order.preserved" || i.TwoGroups, NativeFailure.MissingInput);
        p.Contract(v != "collection.item-budget" || i.MaximumItems < i.Source.Seeds.Length +
            (i.TwoGroups ? i.Replacement.Seeds.Length : 0), NativeFailure.MissingInput);
        p.Contract(v != "collection.complete" || i.MaximumItems >= i.Source.Seeds.Length +
            (i.TwoGroups ? i.Replacement.Seeds.Length : 0), NativeFailure.MissingInput);
        foreach ((string field, bool supplied) in new[] { ("sourceEnvironment", i.SupplySourceEnvironment),
            ("sourcePath", i.SupplySourcePath), ("position", i.Position is not null) })
        {
            p.Contract(v != field + ".omitted" || !supplied, NativeFailure.MissingInput);
            p.Contract(v != field + ".value" || supplied, NativeFailure.MissingInput);
        }
        return i;
    }

    private static async ValueTask ExecuteAsync(NativeEnvironment env, NativeCaseDefinition d,
        NativeCaseProbe p, CancellationToken token)
    {
        ImportInput i = Input(env, "C08-IR-Imports", d, p);
        bool create = d.Key.Operation.EndsWith(".CreateImportAsync", StringComparison.Ordinal);
        bool update = d.Key.Operation.EndsWith(".UpdateImportAsync", StringComparison.Ordinal);
        bool delete = d.Key.Operation.EndsWith(".DeleteImportAsync", StringComparison.Ordinal);
        bool list = d.Key.Operation.EndsWith(".ListImportsAsync", StringComparison.Ordinal);
        bool read = d.Key.Operation.EndsWith(".ReadImportedSecretsAsync", StringComparison.Ordinal);
        p.Contract(!i.TwoGroups || read, NativeFailure.MissingInput);
        p.Contract(!update || !i.SupplySourcePath || i.SupplySourceEnvironment ||
            i.Source.Environment == i.Replacement.Environment, NativeFailure.MissingInput);
        await using var f = new OwnedImports(env, i, p, d.Key.Scope);
        await f.InitializeAsync(!create, token);
        bool denied = InfisicalImportPolicyFamilies.Denied(d);
        InfisicalClient c = denied ? f.Destination.Denied : f.Destination.Runtime;
        var target = f.Target(c, create || list || read ? null : f.ImportId);
        var receipt = new MutationReceipt(target);
        var authority = f.Destination.Authority(c, denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime);
        string path = "/api/v2/secret-imports" + (read ? "/secrets" : create || list ? "" : "/" + f.ImportId);
        string? selectedId = f.ImportId;
        string[]? groupOrder = null;
        if (list)
        {
            var dispatch = await InfisicalImportPolicyFamilies.DispatchAsync(env, d, p, path, "GET",
                ct => c.ListImportsAsync(target, i.MaximumItems, ct), token);
            InfisicalImportPolicyFamilies.Result(dispatch, null, denied ? SecretStatus.Denied : SecretStatus.Success, default, p);
            if (dispatch.Outcome is { IsSuccess: true } result)
                p.Contract(result.Value.IsComplete && result.Value.Items.Count == 1 &&
                    Matches(result.Value.Items[0], f.Source, i.Replication), NativeFailure.ContractMismatch);
        }
        else if (read)
        {
            var dispatch = await InfisicalImportPolicyFamilies.DispatchAsync(env, d, p, path, "GET",
                ct => c.ReadImportedSecretsAsync(target, i.MaximumItems, ct), token);
            InfisicalImportPolicyFamilies.Result(dispatch, null, denied ? SecretStatus.Denied : SecretStatus.Success, default, p);
            if (dispatch.Outcome is { IsSuccess: true } result)
            {
                using InfisicalImportedSecrets secrets = result.Value;
                StaticOwnedFixture[] sources = i.TwoGroups ? [f.Source, f.Replacement] : [f.Source];
                var all = sources.SelectMany(s => s.Input.Seeds.Select(seed => (s, seed))).ToArray();
                p.Contract(secrets.IsComplete == (i.MaximumItems >= all.Length) &&
                    secrets.Items.Count == Math.Min(i.MaximumItems, all.Length) &&
                    secrets.Groups.Count == sources.Length &&
                    secrets.Groups.Select(g => (g.Path, g.Environment, g.FolderId)).Distinct().Count() == sources.Length &&
                    secrets.Groups.All(g => sources.Any(s => g.Path == s.Folder &&
                        g.Environment == s.Input.Environment && g.FolderId == s.FolderId)) &&
                    secrets.Items.Select(item => (item.ProjectId, item.Environment, item.Path, item.Key))
                        .Distinct().Count() == secrets.Items.Count, NativeFailure.ContractMismatch);
                groupOrder = secrets.Groups.Select(g => g.Path).ToArray();
                for (int index = 0; index < secrets.Groups.Count; index++)
                {
                    var group = secrets.Groups[index];
                    var source = sources.SingleOrDefault(s => s.Folder == group.Path);
                    p.Contract(source is not null && group.Environment == source.Input.Environment &&
                        group.FolderId == source.FolderId, NativeFailure.ContractMismatch);
                }
                foreach (var item in secrets.Items)
                {
                    var seed = all.SingleOrDefault(s => s.s.Folder == item.Path && s.seed.Key == item.Key);
                    p.Contract(seed.s is not null && item.ProjectId == seed.s.Input.ProjectId &&
                        item.Environment == seed.s.Input.Environment && item.Material.Reveal() == seed.seed.Value,
                        NativeFailure.ContractMismatch);
                }
            }
        }
        else
        {
            var dispatch = await InfisicalImportPolicyFamilies.DispatchAsync(env, d, p, path,
                create ? "POST" : update ? "PATCH" : delete ? "DELETE" : "GET",
                ct => create ? c.CreateImportAsync(target, f.SourceAddress(f.Source), i.Replication, authority, receipt, ct) :
                    update ? c.UpdateImportAsync(target, authority, receipt,
                        i.SupplySourceEnvironment ? f.Replacement.Input.Environment : null,
                        i.SupplySourcePath ? f.Replacement.Folder : null, i.Position, ct) :
                    delete ? c.DeleteImportAsync(target, authority, receipt, ct) : c.GetImportAsync(target, ct), token);
            InfisicalImportPolicyFamilies.Result(dispatch, create || update || delete ? receipt : null,
                denied ? SecretStatus.Denied : SecretStatus.Success,
                InfisicalImportPolicyFamilies.Interrupted(d) ? DispatchEvidence.PossiblyDispatched :
                    denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied, p);
            if (create && dispatch.Outcome is { IsSuccess: true } result) selectedId = result.Value.Id;
            if (!create && !update && !delete && dispatch.Outcome is { IsSuccess: true } readResult)
                p.Contract(readResult.Value.Id == f.ImportId && Matches(readResult.Value, f.Source, i.Replication),
                    NativeFailure.ContractMismatch);
        }
        var observed = await f.Destination.Observer.ListImportsAsync(f.Target(f.Destination.Observer), cancellationToken: token);
        p.Contract(observed.IsSuccess && observed.Value.IsComplete, NativeFailure.ObserverUnavailable);
        bool absent = create && !i.ExpectedApplied || delete && i.ExpectedApplied;
        bool changedSource = update && i.ExpectedApplied && (i.SupplySourcePath || i.SupplySourceEnvironment);
        StaticOwnedFixture expectedSource = changedSource ? f.Replacement : f.Source;
        if (read)
        {
            var independentlyGrouped = await f.Destination.Observer.ReadImportedSecretsAsync(
                f.Target(f.Destination.Observer), cancellationToken: token);
            p.Contract(independentlyGrouped.IsSuccess, NativeFailure.ObserverUnavailable);
            using var groups = independentlyGrouped.Value;
            StaticOwnedFixture[] sources = i.TwoGroups ? [f.Source, f.Replacement] : [f.Source];
            p.Effect(groups.IsComplete && groups.Groups.Count == sources.Length &&
                groups.Groups.Select(g => (g.Path, g.Environment, g.FolderId)).Distinct().Count() == sources.Length &&
                groups.Groups.All(g => sources.Any(s => g.Path == s.Folder &&
                    g.Environment == s.Input.Environment && g.FolderId == s.FolderId)) &&
                groups.Items.Select(item => (item.ProjectId, item.Environment, item.Path, item.Key))
                    .Distinct().Count() == groups.Items.Count ?
                NativeObservation.Matched : NativeObservation.Mismatched);
            if (groupOrder is not null)
                p.Effect(groups.Groups.Select(g => g.Path).SequenceEqual(groupOrder) ?
                    NativeObservation.Matched : NativeObservation.Mismatched);
            for (int index = 0; index < sources.Length; index++)
            {
                var group = groups.Groups[index];
                var source = sources.SingleOrDefault(s => s.Folder == group.Path);
                p.Contract(source is not null, NativeFailure.ObserverUnavailable);
                p.Effect(group.Environment == source!.Input.Environment &&
                    group.FolderId == source.FolderId && group.Items.Count == source.Input.Seeds.Length &&
                    group.Items.All(item => source.Input.Seeds.Any(seed => item.Key == seed.Key &&
                        item.Material.Reveal() == seed.Value && item.ProjectId == source.Input.ProjectId)) ?
                        NativeObservation.Matched : NativeObservation.Mismatched);
                foreach (StaticSeed seed in source.Input.Seeds)
                    await source.ObserveAsync([new(seed.Key, SecretStatus.Success, seed.Value, null)], token);
            }
        }
        var import = observed.Value.Items.SingleOrDefault(s => selectedId is null ?
            s.SourcePath == f.Source.Folder : s.Id == selectedId);
        p.Effect(absent ? import is null ? NativeObservation.Matched : NativeObservation.Mismatched :
            import is not null && Matches(import, expectedSource, i.Replication) &&
                (!update || import.Position == (i.ExpectedApplied ? i.Position ?? f.SourcePosition : f.SourcePosition)) ?
                NativeObservation.Matched : NativeObservation.Mismatched);
        // Fetch actual source material, then actual intended/observer delivery. No
        // acknowledgement or replication status string substitutes for these reads.
        foreach (StaticSeed seed in expectedSource.Input.Seeds)
        {
            await expectedSource.ObserveAsync([new(seed.Key, SecretStatus.Success, seed.Value, null)], token);
            await f.Destination.ObserveAsync([new(seed.Key, absent ? SecretStatus.Absent : SecretStatus.Success,
                absent ? null : seed.Value, null)], token, imports: true);
        }
        if (i.Replication) p.Effect(NativeObservation.Unavailable);
    }

    private static bool Matches(InfisicalImport import, StaticOwnedFixture source, bool replication) =>
        import.SourcePath == source.Folder && import.SourceEnvironment == source.Input.Environment &&
        import.SourceProjectId == source.Input.ProjectId && import.IsReplication == replication;
}
