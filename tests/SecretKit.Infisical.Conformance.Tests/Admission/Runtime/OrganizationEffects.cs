using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class OrganizationEffects
{
    internal static void Register(NativeCaseRegistry registry, NativeEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected)
    {
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.CreateEnvironmentAsync",
            "SecretKit.Infisical.InfisicalClient.CreateEnvironmentAsync(SecretKit.Core.SecretReference,System.String,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Nullable<System.Double>,System.Threading.CancellationToken)",
            ["position.omitted", "position.value"], true,
            (d, p, t) => EnvironmentAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.CreateFolderAsync",
            "SecretKit.Infisical.InfisicalClient.CreateFolderAsync(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.String,System.Threading.CancellationToken)",
            ["description.omitted", "description.value"], true,
            (d, p, t) => FolderAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.CreateTagAsync",
            "SecretKit.Infisical.InfisicalClient.CreateTagAsync(SecretKit.Core.SecretReference,System.String,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)",
            ["input.target-color"], true,
            (d, p, t) => TagAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.DeleteEnvironmentAsync",
            "SecretKit.Infisical.InfisicalClient.DeleteEnvironmentAsync(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Boolean,System.Threading.CancellationToken)",
            ["hardDelete.false", "hardDelete.true"], true,
            (d, p, t) => EnvironmentAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.DeleteFolderAsync",
            "SecretKit.Infisical.InfisicalClient.DeleteFolderAsync(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Boolean,System.Threading.CancellationToken)",
            ["forceDelete.false", "forceDelete.true", "selector.id", "selector.name"], true,
            (d, p, t) => FolderAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.DeleteTagAsync",
            "SecretKit.Infisical.InfisicalClient.DeleteTagAsync(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)",
            ["input.target"], true,
            (d, p, t) => TagAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.GetEnvironmentAsync",
            "SecretKit.Infisical.InfisicalClient.GetEnvironmentAsync(SecretKit.Core.SecretReference,System.Threading.CancellationToken)",
            ["selector.Id", "selector.Slug"], false,
            (d, p, t) => EnvironmentAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.GetFolderAsync",
            "SecretKit.Infisical.InfisicalClient.GetFolderAsync(SecretKit.Core.SecretReference,System.Threading.CancellationToken)",
            ["selector.exact"], false,
            (d, p, t) => FolderAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.GetTagAsync",
            "SecretKit.Infisical.InfisicalClient.GetTagAsync(SecretKit.Core.SecretReference,System.Threading.CancellationToken)",
            ["selector.Id", "selector.Slug"], false,
            (d, p, t) => TagAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.ListFoldersAsync",
            "SecretKit.Infisical.InfisicalClient.ListFoldersAsync(SecretKit.Core.SecretReference,System.Int32,System.Boolean,System.Nullable<System.DateTimeOffset>,System.Threading.CancellationToken)",
            ["recursive.false", "recursive.true", "lastSecretModified.omitted", "lastSecretModified.value"], false,
            (d, p, t) => FolderAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.ListTagsAsync",
            "SecretKit.Infisical.InfisicalClient.ListTagsAsync(SecretKit.Core.SecretReference,System.Int32,System.Threading.CancellationToken)",
            ["collection.bounded"], false,
            (d, p, t) => TagAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.MoveFolderAsync",
            "SecretKit.Infisical.InfisicalClient.MoveFolderAsync(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalFolderAddress,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)",
            ["input.target-destination"], true,
            (d, p, t) => FolderAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.RestoreEnvironmentAsync",
            "SecretKit.Infisical.InfisicalClient.RestoreEnvironmentAsync(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)",
            ["input.target"], true,
            (d, p, t) => EnvironmentAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.UpdateEnvironmentAsync",
            "SecretKit.Infisical.InfisicalClient.UpdateEnvironmentAsync(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.String,System.String,System.Nullable<System.Double>,System.Threading.CancellationToken)",
            ["name.omitted", "name.value", "slug.omitted", "slug.value", "position.omitted", "position.value"], true,
            (d, p, t) => EnvironmentAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.UpdateFolderAsync",
            "SecretKit.Infisical.InfisicalClient.UpdateFolderAsync(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.String,System.Boolean,System.Threading.CancellationToken)",
            ["description.omitted", "description.value", "clearDescription.false", "clearDescription.true"], true,
            (d, p, t) => FolderAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.UpdateFoldersAsync",
            "SecretKit.Infisical.InfisicalClient.UpdateFoldersAsync(SecretKit.Core.SecretReference,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.InfisicalFolderUpdate>,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)",
            ["description.omitted", "description.null", "description.value", "result.all-selected", "result.partial"], true,
            (d, p, t) => FolderAsync(env, d, p, t));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.UpdateTagAsync",
            "SecretKit.Infisical.InfisicalClient.UpdateTagAsync(SecretKit.Core.SecretReference,System.String,System.String,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)",
            ["input.target-slug-color"], true,
            (d, p, t) => TagAsync(env, d, p, t));
    }

    internal sealed record OrganizationInput(StaticFixtureInput Fixture, string? Description,
        bool ClearDescription, double? Position, string? Name, bool RenameSlug, bool ForceDelete,
        bool HardDelete, bool Recursive, DateTimeOffset? LastSecretModified, int MaximumItems,
        bool ExpectedApplied, bool PartialBatch, bool[]? BatchApplied = null)
    {
        public override string ToString() => "[OrganizationInput]";
    }

    private static OrganizationInput Input(NativeEnvironment env, NativeCaseDefinition d, NativeCaseProbe p)
    {
        OrganizationInput i = InfisicalStaticFamilies.Input<OrganizationInput>(env, "C08-IR-Organization", d);
        if (i.Fixture is null || i.Fixture.Seeds is null)
            throw new NativeCaseFailureException("missing-input");
        string v = d.Key.Variant;
        p.Contract(i.MaximumItems is >= 1 and <= 1000 &&
            (!InfisicalImportPolicyFamilies.Denied(d) || !i.ExpectedApplied) &&
            (InfisicalImportPolicyFamilies.Interrupted(d) || InfisicalImportPolicyFamilies.Denied(d) ||
                i.ExpectedApplied), NativeFailure.MissingInput);
        foreach ((string field, bool supplied) in new[] { ("description", i.Description is not null),
            ("position", i.Position is not null), ("name", i.Name is not null),
            ("slug", i.RenameSlug), ("lastSecretModified", i.LastSecretModified is not null) })
        {
            p.Contract(v != field + ".omitted" || !supplied, NativeFailure.MissingInput);
            p.Contract(v != field + ".value" || supplied, NativeFailure.MissingInput);
        }
        p.Contract(v != "description.null" || i.ClearDescription, NativeFailure.MissingInput);
        foreach ((string field, bool value) in new[] { ("clearDescription", i.ClearDescription),
            ("forceDelete", i.ForceDelete), ("hardDelete", i.HardDelete), ("recursive", i.Recursive) })
            p.Contract(v != field + ".true" || value, NativeFailure.MissingInput);
        foreach ((string field, bool value) in new[] { ("clearDescription", i.ClearDescription),
            ("forceDelete", i.ForceDelete), ("hardDelete", i.HardDelete), ("recursive", i.Recursive) })
            p.Contract(v != field + ".false" || !value, NativeFailure.MissingInput);
        p.Contract(v != "result.partial" || i.PartialBatch, NativeFailure.MissingInput);
        p.Contract(v != "result.all-selected" || !i.PartialBatch, NativeFailure.MissingInput);
        p.Contract(!i.PartialBatch || i.BatchApplied is { Length: 2 }, NativeFailure.MissingInput);
        return i;
    }

    private static async ValueTask EnvironmentAsync(NativeEnvironment env, NativeCaseDefinition d,
        NativeCaseProbe p, CancellationToken token)
    {
        OrganizationInput i = Input(env, d, p);
        await using var f = new StaticOwnedFixture(env, i.Fixture, p, d.Key.Scope);
        await f.InitializeAsync(token);
        string slug = "sk-" + Guid.NewGuid().ToString("N");
        string renamed = "sk-" + Guid.NewGuid().ToString("N");
        string? id = null;
        bool create = d.Key.Operation.EndsWith(".CreateEnvironmentAsync", StringComparison.Ordinal);
        bool get = d.Key.Operation.EndsWith(".GetEnvironmentAsync", StringComparison.Ordinal);
        bool update = d.Key.Operation.EndsWith(".UpdateEnvironmentAsync", StringComparison.Ordinal);
        bool delete = d.Key.Operation.EndsWith(".DeleteEnvironmentAsync", StringComparison.Ordinal);
        SecretReference Target(InfisicalClient c, bool bySlug = false) => new(c.Authority,
            new InfisicalEnvironmentAddress(i.Fixture.ProjectId, bySlug || id is null ? slug : id,
                bySlug || id is null ? InfisicalOrganizationSelector.Slug : InfisicalOrganizationSelector.Id));
        InfisicalNativeAuthority Authority(InfisicalClient c, NativeIdentityRole role) =>
            new(c.Authority, env.Tokens(role), i.Fixture.ProjectId);
        try
        {
            if (!create)
            {
                SecretReference seed = Target(f.Setup);
                var receipt = new MutationReceipt(seed);
                SecretOutcome<InfisicalEnvironment> result = await f.Setup.CreateEnvironmentAsync(seed,
                    "seed", Authority(f.Setup, NativeIdentityRole.Setup), receipt, 1, token);
                p.Contract(result.IsSuccess && receipt.Evidence == DispatchEvidence.Applied, NativeFailure.MissingPrerequisite);
                id = result.Value.Id;
                SecretOutcome<InfisicalEnvironment> initial = await f.Observer.GetEnvironmentAsync(Target(f.Observer), token);
                p.Contract(initial.IsSuccess && initial.Value.Slug == slug && initial.Value.Name == "seed",
                    NativeFailure.ObserverUnavailable);
                if (!get && !update && !delete)
                {
                    SecretReference soft = Target(f.Setup);
                    var softReceipt = new MutationReceipt(soft);
                    var softResult = await f.Setup.DeleteEnvironmentAsync(soft,
                        Authority(f.Setup, NativeIdentityRole.Setup), softReceipt, cancellationToken: token);
                    p.Contract(softResult.IsSuccess && softReceipt.Evidence == DispatchEvidence.Applied,
                        NativeFailure.MissingPrerequisite);
                    var softObserved = await f.Observer.GetEnvironmentAsync(Target(f.Observer), token);
                    p.Contract(softObserved.IsSuccess && softObserved.Value.SoftDeletedAt is not null,
                        NativeFailure.ObserverUnavailable);
                }
            }
            bool denied = InfisicalImportPolicyFamilies.Denied(d);
            InfisicalClient c = denied ? f.Denied : f.Runtime;
            bool bySlug = get && d.Key.Variant == "selector.Slug";
            SecretReference target = Target(c, bySlug);
            var receiptMain = new MutationReceipt(target);
            string path = "/api/v1/projects/" + Uri.EscapeDataString(i.Fixture.ProjectId) + "/environments" +
                (create ? "" : bySlug ? "/slug/" + slug : "/" + id) +
                (!create && !get && !update && !delete ? "/restore" : "");
            StaticDispatch<InfisicalEnvironment> dispatch = await InfisicalImportPolicyFamilies.DispatchAsync(env,
                d, p, path, get ? "GET" : create || !update && !delete ? "POST" : update ? "PATCH" : "DELETE",
                ct => create ? c.CreateEnvironmentAsync(target, i.Name ?? "created",
                    Authority(c, denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime), receiptMain, i.Position, ct) :
                    get ? c.GetEnvironmentAsync(target, ct) :
                    update ? c.UpdateEnvironmentAsync(target, Authority(c, denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime),
                        receiptMain, i.Name, i.RenameSlug ? renamed : null, i.Position, ct) :
                    delete ? c.DeleteEnvironmentAsync(target, Authority(c, denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime),
                        receiptMain, i.HardDelete, ct) :
                    c.RestoreEnvironmentAsync(target, Authority(c, denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime),
                        receiptMain, ct), token);
            InfisicalImportPolicyFamilies.Result(dispatch, get ? null : receiptMain,
                denied ? SecretStatus.Denied : SecretStatus.Success,
                InfisicalImportPolicyFamilies.Interrupted(d) ? DispatchEvidence.PossiblyDispatched :
                    denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied, p);
            if (create && dispatch.Outcome is { IsSuccess: true } created) id = created.Value.Id;
            string expectedSlug = update && i.ExpectedApplied && i.RenameSlug ? renamed : slug;
            var observerTarget = new SecretReference(f.Observer.Authority, new InfisicalEnvironmentAddress(
                i.Fixture.ProjectId, id ?? expectedSlug, id is null ?
                    InfisicalOrganizationSelector.Slug : InfisicalOrganizationSelector.Id));
            var observed = await f.Observer.GetEnvironmentAsync(observerTarget, token);
            bool absent = create && !i.ExpectedApplied || delete && i.HardDelete && i.ExpectedApplied;
            bool softDeleted = delete && !i.HardDelete && i.ExpectedApplied ||
                !create && !get && !update && !delete && !i.ExpectedApplied;
            p.Effect(absent ? observed.Status == SecretStatus.Absent ? NativeObservation.Matched : NativeObservation.Mismatched :
                observed.IsSuccess && observed.Value.Slug == expectedSlug &&
                observed.Value.Name == (i.ExpectedApplied && (create || update) ? i.Name ?? (create ? "created" : "seed") : "seed") &&
                (create && i.ExpectedApplied ? i.Position is null || observed.Value.Position == i.Position :
                    observed.Value.Position == (i.ExpectedApplied && update ? i.Position ?? 1 : 1)) &&
                (observed.Value.SoftDeletedAt is not null) == softDeleted ? NativeObservation.Matched : NativeObservation.Mismatched);
            if (get && dispatch.Outcome is { IsSuccess: true } read)
                p.Contract(observed.IsSuccess && read.Value.Id == observed.Value.Id &&
                    read.Value.Slug == observed.Value.Slug && read.Value.Name == observed.Value.Name &&
                    read.Value.Position == observed.Value.Position, NativeFailure.ContractMismatch);
            if (create && dispatch.Outcome is { IsSuccess: true } createdResult)
                p.Contract(observed.IsSuccess && createdResult.Value.Position == observed.Value.Position,
                    NativeFailure.ContractMismatch);
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            try
            {
                // ID is retained on acknowledged updates. A lost create is located by its owned slug.
                var found = await f.Observer.GetEnvironmentAsync(Target(f.Observer), cleanup.Token);
                if (found.IsSuccess)
                {
                    id = found.Value.Id;
                    var owned = Target(f.Administrative);
                    var r = new MutationReceipt(owned);
                    var removed = await f.Administrative.DeleteEnvironmentAsync(owned,
                        Authority(f.Administrative, NativeIdentityRole.Administrative), r, true, cleanup.Token);
                    var gone = await f.Observer.GetEnvironmentAsync(Target(f.Observer), cleanup.Token);
                    p.Contract((removed.IsSuccess || removed.Status == SecretStatus.Absent) &&
                        gone.Status == SecretStatus.Absent, NativeFailure.CleanupIncomplete);
                }
                else p.Contract(found.Status == SecretStatus.Absent, NativeFailure.CleanupIncomplete);
            }
            catch (Exception)
            {
                env.ConfirmPrerequisite(d.Key.Scope, "approved-sandbox-cleanup", NativeObservation.Mismatched);
                p.Contract(false, NativeFailure.CleanupIncomplete);
            }
        }
    }

    private static async ValueTask TagAsync(NativeEnvironment env, NativeCaseDefinition d,
        NativeCaseProbe p, CancellationToken token)
    {
        OrganizationInput i = Input(env, d, p);
        await using var f = new StaticOwnedFixture(env, i.Fixture, p, d.Key.Scope);
        await f.InitializeAsync(token);
        string slug = "sk-" + Guid.NewGuid().ToString("N"), renamed = "sk-" + Guid.NewGuid().ToString("N");
        string? id = null;
        string color = "#123456";
        bool create = d.Key.Operation.EndsWith(".CreateTagAsync", StringComparison.Ordinal);
        bool update = d.Key.Operation.EndsWith(".UpdateTagAsync", StringComparison.Ordinal);
        bool delete = d.Key.Operation.EndsWith(".DeleteTagAsync", StringComparison.Ordinal);
        bool list = d.Key.Operation.EndsWith(".ListTagsAsync", StringComparison.Ordinal);
        SecretReference Target(InfisicalClient c, bool bySlug = false, bool collection = false) =>
            new(c.Authority, new InfisicalTagAddress(i.Fixture.ProjectId, collection ? null : bySlug || id is null ? slug : id,
                bySlug || id is null ? InfisicalOrganizationSelector.Slug : InfisicalOrganizationSelector.Id));
        InfisicalNativeAuthority Authority(InfisicalClient c, NativeIdentityRole role) =>
            new(c.Authority, env.Tokens(role), i.Fixture.ProjectId);
        try
        {
            if (!create)
            {
                var seed = Target(f.Setup);
                var r = new MutationReceipt(seed);
                var result = await f.Setup.CreateTagAsync(seed, color, Authority(f.Setup, NativeIdentityRole.Setup), r, token);
                p.Contract(result.IsSuccess && r.Evidence == DispatchEvidence.Applied, NativeFailure.MissingPrerequisite);
                id = result.Value.Id;
                var initial = await f.Observer.GetTagAsync(Target(f.Observer), token);
                p.Contract(initial.IsSuccess && initial.Value.Slug == slug && initial.Value.Color == color,
                    NativeFailure.ObserverUnavailable);
            }
            bool denied = InfisicalImportPolicyFamilies.Denied(d);
            InfisicalClient c = denied ? f.Denied : f.Runtime;
            bool bySlug = d.Key.Variant == "selector.Slug";
            var target = Target(c, bySlug, list);
            var receipt = new MutationReceipt(target);
            string path = "/api/v1/projects/" + Uri.EscapeDataString(i.Fixture.ProjectId) + "/tags" +
                (create || list ? "" : bySlug ? "/slug/" + slug : "/" + id);
            if (list)
            {
                var dispatch = await InfisicalImportPolicyFamilies.DispatchAsync(env, d, p, path, "GET",
                    ct => c.ListTagsAsync(target, i.MaximumItems, ct), token);
                InfisicalImportPolicyFamilies.Result(dispatch, null,
                    denied ? SecretStatus.Denied : SecretStatus.Success, default, p);
                if (dispatch.Outcome is { IsSuccess: true } result)
                    p.Contract(result.Value.IsComplete &&
                        result.Value.Items.Select(t => t.Id).Distinct().Count() == result.Value.Items.Count &&
                        result.Value.Items.Count(t => t.Id == id && t.Slug == slug && t.Color == color) == 1,
                        NativeFailure.ObserverUnavailable);
            }
            else
            {
                var dispatch = await InfisicalImportPolicyFamilies.DispatchAsync(env, d, p, path,
                    create ? "POST" : update ? "PATCH" : delete ? "DELETE" : "GET",
                    ct => create ? c.CreateTagAsync(target, color,
                        Authority(c, denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime), receipt, ct) :
                        update ? c.UpdateTagAsync(target, renamed, "#654321",
                            Authority(c, denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime), receipt, ct) :
                        delete ? c.DeleteTagAsync(target, Authority(c, denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime), receipt, ct) :
                        c.GetTagAsync(target, ct), token);
                InfisicalImportPolicyFamilies.Result(dispatch, create || update || delete ? receipt : null,
                    denied ? SecretStatus.Denied : SecretStatus.Success,
                    InfisicalImportPolicyFamilies.Interrupted(d) ? DispatchEvidence.PossiblyDispatched :
                        denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied, p);
                if (create && dispatch.Outcome is { IsSuccess: true } result) id = result.Value.Id;
                if (!create && !update && !delete && dispatch.Outcome is { IsSuccess: true } read)
                    p.Contract(read.Value.Id == id && read.Value.Slug == slug && read.Value.Color == color,
                        NativeFailure.ContractMismatch);
            }
            var observed = await f.Observer.GetTagAsync(Target(f.Observer), token);
            bool absent = create && !i.ExpectedApplied || delete && i.ExpectedApplied;
            p.Effect(absent ? observed.Status == SecretStatus.Absent ? NativeObservation.Matched : NativeObservation.Mismatched :
                observed.IsSuccess && observed.Value.Slug == (update && i.ExpectedApplied ? renamed : slug) &&
                observed.Value.Color == (update && i.ExpectedApplied ? "#654321" : color) ?
                    NativeObservation.Matched : NativeObservation.Mismatched);
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            try
            {
                var found = await f.Observer.GetTagAsync(Target(f.Observer), cleanup.Token);
                if (found.IsSuccess)
                {
                    id = found.Value.Id;
                    var owned = Target(f.Administrative);
                    var removed = await f.Administrative.DeleteTagAsync(owned,
                        Authority(f.Administrative, NativeIdentityRole.Administrative), new(owned), cleanup.Token);
                    var gone = await f.Observer.GetTagAsync(Target(f.Observer), cleanup.Token);
                    p.Contract((removed.IsSuccess || removed.Status == SecretStatus.Absent) &&
                        gone.Status == SecretStatus.Absent, NativeFailure.CleanupIncomplete);
                }
                else p.Contract(found.Status == SecretStatus.Absent, NativeFailure.CleanupIncomplete);
            }
            catch (Exception)
            {
                env.ConfirmPrerequisite(d.Key.Scope, "approved-sandbox-cleanup", NativeObservation.Mismatched);
                p.Contract(false, NativeFailure.CleanupIncomplete);
            }
        }
    }

    private static async ValueTask FolderAsync(NativeEnvironment env, NativeCaseDefinition d,
        NativeCaseProbe p, CancellationToken token)
    {
        OrganizationInput i = Input(env, d, p);
        await using var f = new StaticOwnedFixture(env, i.Fixture, p, d.Key.Scope);
        await f.InitializeAsync(token);
        bool create = d.Key.Operation.EndsWith(".CreateFolderAsync", StringComparison.Ordinal);
        bool get = d.Key.Operation.EndsWith(".GetFolderAsync", StringComparison.Ordinal);
        bool list = d.Key.Operation.EndsWith(".ListFoldersAsync", StringComparison.Ordinal);
        bool batch = d.Key.Operation.EndsWith(".UpdateFoldersAsync", StringComparison.Ordinal);
        bool move = d.Key.Operation.EndsWith(".MoveFolderAsync", StringComparison.Ordinal);
        bool delete = d.Key.Operation.EndsWith(".DeleteFolderAsync", StringComparison.Ordinal);
        string name = "sk-" + Guid.NewGuid().ToString("N"), renamed = "sk-" + Guid.NewGuid().ToString("N");
        string? id = null;
        string destination = f.Folder;
        SecretReference Target(InfisicalClient c, string? selectedId, string? selectedName, string? parent = null) =>
            new(c.Authority, new InfisicalFolderAddress(i.Fixture.ProjectId, i.Fixture.Environment,
                i.Fixture.EnvironmentId, parent ?? f.Folder, selectedId, selectedName));
        if (!create)
        {
            var seed = Target(f.Setup, null, name);
            var r = new MutationReceipt(seed);
            var result = await f.Setup.CreateFolderAsync(seed, f.Authority(f.Setup, NativeIdentityRole.Setup), r, "seed", token);
            p.Contract(result.IsSuccess && r.Evidence == DispatchEvidence.Applied, NativeFailure.MissingPrerequisite);
            id = result.Value.Id;
            var initial = await f.Observer.GetFolderAsync(Target(f.Observer, id, name), token);
            p.Contract(initial.IsSuccess && initial.Value.Description == "seed", NativeFailure.ObserverUnavailable);
            if (list && i.LastSecretModified is not null)
            {
                p.Contract(i.LastSecretModified < DateTimeOffset.UtcNow, NativeFailure.MissingInput);
                await f.SeedAsync("MODIFIED", Guid.NewGuid().ToString("N"), f.Folder + "/" + name, token);
            }
        }
        if (move) (destination, _) = await f.AddFolderAsync(token);
        bool denied = InfisicalImportPolicyFamilies.Denied(d);
        InfisicalClient c = denied ? f.Denied : f.Runtime;
        NativeIdentityRole role = denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime;
        var authority = move ? new InfisicalNativeAuthority(c.Authority, env.Tokens(role), i.Fixture.ProjectId) :
            f.Authority(c, role);
        var target = Target(c, list || batch || create || d.Key.Variant == "selector.name" ? null : id,
            list || batch ? null : create || delete ? name : get || move ? null : renamed);
        var receipt = new MutationReceipt(target);
        string path = "/api/v2/folders" + (list || create ? "" : batch ? "/batch" : move ? "/move" :
            "/" + (d.Key.Variant == "selector.name" ? name : id));
        if (batch)
        {
            // Two independently owned children make partial versus complete observable.
            string secondName = "sk-" + Guid.NewGuid().ToString("N");
            var secondTarget = Target(f.Setup, null, secondName);
            var second = await f.Setup.CreateFolderAsync(secondTarget,
                f.Authority(f.Setup, NativeIdentityRole.Setup), new(secondTarget), "seed", token);
            p.Contract(second.IsSuccess, NativeFailure.MissingPrerequisite);
            var dispatch = await InfisicalImportPolicyFamilies.DispatchAsync(env, d, p, path, "PATCH",
                ct => c.UpdateFoldersAsync(target,
                    [new(id!, renamed, i.Description, i.ClearDescription),
                        new(second.Value.Id, secondName + "-new", i.Description, i.ClearDescription)], authority, receipt, ct), token);
            InfisicalImportPolicyFamilies.Result(dispatch, receipt, denied ? SecretStatus.Denied : SecretStatus.Success,
                InfisicalImportPolicyFamilies.Interrupted(d) || i.PartialBatch && !denied ? DispatchEvidence.PossiblyDispatched :
                    denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied, p);
            if (dispatch.Outcome is { IsSuccess: true } result)
                p.Contract(result.Value.IsComplete == !i.PartialBatch, NativeFailure.ContractMismatch);
            // The response cannot decide unreturned effects. Independently read
            // every selected child against the selected, explicit expected state.
            var secondObserved = await f.Observer.GetFolderAsync(Target(f.Observer, second.Value.Id, null), token);
            p.Contract(secondObserved.IsSuccess, NativeFailure.ObserverUnavailable);
            bool secondApplied = i.PartialBatch ? i.BatchApplied![1] : i.ExpectedApplied;
            p.Effect(secondObserved.Value.Name == (secondApplied ? secondName + "-new" : secondName) &&
                secondObserved.Value.Description == (secondApplied ? i.ClearDescription ? null : i.Description ?? "seed" : "seed") ?
                    NativeObservation.Matched : NativeObservation.Mismatched);
        }
        else if (move)
        {
            var dispatch = await InfisicalImportPolicyFamilies.DispatchAsync(env, d, p, path, "POST",
                ct => c.MoveFolderAsync(target, new(i.Fixture.ProjectId, i.Fixture.Environment,
                    i.Fixture.EnvironmentId, destination), authority, receipt, ct), token);
            InfisicalImportPolicyFamilies.Result(dispatch, receipt, denied ? SecretStatus.Denied : SecretStatus.Success,
                InfisicalImportPolicyFamilies.Interrupted(d) ? DispatchEvidence.PossiblyDispatched :
                    denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied, p);
        }
        else if (list)
        {
            var dispatch = await InfisicalImportPolicyFamilies.DispatchAsync(env, d, p, path, "GET",
                ct => c.ListFoldersAsync(target, i.MaximumItems, i.Recursive, i.LastSecretModified, ct), token);
            InfisicalImportPolicyFamilies.Result(dispatch, null, denied ? SecretStatus.Denied : SecretStatus.Success, default, p);
            if (dispatch.Outcome is { IsSuccess: true } result)
                p.Contract(result.Value.IsComplete &&
                    result.Value.Items.Select(folder => folder.Id).Distinct().Count() == result.Value.Items.Count &&
                    result.Value.Items.Count(folder => folder.Id == id && folder.Name == name) == 1,
                    NativeFailure.ObserverUnavailable);
        }
        else
        {
            var dispatch = await InfisicalImportPolicyFamilies.DispatchAsync(env, d, p, path,
                create ? "POST" : get ? "GET" : delete ? "DELETE" : "PATCH",
                ct => create ? c.CreateFolderAsync(target, authority, receipt, i.Description, ct) :
                    get ? c.GetFolderAsync(target, ct) : delete ?
                    c.DeleteFolderAsync(target, authority, receipt, i.ForceDelete, ct) :
                    c.UpdateFolderAsync(target, authority, receipt, i.Description, i.ClearDescription, ct), token);
            InfisicalImportPolicyFamilies.Result(dispatch, get ? null : receipt, denied ? SecretStatus.Denied : SecretStatus.Success,
                InfisicalImportPolicyFamilies.Interrupted(d) ? DispatchEvidence.PossiblyDispatched :
                    denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied, p);
            if (create && dispatch.Outcome is { IsSuccess: true } result) id = result.Value.Id;
            if (get && dispatch.Outcome is { IsSuccess: true } read)
                p.Contract(read.Value.Id == id && read.Value.Name == name && read.Value.Description == "seed",
                    NativeFailure.ContractMismatch);
        }
        string parent = move && i.ExpectedApplied ? destination : f.Folder;
        var collection = await f.Observer.ListFoldersAsync(Target(f.Observer, null, null, parent), cancellationToken: token);
        p.Contract(collection.IsSuccess && collection.Value.IsComplete, NativeFailure.ObserverUnavailable);
        InfisicalFolder? observed = collection.Value.Items.SingleOrDefault(folder => id is null ? folder.Name == name : folder.Id == id);
        bool absent = create && !i.ExpectedApplied || delete && i.ExpectedApplied;
        bool firstApplied = batch && i.PartialBatch ? i.BatchApplied![0] : i.ExpectedApplied;
        string expectedName = !create && !get && !list && !delete && !move && firstApplied ? renamed : name;
        string? expectedDescription = create ? i.Description : !get && !list && !delete && !move && firstApplied ?
            i.ClearDescription ? null : i.Description ?? "seed" : "seed";
        p.Effect(absent ? observed is null ? NativeObservation.Matched : NativeObservation.Mismatched :
            observed is not null && observed.Name == expectedName && observed.Description == expectedDescription ?
                NativeObservation.Matched : NativeObservation.Mismatched);
        if (move && i.ExpectedApplied)
        {
            var old = await f.Observer.ListFoldersAsync(Target(f.Observer, null, null), cancellationToken: token);
            p.Effect(old.IsSuccess && old.Value.IsComplete && old.Value.Items.All(folder => folder.Id != id) ?
                NativeObservation.Matched : NativeObservation.Mismatched);
        }
    }
}
