using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalBulkAuxiliaryCalibrationTests
{
    internal const string EnvironmentId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    internal static NativeCaseDefinition Definition(string method, string variant, string boundary) =>
        new(new("Infisical", BulkAuxiliaryContract.Prefix + method, variant, "local", boundary),
            BulkAuxiliaryContract.Member(method));
    internal static IEnumerable<(string Method, string Variant)> Variants()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        using var inventory = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(root, "docs/internal/releases/admission/infisical.json")));
        foreach (var operation in inventory.RootElement.GetProperty("operations").EnumerateArray())
        {
            string id = operation.GetProperty("id").GetString()!;
            if (!BulkAuxiliaryContract.Methods.Any(m => id == BulkAuxiliaryContract.Prefix + m)) continue;
            foreach (var variant in operation.GetProperty("variants").EnumerateArray())
                yield return (id[BulkAuxiliaryContract.Prefix.Length..], variant.GetString()!);
        }
    }
    public static IEnumerable<(string Method, string Variant, string Boundary)> Cases() =>
        Variants().SelectMany(v => BulkAuxiliaryContract.Cases.Select(b => (v.Method, v.Variant, b)));

    [Test]
    public async Task AllFiftyEightVariantsRemainAccountedWithoutNativeQualification()
    {
        var variants = Variants().ToArray();
        await Assert.That(variants.Length).IsEqualTo(58);
        await Assert.That(variants.Count(v => !BulkAuxiliaryContract.Gated(v.Variant))).IsEqualTo(50);
        await Assert.That(variants.Count(v => BulkAuxiliaryContract.Gated(v.Variant))).IsEqualTo(8);
        await Assert.That(Cases().Count()).IsEqualTo(290);
    }

    [Test]
    public async Task ClosedShapeBindsOmissionEmptyValueModeAndEncryption()
    {
        var input = Input("CreateSecretsAsync", "metadata.encrypted", "independent-effect");
        try
        {
            var first = input.Bulk.Items[0];
            string Shape(NativeBulkEffects.BulkSecretInput item, InfisicalBulkUpdateMode mode = InfisicalBulkUpdateMode.Ignore) =>
                BulkAuxiliaryContract.Shape([item], mode);
            string[] shapes = [Shape(first with { Comment = null }), Shape(first with { Comment = "" }),
                Shape(first with { Comment = "different" }), Shape(first, InfisicalBulkUpdateMode.Upsert),
                Shape(first with { Metadata = [new("confidential", "new-protected", false)] })];
            await Assert.That(shapes.Distinct().Count()).IsEqualTo(shapes.Length);
        }
        finally { Erase(input); }
    }

    [Test]
    public async Task PreCancelledOriginalLeavesFullAuxiliaryInventoryUnchanged()
    {
        await using var provider = new InfisicalBulkAuxiliaryFixture();
        using var env = provider.Environment(new { });
        var input = Input("CreateSecretsAsync", "metadata.encrypted", "independent-effect");
        var definition = Definition("CreateSecretsAsync", "metadata.encrypted", "independent-effect");
        var root = Root(env, definition, input, provider.Source.Kind);
        BulkAuxiliaryTrial? retained = null;
        try
        {
            var trial = await BulkAuxiliaryTrial.OpenAsync(provider.Source.CreateObserver(), root, input.Baseline,
                15, t => retained = t, CancellationToken.None);
            await using var client = env.CreateRuntimeClient();
            var target = new SecretReference(client.Authority,
                new InfisicalBulkAddress(root.ProjectId, root.Environment, root.Folder, root.FolderId));
            using var material = SecretMaterial.FromText("pre-cancelled-material");
            InfisicalBulkSecret[] items = [new("ALPHA", material)];
            var receipt = new InfisicalBulkReceipt(client, target, items, InfisicalBulkOperation.Create);
            using var cancel = new CancellationTokenSource();
            cancel.Cancel();
            bool cancelled = false;
            try
            {
                await client.CreateSecretsAsync(target, items,
                    new(client.Authority, env.Tokens(NativeIdentityRole.Runtime),
                        root.ProjectId, root.Environment, root.Folder), receipt, cancel.Token);
            }
            catch (OperationCanceledException) { cancelled = true; }
            await Assert.That(cancelled && receipt.Evidence == DispatchEvidence.NotDispatched).IsTrue();
            await trial.CompleteAsync(receipt.Evidence, CancellationToken.None);
            await trial.ObserveAsync(input.Baseline, CancellationToken.None);
            await Assert.That(provider.Requests.Count == 0 && provider.Commits.Count == 0).IsTrue();
        }
        finally
        {
            if (retained is not null) await retained.DisposeAsync();
            Erase(input);
        }
        await Assert.That(provider.ResidualCount).IsEqualTo(0);
    }

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task DirectPublicSdkCalibratesOriginalSourceBeforeEffectHandler(
        string method, string variant, string boundary)
    {
        await using var provider = new InfisicalBulkAuxiliaryFixture();
        var input = Input(method, variant, boundary);
        try
        {
            if (BulkAuxiliaryContract.Gated(variant))
            {
                // Accounted, explicitly unavailable. A controlled local provider
                // does not establish native personal/approval/result semantics.
                await Assert.That(provider.Source.Opens).IsEqualTo(0);
                return;
            }
            using var env = provider.Environment(new { });
            await DirectAsync(provider, env, Definition(method, variant, boundary), input);
            await Assert.That(provider.Source.Opens).IsEqualTo(1);
            await Assert.That(provider.Source.Observations).IsEqualTo(1);
            await Assert.That(provider.ResidualCount).IsEqualTo(0);
            await Assert.That(provider.Source.Registrations).IsEqualTo(0);
            await Assert.That(provider.BorrowedPreserved).IsTrue();
            await Assert.That(provider.Source.Fences.Single().OriginalRequests)
                .IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        }
        finally { Erase(input); }
    }

    // Deliberately calls the three original public SDK methods directly. No
    // effect handler, registration hook, SDK transport substitute or replay.
    internal static async Task DirectAsync(InfisicalBulkAuxiliaryFixture provider, NativeEnvironment env,
        NativeCaseDefinition definition, BulkAuxiliaryInput input)
    {
        var root = Root(env, definition, input, provider.Source.Kind);
        BulkAuxiliaryTrial? retained = null;
        var owned = new List<SecretMaterial>();
        try
        {
            var trial = await BulkAuxiliaryTrial.OpenAsync(provider.Source.CreateObserver(), root, input.Baseline,
                15, t => retained = t, CancellationToken.None);
            await using var client = env.CreateClient(root.Role);
            var target = new SecretReference(client.Authority, new InfisicalBulkAddress(root.ProjectId,
                root.Environment, root.Folder, root.FolderId));
            var authority = new InfisicalNativeAuthority(client.Authority, env.Tokens(root.Role),
                root.ProjectId, root.Environment, root.Folder);
            var items = input.Bulk.Items.Select(i =>
            {
                SecretMaterial? material = i.Value is null ? null : SecretMaterial.FromText(i.Value);
                if (material is not null) owned.Add(material);
                return new InfisicalBulkSecret(i.Key, material, i.NewName, i.Comment,
                    i.Metadata?.Select(m => new InfisicalSecretMetadata(m.Key, m.Value, m.Encrypted)).ToArray(),
                    i.TagIds, i.SelectedFolder ? root.Folder : null, i.SkipMultilineEncoding,
                    i.ReminderNote, i.ReminderRepeatDays, i.ClearReminderNote, i.ClearReminderRepeatDays,
                    i.CreationMetadata, i.Type);
            }).ToArray();
            var receipt = new InfisicalBulkReceipt(client, target, items, root.Method switch
            {
                "POST" => InfisicalBulkOperation.Create,
                "PATCH" => InfisicalBulkOperation.Update,
                _ => InfisicalBulkOperation.Delete
            }, root.Method == "PATCH" ? input.Bulk.Mode : InfisicalBulkUpdateMode.FailOnNotFound);
            using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            bool interrupted = definition.Key.Case is "cancellation-boundary" or "lost-response-no-replay";
            provider.Source.LoseResponse = definition.Key.Case == "lost-response-no-replay";
            using var boundary = interrupted ? new StaticSendBoundary(env.Origin, cancel,
                provider.Source.LoseResponse) : null;
            bool cancelled = false;
            try
            {
                SecretOutcome<InfisicalBulkObservation> result = root.Method switch
                {
                    "POST" => await client.CreateSecretsAsync(target, items, authority, receipt, cancel.Token),
                    "PATCH" => await client.UpdateSecretsAsync(target, items, authority, receipt, input.Bulk.Mode, cancel.Token),
                    _ => await client.DeleteSecretsAsync(target, items, authority, receipt, cancel.Token)
                };
                await Assert.That(result.Status == input.Bulk.ExpectedStatus).IsTrue();
                if (result.IsSuccess)
                    await Assert.That(result.Value.AllApplied == input.Bulk.ExpectedAllApplied &&
                        result.Value.Items.Select(i => i.Evidence).SequenceEqual(input.Bulk.ExpectedItems)).IsTrue();
            }
            catch (OperationCanceledException) when (interrupted && boundary!.Reached.Task.IsCompletedSuccessfully)
            { cancelled = true; }
            await Assert.That(cancelled == interrupted).IsTrue();
            await Assert.That(receipt.Evidence == input.Bulk.ExpectedReceipt).IsTrue();
            await trial.CompleteAsync(receipt.Evidence, CancellationToken.None);
            await trial.ObserveAsync(input.Expected, CancellationToken.None);
            await FreshConsumers(env, root, input);
        }
        finally
        {
            foreach (var material in owned) material.Dispose();
            if (retained is not null) await retained.DisposeAsync();
        }
    }

    private static async Task FreshConsumers(NativeEnvironment env, BulkAuxiliaryRoot root, BulkAuxiliaryInput input)
    {
        await using var runtime = env.CreateRuntimeClient();
        await using var denied = env.CreateDeniedClient();
        var inventory = await runtime.InspectAsync(new InfisicalInventoryScope(runtime.Authority,
            root.ProjectId, root.Environment, root.Folder));
        await Assert.That(inventory.IsSuccess && inventory.Value.IsComplete &&
            inventory.Value.Items.Select(r => ((InfisicalSecretAddress)r.Reference.Address).Key)
                .Order(StringComparer.Ordinal).SequenceEqual(input.Expected.Select(r => r.Key).Order(StringComparer.Ordinal))).IsTrue();
        foreach (string key in input.Baseline.Select(r => r.Key).Concat(input.Bulk.Items.Select(i => i.NewName ?? i.Key)).Distinct())
        {
            var expected = input.Expected.SingleOrDefault(r => r.Key == key);
            var read = await runtime.ReadAsync(new(runtime.Authority,
                new InfisicalSecretAddress(root.ProjectId, root.Environment, root.Folder, key)));
            if (read.IsSuccess)
            {
                using var material = read.Value;
                byte[] bytes = BulkAuxiliaryContract.Bytes(material.Material.Reveal());
                try { await Assert.That(expected is not null && bytes.AsSpan().SequenceEqual(expected.Material)).IsTrue(); }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
            }
            else await Assert.That(expected is null && read.Status == SecretStatus.Absent).IsTrue();
            var rejected = await denied.ReadAsync(new(denied.Authority,
                new InfisicalSecretAddress(root.ProjectId, root.Environment, root.Folder, key)));
            if (rejected.IsSuccess) rejected.Value.Dispose();
            await Assert.That(rejected.Status == SecretStatus.Denied).IsTrue();
        }
    }

    internal static BulkAuxiliaryRoot Root(NativeEnvironment env, NativeCaseDefinition definition,
        BulkAuxiliaryInput input, BulkAuxiliarySourceKind kind) => new(Guid.NewGuid().ToString("D"),
        string.Join("|", definition.Key.Provider, definition.Key.Operation, definition.Key.Variant,
            definition.Key.Scope, definition.Key.Case), env.Origin.AbsoluteUri,
        input.Bulk.Fixture.ProjectId, input.Bulk.Fixture.Environment, input.Bulk.Fixture.OwnedNamespace,
        input.Bulk.Fixture.OwnedNamespace + "/sk-" + Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("D"),
        BulkAuxiliaryContract.Method(definition), BulkAuxiliaryContract.Shape(input.Bulk.Items, input.Bulk.Mode),
        definition.Key.Case == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime,
        input.ProviderRevision, input.DeploymentId, input.SourceProfile, input.RootNonce, kind);

    internal static BulkAuxiliaryInput Input(string method, string variant, string boundary)
    {
        bool create = method == "CreateSecretsAsync", delete = method == "DeleteSecretsAsync";
        var baseline = new List<BulkAuxiliaryRow> { Seed("UNTOUCHED") };
        bool modeCase = variant.StartsWith("mode.", StringComparison.Ordinal);
        if (!create)
        {
            baseline.Add(Seed("ALPHA"));
            if (!modeCase) baseline.Add(Seed("BETA"));
        }
        var mode = variant switch
        {
            "mode.Ignore" => InfisicalBulkUpdateMode.Ignore,
            "mode.Upsert" => InfisicalBulkUpdateMode.Upsert,
            _ => InfisicalBulkUpdateMode.FailOnNotFound
        };
        var items = new[] { "ALPHA", "BETA" }.Select(key =>
        {
            var item = new NativeBulkEffects.BulkSecretInput(key,
                create || variant == "material.value" || variant == "mode.Upsert" && key == "BETA" ? "new\nsecond-line" : null,
                variant == "newName.value" ? key + "_RENAMED" : null,
                variant == "comment.omitted" ? null : variant == "comment.empty" ? "" : "new-comment",
                variant == "metadata.omitted" ? null : variant == "metadata.empty" ? [] :
                    [new("confidential", "new-protected", true), new("public", "new-unencrypted", false)],
                variant == "tagIds.omitted" ? null : variant == "tagIds.empty" ? [] : ["tag-new", "tag-second"],
                variant == "secretPath.selected-folder",
                variant == "skipMultilineEncoding.omitted" ? null : variant != "skipMultilineEncoding.false",
                create || variant is "reminderNote.omitted" or "reminderNote.null" ? null : "new-reminder",
                create || variant is "reminderRepeatDays.omitted" or "reminderRepeatDays.null" ? null : 7,
                variant == "reminderNote.null", variant == "reminderRepeatDays.null",
                create ? variant == "creationMetadata.omitted" ? null :
                    variant == "creationMetadata.empty" ? [] : new() { ["source"] = "interop", ["sourceId"] = "case" } : null,
                variant == "type.Personal" ? InfisicalSecretType.Personal : InfisicalSecretType.Shared);
            return delete ? new NativeBulkEffects.BulkSecretInput(key, null, null, null, null, null,
                false, null, null, null, false, false, null, item.Type) : item;
        }).ToArray();
        bool denied = boundary == "denied-authority";
        bool interrupted = boundary is "cancellation-boundary" or "lost-response-no-replay";
        bool missingFailure = variant == "mode.FailOnNotFound";
        var status = denied ? SecretStatus.Denied : missingFailure ? SecretStatus.Absent : SecretStatus.Success;
        var receipt = interrupted ? DispatchEvidence.PossiblyDispatched : denied || missingFailure ?
            DispatchEvidence.Rejected : variant == "mode.Ignore" ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied;
        var expectedItems = items.Select((_, n) => variant == "mode.Ignore" && n == 1 ?
            DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied).ToArray();
        var bulk = new NativeBulkEffects.BulkInput(new("project", "env", EnvironmentId, "/owned",
                baseline.Select(r => new StaticSeed(r.Key, System.Text.Encoding.UTF8.GetString(r.Material))).ToArray(),
                StaticApiRevision.SecretsV4FoldersV2), items, mode, status, receipt,
            variant != "mode.Ignore" && variant is not ("result.approval-pending" or "result.unobserved-items"),
            variant == "result.approval-pending", expectedItems, [], []);
        if (variant == "result.unobserved-items") bulk = bulk with { ExpectedItems = [DispatchEvidence.PossiblyDispatched, DispatchEvidence.PossiblyDispatched] };
        if (variant == "type.Personal" && create)
            bulk = bulk with { ExpectedStatus = SecretStatus.Invalid, ExpectedReceipt = DispatchEvidence.NotDispatched };
        var input = new BulkAuxiliaryInput(bulk, baseline.ToArray(), [], "controlled-v4",
            "controlled-deployment", "controlled-fixture", Guid.NewGuid().ToString("N"), 15);
        using var expected = new BulkAuxiliaryExpectedRows(input,
            create ? "POST" : delete ? "DELETE" : "PATCH", boundary);
        return input with
        {
            Expected = expected.Rows.Select(BulkAuxiliaryExpectedRows.Copy).ToArray(),
            Bulk = bulk with
            {
                ExpectedState = expected.Rows.Select(r => new StaticExpectedSecret(r.Key, SecretStatus.Success,
                    System.Text.Encoding.UTF8.GetString(r.Material), r.Version)).ToArray()
            }
        };
    }
    internal static BulkAuxiliaryRow Seed(string key) => new(key, "old\nmaterial"u8.ToArray(),
        "old-comment"u8.ToArray(),
        [new("confidential", "old-protected"u8.ToArray(), true, [], false),
            new("public", "old-unencrypted"u8.ToArray(), false, [], false)],
        ["tag-old", "tag-retained"], new() { ["source"] = "baseline", ["sourceId"] = "previous" },
        false, "old-reminder"u8.ToArray(), 30, 1);
    internal static object Family(NativeCaseDefinition definition, BulkAuxiliaryInput input) =>
        new Dictionary<string, object>
        {
            ["C08-IR-NativeBulk"] = new
            {
                scopes = new Dictionary<string, object>
                {
                    [definition.Key.Scope] = new Dictionary<string, object>
                    {
                        [definition.Key.Operation] = new Dictionary<string, object>
                        {
                            [definition.Key.Variant] = new Dictionary<string, object>
                            { [definition.Key.Case] = CaseInput(input) }
                        }
                    }
                }
            }
        };
    private static Dictionary<string, object> CaseInput(BulkAuxiliaryInput input)
    {
        var legacy = input.Bulk with
        {
            ExpectedDetails = input.Bulk.Items.Where(item =>
                input.Expected.Any(row => row.Key == (item.NewName ?? item.Key))).Select(item =>
            {
                var row = input.Expected.Single(r => r.Key == (item.NewName ?? item.Key));
                return new NativeBulkEffects.BulkExpectedDetail(row.Key,
                    System.Text.Encoding.UTF8.GetString(row.Comment),
                    row.Metadata.Select(m => new NativeBulkEffects.BulkMetadataInput(m.Key,
                        System.Text.Encoding.UTF8.GetString(m.Plaintext), m.Encrypted)).ToArray(),
                    row.TagIds, row.CreationMetadata, row.SkipMultilineEncoding,
                    row.ReminderNote is null ? null : System.Text.Encoding.UTF8.GetString(row.ReminderNote), row.ReminderRepeatDays);
            }).ToArray()
        };
        var fields = JsonSerializer.SerializeToElement(legacy, InfisicalStaticFamilies.Options)
            .EnumerateObject().ToDictionary(p => p.Name, p => (object)p.Value.Clone());
        fields.Add("auxiliaryWitness", input);
        return fields;
    }
    internal static void Erase(BulkAuxiliaryInput input)
    {
        foreach (var row in input.Baseline.Concat(input.Expected)) row.Erase();
    }
}
