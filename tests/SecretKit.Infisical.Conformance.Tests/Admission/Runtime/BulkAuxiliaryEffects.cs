using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class BulkAuxiliaryEffects
{
    // Parent hook: before NativeBulkEffects constructs StaticOwnedFixture, call
    // this method and return when true. Absence preserves the original handler.
    // Keep its optional source argument trailing in the parent registration API.
    internal static async ValueTask<bool> TryExecuteAsync(NativeEnvironment env,
        NativeCaseDefinition definition, NativeCaseProbe probe, CancellationToken token,
        IBulkAuxiliarySource? source = null)
    {
        JsonElement scope;
        try
        {
            scope = env.RequireFamilyInput("C08-IR-NativeBulk").GetProperty("scopes")
                .GetProperty(definition.Key.Scope).GetProperty(definition.Key.Operation)
                .GetProperty(definition.Key.Variant).GetProperty(definition.Key.Case);
        }
        catch (KeyNotFoundException) { return false; }
        if (!scope.TryGetProperty("auxiliaryWitness", out var selected)) return false;
        BulkAuxiliaryInput input;
        try
        {
            input = selected.Deserialize<BulkAuxiliaryInput>(InfisicalStaticFamilies.Options)
                ?? throw new NativeCaseFailureException("missing-input");
        }
        catch (JsonException) { throw new NativeCaseFailureException("missing-input"); }
        try
        {
            source ??= InfisicalBulkAuxiliarySource.FromInputs(env);
            if (source is null) { probe.Effect(NativeObservation.Unavailable); return true; }
            await ExecuteAsync(env, definition, probe, input, source, token);
            return true;
        }
        finally
        {
            foreach (var row in input.Baseline.Concat(input.Expected)) row.Erase();
        }
    }

    internal static async ValueTask ExecuteAsync(NativeEnvironment env, NativeCaseDefinition definition,
        NativeCaseProbe probe, BulkAuxiliaryInput input, IBulkAuxiliarySource source, CancellationToken token)
    {
        Validate(definition, input);
        if (BulkAuxiliaryContract.Gated(definition.Key.Variant))
        {
            // A local fixture must not promote native personal/approval/partial
            // result interpretation into an established persistence contract.
            probe.Effect(NativeObservation.Unavailable);
            return;
        }
        bool denied = definition.Key.Case == "denied-authority";
        var role = denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime;
        string folder = input.Bulk.Fixture.OwnedNamespace.TrimEnd('/') + "/sk-" + Guid.NewGuid().ToString("N");
        var root = new BulkAuxiliaryRoot(Guid.NewGuid().ToString("D"),
            string.Join("|", definition.Key.Provider, definition.Key.Operation, definition.Key.Variant,
                definition.Key.Scope, definition.Key.Case), env.Origin.AbsoluteUri,
            input.Bulk.Fixture.ProjectId, input.Bulk.Fixture.Environment,
            input.Bulk.Fixture.OwnedNamespace, folder, Guid.NewGuid().ToString("D"),
            BulkAuxiliaryContract.Method(definition),
            BulkAuxiliaryContract.Shape(input.Bulk.Items, input.Bulk.Mode), role,
            input.ProviderRevision, input.DeploymentId, input.SourceProfile, input.RootNonce, source.Kind);
        BulkAuxiliaryTrial? retained = null;
        var materials = new List<SecretMaterial>();
        try
        {
            var trial = await BulkAuxiliaryTrial.OpenAsync(source, root, input.Baseline, input.TimeoutSeconds,
                value => retained = value, token);
            await using var client = env.CreateClient(role);
            var target = new SecretReference(client.Authority,
                new InfisicalBulkAddress(root.ProjectId, root.Environment, root.Folder, root.FolderId));
            var receipt = new MutationReceipt(target);
            InfisicalBulkSecret[] items = CreateItems(input.Bulk.Items, root.Folder, materials);
            var authority = new InfisicalNativeAuthority(client.Authority, env.Tokens(role),
                root.ProjectId, root.Environment, root.Folder);
            var dispatch = await InfisicalStaticFamilies.DispatchAsync(env, definition, probe,
                ct => CallAsync(client, target, items, authority, receipt, root.Method, input.Bulk.Mode, ct), token);
            probe.Contract(receipt.Evidence == input.Bulk.ExpectedReceipt, NativeFailure.ContractMismatch);
            if (!dispatch.Cancelled)
            {
                var outcome = dispatch.Outcome!;
                probe.Contract(outcome.Status == input.Bulk.ExpectedStatus, NativeFailure.ContractMismatch);
                if (outcome.IsSuccess)
                    probe.Contract(outcome.Value.AllApplied == input.Bulk.ExpectedAllApplied &&
                        outcome.Value.ApprovalPending == input.Bulk.ExpectedApprovalPending &&
                        outcome.Value.Items.Select(i => i.InputIndex).SequenceEqual(Enumerable.Range(0, items.Length)) &&
                        outcome.Value.Items.Select(i => i.Evidence).SequenceEqual(input.Bulk.ExpectedItems),
                        NativeFailure.ContractMismatch);
            }
            // The separate source fences only the prearmed original attempt.
            // It must settle unknown/cancelled work before storage or cleanup.
            await trial.CompleteAsync(receipt.Evidence, token);
            await trial.ObserveAsync(input.Expected, token);
            await ConsumeAsync(env, root, input.Expected, probe, token);
            probe.Effect(NativeObservation.Matched);
        }
        catch (NativeCaseFailureException error)
        {
            // The legacy static bounded helper has no effect-mismatch mapping.
            // Record this unit's measured failure on the probe before it unwinds.
            probe.Contract(false, error.Message switch
            {
                "effect-mismatch" => NativeFailure.EffectMismatch,
                "observer-unavailable" => NativeFailure.ObserverUnavailable,
                "missing-input" => NativeFailure.MissingInput,
                "contract-mismatch" => NativeFailure.ContractMismatch,
                "cleanup-incomplete" => NativeFailure.CleanupIncomplete,
                _ => NativeFailure.UnexpectedFailure
            });
        }
        finally
        {
            foreach (var material in materials) material.Dispose();
            if (retained is not null) await retained.DisposeAsync();
        }
    }

    internal static InfisicalBulkSecret[] CreateItems(NativeBulkEffects.BulkSecretInput[] items,
        string folder, List<SecretMaterial> owned) => items.Select(i =>
    {
        SecretMaterial? material = i.Value is null ? null : SecretMaterial.FromText(i.Value);
        if (material is not null) owned.Add(material);
        return new InfisicalBulkSecret(i.Key, material, i.NewName, i.Comment,
            i.Metadata?.Select(m => new InfisicalSecretMetadata(m.Key, m.Value, m.Encrypted)).ToArray(),
            i.TagIds, i.SelectedFolder ? folder : null, i.SkipMultilineEncoding,
            i.ReminderNote, i.ReminderRepeatDays, i.ClearReminderNote, i.ClearReminderRepeatDays,
            i.CreationMetadata, i.Type);
    }).ToArray();

    internal static ValueTask<SecretOutcome<InfisicalBulkObservation>> CallAsync(InfisicalClient client,
        SecretReference target, InfisicalBulkSecret[] items, InfisicalNativeAuthority authority,
        MutationReceipt receipt, string method, InfisicalBulkUpdateMode mode, CancellationToken token) =>
        method switch
        {
            "POST" => client.CreateSecretsAsync(target, items, authority, receipt, token),
            "PATCH" => client.UpdateSecretsAsync(target, items, authority, receipt, mode, token),
            "DELETE" => client.DeleteSecretsAsync(target, items, authority, receipt, token),
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };

    internal static async ValueTask ConsumeAsync(NativeEnvironment env, BulkAuxiliaryRoot root,
        BulkAuxiliaryRow[] expected, NativeCaseProbe probe, CancellationToken token)
    {
        // Fresh actual SDK instances select runtime and denied credentials. Source
        // storage metadata is not a substitute for either material delivery proof.
        await using var consumer = env.CreateRuntimeClient();
        await using var denied = env.CreateDeniedClient();
        var scope = new InfisicalInventoryScope(consumer.Authority,
            root.ProjectId, root.Environment, root.Folder);
        var inventory = await consumer.InspectAsync(scope, token);
        probe.Contract(inventory.IsSuccess && inventory.Value.IsComplete &&
            inventory.Value.Items.Count == expected.Length &&
            inventory.Value.Items.All(i => i.Reference.Address is InfisicalSecretAddress a &&
                a.ProjectId == root.ProjectId && a.Environment == root.Environment && a.Folder == root.Folder) &&
            inventory.Value.Items.Select(i => ((InfisicalSecretAddress)i.Reference.Address).Key)
                .Order(StringComparer.Ordinal).SequenceEqual(expected.Select(r => r.Key).Order(StringComparer.Ordinal)),
            NativeFailure.ContractMismatch);
        foreach (var row in expected)
        {
            var reference = new SecretReference(consumer.Authority,
                new InfisicalSecretAddress(root.ProjectId, root.Environment, root.Folder, row.Key));
            var delivered = await consumer.ReadAsync(reference, token);
            if (!delivered.IsSuccess) probe.Contract(false, NativeFailure.ContractMismatch);
            using (var read = delivered.Value)
            {
                byte[] bytes = BulkAuxiliaryContract.Bytes(read.Material.Reveal());
                try
                {
                    probe.Contract(bytes.AsSpan().SequenceEqual(row.Material) &&
                        read.Observation.Version == row.Version.ToString(System.Globalization.CultureInfo.InvariantCulture),
                        NativeFailure.ContractMismatch);
                }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
            }
            var rejected = await denied.ReadAsync(new(denied.Authority,
                new InfisicalSecretAddress(root.ProjectId, root.Environment, root.Folder, row.Key)), token);
            if (rejected.IsSuccess) rejected.Value.Dispose();
            probe.Contract(rejected.Status == SecretStatus.Denied, NativeFailure.ContractMismatch);
        }
    }

    private static void Validate(NativeCaseDefinition definition, BulkAuxiliaryInput input)
    {
        string method = BulkAuxiliaryContract.Method(definition);
        string name = definition.Key.Operation[BulkAuxiliaryContract.Prefix.Length..];
        var bulk = input.Bulk;
        BulkAuxiliaryContract.Require(definition.Member == BulkAuxiliaryContract.Member(name) &&
            definition.Key.Provider == "Infisical" && BulkAuxiliaryContract.Cases.Contains(definition.Key.Case),
            "contract-mismatch");
        BulkAuxiliaryContract.Require(input.TimeoutSeconds is >= 1 and <= 300 &&
            !string.IsNullOrWhiteSpace(input.ProviderRevision) && !string.IsNullOrWhiteSpace(input.DeploymentId) &&
            !string.IsNullOrWhiteSpace(input.SourceProfile) && !string.IsNullOrWhiteSpace(input.RootNonce) &&
            bulk.Fixture.ApiRevision == StaticApiRevision.SecretsV4FoldersV2 &&
            bulk.Fixture.OwnedNamespace.StartsWith('/') && bulk.Fixture.OwnedNamespace != "/" &&
            !bulk.Fixture.OwnedNamespace.Split('/').Any(p => p is "." or "..") &&
            bulk.Items.Length is >= 1 and <= 128 && input.Baseline.Length <= 128 &&
            input.Expected.Length <= 128 && Enum.IsDefined(bulk.Mode) &&
            bulk.Items.Select(i => (i.NewName ?? i.Key, i.Type)).Distinct().Count() == bulk.Items.Length &&
            input.Baseline.Select(r => r.Key).Distinct().Count() == input.Baseline.Length &&
            input.Expected.Select(r => r.Key).Distinct().Count() == input.Expected.Length &&
            bulk.Fixture.Seeds.Length == input.Baseline.Length &&
            input.Baseline.All(r => bulk.Fixture.Seeds.Any(s => s.Key == r.Key &&
                s.Value == System.Text.Encoding.UTF8.GetString(r.Material))) &&
            input.Baseline.Concat(input.Expected).All(r => r.Version > 0 &&
                r.CreationMetadata.Keys.All(k => k is "source" or "sourceId")) &&
            bulk.Items.All(i => i.CreationMetadata is null ||
                i.CreationMetadata.Keys.All(k => k is "source" or "sourceId")), "missing-input");
        BulkAuxiliaryContract.Require(Variant(definition.Key.Variant, method, bulk), "contract-mismatch");
        using var derived = new BulkAuxiliaryExpectedRows(input, method, definition.Key.Case);
        BulkAuxiliaryContract.Require(BulkAuxiliaryContract.Equal(input.Expected, derived.Rows, false), "missing-input");
        if (definition.Key.Case == "denied-authority" ||
            bulk.ExpectedStatus is not SecretStatus.Success)
            BulkAuxiliaryContract.Require(BulkAuxiliaryContract.Equal(input.Expected, input.Baseline, false), "missing-input");
    }

    private static bool Variant(string variant, string method, NativeBulkEffects.BulkInput b)
    {
        var items = b.Items;
        bool create = method == "POST", update = method == "PATCH", delete = method == "DELETE";
        if (create && items.Any(i => i.Value is null || i.NewName is not null || i.SelectedFolder ||
            i.ReminderNote is not null || i.ReminderRepeatDays is not null || i.ClearReminderNote || i.ClearReminderRepeatDays))
            return false;
        if (update && items.Any(i => i.CreationMetadata is not null || i.Type != InfisicalSecretType.Shared)) return false;
        if (delete && items.Any(i => i.Value is not null || i.NewName is not null || i.Comment is not null ||
            i.Metadata is not null || i.TagIds is not null || i.SelectedFolder || i.SkipMultilineEncoding is not null ||
            i.ReminderNote is not null || i.ReminderRepeatDays is not null || i.ClearReminderNote ||
            i.ClearReminderRepeatDays || i.CreationMetadata is not null)) return false;
        return variant switch
        {
            "type.Shared" => items.All(i => i.Type == InfisicalSecretType.Shared),
            "type.Personal" => !update && items.Any(i => i.Type == InfisicalSecretType.Personal),
            "result.applied-items" => b.ExpectedAllApplied && !b.ExpectedApprovalPending,
            "result.approval-pending" => !b.ExpectedAllApplied && b.ExpectedApprovalPending,
            "result.unobserved-items" => !b.ExpectedAllApplied && !b.ExpectedApprovalPending &&
                b.ExpectedItems.Contains(DispatchEvidence.PossiblyDispatched),
            "mode.Ignore" or "mode.Upsert" or "mode.FailOnNotFound" => update &&
                variant == "mode." + b.Mode && items.Any(i => b.Fixture.Seeds.Any(s => s.Key == i.Key)) &&
                items.Any(i => !b.Fixture.Seeds.Any(s => s.Key == i.Key)),
            "material.omitted" => update && items.All(i => i.Value is null),
            "material.value" => update && items.Any(i => i.Value is not null),
            "newName.omitted" => update && items.All(i => i.NewName is null),
            "newName.value" => update && items.Any(i => !string.IsNullOrWhiteSpace(i.NewName)),
            "comment.omitted" => !delete && items.All(i => i.Comment is null),
            "comment.empty" => !delete && items.Any(i => i.Comment == ""),
            "comment.value" => !delete && items.Any(i => i.Comment is { Length: > 0 }),
            "metadata.omitted" => !delete && items.All(i => i.Metadata is null),
            "metadata.empty" => !delete && items.Any(i => i.Metadata is { Length: 0 }),
            "metadata.value" => !delete && items.Any(i => i.Metadata is { Length: > 0 }),
            "metadata.encrypted" => create && items.Any(i => i.Metadata?.Any(m => m.Encrypted) == true),
            "metadata.unencrypted" => create && items.Any(i => i.Metadata?.Any(m => !m.Encrypted) == true),
            "tagIds.omitted" => !delete && items.All(i => i.TagIds is null),
            "tagIds.empty" => !delete && items.Any(i => i.TagIds is { Length: 0 }),
            "tagIds.value" => !delete && items.Any(i => i.TagIds is { Length: > 0 }),
            "creationMetadata.omitted" => create && items.All(i => i.CreationMetadata is null),
            "creationMetadata.empty" => create && items.Any(i => i.CreationMetadata is { Count: 0 }),
            "creationMetadata.value" => create && items.Any(i => i.CreationMetadata is { Count: > 0 }),
            "secretPath.omitted" => update && items.All(i => !i.SelectedFolder),
            "secretPath.selected-folder" => update && items.Any(i => i.SelectedFolder),
            "skipMultilineEncoding.omitted" => !delete && items.All(i => i.SkipMultilineEncoding is null),
            "skipMultilineEncoding.false" => !delete && items.Any(i => i.SkipMultilineEncoding == false),
            "skipMultilineEncoding.true" => !delete && items.Any(i => i.SkipMultilineEncoding == true),
            "reminderNote.omitted" => update && items.All(i => i.ReminderNote is null && !i.ClearReminderNote),
            "reminderNote.null" => update && items.Any(i => i.ClearReminderNote && i.ReminderNote is null),
            "reminderNote.value" => update && items.Any(i => i.ReminderNote is not null && !i.ClearReminderNote),
            "reminderRepeatDays.omitted" => update && items.All(i => i.ReminderRepeatDays is null && !i.ClearReminderRepeatDays),
            "reminderRepeatDays.null" => update && items.Any(i => i.ClearReminderRepeatDays && i.ReminderRepeatDays is null),
            "reminderRepeatDays.value" => update && items.Any(i => i.ReminderRepeatDays is not null && !i.ClearReminderRepeatDays),
            _ => false
        };
    }
}
