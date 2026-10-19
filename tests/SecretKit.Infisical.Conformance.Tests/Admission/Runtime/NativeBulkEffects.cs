using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class NativeBulkEffects
{
    private const string Create = "i.runtime.InfisicalClient.CreateSecretsAsync";
    private const string Update = "i.runtime.InfisicalClient.UpdateSecretsAsync";
    private const string Delete = "i.runtime.InfisicalClient.DeleteSecretsAsync";
    private const string Parameters = "(SecretKit.Core.SecretReference,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.InfisicalBulkSecret>,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,";
    private const string CreateMember = "SecretKit.Infisical.InfisicalClient.CreateSecretsAsync" + Parameters + "System.Threading.CancellationToken)";
    private const string UpdateMember = "SecretKit.Infisical.InfisicalClient.UpdateSecretsAsync" + Parameters + "SecretKit.Infisical.InfisicalBulkUpdateMode,System.Threading.CancellationToken)";
    private const string DeleteMember = "SecretKit.Infisical.InfisicalClient.DeleteSecretsAsync" + Parameters + "System.Threading.CancellationToken)";

    internal static void Register(NativeCaseRegistry registry, NativeEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected, IBulkAuxiliarySource? bulkAuxiliary = null)
    {
        foreach (NativeCaseDefinition definition in expected.Where(d =>
            d.Key.Provider == "Infisical" && d.Key.Operation is Create or Update or Delete))
            registry.Add(new(definition, (probe, token) => InfisicalStaticFamilies.BoundedAsync(probe, token,
                bounded => ExecuteAsync(env, definition, probe, bounded, bulkAuxiliary))));
    }

    private static async ValueTask ExecuteAsync(NativeEnvironment env, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token, IBulkAuxiliarySource? bulkAuxiliary)
    {
        string member = definition.Key.Operation switch
        {
            Create => CreateMember,
            Update => UpdateMember,
            Delete => DeleteMember,
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        probe.Contract(definition.Member == member && InfisicalStaticFamilies.Case(definition.Key.Case, true),
            NativeFailure.ContractMismatch);
        if (await BulkAuxiliaryEffects.TryExecuteAsync(env, definition, probe, token, bulkAuxiliary)) return;
        BulkInput input = InfisicalStaticFamilies.Input<BulkInput>(env, "C08-IR-NativeBulk", definition);
        bool denied = definition.Key.Case == "denied-authority";
        bool interrupted = definition.Key.Case is "cancellation-boundary" or "lost-response-no-replay";
        bool rejectedPersonal = definition.Key.Operation == Create && definition.Key.Variant == "type.Personal";
        probe.Contract(input.Items is { Length: > 0 and <= 128 } && input.ExpectedState is { Length: > 0 } &&
            Enum.IsDefined(input.Mode) && Enum.IsDefined(input.ExpectedStatus) &&
            input.Items.Select(i => (i.NewName ?? i.Key, i.Type)).Distinct().Count() == input.Items.Length &&
            input.Items.All(i => input.ExpectedState.Any(s => s.Key == (i.NewName ?? i.Key))) &&
            input.Items.Where(i => i.NewName is not null).All(i =>
                input.ExpectedState.Any(s => s.Key == i.Key && s.Status == SecretStatus.Absent)) &&
            (!denied || input.ExpectedStatus == (rejectedPersonal ? SecretStatus.Invalid : SecretStatus.Denied)) &&
            input.ExpectedReceipt == (interrupted && !rejectedPersonal ? DispatchEvidence.PossiblyDispatched :
                rejectedPersonal ? DispatchEvidence.NotDispatched : denied ? DispatchEvidence.Rejected : input.ExpectedReceipt),
            NativeFailure.MissingInput);
        probe.Contract(VariantMatches(definition, input), NativeFailure.ContractMismatch);
        if (denied || rejectedPersonal)
            probe.Contract(InfisicalStaticFamilies.Unchanged(input.ExpectedState, input.Fixture.Seeds),
                NativeFailure.MissingInput);
        else if (!interrupted && !input.ExpectedApprovalPending)
            probe.Contract(StateMatchesIntent(definition.Key.Operation, input), NativeFailure.MissingInput);
        bool fields = NeedsFieldObserver(definition.Key.Variant, input.Items);
        probe.Contract(!fields || input.ExpectedDetails.Length == input.Items.Length &&
            input.Items.All(i => input.ExpectedDetails.Any(d => d.Key == (i.NewName ?? i.Key))),
            NativeFailure.MissingInput);
        await using var fixture = new StaticOwnedFixture(env, input.Fixture, probe, definition.Key.Scope);
        await fixture.InitializeAsync(token);
        InfisicalClient client = denied ? fixture.Denied : fixture.Runtime;
        NativeIdentityRole role = denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime;
        var target = new SecretReference(client.Authority, new InfisicalBulkAddress(input.Fixture.ProjectId,
            input.Fixture.Environment, fixture.Folder, fixture.FolderId));
        var receipt = new MutationReceipt(target);
        var materials = new List<SecretMaterial>();
        try
        {
            InfisicalBulkSecret[] items = input.Items.Select(i =>
            {
                SecretMaterial? material = i.Value is null ? null : SecretMaterial.FromText(i.Value);
                if (material is not null) materials.Add(material);
                return new InfisicalBulkSecret(i.Key, material, i.NewName, i.Comment,
                    i.Metadata?.Select(m => new InfisicalSecretMetadata(m.Key, m.Value, m.Encrypted)).ToArray(),
                    i.TagIds, i.SelectedFolder ? fixture.Folder : null, i.SkipMultilineEncoding,
                    i.ReminderNote, i.ReminderRepeatDays, i.ClearReminderNote, i.ClearReminderRepeatDays,
                    i.CreationMetadata, i.Type);
            }).ToArray();
            InfisicalNativeAuthority authority = fixture.Authority(client, role);
            StaticDispatch<InfisicalBulkObservation> dispatch = await InfisicalStaticFamilies.DispatchAsync(
                env, definition, probe, ct => definition.Key.Operation switch
                {
                    Create => client.CreateSecretsAsync(target, items, authority, receipt, ct),
                    Update => client.UpdateSecretsAsync(target, items, authority, receipt, input.Mode, ct),
                    Delete => client.DeleteSecretsAsync(target, items, authority, receipt, ct),
                    _ => throw new NativeCaseFailureException("contract-mismatch")
                }, token);
            probe.Contract(receipt.Evidence == input.ExpectedReceipt, NativeFailure.ContractMismatch);
            if (!dispatch.Cancelled)
            {
                SecretOutcome<InfisicalBulkObservation> result = dispatch.Outcome!;
                probe.Contract(result.Status == input.ExpectedStatus, NativeFailure.ContractMismatch);
                if (result.IsSuccess)
                {
                    probe.Contract(result.Value.AllApplied == input.ExpectedAllApplied &&
                        result.Value.ApprovalPending == input.ExpectedApprovalPending &&
                        result.Value.Items.Count == input.ExpectedItems.Length &&
                        result.Value.Items.Select(i => i.InputIndex).SequenceEqual(Enumerable.Range(0, input.Items.Length)) &&
                        result.Value.Items.Select(i => i.Evidence).SequenceEqual(input.ExpectedItems),
                        NativeFailure.ContractMismatch);
                }
            }
            await fixture.ObserveAsync(input.ExpectedState, token, denied: denied);
            // Read/Inspect expose material/version only. They cannot independently witness
            // personal rows, approval records, or persisted bulk auxiliary fields.
            // No guessed JSON projection or echoed request is admitted as that witness.
            if (!rejectedPersonal && (input.Items.Any(i => i.Type == InfisicalSecretType.Personal) ||
                input.ExpectedApprovalPending || fields))
                probe.Effect(NativeObservation.Unavailable);
        }
        finally
        {
            foreach (SecretMaterial material in materials) material.Dispose();
        }
    }

    private static bool StateMatchesIntent(string operation, BulkInput input)
    {
        if (input.ExpectedStatus != SecretStatus.Success)
            return InfisicalStaticFamilies.Unchanged(input.ExpectedState, input.Fixture.Seeds);
        return input.Items.All(item =>
        {
            StaticExpectedSecret state = input.ExpectedState.Single(s => s.Key == (item.NewName ?? item.Key));
            if (operation == Delete) return state.Status == SecretStatus.Absent && state.Value is null;
            StaticSeed? seed = input.Fixture.Seeds.SingleOrDefault(s => s.Key == item.Key);
            if (operation == Update && seed is null && input.Mode == InfisicalBulkUpdateMode.Ignore)
                return state.Status == SecretStatus.Absent && state.Value is null;
            string? intended = item.Value ?? seed?.Value;
            return intended is not null && state.Status == SecretStatus.Success && state.Value == intended;
        });
    }

    private static bool VariantMatches(NativeCaseDefinition definition, BulkInput input)
    {
        string variant = definition.Key.Variant;
        bool create = definition.Key.Operation == Create;
        bool update = definition.Key.Operation == Update;
        bool delete = definition.Key.Operation == Delete;
        BulkSecretInput[] items = input.Items;
        if (create && items.Any(i => i.Value is null || i.NewName is not null || i.SelectedFolder ||
            i.ReminderNote is not null || i.ReminderRepeatDays is not null || i.ClearReminderNote || i.ClearReminderRepeatDays))
            return false;
        if (update && items.Any(i => i.CreationMetadata is not null || i.Type != InfisicalSecretType.Shared))
            return false;
        if (delete && items.Any(i => i.Value is not null || i.NewName is not null || i.Comment is not null ||
            i.Metadata is not null || i.TagIds is not null || i.SelectedFolder || i.SkipMultilineEncoding is not null ||
            i.ReminderNote is not null || i.ReminderRepeatDays is not null || i.ClearReminderNote ||
            i.ClearReminderRepeatDays || i.CreationMetadata is not null))
            return false;
        bool result = variant switch
        {
            "type.Shared" => items.All(i => i.Type == InfisicalSecretType.Shared),
            "type.Personal" => !update && items.Any(i => i.Type == InfisicalSecretType.Personal),
            "result.applied-items" => input.ExpectedAllApplied && !input.ExpectedApprovalPending,
            "result.approval-pending" => !input.ExpectedAllApplied && input.ExpectedApprovalPending,
            "result.unobserved-items" => !input.ExpectedAllApplied && !input.ExpectedApprovalPending &&
                input.ExpectedItems.Contains(DispatchEvidence.PossiblyDispatched),
            "mode.Ignore" => update && input.Mode == InfisicalBulkUpdateMode.Ignore,
            "mode.Upsert" => update && input.Mode == InfisicalBulkUpdateMode.Upsert,
            "mode.FailOnNotFound" => update && input.Mode == InfisicalBulkUpdateMode.FailOnNotFound,
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
        // Modes need a missing row as well as an existing one; otherwise all modes are identical.
        if (variant.StartsWith("mode.", StringComparison.Ordinal))
            result &= items.Any(i => input.Fixture.Seeds.Any(s => s.Key == i.Key)) &&
                items.Any(i => !input.Fixture.Seeds.Any(s => s.Key == i.Key));
        if (create && variant == "type.Personal")
            result &= input.ExpectedStatus == SecretStatus.Invalid &&
                input.ExpectedReceipt == DispatchEvidence.NotDispatched;
        return result;
    }

    private static bool NeedsFieldObserver(string variant, BulkSecretInput[] inputs) =>
        variant.StartsWith("comment.", StringComparison.Ordinal) ||
        variant.StartsWith("metadata.", StringComparison.Ordinal) ||
        variant.StartsWith("tagIds.", StringComparison.Ordinal) ||
        variant.StartsWith("creationMetadata.", StringComparison.Ordinal) ||
        variant.StartsWith("reminder", StringComparison.Ordinal) ||
        variant.StartsWith("skipMultilineEncoding.", StringComparison.Ordinal) ||
        inputs.Any(i => i.Comment is not null || i.Metadata is not null || i.TagIds is not null ||
            i.CreationMetadata is not null || i.ReminderNote is not null || i.ReminderRepeatDays is not null ||
            i.ClearReminderNote || i.ClearReminderRepeatDays || i.SkipMultilineEncoding is not null);

    internal sealed record BulkInput(StaticFixtureInput Fixture, BulkSecretInput[] Items,
        InfisicalBulkUpdateMode Mode, SecretStatus ExpectedStatus, DispatchEvidence ExpectedReceipt,
        bool ExpectedAllApplied, bool ExpectedApprovalPending, DispatchEvidence[] ExpectedItems,
        StaticExpectedSecret[] ExpectedState, BulkExpectedDetail[] ExpectedDetails)
    {
        public override string ToString() => "[BulkInput]";
    }

    internal sealed record BulkSecretInput(string Key, string? Value, string? NewName, string? Comment,
        BulkMetadataInput[]? Metadata, string[]? TagIds, bool SelectedFolder, bool? SkipMultilineEncoding,
        string? ReminderNote, double? ReminderRepeatDays, bool ClearReminderNote, bool ClearReminderRepeatDays,
        Dictionary<string, string>? CreationMetadata, InfisicalSecretType Type)
    {
        public override string ToString() => "[BulkSecretInput]";
    }

    internal sealed record BulkMetadataInput(string Key, string? Value, bool Encrypted)
    {
        public override string ToString() => "[BulkMetadataInput]";
    }

    internal sealed record BulkExpectedDetail(string Key, string? Comment, BulkMetadataInput[] Metadata,
        string[] TagIds, Dictionary<string, string> CreationMetadata, bool? SkipMultilineEncoding,
        string? ReminderNote, double? ReminderRepeatDays)
    {
        public override string ToString() => "[BulkExpectedDetail]";
    }
}
