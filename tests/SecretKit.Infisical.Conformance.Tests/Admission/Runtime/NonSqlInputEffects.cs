using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class NonSqlInputEffects
{
    internal static async ValueTask ExecuteAsync(NativeEnvironment env, NativeCaseDefinition row,
        NativeCaseProbe probe, InfisicalDynamicClientEffects.DynamicInput input,
        InfisicalDynamicProvider provider, InfisicalDynamicProfileInput? selected,
        InfisicalDynamicAlternativeProfileInput? alternative, string alternativeVariant,
        IInfisicalNonSqlInputObserver? source, CancellationToken token)
    {
        var settings = input.NonSqlInputWitness ?? throw new NativeCaseFailureException("missing-input");
        var metadata = input.Metadata ?? throw new NativeCaseFailureException("missing-input");
        string method = row.Key.Operation["i.runtime.InfisicalDynamicClient.".Length..];
        string variant = row.Key.Variant;
        probe.Contract(settings.CaseTimeoutSeconds is >= 1 and <= 900 &&
            input.DefaultSeconds > 0 && input.MaximumSeconds > input.DefaultSeconds &&
            input.Metadata is not null, NativeFailure.MissingInput);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(settings.CaseTimeoutSeconds));
        token = deadline.Token;
        var folder = new LifecycleOwnedFolder(env, input.Sandbox, probe, row.Key.Scope);
        NonSqlInputTrial opened;
        try
        {
            opened = await NonSqlInputTrial.OpenAsync(env, row, input, provider, selected,
                alternative, alternativeVariant, folder.Path, source, token);
        }
        catch { await folder.DisposeAsync(); throw; }
        // Close source last: all save-validation material/resources, including
        // noncommitted attempts, must settle after native definitions and folder.
        await using var trial = opened;
        await using var ownedFolder = folder;
        await folder.InitializeAsync(token);
        var scope = new InfisicalDynamicScope(input.Sandbox.ProjectSlug, input.Sandbox.Environment,
            folder.Path, folder.FolderId);
        using var transport = new LifecycleTransport(row.Key.Case);
        var identities = new LifecycleSelectedTokens(env, NativeIdentityRole.Setup);
        await using var client = new InfisicalDynamicClient(env.Origin, identities, scope,
            new() { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp }, transport: transport);
        await using var observer = new InfisicalDynamicClient(env.Origin, env.Tokens(NativeIdentityRole.Observer),
            scope, new() { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp });
        string name = "definition-" + Guid.NewGuid().ToString("N");
        string controlName = method == "CreateDefinitionAsync" ? "control-" + Guid.NewGuid().ToString("N") : name;
        string? renamed = method == "UpdateDefinitionAsync" && variant == "newName.value" ?
            "definition-" + Guid.NewGuid().ToString("N") : null;
        string[] ownedNames = renamed is null ? [controlName, name] : [controlName, name, renamed];
        bool cleanupComplete = true;
        try
        {
            await trial.ArmAsync(controlName, null, "CreateDefinitionAsync", "seed",
                "selected-contract", NonSqlInputConfiguration.Baseline, token);
            using var baseline = NonSqlInputPrivateProfiles.CreateBaseline(provider, settings);
            var controlTarget = client.Definition(controlName);
            var controlReceipt = new InfisicalDynamicMutationReceipt(controlTarget, InfisicalDynamicOperation.CreateDefinition);
            var created = await client.CreateDefinitionAsync(controlTarget, baseline,
                new(TimeSpan.FromSeconds(input.DefaultSeconds)), new(TimeSpan.FromSeconds(input.MaximumSeconds)),
                controlReceipt, token);
            probe.Contract(created.IsSuccess, NativeFailure.MissingPrerequisite);
            var control = created.Value;
            var baselineFence = await trial.CompleteAsync(controlReceipt.Evidence, token);
            probe.Contract(baselineFence.DefinitionId == control.Id, NativeFailure.EffectMismatch);
            await trial.ObserveAsync(control.Id, NonSqlInputConfiguration.Baseline, token);
            var target = method == "CreateDefinitionAsync" ? client.Definition(name) : control.Target;
            var configuration = method switch
            {
                "CreateDefinitionAsync" => NonSqlInputConfiguration.Selected,
                "UpdateDefinitionAsync" when variant != "inputs.omitted" => NonSqlInputConfiguration.Selected,
                "DeleteDefinitionAsync" => NonSqlInputConfiguration.Absent,
                _ => NonSqlInputConfiguration.Baseline
            };
            await trial.ArmAsync(name, method == "CreateDefinitionAsync" ? null : control.Id,
                method, variant, row.Key.Case, configuration, token);
            bool denied = row.Key.Case == "denied-authority";
            bool cancel = row.Key.Case == "cancellation-boundary";
            bool lost = row.Key.Case == "lost-response-no-replay";
            identities.Role = denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime;
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            Task boundary = transport.Reached.Task;
            Task? cancelling = cancel ? boundary.ContinueWith(_ => cancellation.Cancel(),
                CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default) : null;
            transport.Arm();
            using var changed = alternative is null ?
                InfisicalDynamicProfileInputs.Create(provider, selected ??
                    throw new NativeCaseFailureException("missing-input")) :
                InfisicalDynamicAlternativeProfileInputs.Create(alternativeVariant, alternative);
            var options = variant == "options.omitted" ? null : new NativeDynamicDefinitionOptions(
                variant == "usernameTemplate.value" ? input.UsernameTemplate : null,
                variant == "metadata.omitted" ? null : variant == "metadata.value" ?
                    metadata.Select(m => new NativeDynamicMetadata(m.Key, m.Value)).ToArray() : []);
            bool read = method is "InspectDefinitionAsync" or "ListDefinitionsAsync";
            InfisicalDynamicMutationReceipt? receipt = read ? null : new(target, method switch
            {
                "CreateDefinitionAsync" => InfisicalDynamicOperation.CreateDefinition,
                "DeleteDefinitionAsync" => InfisicalDynamicOperation.DeleteDefinition,
                _ => InfisicalDynamicOperation.UpdateDefinition
            });
            SecretStatus status = SecretStatus.Unknown;
            try
            {
                switch (method)
                {
                    case "CreateDefinitionAsync":
                        status = (await client.CreateDefinitionAsync(target, changed,
                            new(TimeSpan.FromSeconds(input.DefaultSeconds)),
                            variant == "maximumTtl.omitted" ? null : new(TimeSpan.FromSeconds(input.MaximumSeconds)),
                            receipt!, cancellation.Token, options)).Status;
                        break;
                    case "UpdateDefinitionAsync":
                        status = (await client.UpdateDefinitionAsync(control, new(
                            variant == "defaultTtl.omitted" ? null : new(TimeSpan.FromSeconds(input.DefaultSeconds + 1)),
                            variant is "maximumTtl.omitted" or "maximumTtl.null" ? null : new(TimeSpan.FromSeconds(input.MaximumSeconds)),
                            clearMaximumTtl: variant == "maximumTtl.null",
                            inputs: variant == "inputs.omitted" ? null : changed, newName: renamed,
                            options: options, clearUsernameTemplate: variant == "usernameTemplate.null"),
                            receipt!, cancellation.Token)).Status;
                        break;
                    case "UpdateDefinitionPolicyAsync":
                        status = (await client.UpdateDefinitionPolicyAsync(control,
                            new(TimeSpan.FromSeconds(input.DefaultSeconds + 1)),
                            variant == "maximumTtl.null" ? null : new(TimeSpan.FromSeconds(input.MaximumSeconds)),
                            receipt!, cancellation.Token)).Status;
                        break;
                    case "InspectDefinitionAsync":
                        var inspected = await client.InspectDefinitionAsync(target, cancellation.Token);
                        status = inspected.Status;
                        if (inspected.IsSuccess)
                            probe.Contract(inspected.Value.Id == control.Id, NativeFailure.ContractMismatch);
                        break;
                    case "ListDefinitionsAsync":
                        var list = await client.ListDefinitionsAsync(cancellation.Token);
                        status = list.Status;
                        if (list.IsSuccess)
                            probe.Contract(list.Value.IsComplete && list.Value.Items.Count == 1 &&
                                list.Value.Items[0].Id == control.Id, NativeFailure.ContractMismatch);
                        break;
                    case "DeleteDefinitionAsync":
                        var deleted = await client.DeleteDefinitionAsync(control, receipt!,
                            variant == "forceRecordRemoval.true", cancellation.Token);
                        status = deleted.Status;
                        if (deleted.IsSuccess)
                            probe.Contract(deleted.Value.ForcedRecordRemoval == (variant == "forceRecordRemoval.true") &&
                                !deleted.Value.ExternalRevocationVerified, NativeFailure.ContractMismatch);
                        break;
                    default:
                        probe.Contract(false, NativeFailure.ContractMismatch);
                        break;
                }
            }
            catch (OperationCanceledException) when (cancel && boundary.IsCompletedSuccessfully && !token.IsCancellationRequested)
            { status = SecretStatus.Unknown; }
            if (cancelling is not null) await cancelling.WaitAsync(token);
            probe.Contract(status == (cancel || lost ? SecretStatus.Unknown :
                denied ? SecretStatus.Denied : SecretStatus.Success), NativeFailure.ContractMismatch);
            if (cancel || lost) probe.Contract(boundary.IsCompletedSuccessfully, NativeFailure.ContractMismatch);
            var disposition = cancel || lost ? DispatchEvidence.PossiblyDispatched :
                denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied;
            if (receipt is not null)
                probe.Contract(receipt.Evidence == disposition, NativeFailure.ContractMismatch);
            // Reads have no mutation receipt; their observed dispatch result is
            // passed separately and cannot be interpreted as a mutation commit.
            var fence = await trial.CompleteAsync(receipt?.Evidence ?? disposition, token);
            transport.Disarm();
            identities.Role = NativeIdentityRole.Setup;
            string currentName = fence.Applied && renamed is not null ? renamed : name;
            var current = await observer.InspectDefinitionAsync(observer.Definition(currentName), token);
            probe.Contract(fence.DefinitionAbsent ? current.Status == SecretStatus.Absent :
                current.IsSuccess && current.Value.Id == fence.DefinitionId &&
                    current.Value.Provider == provider, NativeFailure.EffectMismatch);
            if (renamed is not null)
                probe.Contract((await observer.InspectDefinitionAsync(observer.Definition(
                    currentName == name ? renamed : name), token)).Status == SecretStatus.Absent,
                    NativeFailure.EffectMismatch);
            if (current.IsSuccess)
            {
                int expectedDefault = method is "UpdateDefinitionAsync" or "UpdateDefinitionPolicyAsync" &&
                    fence.Applied && variant != "defaultTtl.omitted" ? input.DefaultSeconds + 1 : input.DefaultSeconds;
                bool clearMaximum = fence.Applied && (method == "CreateDefinitionAsync" && variant == "maximumTtl.omitted" ||
                    method is "UpdateDefinitionAsync" or "UpdateDefinitionPolicyAsync" && variant == "maximumTtl.null");
                probe.Contract(current.Value.DefaultTtl.Duration == TimeSpan.FromSeconds(expectedDefault) &&
                    current.Value.MaximumTtl?.Duration == (clearMaximum ? null : TimeSpan.FromSeconds(input.MaximumSeconds)),
                    NativeFailure.EffectMismatch);
            }
            await trial.ObserveAsync(fence.DefinitionId, fence.DefinitionAbsent ?
                NonSqlInputConfiguration.Absent : fence.Applied ? configuration : NonSqlInputConfiguration.Baseline, token);
            probe.Effect(NativeObservation.Matched);
        }
        finally
        {
            identities.Role = NativeIdentityRole.Administrative;
            transport.Disarm();
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            try
            {
                foreach (string ownedName in ownedNames.Distinct(StringComparer.Ordinal))
                {
                    var current = await client.InspectDefinitionAsync(client.Definition(ownedName), cleanup.Token);
                    if (current.IsSuccess)
                    {
                        var independent = await observer.InspectDefinitionAsync(observer.Definition(ownedName), cleanup.Token);
                        cleanupComplete &= independent.IsSuccess && independent.Value.Id == current.Value.Id;
                        var inventory = await client.ListLeasesAsync(current.Value, cleanup.Token);
                        cleanupComplete &= inventory.IsSuccess && inventory.Value.IsComplete && inventory.Value.Items.Count == 0;
                        if (independent.IsSuccess)
                        {
                            var observed = await observer.ListLeasesAsync(independent.Value, cleanup.Token);
                            cleanupComplete &= observed.IsSuccess && observed.Value.IsComplete && observed.Value.Items.Count == 0;
                        }
                        cleanupComplete &= (await client.DeleteDefinitionAsync(current.Value,
                            new(current.Value.Target, InfisicalDynamicOperation.DeleteDefinition),
                            cancellationToken: cleanup.Token)).IsSuccess;
                    }
                    else cleanupComplete &= current.Status == SecretStatus.Absent;
                    cleanupComplete &= (await observer.InspectDefinitionAsync(observer.Definition(ownedName),
                        cleanup.Token)).Status == SecretStatus.Absent;
                }
                var remaining = await observer.ListDefinitionsAsync(cleanup.Token);
                cleanupComplete &= remaining.IsSuccess && remaining.Value.IsComplete && remaining.Value.Items.Count == 0;
            }
            catch (Exception) { cleanupComplete = false; }
            if (!cleanupComplete) probe.Contract(false, NativeFailure.CleanupIncomplete);
        }
    }
}
