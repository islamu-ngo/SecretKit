using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class SqlInputEffects
{
    internal static async ValueTask ExecuteAsync(NativeEnvironment env, NativeCaseDefinition row,
        NativeCaseProbe probe, InfisicalDynamicClientEffects.DynamicInput input,
        IInfisicalDynamicBackendObserver? backend, IInfisicalSqlInputObserver? source, CancellationToken token)
    {
        var settings = input.SqlInputWitness ?? throw new NativeCaseFailureException("missing-input");
        var selectedProfile = input.Profile ?? throw new NativeCaseFailureException("missing-input");
        var baseline = settings.Baseline ?? throw new NativeCaseFailureException("missing-input");
        string method = row.Key.Operation["i.runtime.InfisicalDynamicClient.".Length..];
        string variant = InfisicalDynamicClientEffects.NormalizeSqlVariant(row.Key.Variant);
        probe.Contract(InfisicalDynamicClientEffects.ExecutableVariant(row.Key.Variant) &&
            input.DefaultSeconds > 0 && input.MaximumSeconds > input.DefaultSeconds && input.TtlSeconds > 0 &&
            input.AllowedActions is { Length: > 0 } && input.DeniedActions is { Length: > 0 } &&
            Enum.IsDefined(selectedProfile.Engine) && selectedProfile.Engine == baseline.Engine &&
            (!variant.StartsWith("SqlDatabase.engine.", StringComparison.Ordinal) ||
                variant == "SqlDatabase.engine." + selectedProfile.Engine), NativeFailure.MissingInput);
        backend ??= InfisicalLifecycleObservers.FromInputs(env, InfisicalDynamicClientEffects.Family);
        if (backend is null) probe.Effect(NativeObservation.Unavailable);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        probe.Contract(settings.CaseTimeoutSeconds is >= 1 and <= 900, NativeFailure.MissingInput);
        deadline.CancelAfter(TimeSpan.FromSeconds(settings.CaseTimeoutSeconds));
        token = deadline.Token;
        var folder = new LifecycleOwnedFolder(env, input.Sandbox, probe, row.Key.Scope);
        SqlInputTrial opened;
        try { opened = await SqlInputTrial.OpenAsync(env, row, input, settings, folder.Path, source, token); }
        catch { await folder.DisposeAsync(); throw; }
        // Source closes last, after SDK leases, definitions and owned folder.
        await using var trial = opened;
        await using var ownedFolder = folder;
        await folder.InitializeAsync(token);
        var scope = new InfisicalDynamicScope(input.Sandbox.ProjectSlug, input.Sandbox.Environment,
            folder.Path, folder.FolderId);
        using var transport = new LifecycleTransport(row.Key.Case);
        var identities = new LifecycleSelectedTokens(env, NativeIdentityRole.Setup);
        await using var client = new InfisicalDynamicClient(env.Origin, identities, scope,
            new()
            {
                AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp,
                Transport = InfisicalTransportOptions.HostControlled(transport)
            });
        await using var observer = new InfisicalDynamicClient(env.Origin, env.Tokens(NativeIdentityRole.Observer),
            scope, new() { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp });
        string name = "definition-" + Guid.NewGuid().ToString("N");
        string controlName = method == "CreateDefinitionAsync" ? "control-" + Guid.NewGuid().ToString("N") : name;
        string? renamed = method == "UpdateDefinitionAsync" && variant == "newName.value" ?
            "definition-" + Guid.NewGuid().ToString("N") : null;
        string[] ownedNames = renamed is null ? [controlName, name] : [controlName, name, renamed];
        var retained = new List<(DynamicBackendCoordinate Coordinate, SecretMaterial User, SecretMaterial Password,
            DateTimeOffset ExpiresAt)>();
        bool cleanupComplete = true;
        try
        {
            // A positive baseline exists even when selected creation is rejected.
            await trial.ArmAsync(controlName, null, "CreateDefinitionAsync", "seed",
                "selected-contract", SqlInputConfiguration.Baseline, token);
            using var original = new NativeSqlDefinitionProfile(baseline.Engine, baseline.Host, baseline.Port,
                baseline.Username, baseline.Password, baseline.Database, baseline.CreationStatement,
                baseline.RevocationStatement, baseline.RenewalStatement, baseline.Ca, baseline.SslEnabled,
                baseline.GatewayId, baseline.GatewayPoolId);
            var controlTarget = client.Definition(controlName);
            var controlReceipt = new InfisicalDynamicMutationReceipt(controlTarget, InfisicalDynamicOperation.CreateDefinition);
            var created = await client.CreateDefinitionAsync(controlTarget, original,
                new(TimeSpan.FromSeconds(input.DefaultSeconds)), new(TimeSpan.FromSeconds(input.MaximumSeconds)),
                controlReceipt, token);
            probe.Contract(created.IsSuccess, NativeFailure.MissingPrerequisite);
            var control = created.Value;
            var baselineFence = await trial.CompleteAsync(controlReceipt.Evidence, token);
            probe.Contract(baselineFence.DefinitionId == control.Id, NativeFailure.EffectMismatch);
            await CaptureAsync(control, baseline, token);
            await trial.ObserveAsync(control.Id, SqlInputConfiguration.Baseline, token);
            var target = method == "CreateDefinitionAsync" ? client.Definition(name) : control.Target;
            var configuration = method == "UpdateDefinitionPolicyAsync" || variant == "inputs.omitted" ?
                SqlInputConfiguration.Baseline : SqlInputConfiguration.Selected;
            await trial.ArmAsync(name, method == "CreateDefinitionAsync" ? null : control.Id,
                method, row.Key.Variant, row.Key.Case, configuration, token);
            bool denied = row.Key.Case == "denied-authority";
            bool cancel = row.Key.Case == "cancellation-boundary";
            bool lost = row.Key.Case == "lost-response-no-replay";
            identities.Role = denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime;
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            Task boundary = transport.Reached.Task;
            Task? cancelling = cancel ? boundary.ContinueWith(_ => cancellation.Cancel(),
                CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default) : null;
            transport.Arm();
            using var changed = InfisicalDynamicClientEffects.Profile(selectedProfile, variant);
            var options = variant == "options.omitted" ? null : new NativeDynamicDefinitionOptions(
                variant == "usernameTemplate.value" ? input.UsernameTemplate : null,
                variant == "metadata.omitted" ? null : variant == "metadata.value" ?
                    input.Metadata.Select(m => new NativeDynamicMetadata(m.Key, m.Value)).ToArray() : []);
            var receipt = new InfisicalDynamicMutationReceipt(target, method == "CreateDefinitionAsync" ?
                InfisicalDynamicOperation.CreateDefinition : InfisicalDynamicOperation.UpdateDefinition);
            SecretStatus status;
            try
            {
                if (method == "CreateDefinitionAsync")
                    status = (await client.CreateDefinitionAsync(target, changed,
                        new(TimeSpan.FromSeconds(input.DefaultSeconds)),
                        variant == "maximumTtl.omitted" ? null : new(TimeSpan.FromSeconds(input.MaximumSeconds)),
                        receipt, cancellation.Token, options)).Status;
                else if (method == "UpdateDefinitionPolicyAsync")
                    status = (await client.UpdateDefinitionPolicyAsync(control,
                        new(TimeSpan.FromSeconds(input.DefaultSeconds + 1)),
                        variant == "maximumTtl.null" ? null : new(TimeSpan.FromSeconds(input.MaximumSeconds)),
                        receipt, cancellation.Token)).Status;
                else
                    status = (await client.UpdateDefinitionAsync(control, new(
                        variant == "defaultTtl.omitted" ? null : new(TimeSpan.FromSeconds(input.DefaultSeconds + 1)),
                        variant is "maximumTtl.omitted" or "maximumTtl.null" ? null : new(TimeSpan.FromSeconds(input.MaximumSeconds)),
                        clearMaximumTtl: variant == "maximumTtl.null",
                        inputs: variant == "inputs.omitted" ? null : changed, newName: renamed,
                        options: options, clearUsernameTemplate: variant == "usernameTemplate.null"),
                        receipt, cancellation.Token)).Status;
            }
            catch (OperationCanceledException) when (cancel && boundary.IsCompletedSuccessfully && !token.IsCancellationRequested)
            { status = SecretStatus.Unknown; }
            if (cancelling is not null) await cancelling.WaitAsync(token);
            probe.Contract(status == (cancel || lost ? SecretStatus.Unknown :
                denied ? SecretStatus.Denied : SecretStatus.Success), NativeFailure.ContractMismatch);
            probe.Contract(receipt.Evidence == (cancel || lost ? DispatchEvidence.PossiblyDispatched :
                denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied), NativeFailure.ContractMismatch);
            if (cancel || lost) probe.Contract(boundary.IsCompletedSuccessfully, NativeFailure.ContractMismatch);
            var fence = await trial.CompleteAsync(receipt.Evidence, token);
            transport.Disarm();
            identities.Role = NativeIdentityRole.Setup;
            string currentName = fence.Applied && renamed is not null ? renamed : name;
            var current = await observer.InspectDefinitionAsync(observer.Definition(currentName), token);
            if (method == "CreateDefinitionAsync" && !fence.Applied)
            {
                probe.Contract(fence.DefinitionAbsent && current.Status == SecretStatus.Absent, NativeFailure.EffectMismatch);
                // Retained baseline credentials still authenticate after nonapplication.
                await AuthenticateAsync(retained[0], token);
                probe.Effect(NativeObservation.Matched);
                return;
            }
            probe.Contract(current.IsSuccess && !fence.DefinitionAbsent &&
                current.Value.Id == fence.DefinitionId, NativeFailure.EffectMismatch);
            int expectedDefault = method != "CreateDefinitionAsync" && fence.Applied &&
                variant != "defaultTtl.omitted" ? input.DefaultSeconds + 1 : input.DefaultSeconds;
            bool clearMaximum = fence.Applied && (method == "CreateDefinitionAsync" && variant == "maximumTtl.omitted" ||
                method != "CreateDefinitionAsync" && variant == "maximumTtl.null");
            probe.Contract(current.Value.DefaultTtl.Duration == TimeSpan.FromSeconds(expectedDefault) &&
                current.Value.MaximumTtl?.Duration == (clearMaximum ? null : TimeSpan.FromSeconds(input.MaximumSeconds)),
                NativeFailure.EffectMismatch);
            var effective = fence.Applied && configuration == SqlInputConfiguration.Selected ? selectedProfile : baseline;
            await CaptureAsync(current.Value, effective, token);
            if (fence.Applied && variant == "passwordRequirements.value")
            {
                var policy = selectedProfile.PasswordRequirements ??
                    throw new NativeCaseFailureException("missing-input");
                char[] issued = retained[^1].Password.ExportCharacters();
                try
                {
                    int lower = 0, upper = 0, digits = 0, symbols = 0;
                    bool alphabet = true;
                    foreach (char character in issued)
                    {
                        if (character is >= 'a' and <= 'z') lower++;
                        else if (character is >= 'A' and <= 'Z') upper++;
                        else if (character is >= '0' and <= '9') digits++;
                        else
                        {
                            symbols++;
                            alphabet &= policy.AllowedSymbols?.Contains(character) != false;
                        }
                    }
                    probe.Contract(issued.Length == policy.Length && lower >= policy.Lowercase &&
                        upper >= policy.Uppercase && digits >= policy.Digits && symbols >= policy.Symbols &&
                        alphabet, NativeFailure.EffectMismatch);
                }
                finally { Array.Clear(issued); }
            }
            await trial.ObserveAsync(current.Value.Id,
                fence.Applied ? configuration : SqlInputConfiguration.Baseline, token);
            await AuthenticateAsync(retained[0], token);
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
                        var observed = await observer.InspectDefinitionAsync(observer.Definition(ownedName), cleanup.Token);
                        cleanupComplete &= observed.IsSuccess && observed.Value.Id == current.Value.Id;
                        var inventory = await client.ListLeasesAsync(current.Value, cleanup.Token);
                        var independent = observed.IsSuccess ?
                            await observer.ListLeasesAsync(observed.Value, cleanup.Token) :
                            SecretOutcome<InfisicalNativeList<InfisicalLeaseObservation>>.Failure(SecretStatus.Invalid);
                        cleanupComplete &= inventory.IsSuccess && inventory.Value.IsComplete &&
                            independent.IsSuccess && independent.Value.IsComplete &&
                            inventory.Value.Items.Select(l => l.Reference.Id).Order()
                                .SequenceEqual(independent.Value.Items.Select(l => l.Reference.Id).Order());
                        if (inventory.IsSuccess)
                            foreach (var lease in inventory.Value.Items)
                                cleanupComplete &= (await client.RevokeLeaseAsync(lease.Reference,
                                    new(lease.Reference, InfisicalDynamicOperation.Revoke),
                                    cancellationToken: cleanup.Token)).IsSuccess;
                        cleanupComplete &= (await client.DeleteDefinitionAsync(current.Value,
                            new(current.Value.Target, InfisicalDynamicOperation.DeleteDefinition),
                            cancellationToken: cleanup.Token)).IsSuccess;
                    }
                    else cleanupComplete &= current.Status == SecretStatus.Absent;
                    cleanupComplete &= (await observer.InspectDefinitionAsync(observer.Definition(ownedName),
                        cleanup.Token)).Status == SecretStatus.Absent;
                }
            }
            catch (Exception) { cleanupComplete = false; }
            foreach (var captured in retained)
            {
                try
                {
                    var facts = await backend!.MeasureAsync(captured.Coordinate, captured.User, captured.Password, cleanup.Token);
                    cleanupComplete &= facts.Coordinate == captured.Coordinate &&
                        facts.Authentication == BackendAuthentication.Rejected;
                }
                catch (Exception) { cleanupComplete = false; }
                finally { captured.User.Dispose(); captured.Password.Dispose(); }
            }
            if (!cleanupComplete) probe.Contract(false, NativeFailure.CleanupIncomplete);
        }

        async ValueTask CaptureAsync(InfisicalDynamicDefinition definition, DynamicSqlInput profile, CancellationToken ct)
        {
            var owned = await client.InspectDefinitionAsync(client.Definition(definition.Target.Name), ct);
            probe.Contract(owned.IsSuccess && owned.Value.Id == definition.Id, NativeFailure.ObserverUnavailable);
            var acquired = await client.AcquireDatabaseAsync(owned.Value,
                new(owned.Value.Target, InfisicalDynamicOperation.Acquire), cancellationToken: ct);
            probe.Contract(acquired.IsSuccess, NativeFailure.EffectMismatch);
            using var lease = acquired.Value;
            using var credentials = lease.CopyCredentials().Value;
            var user = SecretMaterial.FromText(credentials.RevealUsername());
            SecretMaterial password;
            try { password = SecretMaterial.FromText(credentials.RevealPassword()); }
            catch { user.Dispose(); throw; }
            var capture = (Coordinate: new DynamicBackendCoordinate(profile.Engine, profile.Host, profile.Port,
                profile.Database, definition.Id, lease.Reference.Id), User: user, Password: password,
                ExpiresAt: lease.Observation.ExpiresAt);
            retained.Add(capture);
            var observed = await observer.InspectDefinitionAsync(observer.Definition(definition.Target.Name), ct);
            probe.Contract(observed.IsSuccess && observed.Value.Id == definition.Id, NativeFailure.ObserverUnavailable);
            var inventory = await observer.ListLeasesAsync(observed.Value, ct);
            probe.Contract(inventory.IsSuccess && inventory.Value.IsComplete &&
                inventory.Value.Items.Any(l => l.Reference.Id == lease.Reference.Id &&
                    l.ExpiresAt == lease.Observation.ExpiresAt), NativeFailure.ObserverUnavailable);
            await AuthenticateAsync(capture, ct);
            using var wrong = SecretMaterial.FromText(Guid.NewGuid().ToString("N"));
            var rejected = await backend!.MeasureAsync(capture.Coordinate, capture.User, wrong, ct);
            probe.Contract(rejected.Coordinate == capture.Coordinate &&
                rejected.Authentication == BackendAuthentication.Rejected, NativeFailure.EffectMismatch);
            await AuthenticateAsync(capture, ct);
        }

        async ValueTask AuthenticateAsync((DynamicBackendCoordinate Coordinate, SecretMaterial User, SecretMaterial Password,
            DateTimeOffset ExpiresAt) capture,
            CancellationToken ct)
        {
            var facts = await backend!.MeasureAsync(capture.Coordinate, capture.User, capture.Password, ct);
            if (facts.Authentication == BackendAuthentication.Unavailable) probe.Effect(NativeObservation.Unavailable);
            probe.Contract(facts.Coordinate == capture.Coordinate && facts.Authentication == BackendAuthentication.Accepted &&
                facts.AllowedActions.SequenceEqual(input.AllowedActions) &&
                facts.DeniedActions.SequenceEqual(input.DeniedActions) &&
                facts.ExpiresAt == capture.ExpiresAt, NativeFailure.EffectMismatch);
        }
    }
}
