using System.Text.Json;
using Azure;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Secrets;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

internal static class AzureNativeLifecycleEffects
{
    public static void Register(NativeCaseRegistry registry, OwnedAzureEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected)
    {
        foreach (NativeCaseDefinition definition in expected.Where(d => d.Key.Provider == "AzureKeyVault" &&
            d.Key.Operation is "a.runtime.AzureKeyVaultClient.GetSecretVersionAsync" or
                "a.runtime.AzureKeyVaultClient.GetSecretVersionsAsync" or
                "a.runtime.AzureKeyVaultClient.GetDeletedSecretAsync" or
                "a.runtime.AzureKeyVaultClient.GetDeletedSecretsAsync" or
                "a.runtime.AzureKeyVaultClient.StartDeleteSecretAsync" or
                "a.runtime.AzureKeyVaultClient.StartRecoverDeletedSecretAsync" or
                "a.runtime.AzureKeyVaultClient.PurgeDeletedSecretAsync" or
                "a.runtime.AzureKeyVaultClient.BackupSecretAsync" or
                "a.runtime.AzureKeyVaultClient.RestoreSecretBackupAsync" or
                "a.runtime.AzureKeyVaultClient.CheckLifecycleStatusAsync" or
                "a.runtime.AzureKeyVaultClient.UpdatePropertiesAsync"))
            registry.Add(new(definition, (probe, token) =>
                definition.Key.Operation == "a.runtime.AzureKeyVaultClient.UpdatePropertiesAsync"
                    ? UpdateProperties(environment, definition, probe, token)
                    : definition.Key.Operation is "a.runtime.AzureKeyVaultClient.GetDeletedSecretAsync" or
                        "a.runtime.AzureKeyVaultClient.GetDeletedSecretsAsync"
                        ? Deleted(environment, definition, probe, token)
                        : definition.Key.Operation is "a.runtime.AzureKeyVaultClient.StartDeleteSecretAsync" or
                            "a.runtime.AzureKeyVaultClient.StartRecoverDeletedSecretAsync" or
                            "a.runtime.AzureKeyVaultClient.PurgeDeletedSecretAsync"
                            ? LifecycleMutation(environment, definition, probe, token)
                            : definition.Key.Operation is "a.runtime.AzureKeyVaultClient.BackupSecretAsync" or
                                "a.runtime.AzureKeyVaultClient.RestoreSecretBackupAsync"
                                ? BackupRestore(environment, definition, probe, token)
                                : definition.Key.Operation == "a.runtime.AzureKeyVaultClient.CheckLifecycleStatusAsync"
                                    ? LifecycleStatus(environment, definition, probe, token)
                                    : Versions(environment, definition, probe, token)));
    }

    private static async ValueTask LifecycleStatus(OwnedAzureEnvironment environment, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token)
    {
        probe.Contract(definition.Member ==
            "SecretKit.AzureKeyVault.AzureKeyVaultClient.CheckLifecycleStatusAsync(SecretKit.AzureKeyVault.AzureLifecycleOperation,System.Threading.CancellationToken)" &&
            definition.Key.Variant is "kind.Delete.Pending" or "kind.Delete.Applied" or
                "kind.Recover.Pending" or "kind.Recover.Applied" &&
            definition.Key.Case is "selected-contract" or "denied-authority" or
                "independent-effect" or "cancellation-boundary", NativeFailure.ContractMismatch);
        JsonElement input = environment.RequireFamilyInput("C08-AR-AzureNativeLifecycle");
        // Status denial needs a principal allowed to start but denied to inspect.
        // A separate prefix lets the host select that policy without weakening mutation denial fixtures.
        string sandbox = input.GetProperty("statusNamespace").GetString()!;
        probe.Contract(sandbox.Length is >= 3 and <= 40 && sandbox.All(c =>
            char.IsAsciiLetterOrDigit(c) || c == '-'), NativeFailure.MissingInput);
        bool delete = definition.Key.Variant.StartsWith("kind.Delete.", StringComparison.Ordinal);
        bool pending = definition.Key.Variant.EndsWith(".Pending", StringComparison.Ordinal);
        string name = sandbox + "-" + Guid.NewGuid().ToString("N");
        string material = Guid.NewGuid().ToString("N");
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var wire = new HttpClientTransport(http);
        var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01) { Transport = wire };
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        var setup = new SecretClient(environment.VaultUri, environment.Credential(NativeIdentityRole.Setup), options);
        var observer = new SecretClient(environment.VaultUri, environment.Credential(NativeIdentityRole.Observer), options);
        try
        {
            string first = (await setup.SetSecretAsync(name, material, token)).Value.Properties.Version;
            string latest = (await setup.SetSecretAsync(name, material, token)).Value.Properties.Version;
            if (!delete)
            {
                await setup.StartDeleteSecretAsync(name, token);
                try { _ = await observer.GetDeletedSecretAsync(name, token); }
                catch (RequestFailedException error) when (error.Status == 404)
                { throw new NativeCaseFailureException("observer-unavailable"); }
            }
            var boundary = new AzureKeyVaultClientEffects.ResponseBoundary(wire, name,
                delete ? "/deletedsecrets/" + name : "/secrets/" + name);
            bool denied = definition.Key.Case == "denied-authority";
            AzureKeyVaultClient client = environment.CreateClient(denied ?
                NativeIdentityRole.Denied : NativeIdentityRole.Runtime, boundary);
            var target = new SecretReference(client.Authority, new AzureSecretAddress(name));
            var receipt = new MutationReceipt(target);
            SecretOutcome<AzureLifecycleResult> started = delete ?
                await client.StartDeleteSecretAsync(target, receipt, token) :
                await client.StartRecoverDeletedSecretAsync(target, receipt, token);
            probe.Contract(started.IsSuccess && receipt.Evidence == DispatchEvidence.Pending, NativeFailure.MissingPrerequisite);
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            boundary.Hold = definition.Key.Case == "cancellation-boundary";
            Task<SecretOutcome<AzureLifecycleResult>> operation =
                client.CheckLifecycleStatusAsync(started.Value.Operation, cancellation.Token).AsTask();
            if (boundary.Hold)
            {
                Task winner = await Task.WhenAny(operation, boundary.Observed.Task).WaitAsync(token);
                if (winner == boundary.Observed.Task)
                {
                    cancellation.Cancel();
                    boundary.Release.TrySetResult();
                }
            }
            try
            {
                SecretOutcome<AzureLifecycleResult> result = await operation;
                probe.Contract(!boundary.Hold && (denied ? result.Status == SecretStatus.Denied &&
                    boundary.LastAuthorizedStatus == 403 : result.IsSuccess &&
                    result.Value.State == (pending ? AzureLifecycleState.Pending : AzureLifecycleState.Applied)),
                    NativeFailure.ContractMismatch);
            }
            catch (OperationCanceledException) when (boundary.Hold && cancellation.IsCancellationRequested &&
                !token.IsCancellationRequested)
            { probe.Contract(boundary.Observed.Task.IsCompletedSuccessfully, NativeFailure.ContractMismatch); }
            probe.Contract(receipt.Evidence == DispatchEvidence.Pending, NativeFailure.ContractMismatch);
            bool independentlyPending;
            if (delete)
            {
                try
                {
                    DeletedSecret measured = (await observer.GetDeletedSecretAsync(name, token)).Value;
                    probe.Contract(measured.Name == name && measured.DeletedOn is not null, NativeFailure.EffectMismatch);
                    independentlyPending = false;
                }
                catch (RequestFailedException error) when (error.Status == 404) { independentlyPending = true; }
            }
            else
            {
                try
                {
                    foreach (string version in new[] { first, latest })
                    {
                        KeyVaultSecret measured = (await observer.GetSecretAsync(name, version, token)).Value;
                        probe.Contract(measured.Value == material, NativeFailure.EffectMismatch);
                    }
                    independentlyPending = false;
                }
                catch (RequestFailedException error) when (error.Status == 404) { independentlyPending = true; }
            }
            // Propagation fixtures must actually expose their declared native state.
            // No delay, replay or substituted response can manufacture a Pending row.
            probe.Contract(independentlyPending == pending, NativeFailure.MissingPrerequisite);
            probe.Effect(NativeObservation.Matched);
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            bool clean = true;
            try
            {
                try { await setup.StartDeleteSecretAsync(name, cleanup.Token); }
                catch (RequestFailedException error) when (error.Status is 404 or 409) { }
                try { await observer.GetSecretAsync(name, cancellationToken: cleanup.Token); clean = false; }
                catch (RequestFailedException error) when (error.Status == 404) { }
            }
            catch (Exception) { clean = false; }
            probe.Contract(clean, NativeFailure.CleanupIncomplete);
        }
    }

    private static async ValueTask BackupRestore(OwnedAzureEnvironment environment, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token)
    {
        bool restore = definition.Key.Operation == "a.runtime.AzureKeyVaultClient.RestoreSecretBackupAsync";
        probe.Contract(definition.Member == (restore ?
            "SecretKit.AzureKeyVault.AzureKeyVaultClient.RestoreSecretBackupAsync(SecretKit.AzureKeyVault.AzureRestoreSecretRequest,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)" :
            "SecretKit.AzureKeyVault.AzureKeyVaultClient.BackupSecretAsync(SecretKit.Core.SecretReference,System.Threading.CancellationToken)") &&
            (restore ? definition.Key.Variant is "precondition.None" or "precondition.CreateOnly.rejected" or
                "precondition.MatchVersion.rejected" : definition.Key.Variant == "selector.exact"),
            NativeFailure.ContractMismatch);
        probe.Contract(definition.Key.Case is "selected-contract" or "denied-authority" or
            "independent-effect" or "cancellation-boundary" ||
            restore && definition.Key.Case == "lost-response-no-replay", NativeFailure.ContractMismatch);
        JsonElement input = environment.RequireFamilyInput("C08-AR-AzureNativeLifecycle");
        string sandbox = input.GetProperty("namespace").GetString()!;
        probe.Contract(sandbox.Length is >= 3 and <= 40 && sandbox.All(c =>
            char.IsAsciiLetterOrDigit(c) || c == '-'), NativeFailure.MissingInput);
        using OwnedAzureEnvironment destination = OwnedAzureEnvironment.Create(input.GetProperty("backupDestination"));
        probe.Contract(destination.VaultUri != environment.VaultUri, NativeFailure.MissingInput);
        string name = sandbox + "-" + Guid.NewGuid().ToString("N");
        string[] material = [Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N")];
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var wire = new HttpClientTransport(http);
        var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01) { Transport = wire };
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        var sourceSetup = new SecretClient(environment.VaultUri, environment.Credential(NativeIdentityRole.Setup), options);
        var sourceObserver = new SecretClient(environment.VaultUri, environment.Credential(NativeIdentityRole.Observer), options);
        var destinationSetup = new SecretClient(destination.VaultUri, destination.Credential(NativeIdentityRole.Setup), options);
        var destinationObserver = new SecretClient(destination.VaultUri, destination.Credential(NativeIdentityRole.Observer), options);
        bool destinationOwned = false;
        try
        {
            var seeded = new List<SecretProperties>();
            for (int index = 0; index < material.Length; index++)
            {
                var secret = new KeyVaultSecret(name, material[index]);
                secret.Properties.Enabled = true;
                secret.Properties.ContentType = "backup-" + index;
                secret.Properties.Tags.Add("version", index.ToString(System.Globalization.CultureInfo.InvariantCulture));
                seeded.Add((await sourceSetup.SetSecretAsync(secret, token)).Value.Properties);
            }
            // Neither an active nor retained deleted destination may be overwritten.
            try { await destinationObserver.GetSecretAsync(name, cancellationToken: token); probe.Contract(false, NativeFailure.MissingPrerequisite); }
            catch (RequestFailedException error) when (error.Status == 404) { }
            try { await destinationObserver.GetDeletedSecretAsync(name, token); probe.Contract(false, NativeFailure.MissingPrerequisite); }
            catch (RequestFailedException error) when (error.Status == 404) { }
            destinationOwned = true;
            bool denied = definition.Key.Case == "denied-authority";
            bool rejected = restore && definition.Key.Variant != "precondition.None";
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            var boundary = new AzureKeyVaultClientEffects.ResponseBoundary(wire, name,
                restore ? "/secrets/restore" : "/secrets/" + name + "/backup")
            {
                Hold = definition.Key.Case == "cancellation-boundary",
                Lose = definition.Key.Case == "lost-response-no-replay"
            };
            AzureKeyVaultClient client = (restore ? destination : environment).CreateClient(denied ?
                NativeIdentityRole.Denied : NativeIdentityRole.Runtime, boundary);
            var target = new SecretReference(client.Authority, new AzureSecretAddress(name));
            var receipt = new MutationReceipt(target);
            AzureSecretBackup? setupBackup = null;
            if (restore)
            {
                byte[] bytes = (await sourceSetup.BackupSecretAsync(name, token)).Value;
                try { setupBackup = AzureSecretBackup.FromBytes(bytes); }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
            }
            using AzureSecretBackup? ownedSetupBackup = setupBackup;
            AzureSecretBackup? acquired = null;
            try
            {
                Task operation = Invoke();
                if (boundary.Hold && !rejected)
                {
                    Task winner = await Task.WhenAny(operation, boundary.Observed.Task).WaitAsync(token);
                    if (winner == boundary.Observed.Task)
                    {
                        cancellation.Cancel();
                        boundary.Release.TrySetResult();
                    }
                }
                bool interrupted = false;
                try { await operation; probe.Contract(!boundary.Hold || rejected, NativeFailure.ContractMismatch); }
                catch (OperationCanceledException) when (boundary.Hold && cancellation.IsCancellationRequested &&
                    !token.IsCancellationRequested)
                {
                    interrupted = true;
                    probe.Contract(boundary.Observed.Task.IsCompletedSuccessfully &&
                        (!restore || receipt.Evidence == DispatchEvidence.PossiblyDispatched), NativeFailure.ContractMismatch);
                }
                if (!restore && acquired is not null)
                {
                    byte[] bytes = acquired.Export();
                    try { await destinationSetup.RestoreSecretBackupAsync(bytes, token); }
                    finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
                }
                bool expectedRestored = !rejected && !denied && (restore || acquired is not null);
                for (int index = 0; index < seeded.Count; index++)
                {
                    KeyVaultSecret original = (await sourceObserver.GetSecretAsync(name, seeded[index].Version, token)).Value;
                    probe.Effect(original.Value == material[index] ? NativeObservation.Matched : NativeObservation.Mismatched);
                    if (expectedRestored)
                    {
                        KeyVaultSecret restored = (await destinationObserver.GetSecretAsync(name, seeded[index].Version, token)).Value;
                        probe.Effect(restored.Value == material[index] && Matches(restored.Properties, seeded[index], null)
                            ? NativeObservation.Matched : NativeObservation.Mismatched);
                    }
                }
                var versions = new List<string>();
                if (expectedRestored)
                {
                    await foreach (SecretProperties property in destinationObserver.GetPropertiesOfSecretVersionsAsync(name, token))
                        versions.Add(property.Version);
                    probe.Effect(versions.Count == seeded.Count && seeded.All(p => versions.Contains(p.Version))
                        ? NativeObservation.Matched : NativeObservation.Mismatched);
                }
                else
                {
                    try { await destinationObserver.GetSecretAsync(name, cancellationToken: token); probe.Effect(NativeObservation.Mismatched); }
                    catch (RequestFailedException error) when (error.Status == 404) { probe.Effect(NativeObservation.Matched); }
                }
                // Interrupted acquisition yields no caller-owned artifact to restore.
                if (!restore && interrupted) probe.Effect(NativeObservation.Unavailable);

                async Task Invoke()
                {
                    if (!restore)
                    {
                        SecretOutcome<AzureSecretBackup> result = await client.BackupSecretAsync(target, cancellation.Token);
                        if (result.IsSuccess) acquired = result.Value;
                        probe.Contract(denied ? result.Status == SecretStatus.Denied && boundary.LastAuthorizedStatus == 403 :
                            result.IsSuccess, NativeFailure.ContractMismatch);
                    }
                    else
                    {
                        AzureSetSecretPrecondition condition = definition.Key.Variant switch
                        {
                            "precondition.CreateOnly.rejected" => AzureSetSecretPrecondition.CreateOnly,
                            "precondition.MatchVersion.rejected" => AzureSetSecretPrecondition.MatchVersion,
                            _ => AzureSetSecretPrecondition.None
                        };
                        var result = await client.RestoreSecretBackupAsync(new(target, setupBackup!, condition), receipt, cancellation.Token);
                        probe.Contract(rejected ? result.Status == SecretStatus.Unsupported && receipt.Evidence == DispatchEvidence.NotDispatched :
                            denied ? result.Status == SecretStatus.Denied && boundary.LastAuthorizedStatus == 403 &&
                                receipt.Evidence == DispatchEvidence.Rejected :
                            boundary.Lose ? result.Status == SecretStatus.Unknown && receipt.Evidence == DispatchEvidence.PossiblyDispatched :
                            result.IsSuccess && receipt.Evidence == DispatchEvidence.Applied, NativeFailure.ContractMismatch);
                    }
                }
            }
            finally { acquired?.Dispose(); }
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            bool clean = true;
            foreach ((SecretClient setup, SecretClient observer) in destinationOwned ?
                new[] { (sourceSetup, sourceObserver), (destinationSetup, destinationObserver) } :
                new[] { (sourceSetup, sourceObserver) })
            {
                try
                {
                    try { await setup.StartDeleteSecretAsync(name, cleanup.Token); }
                    catch (RequestFailedException error) when (error.Status is 404 or 409) { }
                    try { await observer.GetSecretAsync(name, cancellationToken: cleanup.Token); clean = false; }
                    catch (RequestFailedException error) when (error.Status == 404) { }
                }
                catch (Exception) { clean = false; }
            }
            probe.Contract(clean, NativeFailure.CleanupIncomplete);
        }
    }

    private static async ValueTask LifecycleMutation(OwnedAzureEnvironment environment, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token)
    {
        string method = definition.Key.Operation["a.runtime.AzureKeyVaultClient.".Length..];
        bool delete = method == "StartDeleteSecretAsync", purge = method == "PurgeDeletedSecretAsync";
        probe.Contract(definition.Member == "SecretKit.AzureKeyVault.AzureKeyVaultClient." + method +
            "(SecretKit.Core.SecretReference,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)" &&
            definition.Key.Variant == "input.target" && definition.Key.Case is "selected-contract" or
                "independent-effect" or "denied-authority" or "cancellation-boundary" or "lost-response-no-replay",
            NativeFailure.ContractMismatch);
        JsonElement input = environment.RequireFamilyInput("C08-AR-AzureNativeLifecycle");
        string sandbox = input.GetProperty("namespace").GetString()!;
        probe.Contract(sandbox.Length is >= 3 and <= 40 && sandbox.All(c =>
            char.IsAsciiLetterOrDigit(c) || c == '-'), NativeFailure.MissingInput);
        if (purge)
            probe.Contract(input.GetProperty("allowOwnedSecretPurge").GetBoolean(), NativeFailure.MissingPrerequisite);
        string name = sandbox + "-" + Guid.NewGuid().ToString("N");
        string material = Guid.NewGuid().ToString("N");
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var wire = new HttpClientTransport(http);
        var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01) { Transport = wire };
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        var setup = new SecretClient(environment.VaultUri, environment.Credential(NativeIdentityRole.Setup), options);
        var observer = new SecretClient(environment.VaultUri, environment.Credential(NativeIdentityRole.Observer), options);
        try
        {
            string first = (await setup.SetSecretAsync(name, material, token)).Value.Properties.Version;
            string latest = (await setup.SetSecretAsync(name, material, token)).Value.Properties.Version;
            if (!delete)
            {
                await setup.StartDeleteSecretAsync(name, token);
                try { _ = await observer.GetDeletedSecretAsync(name, token); }
                catch (RequestFailedException error) when (error.Status == 404)
                { throw new NativeCaseFailureException("observer-unavailable"); }
            }
            bool denied = definition.Key.Case == "denied-authority";
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            var boundary = new AzureKeyVaultClientEffects.ResponseBoundary(wire, name,
                delete ? "/secrets/" + name : "/deletedsecrets/" + name)
            {
                Hold = definition.Key.Case == "cancellation-boundary",
                Lose = definition.Key.Case == "lost-response-no-replay"
            };
            AzureKeyVaultClient client = environment.CreateClient(denied ?
                NativeIdentityRole.Denied : NativeIdentityRole.Runtime, boundary);
            var target = new SecretReference(client.Authority, new AzureSecretAddress(name));
            var receipt = new MutationReceipt(target);
            Task operation = Invoke();
            if (boundary.Hold)
            {
                Task winner = await Task.WhenAny(operation, boundary.Observed.Task).WaitAsync(token);
                if (winner == boundary.Observed.Task)
                {
                    cancellation.Cancel();
                    boundary.Release.TrySetResult();
                }
            }
            try { await operation; probe.Contract(!boundary.Hold, NativeFailure.ContractMismatch); }
            catch (OperationCanceledException) when (boundary.Hold && cancellation.IsCancellationRequested &&
                !token.IsCancellationRequested)
            {
                probe.Contract(boundary.Observed.Task.IsCompletedSuccessfully &&
                    receipt.Evidence == DispatchEvidence.PossiblyDispatched, NativeFailure.ContractMismatch);
            }
            bool expectActive = denied ? delete : !delete && !purge;
            if (expectActive)
            {
                foreach (string version in new[] { first, latest })
                {
                    KeyVaultSecret measured = (await observer.GetSecretAsync(name, version, token)).Value;
                    probe.Effect(measured.Value == material ? NativeObservation.Matched : NativeObservation.Mismatched);
                }
                var versions = new List<string>();
                await foreach (SecretProperties version in observer.GetPropertiesOfSecretVersionsAsync(name, token))
                    versions.Add(version.Version);
                probe.Effect(versions.Count == 2 && versions.Contains(first) && versions.Contains(latest)
                    ? NativeObservation.Matched : NativeObservation.Mismatched);
            }
            else
            {
                try { await observer.GetSecretAsync(name, cancellationToken: token); probe.Effect(NativeObservation.Mismatched); }
                catch (RequestFailedException error) when (error.Status == 404) { }
            }
            bool expectDeleted = denied ? !delete : delete;
            try
            {
                DeletedSecret measured = (await observer.GetDeletedSecretAsync(name, token)).Value;
                probe.Effect(expectDeleted && measured.Name == name && measured.DeletedOn is not null ?
                    NativeObservation.Matched : NativeObservation.Mismatched);
            }
            catch (RequestFailedException error) when (error.Status == 404)
            { probe.Effect(!expectDeleted ? NativeObservation.Matched : NativeObservation.Unavailable); }

            async Task Invoke()
            {
                SecretStatus status;
                if (purge) status = (await client.PurgeDeletedSecretAsync(target, receipt, cancellation.Token)).Status;
                else
                {
                    SecretOutcome<AzureLifecycleResult> result = delete ?
                        await client.StartDeleteSecretAsync(target, receipt, cancellation.Token) :
                        await client.StartRecoverDeletedSecretAsync(target, receipt, cancellation.Token);
                    status = result.Status;
                    if (result.IsSuccess)
                        probe.Contract(result.Value.State == AzureLifecycleState.Pending &&
                            result.Value.Operation.Kind == (delete ? AzureLifecycleKind.Delete : AzureLifecycleKind.Recover),
                            NativeFailure.ContractMismatch);
                }
                probe.Contract(denied ? status == SecretStatus.Denied && boundary.LastAuthorizedStatus == 403 &&
                    receipt.Evidence == DispatchEvidence.Rejected :
                    boundary.Lose ? status == SecretStatus.Unknown && receipt.Evidence == DispatchEvidence.PossiblyDispatched :
                    status == SecretStatus.Success && receipt.Evidence == (purge ? DispatchEvidence.Applied : DispatchEvidence.Pending),
                    NativeFailure.ContractMismatch);
            }
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            bool clean = true;
            try
            {
                try { await setup.StartDeleteSecretAsync(name, cleanup.Token); }
                catch (RequestFailedException error) when (error.Status is 404 or 409) { }
                try { await observer.GetSecretAsync(name, cancellationToken: cleanup.Token); clean = false; }
                catch (RequestFailedException error) when (error.Status == 404) { }
            }
            catch (Exception) { clean = false; }
            probe.Contract(clean, NativeFailure.CleanupIncomplete);
        }
    }

    private static async ValueTask Deleted(OwnedAzureEnvironment environment, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token)
    {
        bool inventory = definition.Key.Operation == "a.runtime.AzureKeyVaultClient.GetDeletedSecretsAsync";
        probe.Contract(definition.Member == (inventory ?
            "SecretKit.AzureKeyVault.AzureKeyVaultClient.GetDeletedSecretsAsync(SecretKit.AzureKeyVault.AzureInventoryScope,System.Threading.CancellationToken)" :
            "SecretKit.AzureKeyVault.AzureKeyVaultClient.GetDeletedSecretAsync(SecretKit.Core.SecretReference,System.Threading.CancellationToken)"),
            NativeFailure.ContractMismatch);
        probe.Contract((inventory ? definition.Key.Variant is "selector.exact" or "page.complete" or
                "page.page-budget" or "page.item-budget" : definition.Key.Variant == "selector.exact") &&
            definition.Key.Case is "selected-contract" or "independent-effect" or "denied-authority" or
                "cancellation-boundary", NativeFailure.ContractMismatch);
        JsonElement input = environment.RequireFamilyInput("C08-AR-AzureNativeLifecycle");
        string sandbox = input.GetProperty("namespace").GetString()!;
        probe.Contract(sandbox.Length is >= 3 and <= 40 && sandbox.All(c =>
            char.IsAsciiLetterOrDigit(c) || c == '-'), NativeFailure.MissingInput);
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var wire = new HttpClientTransport(http);
        var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01) { Transport = wire };
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        var setup = new SecretClient(environment.VaultUri, environment.Credential(NativeIdentityRole.Setup), options);
        var observer = new SecretClient(environment.VaultUri, environment.Credential(NativeIdentityRole.Observer), options);
        var names = new List<string>();
        try
        {
            int count = inventory && definition.Key.Variant == "page.page-budget" ? 26 : inventory ? 2 : 1;
            for (int index = 0; index < count; index++)
            {
                string name = sandbox + "-" + Guid.NewGuid().ToString("N");
                names.Add(name);
                await setup.SetSecretAsync(name, Guid.NewGuid().ToString("N"), token);
                await setup.StartDeleteSecretAsync(name, token);
                // One observation only. Native propagation is not made deterministic by sleeping.
                try { _ = await observer.GetDeletedSecretAsync(name, token); }
                catch (RequestFailedException error) when (error.Status == 404)
                { throw new NativeCaseFailureException("observer-unavailable"); }
            }
            string selected = names[0];
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            var boundary = new AzureKeyVaultClientEffects.ResponseBoundary(wire, selected,
                inventory ? "/deletedsecrets" : "/deletedsecrets/" + selected)
            { Hold = definition.Key.Case == "cancellation-boundary" };
            AzureKeyVaultClient client = environment.CreateClient(definition.Key.Case == "denied-authority"
                ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime, boundary);
            Task operation = Invoke();
            if (boundary.Hold)
            {
                Task winner = await Task.WhenAny(operation, boundary.Observed.Task).WaitAsync(token);
                if (winner == boundary.Observed.Task)
                {
                    cancellation.Cancel();
                    boundary.Release.TrySetResult();
                }
            }
            try { await operation; probe.Contract(!boundary.Hold, NativeFailure.ContractMismatch); }
            catch (OperationCanceledException) when (boundary.Hold && cancellation.IsCancellationRequested &&
                !token.IsCancellationRequested)
            { probe.Contract(boundary.Observed.Task.IsCompletedSuccessfully, NativeFailure.ContractMismatch); }
            foreach (string name in names)
            {
                DeletedSecret deleted = (await observer.GetDeletedSecretAsync(name, token)).Value;
                probe.Effect(deleted.Name == name && deleted.DeletedOn is not null &&
                    deleted.ScheduledPurgeDate is not null ? NativeObservation.Matched : NativeObservation.Mismatched);
            }

            async Task Invoke()
            {
                if (!inventory)
                {
                    var target = new SecretReference(client.Authority, new AzureSecretAddress(selected));
                    SecretOutcome<AzureSecretMetadata> result = await client.GetDeletedSecretAsync(target, cancellation.Token);
                    if (definition.Key.Case == "denied-authority")
                        probe.Contract(result.Status == SecretStatus.Denied && boundary.LastAuthorizedStatus == 403,
                            NativeFailure.ContractMismatch);
                    else
                    {
                        probe.Contract(result.IsSuccess, NativeFailure.ContractMismatch);
                        DeletedSecret measured = (await observer.GetDeletedSecretAsync(selected, token)).Value;
                        probe.Effect(DeletedMatches(result.Value, measured) ?
                            NativeObservation.Matched : NativeObservation.Mismatched);
                    }
                    return;
                }
                JsonElement limits = input.GetProperty("inventory");
                int pages = definition.Key.Variant == "page.page-budget" ? 1 : limits.GetProperty("maximumPages").GetInt32();
                int items = definition.Key.Variant == "page.item-budget" ? 1 : limits.GetProperty("maximumItems").GetInt32();
                SecretOutcome<AzureNativeInventory> list = await client.GetDeletedSecretsAsync(
                    new AzureInventoryScope(client.Authority, pages, items), cancellation.Token);
                if (definition.Key.Case == "denied-authority")
                    probe.Contract(list.Status == SecretStatus.Denied && boundary.LastAuthorizedStatus == 403,
                        NativeFailure.ContractMismatch);
                else
                {
                    probe.Contract(list.IsSuccess, NativeFailure.ContractMismatch);
                    var measured = new List<DeletedSecret>();
                    await foreach (DeletedSecret deleted in observer.GetDeletedSecretsAsync(token)) measured.Add(deleted);
                    bool complete = definition.Key.Variant is "selector.exact" or "page.complete";
                    probe.Contract(list.Value.IsComplete == complete && list.Value.Items.Count <= items,
                        NativeFailure.ContractMismatch);
                    probe.Effect(list.Value.Items.All(m => measured.Any(d => DeletedMatches(m, d))) &&
                        (complete ? list.Value.Items.Count == measured.Count : list.Value.Items.Count < measured.Count)
                        ? NativeObservation.Matched : NativeObservation.Mismatched);
                }
            }
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            bool clean = true;
            foreach (string name in names)
            {
                try
                {
                    try { await setup.StartDeleteSecretAsync(name, cleanup.Token); }
                    catch (RequestFailedException error) when (error.Status is 404 or 409) { }
                    try { await observer.GetSecretAsync(name, cancellationToken: cleanup.Token); clean = false; }
                    catch (RequestFailedException error) when (error.Status == 404) { }
                }
                catch (Exception) { clean = false; }
            }
            probe.Contract(clean, NativeFailure.CleanupIncomplete);
        }
    }

    private static bool DeletedMatches(AzureSecretMetadata actual, DeletedSecret measured) =>
        actual.Reference.Address is AzureSecretAddress address && address.Name == measured.Name &&
        address.Version == measured.Properties.Version && actual.DeletedOn == measured.DeletedOn &&
        actual.ScheduledPurgeOn == measured.ScheduledPurgeDate && actual.Enabled == measured.Properties.Enabled &&
        actual.NotBefore == measured.Properties.NotBefore && actual.ExpiresOn == measured.Properties.ExpiresOn &&
        actual.ContentType == measured.Properties.ContentType && actual.Tags.Count == measured.Properties.Tags.Count &&
        actual.Tags.All(t => measured.Properties.Tags.TryGetValue(t.Key, out string? value) && value == t.Value);

    internal static AzureUpdatePropertiesRequest Patch(SecretReference target, string variant, DateTimeOffset now)
    {
        bool? enabled = null;
        DateTimeOffset? notBefore = null, expiresOn = null;
        string? contentType = null;
        IReadOnlyDictionary<string, string>? tags = null;
        AzureSetSecretPrecondition precondition = AzureSetSecretPrecondition.None;
        switch (variant)
        {
            case "precondition.None":
            case "AzureUpdatePropertiesRequest.precondition.None":
                contentType = "patched"; break;
            case "precondition.CreateOnly.rejected":
            case "AzureUpdatePropertiesRequest.precondition.CreateOnly":
                precondition = AzureSetSecretPrecondition.CreateOnly; break;
            case "precondition.MatchVersion.rejected":
            case "AzureUpdatePropertiesRequest.precondition.MatchVersion":
                precondition = AzureSetSecretPrecondition.MatchVersion; break;
            case "AzureUpdatePropertiesRequest.enabled.omitted":
            case "AzureUpdatePropertiesRequest.notBefore.omitted":
            case "AzureUpdatePropertiesRequest.expiresOn.omitted":
            case "AzureUpdatePropertiesRequest.contentType.omitted":
            case "tags.omitted":
                break;
            case "AzureUpdatePropertiesRequest.enabled.false": enabled = false; break;
            case "AzureUpdatePropertiesRequest.enabled.true": enabled = true; break;
            case "AzureUpdatePropertiesRequest.notBefore.value": notBefore = now.AddDays(-2); break;
            case "AzureUpdatePropertiesRequest.expiresOn.value": expiresOn = now.AddDays(3); break;
            case "AzureUpdatePropertiesRequest.contentType.value": contentType = "patched"; break;
            case "tags.nonempty": tags = new Dictionary<string, string> { ["changed"] = "value" }; break;
            case "tags.empty.clear": tags = new Dictionary<string, string>(); break;
            default: throw new NativeCaseFailureException("missing-input");
        }
        return new(target, enabled, notBefore, expiresOn, contentType, tags, precondition);
    }

    private static async ValueTask UpdateProperties(OwnedAzureEnvironment environment, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token)
    {
        probe.Contract(definition.Member ==
            "SecretKit.AzureKeyVault.AzureKeyVaultClient.UpdatePropertiesAsync(SecretKit.AzureKeyVault.AzureUpdatePropertiesRequest,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)" &&
            definition.Key.Case is "selected-contract" or "independent-effect" or "denied-authority" or
                "cancellation-boundary" or "lost-response-no-replay", NativeFailure.ContractMismatch);
        JsonElement input = environment.RequireFamilyInput("C08-AR-AzureNativeLifecycle");
        string sandbox = input.GetProperty("namespace").GetString()!;
        probe.Contract(sandbox.Length is >= 3 and <= 40 && sandbox.All(c =>
            char.IsAsciiLetterOrDigit(c) || c == '-'), NativeFailure.MissingInput);
        string name = sandbox + "-" + Guid.NewGuid().ToString("N");
        string material = Guid.NewGuid().ToString("N");
        DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        // Validate the selected variant before acquiring provider authority.
        AzureKeyVaultClient validationClient = environment.CreateClient(NativeIdentityRole.Runtime);
        var validationTarget = new SecretReference(validationClient.Authority,
            new AzureSecretAddress(name, "11111111111111111111111111111111"));
        _ = Patch(validationTarget, definition.Key.Variant, now);
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var wire = new HttpClientTransport(http);
        var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01) { Transport = wire };
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        var setup = new SecretClient(environment.VaultUri, environment.Credential(NativeIdentityRole.Setup), options);
        var observer = new SecretClient(environment.VaultUri, environment.Credential(NativeIdentityRole.Observer), options);
        try
        {
            // A different latest version catches accidentally updating latest instead of the exact selector.
            var seed = new KeyVaultSecret(name, material);
            seed.Properties.Enabled = definition.Key.Variant != "AzureUpdatePropertiesRequest.enabled.true";
            seed.Properties.NotBefore = now.AddDays(-1);
            seed.Properties.ExpiresOn = now.AddDays(2);
            seed.Properties.ContentType = "baseline";
            seed.Properties.Tags.Add("baseline", "value");
            SecretProperties first = (await setup.SetSecretAsync(seed, token)).Value.Properties;
            SecretProperties latest = (await setup.SetSecretAsync(new KeyVaultSecret(name, material), token)).Value.Properties;
            SecretProperties before = await ExactProperties(observer, name, first.Version, token);
            SecretProperties latestBefore = (await observer.GetSecretAsync(name, latest.Version, token)).Value.Properties;
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            var boundary = new AzureKeyVaultClientEffects.ResponseBoundary(wire, name)
            {
                Hold = definition.Key.Case == "cancellation-boundary",
                Lose = definition.Key.Case == "lost-response-no-replay"
            };
            AzureKeyVaultClient client = environment.CreateClient(definition.Key.Case == "denied-authority"
                ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime, boundary);
            var target = new SecretReference(client.Authority, new AzureSecretAddress(name, first.Version));
            AzureUpdatePropertiesRequest request = Patch(target, definition.Key.Variant, now);
            bool rejected = request.Precondition != AzureSetSecretPrecondition.None;
            var receipt = new MutationReceipt(target);
            Task<SecretOutcome<AzureSecretMetadata>> operation =
                client.UpdatePropertiesAsync(request, receipt, cancellation.Token).AsTask();
            if (boundary.Hold && !rejected)
            {
                Task winner = await Task.WhenAny(operation, boundary.Observed.Task).WaitAsync(token);
                if (winner == boundary.Observed.Task)
                {
                    cancellation.Cancel();
                    boundary.Release.TrySetResult();
                }
            }
            bool denied = definition.Key.Case == "denied-authority";
            bool applied = false;
            try
            {
                SecretOutcome<AzureSecretMetadata> result = await operation;
                probe.Contract(rejected ? result.Status == SecretStatus.Unsupported &&
                    receipt.Evidence == DispatchEvidence.NotDispatched :
                    denied ? AzureKeyVaultClientEffects.DeniedMutationMatches(result.Status,
                        boundary.LastAuthorizedStatus, receipt.Evidence) :
                    boundary.Lose ? result.Status == SecretStatus.Unknown &&
                        receipt.Evidence == DispatchEvidence.PossiblyDispatched :
                    !boundary.Hold && result.IsSuccess && receipt.Evidence == DispatchEvidence.Applied,
                    NativeFailure.ContractMismatch);
                applied = !rejected && !denied;
                if (result.IsSuccess)
                    probe.Contract(result.Value.Reference.Address is AzureSecretAddress address &&
                        address.Name == name && address.Version == first.Version, NativeFailure.ContractMismatch);
            }
            catch (OperationCanceledException) when (boundary.Hold && cancellation.IsCancellationRequested &&
                !token.IsCancellationRequested)
            {
                probe.Contract(!rejected && receipt.Evidence == DispatchEvidence.PossiblyDispatched &&
                    boundary.Observed.Task.IsCompletedSuccessfully, NativeFailure.ContractMismatch);
                // This boundary is after the authorized PATCH response, not before dispatch.
                applied = true;
            }
            SecretProperties after = await ExactProperties(observer, name, first.Version, token);
            probe.Effect(Matches(after, before, applied ? request : null)
                ? NativeObservation.Matched : NativeObservation.Mismatched);
            SecretProperties latestAfter = await ExactProperties(observer, name, latest.Version, token);
            probe.Effect(Matches(latestAfter, latestBefore, null)
                ? NativeObservation.Matched : NativeObservation.Mismatched);
            var versions = new List<string>();
            await foreach (SecretProperties version in observer.GetPropertiesOfSecretVersionsAsync(name, token))
                versions.Add(version.Version);
            probe.Effect(versions.Count == 2 && versions.Contains(first.Version) && versions.Contains(latest.Version)
                ? NativeObservation.Matched : NativeObservation.Mismatched);
            // Disabled values cannot be fetched. Restore only the owned version's enable
            // flag through setup after observing it, then independently verify unchanged material.
            if (after.Enabled == false)
                await setup.UpdateSecretPropertiesAsync(new SecretProperties(first.Id) { Enabled = true }, token);
            KeyVaultSecret read = (await observer.GetSecretAsync(name, first.Version, token)).Value;
            probe.Effect(read.Value == material ? NativeObservation.Matched : NativeObservation.Mismatched);
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            bool clean = true;
            try
            {
                try { await setup.StartDeleteSecretAsync(name, cleanup.Token); }
                catch (RequestFailedException error) when (error.Status == 404) { }
                try { await observer.GetSecretAsync(name, cancellationToken: cleanup.Token); clean = false; }
                catch (RequestFailedException error) when (error.Status == 404) { }
            }
            catch (Exception) { clean = false; }
            probe.Contract(clean, NativeFailure.CleanupIncomplete);
            environment.ConfirmPrerequisite(definition.Key.Scope, "approved-sandbox-cleanup", NativeObservation.Matched);
        }
    }

    private static async Task<SecretProperties> ExactProperties(SecretClient observer, string name, string version,
        CancellationToken token)
    {
        await foreach (SecretProperties property in observer.GetPropertiesOfSecretVersionsAsync(name, token))
            if (property.Version == version) return property;
        throw new NativeCaseFailureException("effect-mismatch");
    }

    private static bool Matches(SecretProperties actual, SecretProperties before, AzureUpdatePropertiesRequest? patch)
    {
        IReadOnlyDictionary<string, string> tags = patch?.Tags ?? new Dictionary<string, string>(before.Tags);
        return actual.Version == before.Version && actual.Enabled == (patch?.Enabled ?? before.Enabled) &&
            actual.NotBefore == (patch?.NotBefore ?? before.NotBefore) &&
            actual.ExpiresOn == (patch?.ExpiresOn ?? before.ExpiresOn) &&
            actual.ContentType == (patch?.ContentType ?? before.ContentType) &&
            actual.Tags.Count == tags.Count && tags.All(t => actual.Tags.TryGetValue(t.Key, out string? v) && v == t.Value);
    }

    private static async ValueTask Versions(OwnedAzureEnvironment environment, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token)
    {
        bool exact = definition.Key.Operation == "a.runtime.AzureKeyVaultClient.GetSecretVersionAsync";
        string member = exact ? "GetSecretVersionAsync(SecretKit.Core.SecretReference,System.Threading.CancellationToken)"
            : "GetSecretVersionsAsync(SecretKit.Core.SecretReference,SecretKit.AzureKeyVault.AzureInventoryScope,System.Threading.CancellationToken)";
        probe.Contract(definition.Member == "SecretKit.AzureKeyVault.AzureKeyVaultClient." + member,
            NativeFailure.ContractMismatch);
        JsonElement input = environment.RequireFamilyInput("C08-AR-AzureNativeLifecycle");
        string sandbox = input.GetProperty("namespace").GetString()!;
        probe.Contract(sandbox.Length is >= 3 and <= 40 && sandbox.All(c =>
            char.IsAsciiLetterOrDigit(c) || c == '-'), NativeFailure.MissingInput);
        string name = sandbox + "-" + Guid.NewGuid().ToString("N");
        string material = Guid.NewGuid().ToString("N");
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var wire = new HttpClientTransport(http);
        var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01) { Transport = wire };
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        var setup = new SecretClient(environment.VaultUri, environment.Credential(NativeIdentityRole.Setup), options);
        var observer = new SecretClient(environment.VaultUri, environment.Credential(NativeIdentityRole.Observer), options);
        var seeded = new List<SecretProperties>();
        try
        {
            int count = exact ? 1 : definition.Key.Variant == "page.page-budget" ? 26 : 2;
            for (int index = 0; index < count; index++)
            {
                var secret = new KeyVaultSecret(name, material);
                secret.Properties.Enabled = true;
                DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                if (exact)
                {
                    switch (definition.Key.Variant)
                    {
                        case "version.exact.valid": break;
                        case "version.exact.disabled": secret.Properties.Enabled = false; break;
                        case "version.exact.not-yet-valid": secret.Properties.NotBefore = now.AddDays(1); break;
                        case "version.exact.expired": secret.Properties.ExpiresOn = now.AddDays(-1); break;
                        default: throw new NativeCaseFailureException("missing-input");
                    }
                }
                seeded.Add((await setup.SetSecretAsync(secret, token)).Value.Properties);
            }
            var before = new List<SecretProperties>();
            await foreach (SecretProperties property in observer.GetPropertiesOfSecretVersionsAsync(name, token))
                before.Add(property);
            probe.Contract(before.Count == count && seeded.All(s => before.Any(p => p.Version == s.Version)),
                NativeFailure.MissingPrerequisite);
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            var boundary = new AzureKeyVaultClientEffects.ResponseBoundary(wire, name)
            {
                Hold = definition.Key.Case == "cancellation-boundary"
            };
            AzureKeyVaultClient client = environment.CreateClient(definition.Key.Case == "denied-authority"
                ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime, boundary);
            var target = new SecretReference(client.Authority, new AzureSecretAddress(name,
                exact ? seeded[0].Version : null));
            Task operation = Invoke();
            if (boundary.Hold)
            {
                Task winner = await Task.WhenAny(operation, boundary.Observed.Task).WaitAsync(token);
                if (winner == boundary.Observed.Task)
                {
                    cancellation.Cancel();
                    boundary.Release.TrySetResult();
                }
            }
            try
            {
                await operation;
                probe.Contract(!boundary.Hold, NativeFailure.ContractMismatch);
            }
            catch (OperationCanceledException) when (boundary.Hold && cancellation.IsCancellationRequested)
            {
                probe.Contract(true, NativeFailure.ContractMismatch);
            }
            var after = new List<SecretProperties>();
            await foreach (SecretProperties property in observer.GetPropertiesOfSecretVersionsAsync(name, token))
                after.Add(property);
            probe.Effect(after.Count == before.Count && before.All(b => after.Any(a =>
                a.Version == b.Version && a.Enabled == b.Enabled && a.NotBefore == b.NotBefore &&
                a.ExpiresOn == b.ExpiresOn)) ? NativeObservation.Matched : NativeObservation.Mismatched);
            if (seeded[0].Enabled == true && seeded[0].NotBefore is null && seeded[0].ExpiresOn is null)
            {
                foreach (SecretProperties property in after)
                {
                    KeyVaultSecret independentlyRead = (await observer.GetSecretAsync(name, property.Version, token)).Value;
                    probe.Effect(independentlyRead.Value == material ? NativeObservation.Matched : NativeObservation.Mismatched);
                }
            }

            async Task Invoke()
            {
                if (exact)
                {
                    SecretOutcome<SecretRead> result = await client.GetSecretVersionAsync(target, cancellation.Token);
                    if (result.IsSuccess)
                    {
                        using SecretRead read = result.Value;
                        SecretValidity validity = definition.Key.Variant switch
                        {
                            "version.exact.valid" => SecretValidity.Valid,
                            "version.exact.disabled" => SecretValidity.Disabled,
                            "version.exact.not-yet-valid" => SecretValidity.NotYetValid,
                            "version.exact.expired" => SecretValidity.Expired,
                            _ => throw new NativeCaseFailureException("missing-input")
                        };
                        probe.Contract(definition.Key.Case != "denied-authority" &&
                            read.Material.Reveal() == material && read.Observation.Validity == validity,
                            NativeFailure.ContractMismatch);
                    }
                    else probe.Contract(result.Status == SecretStatus.Denied && boundary.LastAuthorizedStatus == 403 &&
                        (definition.Key.Case == "denied-authority" || definition.Key.Variant != "version.exact.valid"),
                        NativeFailure.ContractMismatch);
                }
                else
                {
                    JsonElement limits = input.GetProperty("inventory");
                    int pages = definition.Key.Variant == "page.page-budget" ? 1 : limits.GetProperty("maximumPages").GetInt32();
                    int items = definition.Key.Variant == "page.item-budget" ? 1 : limits.GetProperty("maximumItems").GetInt32();
                    SecretOutcome<AzureNativeInventory> result = await client.GetSecretVersionsAsync(target,
                        new AzureInventoryScope(client.Authority, pages, items), cancellation.Token);
                    if (definition.Key.Case == "denied-authority")
                        probe.Contract(result.Status == SecretStatus.Denied, NativeFailure.ContractMismatch);
                    else
                    {
                        probe.Contract(result.IsSuccess, NativeFailure.ContractMismatch);
                        bool complete = definition.Key.Variant is "selector.exact" or "page.complete";
                        probe.Contract(result.Value.IsComplete == complete && result.Value.Items.Count <= items &&
                            result.Value.Items.All(i => i.Reference.Address is AzureSecretAddress a &&
                                a.Name == name && before.Any(p => p.Version == a.Version &&
                                    p.Enabled == i.Enabled && p.NotBefore == i.NotBefore && p.ExpiresOn == i.ExpiresOn)),
                            NativeFailure.ContractMismatch);
                        probe.Effect(AzureKeyVaultClientEffects.InventoryMatches(result.Value.Items.Select(i =>
                            (AzureSecretAddress)i.Reference.Address).Select(a => (a.Name, a.Version!)).ToArray(),
                            before.Select(p => (name, p.Version)).ToArray(), complete) ?
                            NativeObservation.Matched : NativeObservation.Mismatched);
                    }
                }
            }
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            bool clean = true;
            try
            {
                try { await setup.StartDeleteSecretAsync(name, cleanup.Token); }
                catch (RequestFailedException error) when (error.Status == 404) { }
                try
                {
                    await observer.GetSecretAsync(name, cancellationToken: cleanup.Token);
                    clean = false;
                }
                catch (RequestFailedException error) when (error.Status == 404) { }
            }
            catch (Exception) { clean = false; }
            probe.Contract(clean, NativeFailure.CleanupIncomplete);
        }
    }
}
