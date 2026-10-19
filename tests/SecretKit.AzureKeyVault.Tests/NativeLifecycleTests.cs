using System.Text.Json;
using Azure.Security.KeyVault.Secrets;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Tests;

public sealed class NativeLifecycleTests
{
    private const string Version = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Test]
    public async Task NativeMetadataInputIsBoundedBeforeProviderUse()
    {
        var backend = new NativeBackend();
        var client = backend.Client();
        var target = Target(client, Version);
        await Assert.That(() => new AzureUpdatePropertiesRequest(target,
            contentType: new string('x', 64 * 1024 + 1))).Throws<ArgumentException>();
        await Assert.That(() => new AzureUpdatePropertiesRequest(target,
            tags: new Dictionary<string, string> { ["tag"] = new string('x', 64 * 1024) }))
            .Throws<ArgumentException>();
        await Assert.That(backend.Paths.Count).IsEqualTo(0);
        await Assert.That(backend.Updates).IsEqualTo(0);
    }

    [Test]
    public async Task ExactVersionRejectsDecoratedProviderIdentifier()
    {
        var vault = new Uri("https://native-red.vault.azure.net");
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Json(200,
            JsonSerializer.Serialize(new
            {
                value = "material-canary",
                id = $"{vault}secrets/name-canary/{Version}?foreign=canary",
                attributes = new { enabled = true }
            }))));
        var client = new AzureKeyVaultClient(vault, new TestCredential(), wire);
        var target = new SecretReference(client.Authority, new AzureSecretAddress("name-canary", Version));

        var outcome = await client.ReadAsync(target);
        if (outcome.IsSuccess)
        {
            outcome.Value.Dispose();
        }

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(JsonSerializer.Serialize(outcome).Contains("canary")).IsFalse();
    }

    [Test]
    public async Task NativeExactVersionRetrievalAndVersionMetadataPreserveDisabledState()
    {
        var backend = new NativeBackend();
        var client = backend.Client();
        var target = Target(client, Version);
        using var read = (await client.GetSecretVersionAsync(target)).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo("material-canary");
        await Assert.That(read.Observation.Validity).IsEqualTo(SecretValidity.Disabled);
        await Assert.That(backend.Paths.Last()).IsEqualTo($"/secrets/name-canary/{Version}");
        var versions = (await client.GetSecretVersionsAsync(Target(client), new AzureInventoryScope(client.Authority))).Value;
        await Assert.That(versions.Items.Single().Reference.Address is AzureSecretAddress { Version: Version }).IsTrue();
        await Assert.That(versions.IsComplete).IsTrue();
        await Assert.That(backend.Paths.Last()).IsEqualTo("/secrets/name-canary/versions");
    }

    [Test]
    public async Task ExactMetadataUpdateDoesNotWriteMaterialOrAnotherVersion()
    {
        var backend = new NativeBackend();
        var client = backend.Client();
        var target = Target(client, Version);
        var tags = new Dictionary<string, string> { ["tag-canary"] = "value-canary" };
        var request = new AzureUpdatePropertiesRequest(target, enabled: true, contentType: "content-canary", tags: tags);
        tags["tag-canary"] = "changed";
        var receipt = new MutationReceipt(target);
        var result = await client.UpdatePropertiesAsync(request, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Enabled == true).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(backend.Material).IsEqualTo("material-canary");
        await Assert.That(backend.Updates).IsEqualTo(1);
        using var body = JsonDocument.Parse(backend.LastBody!);
        await Assert.That(body.RootElement.TryGetProperty("value", out _)).IsFalse();
        await Assert.That(body.RootElement.GetProperty("tags").GetProperty("tag-canary").GetString()).IsEqualTo("value-canary");
        await Assert.That((await client.UpdatePropertiesAsync(request, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(backend.Updates).IsEqualTo(1);
        await Safe(request, result.Value);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task LifecycleStartAndExplicitStatusDistinguishPendingFromApplied(bool recover)
    {
        var backend = new NativeBackend { Deleted = recover };
        var client = backend.Client();
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        var result = recover
            ? await client.StartRecoverDeletedSecretAsync(target, receipt)
            : await client.StartDeleteSecretAsync(target, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.State).IsEqualTo(AzureLifecycleState.Pending);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(backend.StatusReads).IsEqualTo(0);
        var pending = await client.CheckLifecycleStatusAsync(result.Value.Operation);
        await Assert.That(pending.Value.State).IsEqualTo(AzureLifecycleState.Pending);
        backend.Ready = true;
        var applied = await client.CheckLifecycleStatusAsync(result.Value.Operation);
        await Assert.That(applied.Value.State).IsEqualTo(AzureLifecycleState.Applied);
        await Assert.That(backend.Deleted).IsEqualTo(!recover);
        await Assert.That(backend.Mutations).IsEqualTo(1);
        await Assert.That(backend.StatusReads).IsEqualTo(2);
        await Safe(result.Value, applied.Value, result.Value.Operation);
        var foreign = new AzureKeyVaultClient(backend.Vault, new TestCredential(), backend.Wire);
        await Assert.That((await foreign.CheckLifecycleStatusAsync(result.Value.Operation)).Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task DeletedInventoryAndGetExposeOnlyValidatedMetadata()
    {
        var backend = new NativeBackend { Deleted = true, Ready = true };
        var client = backend.Client();
        var get = (await client.GetDeletedSecretAsync(Target(client))).Value;
        await Assert.That(get.DeletedOn.HasValue).IsTrue();
        var list = (await client.GetDeletedSecretsAsync(new AzureInventoryScope(client.Authority))).Value;
        await Assert.That(list.Items.Count).IsEqualTo(1);
        await Assert.That(list.IsComplete).IsTrue();
        await Assert.That(list.Items.Single().ScheduledPurgeOn.HasValue).IsTrue();
        await Safe(get, list);
    }

    [Test]
    [Arguments("delete")]
    [Arguments("recover")]
    [Arguments("purge")]
    [Arguments("update")]
    [Arguments("restore")]
    public async Task LostCommittedResponseRetainsPossibleDispatchWithoutReplay(string operation)
    {
        var backend = new NativeBackend { Deleted = operation is "recover" or "purge", DropResponse = true };
        var client = backend.Client();
        var target = Target(client, operation == "update" ? Version : null);
        var receipt = new MutationReceipt(target);
        var status = await Mutate(client, target, receipt, operation);
        await Assert.That(status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(backend.Mutations).IsEqualTo(1);
        await Assert.That(await Mutate(client, target, receipt, operation)).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(backend.Mutations).IsEqualTo(1);
        await Assert.That(backend.Deleted).IsEqualTo(operation == "delete");
        if (operation == "update")
        {
            await Assert.That(backend.Enabled).IsTrue();
        }
        if (operation == "restore")
        {
            await Assert.That(backend.Restored).IsTrue();
        }
    }

    [Test]
    [Arguments("delete")]
    [Arguments("recover")]
    [Arguments("purge")]
    [Arguments("update")]
    [Arguments("restore")]
    public async Task CancellationAfterCommitUsesExactEventAndRetainsEvidence(string operation)
    {
        var backend = new NativeBackend { Deleted = operation is "recover" or "purge", HoldResponse = true };
        var client = backend.Client();
        var target = Target(client, operation == "update" ? Version : null);
        var receipt = new MutationReceipt(target);
        using var cancellation = new CancellationTokenSource();
        var pending = Mutate(client, target, receipt, operation, cancellation.Token);
        await backend.Committed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        cancellation.Cancel();
        await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(backend.Mutations).IsEqualTo(1);
    }

    [Test]
    [Arguments("delete")]
    [Arguments("recover")]
    [Arguments("purge")]
    [Arguments("update")]
    [Arguments("restore")]
    public async Task PreCancellationConsumesReceiptWithoutSending(string operation)
    {
        var backend = new NativeBackend();
        var client = backend.Client();
        var target = Target(client, operation == "update" ? Version : null);
        var receipt = new MutationReceipt(target);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.That(async () => await Mutate(client, target, receipt, operation, cancellation.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(backend.Paths.Count).IsEqualTo(0);
        await Assert.That(await Mutate(client, target, receipt, operation)).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(backend.Paths.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("delete")]
    [Arguments("recover")]
    [Arguments("purge")]
    [Arguments("restore")]
    public async Task VersionScopedWholeSecretMutationIsUnsupported(string operation)
    {
        var backend = new NativeBackend();
        var client = backend.Client();
        var target = Target(client, Version);
        var receipt = new MutationReceipt(target);
        await Assert.That(await Mutate(client, target, receipt, operation)).IsEqualTo(SecretStatus.Unsupported);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(backend.Paths.Count).IsEqualTo(0);
    }

    [Test]
    public async Task UnsupportedMandatedConditionsAndUnversionedUpdateSendNothing()
    {
        var backend = new NativeBackend();
        var client = backend.Client();
        var target = Target(client, Version);
        var receipt = new MutationReceipt(target);
        await Assert.That((await client.UpdatePropertiesAsync(new AzureUpdatePropertiesRequest(
            target, enabled: true, precondition: AzureSetSecretPrecondition.MatchVersion), receipt)).Status)
            .IsEqualTo(SecretStatus.Unsupported);
        var latest = Target(client);
        await Assert.That((await client.UpdatePropertiesAsync(new AzureUpdatePropertiesRequest(latest, enabled: true),
            new MutationReceipt(latest))).Status).IsEqualTo(SecretStatus.Unsupported);
        await Assert.That((await client.GetSecretVersionAsync(latest)).Status).IsEqualTo(SecretStatus.Unsupported);
        await Assert.That((await client.BackupSecretAsync(target)).Status).IsEqualTo(SecretStatus.Unsupported);
        await Assert.That(backend.Paths.Count).IsEqualTo(0);
    }

    [Test]
    public async Task BackupCopiesExportsAndDisposalHaveIndependentOwnership()
    {
        var backend = new NativeBackend();
        var client = backend.Client();
        var backup = (await client.BackupSecretAsync(Target(client))).Value;
        var exported = backup.Export();
        using var copy = backup.Copy();
        exported[0] = 99;
        await Assert.That(copy.Export()[0]).IsEqualTo((byte)1);
        await Safe(backup, copy);
        backup.Dispose();
        await Assert.That(() => backup.Export()).Throws<ObjectDisposedException>();
        await Assert.That(copy.Export()[0]).IsEqualTo((byte)1);
        var source = new byte[] { 1, 2, 3, 4 };
        using var imported = AzureSecretBackup.FromBytes(source);
        source[0] = 99;
        await Assert.That(imported.Export()[0]).IsEqualTo((byte)1);
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        var restored = await client.RestoreSecretBackupAsync(new AzureRestoreSecretRequest(target, copy), receipt);
        await Assert.That(restored.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(copy.Export()[0]).IsEqualTo((byte)1);
        await Assert.That(backend.Restored).IsTrue();
    }

    [Test]
    [Arguments("version", "name")]
    [Arguments("version", "vault")]
    [Arguments("version", "version")]
    [Arguments("versions", "name")]
    [Arguments("versions", "vault")]
    [Arguments("versions", "query")]
    [Arguments("deleted", "name")]
    [Arguments("deleted", "vault")]
    [Arguments("deleted", "recovery")]
    [Arguments("deleted-list", "vault")]
    [Arguments("update", "version")]
    [Arguments("restore", "name")]
    [Arguments("delete", "name")]
    [Arguments("recover", "vault")]
    public async Task ForeignReturnedCoordinatesCannotBecomeTrusted(string operation, string corruption)
    {
        var backend = new NativeBackend { Corruption = corruption, Deleted = operation is "deleted" or "deleted-list" or "recover", Ready = true };
        var client = backend.Client();
        var target = Target(client, operation is "version" or "update" ? Version : null);
        var receipt = new MutationReceipt(target);
        SecretStatus status = operation switch
        {
            "version" => (await client.GetSecretVersionAsync(target)).Status,
            "versions" => (await client.GetSecretVersionsAsync(target, new AzureInventoryScope(client.Authority))).Status,
            "deleted" => (await client.GetDeletedSecretAsync(target)).Status,
            "deleted-list" => (await client.GetDeletedSecretsAsync(new AzureInventoryScope(client.Authority))).Status,
            _ => await Mutate(client, target, receipt, operation)
        };
        await Assert.That(status).IsEqualTo(operation is "update" or "restore" or "delete" or "recover"
            ? SecretStatus.Unknown : SecretStatus.Invalid);
        await Assert.That(receipt.Evidence == DispatchEvidence.Applied).IsFalse();
    }

    [Test]
    [Arguments("version")]
    [Arguments("versions")]
    [Arguments("deleted")]
    [Arguments("deleted-list")]
    [Arguments("backup")]
    public async Task NativeReadBodyBudgetsFailClosed(string operation)
    {
        var backend = new NativeBackend { Oversized = true, Deleted = true, Ready = true };
        var client = backend.Client(1024);
        var target = Target(client, operation == "version" ? Version : null);
        var status = operation switch
        {
            "version" => (await client.GetSecretVersionAsync(target)).Status,
            "versions" => (await client.GetSecretVersionsAsync(target, new AzureInventoryScope(client.Authority))).Status,
            "deleted" => (await client.GetDeletedSecretAsync(target)).Status,
            "deleted-list" => (await client.GetDeletedSecretsAsync(new AzureInventoryScope(client.Authority))).Status,
            _ => (await client.BackupSecretAsync(target)).Status
        };
        await Assert.That(status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task NativePermissionFailuresAreOutcomesNotCapabilityClaims()
    {
        var backend = new NativeBackend { Denied = true };
        var client = backend.Client();
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        await Assert.That((await client.StartDeleteSecretAsync(target, receipt)).Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(receipt.Evidence == DispatchEvidence.Applied).IsFalse();
        await Assert.That((await client.BackupSecretAsync(target)).Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(backend.Mutations).IsEqualTo(0);
    }

    [Test]
    [Arguments("delete")]
    [Arguments("recover")]
    [Arguments("purge")]
    [Arguments("update")]
    [Arguments("restore")]
    public async Task PostCommitChallengeCannotReplayBodylessOrBodyBearingMutation(string operation)
    {
        var backend = new NativeBackend { ChallengeAfterCommit = true, Deleted = operation is "recover" or "purge" };
        var client = backend.Client();
        var target = Target(client, operation == "update" ? Version : null);
        var receipt = new MutationReceipt(target);
        await Assert.That(await Mutate(client, target, receipt, operation)).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(backend.Mutations).IsEqualTo(1);
        await Assert.That(backend.Deleted).IsEqualTo(operation == "delete");
    }

    [Test]
    public async Task CancellationDuringChallengePrecedesPossibleDispatchAndConsumesReceipt()
    {
        var backend = new NativeBackend { HoldChallenge = true };
        var client = backend.Client();
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        using var cancellation = new CancellationTokenSource();
        var pending = client.StartDeleteSecretAsync(target, receipt, cancellation.Token).AsTask();
        await backend.ChallengeSeen.Task.WaitAsync(TimeSpan.FromSeconds(10));
        cancellation.Cancel();
        await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(backend.Mutations).IsEqualTo(0);
        await Assert.That((await client.StartDeleteSecretAsync(target, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CollectionsBoundPagesItemsAndValidateContinuationAuthority(bool deleted)
    {
        var backend = new NativeBackend { Deleted = deleted, Ready = true, Pages = true };
        var client = backend.Client();
        var scope = new AzureInventoryScope(client.Authority, maximumPages: 1);
        var bounded = deleted ? await client.GetDeletedSecretsAsync(scope)
            : await client.GetSecretVersionsAsync(Target(client), scope);
        await Assert.That(bounded.Value.Items.Count).IsEqualTo(1);
        await Assert.That(bounded.Value.IsComplete).IsFalse();
        scope = new AzureInventoryScope(client.Authority);
        var completed = deleted ? await client.GetDeletedSecretsAsync(scope)
            : await client.GetSecretVersionsAsync(Target(client), scope);
        await Assert.That(completed.Value.Items.Count).IsEqualTo(2);
        await Assert.That(completed.Value.IsComplete).IsTrue();
        var bad = new NativeBackend { Deleted = deleted, Ready = true, ForeignContinuation = true };
        client = bad.Client();
        scope = new AzureInventoryScope(client.Authority);
        var rejected = deleted ? await client.GetDeletedSecretsAsync(scope)
            : await client.GetSecretVersionsAsync(Target(client), scope);
        await Assert.That(rejected.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(bad.Wire.Requests.All(uri => uri.Host == bad.Vault.Host)).IsTrue();
    }

    [Test]
    public async Task TerminalOversizedCollectionIsIncompleteAndNotASnapshot()
    {
        var backend = new NativeBackend { MultipleRows = true };
        var client = backend.Client();
        var result = await client.GetSecretVersionsAsync(Target(client),
            new AzureInventoryScope(client.Authority, maximumItems: 1));
        await Assert.That(result.Value.Items.Count).IsEqualTo(1);
        await Assert.That(result.Value.IsComplete).IsFalse();
    }

    [Test]
    public async Task RestoreRequestAndMetadataBodyBoundsFailBeforeDispatch()
    {
        var backend = new NativeBackend();
        var client = backend.Client(1024);
        var target = Target(client);
        using var backup = AzureSecretBackup.FromBytes(new byte[1024]);
        var receipt = new MutationReceipt(target);
        var restored = await client.RestoreSecretBackupAsync(new AzureRestoreSecretRequest(target, backup), receipt);
        await Assert.That(restored.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        target = Target(client, Version);
        receipt = new MutationReceipt(target);
        var updated = await client.UpdatePropertiesAsync(new AzureUpdatePropertiesRequest(target,
            contentType: new string('x', 2000)), receipt);
        await Assert.That(updated.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(backend.Mutations).IsEqualTo(0);
    }

    [Test]
    public async Task DisposedBackupAndForeignAuthorityCannotDispatch()
    {
        var backend = new NativeBackend();
        var client = backend.Client();
        using var backup = AzureSecretBackup.FromBytes(new byte[] { 1 });
        backup.Dispose();
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        var result = await client.RestoreSecretBackupAsync(new AzureRestoreSecretRequest(target, backup), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        var foreign = new SecretReference(new SecretAuthority(), new AzureSecretAddress("name-canary"));
        await Assert.That((await client.StartDeleteSecretAsync(foreign, new MutationReceipt(foreign))).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That((await client.BackupSecretAsync(foreign)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That((await client.GetDeletedSecretsAsync(new AzureInventoryScope(new SecretAuthority()))).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That((await client.StartDeleteSecretAsync(target, new MutationReceipt(Target(client)))).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That(backend.Paths.Count).IsEqualTo(0);
    }

    [Test]
    public async Task UpdateOmissionAndExplicitEmptyTagsPreserveNativePatch()
    {
        var backend = new NativeBackend();
        var client = backend.Client();
        var target = Target(client, Version);
        await client.UpdatePropertiesAsync(new AzureUpdatePropertiesRequest(target, enabled: false),
            new MutationReceipt(target));
        using (var body = JsonDocument.Parse(backend.LastBody!))
        {
            await Assert.That(body.RootElement.TryGetProperty("tags", out _)).IsFalse();
            await Assert.That(body.RootElement.TryGetProperty("contentType", out _)).IsFalse();
        }
        var receipt = new MutationReceipt(target);
        var cleared = await client.UpdatePropertiesAsync(new AzureUpdatePropertiesRequest(target,
            tags: new Dictionary<string, string>()), receipt);
        await Assert.That(cleared.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        using var clearedBody = JsonDocument.Parse(backend.LastBody!);
        await Assert.That(clearedBody.RootElement.GetProperty("tags").EnumerateObject().Count()).IsEqualTo(0);
        await Assert.That(backend.Updates).IsEqualTo(2);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SdkOmitsEmptyTagsEvenAfterExplicitClear(bool clear)
    {
        var vault = new Uri("https://tag-clear.vault.azure.net");
        string? sent = null;
        var wire = new WireTransport(async (request, cancellationToken) =>
        {
            if (request.Headers.Authorization is null)
            {
                return WireTransport.Challenge();
            }
            sent = await request.Content!.ReadAsStringAsync(cancellationToken);
            return WireTransport.Json(200, JsonSerializer.Serialize(new
            {
                id = $"{vault}secrets/name-canary/{Version}",
                tags = new Dictionary<string, string>()
            }));
        });
        var sdk = new SecretClient(vault, new TestCredential(),
            new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01) { Transport = wire });
        var properties = new SecretProperties(new Uri(vault, $"secrets/name-canary/{Version}"));
        if (clear)
        {
            properties.Tags.Add("tag-canary", "value-canary");
            properties.Tags.Clear();
        }

        await sdk.UpdateSecretPropertiesAsync(properties);

        using var body = JsonDocument.Parse(sent!);
        await Assert.That(body.RootElement.TryGetProperty("tags", out _)).IsFalse();
    }

    [Test]
    public async Task EmptyTagsAreExplicitlyClearedWithoutWritingMaterial()
    {
        var backend = new NativeBackend { Ready = true };
        backend.Tags.Add("tag-canary", "value-canary");
        var client = backend.Client();
        var target = Target(client, Version);
        var receipt = new MutationReceipt(target);
        var result = await client.UpdatePropertiesAsync(new AzureUpdatePropertiesRequest(target,
            tags: new Dictionary<string, string>()), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        using var body = JsonDocument.Parse(backend.LastBody!);
        await Assert.That(body.RootElement.GetProperty("tags").EnumerateObject().Count()).IsEqualTo(0);
        await Assert.That(body.RootElement.TryGetProperty("value", out _)).IsFalse();
        var observed = (await client.GetSecretVersionsAsync(Target(client),
            new AzureInventoryScope(client.Authority))).Value;
        await Assert.That(observed.Items.Single().Tags.Count).IsEqualTo(0);
        using var read = (await client.GetSecretVersionAsync(target)).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo("material-canary");
        await Assert.That(backend.Updates).IsEqualTo(1);
        await Assert.That((await client.UpdatePropertiesAsync(new AzureUpdatePropertiesRequest(target,
            tags: new Dictionary<string, string>()), receipt)).Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task EmptyTagClearDenialAndLostResponseCannotReplay(bool lostResponse)
    {
        var backend = new NativeBackend { Denied = !lostResponse, DropResponse = lostResponse };
        backend.Tags.Add("tag-canary", "value-canary");
        var client = backend.Client();
        var target = Target(client, Version);
        var request = new AzureUpdatePropertiesRequest(target, tags: new Dictionary<string, string>());
        var receipt = new MutationReceipt(target);
        var result = await client.UpdatePropertiesAsync(request, receipt);
        await Assert.That(receipt.Evidence).IsEqualTo(lostResponse
            ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Rejected);
        await Assert.That(result.Status == SecretStatus.Success).IsFalse();
        await Assert.That(backend.Tags.Count).IsEqualTo(lostResponse ? 0 : 1);
        await Assert.That((await client.UpdatePropertiesAsync(request, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(backend.Mutations).IsEqualTo(lostResponse ? 1 : 0);
    }

    [Test]
    public async Task EmptyTagClearCancellationKeepsTheObservedUncertainEffect()
    {
        var backend = new NativeBackend { HoldResponse = true };
        backend.Tags.Add("tag-canary", "value-canary");
        var client = backend.Client();
        var target = Target(client, Version);
        var receipt = new MutationReceipt(target);
        using var cancellation = new CancellationTokenSource();
        var pending = client.UpdatePropertiesAsync(new AzureUpdatePropertiesRequest(target,
            tags: new Dictionary<string, string>()), receipt, cancellation.Token);
        await backend.Committed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        cancellation.Cancel();
        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(backend.Tags.Count).IsEqualTo(0);
        await Assert.That(backend.Mutations).IsEqualTo(1);
    }

    [Test]
    public async Task PurgeAcknowledgementChangesProviderStateWithoutClaimingAnInstantSnapshot()
    {
        var backend = new NativeBackend { Deleted = true, Ready = true };
        var client = backend.Client();
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        var result = await client.PurgeDeletedSecretAsync(target, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That((await client.GetDeletedSecretAsync(target)).Status).IsEqualTo(SecretStatus.Absent);
        await Assert.That((await client.PurgeDeletedSecretAsync(target, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(backend.Mutations).IsEqualTo(1);
    }

    [Test]
    public async Task InFlightRestoreOwnsItsCopyWhenCallerDisposesArtifact()
    {
        var backend = new NativeBackend { HoldResponse = true };
        var client = backend.Client();
        var target = Target(client);
        using var backup = AzureSecretBackup.FromBytes(new byte[] { 1, 2, 3, 4 });
        var pending = client.RestoreSecretBackupAsync(new AzureRestoreSecretRequest(target, backup),
            new MutationReceipt(target)).AsTask();
        await backend.Committed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        backup.Dispose();
        backend.ResponseReleased.TrySetResult();
        await Assert.That((await pending.WaitAsync(TimeSpan.FromSeconds(10))).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(backend.Restored).IsTrue();
        using var body = JsonDocument.Parse(backend.LastBody!);
        await Assert.That(body.RootElement.GetProperty("value").GetString()).IsEqualTo("AQIDBA");
        await Assert.That(() => backup.Copy()).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusFailureDoesNotInventPendingFromDenialOrForeignCoordinates(bool denied)
    {
        var backend = new NativeBackend();
        var client = backend.Client();
        var target = Target(client);
        var started = await client.StartDeleteSecretAsync(target, new MutationReceipt(target));
        backend.Ready = true;
        backend.Denied = denied;
        backend.Corruption = denied ? null : "recovery";
        var status = await client.CheckLifecycleStatusAsync(started.Value.Operation);
        await Assert.That(status.Status).IsEqualTo(denied ? SecretStatus.Denied : SecretStatus.Invalid);
        await Assert.That(backend.Mutations).IsEqualTo(1);
    }

    [Test]
    public async Task CancellationPreventsNextCollectionPageWithoutTiming()
    {
        var backend = new NativeBackend { Pages = true };
        var client = backend.Client();
        using var cancellation = new CancellationTokenSource();
        backend.CancelAfterPage = cancellation;
        await Assert.That(async () => await client.GetSecretVersionsAsync(Target(client),
            new AzureInventoryScope(client.Authority), cancellation.Token)).Throws<OperationCanceledException>();
        await Assert.That(backend.Wire.Requests.Any(uri => uri.Query.Contains("page=2", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task UnknownLengthNativeStreamsRespectResponseBudget(bool deleted)
    {
        var backend = new NativeBackend { UnknownLength = true, Oversized = true, Deleted = deleted, Ready = true };
        var client = backend.Client(1024);
        var status = deleted ? (await client.GetDeletedSecretAsync(Target(client))).Status
            : (await client.GetSecretVersionAsync(Target(client, Version))).Status;
        await Assert.That(status).IsEqualTo(SecretStatus.Invalid);
    }

    private static SecretReference Target(AzureKeyVaultClient client, string? version = null) =>
        new(client.Authority, new AzureSecretAddress("name-canary", version));

    private static async Task<SecretStatus> Mutate(AzureKeyVaultClient client, SecretReference target,
        MutationReceipt receipt, string operation, CancellationToken cancellationToken = default)
    {
        using var backup = AzureSecretBackup.FromBytes(new byte[] { 1, 2, 3, 4 });
        return operation switch
        {
            "delete" => (await client.StartDeleteSecretAsync(target, receipt, cancellationToken)).Status,
            "recover" => (await client.StartRecoverDeletedSecretAsync(target, receipt, cancellationToken)).Status,
            "purge" => (await client.PurgeDeletedSecretAsync(target, receipt, cancellationToken)).Status,
            "update" => (await client.UpdatePropertiesAsync(new AzureUpdatePropertiesRequest(target, enabled: true), receipt, cancellationToken)).Status,
            "restore" => (await client.RestoreSecretBackupAsync(new AzureRestoreSecretRequest(target, backup), receipt, cancellationToken)).Status,
            _ => throw new InvalidOperationException("Unknown fixture operation.")
        };
    }

    private static async Task Safe(params object[] models)
    {
        foreach (var model in models)
        {
            await Assert.That(JsonSerializer.Serialize(model).Contains("canary")).IsFalse();
            await Assert.That(JsonSerializer.Serialize(model).Contains(Version)).IsFalse();
            await Assert.That(model.ToString()!.Contains("canary")).IsFalse();
            await Assert.That(model.ToString()!.Contains(Version)).IsFalse();
        }
    }

    private sealed class NativeBackend
    {
        public Uri Vault { get; } = new($"https://n{Guid.NewGuid():N}"[..22] + ".vault.azure.net");
        public WireTransport Wire { get; }
        public bool Deleted { get; set; }
        public bool Ready { get; set; }
        public bool Enabled { get; set; }
        public bool Restored { get; private set; }
        public string Material { get; } = "material-canary";
        public Dictionary<string, string> Tags { get; } = [];
        public bool DropResponse { get; init; }
        public bool HoldResponse { get; init; }
        public bool Oversized { get; init; }
        public bool Denied { get; set; }
        public bool ChallengeAfterCommit { get; init; }
        public bool HoldChallenge { get; init; }
        public bool Pages { get; init; }
        public bool ForeignContinuation { get; init; }
        public bool MultipleRows { get; init; }
        public bool UnknownLength { get; init; }
        public CancellationTokenSource? CancelAfterPage { get; set; }
        public string? Corruption { get; set; }
        public int Mutations { get; private set; }
        public int Updates { get; private set; }
        public int StatusReads { get; private set; }
        public List<string> Paths { get; } = [];
        public string? LastBody { get; private set; }
        public TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ChallengeSeen { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ResponseReleased { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public NativeBackend() => Wire = new WireTransport(Respond);
        public AzureKeyVaultClient Client(int maximumResponseBytes = 1024 * 1024) =>
            new(Vault, new TestCredential(), Wire, new FixedTime(), maximumResponseBytes);

        private string Id => $"{(Corruption == "vault" ? "https://other.vault.azure.net/" : Vault.ToString())}secrets/" +
            $"{(Corruption == "name" ? "foreign" : "name-canary")}/" +
            $"{(Corruption == "version" ? new string('b', 32) : Version)}" +
            (Corruption == "query" ? "?foreign=canary" : "");

        private object Bundle(bool deleted = false) => deleted
            ? new
            {
                id = Id,
                value = Material,
                recoveryId = $"{(Corruption == "recovery" ? "https://foreign.vault.azure.net/" : Vault.ToString())}deletedsecrets/name-canary",
                deletedDate = 1_999_999_990,
                scheduledPurgeDate = 2_001_000_000,
                attributes = new { enabled = Enabled }
            }
            : new { id = Id, value = Material, attributes = new { enabled = Enabled }, tags = Tags };

        private async Task<HttpResponseMessage> Respond(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath.TrimEnd('/');
            Paths.Add(path);
            if (request.Headers.Authorization is null)
            {
                ChallengeSeen.TrySetResult();
                if (HoldChallenge)
                {
                    var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    using var registration = cancellationToken.Register(() => cancelled.TrySetCanceled(cancellationToken));
                    await cancelled.Task;
                }
                return WireTransport.Challenge();
            }
            if (Denied)
            {
                return WireTransport.Json(403, """{"error":{"message":"error-canary"}}""");
            }
            if (request.Method != HttpMethod.Get && !path.EndsWith("/backup", StringComparison.Ordinal))
            {
                Mutations++;
                LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
                if (request.Method == HttpMethod.Patch)
                {
                    Updates++;
                    Enabled = true;
                    using var body = JsonDocument.Parse(LastBody!);
                    if (body.RootElement.TryGetProperty("tags", out var tags))
                    {
                        Tags.Clear();
                        foreach (var tag in tags.EnumerateObject())
                            Tags.Add(tag.Name, tag.Value.GetString()!);
                    }
                }
                if (path.EndsWith("/recover", StringComparison.Ordinal))
                {
                    Deleted = false;
                }
                if (request.Method == HttpMethod.Delete)
                {
                    Deleted = path.StartsWith("/secrets/", StringComparison.Ordinal);
                }
                if (path == "/secrets/restore")
                {
                    Restored = true;
                    Deleted = false;
                }
                Committed.TrySetResult();
                if (HoldResponse)
                {
                    await ResponseReleased.Task.WaitAsync(cancellationToken);
                }
                if (DropResponse)
                {
                    throw new HttpRequestException("lost-response-canary");
                }
                if (ChallengeAfterCommit)
                {
                    return WireTransport.Challenge();
                }
                if (request.Method == HttpMethod.Delete && path.StartsWith("/deletedsecrets/", StringComparison.Ordinal))
                {
                    return WireTransport.Json(204, "");
                }
                return WireTransport.Json(200, JsonSerializer.Serialize(Bundle(Deleted)));
            }
            if (Oversized)
            {
                var response = WireTransport.Json(200, JsonSerializer.Serialize(new { value = new string('x', 4000) }));
                if (UnknownLength)
                {
                    response.Content = new StreamContent(new NonSeekStream(
                        System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { value = new string('x', 4000) }))));
                }
                return response;
            }
            if (path.EndsWith("/backup", StringComparison.Ordinal))
            {
                return WireTransport.Json(200, """{"value":"AQIDBA"}""");
            }
            if (path.EndsWith("/versions", StringComparison.Ordinal))
            {
                return Collection(request, false);
            }
            if (path == "/deletedsecrets")
            {
                return Collection(request, true);
            }
            StatusReads++;
            if ((Mutations > 0 && !Ready) || (path.StartsWith("/deletedsecrets/", StringComparison.Ordinal) != Deleted))
            {
                return WireTransport.Json(404, "{}");
            }
            return WireTransport.Json(200, JsonSerializer.Serialize(Bundle(Deleted)));
        }

        private HttpResponseMessage Collection(HttpRequestMessage request, bool deleted)
        {
            string? next = ForeignContinuation ? "https://foreign.vault.azure.net/secrets?api-version=2025-07-01"
                : Pages && !request.RequestUri!.Query.Contains("page=2", StringComparison.Ordinal)
                    ? $"{Vault.GetLeftPart(UriPartial.Authority)}{request.RequestUri.AbsolutePath}?api-version=2025-07-01&page=2"
                    : null;
            var response = WireTransport.Json(200, JsonSerializer.Serialize(new
            {
                value = MultipleRows ? new[] { Bundle(deleted), Bundle(deleted) } : new[] { Bundle(deleted) },
                nextLink = next
            }));
            CancelAfterPage?.Cancel();
            return response;
        }
    }

    private sealed class NonSeekStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
    }
}
