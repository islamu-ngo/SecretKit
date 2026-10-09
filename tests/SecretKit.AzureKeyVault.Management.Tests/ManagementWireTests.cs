using System.Diagnostics;
using System.Net;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management.Tests;

public sealed class ManagementWireTests
{
    private static VaultScope Scope() => ScopeAuthorityTests.Scope();
    private static VaultConfiguration Configuration() => new("eastus",
        Guid.Parse("22222222-2222-2222-2222-222222222222"), VaultSku.Standard, true, true, 7, false);

    [Test]
    public async Task ActualSdkReadUsesSelectedAuthorityAndRevisionWithoutActivity()
    {
        var activities = new List<string>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name.StartsWith("Azure.", StringComparison.Ordinal),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStarted = activity => activities.Add(activity.DisplayName)
        };
        ActivitySource.AddActivityListener(listener);
        var credential = new Credential();
        var backend = new WireBackend((request, _) =>
        {
            if (request.RequestUri?.Host != "management.azure.com" ||
                request.RequestUri.AbsolutePath != ScopeAuthorityTests.Id ||
                request.RequestUri.Query != "?api-version=2026-02-01" ||
                request.Headers.Authorization?.Parameter != "credential-canary")
            {
                throw new InvalidOperationException("Unexpected wire authority.");
            }

            return Task.FromResult(WireBackend.Json(200, ScopeAuthorityTests.VaultJson(ScopeAuthorityTests.Id)));
        });
        var result = await new VaultAdministration(credential, backend).GetVaultAsync(Scope());
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.ProvisioningState).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(result.Value.RuntimeDeliveryProven).IsFalse();
        await Assert.That(credential.Audiences.All(s => s == "https://management.azure.com/.default")).IsTrue();
        await Assert.That(activities.Count).IsEqualTo(0);
        await Assert.That(JsonSerializer.Serialize(result.Value).Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments(400, SecretStatus.Invalid)]
    [Arguments(401, SecretStatus.Denied)]
    [Arguments(403, SecretStatus.Denied)]
    [Arguments(404, SecretStatus.Absent)]
    [Arguments(409, SecretStatus.Conflict)]
    [Arguments(429, SecretStatus.Throttled)]
    [Arguments(503, SecretStatus.Unavailable)]
    public async Task ErrorsAreBoundedAndDoNotLeakProviderBody(int status, SecretStatus expected)
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(status,
            """{"error":{"code":"coordinate-canary","message":"secret-canary"}}""")));
        var result = await new VaultAdministration(new Credential(), backend).GetVaultAsync(Scope());
        await Assert.That(result.Status).IsEqualTo(expected);
        await Assert.That(JsonSerializer.Serialize(result).Contains("canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That(result.ToString().Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task LostCommittedCreateCannotReplayReceipt()
    {
        bool exists = false;
        var scope = Scope();
        var backend = new WireBackend(async (request, token) =>
        {
            if (request.Method == HttpMethod.Put)
            {
                var body = await request.Content!.ReadAsStringAsync(token);
                using var parsed = JsonDocument.Parse(body);
                if (parsed.RootElement.GetProperty("properties").GetProperty("enableRbacAuthorization").GetBoolean() != true)
                {
                    throw new InvalidOperationException("Unexpected wire state.");
                }

                if (exists)
                {
                    throw new InvalidOperationException("Mutation was replayed.");
                }

                exists = true;
                throw new HttpRequestException("committed-response-canary");
            }

            return WireBackend.Json(exists ? 200 : 404, exists
                ? ScopeAuthorityTests.VaultJson(ScopeAuthorityTests.Id) : "{}");
        });
        var client = new VaultAdministration(new Credential(), backend);
        var receipt = client.PrepareReceipt(scope, ManagementMutation.CreateOrUpdateVault);
        var result = await client.CreateOrUpdateVaultAsync(scope, Configuration(), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(exists).IsTrue();
        await Assert.That((await client.GetVaultAsync(scope)).IsSuccess).IsTrue();
        await Assert.That((await client.CreateOrUpdateVaultAsync(scope, Configuration(), receipt)).Status)
            .IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task CancellationBeforeCredentialDispatchRetainsNotDispatched()
    {
        bool exists = false;
        var backend = new WireBackend((_, _) =>
        {
            exists = true;
            return Task.FromResult(WireBackend.Json(201, ScopeAuthorityTests.VaultJson(ScopeAuthorityTests.Id)));
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Scope();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.CreateOrUpdateVault);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        bool canceled = false;
        try
        {
            await client.CreateOrUpdateVaultAsync(scope, Configuration(), receipt, cancellation.Token);
        }
        catch (OperationCanceledException)
        {
            canceled = true;
        }

        await Assert.That(canceled).IsTrue();
        await Assert.That(exists).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That((await client.CreateOrUpdateVaultAsync(scope, Configuration(), receipt)).Status)
            .IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task CancellationAfterCommitRetainsReceiptWithoutReplay()
    {
        var committed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        bool exists = false;
        var backend = new WireBackend(async (_, token) =>
        {
            exists = true;
            committed.SetResult();
            var canceled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var registration = token.Register(() => canceled.TrySetCanceled(token));
            await canceled.Task;
            return WireBackend.Json(201, "{}");
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Scope();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.CreateOrUpdateVault);
        using var cancellation = new CancellationTokenSource();
        var pending = client.CreateOrUpdateVaultAsync(scope, Configuration(), receipt, cancellation.Token).AsTask();
        await committed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        cancellation.Cancel();
        bool wasCanceled = false;
        try
        {
            await pending.WaitAsync(TimeSpan.FromSeconds(10));
        }
        catch (OperationCanceledException)
        {
            wasCanceled = true;
        }

        await Assert.That(wasCanceled).IsTrue();
        await Assert.That(exists).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That((await client.CreateOrUpdateVaultAsync(scope, Configuration(), receipt)).Status)
            .IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task ReceiptRejectsOtherClientScopeAndOperation()
    {
        bool exists = false;
        var backend = new WireBackend((_, _) =>
        {
            exists = true;
            return Task.FromResult(WireBackend.Json(201, ScopeAuthorityTests.VaultJson(ScopeAuthorityTests.Id)));
        });
        var client = new VaultAdministration(new Credential(), backend);
        var other = new VaultAdministration(new Credential(), backend);
        var scope = Scope();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.CreateOrUpdateVault);
        await Assert.That((await other.CreateOrUpdateVaultAsync(scope, Configuration(), receipt)).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That((await client.CreateOrUpdateVaultAsync(Scope(), Configuration(), receipt)).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That((await client.DeleteVaultAsync(scope, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(exists).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CreationAndRecoveryRetainNativeMode(bool recover)
    {
        string? mode = null;
        var backend = new WireBackend(async (request, token) =>
        {
            if (request.Method == HttpMethod.Get)
            {
                return WireBackend.Json(200, ScopeAuthorityTests.VaultJson(ScopeAuthorityTests.Id));
            }

            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            mode = body.RootElement.GetProperty("properties").GetProperty("createMode").GetString();
            return WireBackend.Json(201, ScopeAuthorityTests.VaultJson(ScopeAuthorityTests.Id));
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Scope();
        var receipt = client.PrepareReceipt(scope, recover ? ManagementMutation.RecoverVault : ManagementMutation.CreateOrUpdateVault);
        var result = recover
            ? await client.RecoverVaultAsync(scope, Configuration(), receipt)
            : await client.CreateOrUpdateVaultAsync(scope, Configuration(), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(mode).IsEqualTo(recover ? "recover" : "default");
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(await result.Value.CheckStatusAsync()).IsEqualTo(SecretStatus.Success);
    }

    [Test]
    public async Task PatchDoesNotSendOmittedSettings()
    {
        bool networkDisabled = false;
        var backend = new WireBackend(async (request, token) =>
        {
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            var properties = body.RootElement.GetProperty("properties");
            if (properties.EnumerateObject().Count() != 1 ||
                body.RootElement.EnumerateObject().Count() != 1)
            {
                throw new InvalidOperationException("Omitted setting was sent.");
            }

            networkDisabled = request.Method == HttpMethod.Patch &&
                properties.GetProperty("publicNetworkAccess").GetString() == "Disabled";
            return WireBackend.Json(200, ScopeAuthorityTests.VaultJson(ScopeAuthorityTests.Id));
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Scope();
        var result = await client.UpdateSettingsAsync(scope, new VaultSettingsPatch(publicNetworkAccess: false),
            client.PrepareReceipt(scope, ManagementMutation.UpdateVault));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(networkDisabled).IsTrue();
    }

    [Test]
    [Arguments(AccessPolicyChange.Add)]
    [Arguments(AccessPolicyChange.Replace)]
    [Arguments(AccessPolicyChange.Remove)]
    public async Task SecretOnlyPoliciesChangeActualBackendState(AccessPolicyChange change)
    {
        var permissions = new HashSet<string>();
        if (change == AccessPolicyChange.Remove)
        {
            permissions.Add("get");
        }

        var backend = new WireBackend(async (request, token) =>
        {
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            var policies = body.RootElement.GetProperty("properties").GetProperty("accessPolicies");
            var native = policies[0].GetProperty("permissions");
            if (native.TryGetProperty("keys", out var keys) && keys.GetArrayLength() != 0)
            {
                throw new InvalidOperationException("Non-secret permissions escaped.");
            }

            var selected = native.GetProperty("secrets").EnumerateArray().Select(e => e.GetString()!).ToArray();
            if (request.RequestUri!.AbsolutePath.EndsWith("/remove", StringComparison.OrdinalIgnoreCase))
            {
                permissions.ExceptWith(selected);
            }
            else
            {
                if (change == AccessPolicyChange.Replace)
                {
                    permissions.Clear();
                }

                permissions.UnionWith(selected);
            }

            return WireBackend.Json(200,
                $$$"""{"id":"{{{ScopeAuthorityTests.Id}}}","properties":{"accessPolicies":{{{policies.GetRawText()}}}}}""");
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = Scope();
        var mutation = change switch
        {
            AccessPolicyChange.Add => ManagementMutation.AddAccessPolicy,
            AccessPolicyChange.Replace => ManagementMutation.ReplaceAccessPolicy,
            _ => ManagementMutation.RemoveAccessPolicy
        };
        var policy = new SecretAccessPolicy(Guid.Parse("22222222-2222-2222-2222-222222222222"),
            Guid.Parse("33333333-3333-3333-3333-333333333333"), [SecretPermission.Get]);
        var result = await client.ChangeAccessPoliciesAsync(scope, change, [policy], client.PrepareReceipt(scope, mutation));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(permissions.Contains("get")).IsEqualTo(change != AccessPolicyChange.Remove);
        await Assert.That(JsonSerializer.Serialize(result.Value).Contains("33333333", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task CollectionStopsAtPageBudgetAndRejectsEscapingContinuation()
    {
        var scope = Scope().ResourceGroup;
        string path = ScopeAuthorityTests.Id[..ScopeAuthorityTests.Id.LastIndexOf('/')];
        var next = $"https://management.azure.com{path}?api-version=2026-02-01&$skiptoken=opaque";
        var backend = new WireBackend((request, _) =>
        {
            if (request.RequestUri!.Query.Contains("skiptoken", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Budget did not stop the next page.");
            }

            return Task.FromResult(WireBackend.Json(200,
                $$$"""{"value":[{{{ScopeAuthorityTests.VaultJson(ScopeAuthorityTests.Id)}}}],"nextLink":"{{{next}}}"}"""));
        });
        var client = new VaultAdministration(new Credential(), backend);
        var limited = await client.ListVaultsAsync(scope, new CollectionLimits(1, 10));
        await Assert.That(limited.Items.Count).IsEqualTo(1);
        await Assert.That(limited.Complete).IsFalse();
        await Assert.That(limited.Status).IsEqualTo(SecretStatus.Unsupported);
        var escaped = new WireBackend((request, _) =>
        {
            if (request.RequestUri!.Host != "management.azure.com")
            {
                throw new InvalidOperationException("Continuation escaped.");
            }

            return Task.FromResult(WireBackend.Json(200,
                $$$"""{"value":[{{{ScopeAuthorityTests.VaultJson(ScopeAuthorityTests.Id)}}}],"nextLink":"https://evil.invalid/steal?api-version=2026-02-01"}"""));
        });
        var invalid = await new VaultAdministration(new Credential(), escaped)
            .ListVaultsAsync(scope, new CollectionLimits(2, 10));
        await Assert.That(invalid.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(invalid.Complete).IsFalse();
        await Assert.That(invalid.Items.Count).IsEqualTo(0);
    }

    [Test]
    public async Task OversizedResponseCannotPublishCoordinates()
    {
        var backend = new WireBackend((_, _) => Task.FromResult(
            WireBackend.Json(200, ScopeAuthorityTests.VaultJson(ScopeAuthorityTests.Id) + new string(' ', 2048))));
        var result = await new VaultAdministration(new Credential(), backend, maximumResponseBytes: 1024).GetVaultAsync(Scope());
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task ScopeSerializationAndValidationProtectIdentifiers()
    {
        var scope = Scope();
        await Assert.That(JsonSerializer.Serialize(scope)).IsEqualTo("{}");
        await Assert.That(scope.ToString()).IsEqualTo("[SecretAddress]");
        await Assert.That(scope.ExportResourceId()).IsEqualTo(ScopeAuthorityTests.Id);
        bool rejected = false;
        try
        {
            _ = new VaultScope(scope.ResourceGroup, "bad/name-canary");
        }
        catch (ArgumentException exception)
        {
            rejected = !exception.ToString().Contains("name-canary", StringComparison.Ordinal);
        }

        await Assert.That(rejected).IsTrue();
    }
}
