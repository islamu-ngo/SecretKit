using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Secrets;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultPolicyPermissionTrial;
using M = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureVaultPolicyWitnessCompositionTests
{
    private const string Version = "0123456789abcdef0123456789abcdef";
    private const string Material = "owned-policy-canary";
    private static readonly DateTimeOffset Now = new(2026, 10, 16, 0, 0, 0, TimeSpan.Zero);
    private static string Digest => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Material)));

    [Test]
    [Arguments("all")]
    [Arguments("remove")]
    [Arguments("read-only")]
    public async Task SixteenActualObservationsOnOneOwnedVaultSatisfyUnchangedEffectValidation(string policy)
    {
        await using var f = new Fixture(policy);
        var window = f.Source.Arm(f.Manifest);
        var result = await f.Source.CollectAsync(window, f.Binding);
        await Assert.That(result.Observations.Count).IsEqualTo(16);
        await Assert.That(result.Observations.All(o => o.Attempted && o.RemoteSettled)).IsTrue();
        await Assert.That(f.Journal.Read(f.Owner, f.Binding.Selector).Resources.Length).IsEqualTo(14);
        await Assert.That(f.Journal.Read(f.Owner, f.Binding.Selector).Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsTrue();
        await Assert.That(f.Requests.Count(r => r.Channel == "intended")).IsEqualTo(8);
        await Assert.That(f.Requests.Count(r => r.Channel == "denied")).IsEqualTo(8);
        await Assert.That(f.Requests.Count(r => r.Channel == "observer"))
            .IsEqualTo(policy == "all" ? 2 : 0);
        await Assert.That(f.Requests.All(r => r.Uri.StartsWith(f.Origin + "/", StringComparison.Ordinal))).IsTrue();
        await Assert.That(result.PrincipalQualified || result.EgressQualified).IsFalse();
        var effects = VaultAdministrationEffects.ComposePolicyEffects(f.Source, window, f.Binding, f.Claim, result);
        await Assert.That(effects.Length).IsEqualTo(8);
        var requested = new VaultAdministrationEffects.Policy(f.Claim.TenantId, f.Claim.PrincipalId,
            f.Grants.ToArray(), null);
        var baseline = new VaultAdministrationEffects.Configuration("eastus", f.Claim.TenantId,
            VaultSku.Standard, false, false, 7, true, policy == "remove" ? [requested] : []);
        var lease = new VaultAdministrationEffects.Lease(
            new(f.Binding.Selector.Nonce, f.Binding.LeaseId, "source", "https://management.azure.com",
                "2026-02-01", Now, [f.VaultId]), f.Binding.VaultName, null, "canary", Digest, baseline,
            PrivateConnectionState.Unknown);
        var measured = new VaultAdministrationEffects.Measurement(f.Binding.LeaseId, f.Binding.Selector.Nonce,
            "source", Now, f.VaultId, SecretStatus.Success, SecretStatus.Absent, baseline,
            policy == "remove" ? [] : [requested], PrivateConnectionState.Unknown, SecretStatus.Absent,
            effects, null, [], [], [], [], null);
        VaultAdministrationEffects.ValidateEffect("ChangeAccessPoliciesAsync", f.Binding.Selector.Variant,
            baseline, lease, measured, [requested],
            policy == "remove" ? AccessPolicyChange.Remove : AccessPolicyChange.Add, unchanged: false);
        await Assert.That(f.Credentials.Where(c => c.Calls > 0).All(c => c.Scope == C.Audience && c.Tenant is null)).IsTrue();
    }

    [Test]
    [Arguments(403)]
    [Arguments(404)]
    [Arguments(202)]
    public async Task MissingObserverProofRetainsItsExactFenceAndStopsLaterMutations(int status)
    {
        await using var f = new Fixture("all");
        f.ObserverStatus = status;
        var window = f.Source.Arm(f.Manifest);
        var result = await f.Source.CollectAsync(window, f.Binding);
        var deletion = result.Observations.Single(o => o.Permission == SecretPermission.Delete && !o.DeniedAuthority);
        await Assert.That(deletion.Accepted).IsTrue();
        await Assert.That(deletion.RemoteSettled).IsFalse();
        await Assert.That(deletion.SettlementFailure == C.Failure.None).IsFalse();
        await Assert.That(result.Observations.Where(o => o.Permission is SecretPermission.Recover or
            SecretPermission.Restore or SecretPermission.Purge).All(o => !o.Attempted)).IsTrue();
        var retained = f.Journal.Read(f.Owner, f.Binding.Selector).Resources.Single(r => r.ActiveDispatch != Guid.Empty);
        await Assert.That(retained.Id).IsEqualTo(f.Resource("delete-intended"));
        await Assert.That(retained.InvocationTerminated).IsTrue();
        await Assert.That(() => VaultAdministrationEffects.ComposePolicyEffects(f.Source, window,
            f.Binding, f.Claim, result)).Throws<Exception>();
        await Assert.That(f.Journal.Close(f.Owner, f.Binding.Selector).Released).IsFalse();
    }

    [Test]
    public async Task WarmChallengeStillSwitchesTheActualObserverWireAuthority()
    {
        await using var f = new Fixture("all");
        using var warm = new HttpClient(new WarmHandler(f.Origin));
        var native = new SecretClient(new Uri(f.Origin), new Credential("warm", f),
            new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01)
            { Transport = new HttpClientTransport(warm) });
        await native.GetSecretAsync("shared-read", Version);
        var result = await f.Source.CollectAsync(f.Source.Arm(f.Manifest), f.Binding);
        await Assert.That(result.Observations.All(o => o.RemoteSettled)).IsTrue();
        await Assert.That(f.Requests.Count(r => r.Channel == "observer")).IsEqualTo(2);
        await Assert.That(f.Credentials.Single(c => c.Channel == "observer").Calls).IsEqualTo(2);
        await Assert.That(f.Credentials.Where(c => c.Calls > 0).All(c => c.Tenant is null)).IsTrue();
    }

    [Test]
    public async Task SuccessfulDeniedLroSettlesUnderObserverWithoutInventingDenial()
    {
        await using var f = new Fixture("all");
        f.DeniedLroSucceeds = true;
        var window = f.Source.Arm(f.Manifest);
        var result = await f.Source.CollectAsync(window, f.Binding);
        foreach (var permission in new[] { SecretPermission.Delete, SecretPermission.Recover })
        {
            var observed = result.Observations.Single(o => o.Permission == permission && o.DeniedAuthority);
            await Assert.That(observed.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(observed.Accepted && observed.RemoteSettled).IsTrue();
            await Assert.That(observed.SettlementRequestId).IsNotNull();
        }
        await Assert.That(f.Requests.Count(r => r.Channel == "observer")).IsEqualTo(4);
        var effects = f.Source.ComposePolicyEffects(window, f.Binding, f.Claim, result);
        await Assert.That(effects.Where(e => e.Permission is SecretPermission.Delete or SecretPermission.Recover)
            .All(e => e.DeniedStatus == SecretStatus.Success)).IsTrue();
    }

    [Test]
    public async Task CloseDuringObserverCredentialAcquisitionPreventsTheStatusSend()
    {
        await using var f = new Fixture("all");
        f.ObserverBeforeReturn = () => f.Journal.Close(f.Owner, f.Binding.Selector);
        var result = await f.Source.CollectAsync(f.Source.Arm(f.Manifest), f.Binding);
        await Assert.That(f.Requests.Count(r => r.Channel == "observer")).IsEqualTo(0);
        await Assert.That(result.Observations.Single(o => o.Permission == SecretPermission.Delete &&
            !o.DeniedAuthority).RemoteSettled).IsFalse();
        await Assert.That(f.Journal.Read(f.Owner, f.Binding.Selector).Released).IsFalse();
    }

    [Test]
    [Arguments("foreign-id")]
    [Arguments("foreign-version")]
    public async Task ForeignStatusProofNeverSettlesOrBecomesReplayAuthority(string fault)
    {
        await using var f = new Fixture("all");
        f.ObserverFault = fault;
        var result = await f.Source.CollectAsync(f.Source.Arm(f.Manifest), f.Binding);
        await Assert.That(result.Observations.Single(o => o.Permission == SecretPermission.Delete &&
            !o.DeniedAuthority).RemoteSettled).IsFalse();
        var before = f.Requests.Count;
        await using var restarted = f.Reopen();
        var retried = await restarted.CollectAsync(restarted.Arm(f.Manifest), f.Binding);
        await Assert.That(retried.Observations.All(o => !o.Attempted && o.Status == SecretStatus.Unavailable)).IsTrue();
        await Assert.That(f.Requests.Count).IsEqualTo(before);
        await Assert.That(f.Journal.Read(f.Owner, f.Binding.Selector).Resources.Single(r =>
            r.ActiveDispatch != Guid.Empty).InvocationTerminated).IsTrue();
    }

    [Test]
    public async Task SealedProjectionRejectsForgedMeasurementDifferentPrincipalAndBinding()
    {
        await using var f = new Fixture("all");
        var window = f.Source.Arm(f.Manifest);
        var result = await f.Source.CollectAsync(window, f.Binding);
        var copied = new C.Measurement
        {
            Binding = result.Binding,
            IntendedPrincipal = result.IntendedPrincipal,
            WindowId = result.WindowId,
            ArmedAt = result.ArmedAt,
            FinishedAt = result.FinishedAt,
            Observations = result.Observations
        };
        await Assert.That(() => f.Source.ComposePolicyEffects(window, f.Binding, f.Claim, copied)).Throws<Exception>();
        await Assert.That(() => f.Source.ComposePolicyEffects(window, f.Binding,
            f.Claim with { PrincipalId = Guid.NewGuid() }, result)).Throws<Exception>();
        await Assert.That(() => f.Source.ComposePolicyEffects(window,
            f.Binding with { LeaseId = Guid.NewGuid() }, f.Claim, result)).Throws<Exception>();
        await Assert.That(f.Source.ComposePolicyEffects(window, f.Binding, f.Claim, result).Length).IsEqualTo(8);
    }

    [Test]
    public async Task TwentyTwoDeclaredNamesAcceptAnotherSourcesNativeActivatedInventory()
    {
        await using var f = new Fixture("all", inventory: "owned");
        await using var first = f.Reopen();
        using var material = SecretMaterial.FromText(Material);
        var firstManifest = f.Manifest with
        {
            Fixtures = [new(SecretPermission.Set, false, "other-0", null, C.PreparedState.Absent, Digest, material, null)],
            InventoryOnly = []
        };
        var firstWindow = first.Arm(firstManifest);
        var secondWindow = f.Source.Arm(f.Manifest);
        await Assert.That(f.Manifest.Fixtures.Length).IsEqualTo(16);
        await Assert.That(f.Manifest.Fixtures.Select(e => e.Name).Distinct().Count()).IsEqualTo(11);
        await Assert.That(f.Manifest.InventoryOnly!.Length).IsEqualTo(11);
        await Assert.That(f.Journal.Read(f.Owner, f.Binding.Selector).Resources.Length).IsEqualTo(24);
        await Assert.That(f.Active.Contains("other-0")).IsFalse();
        var activated = await first.CollectAsync(firstWindow, f.Binding);
        var set = activated.Observations.Single(o => o.Permission == SecretPermission.Set && !o.DeniedAuthority);
        await Assert.That(set.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(set.Attempted && set.RemoteSettled).IsTrue();
        await Assert.That(f.Active.Contains("other-0")).IsTrue();
        var state = f.Journal.Read(f.Owner, f.Binding.Selector);
        await Assert.That(state.Resources.Single(r => r.Id == f.Resource("other-0")).SelectedAttempted).IsTrue();
        var result = await f.Source.CollectAsync(secondWindow, f.Binding);
        await Assert.That(result.Observations.Count).IsEqualTo(16);
        await Assert.That(result.Observations.All(o => o.Attempted && o.RemoteSettled && o.Failure == C.Failure.None)).IsTrue();
        await Assert.That(result.Observations.Where(o => o.Permission == SecretPermission.List)
            .Single(o => !o.DeniedAuthority).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.ComposePolicyEffects(secondWindow, f.Binding, f.Claim, result).Length).IsEqualTo(8);
        await Assert.That(f.Requests.Count(r => r.Method == "PUT" && r.Uri.Contains("/secrets/other-0?", StringComparison.Ordinal)))
            .IsEqualTo(1);
        await Assert.That(f.Journal.Read(f.Owner, f.Binding.Selector).Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsTrue();
    }

    [Test]
    [Arguments("foreign")]
    [Arguments("unowned")]
    [Arguments("borrowed")]
    public async Task ExpandedInventoryCannotAdoptForeignUnownedOrBorrowedCoordinates(string inventory)
    {
        await using var f = new Fixture("all", inventory);
        var result = await f.Source.CollectAsync(f.Source.Arm(f.Manifest), f.Binding);
        await Assert.That(result.Observations.Count).IsEqualTo(16);
        await Assert.That(result.Observations.All(o => !o.Attempted && o.Status == SecretStatus.Unavailable)).IsTrue();
        await Assert.That(f.Requests.Count).IsEqualTo(0);
        await Assert.That(f.Credentials.All(c => c.Calls == 0)).IsTrue();
    }

    [Test]
    public async Task TwentyThreeDistinctFixtureAndInventoryNamesAreRejectedBeforeDispatch()
    {
        await using var f = new Fixture("all", inventory: "owned");
        var oversized = f.Manifest with { InventoryOnly = [.. f.Manifest.InventoryOnly!, "other-10"] };
        await Assert.That(() => f.Source.Arm(oversized)).Throws<ArgumentException>();
        await Assert.That(f.Requests.Count).IsEqualTo(0);
        await Assert.That(f.Credentials.All(c => c.Calls == 0)).IsTrue();
        await Assert.That(f.Journal.Read(f.Owner, f.Binding.Selector).Resources.Length).IsEqualTo(24);
    }

    [Test]
    [Arguments("mutation-alias")]
    [Arguments("inconsistent-read")]
    [Arguments("undeclared-list")]
    public async Task SharedReadInventoryCannotAdoptMutatingOrUndeclaredCoordinates(string fault)
    {
        await using var f = new Fixture("all");
        if (fault == "undeclared-list")
        {
            f.Active.Add("foreign-secret");
            var result = await f.Source.CollectAsync(f.Source.Arm(f.Manifest), f.Binding);
            await Assert.That(result.Observations.Where(o => o.Permission == SecretPermission.List)
                .All(o => o.Status == SecretStatus.Unavailable || o.Status == SecretStatus.Denied)).IsTrue();
            return;
        }
        var entries = f.Manifest.Fixtures.ToArray();
        int index = Array.FindIndex(entries, e => e.Permission == (fault == "mutation-alias" ? SecretPermission.Set : SecretPermission.Backup));
        entries[index] = entries[index] with
        {
            Name = "shared-read",
            Sha256 = fault == "inconsistent-read" ? new string('A', 64) : entries[index].Sha256
        };
        await Assert.That(() => f.Source.Arm(f.Manifest with { Fixtures = entries })).Throws<ArgumentException>();
    }

    [Test]
    public async Task StatusBodyCancellationRetainsTheBorrowerAndFenceUntilActualExit()
    {
        await using var f = new Fixture("all");
        f.BlockObserverBody = true;
        using var cancellation = new CancellationTokenSource();
        var pending = f.Source.CollectAsync(f.Source.Arm(f.Manifest), f.Binding, cancellation.Token).AsTask();
        try
        {
            await f.StatusBodyEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            cancellation.Cancel();
            f.Journal.Close(f.Owner, f.Binding.Selector);
            var state = f.Journal.Read(f.Owner, f.Binding.Selector);
            await Assert.That(state.Resources.Single(r => r.ActiveDispatch != Guid.Empty).InvocationTerminated).IsFalse();
            await Assert.That(f.StatusStorage!.Any(b => b != 0)).IsTrue();
            f.StatusBodyRelease.TrySetResult();
            await Assert.That(async () => await pending).Throws<OperationCanceledException>();
            await Assert.That(f.StorageLiveAtExit).IsTrue();
            await Assert.That(f.StatusStorage!.All(b => b == 0)).IsTrue();
            var retained = f.Journal.Read(f.Owner, f.Binding.Selector);
            await Assert.That(retained.Released).IsFalse();
            await Assert.That(retained.Resources.Single(r => r.ActiveDispatch != Guid.Empty).InvocationTerminated).IsTrue();
        }
        finally
        {
            f.StatusBodyRelease.TrySetResult();
            try { await pending; } catch (OperationCanceledException) { }
        }
    }

    private sealed record RequestRow(string Channel, string Uri, string Method);

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "policy-composition-" + Guid.NewGuid().ToString("N"));
        internal readonly string Owner = "composition-owner";
        internal readonly C.PrincipalClaim Claim = new(Guid.NewGuid(), Guid.NewGuid(), null);
        internal readonly RoleFixtureJournal Journal;
        internal readonly C Source;
        internal readonly M.Binding Binding;
        internal readonly C.Manifest Manifest;
        internal readonly HashSet<SecretPermission> Grants;
        internal readonly HashSet<string> Active = new(StringComparer.Ordinal) { "shared-read", "canary", "delete-intended", "delete-denied" };
        private readonly HashSet<string> deleted = new(StringComparer.Ordinal) { "recover-intended", "recover-denied", "purge-intended", "purge-denied" };
        internal readonly List<RequestRow> Requests = [];
        internal readonly List<Credential> Credentials = [];
        private readonly List<HttpClient> clients = [];
        internal readonly TaskCompletionSource StatusBodyEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource StatusBodyRelease = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool BlockObserverBody, StorageLiveAtExit, DeniedLroSucceeds;
        internal byte[]? StatusStorage;
        internal int ObserverStatus = 200;
        internal string? ObserverFault;
        internal Action? ObserverBeforeReturn;
        internal string Origin => "https://" + Binding.VaultName + ".vault.azure.net";
        internal string VaultId => $"/subscriptions/{Binding.SubscriptionId:D}/resourceGroups/owned/providers/Microsoft.KeyVault/vaults/{Binding.VaultName}";
        internal string Resource(string name) => VaultId + "/secrets/" + name;

        internal Fixture(string policy, string? inventory = null)
        {
            Directory.CreateDirectory(directory);
            Journal = new(directory);
            Grants = policy == "all" ? Enum.GetValues<SecretPermission>().ToHashSet() :
                policy == "read-only" ? [SecretPermission.Get, SecretPermission.List, SecretPermission.Backup] : [];
            var selector = new FixtureSelector(Guid.NewGuid(), "original-policy-scope",
                M.Operation(M.QueryKind.ChangeAccessPolicies), policy == "remove" ? "change.Remove" : "change.Add", "independent-effect");
            var original = new M.Binding(selector, Guid.Empty, M.QueryKind.ChangeAccessPolicies, M.ReadKind.GetVault,
                Guid.NewGuid(), "owned", "eastus", "p" + Guid.NewGuid().ToString("N")[..20], null);
            var entries = new List<C.PreparedFixture>();
            foreach (var permission in Enum.GetValues<SecretPermission>())
                foreach (bool denied in new[] { true, false })
                {
                    bool read = permission is SecretPermission.Get or SecretPermission.List or SecretPermission.Backup;
                    string name = read ? "shared-read" : permission.ToString().ToLowerInvariant() + (denied ? "-denied" : "-intended");
                    entries.Add(new(permission, denied, name, permission == SecretPermission.Set ? null : Version,
                        read || permission == SecretPermission.Delete ? C.PreparedState.Active :
                        permission is SecretPermission.Recover or SecretPermission.Purge ? C.PreparedState.Deleted : C.PreparedState.Absent,
                        Digest, permission == SecretPermission.Set ? SecretMaterial.FromText(Material) : null,
                        permission == SecretPermission.Restore ? AzureSecretBackup.FromBytes([denied ? (byte)1 : (byte)2, 42]) : null));
                }
            string vaultId = $"/subscriptions/{original.SubscriptionId:D}/resourceGroups/owned/providers/Microsoft.KeyVault/vaults/{original.VaultName}";
            var resources = new List<RoleFixtureJournal.Resource>
            {
                new(vaultId, false),
                new($"/subscriptions/{original.SubscriptionId:D}/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/{original.VaultName}", false, CleanupOnly: true),
                new(vaultId + "/secrets/canary", false)
            };
            resources.AddRange(entries.Select(e => e.Name).Distinct(StringComparer.Ordinal).Select(name =>
                new RoleFixtureJournal.Resource(vaultId + "/secrets/" + name, false)));
            string[] inventoryOnly = inventory is null ? ["canary"] :
                ["canary", .. Enumerable.Range(0, 10).Select(i => "other-" + i)];
            if (inventory is not null)
            {
                foreach (string name in inventoryOnly.Skip(1))
                {
                    if (name == "other-0" && inventory == "unowned") continue;
                    string id = name == "other-0" && inventory == "foreign"
                        ? vaultId + "-foreign/secrets/" + name : vaultId + "/secrets/" + name;
                    resources.Add(new(id, name == "other-0" && inventory == "borrowed"));
                    if (name != "other-0") Active.Add(name);
                }
            }
            var prepared = Journal.Prepare(Owner, selector, resources.ToArray());
            foreach (var resource in resources.Where(r => !r.CleanupOnly && !r.Borrowed))
            {
                Guid dispatch = Journal.BeginDispatch(Owner, selector, resource.Id, delete: false);
                Journal.EndDispatch(Owner, selector, resource.Id, dispatch);
            }
            Binding = original with { LeaseId = prepared.LeaseId };
            Manifest = new(Owner, Binding, C.Revision, entries.ToArray(), inventoryOnly);
            Source = Reopen();
        }

        internal C Reopen() => new(Journal, Claim, Authority("intended"), Authority("denied"),
            new(16384, 4096, 4096, 2048, 64, 12, TimeSpan.FromSeconds(20)), new Clock(), Authority("observer"));

        private C.Authority Authority(string channel)
        {
            var credential = new Credential(channel, this);
            Credentials.Add(credential);
            var client = new HttpClient(new Handler(this, channel));
            clients.Add(client);
            return new(channel, credential, new HttpClientTransport(client));
        }

        internal async Task<HttpResponseMessage> Send(string channel, HttpRequestMessage request, CancellationToken token)
        {
            Requests.Add(new(channel, request.RequestUri!.AbsoluteUri, request.Method.Method));
            if (request.Headers.Authorization?.ToString() != "Bearer " + channel)
                throw new InvalidOperationException("test-wrong-authority");
            string[] path = request.RequestUri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            string? name = path.Length > 1 ? path[1] : null;
            bool status = channel == "observer";
            SecretPermission permission = request.Method == HttpMethod.Get
                ? name is null ? SecretPermission.List : SecretPermission.Get
                : path[0] == "deletedsecrets"
                    ? request.Method == HttpMethod.Delete ? SecretPermission.Purge : SecretPermission.Recover
                    : request.Method == HttpMethod.Put ? SecretPermission.Set
                    : request.Method == HttpMethod.Delete ? SecretPermission.Delete
                    : name == "restore" ? SecretPermission.Restore : SecretPermission.Backup;
            if (status && (request.Method != HttpMethod.Get ||
                name is not ("delete-intended" or "recover-intended" or "delete-denied" or "recover-denied")))
                throw new InvalidOperationException("test-unbound-status");
            if (status && ObserverStatus != 200) return Reply(ObserverStatus, Error(ObserverStatus));
            if (!status && (channel == "denied" && !(DeniedLroSucceeds &&
                permission is SecretPermission.Delete or SecretPermission.Recover) || !Grants.Contains(permission)))
                return Reply(403, Error(403));
            if (permission == SecretPermission.List)
                return Reply(200, JsonSerializer.Serialize(new
                {
                    value = Active.OrderBy(n => n, StringComparer.Ordinal).Select(n => new
                    {
                        id = Origin + "/secrets/" + n,
                        attributes = new { enabled = true }
                    }).ToArray()
                }));
            if (permission == SecretPermission.Backup)
                return Reply(200, """{"value":"AQIq"}""");
            if (permission == SecretPermission.Set || permission == SecretPermission.Restore)
            {
                using var document = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                string value = document.RootElement.GetProperty("value").GetString()!;
                if (permission == SecretPermission.Restore)
                {
                    byte[] backup = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
                    name = backup[0] == 1 ? "restore-denied" : "restore-intended";
                }
                else if (value != Material) throw new InvalidOperationException("test-wrong-write-material");
                if (!Active.Add(name!)) throw new InvalidOperationException("test-mutation-replay");
            }
            if (!status && permission == SecretPermission.Delete)
            {
                if (!Active.Remove(name!) || !deleted.Add(name!)) throw new InvalidOperationException("test-delete-state");
            }
            if (!status && permission == SecretPermission.Recover)
            {
                if (!deleted.Remove(name!) || !Active.Add(name!)) throw new InvalidOperationException("test-recover-state");
            }
            if (permission == SecretPermission.Purge)
            {
                if (!deleted.Remove(name!)) throw new InvalidOperationException("test-purge-state");
                return Reply(204, "");
            }
            bool deletedResponse = path[0] == "deletedsecrets" &&
                (status || permission == SecretPermission.Delete) || !status && permission == SecretPermission.Delete;
            string body = deletedResponse
                ? JsonSerializer.Serialize(new
                {
                    id = Origin + "/secrets/" + name + "/" + Version,
                    recoveryId = Origin + "/deletedsecrets/" + name,
                    attributes = new { enabled = true }
                })
                : JsonSerializer.Serialize(new
                {
                    id = Origin + "/secrets/" + name + "/" + Version,
                    value = Material,
                    attributes = new { enabled = true }
                });
            if (status && ObserverFault == "foreign-id")
                body = body.Replace("/secrets/" + name + "/", "/secrets/foreign/", StringComparison.Ordinal);
            if (status && ObserverFault == "foreign-version")
                body = body.Replace(Version, new string('f', 32), StringComparison.Ordinal);
            var response = Reply(200, body);
            if (status && BlockObserverBody)
            {
                response.Content = new StreamContent(new BlockedBody(Encoding.UTF8.GetBytes(body), this));
                response.Content.Headers.ContentType = new("application/json");
            }
            return response;
        }

        private static string Error(int status) => JsonSerializer.Serialize(new
        {
            error = new { code = status == 404 ? "SecretNotFound" : "Forbidden", message = "controlled failure" }
        });

        private static HttpResponseMessage Reply(int status, string body)
        {
            var response = new HttpResponseMessage((HttpStatusCode)status) { Content = new StringContent(body) };
            response.Content.Headers.ContentType = new("application/json");
            response.Headers.TryAddWithoutValidation("x-ms-request-id", Guid.NewGuid().ToString("N"));
            return response;
        }

        public async ValueTask DisposeAsync()
        {
            StatusBodyRelease.TrySetResult();
            await Source.DisposeAsync();
            foreach (var client in clients) client.Dispose();
            foreach (var entry in Manifest.Fixtures) { entry.OwnedSet?.Dispose(); entry.Backup?.Dispose(); }
            Directory.Delete(directory, recursive: true);
        }
    }

    private sealed class Credential(string channel, Fixture fixture) : TokenCredential
    {
        internal string Channel => channel;
        internal int Calls;
        internal string? Scope, Tenant;
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("test-async-only");
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            Calls++;
            Scope = requestContext.Scopes.Single();
            Tenant = requestContext.TenantId;
            if (channel == "observer") fixture.ObserverBeforeReturn?.Invoke();
            return ValueTask.FromResult(new AccessToken(channel, DateTimeOffset.MaxValue));
        }
    }

    private sealed class Handler(Fixture fixture, string channel) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            fixture.Send(channel, request, cancellationToken);
    }

    private sealed class WarmHandler(string origin) : HttpMessageHandler
    {
        private int sends;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref sends) == 1)
            {
                var challenge = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                challenge.Headers.TryAddWithoutValidation("WWW-Authenticate",
                    "Bearer authorization=\"https://login.windows.net/11111111-1111-1111-1111-111111111111\", resource=\"https://vault.azure.net\"");
                return Task.FromResult(challenge);
            }
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new
                {
                    id = origin + "/secrets/shared-read/" + Version,
                    value = Material,
                    attributes = new { enabled = true }
                }))
            };
            response.Content.Headers.ContentType = new("application/json");
            return Task.FromResult(response);
        }
    }

    private sealed class BlockedBody(byte[] bytes, Fixture fixture) : Stream
    {
        private readonly MemoryStream inner = new(bytes, false);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new InvalidOperationException("test-async-only");
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var array)) fixture.StatusStorage = array.Array;
            buffer.Span.Fill(0x5a);
            fixture.StatusBodyEntered.TrySetResult();
            await fixture.StatusBodyRelease.Task.ConfigureAwait(false);
            fixture.StorageLiveAtExit = fixture.StatusStorage!.Any(b => b != 0);
            cancellationToken.ThrowIfCancellationRequested();
            return await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
    }

    private sealed class Clock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
        public override long GetTimestamp() => 0;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    }
}
