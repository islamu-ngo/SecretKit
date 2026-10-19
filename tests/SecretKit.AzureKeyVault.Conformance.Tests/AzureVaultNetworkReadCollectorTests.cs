using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Secrets;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultNetworkReadCollector;
using M = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureVaultNetworkReadCollectorTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private const string Origin = "https://network-vault.vault.azure.net";
    private const string Version = "0123456789abcdef0123456789abcdef";
    private const string Material = "local-protected-canary";
    private static string Digest => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Material)));
    private static string Id => Origin + "/secrets/canary/" + Version;

    private static C.Binding Binding(M.QueryKind query = M.QueryKind.GetPrivateConnection)
    {
        var member = VaultAdministrationEffects.Members.Single(m => m.Operation == M.Operation(query));
        return new(new(new(Guid.NewGuid(), "controlled", member.Operation, member.Variants[0], "independent-effect"),
            Guid.NewGuid(), query, M.DefaultRead(query), Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "network-group", "eastus", "network-vault", "original-connection"), "canary", Version, Digest, C.Revision);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    public async Task EveryOriginalMemberAndVariantKeepsTheSameRuntimeBinding(int memberIndex)
    {
        M.QueryKind[] queries =
        [
            M.QueryKind.GetPrivateConnection, M.QueryKind.UpdatePrivateConnection, M.QueryKind.DeletePrivateConnection,
            M.QueryKind.ListPrivateConnections, M.QueryKind.ListPrivateLinkResources
        ];
        var query = queries[memberIndex];
        var member = VaultAdministrationEffects.Members.Single(m => m.Operation == M.Operation(query));
        foreach (string variant in member.Variants)
        {
            using var f = new Fixture();
            var binding = Binding(query);
            binding = binding with { Original = binding.Original with { Selector = binding.Original.Selector with { Variant = variant } } };
            var result = await f.Collect(binding);
            await Assert.That(result.Binding).IsEqualTo(binding);
            await Assert.That(result.PrivateRead.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(result.PublicRead.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(result.PrivateRead.CanarySha256).IsEqualTo(Digest);
            await Assert.That(result.PublicRead.CanarySha256).IsEqualTo(Digest);
            await Assert.That(result.PrivateRead.NativeRequestIds.Single()).IsEqualTo("private-request");
            await Assert.That(result.PublicRead.NativeRequestIds.Single()).IsEqualTo("public-request");
            await Assert.That(result.PrivateRead.Identity).IsEqualTo("private-declaration");
            await Assert.That(result.PublicRead.Identity).IsEqualTo("public-declaration");
            await Assert.That(result.ApiRevision).IsEqualTo("2025-07-01");
            await Assert.That(result.ArmedAt).IsEqualTo(Now);
            await Assert.That(result.StartedAt).IsEqualTo(Now);
            await Assert.That(result.FinishedAt).IsEqualTo(Now);
            await Assert.That(result.PrincipalQualified).IsFalse();
            await Assert.That(result.EgressQualified).IsFalse();
            foreach (var backend in new[] { f.Private, f.Public })
            {
                await Assert.That(backend.Requests.Single().Uri).IsEqualTo(Id + "?api-version=2025-07-01");
                await Assert.That(backend.Requests.Single().Method).IsEqualTo(HttpMethod.Get);
                await Assert.That(backend.Requests.Single().Authorization).IsEqualTo("Bearer " + backend.Token);
            }
            await Assert.That(f.PrivateCredential.Scopes.Single()).IsEqualTo(C.Audience);
            await Assert.That(f.PublicCredential.Scopes.Single()).IsEqualTo(C.Audience);
        }
    }

    [Test]
    [Arguments(200, 403)]
    [Arguments(403, 200)]
    [Arguments(404, 403)]
    [Arguments(403, 404)]
    [Arguments(404, 404)]
    public async Task BothChannelsReportActualIndependentStatusRegardlessOfSelectedConnectionState(int privateStatus, int publicStatus)
    {
        foreach (PrivateConnectionState ignoredSelectedState in Enum.GetValues<PrivateConnectionState>())
        {
            // Selected state deliberately never enters this source's API.
            _ = ignoredSelectedState;
            using var f = new Fixture();
            f.Private.Status = privateStatus;
            f.Public.Status = publicStatus;
            var result = await f.Collect(Binding());
            await Check(result.PrivateRead, privateStatus, "private-request");
            await Check(result.PublicRead, publicStatus, "public-request");
        }

        static async Task Check(C.Read read, int status, string request)
        {
            await Assert.That(read.Status).IsEqualTo(status == 200 ? SecretStatus.Success :
                status == 403 ? SecretStatus.Denied : SecretStatus.Absent);
            await Assert.That(read.CanarySha256).IsEqualTo(status == 200 ? Digest : null);
            await Assert.That(read.NativeRequestIds.Single()).IsEqualTo(request);
            await Assert.That(read.Failure).IsEqualTo(C.Failure.None);
        }
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("lease")]
    [Arguments("scope")]
    [Arguments("operation")]
    [Arguments("variant")]
    [Arguments("case")]
    [Arguments("query")]
    [Arguments("read")]
    [Arguments("subscription")]
    [Arguments("group")]
    [Arguments("location")]
    [Arguments("vault")]
    [Arguments("connection")]
    [Arguments("name")]
    [Arguments("version")]
    [Arguments("hash")]
    [Arguments("revision")]
    public async Task FullOriginalBindingCannotBeSubstitutedAtCollection(string field)
    {
        using var f = new Fixture();
        var b = Binding();
        var window = f.Source.Arm(b);
        var o = b.Original;
        var changed = field switch
        {
            "nonce" => b with { Original = o with { Selector = o.Selector with { Nonce = Guid.NewGuid() } } },
            "lease" => b with { Original = o with { LeaseId = Guid.NewGuid() } },
            "scope" => b with { Original = o with { Selector = o.Selector with { Scope = "other" } } },
            "operation" => b with { Original = o with { Selector = o.Selector with { Operation = "other" } } },
            "variant" => b with { Original = o with { Selector = o.Selector with { Variant = "state.Rejected" } } },
            "case" => b with { Original = o with { Selector = o.Selector with { Case = "selected-contract" } } },
            "query" => b with { Original = o with { Query = M.QueryKind.UpdatePrivateConnection } },
            "read" => b with { Original = o with { Read = M.ReadKind.GetVault } },
            "subscription" => b with { Original = o with { SubscriptionId = Guid.NewGuid() } },
            "group" => b with { Original = o with { ResourceGroup = "other" } },
            "location" => b with { Original = o with { Location = "westus" } },
            "vault" => b with { Original = o with { VaultName = "other-vault" } },
            "connection" => b with { Original = o with { ConnectionName = "other" } },
            "name" => b with { CanaryName = "other" },
            "version" => b with { CanaryVersion = new string('a', 32) },
            "hash" => b with { CanarySha256 = new string('A', 64) },
            _ => b with { ApiRevision = "other" }
        };
        await Assert.That(async () => await f.Source.CollectAsync(window, changed)).Throws<InvalidOperationException>();
        await Assert.That(f.Private.Requests.Count + f.Public.Requests.Count).IsEqualTo(0);
        await Assert.That((await f.Source.CollectAsync(window, b)).PrivateRead.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(async () => await f.Source.CollectAsync(window, b)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("query")]
    [Arguments("read")]
    [Arguments("variant")]
    [Arguments("case")]
    [Arguments("nonce")]
    [Arguments("lease")]
    [Arguments("subscription")]
    [Arguments("group")]
    [Arguments("vault")]
    [Arguments("connection")]
    [Arguments("revision")]
    [Arguments("name")]
    [Arguments("version")]
    [Arguments("hash")]
    public async Task InvalidBindingsFailBeforeCredentialOrEgress(string field)
    {
        using var f = new Fixture();
        var b = Binding();
        var o = b.Original;
        b = field switch
        {
            "query" => b with { Original = o with { Query = M.QueryKind.GetVault } },
            "read" => b with { Original = o with { Read = M.ReadKind.GetVault } },
            "variant" => b with { Original = o with { Selector = o.Selector with { Variant = "future" } } },
            "case" => b with { Original = o with { Selector = o.Selector with { Case = "future" } } },
            "nonce" => b with { Original = o with { Selector = o.Selector with { Nonce = Guid.Empty } } },
            "lease" => b with { Original = o with { LeaseId = Guid.Empty } },
            "subscription" => b with { Original = o with { SubscriptionId = Guid.Empty } },
            "group" => b with { Original = o with { ResourceGroup = "../other" } },
            "vault" => b with { Original = o with { VaultName = "foreign.invalid/path" } },
            "connection" => b with { Original = o with { ConnectionName = null } },
            "revision" => b with { ApiRevision = "2024-01-01" },
            "name" => b with { CanaryName = "../other" },
            "version" => b with { CanaryVersion = "latest" },
            _ => b with { CanarySha256 = "unknown" }
        };
        await Assert.That(() => f.Source.Arm(b)).Throws<ArgumentException>();
        await Assert.That(f.PrivateCredential.Calls + f.PublicCredential.Calls).IsEqualTo(0);
        await Assert.That(f.Private.Requests.Count + f.Public.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task ForeignForgedReplayAndConcurrentWindowsCannotAcquireSourceOwnership()
    {
        using var f = new Fixture();
        using var other = new Fixture();
        var b = Binding();
        var window = f.Source.Arm(b);
        await Assert.That(async () => await f.Source.CollectAsync(other.Source.Arm(b), b)).Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Source.CollectAsync(C.Window.Create(b, Now), b)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Source.Arm(b)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Source.Arm(b with { Original = b.Original with { LeaseId = Guid.NewGuid() } }))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Source.Arm(b with
        {
            Original = b.Original with { Selector = b.Original.Selector with { Nonce = Guid.NewGuid() } }
        })).Throws<InvalidOperationException>();
        f.Private.BodyGate = new();
        var pending = f.Source.CollectAsync(window, b).AsTask();
        await f.Private.BodyGate.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.That(async () => await f.Source.CollectAsync(window, b)).Throws<InvalidOperationException>();
        f.Private.BodyGate.Release.TrySetResult();
        await pending;
        await Assert.That(async () => await f.Source.CollectAsync(window, b)).Throws<InvalidOperationException>();
        await Assert.That(f.Private.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task SourceRetainsOnlyThirtyTwoOneUseRegistrations()
    {
        using var f = new Fixture();
        for (int i = 0; i < 32; i++) f.Source.Arm(Binding());
        await Assert.That(() => f.Source.Arm(Binding())).Throws<InvalidOperationException>();
        await Assert.That(f.Private.Requests.Count + f.Public.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("foreign-id")]
    [Arguments("foreign-name")]
    [Arguments("foreign-version")]
    [Arguments("id-query")]
    [Arguments("id-case")]
    [Arguments("wrong-hash")]
    [Arguments("missing-value")]
    [Arguments("null-value")]
    [Arguments("disabled")]
    [Arguments("unknown-enabled")]
    [Arguments("expired")]
    [Arguments("not-yet-valid")]
    [Arguments("duplicate")]
    [Arguments("case")]
    [Arguments("error-in-success")]
    [Arguments("partial")]
    [Arguments("nextLink")]
    [Arguments("array-root")]
    [Arguments("malformed")]
    [Arguments("depth")]
    [Arguments("nodes")]
    [Arguments("rows")]
    [Arguments("row-bytes")]
    [Arguments("body-bytes")]
    [Arguments("declared-bytes")]
    [Arguments("length-mismatch")]
    [Arguments("range")]
    [Arguments("partial-http")]
    [Arguments("duplicate-request-id")]
    [Arguments("long-request-id")]
    [Arguments("header-count")]
    [Arguments("header-bytes")]
    [Arguments("wrong-content-type")]
    [Arguments("redirect")]
    public async Task MalformedNativePrivateResponseIsUnavailableBeforeSdkParsing(string fault)
    {
        using var f = new Fixture();
        f.Private.Fault = fault;
        var result = await f.Collect(Binding());
        await Assert.That(result.PrivateRead.Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(result.PrivateRead.CanarySha256).IsNull();
        await Assert.That(result.PrivateRead.NativeRequestIds.Count).IsEqualTo(0);
        await Assert.That(result.PublicRead.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.PublicRead.CanarySha256).IsEqualTo(Digest);
        await Assert.That(f.Private.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Private.LastStream is null || f.Private.LastStream.Disposed).IsTrue();
        await Assert.That(f.Private.Storage.All(bytes => bytes.All(v => v == 0))).IsTrue();
    }

    [Test]
    [Arguments(401, "valid")]
    [Arguments(403, "wrong-code")]
    [Arguments(403, "missing-code")]
    [Arguments(403, "success-in-error")]
    [Arguments(403, "null-error")]
    [Arguments(403, "case-error")]
    [Arguments(404, "wrong-code")]
    [Arguments(404, "missing-code")]
    [Arguments(429, "valid")]
    [Arguments(500, "valid")]
    public async Task OnlyValidatedBoundForbiddenAndNotFoundHaveConcreteMeaning(int status, string fault)
    {
        using var f = new Fixture();
        f.Private.Status = status;
        f.Private.Fault = fault;
        var result = await f.Collect(Binding());
        await Assert.That(result.PrivateRead.Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(result.PrivateRead.NativeRequestIds.Count).IsEqualTo(0);
        await Assert.That(result.PrivateRead.CanarySha256).IsNull();
        await Assert.That(result.PublicRead.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Private.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task PrivateSuccessSurvivesIndependentPublicFailureAndBorrowedResourcesRemainOwned(bool sharedCredential)
    {
        using var f = new Fixture(sharedCredential);
        f.Public.Throw = true;
        var result = await f.Collect(Binding());
        await Assert.That(result.PrivateRead.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.PrivateRead.CanarySha256).IsEqualTo(Digest);
        await Assert.That(result.PrivateRead.NativeRequestIds.Single()).IsEqualTo("private-request");
        await Assert.That(result.PublicRead.Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(result.PublicRead.CanarySha256).IsNull();
        await Assert.That(result.PublicRead.NativeRequestIds.Count).IsEqualTo(0);
        await Assert.That(f.Private.Disposed || f.Public.Disposed || f.PrivateCredential.Disposed || f.PublicCredential.Disposed).IsFalse();
        await Assert.That(f.Private.Storage.Count > 0).IsTrue();
        await Assert.That(f.Private.Storage.All(bytes => bytes.All(v => v == 0))).IsTrue();
        await Assert.That(result.PrincipalQualified || result.EgressQualified).IsFalse();
    }

    [Test]
    [Arguments("wall")]
    [Arguments("monotonic")]
    [Arguments("wall-rollback")]
    [Arguments("monotonic-rollback")]
    public async Task BothClocksGateBeforeActualCredential(string mode)
    {
        using var f = new Fixture();
        var b = Binding();
        var window = f.Source.Arm(b);
        Move(f.Clock, mode);
        var result = await f.Source.CollectAsync(window, b);
        await Assert.That(result.PrivateRead.Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(result.PublicRead.Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(f.PrivateCredential.Calls + f.PublicCredential.Calls).IsEqualTo(0);
        await Assert.That(f.Private.Requests.Count + f.Public.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("wall")]
    [Arguments("monotonic")]
    [Arguments("wall-rollback")]
    [Arguments("monotonic-rollback")]
    public async Task BothClocksGateAfterActualCredentialBeforeEgress(string mode)
    {
        using var f = new Fixture();
        f.PrivateCredential.BeforeReturn = () => Move(f.Clock, mode);
        var result = await f.Collect(Binding());
        await Assert.That(result.PrivateRead.Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(result.PublicRead.Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(f.PrivateCredential.Calls).IsEqualTo(1);
        await Assert.That(f.Private.Requests.Count + f.Public.Requests.Count).IsEqualTo(0);
    }

    private static void Move(Clock clock, string mode)
    {
        if (mode == "wall") clock.Wall += TimeSpan.FromSeconds(11);
        if (mode == "monotonic") clock.Advance(TimeSpan.FromSeconds(11), wall: false);
        if (mode == "wall-rollback") clock.Wall -= TimeSpan.FromTicks(1);
        if (mode == "monotonic-rollback") clock.Stamp--;
    }

    [Test]
    [Arguments("credential", false)]
    [Arguments("send", false)]
    [Arguments("body", false)]
    [Arguments("sdk", false)]
    [Arguments("credential", true)]
    [Arguments("send", true)]
    [Arguments("body", true)]
    [Arguments("sdk", true)]
    public async Task CancellationAndDeadlineRetainActualBorrowersUntilTheirExit(string phase, bool deadline)
    {
        using var f = new Fixture();
        using var cancel = new CancellationTokenSource();
        var gate = new Gate();
        if (phase == "credential") f.PrivateCredential.Gate = gate;
        if (phase == "send") f.Private.SendGate = gate;
        if (phase == "body") f.Private.BodyGate = gate;
        if (phase == "sdk") f.Private.SdkGate = gate;
        int borrowerExit = 0, collectorExit = 0, sequence = 0;
        gate.OnExit = () => borrowerExit = Interlocked.Increment(ref sequence);
        var b = Binding();
        var pending = phase == "sdk" ? Task.Run(Observe) : Observe();
        await gate.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        if (deadline) f.Clock.Advance(TimeSpan.FromSeconds(11));
        else cancel.Cancel();
        // Cancellation callback completion is not evidence that the collector
        // processed cancellation. Exit order and last storage use below are.
        bool borrowerActive = !gate.Exited.Task.IsCompleted;
        bool rawDisposed = f.Private.LastStream?.Disposed ?? false;
        bool bodyStorageLive = phase != "body" || f.Private.LastStream!.Destination!.Any(v => v != 0);
        bool sdkStorageLive = phase != "sdk" || f.Private.Storage.Single().Any(v => v != 0);
        gate.Release.TrySetResult();
        if (deadline)
        {
            var result = await pending.WaitAsync(TimeSpan.FromSeconds(5));
            await Assert.That(result!.PrivateRead.Status).IsEqualTo(SecretStatus.Unavailable);
        }
        else await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(5))).Throws<OperationCanceledException>();
        await gate.Exited.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.That(borrowerActive).IsTrue();
        await Assert.That(rawDisposed).IsEqualTo(phase == "sdk");
        await Assert.That(bodyStorageLive && sdkStorageLive).IsTrue();
        await Assert.That(borrowerExit > 0 && collectorExit > borrowerExit).IsTrue();
        await Assert.That(gate.StorageWasLiveAtExit).IsTrue();
        await Assert.That(f.Private.Storage.All(bytes => bytes.All(v => v == 0))).IsTrue();
        if (phase == "body")
            await Assert.That(f.Private.LastStream!.Destination!.All(v => v == 0)).IsTrue();
        await Assert.That(f.Public.Requests.Count).IsEqualTo(0);
        await Assert.That(f.Private.Disposed || f.PrivateCredential.Disposed).IsFalse();
        await Assert.That(async () => await f.Source.CollectAsync(f.Source.Arm(b), b)).Throws<InvalidOperationException>();

        async Task<C.Measurement?> Observe()
        {
            try { return await f.Source.CollectAsync(f.Source.Arm(b), b, cancel.Token); }
            finally { collectorExit = Interlocked.Increment(ref sequence); }
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CallerCancellationWinsEvenWhenBackendReturnsAValidSuccess(bool publicChannel)
    {
        using var f = new Fixture();
        using var cancel = new CancellationTokenSource();
        (publicChannel ? f.Public : f.Private).BeforeReturn = cancel.Cancel;
        await Assert.That(async () => await f.Collect(Binding(), cancel.Token)).Throws<OperationCanceledException>();
        await Assert.That(f.Private.Storage.All(bytes => bytes.All(v => v == 0))).IsTrue();
        await Assert.That(f.Public.Storage.All(bytes => bytes.All(v => v == 0))).IsTrue();
    }

    [Test]
    public async Task PreCanceledWindowIsConsumedWithoutCallingBorrowedResources()
    {
        using var f = new Fixture();
        var b = Binding();
        var window = f.Source.Arm(b);
        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        await Assert.That(async () => await f.Source.CollectAsync(window, b, cancel.Token)).Throws<OperationCanceledException>();
        await Assert.That(async () => await f.Source.CollectAsync(window, b)).Throws<InvalidOperationException>();
        await Assert.That(f.PrivateCredential.Calls + f.PublicCredential.Calls).IsEqualTo(0);
    }

    [Test]
    public async Task DefaultSerializationFormattingAndActualExceptionsAreRedacted()
    {
        using var f = new Fixture();
        var b = Binding();
        var window = f.Source.Arm(b);
        var result = await f.Source.CollectAsync(window, b);
        foreach (object value in new object[] { b, window, result, result.PrivateRead, result.PublicRead, f.Source, f.PrivateAuthority })
        {
            await Assert.That(JsonSerializer.Serialize(value)).IsEqualTo("{}");
            await Assert.That(value.ToString()!.Contains("network-vault", StringComparison.Ordinal)).IsFalse();
            await Assert.That(value.ToString()!.Contains(Material, StringComparison.Ordinal)).IsFalse();
        }
        Exception? actual = null;
        try { await f.Source.CollectAsync(window, b); }
        catch (Exception e) { actual = e; }
        await Assert.That(actual is InvalidOperationException).IsTrue();
        await Check(actual!);
        actual = null;
        try { f.Source.Arm(b with { CanaryName = Material + "/network-vault" }); }
        catch (Exception e) { actual = e; }
        await Assert.That(actual is ArgumentException).IsTrue();
        await Check(actual!);
        f.Private.Throw = true;
        var unavailable = await f.Collect(Binding());
        await Assert.That(unavailable.PrivateRead.Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(JsonSerializer.Serialize(unavailable)).IsEqualTo("{}");

        static async Task Check(Exception error)
        {
            string contents = error.ToString() + error.Message + error.InnerException +
                string.Join(",", error.Data.Keys.Cast<object>().Select(key => key + "=" + error.Data[key]));
            foreach (string forbidden in new[] { Origin, Material, Version, Digest, "original-connection", "protected-native-error" })
                await Assert.That(contents.Contains(forbidden, StringComparison.Ordinal)).IsFalse();
            await Assert.That(error.InnerException).IsNull();
        }
    }

    [Test]
    public async Task CachedNativeChallengeStillUsesEachExplicitAuthorityAndOneBoundDispatch()
    {
        using var warmer = new Fixture();
        warmer.Private.WarmChallenge = true;
        using var client = new HttpClient(warmer.Private);
        var native = new SecretClient(new Uri(Origin), warmer.PrivateCredential,
            new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01)
            { Transport = new HttpClientTransport(client) });
        await native.GetSecretAsync("canary", Version);
        await Assert.That(warmer.Private.Requests.Count).IsEqualTo(2);
        using var f = new Fixture();
        var result = await f.Collect(Binding());
        await Assert.That(result.PrivateRead.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.PublicRead.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.PrivateCredential.Calls).IsEqualTo(1);
        await Assert.That(f.PublicCredential.Calls).IsEqualTo(1);
        await Assert.That(f.PrivateCredential.LastTenant).IsNull();
        await Assert.That(f.PublicCredential.LastTenant).IsNull();
        await Assert.That(f.Private.Requests.Single().Authorization).IsEqualTo("Bearer private-token");
        await Assert.That(f.Public.Requests.Single().Authorization).IsEqualTo("Bearer public-token");
    }

    private sealed class Fixture : IDisposable
    {
        internal readonly Clock Clock = new();
        internal readonly Credential PrivateCredential = new("private-token");
        internal readonly Credential PublicCredential;
        internal readonly Backend Private = new("private-request", "private-token");
        internal readonly Backend Public;
        internal readonly C.Authority PrivateAuthority;
        internal readonly C Source;
        private readonly HttpClient privateClient, publicClient;
        internal Fixture(bool sharedCredential = false)
        {
            PublicCredential = sharedCredential ? PrivateCredential : new("public-token");
            Public = new("public-request", sharedCredential ? "private-token" : "public-token");
            privateClient = new(Private);
            publicClient = new(Public);
            PrivateAuthority = new("private-declaration", PrivateCredential, new SpyTransport(new HttpClientTransport(privateClient), Private));
            Source = new(PrivateAuthority,
                new("public-declaration", PublicCredential, new SpyTransport(new HttpClientTransport(publicClient), Public)),
                new(8192, 4096, 128, 8, 8, TimeSpan.FromSeconds(10)), Clock);
        }
        internal ValueTask<C.Measurement> Collect(C.Binding b, CancellationToken token = default) =>
            Source.CollectAsync(Source.Arm(b), b, token);
        public void Dispose()
        {
            privateClient.Dispose();
            publicClient.Dispose();
            PrivateCredential.Dispose();
            if (!ReferenceEquals(PrivateCredential, PublicCredential)) PublicCredential.Dispose();
        }
    }

    private sealed class Gate
    {
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Action? OnExit;
        internal bool StorageWasLiveAtExit;
        internal async Task WaitAsync()
        {
            Entered.TrySetResult();
            await Release.Task;
        }
        internal void Complete(Func<bool>? storage = null)
        {
            StorageWasLiveAtExit = storage?.Invoke() ?? true;
            OnExit?.Invoke();
            Exited.TrySetResult();
        }
    }

    private sealed class Credential(string token) : TokenCredential, IDisposable
    {
        internal readonly HashSet<string> Scopes = [];
        internal int Calls;
        internal string? LastTenant;
        internal bool Disposed;
        internal Action? BeforeReturn;
        internal Gate? Gate;
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            Calls++;
            LastTenant = requestContext.TenantId;
            foreach (string scope in requestContext.Scopes) Scopes.Add(scope);
            try
            {
                if (Gate is { } gate) await gate.WaitAsync();
                BeforeReturn?.Invoke();
                return new(token, DateTimeOffset.MaxValue);
            }
            finally { Gate?.Complete(); }
        }
        public void Dispose() => Disposed = true;
    }

    private sealed record RequestRow(string Uri, HttpMethod Method, string? Authorization);

    private sealed class Backend(string requestId, string token) : HttpMessageHandler
    {
        internal string Token => token;
        internal readonly List<RequestRow> Requests = [];
        internal readonly List<byte[]> Storage = [];
        internal int Status = 200;
        internal string? Fault;
        internal bool Throw, Disposed, WarmChallenge;
        internal Gate? SendGate, BodyGate, SdkGate;
        internal Action? BeforeReturn;
        internal BodyStream? LastStream;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(new(request.RequestUri!.AbsoluteUri, request.Method, request.Headers.Authorization?.ToString()));
            if (WarmChallenge && Requests.Count == 1)
            {
                var challenge = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                challenge.Headers.TryAddWithoutValidation("WWW-Authenticate",
                    "Bearer authorization=\"https://login.windows.net/11111111-1111-1111-1111-111111111111\", resource=\"https://vault.azure.net\"");
                return challenge;
            }
            try
            {
                if (SendGate is { } send) await send.WaitAsync();
                if (Throw) throw new HttpRequestException(Origin + Material + "protected-native-error");
                string id = Fault switch
                {
                    "foreign-id" => Id.Replace("network-vault", "foreign-vault", StringComparison.Ordinal),
                    "foreign-name" => Id.Replace("/canary/", "/foreign/", StringComparison.Ordinal),
                    "foreign-version" => Id.Replace(Version, new string('f', 32), StringComparison.Ordinal),
                    "id-query" => Id + "?other=1",
                    "id-case" => Id.Replace("canary", "CANARY", StringComparison.Ordinal),
                    _ => Id
                };
                string value = Fault == "wrong-hash" ? "wrong-value" : Material;
                string body = JsonSerializer.Serialize(new { value, id, attributes = new { enabled = true } });
                if (Fault == "missing-value") body = JsonSerializer.Serialize(new { id, attributes = new { enabled = true } });
                if (Fault == "null-value") body = body.Replace(JsonSerializer.Serialize(value), "null", StringComparison.Ordinal);
                if (Fault == "disabled") body = body.Replace("true", "false", StringComparison.Ordinal);
                if (Fault == "unknown-enabled") body = body.Replace("true", "\"future\"", StringComparison.Ordinal);
                if (Fault == "expired") body = body.Replace("\"enabled\":true", "\"enabled\":true,\"exp\":1", StringComparison.Ordinal);
                if (Fault == "not-yet-valid") body = body.Replace("\"enabled\":true", "\"enabled\":true,\"nbf\":4102444800", StringComparison.Ordinal);
                if (Fault == "duplicate") body = body.Replace("\"id\":", "\"id\":\"duplicate\",\"id\":", StringComparison.Ordinal);
                if (Fault == "case") body = body.Replace("\"value\":", "\"Value\":", StringComparison.Ordinal);
                if (Fault == "error-in-success") body = body[..^1] + ",\"error\":{\"code\":\"Forbidden\"}}";
                if (Fault is "partial" or "nextLink") body = body[..^1] + ",\"" + Fault + "\":true}";
                if (Fault == "array-root") body = "[" + body + "]";
                if (Fault == "malformed") body = "{";
                if (Fault == "depth") body = new string('[', 12) + "{}" + new string(']', 12);
                if (Fault == "nodes") body = "{\"padding\":[" + string.Join(",", Enumerable.Repeat("0", 200)) + "]}";
                if (Fault == "rows") body = "{\"padding\":[" + string.Join(",", Enumerable.Repeat("{}", 10)) + "]}";
                if (Fault == "row-bytes") body = "{\"padding\":\"" + new string('x', 5000) + "\"}";
                if (Fault == "body-bytes") body = new string('x', 9000);
                if (Status >= 400)
                {
                    string code = Status == 403 ? "Forbidden" : Status == 404 ? "SecretNotFound" : "Failure";
                    body = JsonSerializer.Serialize(new { error = new { code, message = "protected-native-error" } });
                    if (Fault == "wrong-code") body = body.Replace(code, "FutureCode", StringComparison.Ordinal);
                    if (Fault == "missing-code") body = """{"error":{"message":"protected-native-error"}}""";
                    if (Fault == "success-in-error") body = body[..^1] + ",\"value\":\"protected-native-error\"}";
                    if (Fault == "null-error") body = """{"error":null}""";
                    if (Fault == "case-error") body = body.Replace("\"error\"", "\"Error\"", StringComparison.Ordinal);
                }
                var response = new HttpResponseMessage((HttpStatusCode)(Fault == "partial-http" ? 206 :
                    Fault == "redirect" ? 307 : Status));
                response.Headers.TryAddWithoutValidation("x-ms-request-id", Fault == "long-request-id" ? new string('a', 300) : requestId);
                if (Fault == "duplicate-request-id") response.Headers.TryAddWithoutValidation("x-ms-request-id", "other");
                if (Fault == "header-count")
                    for (int i = 0; i < 40; i++) response.Headers.TryAddWithoutValidation("X-Extra-" + i, "x");
                if (Fault == "header-bytes") response.Headers.TryAddWithoutValidation("X-Extra", new string('x', 17000));
                if (Fault == "redirect") response.Headers.Location = new("https://foreign.invalid/");
                LastStream = new(Encoding.UTF8.GetBytes(body), BodyGate);
                response.Content = new StreamContent(LastStream);
                response.Content.Headers.ContentType = new(Fault == "wrong-content-type" ? "text/plain" : "application/json");
                if (Fault == "range") response.Content.Headers.TryAddWithoutValidation("Content-Range", "bytes 0-1/2");
                if (Fault != "body-bytes")
                    response.Content.Headers.ContentLength = Fault == "declared-bytes" ? 10000 :
                        Encoding.UTF8.GetByteCount(body) + (Fault == "length-mismatch" ? 1 : 0);
                BeforeReturn?.Invoke();
                return response;
            }
            finally { SendGate?.Complete(); }
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }

    // Composition prevents MemoryStream's byte[] overload bypassing our actual
    // borrower. Both asynchronous overloads reach the same retained read.
    private sealed class BodyStream(byte[] bytes, Gate? gate) : Stream
    {
        private readonly MemoryStream inner = new(bytes);
        internal byte[]? Destination;
        internal bool Disposed;
        private bool entered;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new InvalidOperationException("async-only");
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var segment)) Destination = segment.Array;
            try
            {
                if (gate is not null && !entered)
                {
                    entered = true;
                    buffer.Span.Fill(0x5a);
                    await gate.WaitAsync();
                }
                return await inner.ReadAsync(buffer, CancellationToken.None);
            }
            finally { gate?.Complete(() => Destination!.Any(v => v != 0) && !Disposed); }
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { Disposed = true; inner.Dispose(); base.Dispose(disposing); }
    }

    private sealed class SpyTransport(HttpPipelineTransport inner, Backend backend) : HttpPipelineTransport
    {
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            message.Response = new SpyResponse(message.Response, backend);
        }
    }

    private sealed class SpyResponse(Response inner, Backend backend) : Response
    {
        public override int Status => inner.Status;
        public override string ReasonPhrase => inner.ReasonPhrase;
        public override string ClientRequestId { get => inner.ClientRequestId; set => inner.ClientRequestId = value; }
        public override Stream? ContentStream
        {
            get => inner.ContentStream;
            set
            {
                if (backend.Storage.Count == 0 && value is MemoryStream memory &&
                    memory.TryGetBuffer(out var segment) && segment.Array is { } bytes)
                {
                    // Only the source's first replacement belongs to the
                    // collector. Copies subsequently made by the SDK do not.
                    backend.Storage.Add(bytes);
                    // The native parser's read is held after the source transport
                    // returns. The backing array must survive the whole SDK task.
                    inner.ContentStream = backend.SdkGate is { } gate ? new SdkStream(memory, gate, bytes) : memory;
                }
                else inner.ContentStream = value;
            }
        }
        public override void Dispose() => inner.Dispose();
        protected override bool ContainsHeader(string name) => inner.Headers.Contains(name);
        protected override IEnumerable<HttpHeader> EnumerateHeaders() => inner.Headers;
        protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value) => inner.Headers.TryGetValue(name, out value);
        protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values) =>
            inner.Headers.TryGetValues(name, out values);
    }

    private sealed class SdkStream(Stream inner, Gate gate, byte[] storage) : Stream
    {
        private bool entered;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            try
            {
                if (!entered) { entered = true; gate.WaitAsync().GetAwaiter().GetResult(); }
                return inner.Read(buffer, offset, count);
            }
            finally { gate.Complete(() => storage.Any(v => v != 0)); }
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            try
            {
                if (!entered) { entered = true; await gate.WaitAsync(); }
                return await inner.ReadAsync(buffer, CancellationToken.None);
            }
            finally { gate.Complete(() => storage.Any(v => v != 0)); }
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { inner.Dispose(); base.Dispose(disposing); }
    }

    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Wall = Now;
        internal long Stamp;
        private readonly List<Hook> timers = [];
        public override DateTimeOffset GetUtcNow() => Wall;
        public override long GetTimestamp() => Stamp;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new Hook(this, callback, state) { Due = Stamp + dueTime.Ticks };
            timers.Add(timer);
            return timer;
        }
        internal void Advance(TimeSpan amount, bool wall = true)
        {
            Stamp += amount.Ticks;
            if (wall) Wall += amount;
            foreach (var timer in timers.ToArray())
                if (timer.Due <= Stamp) { timer.Due = long.MaxValue; timer.Fire(); }
        }
        private sealed class Hook(Clock clock, TimerCallback callback, object? state) : ITimer
        {
            internal long Due;
            internal void Fire() => callback(state);
            public bool Change(TimeSpan dueTime, TimeSpan period) { Due = clock.Stamp + dueTime.Ticks; return true; }
            public void Dispose() => Due = long.MaxValue;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
