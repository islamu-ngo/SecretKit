using System.Net;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureRoleAdministrationCollectorTests
{
    [Test]
    [Arguments("pages", false)]
    [Arguments("items", false)]
    [Arguments("declared-bytes", false)]
    [Arguments("stream-bytes", false)]
    [Arguments("pages", true)]
    [Arguments("items", true)]
    [Arguments("declared-bytes", true)]
    [Arguments("stream-bytes", true)]
    public async Task BudgetsRejectBeforeNativeModelOrNextDispatch(string budget, bool definitions)
    {
        using var fixture = new Fixture();
        CountingStream? stream = null;
        fixture.Arm.Respond = (request, _) =>
        {
            if (definitions && request.RequestUri!.AbsolutePath == AssignmentPath)
                return Task.FromResult(Json(200, Page("")));
            string row = definitions ? Definition(DefinitionId) : Assignment(AssignmentId);
            var response = Json(200, budget == "pages" ? Page(row, Next(definitions)) :
                budget == "items" ? Page(row + "," + (definitions ? Definition(OtherId) : Assignment(OtherId))) :
                new string('x', 4096));
            if (budget == "stream-bytes")
            {
                response.Content.Dispose();
                stream = new(Encoding.UTF8.GetBytes(new string('x', 4096)));
                response.Content = new StreamContent(stream);
            }
            return Task.FromResult(response);
        };
        var collector = fixture.Collector(new(1, 1, budget is "pages" or "items" ? 4096 : 1024, TimeSpan.FromSeconds(10)));
        var binding = Binding();
        var result = await collector.CollectAsync(collector.Arm(binding), binding, RoleAdministrationCollector.Phase.After);
        await Assert.That(result.Failure).IsEqualTo(RoleAdministrationCollector.Failure.Budget);
        await Assert.That(result.TargetPresent).IsNull();
        await Assert.That(fixture.Arm.Requests.Count).IsEqualTo(definitions ? 2 : 1);
        if (stream is not null)
        {
            await Assert.That(stream.ReadBytes).IsEqualTo(1025);
            await Assert.That(stream.Disposed).IsTrue();
        }
    }

    [Test]
    [Arguments("wrong-id")]
    [Arguments("wrong-name")]
    [Arguments("wrong-version")]
    [Arguments("wrong-host")]
    [Arguments("missing-value")]
    [Arguments("missing-request-id")]
    [Arguments("bad-request-id")]
    [Arguments("duplicate-value")]
    [Arguments("oversized")]
    [Arguments("redirect")]
    public async Task ActualSecretReadCoordinatesAndFinalEvidenceFailClosed(string fault)
    {
        using var fixture = new Fixture();
        var normal = fixture.Intended.Respond;
        fixture.Intended.Respond = async (request, token) =>
        {
            var response = await normal(request, token);
            if (request.Headers.Authorization is null) return response;
            string id = fault switch
            {
                "wrong-id" => SecretId + "/extra",
                "wrong-name" => SecretId.Replace("/canary/", "/other/", StringComparison.Ordinal),
                "wrong-version" => SecretId.Replace(Version, new string('b', 32), StringComparison.Ordinal),
                "wrong-host" => SecretId.Replace("collector-vault", "foreign-vault", StringComparison.Ordinal),
                _ => SecretId
            };
            response.Content.Dispose();
            string body = JsonSerializer.Serialize(new { id, value = Material, attributes = new { enabled = true } });
            if (fault == "missing-value") body = JsonSerializer.Serialize(new { id });
            if (fault == "duplicate-value") body = body.Replace("\"value\":", "\"value\":\"other\",\"value\":", StringComparison.Ordinal);
            if (fault == "oversized") body = new string('x', 65537);
            response.Content = new StringContent(body, Encoding.UTF8, "application/json");
            if (fault == "missing-request-id") response.Headers.Remove("x-ms-request-id");
            if (fault == "bad-request-id")
            {
                response.Headers.Remove("x-ms-request-id");
                response.Headers.TryAddWithoutValidation("x-ms-request-id", "private value");
            }
            if (fault == "redirect")
            {
                response.StatusCode = HttpStatusCode.TemporaryRedirect;
                response.Headers.Location = new("https://foreign.invalid/");
            }
            return response;
        };
        var collector = fixture.Collector();
        var binding = Binding();
        var result = await collector.CollectAsync(collector.Arm(binding), binding, RoleAdministrationCollector.Phase.After);
        await Assert.That(result.Complete).IsFalse();
        await Assert.That(result.TargetPresent).IsNull();
        await Assert.That(result.Intended.Sha256).IsNull();
        await Assert.That(result.Intended.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(result.Observer.Complete).IsTrue();
        await Assert.That(fixture.ObserverCredential.Uses > 0).IsTrue();
        await Assert.That(fixture.Intended.Requests.All(r => r.Uri.Host == "collector-vault.vault.azure.net")).IsTrue();
    }

    [Test]
    [Arguments(401, SecretStatus.Denied)]
    [Arguments(403, SecretStatus.Denied)]
    [Arguments(404, SecretStatus.Absent)]
    [Arguments(429, SecretStatus.Throttled)]
    [Arguments(503, SecretStatus.Unavailable)]
    public async Task FailedReadsRetainOnlyActualFinalIdsAndNeverFallback(int status, SecretStatus expected)
    {
        using var fixture = new Fixture();
        fixture.Intended.Respond = (_, _) => Task.FromResult(Json(status,
            """{"error":{"code":"Failure","message":"private-native-error"}}""", "actual-failure"));
        var collector = fixture.Collector();
        var binding = Binding();
        var result = await collector.CollectAsync(collector.Arm(binding), binding, RoleAdministrationCollector.Phase.After);
        await Assert.That(result.Intended.Status).IsEqualTo(expected);
        await Assert.That(result.Intended.NativeRequestId).IsEqualTo("actual-failure");
        await Assert.That(result.Intended.Sha256).IsNull();
        await Assert.That(fixture.Intended.Requests.Count).IsEqualTo(1);
        await Assert.That(result.Denied.NativeRequestId).IsEqualTo("denied-final");
        await Assert.That(result.Observer.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(JsonSerializer.Serialize(result)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(result.Intended)).IsEqualTo("{}");
        await Assert.That(result.ToString()).DoesNotContain("private");
    }

    [Test]
    public async Task FinalUnauthorizedChallengeIsMeasuredRatherThanReplayed()
    {
        using var fixture = new Fixture();
        var normal = fixture.Intended.Respond;
        fixture.Intended.Respond = async (request, token) =>
        {
            var response = await normal(request, token);
            if (request.Headers.Authorization is not null)
            {
                response.Dispose();
                response = Json(401, """{"error":{"code":"Unauthorized","message":"private-native-error"}}""", "final-unauthorized");
                response.Headers.TryAddWithoutValidation("WWW-Authenticate",
                    "Bearer authorization=\"https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222\", resource=\"https://vault.azure.net\"");
            }
            return response;
        };
        var collector = fixture.Collector();
        var binding = Binding();
        var result = await collector.CollectAsync(collector.Arm(binding), binding, RoleAdministrationCollector.Phase.After);
        await Assert.That(result.Intended.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(result.Intended.NativeRequestId).IsEqualTo("final-unauthorized");
        await Assert.That(result.Intended.Sha256).IsNull();
        await Assert.That(fixture.Intended.Requests.Count <= 2).IsTrue();
        await Assert.That(result.Observer.Status).IsEqualTo(SecretStatus.Success);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task NativeTransportLossCannotBecomeAbsenceOrExposeExceptionPayload(bool management)
    {
        using var fixture = new Fixture();
        (management ? fixture.Arm : fixture.Intended).Respond = (_, _) =>
            throw new HttpRequestException("private-native-error " + Material);
        var collector = fixture.Collector();
        var binding = Binding();
        var result = await collector.CollectAsync(collector.Arm(binding), binding, RoleAdministrationCollector.Phase.After);
        await Assert.That(result.Complete).IsFalse();
        await Assert.That(result.TargetPresent).IsNull();
        await Assert.That(result.Assignments.Count).IsEqualTo(0);
        await Assert.That(result.Intended.Sha256).IsNull();
        await Assert.That(result.Intended.NativeRequestId).IsNull();
        await Assert.That((management ? fixture.Arm : fixture.Intended).Requests.Count).IsEqualTo(1);
        await Assert.That(JsonSerializer.Serialize(result)).IsEqualTo("{}");
        await Assert.That(result.ToString()).DoesNotContain(Material);
    }

    [Test]
    public async Task CompleteEmptyInventoriesAreMeasuredAbsenceNotMissingEvidence()
    {
        using var fixture = new Fixture();
        fixture.Arm.Respond = (_, _) => Task.FromResult(Json(200, Page("")));
        var collector = fixture.Collector(new(1, 1, 1024, TimeSpan.FromSeconds(10)));
        var binding = Binding();
        var result = await collector.CollectAsync(collector.Arm(binding), binding, RoleAdministrationCollector.Phase.After);
        await Assert.That(result.Complete).IsTrue();
        await Assert.That(result.TargetPresent).IsFalse();
        await Assert.That(result.Assignments.Count).IsEqualTo(0);
        await Assert.That(result.Definitions.Count).IsEqualTo(0);
        await Assert.That(result.Intended.Status).IsEqualTo(SecretStatus.Success);
    }

    [Test]
    public async Task NativeChallengeVerificationRejectsForeignResourceWithoutCredentialUse()
    {
        using var fixture = new Fixture();
        // A unique DNS name prevents the native SDK's process-wide challenge cache
        // from substituting a previously validated challenge in this negative case.
        var vault = new VaultScope(Vault().ResourceGroup, "foreign-challenge-test");
        var binding = Binding() with { Vault = vault, Target = new(vault, AssignmentId) };
        fixture.Arm.Respond = (request, _) => Task.FromResult(Json(200, Page(
            request.RequestUri!.AbsolutePath.EndsWith("/roleAssignments", StringComparison.Ordinal)
                ? Assignment(AssignmentId, vault.ExportResourceId()) : Definition(DefinitionId))));
        fixture.Intended.Respond = (_, _) =>
        {
            var response = Json(401, "{}", "challenge");
            response.Headers.TryAddWithoutValidation("WWW-Authenticate",
                "Bearer authorization=\"https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222\", resource=\"https://foreign.invalid\"");
            return Task.FromResult(response);
        };
        var collector = fixture.Collector();
        var result = await collector.CollectAsync(collector.Arm(binding), binding, RoleAdministrationCollector.Phase.After);
        await Assert.That(result.Complete).IsFalse();
        await Assert.That(fixture.IntendedCredential.Uses).IsEqualTo(0);
        await Assert.That(fixture.Intended.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("credential")]
    [Arguments("transport")]
    [Arguments("label")]
    public async Task AuthorityAliasingIsRejectedBeforeDispatch(string alias)
    {
        using var fixture = new Fixture();
        var arm = new RoleAdministrationCollector.Authority("arm", fixture.ArmCredential, fixture.Transports[0]);
        var intended = new RoleAdministrationCollector.Authority(alias == "label" ? "arm" : "intended",
            alias == "credential" ? fixture.ArmCredential : fixture.IntendedCredential,
            alias == "transport" ? fixture.Transports[0] : fixture.Transports[1]);
        await Assert.That(() => new RoleAdministrationCollector(arm, intended,
            new("denied", fixture.DeniedCredential, fixture.Transports[2]),
            new("observer", fixture.ObserverCredential, fixture.Transports[3]),
            new(4, 100, 65536, TimeSpan.FromSeconds(10)))).Throws<ArgumentException>();
        await Assert.That(fixture.Arm.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task IndependentNativeStateDistinguishesPersistedMutationFromEchoOnly(bool persist)
    {
        using var fixture = new Fixture();
        bool assigned = false;
        fixture.Arm.Respond = (request, _) => Task.FromResult(Json(200, Page(
            request.RequestUri!.AbsolutePath == DefinitionPath ? Definition(DefinitionId) :
            assigned ? Assignment(AssignmentId) : "")));
        var read = fixture.Intended.Respond;
        fixture.Intended.Respond = (request, token) => assigned || request.Headers.Authorization is null
            ? read(request, token) : Task.FromResult(Json(403, """{"error":{"code":"Forbidden","message":"denied"}}""", "intended-denial"));
        var collector = fixture.Collector();
        var binding = Binding();
        var window = collector.Arm(binding);
        var before = await collector.CollectAsync(window, binding, RoleAdministrationCollector.Phase.Baseline);
        await Assert.That(before.Complete).IsTrue();
        await Assert.That(before.TargetPresent).IsFalse();
        await Assert.That(before.Intended.Status).IsEqualTo(SecretStatus.Denied);
        using var handler = new MutationBackend(() => assigned = persist);
        using var http = new HttpClient(handler);
        var selected = new VaultAdministration(new Credential("administrative", "https://management.azure.com/.default"),
            new HttpClientTransport(http));
        var receipt = selected.PrepareReceipt(binding.Target, ManagementMutation.CreateRoleAssignment);
        var echoed = await selected.CreateRoleAssignmentAsync(binding.Target, new(new(SubscriptionId), DefinitionId),
            PrincipalId, receipt);
        await Assert.That(echoed.Status).IsEqualTo(SecretStatus.Success);
        var after = await collector.CollectAsync(window, binding, RoleAdministrationCollector.Phase.After);
        await Assert.That(after.Complete).IsTrue();
        await Assert.That(after.Sequence).IsEqualTo(before.Sequence + 1);
        await Assert.That(after.WindowId).IsEqualTo(before.WindowId);
        if (persist)
        {
            RoleAdministrationEffects.ValidateMutation("CreateRoleAssignmentAsync", false, binding.Target,
                PrincipalId, DefinitionId, before.Assignments.ToArray(), after.Assignments.ToArray());
            await Assert.That(after.Intended.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(after.Intended.Sha256).IsNotNull();
        }
        else
        {
            await Assert.That(() => RoleAdministrationEffects.ValidateMutation("CreateRoleAssignmentAsync", false,
                binding.Target, PrincipalId, DefinitionId, before.Assignments.ToArray(), after.Assignments.ToArray()))
                .Throws<NativeCaseFailureException>();
            await Assert.That(after.TargetPresent).IsFalse();
            await Assert.That(after.Intended.Status).IsEqualTo(SecretStatus.Denied);
        }
        await Assert.That(fixture.Arm.Requests.All(r => r.Method == HttpMethod.Get)).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task AncestorSelectorsMustBeExplicitlyBorrowedAndRemainUnchanged(bool subscription)
    {
        using var fixture = new Fixture();
        ManagementScope parent = subscription ? new SubscriptionScope(SubscriptionId) : Vault().ResourceGroup;
        var target = new RoleAssignmentScope(parent, OtherId);
        var binding = Binding() with { Target = target };
        var collector = fixture.Collector();
        await Assert.That(() => collector.Arm(binding)).Throws<ArgumentException>();
        binding = binding with { BorrowedAncestors = [target] };
        string inherited = Assignment(OtherId, RoleAdministrationEffects.ParentId(parent));
        fixture.Arm.Respond = (request, _) => Task.FromResult(Json(200, Page(
            request.RequestUri!.AbsolutePath == DefinitionPath ? Definition(DefinitionId) :
                Assignment(AssignmentId) + "," + inherited)));
        var window = collector.Arm(binding);
        var before = await collector.CollectAsync(window, binding, RoleAdministrationCollector.Phase.Baseline);
        var after = await collector.CollectAsync(window, binding, RoleAdministrationCollector.Phase.After);
        await Assert.That(before.Complete && after.Complete).IsTrue();
        await Assert.That(after.TargetPresent).IsTrue();
        await Assert.That(after.Assignments.SequenceEqual(before.Assignments)).IsTrue();
        await Assert.That(fixture.Arm.Requests.All(r => r.Method == HttpMethod.Get)).IsTrue();
        await Assert.That(fixture.Arm.Disposed || fixture.Intended.Disposed || fixture.Denied.Disposed || fixture.Observer.Disposed).IsFalse();
        await Assert.That(fixture.ArmCredential.Disposed || fixture.IntendedCredential.Disposed ||
            fixture.DeniedCredential.Disposed || fixture.ObserverCredential.Disposed).IsFalse();
        await Assert.That(JsonSerializer.Serialize(binding)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(after)).IsEqualTo("{}");
    }

    private sealed class MutationBackend(Action apply) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method != HttpMethod.Put || request.Headers.Authorization?.Parameter != "administrative" ||
                request.RequestUri!.AbsolutePath != AssignmentPath + "/" + AssignmentId)
                throw new InvalidOperationException("controlled-mutation-boundary");
            apply();
            return Task.FromResult(Json(201, Assignment(AssignmentId), "selected-echo"));
        }
    }

    private sealed class CountingStream(byte[] bytes) : Stream
    {
        internal int ReadBytes;
        internal bool Disposed;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int length = Math.Min(count, bytes.Length - ReadBytes);
            bytes.AsSpan(ReadBytes, length).CopyTo(buffer.AsSpan(offset, count));
            ReadBytes += length;
            return length;
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int length = Math.Min(buffer.Length, bytes.Length - ReadBytes);
            bytes.AsMemory(ReadBytes, length).CopyTo(buffer);
            ReadBytes += length;
            return ValueTask.FromResult(length);
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
