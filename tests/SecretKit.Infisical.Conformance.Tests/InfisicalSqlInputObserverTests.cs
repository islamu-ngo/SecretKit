using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Controlled private-source protocol evidence, never native qualification.
public sealed class InfisicalSqlInputObserverTests
{
    private static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private static readonly DateTimeOffset Clock = DateTimeOffset.UnixEpoch.AddDays(1);
    private static readonly Guid Definition = Guid.Parse("00000000-0000-0000-0000-000000000002");
    private static readonly InfisicalLifecycleObservers.Settings Settings =
        new(new("https://observer.invalid/owned/"), "synthetic-token", "sql-source-instance", 30);
    private static SqlInputRootAttempt Root() => new("root", "case", "v0.166.3", "deployment",
        "sql-profile", "owned-nonce", NativeSqlEngine.Postgres,
        "00000000-0000-0000-0000-000000000001", "testing", "/owned", SqlInputSource.ControlledFixture);
    private static DynamicSqlInput Profile(string target, string? ca = "synthetic-ca") =>
        new(NativeSqlEngine.Postgres, target + ".invalid", 5432, target, target + "-admin",
            target + "-private-password", "create synthetic", "revoke synthetic", "renew synthetic",
            ca, null, null, null);
    private static SqlInputPrivateProfiles Profiles(string variant = "sql.ca.value", string? ca = "synthetic-ca") =>
        new(Profile("baseline", ca), Profile("selected", ca), "update", variant,
            metadata: [new("synthetic-key", "synthetic-value")], optionsSupplied: true);
    private static SqlInputAttempt Attempt(SqlInputBinding binding, string id = "mutation",
        string variant = "sql.ca.value") =>
        new(binding, id, "owned-definition", Definition, "update", variant, "selected-contract",
            SqlInputConfiguration.Selected);
    private static async Task<SqlInputBinding> Open(InfisicalSqlInputObserver observer, SqlInputRootAttempt root)
    {
        using var profiles = Profiles();
        return await observer.OpenAsync(root, profiles, CancellationToken.None);
    }

    [Test]
    public async Task SelectedPrivateOptionsReachSourceBeforeCopiesAreDestroyed()
    {
        bool captured = false;
        using var service = new Service
        {
            InspectOptions = options =>
            {
                captured = options.TryGetProperty("usernameTemplate", out var username) &&
                    username.GetString() == "selected-user" &&
                    options.TryGetProperty("metadata", out var metadata) && metadata.GetArrayLength() == 1 &&
                    metadata[0].GetProperty("key").GetString() == "selected-key" &&
                    metadata[0].GetProperty("value").GetString() == "selected-value" &&
                    options.TryGetProperty("optionsSupplied", out var supplied) && supplied.GetBoolean() &&
                    options.TryGetProperty("clearUsernameTemplate", out var clear) && clear.GetBoolean();
            }
        };
        var observer = service.Observer();
        var root = Root();
        using var profiles = new SqlInputPrivateProfiles(Profile("baseline"), Profile("selected"),
            "UpdateDefinitionAsync", "metadata.value", "selected-user",
            [new("selected-key", "selected-value")], optionsSupplied: true, clearUsernameTemplate: true);
        await observer.OpenAsync(root, profiles, CancellationToken.None);
        await observer.CloseAsync(root, CancellationToken.None);
        await Assert.That(captured).IsTrue();
        await Assert.That(service.PrivateOnlyInOpen).IsTrue();
        await Assert.That(service.Buffers.All(buffer => buffer.All(value => value == 0))).IsTrue();
    }

    [Test]
    [Arguments(DispatchEvidence.Applied, true)]
    [Arguments(DispatchEvidence.Rejected, false)]
    [Arguments(DispatchEvidence.NotDispatched, false)]
    [Arguments(DispatchEvidence.PossiblyDispatched, true)]
    [Arguments(DispatchEvidence.PossiblyDispatched, false)]
    public async Task OriginalReceiptSettlesActualCommitWithoutReplay(DispatchEvidence receipt, bool applied)
    {
        using var service = new Service { Applied = applied };
        var observer = service.Observer();
        var root = Root();
        var binding = await Open(observer, root);
        var arm = await observer.ArmAsync(Attempt(binding), CancellationToken.None);
        var fence = await observer.CompleteAsync(arm, receipt, CancellationToken.None);
        await Assert.That(fence.Applied).IsEqualTo(applied);
        await Assert.That(fence.Disposition).IsEqualTo(receipt);
        await Assert.That(fence.MatchedCommits).IsEqualTo(applied ? 1 : 0);
        var observation = await observer.ObserveAsync(binding, Definition,
            applied ? SqlInputConfiguration.Selected : SqlInputConfiguration.Baseline, CancellationToken.None);
        await Assert.That(observation.IndependentStorageRead && observation.ActualAdminSessionCaptured).IsTrue();
        await Assert.That(async () => await observer.CompleteAsync(arm, receipt, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.ObserveAsync(binding, Definition,
            observation.Configuration, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await observer.CloseAsync(root, CancellationToken.None);
        await Assert.That(service.RootExists || service.PrivateRetained).IsFalse();
        await Assert.That(service.BorrowedStatePreserved).IsTrue();
        await Assert.That(service.Buffers.All(b => b.All(v => v == 0))).IsTrue();
        await Assert.That(service.PrivateOnlyInOpen).IsTrue();
    }

    [Test]
    public async Task CancelledTransportCanSettleWithoutAnUpstreamRequest()
    {
        // Given an armed original attempt and an independently fenced empty journal.
        using var service = new Service { Applied = false };
        service.Change = (route, facts) =>
        {
            if (route != "complete") return;
            facts["matchedRequests"] = 0;
            facts["providerRequestId"] = null;
        };
        var observer = service.Observer();
        var root = Root();
        var binding = await Open(observer, root);
        var arm = await observer.ArmAsync(Attempt(binding), CancellationToken.None);
        // When the SDK's uncertain receipt settles as no upstream application.
        var fence = await observer.CompleteAsync(arm, DispatchEvidence.PossiblyDispatched, CancellationToken.None);
        // Then no fictitious request is required and the consumed arm cannot replay.
        await Assert.That(fence.Applied).IsFalse();
        await Assert.That(fence.MatchedRequests).IsEqualTo(0);
        await Assert.That(async () => await observer.CompleteAsync(arm,
            DispatchEvidence.PossiblyDispatched, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await observer.CloseAsync(root, CancellationToken.None);
        await Assert.That(service.RootExists || service.PrivateRetained).IsFalse();
    }

    [Test]
    [Arguments("open")]
    [Arguments("arm")]
    [Arguments("complete")]
    public async Task LostReplyConsumesOriginalAttemptAndStillCleansIt(string lost)
    {
        using var service = new Service { LostRoute = lost };
        var observer = service.Observer();
        var root = Root();
        SqlInputBinding? binding = null;
        SqlInputArm? arm = null;
        await Assert.That(async () =>
        {
            binding = await Open(observer, root);
            arm = await observer.ArmAsync(Attempt(binding), CancellationToken.None);
            await observer.CompleteAsync(arm, DispatchEvidence.PossiblyDispatched, CancellationToken.None);
        }).Throws<NativeCaseFailureException>();
        if (binding is not null)
            await Assert.That(async () => await observer.ArmAsync(Attempt(binding), CancellationToken.None))
                .Throws<NativeCaseFailureException>();
        if (arm is not null)
            await Assert.That(async () => await observer.CompleteAsync(arm,
                DispatchEvidence.PossiblyDispatched, CancellationToken.None)).Throws<NativeCaseFailureException>();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await observer.CloseAsync(root, cancelled.Token);
        await Assert.That(service.ClosedAttempt).IsEqualTo(root);
        await Assert.That(service.RootExists || service.PrivateRetained).IsFalse();
        await Assert.That(service.Routes.Count(r => r == lost)).IsEqualTo(1);
    }

    [Test]
    [Arguments("open")]
    [Arguments("arm")]
    [Arguments("complete")]
    [Arguments("observe")]
    [Arguments("close")]
    public async Task AllNestedEvidenceFieldsAreRequired(string route)
    {
        JsonObject? baseline = null;
        using (var service = new Service
        {
            Change = (actual, facts) => { if (actual == route) baseline = facts.DeepClone().AsObject(); }
        }) await Exercise(service, route);
        if (baseline is null) throw new InvalidOperationException("missing-test-evidence");
        foreach (string[] path in FieldPaths(baseline, []))
        {
            using var service = new Service
            {
                Change = (actual, facts) =>
                {
                    if (actual != route) return;
                    JsonObject parent = facts;
                    foreach (string name in path[..^1]) parent = parent[name]!.AsObject();
                    parent.Remove(path[^1]);
                }
            };
            await Assert.That(async () => await Exercise(service, route)).Throws<NativeCaseFailureException>();
            await Assert.That(service.RootExists || service.PrivateRetained).IsFalse();
        }
    }

    [Test]
    [Arguments("open", "sourceIdentity")]
    [Arguments("open", "clockAuthority")]
    [Arguments("open", "clockEpoch")]
    [Arguments("open", "registrationId")]
    [Arguments("open", "sequence")]
    [Arguments("open", "ownedRootCreated")]
    [Arguments("open", "rootInitiallyAbsent")]
    [Arguments("open", "baselineAdminAccepted")]
    [Arguments("open", "selectedAdminAccepted")]
    [Arguments("open", "wrongAdminRejected")]
    [Arguments("open", "distinctContrasts")]
    [Arguments("open", "independentStorageQualified")]
    [Arguments("open", "adminSessionCaptureQualified")]
    [Arguments("open", "tlsCaptureQualified")]
    [Arguments("arm", "registrationId")]
    [Arguments("arm", "cursor")]
    [Arguments("arm", "armedAt")]
    [Arguments("arm", "captureArmed")]
    [Arguments("complete", "disposition")]
    [Arguments("complete", "eventId")]
    [Arguments("complete", "providerRequestId")]
    [Arguments("complete", "sequence")]
    [Arguments("complete", "settledAt")]
    [Arguments("complete", "matchedRequests")]
    [Arguments("complete", "matchedCommits")]
    [Arguments("complete", "applied")]
    [Arguments("complete", "definitionId")]
    [Arguments("complete", "independentStorageRead")]
    [Arguments("complete", "originalAttemptSettled")]
    [Arguments("complete", "excludesLateCommit")]
    [Arguments("complete", "noReplay")]
    [Arguments("observe", "definitionId")]
    [Arguments("observe", "configuration")]
    [Arguments("observe", "phase")]
    [Arguments("observe", "eventId")]
    [Arguments("observe", "sequence")]
    [Arguments("observe", "observedAt")]
    [Arguments("observe", "independentStorageRead")]
    [Arguments("observe", "persistedMergeMatches")]
    [Arguments("observe", "optionsMatch")]
    [Arguments("observe", "adminPrincipalMatches")]
    [Arguments("observe", "adminTargetMatches")]
    [Arguments("observe", "wrongAdminRejected")]
    [Arguments("observe", "actualAdminSessionCaptured")]
    [Arguments("observe", "gatewayRouteMatches")]
    [Arguments("observe", "engineQualifiedTlsMatches")]
    [Arguments("observe", "ownedCaChain")]
    [Arguments("observe", "invalidTrustRejected")]
    [Arguments("observe", "freshPublicLeaseObserved")]
    [Arguments("observe", "retainedStatementsMatch")]
    [Arguments("close", "closed")]
    [Arguments("close", "ownedRootRemoved")]
    [Arguments("close", "borrowedStatePreserved")]
    [Arguments("close", "definitionsAbsent")]
    [Arguments("close", "leasesAbsent")]
    [Arguments("close", "principalsAbsent")]
    [Arguments("close", "privateProfilesDestroyed")]
    [Arguments("close", "originalAttemptsSettled")]
    [Arguments("close", "lateCreationFenced")]
    [Arguments("close", "remainingRegistrations")]
    [Arguments("close", "pendingDeliveries")]
    public async Task ForgedQualificationAndBackwardEvidenceFailClosed(string route, string field)
    {
        using var service = new Service
        {
            Change = (actual, facts) =>
            {
                if (actual != route) return;
                JsonNode? value = facts[field];
                if (field == "registrationId" && route == "arm") facts[field] = "root-registration";
                else if (field == "sourceIdentity") facts[field] = "foreign-source";
                else if (field is "armedAt" or "settledAt" or "observedAt") facts[field] = Clock.AddSeconds(-1);
                else if (field == "definitionId") facts[field] = Guid.Empty;
                else if (field is "sequence" or "cursor") facts[field] = -1;
                else if (field == "disposition") facts[field] = (int)DispatchEvidence.Rejected;
                else if (field == "configuration") facts[field] = (int)SqlInputConfiguration.Baseline;
                else if (field is "remainingRegistrations" or "pendingDeliveries") facts[field] = 1;
                else if (field is "matchedRequests" or "matchedCommits") facts[field] = 0;
                else if (value is JsonValue scalar && scalar.TryGetValue<bool>(out _)) facts[field] = false;
                else facts[field] = "";
            }
        };
        await Assert.That(async () => await Exercise(service, route)).Throws<NativeCaseFailureException>();
        await Assert.That(service.RootExists || service.PrivateRetained).IsFalse();
    }

    [Test]
    [Arguments("attempt", "sourceProfile")]
    [Arguments("attempt", "rootNonce")]
    [Arguments("attempt", "deploymentId")]
    [Arguments("attempt", "projectId")]
    [Arguments("attempt", "environment")]
    [Arguments("attempt", "folder")]
    [Arguments("attempt", "caseIdentity")]
    [Arguments("attempt", "id")]
    public async Task ForeignRootCoordinatesNeverBind(string parent, string field)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route == "open") facts[parent]![field] = "foreign";
            }
        };
        await Assert.That(async () => await Exercise(service, "open")).Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("event")]
    [Arguments("request")]
    [Arguments("registration")]
    public async Task ReusedIdentifiersAreRejectedAcrossOriginalAttempts(string duplicate)
    {
        using var service = new Service();
        var observer = service.Observer();
        var root = Root();
        var binding = await Open(observer, root);
        var first = await observer.ArmAsync(Attempt(binding, "first"), CancellationToken.None);
        var fence = await observer.CompleteAsync(first, DispatchEvidence.Applied, CancellationToken.None);
        service.Change = (route, facts) =>
        {
            if (route == "arm" && duplicate == "registration") facts["registrationId"] = first.RegistrationId;
            if (route == "complete" && duplicate == "event") facts["eventId"] = fence.EventId;
            if (route == "complete" && duplicate == "request") facts["providerRequestId"] = fence.ProviderRequestId;
        };
        await Assert.That(async () =>
        {
            var next = await observer.ArmAsync(Attempt(binding, "second"), CancellationToken.None);
            await observer.CompleteAsync(next, DispatchEvidence.Applied, CancellationToken.None);
        }).Throws<NativeCaseFailureException>();
        await observer.CloseAsync(root, CancellationToken.None);
    }

    [Test]
    public async Task CallerCopiesAndUnsettledOrForeignBindingsCannotResume()
    {
        using var service = new Service();
        var observer = service.Observer();
        var root = Root();
        var binding = await Open(observer, root);
        await Assert.That(async () => await observer.ArmAsync(Attempt(binding with { }), CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        var arm = await observer.ArmAsync(Attempt(binding), CancellationToken.None);
        await Assert.That(async () => await observer.ArmAsync(Attempt(binding, "overlap"), CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.CompleteAsync(arm with { }, DispatchEvidence.Applied,
            CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.CompleteAsync(arm, DispatchEvidence.Pending,
            CancellationToken.None)).Throws<NativeCaseFailureException>();
        await observer.CompleteAsync(arm, DispatchEvidence.Applied, CancellationToken.None);
        await Assert.That(async () => await observer.ObserveAsync(binding, Guid.Empty,
            SqlInputConfiguration.Selected, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.CloseAsync(root with { }, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await observer.CloseAsync(root, CancellationToken.None);
        await Assert.That(async () => await Open(observer, root)).Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("schema")]
    [Arguments("nonce")]
    [Arguments("identity")]
    [Arguments("duplicate")]
    [Arguments("unknown")]
    [Arguments("http")]
    public async Task SharedChannelEnvelopeCannotForgeSourceEvidence(string fault)
    {
        using var service = new Service { EnvelopeFault = fault };
        var observer = service.Observer();
        var root = Root();
        await Assert.That(async () => await Open(observer, root)).Throws<NativeCaseFailureException>();
        service.EnvelopeFault = null;
        await observer.CloseAsync(root, CancellationToken.None);
    }

    [Test]
    [Arguments("sql.sslEnabled.true")]
    [Arguments("NativeSqlDefinitionProfile.sslEnabled.false")]
    public async Task NonMssqlSslDoesNotInventTlsCapability(string variant)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route == "open")
                {
                    facts["tlsCaptureQualified"] = false;
                    facts["routingCaptureQualified"] = false;
                }
                if (route == "observe")
                {
                    facts["ownedCaChain"] = false;
                    facts["invalidTrustRejected"] = false;
                }
            }
        };
        var observer = service.Observer();
        var root = Root();
        using var profiles = Profiles(variant, ca: null);
        var binding = await observer.OpenAsync(root, profiles, CancellationToken.None);
        var arm = await observer.ArmAsync(Attempt(binding, variant: variant), CancellationToken.None);
        await observer.CompleteAsync(arm, DispatchEvidence.Applied, CancellationToken.None);
        await observer.ObserveAsync(binding, Definition, SqlInputConfiguration.Selected, CancellationToken.None);
        await observer.CloseAsync(root, CancellationToken.None);
        await Assert.That(service.NormalizedVariant).IsEqualTo(InfisicalDynamicClientEffects.NormalizeSqlVariant(variant));
        await Assert.That(service.BaselineVariant).IsEqualTo("seed");
    }

    [Test]
    public async Task DisposedProfilesFailWithoutLeakingAndStillPermitOriginalCleanup()
    {
        using var service = new Service();
        var observer = service.Observer();
        var root = Root();
        var profiles = Profiles();
        profiles.Dispose();
        await Assert.That(async () => await observer.OpenAsync(root, profiles, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await observer.CloseAsync(root, CancellationToken.None);
        await Assert.That(service.Buffers.All(b => b.All(v => v == 0))).IsTrue();
        await Assert.That(profiles.ToString()).IsEqualTo("[SqlInputPrivateProfiles]");
        await Assert.That(root.ToString()).IsEqualTo("[SqlInputRootAttempt]");
    }

    private static async Task Exercise(Service service, string route)
    {
        var observer = service.Observer();
        var root = Root();
        try
        {
            var binding = await Open(observer, root);
            if (route == "open") return;
            var arm = await observer.ArmAsync(Attempt(binding), CancellationToken.None);
            if (route == "arm") return;
            await observer.CompleteAsync(arm, DispatchEvidence.Applied, CancellationToken.None);
            if (route == "complete") return;
            await observer.ObserveAsync(binding, Definition, SqlInputConfiguration.Selected, CancellationToken.None);
            if (route == "close") await observer.CloseAsync(root, CancellationToken.None);
        }
        finally
        {
            service.Change = null;
            if (route != "close") await observer.CloseAsync(root, CancellationToken.None);
        }
    }

    private static IEnumerable<string[]> FieldPaths(JsonObject value, string[] prefix)
    {
        foreach (var field in value)
        {
            string[] path = [.. prefix, field.Key];
            yield return path;
            if (field.Value is JsonObject child)
                foreach (string[] nested in FieldPaths(child, path)) yield return nested;
        }
    }

    private sealed class Service : HttpMessageHandler
    {
        internal Action<JsonElement>? InspectOptions { get; init; }
        internal Action<string, JsonObject>? Change { get; set; }
        internal string? LostRoute { get; set; }
        internal string? EnvelopeFault { get; set; }
        internal bool Applied { get; set; } = true;
        internal bool RootExists { get; private set; }
        internal bool PrivateRetained => privateCopies.Count != 0;
        internal bool BorrowedStatePreserved { get; } = true;
        internal bool PrivateOnlyInOpen { get; private set; } = true;
        internal string? NormalizedVariant { get; private set; }
        internal string? BaselineVariant { get; private set; }
        internal SqlInputRootAttempt? ClosedAttempt { get; private set; }
        internal List<byte[]> Buffers { get; } = [];
        internal List<string> Routes { get; } = [];
        private readonly List<byte[]> privateCopies = [];
        private long sequence;

        internal InfisicalSqlInputObserver Observer() => new(new(Settings, this, length =>
        {
            byte[] buffer = new byte[length];
            Buffers.Add(buffer);
            return buffer;
        }), Settings.Identity, SqlInputSource.ControlledFixture);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token);
            try
            {
                using var document = JsonDocument.Parse(bytes);
                var body = document.RootElement;
                string route = request.RequestUri!.AbsolutePath.Split('/').Last();
                Routes.Add(route);
                await Assert.That(request.RequestUri.AbsolutePath).IsEqualTo("/owned/sql-input/" + route);
                if (route != "open" && body.TryGetProperty("profiles", out _)) PrivateOnlyInOpen = false;
                object evidence;
                switch (route)
                {
                    case "open":
                        var root = body.GetProperty("attempt").Deserialize<SqlInputRootAttempt>(Json)!;
                        var profiles = body.GetProperty("profiles");
                        InspectOptions?.Invoke(profiles.GetProperty("options"));
                        NormalizedVariant = profiles.GetProperty("variant").GetString();
                        BaselineVariant = profiles.GetProperty("baselineVariant").GetString();
                        foreach (string key in new[] { "baseline", "selected" })
                        {
                            var profile = profiles.GetProperty(key).Deserialize<DynamicSqlInput>(Json)!;
                            await Assert.That(profile.Password).IsEqualTo(key + "-private-password");
                            privateCopies.Add(JsonSerializer.SerializeToUtf8Bytes(profile, Json));
                        }
                        RootExists = true;
                        evidence = new SqlInputBinding(root, "root-registration", Settings.Identity, "provider-clock",
                            "epoch", Clock, ++sequence, true, true, true, true, true, true, true, true, true, true);
                        break;
                    case "arm":
                        var attempt = body.GetProperty("attempt").Deserialize<SqlInputAttempt>(Json)!;
                        evidence = new SqlInputArm(attempt, "arm-" + sequence, ++sequence, Clock, true);
                        break;
                    case "complete":
                        var arm = body.GetProperty("arm").Deserialize<SqlInputArm>(Json)!;
                        var receipt = body.GetProperty("receipt").Deserialize<DispatchEvidence>(Json);
                        evidence = new SqlInputFence(arm, receipt, "event-" + sequence,
                            receipt == DispatchEvidence.NotDispatched ? null : "request-" + sequence,
                            ++sequence, Clock, receipt == DispatchEvidence.NotDispatched ? 0 : 1,
                            Applied ? 1 : 0, Applied, Definition, true, false, true, true, true);
                        break;
                    case "observe":
                        evidence = new SqlInputObservation(body.GetProperty("binding").Deserialize<SqlInputBinding>(Json)!,
                            body.GetProperty("definitionId").GetGuid(),
                            body.GetProperty("configuration").Deserialize<SqlInputConfiguration>(Json),
                            body.GetProperty("phase").GetString()!, "event-" + sequence, ++sequence, Clock,
                            true, true, true, true, true, true, true, true, true, true, true, true, true);
                        break;
                    case "close":
                        ClosedAttempt = body.GetProperty("attempt").Deserialize<SqlInputRootAttempt>(Json)!;
                        RootExists = false;
                        foreach (byte[] value in privateCopies) CryptographicOperations.ZeroMemory(value);
                        privateCopies.Clear();
                        evidence = new SqlInputCleanup(ClosedAttempt, true, true, true, true, true, true,
                            true, true, true, 0, 0);
                        break;
                    default: throw new InvalidOperationException("unexpected-route");
                }
                if (route == LostRoute) throw new HttpRequestException("synthetic-private-must-not-escape");
                JsonObject facts = JsonSerializer.SerializeToNode(evidence, Json)!.AsObject();
                Change?.Invoke(route, facts);
                if (EnvelopeFault == "unknown") facts["privateMaterial"] = "synthetic-private";
                var envelope = new JsonObject
                {
                    ["schemaVersion"] = EnvelopeFault == "schema" ? 2 : 1,
                    ["nonce"] = EnvelopeFault == "nonce" ? "foreign" : body.GetProperty("nonce").GetString(),
                    ["observerIdentity"] = EnvelopeFault == "identity" ? "foreign" : Settings.Identity,
                    ["observedAt"] = DateTimeOffset.UtcNow,
                    ["facts"] = facts
                };
                string content = envelope.ToJsonString(Json);
                if (EnvelopeFault == "duplicate") content = content.Insert(1, "\"schemaVersion\":1,");
                return new(EnvelopeFault == "http" ? HttpStatusCode.BadRequest : HttpStatusCode.OK)
                {
                    Content = new StringContent(content)
                };
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }

        protected override void Dispose(bool disposing)
        {
            foreach (byte[] value in privateCopies) CryptographicOperations.ZeroMemory(value);
            privateCopies.Clear();
            base.Dispose(disposing);
        }
    }
}
