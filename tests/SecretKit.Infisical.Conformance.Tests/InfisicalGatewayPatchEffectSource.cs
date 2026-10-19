using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Reads the provider's independently committed configuration and terminal
// validation journal. Neither Open nor Arm can apply a PATCH.
internal sealed class InfisicalGatewayPatchEffectSource(InfisicalGatewayPatchEffectFixture fixture) : HttpMessageHandler
{
    internal const string Identity = "controlled-gateway-source";
    private readonly Dictionary<string, Session> sessions = [];
    internal int Opens { get; private set; }
    internal int Observations { get; private set; }
    internal int Registrations => sessions.Count;
    internal bool PrivateCopiesDestroyed => sessions.Count == 0 && fixture.Destroyed && fixture.GatewayCount == 0;
    internal List<GatewayPatchFence> Fences { get; } = [];
    internal IGatewayPatchObserver CreateObserver(Func<int, byte[]>? allocate = null) => new InfisicalGatewayPatchObserver(
        new InfisicalLifecycleObservers(new(new("https://source.invalid/"), "private-source-token", Identity, 15), this, allocate),
        Identity, GatewayPatchSource.ControlledFixture);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token);
        JsonObject command;
        try { command = JsonNode.Parse(bytes)!.AsObject(); }
        finally { Array.Clear(bytes); }
        string nonce = command["nonce"]!.GetValue<string>();
        if (request.Headers.Authorization?.Parameter != "private-source-token") return new(HttpStatusCode.Forbidden);
        object facts;
        lock (fixture.Gate)
        {
            facts = request.RequestUri!.AbsolutePath.Split('/').Last() switch
            {
                "open" => Open(Read<GatewayPatchRootAttempt>(command, "attempt"),
                    Read<GatewayPatchAuthenticationInput>(command["profiles"]!.AsObject(), "baseline"),
                    Read<GatewayPatchAuthenticationInput>(command["profiles"]!.AsObject(), "selected")),
                "arm" => Arm(command),
                "complete" => Complete(Read<GatewayPatchArm>(command, "arm"), Read<DispatchEvidence>(command, "receipt")),
                "observe" => Observe(Read<GatewayPatchBinding>(command, "binding"), Read<GatewayPatchFence>(command, "fence")),
                "close" => Close(Read<GatewayPatchRootAttempt>(command, "attempt")),
                _ => throw new NativeCaseFailureException("observer-unavailable")
            };
        }
        command.Clear();
        return new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                nonce = nonce,
                observerIdentity = Identity,
                observedAt = DateTimeOffset.UtcNow,
                facts
            }, InfisicalGatewayPatchEffectTests.Options))
        };
    }
    private GatewayPatchBinding Open(GatewayPatchRootAttempt root, GatewayPatchAuthenticationInput baseline,
        GatewayPatchAuthenticationInput selected)
    {
        Opens++;
        if (sessions.ContainsKey(root.Id)) throw new NativeCaseFailureException("observer-unavailable");
        bool absent = fixture.ResidualCount == 0;
        fixture.RegisterRoot(root, baseline);
        var binding = new GatewayPatchBinding(root, Guid.NewGuid().ToString("D"),
            fixture.Fault == "foreign-source" ? "foreign-source" : Identity,
            "provider-application-clock", "epoch-2040", fixture.Now, fixture.Tick(),
            absent, true, true, true, true, baseline != selected, fixture.BorrowedPreserved);
        sessions.Add(root.Id, new(binding, baseline, selected));
        if (fixture.Fault == "lost-open") throw new NativeCaseFailureException("observer-unavailable");
        return binding;
    }
    private GatewayPatchArm Arm(JsonObject command)
    {
        var binding = Read<GatewayPatchBinding>(command, "binding");
        var session = Get(binding);
        string? id = command["gatewayId"]?.GetValue<string>();
        string operation = command["operation"]!.GetValue<string>();
        var before = id is null ? null : fixture.Storage(id);
        if (operation == "Update" && (before is null ||
            InfisicalGatewayPatchEffectFixture.Text(before, "name") != binding.Attempt.OriginalName))
            throw new NativeCaseFailureException("observer-unavailable");
        var arm = new GatewayPatchArm(binding, command["attemptId"]!.GetValue<string>(), Guid.NewGuid().ToString("D"),
            operation, command["variant"]!.GetValue<string>(), command["case"]!.GetValue<string>(),
            id, fixture.Tick(), fixture.Now, true);
        session.Arms.Add(arm.AttemptId, new(arm, before));
        return arm;
    }
    private GatewayPatchFence Complete(GatewayPatchArm arm, DispatchEvidence receipt)
    {
        var session = Get(arm.Binding);
        var capture = session.Arms[arm.AttemptId];
        if (capture.Arm != arm || capture.Fence is not null) throw new NativeCaseFailureException("observer-unavailable");
        var events = fixture.Requests.Where(e => e.Sequence > arm.Cursor &&
            (arm.GatewayId is not null ? e.GatewayId == arm.GatewayId :
                InfisicalGatewayPatchEffectFixture.Text(e.After, "name") == session.Binding.Attempt.OriginalName)).ToArray();
        var original = events.SingleOrDefault();
        int count = events.Sum(e => e.Count);
        string id = arm.GatewayId ?? original?.GatewayId ?? session.Binding.Attempt.OriginalName;
        bool notSent = receipt == DispatchEvidence.NotDispatched && count == 0;
        var result = new GatewayPatchFence(arm, receipt, original?.Id ?? Guid.NewGuid().ToString("D"),
            original?.Id, id, fixture.Tick(), fixture.Now, count, original?.AuthApplied ?? false,
            original?.NameApplied ?? false, notSent || original is { Settled: true },
            notSent || original is { Settled: true }, count <= 1, notSent || original is { Settled: true });
        capture.Fence = result;
        Fences.Add(result);
        return result;
    }
    private GatewayPatchObservation Observe(GatewayPatchBinding binding, GatewayPatchFence fence)
    {
        var session = Get(binding);
        var capture = session.Arms[fence.Arm.AttemptId];
        if (capture.Fence != fence || capture.Observed) throw new NativeCaseFailureException("observer-unavailable");
        capture.Observed = true; Observations++;
        var actual = fixture.Storage(fence.GatewayId);
        var selected = fence.Arm.Operation == "Create" ? session.Baseline! : session.Selected!;
        var old = capture.Before?["authMethod"]?.AsObject();
        var expected = fence.AuthenticationApplied ? Expected(selected, old) : old?.DeepClone().AsObject();
        bool config = actual is not null && expected is not null && Compare(actual["authMethod"]!.AsObject(), expected);
        string expectedName = fence.NameApplied && fence.Arm.Operation == "Update" && GatewayPatchEffects.Renames(fence.Arm.Variant) ?
            binding.Attempt.Renamed : binding.Attempt.OriginalName;
        bool name = actual is not null && InfisicalGatewayPatchEffectFixture.Text(actual, "name") == expectedName;
        bool allowed = expected is not null && ExpectedAuthentication(expected);
        InfisicalGatewayPatchEffectFixture.AuthenticationEvent? positive = null, negative = null;
        if (actual is not null)
        {
            positive = fixture.Authenticate(fence.GatewayId, false, expected!);
            negative = fixture.Authenticate(fence.GatewayId, true, expected!);
        }
        bool runtime = positive is not null && positive.Sequence > fence.Sequence &&
            positive.GatewayId == fence.GatewayId && positive.Accepted == allowed;
        bool tokenReview = positive is not null && positive.TokenReview == allowed;
        return new(binding, fence.GatewayId, fence.Arm.AttemptId, Guid.NewGuid().ToString("D"),
            fixture.Tick(), fixture.Now, actual is not null, config, config, config, config, name, runtime,
            negative is { Accepted: false }, tokenReview, fixture.BorrowedPreserved);
    }
    private GatewayPatchCleanup Close(GatewayPatchRootAttempt root)
    {
        if (!sessions.Remove(root.Id, out var session) || session.Binding.Attempt != root)
            throw new NativeCaseFailureException("cleanup-incomplete");
        bool settled = fixture.Requests.All(e => e.Settled && e.Count <= 1);
        foreach (var capture in session.Arms.Values) capture.Before?.Clear();
        session.Arms.Clear(); session.Baseline = null; session.Selected = null;
        fixture.RemoveRoot(root.Id, settled); fixture.Erase();
        return new(root, true, fixture.ResidualCount == 0, fixture.ResidualCount == 0,
            true, PrivateCopiesDestroyed, fixture.BorrowedPreserved, settled, settled,
            sessions.Count, fixture.Fault == "cleanup-pending" ? 1 : 0);
    }
    private Session Get(GatewayPatchBinding binding)
    {
        if (!sessions.TryGetValue(binding.Attempt.Id, out var session) || session.Binding != binding)
            throw new NativeCaseFailureException("observer-unavailable");
        return session;
    }
    private static T Read<T>(JsonObject command, string field) => command[field]!
        .Deserialize<T>(InfisicalGatewayPatchEffectTests.Options)!;

    // Separately authored typed expectation, never a projection of the PATCH body
    // or a borrowed copy of the service's application algorithm.
    private static JsonObject Expected(GatewayPatchAuthenticationInput p, JsonObject? previous)
    {
        string method = p.Method.ToString().ToLowerInvariant();
        var c = new JsonObject();
        JsonObject? old = previous?["method"]?.GetValue<string>() == method ? previous["config"]!.AsObject() : null;
        switch (p.Method)
        {
            case GatewayAuthenticationMethod.Aws:
                c["allowedAccountIds"] = p.AllowedAccountIds ?? "";
                c["allowedPrincipalArns"] = p.AllowedPrincipalArns ?? ""; break;
            case GatewayAuthenticationMethod.Gcp:
                c["allowedProjects"] = p.AllowedProjects ?? "";
                c["allowedServiceAccounts"] = p.AllowedServiceAccounts ?? "";
                c["allowedZones"] = p.AllowedZones ?? "";
                c["type"] = p.GcpType == GatewayGcpType.Iam ? "iam" : "gce"; break;
            case GatewayAuthenticationMethod.Kubernetes:
                c["allowedNames"] = p.AllowedNames; c["allowedNamespaces"] = p.AllowedNamespaces;
                c["allowedAudience"] = p.AllowedAudience ?? ""; c["verifyTlsCertificate"] = p.VerifyTlsCertificate ?? true;
                c["tokenReviewMode"] = p.TokenReviewMode == GatewayTokenReviewMode.Gateway ? "gateway" : "api";
                c["gatewayId"] = p.ClearGatewayId ? null : p.GatewayId;
                c["gatewayPoolId"] = p.ClearGatewayPoolId ? null : p.GatewayPoolId;
                c["kubernetesHost"] = p.KubernetesHost ?? old?["kubernetesHost"]?.GetValue<string>();
                c["caCertificate"] = p.CaCertificate ?? old?["caCertificate"]?.GetValue<string>() ?? "";
                bool retain = old is not null && Text(old, "kubernetesHost") == Text(c, "kubernetesHost") &&
                    Text(old, "tokenReviewMode") == Text(c, "tokenReviewMode") &&
                    Text(old, "gatewayId") == Text(c, "gatewayId") && Text(old, "gatewayPoolId") == Text(c, "gatewayPoolId");
                c["tokenReviewerJwt"] = p.TokenReviewerJwt ?? (retain ? Text(old, "tokenReviewerJwt") : null);
                break;
            case GatewayAuthenticationMethod.Identity:
                c["identityId"] = InfisicalGatewayPatchEffectFixture.Identity; c["identityName"] = "owned-identity"; break;
        }
        return new() { ["method"] = method, ["config"] = c };
    }
    private static bool Compare(JsonObject actual, JsonObject expected)
    {
        if (Text(actual, "method") != Text(expected, "method")) return false;
        var a = actual["config"]!.DeepClone().AsObject();
        foreach (string metadata in new[] { "id", "createdAt", "updatedAt" }) a.Remove(metadata);
        var e = expected["config"]!.DeepClone().AsObject();
        foreach (string metadata in new[] { "id", "createdAt", "updatedAt" }) e.Remove(metadata);
        return JsonNode.DeepEquals(a, e);
    }
    private static bool ExpectedAuthentication(JsonObject expected)
    {
        if (Text(expected, "method") != "kubernetes") return true;
        var c = expected["config"]!.AsObject();
        string? host = Text(c, "kubernetesHost");
        string ca = host == "https://cluster-two.invalid" ? "CA-two" : "CA-one";
        string reviewer = host == "https://cluster-two.invalid" ? "reviewer-two" : "reviewer-one";
        return host is "https://cluster-one.invalid" or "https://cluster-two.invalid" &&
            (!(c["verifyTlsCertificate"]?.GetValue<bool>() ?? true) || Text(c, "caCertificate") == ca ||
                Text(c, "caCertificate") == ca + "-selected") &&
            (Text(c, "tokenReviewerJwt") == reviewer || Text(c, "tokenReviewerJwt") == reviewer + "-selected");
    }
    private static string? Text(JsonObject? c, string field) => InfisicalGatewayPatchEffectFixture.Text(c, field);
    private sealed class Session(GatewayPatchBinding binding, GatewayPatchAuthenticationInput baseline,
        GatewayPatchAuthenticationInput selected)
    {
        internal GatewayPatchBinding Binding { get; } = binding;
        internal GatewayPatchAuthenticationInput? Baseline { get; set; } = baseline;
        internal GatewayPatchAuthenticationInput? Selected { get; set; } = selected;
        internal Dictionary<string, Capture> Arms { get; } = [];
    }
    private sealed class Capture(GatewayPatchArm arm, JsonObject? before)
    {
        internal GatewayPatchArm Arm { get; } = arm;
        internal JsonObject? Before { get; } = before;
        internal GatewayPatchFence? Fence { get; set; }
        internal bool Observed { get; set; }
    }
}
