using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// This private source has no management-write API. It reads service storage and
// separately authored reference and backend inventories through the fixture.
internal sealed class InfisicalProxyPatchEffectSource(InfisicalProxyPatchEffectFixture fixture) : HttpMessageHandler
{
    internal const string Identity = "controlled-proxy-source";
    private readonly Dictionary<string, Session> sessions = [];
    internal int Opens { get; private set; }
    internal int Observations { get; private set; }
    internal int Registrations => sessions.Count;
    internal bool PrivateCopiesDestroyed => sessions.Count == 0 && fixture.PrivateCopiesDestroyed;
    internal readonly List<ProxyPatchFence> Fences = [];
    internal InfisicalLifecycleObservers.Settings Settings => new(new("https://source.invalid/"),
        "private-source-token", Identity, 15);
    internal IProxyPatchObserver CreateObserver() => new InfisicalProxyPatchObserver(
        new InfisicalLifecycleObservers(Settings, this), Identity, ProxyPatchSource.ControlledFixture);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token);
        JsonObject command;
        try { command = JsonNode.Parse(bytes)!.AsObject(); }
        finally { Array.Clear(bytes); }
        if (request.Headers.Authorization?.Parameter != "private-source-token")
            return new(HttpStatusCode.Forbidden);
        if (request.RequestUri!.AbsolutePath.EndsWith("/observe", StringComparison.Ordinal))
        {
            var fence = Read<ProxyPatchFence>(command, "fence");
            var storage = fixture.Storage(fence.ServiceId);
            if (storage is not null)
                foreach (JsonObject row in storage["credentials"]!.AsArray().Cast<JsonObject>())
                {
                    var role = row["role"]!.GetValue<string>() == "header-rewrite" ?
                        ProxiedServiceCredentialRole.HeaderRewrite : ProxiedServiceCredentialRole.CredentialSubstitution;
                    var surface = Enum.Parse<ProxiedServiceSubstitutionSurface>(
                        row["substitutionSurfaces"]?[0]?.GetValue<string>() ?? "header", true);
                    string challenge = Guid.NewGuid().ToString("N");
                    using var allowed = await fixture.SendThroughAsync(fence.ServiceId, challenge, role, surface, new Tokens("runtime-token"), token);
                    using var denied = await fixture.SendThroughAsync(fence.ServiceId, challenge, role, surface, new Tokens("denied-token"), token);
                }
        }
        object facts;
        lock (fixture.Gate)
        {
            facts = request.RequestUri!.AbsolutePath.Split('/').Last() switch
            {
                "open" => Open(Read<ProxyPatchRootAttempt>(command, "attempt")),
                "arm" => Arm(command),
                "complete" => Complete(Read<ProxyPatchArm>(command, "arm"), Read<DispatchEvidence>(command, "receipt")),
                "observe" => Observe(Read<ProxyPatchBinding>(command, "binding"), Read<ProxyPatchFence>(command, "fence")),
                "close" => Close(Read<ProxyPatchRootAttempt>(command, "attempt")),
                _ => throw new NativeCaseFailureException("observer-unavailable")
            };
        }
        return new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                nonce = command["nonce"]!.GetValue<string>(),
                observerIdentity = Identity,
                observedAt = DateTimeOffset.UtcNow,
                facts
            }, InfisicalProxyPatchEffectTests.Options))
        };
    }

    private ProxyPatchBinding Open(ProxyPatchRootAttempt attempt)
    {
        Opens++;
        if (sessions.ContainsKey(attempt.Id)) throw new NativeCaseFailureException("observer-unavailable");
        bool absent = fixture.ServiceCount == 0;
        var binding = new ProxyPatchBinding(attempt, Guid.NewGuid().ToString("N"),
            fixture.Mode == "source-foreign" ? "foreign-source" : Identity, "provider-application-clock", "epoch-2040",
            fixture.Now, fixture.Tick(), absent, true, true, true, true, true, fixture.BorrowedStatePreserved);
        sessions.Add(attempt.Id, new(binding));
        return binding;
    }

    private ProxyPatchArm Arm(JsonObject command)
    {
        var binding = Read<ProxyPatchBinding>(command, "binding");
        var session = Get(binding);
        string? serviceId = command["serviceId"]?.GetValue<string>();
        JsonObject? baseline = serviceId is null ? null : fixture.Storage(serviceId);
        var arm = new ProxyPatchArm(binding, command["attemptId"]!.GetValue<string>(),
            Guid.NewGuid().ToString("N"), command["operation"]!.GetValue<string>(),
            command["variant"]!.GetValue<string>(), command["case"]!.GetValue<string>(),
            serviceId, fixture.Tick(), fixture.Now, true);
        session.Arms.Add(arm.AttemptId, new(arm, baseline, Expected(arm, baseline)));
        return arm;
    }

    private ProxyPatchFence Complete(ProxyPatchArm arm, DispatchEvidence receipt)
    {
        var session = Get(arm.Binding);
        if (!session.Arms.TryGetValue(arm.AttemptId, out var captured) || captured.Arm != arm || captured.Completed)
            throw new NativeCaseFailureException("observer-unavailable");
        captured.Completed = true;
        var requests = fixture.Patches.Where(e => e.Sequence > arm.Cursor &&
            (arm.ServiceId is null || e.ServiceId == arm.ServiceId)).ToArray();
        var selected = requests.SingleOrDefault();
        int count = requests.Sum(r => r.Requests);
        string serviceId = arm.ServiceId ?? selected?.ServiceId ?? arm.Binding.Attempt.OriginalName;
        bool noDispatch = receipt == DispatchEvidence.NotDispatched && count == 0;
        bool validated = noDispatch || selected is { Validated: true } &&
            fixture.Validations.Any(v => v.Sequence > arm.Cursor && v.ServiceId == serviceId &&
                v.Action == (arm.Operation == "Create" ? "Create" : "Edit"));
        var fence = new ProxyPatchFence(arm, receipt, selected?.EventId ?? Guid.NewGuid().ToString("N"),
            selected?.EventId, serviceId, fixture.Tick(), fixture.Now, count,
            fixture.Commits.Count(c => requests.Any(r => r.EventId == c.RequestEventId)), selected?.Applied ?? false,
            noDispatch || selected is { Settled: true }, noDispatch || selected is { Settled: true },
            noDispatch || selected is { NoReplay: true } && count == 1, validated, fixture.PendingActions);
        captured.Fence = fence;
        Fences.Add(fence);
        return fence;
    }

    private ProxyPatchObservation Observe(ProxyPatchBinding binding, ProxyPatchFence fence)
    {
        var session = Get(binding);
        if (!session.Arms.TryGetValue(fence.Arm.AttemptId, out var captured) || captured.Fence != fence)
            throw new NativeCaseFailureException("observer-unavailable");
        Observations++;
        var actual = fixture.Storage(fence.ServiceId);
        var patch = fixture.Patches.SingleOrDefault(e => e.EventId == fence.EventId);
        JsonObject? expected = fence.Applied ? captured.Expected : captured.Baseline;
        // ExpectedSelected is an independent complete expected projection.
        // Reject an uncalibrated source rather than deriving intent from wire.
        bool rows = actual is not null && expected is not null && Same(actual, expected);
        bool options = rows;
        bool omitted = patch is null || patch.SuppliedArray || captured.Baseline is not null && actual is not null &&
            JsonNode.DeepEquals(actual["credentials"], captured.Baseline["credentials"]);
        bool removed = !fence.Applied || fence.Arm.Operation == "Create" || patch is null || !patch.SuppliedArray ||
            actual is not null && captured.Baseline is not null &&
            !actual["credentials"]!.AsArray().Any(r => r!["id"]!.GetValue<string>() ==
                captured.Baseline["credentials"]![1]!["id"]!.GetValue<string>());
        var deliveries = fixture.Deliveries.Where(d => d.Sequence > fence.Sequence && d.ServiceId == fence.ServiceId).ToArray();
        var allowed = deliveries.Where(d => d.Actor == "runtime-token").ToArray();
        var denied = deliveries.Where(d => d.Actor == "denied-token").ToArray();
        bool enabled = actual?["isEnabled"]?.GetValue<bool>() == true;
        bool Matches(InfisicalProxyPatchEffectFixture.DeliveryEvent delivery)
        {
            var row = expected?["credentials"]!.AsArray().Cast<JsonObject>().FirstOrDefault(r =>
                r["role"]!.GetValue<string>() == delivery.Role &&
                (r["substitutionSurfaces"]?[0]?.GetValue<string>() ?? "header") == delivery.Surface);
            string? key = InfisicalProxyPatchEffectFixture.Text(row, "secretKey") ??
                InfisicalProxyPatchEffectFixture.Text(row, "dynamicSecretName");
            string? value = fixture.ReferenceValue(key);
            string prefix = InfisicalProxyPatchEffectFixture.Text(row, "headerPrefix") ?? "";
            return enabled && value is not null ? delivery.Requests == 1 && delivery.Value == prefix + value :
                delivery.Requests == 0 && delivery.Value is null;
        }
        bool runtime = allowed.Length > 0 && allowed.All(Matches);
        bool wrong = allowed.Length > 0 && allowed.All(Matches);
        bool deniedAbsent = denied.Length > 0 && denied.All(d => d.Requests == 0 && d.Value is null);
        bool authority = (!fence.Applied || fence.OriginalReferencesValidated) &&
            fixture.Validations.Where(v => v.Sequence > fence.Arm.Cursor && v.ServiceId == fence.ServiceId)
                .All(v => v.Action == (fence.Arm.Operation == "Create" ? "Create" : "Edit") &&
                    v.Privilege is "None" or "ReadValue" or "Lease" &&
                    (!v.Accepted || v.Privilege != "Lease" || v.Brokerable && v.Entitled));
        return new(binding, fence.ServiceId, fence.Arm.AttemptId, Guid.NewGuid().ToString("N"),
            fixture.Tick(), fixture.Now, true, rows, options, omitted, removed, runtime, wrong,
            deniedAbsent, authority, fixture.BorrowedStatePreserved);
    }

    private ProxyPatchCleanup Close(ProxyPatchRootAttempt attempt)
    {
        if (!sessions.Remove(attempt.Id, out var session)) throw new NativeCaseFailureException("cleanup-incomplete");
        bool settled = session.Arms.Values.All(a => a.Completed && a.Fence is { OriginalAttemptSettled: true, NoReplay: true });
        session.Arms.Clear();
        fixture.DestroyJournalCopies();
        return new(attempt, true, fixture.ResidualCount == 0, fixture.ReferenceCount == 0,
            fixture.ServiceCount == 0, fixture.BorrowedStatePreserved, fixture.PrivateCopiesDestroyed,
            settled, settled && fixture.Mode != "late", sessions.Count, fixture.PendingActions);
    }

    internal static bool Same(JsonObject actual, JsonObject expected)
    {
        foreach (string field in new[] { "name", "hostPattern", "isEnabled" })
            if (!JsonNode.DeepEquals(actual[field], expected[field])) return false;
        var a = actual["credentials"]!.AsArray();
        var e = expected["credentials"]!.AsArray();
        if (a.Count != e.Count) return false;
        for (int i = 0; i < a.Count; i++)
            foreach (string field in InfisicalProxyPatchEffectFixture.OptionalFields.Prepend("role"))
                if (!JsonNode.DeepEquals(a[i]![field], e[i]![field])) return false;
        return true;
    }

    private JsonObject Expected(ProxyPatchArm arm, JsonObject? baseline)
    {
        string name = arm.Binding.Attempt.OriginalName;
        var first = fixture.Keys(name + "-first");
        var second = fixture.Keys(name + "-second");
        var selected = fixture.Keys(name + "-selected");
        if (arm.Operation == "Create")
            return new()
            {
                ["name"] = name,
                ["hostPattern"] = "baseline.invalid",
                ["isEnabled"] = true,
                ["credentials"] = new JsonArray(
                    arm.Variant == "calibration-seed" ?
                        Row("header-rewrite", first[0], first[1], "password", "X-First", "First ", "password",
                            "SK_FIRST", "BASELINE", "header") :
                        Row("header-rewrite", first[0], header: "X-First", prefix: "First ", purpose: "password"),
                    Row("credential-substitution", second[0], placeholderKey: "SK_SECOND", surface: "query"))
            };
        var expected = baseline!.DeepClone().AsObject();
        string v = arm.Variant;
        bool Omitted(string field) => v == "ProxiedServiceCredentialInput." + field + ".omitted";
        bool dynamic = v == "credential.dynamic-secret" || v.Contains("dynamicSecret", StringComparison.Ordinal);
        bool substitution = v.Contains("placeholder", StringComparison.Ordinal) ||
            v.Contains("substitutionSurfaces", StringComparison.Ordinal) ||
            v == "credential.role.CredentialSubstitution" || v.StartsWith("credential.surface.", StringComparison.Ordinal);
        string surface = v.StartsWith("credential.surface.", StringComparison.Ordinal) ? v.Split('.')[2].ToLowerInvariant() : "header";
        if (v == "ProxiedServiceUpdate.name.value") expected["name"] = arm.Binding.Attempt.Renamed;
        if (v == "ProxiedServiceUpdate.hostPattern.value") expected["hostPattern"] = "selected.invalid";
        if (v == "ProxiedServiceUpdate.isEnabled.false") expected["isEnabled"] = false;
        if (v == "ProxiedServiceUpdate.isEnabled.true") expected["isEnabled"] = true;
        if (v is not ("patch.empty" or "credentials.omitted" or "ProxiedServiceUpdate.credentials.omitted"))
            expected["credentials"] = new JsonArray(Row(substitution ? "credential-substitution" : "header-rewrite",
                !dynamic && !Omitted("secretKey") ? selected[0] : null,
                dynamic && !Omitted("dynamicSecretName") ? selected[1] : null,
                dynamic && !Omitted("dynamicSecretField") ? "password" : null,
                Omitted("headerName") ? null : "X-Selected",
                v == "ProxiedServiceCredentialInput.headerPrefix.value" ? "Selected " : null,
                Omitted("headerPurpose") ? null : v.EndsWith(".Username", StringComparison.Ordinal) ? "username" : "password",
                substitution && !Omitted("placeholderKey") ? "SK_SELECTED" : null,
                v == "ProxiedServiceCredentialInput.placeholderValue.value" ? "SK_SELECTED" : null,
                substitution && !Omitted("substitutionSurfaces") ? surface : null));
        return expected;
    }

    private static JsonObject Row(string role, string? key, string? dynamic = null, string? field = null,
        string? header = null, string? prefix = null, string? purpose = null, string? placeholderKey = null,
        string? placeholder = null, string? surface = null) => new()
        {
            ["role"] = role,
            ["secretKey"] = key,
            ["dynamicSecretName"] = dynamic,
            ["dynamicSecretField"] = field,
            ["headerName"] = header,
            ["headerPrefix"] = prefix,
            ["headerPurpose"] = purpose,
            ["placeholderKey"] = placeholderKey,
            ["placeholderValue"] = placeholder,
            ["substitutionSurfaces"] = surface is null ? null : new JsonArray(JsonValue.Create(surface))
        };

    private sealed class Tokens(string selected) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText(selected))));
        }
    }

    private Session Get(ProxyPatchBinding binding) =>
        sessions.TryGetValue(binding.Attempt.Id, out var session) && session.Binding == binding ? session :
            throw new NativeCaseFailureException("observer-unavailable");
    private static T Read<T>(JsonObject body, string field) =>
        body[field]!.Deserialize<T>(InfisicalProxyPatchEffectTests.Options)!;
    private sealed class Session(ProxyPatchBinding binding)
    {
        internal ProxyPatchBinding Binding { get; } = binding;
        internal Dictionary<string, Capture> Arms { get; } = [];
    }
    private sealed class Capture(ProxyPatchArm arm, JsonObject? baseline, JsonObject? expected)
    {
        internal ProxyPatchArm Arm { get; } = arm;
        internal JsonObject? Baseline { get; } = baseline;
        internal JsonObject? Expected { get; } = expected;
        internal bool Completed { get; set; }
        internal ProxyPatchFence? Fence { get; set; }
    }
}
