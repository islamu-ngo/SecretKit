using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Offline characterization of the channel and local callback, not native
// provider expiry certification or handler test-first evidence.
public sealed class InfisicalMembershipExpiryObserverTests
{
    private static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private static readonly InfisicalLifecycleObservers.Settings Settings =
        new(new("https://observer.invalid/owned/"), "service-token", "independent-service", 30);
    private static readonly DateTimeOffset Clock = DateTimeOffset.UnixEpoch.AddDays(1);
    private static MembershipExpiryIntent Intent(string? existing = "membership") =>
        new(new("attempt", "case", "organization", "project", MembershipExpiryPrincipal.Identity,
            "principal", "runtime", existing, MembershipExpirySource.ControlledFixture), "1m", 10);

    [Test]
    [Arguments("Applied", "membership")]
    [Arguments("Applied", null)]
    [Arguments("Rejected", "membership")]
    [Arguments("Rejected", null)]
    public async Task BracketsActualCallbackStateAcrossAllPhases(string disposition, string? existing)
    {
        using var service = new Service { Disposition = Enum.Parse<MembershipExpiryDisposition>(disposition) };
        var observer = service.CreateObserver();
        var intent = Intent(existing);
        var arm = await observer.ArmAsync(intent, CancellationToken.None);
        var binding = await observer.CompleteAsync(arm, CancellationToken.None);
        foreach (MembershipExpiryPhase phase in Enum.GetValues<MembershipExpiryPhase>())
        {
            var observation = await observer.ObserveAsync(binding, phase, token =>
            {
                token.ThrowIfCancellationRequested();
                if (!service.WindowOpen) throw new InvalidOperationException("callback-not-bracketed");
                service.CallbackState++;
                service.Time = service.Time.AddSeconds(1);
                return ValueTask.FromResult(service.CallbackState);
            }, CancellationToken.None);
            await Assert.That(observation.Sample).IsEqualTo(service.CallbackState);
            await Assert.That(observation.Window.ClosedAt).IsEqualTo(service.Time);
            await Assert.That(service.ClosedCallbackState).IsEqualTo(service.CallbackState);
            await Assert.That(service.WindowOpen).IsFalse();
        }
        var cleanup = await observer.CloseAsync(intent.Attempt, CancellationToken.None);
        await Assert.That(cleanup.RemainingRegistrations).IsEqualTo(0);
        await Assert.That(service.Registered).IsFalse();
        await Assert.That(service.CallbackState).IsEqualTo(3);
        await Assert.That(observer.ToString()).IsEqualTo("[InfisicalMembershipExpiryObserver]");
    }

    [Test]
    [Arguments("source")]
    [Arguments("identity")]
    [Arguments("clock")]
    [Arguments("epoch")]
    [Arguments("capture")]
    [Arguments("intent")]
    [Arguments("cursor")]
    [Arguments("starts")]
    [Arguments("duration")]
    [Arguments("utc")]
    [Arguments("registration")]
    public async Task ArmRejectsSubstitutionAndInvalidSchedule(string mode)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route != "arm") return;
                switch (mode)
                {
                    case "source": facts["intent"]!["attempt"]!["source"] = "NativeProvider"; break;
                    case "identity": facts["sourceIdentity"] = "other"; break;
                    case "clock": facts["clockAuthority"] = ""; break;
                    case "epoch": facts["clockEpoch"] = new string('a', 513); break;
                    case "capture": facts["captureArmed"] = false; break;
                    case "intent": facts["intent"]!["attempt"]!["runtimePrincipalId"] = "other"; break;
                    case "cursor": facts["cursor"] = -1; break;
                    case "starts": facts["startsAt"] = Clock; break;
                    case "duration": facts["endsAt"] = Clock.AddSeconds(71); break;
                    case "utc": facts["armedAt"] = Clock.ToOffset(TimeSpan.FromHours(1)); break;
                    case "registration": facts["registrationId"] = "bad\nid"; break;
                }
            }
        };
        var observer = service.CreateObserver();
        var intent = Intent();
        await Assert.That(async () => await observer.ArmAsync(intent, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await observer.CloseAsync(intent.Attempt, CancellationToken.None);
        await Assert.That(service.Registered).IsFalse();
    }

    [Test]
    [Arguments("source")]
    [Arguments("principal")]
    [Arguments("duration")]
    [Arguments("lead")]
    [Arguments("id")]
    [Arguments("long")]
    public async Task InvalidIntentCannotRegister(string mode)
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var intent = Intent();
        intent = mode switch
        {
            "source" => intent with { Attempt = intent.Attempt with { Source = MembershipExpirySource.NativeProvider } },
            "principal" => intent with { Attempt = intent.Attempt with { PrincipalKind = (MembershipExpiryPrincipal)99 } },
            "duration" => intent with { RelativeDuration = "60s" },
            "lead" => intent with { ActivationLeadSeconds = 0 },
            "id" => intent with { Attempt = intent.Attempt with { Id = "bad\nid" } },
            _ => intent with { Attempt = intent.Attempt with { CaseIdentity = new string('a', 513) } }
        };
        await Assert.That(async () => await observer.ArmAsync(intent, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(service.Registered).IsFalse();
    }

    [Test]
    [Arguments("arm")]
    [Arguments("request")]
    [Arguments("sequence")]
    [Arguments("fence")]
    [Arguments("membership")]
    [Arguments("assignment")]
    [Arguments("not-dispatched")]
    [Arguments("undefined")]
    [Arguments("rejected-assignment")]
    [Arguments("rejected-membership")]
    public async Task CompletionRequiresBoundTerminalProviderEvidence(string mode)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route != "complete") return;
                switch (mode)
                {
                    case "arm": facts["arm"]!["clockAuthority"] = "other"; break;
                    case "request": facts["providerRequestId"] = ""; break;
                    case "sequence": facts["sequence"] = 1; break;
                    case "fence": facts["excludesLateCommit"] = false; break;
                    case "membership": facts["membershipId"] = "other"; break;
                    case "assignment": facts["assignmentId"] = null; break;
                    case "not-dispatched": facts["disposition"] = "NotDispatched"; break;
                    case "undefined": facts["disposition"] = 99; break;
                    case "rejected-assignment": facts["disposition"] = "Rejected"; break;
                    case "rejected-membership":
                        facts["disposition"] = "Rejected";
                        facts["assignmentId"] = null;
                        facts["membershipId"] = null;
                        break;
                }
            }
        };
        var observer = service.CreateObserver();
        var intent = Intent();
        var arm = await observer.ArmAsync(intent, CancellationToken.None);
        await Assert.That(async () => await observer.CompleteAsync(arm, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await observer.CloseAsync(intent.Attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("binding")]
    [Arguments("phase")]
    [Arguments("authority")]
    [Arguments("event")]
    [Arguments("sequence")]
    [Arguments("time")]
    [Arguments("utc")]
    public async Task OpenRejectsFalseEventBeforeInvokingCallback(string mode)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route != "open") return;
                switch (mode)
                {
                    case "binding": facts["binding"]!["arm"]!["clockEpoch"] = "other"; break;
                    case "phase": facts["phase"] = "Active"; break;
                    case "authority": facts["authoritative"] = false; break;
                    case "event": facts["eventObserved"] = false; break;
                    case "sequence": facts["sequence"] = 2; break;
                    case "time": facts["openedAt"] = Clock.AddSeconds(10); break;
                    case "utc": facts["openedAt"] = Clock.ToOffset(TimeSpan.FromHours(1)); break;
                }
            }
        };
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent(), CancellationToken.None);
        var binding = await observer.CompleteAsync(arm, CancellationToken.None);
        await Assert.That(async () => await observer.ObserveAsync(binding, MembershipExpiryPhase.BeforeActivation,
            _ => { service.CallbackState++; return ValueTask.FromResult(true); }, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(service.CallbackState).IsEqualTo(0);
        await Assert.That(service.WindowOpen).IsFalse();
        await observer.CloseAsync(arm.Intent.Attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("crossover")]
    [Arguments("sequence")]
    [Arguments("window")]
    [Arguments("event")]
    [Arguments("authority")]
    [Arguments("binding")]
    [Arguments("opened")]
    [Arguments("phase")]
    [Arguments("reverse")]
    public async Task ClosureRequiresEntireCallbackIntervalWithinPhase(string mode)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route != "close-window") return;
                switch (mode)
                {
                    case "sequence": facts["sequence"] = 3; break;
                    case "window": facts["windowId"] = "other"; break;
                    case "event": facts["eventId"] = "other"; break;
                    case "authority": facts["authoritative"] = false; break;
                    case "binding": facts["binding"]!["assignmentId"] = "other"; break;
                    case "opened": facts["openedAt"] = Clock.AddSeconds(1); break;
                    case "phase": facts["phase"] = "Active"; break;
                    case "reverse": facts["closedAt"] = Clock.AddSeconds(-1); break;
                }
            }
        };
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent(), CancellationToken.None);
        var binding = await observer.CompleteAsync(arm, CancellationToken.None);
        await Assert.That(async () => await observer.ObserveAsync(binding, MembershipExpiryPhase.BeforeActivation,
            _ =>
            {
                if (!service.WindowOpen) throw new InvalidOperationException("callback-not-bracketed");
                service.CallbackState++;
                if (mode == "crossover") service.Time = arm.StartsAt;
                return ValueTask.FromResult(true);
            }, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(service.ClosedCallbackState).IsEqualTo(1);
        await observer.CloseAsync(arm.Intent.Attempt, CancellationToken.None);
    }

    [Test]
    [Arguments(false, false)]
    [Arguments(true, false)]
    [Arguments(false, true)]
    [Arguments(true, true)]
    public async Task CallbackFailureStillClosesWithoutCallerCancellation(bool cancel, bool lostClosure)
    {
        using var service = new Service
        {
            LostRoute = lostClosure ? "close-window" : null
        };
        using var stop = new CancellationTokenSource();
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent(), CancellationToken.None);
        var binding = await observer.CompleteAsync(arm, CancellationToken.None);
        var failure = new InvalidOperationException("callback-failed");
        Exception? seen = null;
        try
        {
            await observer.ObserveAsync<bool>(binding, MembershipExpiryPhase.BeforeActivation, token =>
            {
                service.CallbackState++;
                if (cancel)
                {
                    stop.Cancel();
                    token.ThrowIfCancellationRequested();
                }
                throw failure;
            }, stop.Token);
        }
        catch (Exception error) { seen = error; }
        if (lostClosure)
        {
            await Assert.That(seen is NativeCaseFailureException).IsTrue();
            await Assert.That(seen!.Message).IsEqualTo("cleanup-incomplete");
        }
        else if (cancel) await Assert.That(seen is OperationCanceledException).IsTrue();
        else await Assert.That(ReferenceEquals(seen, failure)).IsTrue();
        await Assert.That(service.WindowOpen).IsFalse();
        await Assert.That(service.ClosedCallbackState).IsEqualTo(1);
        await observer.CloseAsync(arm.Intent.Attempt, stop.Token);
        await Assert.That(service.Registered).IsFalse();
    }

    [Test]
    public async Task CallerCannotReplacePinnedEvidenceOrReuseConsumedPhase()
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var intent = Intent();
        var arm = await observer.ArmAsync(intent, CancellationToken.None);
        await Assert.That(async () => await observer.CompleteAsync(arm with { ClockEpoch = "other" }, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        var binding = await observer.CompleteAsync(arm, CancellationToken.None);
        await Assert.That(async () => await observer.ObserveAsync(binding with { Sequence = 99 },
            MembershipExpiryPhase.BeforeActivation, Sample, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.ObserveAsync(binding, MembershipExpiryPhase.Active, Sample,
            CancellationToken.None)).Throws<NativeCaseFailureException>();
        await observer.ObserveAsync(binding, MembershipExpiryPhase.BeforeActivation, Sample, CancellationToken.None);
        await Assert.That(async () => await observer.ObserveAsync(binding, MembershipExpiryPhase.BeforeActivation, Sample,
            CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.CloseAsync(intent.Attempt with { ProjectId = "other" },
            CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.ArmAsync(intent, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await observer.CloseAsync(intent.Attempt, CancellationToken.None);
        await Assert.That(async () => await observer.ObserveAsync(binding, MembershipExpiryPhase.Active, Sample,
            CancellationToken.None)).Throws<NativeCaseFailureException>();
    }

    [Test]
    public async Task ExplicitLocalNotDispatchedFenceDoesNotContactCompletionEndpoint()
    {
        using var service = new Service { LostRoute = "complete" };
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent(), CancellationToken.None);
        // This is a local infrastructure seam only. The parent must supply the
        // actual pre-dispatch receipt before constructing this evidence.
        var binding = new MembershipExpiryFence(arm, null, MembershipExpiryDisposition.NotDispatched,
            arm.Intent.Attempt.ExistingMembershipId, null, arm.Cursor + 1, true);
        await observer.ObserveAsync(binding, MembershipExpiryPhase.BeforeActivation, Sample, CancellationToken.None);
        await observer.CloseAsync(arm.Intent.Attempt, CancellationToken.None);
        await Assert.That(service.Registered).IsFalse();
    }

    [Test]
    [Arguments("attempt")]
    [Arguments("closed")]
    [Arguments("lateCreationFenced")]
    [Arguments("mutationSettled")]
    [Arguments("inventoryComplete")]
    [Arguments("remainingRegistrations")]
    [Arguments("pendingDeliveries")]
    [Arguments("lost")]
    public async Task LostArmStillRequiresExactAcknowledgedAttemptCleanup(string mode)
    {
        using var service = new Service
        {
            LostRoute = "arm",
            Change = (route, facts) =>
            {
                if (route != "close") return;
                if (mode == "attempt") facts["attempt"]!["id"] = "other";
                else if (mode is "remainingRegistrations" or "pendingDeliveries") facts[mode] = 1;
                else if (mode != "lost") facts[mode] = false;
            }
        };
        var observer = service.CreateObserver();
        var intent = Intent();
        await Assert.That(async () => await observer.ArmAsync(intent, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(service.Registered).IsTrue();
        if (mode == "lost") service.LostRoute = "close";
        await Assert.That(async () => await observer.CloseAsync(intent.Attempt, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        service.Change = null;
        service.LostRoute = null;
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await observer.CloseAsync(intent.Attempt, canceled.Token);
        await Assert.That(service.Registered).IsFalse();
    }

    [Test]
    [Arguments("arm")]
    [Arguments("complete")]
    [Arguments("open")]
    [Arguments("close-window")]
    [Arguments("close")]
    public async Task EveryEvidenceFieldIncludingNestedFieldsIsRequired(string route)
    {
        MembershipExpiryArm arm = new(Intent(), "registration", Settings.Identity, "fixture-clock", "epoch",
            Clock, Clock.AddSeconds(10), Clock.AddSeconds(70), 1, true);
        MembershipExpiryFence fence = new(arm, "provider-request", MembershipExpiryDisposition.Applied,
            "membership", "assignment", 2, true);
        object evidence = route switch
        {
            "arm" => arm,
            "complete" => fence,
            "open" or "close-window" => new MembershipExpiryWindow(fence, MembershipExpiryPhase.BeforeActivation,
                "window", "event", 3, Clock, Clock, true, true),
            _ => new MembershipExpiryCleanup(Intent().Attempt, true, true, true, true, 0, 0)
        };
        foreach (string[] path in FieldPaths(JsonSerializer.SerializeToNode(evidence, Json)!.AsObject(), []))
        {
            using var service = new Service
            {
                Change = (current, facts) =>
                {
                    if (current != route) return;
                    JsonObject owner = facts;
                    foreach (string part in path[..^1]) owner = owner[part]!.AsObject();
                    owner.Remove(path[^1]);
                }
            };
            var observer = service.CreateObserver();
            await Assert.That(async () =>
            {
                var armed = await observer.ArmAsync(Intent(), CancellationToken.None);
                var bound = await observer.CompleteAsync(armed, CancellationToken.None);
                await observer.ObserveAsync(bound, MembershipExpiryPhase.BeforeActivation, Sample, CancellationToken.None);
                await observer.CloseAsync(armed.Intent.Attempt, CancellationToken.None);
            }).Throws<NativeCaseFailureException>();
            service.Change = null;
            await observer.CloseAsync(Intent().Attempt, CancellationToken.None);
            await Assert.That(service.Registered).IsFalse();
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task FamilyRootSelectionNeverImportsControlledServiceAuthority(bool configured)
    {
        JsonObject family = new();
        if (configured) family["observer"] = JsonSerializer.SerializeToNode(Settings, Json);
        using var document = EnvironmentInput(family);
        using var environment = NativeEnvironment.Create(document.RootElement);
        var observer = InfisicalMembershipExpiryObserver.FromInputs(environment, "C08-IM-ProjectMemberships");
        await Assert.That(observer is not null).IsEqualTo(configured);
        if (observer is not null)
            await Assert.That(async () => await observer.ArmAsync(Intent(), CancellationToken.None))
                .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("ControlledFixture")]
    [Arguments("unknown")]
    [Arguments("1")]
    public async Task NativeInputsRejectControlledOrInvalidSource(string selected)
    {
        var settings = JsonSerializer.SerializeToNode(Settings, Json)!.AsObject();
        settings["source"] = selected == "1" ? JsonValue.Create(1) : JsonValue.Create(selected);
        using var document = EnvironmentInput(new() { ["observer"] = settings });
        using var environment = NativeEnvironment.Create(document.RootElement);
        await Assert.That(() => InfisicalMembershipExpiryObserver.FromInputs(environment, "C08-IM-ProjectMemberships"))
            .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("endpoint")]
    [Arguments("token")]
    [Arguments("identity")]
    [Arguments("timeoutSeconds")]
    public async Task FamilyRootSettingsRequireEveryChannelField(string field)
    {
        var settings = JsonSerializer.SerializeToNode(Settings, Json)!.AsObject();
        settings.Remove(field);
        using var document = EnvironmentInput(new() { ["observer"] = settings });
        using var environment = NativeEnvironment.Create(document.RootElement);
        await Assert.That(() => InfisicalMembershipExpiryObserver.FromInputs(environment, "C08-IM-ProjectMemberships"))
            .Throws<NativeCaseFailureException>();
    }

    private static ValueTask<bool> Sample(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return ValueTask.FromResult(true);
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

    private static JsonDocument EnvironmentInput(JsonObject family) => JsonDocument.Parse(new JsonObject
    {
        ["origin"] = "https://infisical.invalid",
        ["setup"] = "setup",
        ["runtime"] = "runtime",
        ["denied"] = "denied",
        ["administrative"] = "administrative",
        ["observer"] = "observer",
        ["families"] = new JsonObject { ["C08-IM-ProjectMemberships"] = family }
    }.ToJsonString());

    private sealed class Service : HttpMessageHandler
    {
        internal Action<string, JsonObject>? Change { get; set; }
        internal string? LostRoute { get; set; }
        internal MembershipExpiryDisposition Disposition { get; init; } = MembershipExpiryDisposition.Applied;
        internal bool Registered { get; private set; }
        internal bool WindowOpen { get; private set; }
        internal int CallbackState { get; set; }
        internal int ClosedCallbackState { get; private set; }
        internal DateTimeOffset Time { get; set; } = Clock;
        private MembershipExpiryArm? arm;
        private MembershipExpiryWindow? window;
        private long sequence = 2;

        internal InfisicalMembershipExpiryObserver CreateObserver() =>
            new(new(Settings, this), Settings.Identity, MembershipExpirySource.ControlledFixture);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            JsonObject body = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
            await Assert.That(request.Headers.Authorization!.Parameter).IsEqualTo(Settings.Token);
            string route = request.RequestUri!.AbsolutePath.Split('/').Last();
            await Assert.That(request.RequestUri.AbsolutePath).IsEqualTo("/owned/membership-expiry/" + route);
            object evidence;
            switch (route)
            {
                case "arm":
                    var intent = body["intent"]!.Deserialize<MembershipExpiryIntent>(Json)!;
                    Registered = true;
                    arm = new(intent, "registration", Settings.Identity, "fixture-clock", "epoch",
                        Clock, Clock.AddSeconds(intent.ActivationLeadSeconds),
                        Clock.AddSeconds(intent.ActivationLeadSeconds + 60), 1, true);
                    evidence = arm;
                    break;
                case "complete":
                    await Assert.That(body["arm"]!.Deserialize<MembershipExpiryArm>(Json)).IsEqualTo(arm);
                    evidence = new MembershipExpiryFence(arm!, "provider-request", Disposition,
                        arm!.Intent.Attempt.ExistingMembershipId ?? (Disposition == MembershipExpiryDisposition.Applied ? "created" : null),
                        Disposition == MembershipExpiryDisposition.Applied ? "assignment" : null, sequence, true);
                    break;
                case "open":
                    var binding = body["binding"]!.Deserialize<MembershipExpiryFence>(Json)!;
                    var phase = body["phase"]!.Deserialize<MembershipExpiryPhase>(Json);
                    await Assert.That(body["priorSequence"]!.GetValue<long>()).IsEqualTo(sequence);
                    Time = phase switch
                    {
                        MembershipExpiryPhase.Active => arm!.StartsAt,
                        MembershipExpiryPhase.Expired => arm!.EndsAt,
                        _ => arm!.ArmedAt
                    };
                    WindowOpen = true;
                    window = new(binding, phase, "window-" + phase, "event-" + phase, ++sequence, Time, Time, true, true);
                    evidence = window;
                    break;
                case "close-window":
                    token.ThrowIfCancellationRequested();
                    WindowOpen = false;
                    ClosedCallbackState = CallbackState;
                    evidence = window! with { Sequence = ++sequence, ClosedAt = Time };
                    break;
                case "close":
                    Registered = false;
                    WindowOpen = false;
                    evidence = new MembershipExpiryCleanup(body["attempt"]!.Deserialize<MembershipExpiryAttempt>(Json)!,
                        true, true, true, true, 0, 0);
                    break;
                default: throw new InvalidOperationException("unexpected-route");
            }
            if (route == LostRoute) throw new HttpRequestException("lost-response");
            JsonObject facts = JsonSerializer.SerializeToNode(evidence, Json)!.AsObject();
            Change?.Invoke(route, facts);
            return new(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new
                {
                    schemaVersion = 1,
                    nonce = body["nonce"]!.GetValue<string>(),
                    observerIdentity = Settings.Identity,
                    observedAt = DateTimeOffset.UtcNow,
                    facts
                }, Json))
            };
        }
    }
}
