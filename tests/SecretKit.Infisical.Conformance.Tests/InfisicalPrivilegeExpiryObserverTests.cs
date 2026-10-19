using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Offline characterization of the channel and local callback, not native
// provider expiry certification or handler test-first evidence.
public sealed class InfisicalPrivilegeExpiryObserverTests
{
    private static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private static readonly InfisicalLifecycleObservers.Settings Settings =
        new(new("https://observer.invalid/owned/"), "service-token", "independent-service", 30);
    private static readonly DateTimeOffset Clock = DateTimeOffset.UnixEpoch.AddDays(1);
    private static PrivilegeExpiryIntent Intent(string? existing = "privilege", string duration = "1m") =>
        new(new("attempt", "case", "operation", PrivilegeExpiryVersion.ProjectV2, "organization", "project",
            "project-slug", "identity", "membership", "privilege-slug", existing,
            PrivilegeExpirySource.ControlledFixture), duration, 10);

    private static int Seconds(string duration) => duration switch
    {
        "1m" => 60,
        "1h" => 3600,
        "1d" => 86400,
        _ => throw new InvalidOperationException("unexpected-duration")
    };

    [Test]
    [Arguments("1m")]
    [Arguments("1h")]
    [Arguments("1d")]
    public async Task BracketsActualCallbackStateAcrossAllPhases(string duration)
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var intent = Intent(duration: duration);
        var arm = await observer.ArmAsync(intent, CancellationToken.None);
        var binding = await observer.CompleteAsync(arm, CancellationToken.None);
        foreach (PrivilegeExpiryPhase phase in Enum.GetValues<PrivilegeExpiryPhase>())
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
        await Assert.That(observer.ToString()).IsEqualTo("[InfisicalPrivilegeExpiryObserver]");
    }

    [Test]
    [Arguments("LegacyV1")]
    [Arguments("ProjectV2")]
    public async Task SelectedVersionAndOperationSurviveAllWindows(string version)
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var intent = Intent();
        intent = intent with
        {
            Attempt = intent.Attempt with
            {
                Version = Enum.Parse<PrivilegeExpiryVersion>(version),
                Operation = version == "LegacyV1"
                    ? "infisical.post.v1.additional.privilege.identity.temporary"
                    : "infisical.post.v2.identity.project.additional.privilege"
            }
        };
        var arm = await observer.ArmAsync(intent, CancellationToken.None);
        var binding = await observer.CompleteAsync(arm, CancellationToken.None);
        foreach (PrivilegeExpiryPhase phase in Enum.GetValues<PrivilegeExpiryPhase>())
        {
            var observed = await observer.ObserveAsync(binding, phase, Sample, CancellationToken.None);
            await Assert.That(observed.Window.Binding.Arm.Intent).IsEqualTo(intent);
        }
        await observer.CloseAsync(intent.Attempt, CancellationToken.None);
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
                    case "intent": facts["intent"]!["attempt"]!["identityId"] = "other"; break;
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
    [Arguments("version")]
    [Arguments("duration")]
    [Arguments("lead")]
    [Arguments("lead-high")]
    [Arguments("id")]
    [Arguments("long")]
    public async Task InvalidIntentCannotRegister(string mode)
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var intent = Intent();
        intent = mode switch
        {
            "source" => intent with { Attempt = intent.Attempt with { Source = PrivilegeExpirySource.NativeProvider } },
            "version" => intent with { Attempt = intent.Attempt with { Version = (PrivilegeExpiryVersion)99 } },
            "duration" => intent with { RelativeDuration = "60s" },
            "lead" => intent with { ActivationLeadSeconds = 0 },
            "lead-high" => intent with { ActivationLeadSeconds = 301 },
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
    [Arguments("privilege")]
    [Arguments("slug")]
    [Arguments("not-dispatched")]
    [Arguments("undefined")]
    [Arguments("rejected-slug")]
    [Arguments("rejected-privilege")]
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
                    case "privilege": facts["privilegeId"] = "other"; break;
                    case "slug": facts["privilegeSlug"] = null; break;
                    case "not-dispatched":
                        facts["disposition"] = "NotDispatched";
                        facts["providerRequestId"] = null;
                        break;
                    case "undefined": facts["disposition"] = 99; break;
                    case "rejected-slug": facts["disposition"] = "Rejected"; facts["privilegeSlug"] = "other"; break;
                    case "rejected-privilege":
                        facts["disposition"] = "Rejected";
                        facts["privilegeId"] = null;
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
        await Assert.That(async () => await observer.ObserveAsync(binding, PrivilegeExpiryPhase.BeforeActivation,
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
                    case "binding": facts["binding"]!["privilegeSlug"] = "other"; break;
                    case "opened": facts["openedAt"] = Clock.AddSeconds(1); break;
                    case "phase": facts["phase"] = "Active"; break;
                    case "reverse": facts["closedAt"] = Clock.AddSeconds(-1); break;
                }
            }
        };
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent(), CancellationToken.None);
        var binding = await observer.CompleteAsync(arm, CancellationToken.None);
        await Assert.That(async () => await observer.ObserveAsync(binding, PrivilegeExpiryPhase.BeforeActivation,
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
            await observer.ObserveAsync<bool>(binding, PrivilegeExpiryPhase.BeforeActivation, token =>
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
            PrivilegeExpiryPhase.BeforeActivation, Sample, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.ObserveAsync(binding, PrivilegeExpiryPhase.Active, Sample,
            CancellationToken.None)).Throws<NativeCaseFailureException>();
        await observer.ObserveAsync(binding, PrivilegeExpiryPhase.BeforeActivation, Sample, CancellationToken.None);
        await Assert.That(async () => await observer.ObserveAsync(binding, PrivilegeExpiryPhase.BeforeActivation, Sample,
            CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.CloseAsync(intent.Attempt with { ProjectId = "other" },
            CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.ArmAsync(intent, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await observer.CloseAsync(intent.Attempt, CancellationToken.None);
        await Assert.That(async () => await observer.ObserveAsync(binding, PrivilegeExpiryPhase.Active, Sample,
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
        var binding = new PrivilegeExpiryFence(arm, null, PrivilegeExpiryDisposition.NotDispatched,
            arm.Intent.Attempt.ExistingPrivilegeId, arm.Intent.Attempt.PrivilegeSlug, arm.Cursor + 1, true);
        await observer.ObserveAsync(binding, PrivilegeExpiryPhase.BeforeActivation, Sample, CancellationToken.None);
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
        PrivilegeExpiryArm arm = new(Intent(), "registration", Settings.Identity, "fixture-clock", "epoch",
            Clock, Clock.AddSeconds(10), Clock.AddSeconds(70), 1, true);
        PrivilegeExpiryFence fence = new(arm, "provider-request", PrivilegeExpiryDisposition.Applied,
            "privilege", "privilege-slug", 2, true);
        object evidence = route switch
        {
            "arm" => arm,
            "complete" => fence,
            "open" or "close-window" => new PrivilegeExpiryWindow(fence, PrivilegeExpiryPhase.BeforeActivation,
                "window", "event", 3, Clock, Clock, true, true),
            _ => new PrivilegeExpiryCleanup(Intent().Attempt, true, true, true, true, 0, 0)
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
                await observer.ObserveAsync(bound, PrivilegeExpiryPhase.BeforeActivation, Sample, CancellationToken.None);
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
        var observer = InfisicalPrivilegeExpiryObserver.FromInputs(environment, "C14-IM-IdentityPrivileges");
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
        await Assert.That(() => InfisicalPrivilegeExpiryObserver.FromInputs(environment, "C14-IM-IdentityPrivileges"))
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
        await Assert.That(() => InfisicalPrivilegeExpiryObserver.FromInputs(environment, "C14-IM-IdentityPrivileges"))
            .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("Applied", "privilege")]
    [Arguments("Applied", null)]
    [Arguments("Rejected", "privilege")]
    [Arguments("Rejected", null)]
    public async Task TerminalFencePreservesPrivilegeIdentityAndSelectedSlug(string disposition, string? existing)
    {
        using var service = new Service { Disposition = Enum.Parse<PrivilegeExpiryDisposition>(disposition) };
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent(existing), CancellationToken.None);
        var binding = await observer.CompleteAsync(arm, CancellationToken.None);
        await Assert.That(binding.PrivilegeId).IsEqualTo(existing ??
            (disposition == "Applied" ? "created" : null));
        await Assert.That(binding.PrivilegeSlug).IsEqualTo(arm.Intent.Attempt.PrivilegeSlug);
        await Assert.That(binding.Arm.Intent.Attempt.MembershipId).IsEqualTo("membership");
        await observer.CloseAsync(arm.Intent.Attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("id")]
    [Arguments("caseIdentity")]
    [Arguments("operation")]
    [Arguments("version")]
    [Arguments("organizationId")]
    [Arguments("projectId")]
    [Arguments("projectSlug")]
    [Arguments("identityId")]
    [Arguments("membershipId")]
    [Arguments("privilegeSlug")]
    [Arguments("existingPrivilegeId")]
    [Arguments("source")]
    public async Task EverySelectedAttemptBindingRejectsServiceSubstitution(string field)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route != "arm") return;
                var attempt = facts["intent"]!["attempt"]!.AsObject();
                attempt[field] = field is "version" or "source" ? JsonValue.Create(99) : JsonValue.Create("other");
            }
        };
        var observer = service.CreateObserver();
        var intent = Intent();
        await Assert.That(async () => await observer.ArmAsync(intent, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await observer.CloseAsync(intent.Attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("operation")]
    [Arguments("membershipId")]
    [Arguments("identityId")]
    [Arguments("projectSlug")]
    [Arguments("privilegeSlug")]
    [Arguments("existingPrivilegeId")]
    public async Task MalformedAttemptSelectorsNeverContactService(string field)
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var node = JsonSerializer.SerializeToNode(Intent(), Json)!;
        node["attempt"]![field] = "bad\nid";
        var intent = node.Deserialize<PrivilegeExpiryIntent>(Json)!;
        await Assert.That(async () => await observer.ArmAsync(intent, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(service.Registered).IsFalse();
    }

    [Test]
    [Arguments(1)]
    [Arguments(300)]
    public async Task LeadBoundsAreExact(int lead)
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent() with { ActivationLeadSeconds = lead }, CancellationToken.None);
        await Assert.That(arm.StartsAt - arm.ArmedAt).IsEqualTo(TimeSpan.FromSeconds(lead));
        await observer.CloseAsync(arm.Intent.Attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("1h")]
    [Arguments("1d")]
    public async Task NativeLongLivedObservationIsNotEnabled(string duration)
    {
        using var service = new Service();
        var observer = new InfisicalPrivilegeExpiryObserver(new(Settings, service), Settings.Identity);
        var intent = Intent(duration: duration);
        intent = intent with { Attempt = intent.Attempt with { Source = PrivilegeExpirySource.NativeProvider } };
        await Assert.That(async () => await observer.ArmAsync(intent, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(service.Registered).IsFalse();
    }

    [Test]
    public async Task NativeScheduleRejectsHistoricalFixtureClock()
    {
        using var service = new Service();
        var observer = new InfisicalPrivilegeExpiryObserver(new(Settings, service), Settings.Identity);
        var intent = Intent();
        intent = intent with { Attempt = intent.Attempt with { Source = PrivilegeExpirySource.NativeProvider } };
        await Assert.That(async () => await observer.ArmAsync(intent, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await observer.CloseAsync(intent.Attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("request")]
    [Arguments("id")]
    [Arguments("slug")]
    [Arguments("fence")]
    [Arguments("sequence")]
    public async Task LocalNotDispatchedFenceMustBeExact(string mode)
    {
        using var service = new Service { LostRoute = "complete" };
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent(), CancellationToken.None);
        var binding = new PrivilegeExpiryFence(arm, null, PrivilegeExpiryDisposition.NotDispatched,
            arm.Intent.Attempt.ExistingPrivilegeId, arm.Intent.Attempt.PrivilegeSlug, 2, true);
        binding = mode switch
        {
            "request" => binding with { ProviderRequestId = "request" },
            "id" => binding with { PrivilegeId = "other" },
            "slug" => binding with { PrivilegeSlug = "other" },
            "fence" => binding with { ExcludesLateCommit = false },
            _ => binding with { Sequence = 1 }
        };
        await Assert.That(async () => await observer.ObserveAsync(binding, PrivilegeExpiryPhase.BeforeActivation,
            Sample, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(service.WindowOpen).IsFalse();
        await observer.CloseAsync(arm.Intent.Attempt, CancellationToken.None);
    }

    [Test]
    public async Task ActiveCallbackCrossingExpiryIsRejectedAndNeverReplayed()
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent(), CancellationToken.None);
        var binding = await observer.CompleteAsync(arm, CancellationToken.None);
        await observer.ObserveAsync(binding, PrivilegeExpiryPhase.BeforeActivation, Sample, CancellationToken.None);
        await Assert.That(async () => await observer.ObserveAsync(binding, PrivilegeExpiryPhase.Active, _ =>
        {
            service.CallbackState++;
            service.Time = arm.EndsAt;
            return ValueTask.FromResult(true);
        }, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.ObserveAsync(binding, PrivilegeExpiryPhase.Active, _ =>
        {
            service.CallbackState++;
            return ValueTask.FromResult(true);
        }, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(service.CallbackState).IsEqualTo(1);
        await Assert.That(service.WindowOpen).IsFalse();
        await observer.CloseAsync(arm.Intent.Attempt, CancellationToken.None);
    }

    [Test]
    public async Task ConcurrentCallerCannotCrossAnInFlightCallback()
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent(), CancellationToken.None);
        var binding = await observer.CompleteAsync(arm, CancellationToken.None);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var observation = observer.ObserveAsync(binding, PrivilegeExpiryPhase.BeforeActivation, async token =>
        {
            service.CallbackState++;
            entered.SetResult();
            await release.Task.WaitAsync(token);
            return true;
        }, CancellationToken.None).AsTask();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(async () => await observer.ObserveAsync(binding, PrivilegeExpiryPhase.BeforeActivation,
                Sample, CancellationToken.None)).Throws<NativeCaseFailureException>();
            await Assert.That(async () => await observer.CloseAsync(arm.Intent.Attempt, CancellationToken.None))
                .Throws<NativeCaseFailureException>();
        }
        finally { release.TrySetResult(); }
        await observation;
        await Assert.That(service.CallbackState).IsEqualTo(1);
        await observer.CloseAsync(arm.Intent.Attempt, CancellationToken.None);
    }

    private static ValueTask<bool> Sample(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return ValueTask.FromResult(true);
    }

    [Test]
    [Arguments("NativeProvider")]
    [Arguments("0")]
    public async Task NativeSourceCanBeSelectedExplicitly(string selected)
    {
        var settings = JsonSerializer.SerializeToNode(Settings, Json)!.AsObject();
        settings["source"] = selected == "0" ? JsonValue.Create(0) : JsonValue.Create(selected);
        using var document = EnvironmentInput(new() { ["observer"] = settings });
        using var environment = NativeEnvironment.Create(document.RootElement);
        var observer = InfisicalPrivilegeExpiryObserver.FromInputs(environment, "C14-IM-IdentityPrivileges");
        await Assert.That(observer is not null).IsTrue();
        await Assert.That(async () => await observer!.ArmAsync(Intent(), CancellationToken.None))
            .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("arm")]
    [Arguments("complete")]
    [Arguments("open")]
    [Arguments("close-window")]
    public async Task LostRepliesStillAllowOriginalAttemptCleanup(string route)
    {
        using var service = new Service { LostRoute = route };
        var observer = service.CreateObserver();
        var intent = Intent();
        await Assert.That(async () =>
        {
            var arm = await observer.ArmAsync(intent, CancellationToken.None);
            var binding = await observer.CompleteAsync(arm, CancellationToken.None);
            await observer.ObserveAsync(binding, PrivilegeExpiryPhase.BeforeActivation, Sample, CancellationToken.None);
        }).Throws<NativeCaseFailureException>();
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await observer.CloseAsync(intent.Attempt, canceled.Token);
        await Assert.That(service.Registered).IsFalse();
        await Assert.That(service.WindowOpen).IsFalse();
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("identity")]
    [Arguments("schema")]
    [Arguments("observedAt")]
    [Arguments("duplicate")]
    [Arguments("permissions")]
    public async Task ChannelRejectsMalformedOrSubstitutedEnvelopes(string mode)
    {
        using var service = new Service { EnvelopeFault = mode };
        var observer = service.CreateObserver();
        var intent = Intent();
        await Assert.That(async () => await observer.ArmAsync(intent, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        service.EnvelopeFault = null;
        await observer.CloseAsync(intent.Attempt, CancellationToken.None);
        await Assert.That(service.Registered).IsFalse();
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
        ["families"] = new JsonObject { ["C14-IM-IdentityPrivileges"] = family }
    }.ToJsonString());

    private sealed class Service : HttpMessageHandler
    {
        internal Action<string, JsonObject>? Change { get; set; }
        internal string? LostRoute { get; set; }
        internal string? EnvelopeFault { get; set; }
        internal PrivilegeExpiryDisposition Disposition { get; init; } = PrivilegeExpiryDisposition.Applied;
        internal bool Registered { get; private set; }
        internal bool WindowOpen { get; private set; }
        internal int CallbackState { get; set; }
        internal int ClosedCallbackState { get; private set; }
        internal DateTimeOffset Time { get; set; } = Clock;
        private PrivilegeExpiryArm? arm;
        private PrivilegeExpiryWindow? window;
        private long sequence = 2;

        internal InfisicalPrivilegeExpiryObserver CreateObserver() =>
            new(new(Settings, this), Settings.Identity, PrivilegeExpirySource.ControlledFixture);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            JsonObject body = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
            await Assert.That(request.Headers.Authorization!.Parameter).IsEqualTo(Settings.Token);
            string route = request.RequestUri!.AbsolutePath.Split('/').Last();
            await Assert.That(request.RequestUri.AbsolutePath).IsEqualTo("/owned/privilege-expiry/" + route);
            object evidence;
            switch (route)
            {
                case "arm":
                    var intent = body["intent"]!.Deserialize<PrivilegeExpiryIntent>(Json)!;
                    Registered = true;
                    arm = new(intent, "registration", Settings.Identity, "fixture-clock", "epoch",
                        Clock, Clock.AddSeconds(intent.ActivationLeadSeconds),
                        Clock.AddSeconds(intent.ActivationLeadSeconds + Seconds(intent.RelativeDuration)), 1, true);
                    evidence = arm;
                    break;
                case "complete":
                    await Assert.That(body["arm"]!.Deserialize<PrivilegeExpiryArm>(Json)).IsEqualTo(arm);
                    evidence = new PrivilegeExpiryFence(arm!, "provider-request", Disposition,
                        arm!.Intent.Attempt.ExistingPrivilegeId ?? (Disposition == PrivilegeExpiryDisposition.Applied ? "created" : null),
                        arm.Intent.Attempt.PrivilegeSlug, sequence, true);
                    break;
                case "open":
                    var binding = body["binding"]!.Deserialize<PrivilegeExpiryFence>(Json)!;
                    var phase = body["phase"]!.Deserialize<PrivilegeExpiryPhase>(Json);
                    await Assert.That(body["priorSequence"]!.GetValue<long>()).IsEqualTo(sequence);
                    Time = phase switch
                    {
                        PrivilegeExpiryPhase.Active => arm!.StartsAt,
                        PrivilegeExpiryPhase.Expired => arm!.EndsAt,
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
                    evidence = new PrivilegeExpiryCleanup(body["attempt"]!.Deserialize<PrivilegeExpiryAttempt>(Json)!,
                        true, true, true, true, 0, 0);
                    break;
                default: throw new InvalidOperationException("unexpected-route");
            }
            if (route == LostRoute) throw new HttpRequestException("lost-response");
            JsonObject facts = JsonSerializer.SerializeToNode(evidence, Json)!.AsObject();
            Change?.Invoke(route, facts);
            var envelope = new JsonObject
            {
                ["schemaVersion"] = 1,
                ["nonce"] = body["nonce"]!.GetValue<string>(),
                ["observerIdentity"] = Settings.Identity,
                ["observedAt"] = DateTimeOffset.UtcNow,
                ["facts"] = facts
            };
            switch (EnvelopeFault)
            {
                case "nonce": envelope["nonce"] = "replayed"; break;
                case "identity": envelope["observerIdentity"] = "other"; break;
                case "schema": envelope["schemaVersion"] = 2; break;
                case "observedAt": envelope["observedAt"] = Clock; break;
                case "permissions": facts["canRead"] = true; break;
            }
            string content = envelope.ToJsonString(Json);
            if (EnvelopeFault == "duplicate") content = content.Insert(1, "\"schemaVersion\":1,");
            return new(HttpStatusCode.OK)
            {
                Content = new StringContent(content)
            };
        }
    }
}
