using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Offline HTTP-channel evidence only, not native scope or expiry certification.
public sealed class InfisicalOrganizationGroupExpiryObserverTests
{
    private static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private static readonly InfisicalLifecycleObservers.Settings Settings =
        new(new("https://observer.invalid/owned/"), "service-token", "independent-service", 30);
    private static readonly DateTimeOffset Clock = DateTimeOffset.UnixEpoch.AddDays(1);
    private const string Family = "C08-IM-ProjectMemberships";
    private static string Id(int value) => new Guid(value, 0, 0, new byte[8]).ToString();
    private static OrganizationGroupExpiryIntent Intent(bool update = true,
        OrganizationGroupExpiredMetadata policy = OrganizationGroupExpiredMetadata.RetainedInactive, int lead = 10) =>
        new(new("attempt", "case", "i.management.MembershipOperations." +
            (update ? "UpdateOrganizationGroupRoles" : "AddOrganizationGroup"), "v0.166.3",
            new(Id(1), Id(3), Id(4), Id(2), Id(5), Id(6), Id(7), Id(8), Id(9)),
            Id(10), Id(11), Id(12), Id(13), "custom-groups-reader", update ? Id(14) : null,
            MembershipExpirySource.ControlledFixture, policy), "1m", lead);

    [Test]
    [Arguments(false, false, false, 1)]
    [Arguments(false, false, true, 300)]
    [Arguments(false, true, false, 300)]
    [Arguments(false, true, true, 1)]
    [Arguments(true, false, false, 300)]
    [Arguments(true, false, true, 1)]
    [Arguments(true, true, false, 1)]
    [Arguments(true, true, true, 300)]
    public async Task OfflineContractsBracketActualCallbacks(bool update, bool rejected, bool removed, int lead)
    {
        using var service = new Service { Disposition = rejected ? MembershipExpiryDisposition.Rejected : MembershipExpiryDisposition.Applied };
        var observer = service.CreateObserver();
        var intent = Intent(update, removed ? OrganizationGroupExpiredMetadata.RemovedAssignment :
            OrganizationGroupExpiredMetadata.RetainedInactive, lead);
        var arm = await observer.ArmAsync(intent, CancellationToken.None);
        var fence = await observer.CompleteAsync(arm, CancellationToken.None);
        await Assert.That(arm.ObservedScopes).IsEqualTo(intent.Attempt.Scopes);
        await Assert.That(arm.EndsAt - arm.StartsAt).IsEqualTo(TimeSpan.FromSeconds(60));
        await Assert.That(fence.MutationIdentityId).IsEqualTo(rejected ?
            intent.Attempt.Scopes.TargetDeniedIdentityId : intent.Attempt.Scopes.TargetAdministrativeIdentityId);
        foreach (MembershipExpiryPhase phase in Enum.GetValues<MembershipExpiryPhase>())
        {
            var observation = await observer.ObserveAsync(fence, phase, token =>
            {
                token.ThrowIfCancellationRequested();
                if (!service.WindowOpen) throw new InvalidOperationException("callback-not-bracketed");
                service.CallbackState++;
                service.Time = service.Time.AddTicks(1);
                return ValueTask.FromResult(service.CallbackState);
            }, CancellationToken.None);
            await Assert.That(observation.Sample).IsEqualTo(service.CallbackState);
            await Assert.That(observation.Window.ClosedAt).IsEqualTo(service.Time);
            await Assert.That(service.ClosedCallbackState).IsEqualTo(service.CallbackState);
            await Assert.That(service.WindowOpen).IsFalse();
        }
        await observer.CloseAsync(intent.Attempt, CancellationToken.None);
        await Assert.That(service.Registered).IsFalse();
        await Assert.That(service.CallbackState).IsEqualTo(3);
        await Assert.That(observer.ToString()).IsEqualTo("[InfisicalOrganizationGroupExpiryObserver]");
        await Assert.That(intent.ToString()).IsEqualTo("[OrganizationGroupExpiryIntent]");
        await Assert.That(intent.Attempt.ToString()).IsEqualTo("[OrganizationGroupExpiryAttempt]");
        await Assert.That(arm.ToString()).IsEqualTo("[OrganizationGroupExpiryArm]");
        await Assert.That(fence.ToString()).IsEqualTo("[OrganizationGroupExpiryFence]");
    }

    [Test]
    [Arguments("source")]
    [Arguments("caseIdentity")]
    [Arguments("operation")]
    [Arguments("shortOperation")]
    [Arguments("providerVersion")]
    [Arguments("groupId")]
    [Arguments("ownerMembershipId")]
    [Arguments("runtimeLinkId")]
    [Arguments("roleId")]
    [Arguments("roleSlug")]
    [Arguments("addExisting")]
    [Arguments("updateAbsent")]
    [Arguments("ownerTargetMembership")]
    [Arguments("metadata")]
    [Arguments("duration")]
    [Arguments("leadZero")]
    [Arguments("leadTooLarge")]
    [Arguments("id")]
    [Arguments("long")]
    public async Task InvalidIntentCannotRegister(string mode)
    {
        var intent = Intent();
        var attempt = intent.Attempt;
        intent = mode switch
        {
            "source" => intent with { Attempt = attempt with { Source = MembershipExpirySource.NativeProvider } },
            "caseIdentity" => intent with { Attempt = attempt with { CaseIdentity = "" } },
            "operation" => intent with { Attempt = attempt with { Operation = "i.management.MembershipOperations.RemoveOrganizationGroup" } },
            "shortOperation" => intent with { Attempt = attempt with { Operation = "UpdateOrganizationGroupRoles" } },
            "providerVersion" => intent with { Attempt = attempt with { ProviderVersion = "v0.166.4" } },
            "groupId" => intent with { Attempt = attempt with { GroupId = "not-guid" } },
            "ownerMembershipId" => intent with { Attempt = attempt with { OwnerMembershipId = "" } },
            "runtimeLinkId" => intent with { Attempt = attempt with { RuntimeLinkId = "" } },
            "roleId" => intent with { Attempt = attempt with { RoleId = "" } },
            "roleSlug" => intent with { Attempt = attempt with { RoleSlug = "bad\nslug" } },
            "addExisting" => intent with { Attempt = attempt with { Operation = Intent(false).Attempt.Operation } },
            "updateAbsent" => intent with { Attempt = attempt with { ExistingTargetMembershipId = null } },
            "ownerTargetMembership" => intent with { Attempt = attempt with { ExistingTargetMembershipId = attempt.OwnerMembershipId } },
            "metadata" => intent with { Attempt = attempt with { ExpiredMetadata = (OrganizationGroupExpiredMetadata)99 } },
            "duration" => intent with { RelativeDuration = "60s" },
            "leadZero" => intent with { ActivationLeadSeconds = 0 },
            "leadTooLarge" => intent with { ActivationLeadSeconds = 301 },
            "id" => intent with { Attempt = attempt with { Id = "bad\nid" } },
            _ => intent with { Attempt = attempt with { CaseIdentity = new string('a', 513) } }
        };
        using var service = new Service();
        var observer = service.CreateObserver();
        await Assert.That(async () => await observer.ArmAsync(intent, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(service.Registered).IsFalse();
    }

    [Test]
    public async Task EverySelectedScopeMustBeGuidAndPrincipalsDistinct()
    {
        var intent = Intent();
        JsonObject scope = JsonSerializer.SerializeToNode(intent.Attempt.Scopes, Json)!.AsObject();
        foreach (string field in scope.Select(pair => pair.Key).ToArray())
        {
            foreach (string replacement in new[] { "", "not-guid", Guid.Empty.ToString() })
            {
                var changed = scope.DeepClone().AsObject();
                changed[field] = replacement;
                var invalid = intent with { Attempt = intent.Attempt with { Scopes = changed.Deserialize<OrganizationGroupExpiryScopes>(Json)! } };
                using var service = new Service();
                await Assert.That(async () => await service.CreateObserver().ArmAsync(invalid, CancellationToken.None))
                    .Throws<NativeCaseFailureException>();
                await Assert.That(service.Registered).IsFalse();
            }
        }
        string[] principals = scope.Select(pair => pair.Key).Where(key => !key.EndsWith("OrganizationId", StringComparison.Ordinal)).ToArray();
        for (int a = 0; a < principals.Length; a++)
        {
            for (int b = a + 1; b < principals.Length; b++)
            {
                var changed = scope.DeepClone().AsObject();
                changed[principals[b]] = Guid.Parse(scope[principals[a]]!.GetValue<string>()).ToString("B").ToUpperInvariant();
                using var service = new Service();
                var invalid = intent with { Attempt = intent.Attempt with { Scopes = changed.Deserialize<OrganizationGroupExpiryScopes>(Json)! } };
                await Assert.That(async () => await service.CreateObserver().ArmAsync(invalid, CancellationToken.None))
                    .Throws<NativeCaseFailureException>();
            }
        }
        using var sameOrganization = new Service();
        var scopes = intent.Attempt.Scopes;
        var same = intent with { Attempt = intent.Attempt with { Scopes = scopes with { TargetOrganizationId = scopes.OwnerOrganizationId } } };
        await Assert.That(async () => await sameOrganization.CreateObserver().ArmAsync(same, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("identity")]
    [Arguments("clock")]
    [Arguments("epoch")]
    [Arguments("capture")]
    [Arguments("cursor")]
    [Arguments("starts")]
    [Arguments("duration")]
    [Arguments("utc")]
    [Arguments("registration")]
    [Arguments("authenticated")]
    [Arguments("source")]
    public async Task ArmRejectsFalseAuthorityAndSchedule(string mode)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route != "arm") return;
                switch (mode)
                {
                    case "identity": facts["sourceIdentity"] = "other"; break;
                    case "clock": facts["clockAuthority"] = ""; break;
                    case "epoch": facts["clockEpoch"] = new string('a', 513); break;
                    case "capture": facts["captureArmed"] = false; break;
                    case "cursor": facts["cursor"] = -1; break;
                    case "starts": facts["startsAt"] = Clock; break;
                    case "duration": facts["endsAt"] = Clock.AddSeconds(71); break;
                    case "utc": facts["armedAt"] = Clock.ToOffset(TimeSpan.FromHours(1)); break;
                    case "registration": facts["registrationId"] = "bad\nid"; break;
                    case "authenticated": facts["authenticatedScopesObserved"] = false; break;
                    case "source": facts["intent"]!["attempt"]!["source"] = "NativeProvider"; break;
                }
            }
        };
        var observer = service.CreateObserver();
        await Assert.That(async () => await observer.ArmAsync(Intent(), CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await observer.CloseAsync(Intent().Attempt, CancellationToken.None);
        await Assert.That(service.Registered).IsFalse();
    }

    [Test]
    public async Task ArmPinsEveryAttemptAndAuthenticatedScopeField()
    {
        JsonObject attempt = JsonSerializer.SerializeToNode(Intent().Attempt, Json)!.AsObject();
        IEnumerable<string[]> paths = FieldPaths(attempt, ["intent", "attempt"])
            .Concat(FieldPaths(JsonSerializer.SerializeToNode(Intent().Attempt.Scopes, Json)!.AsObject(), ["observedScopes"]));
        foreach (string[] path in paths)
        {
            using var service = new Service
            {
                Change = (route, facts) =>
                {
                    if (route != "arm") return;
                    JsonObject owner = At(facts, path[..^1]);
                    // Null is also a substitution for required object/enum fields.
                    owner[path[^1]] = owner[path[^1]] is JsonValue value && value.TryGetValue<string>(out _) ?
                        JsonValue.Create(Id(99)) : null;
                }
            };
            var observer = service.CreateObserver();
            await Assert.That(async () => await observer.ArmAsync(Intent(), CancellationToken.None))
                .Throws<NativeCaseFailureException>();
            await observer.CloseAsync(Intent().Attempt, CancellationToken.None);
        }
    }

    [Test]
    [Arguments(-3600)]
    [Arguments(3600)]
    [Arguments(-20)]
    public async Task NativeArmRejectsStaleFutureClockOrPastActivation(int shift)
    {
        using var service = new Service { ArmedAt = DateTimeOffset.UtcNow.AddSeconds(shift) };
        var observer = service.CreateObserver(MembershipExpirySource.NativeProvider);
        var intent = Intent() with { Attempt = Intent().Attempt with { Source = MembershipExpirySource.NativeProvider } };
        await Assert.That(async () => await observer.ArmAsync(intent, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await observer.CloseAsync(intent.Attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("arm")]
    [Arguments("request")]
    [Arguments("sequence")]
    [Arguments("fence")]
    [Arguments("membership")]
    [Arguments("ownerMembership")]
    [Arguments("assignment")]
    [Arguments("not-dispatched")]
    [Arguments("undefined")]
    [Arguments("mutationOrg")]
    [Arguments("mutationActor")]
    [Arguments("rejected-assignment")]
    [Arguments("rejected-membership")]
    [Arguments("rejected-admin")]
    [Arguments("nested-utc")]
    public async Task CompletionRequiresBoundTerminalProviderEvidence(string mode)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route != "complete") return;
                switch (mode)
                {
                    case "arm": facts["arm"]!["clockEpoch"] = "other"; break;
                    case "request": facts["providerRequestId"] = ""; break;
                    case "sequence": facts["sequence"] = 1; break;
                    case "fence": facts["excludesLateCommit"] = false; break;
                    case "membership": facts["targetMembershipId"] = Id(98); break;
                    case "ownerMembership": facts["targetMembershipId"] = Intent().Attempt.OwnerMembershipId; break;
                    case "assignment": facts["temporaryAssignmentId"] = null; break;
                    case "not-dispatched": facts["disposition"] = "NotDispatched"; break;
                    case "undefined": facts["disposition"] = 99; break;
                    case "mutationOrg": facts["mutationOrganizationId"] = Intent().Attempt.Scopes.OwnerOrganizationId; break;
                    case "mutationActor": facts["mutationIdentityId"] = Intent().Attempt.Scopes.TargetDeniedIdentityId; break;
                    case "rejected-assignment":
                        facts["disposition"] = "Rejected";
                        facts["mutationIdentityId"] = Intent().Attempt.Scopes.TargetDeniedIdentityId;
                        break;
                    case "rejected-membership":
                        facts["disposition"] = "Rejected";
                        facts["temporaryAssignmentId"] = null;
                        facts["targetMembershipId"] = null;
                        facts["mutationIdentityId"] = Intent().Attempt.Scopes.TargetDeniedIdentityId;
                        break;
                    case "rejected-admin":
                        facts["disposition"] = "Rejected";
                        facts["temporaryAssignmentId"] = null;
                        break;
                    case "nested-utc": facts["arm"]!["startsAt"] = Clock.AddSeconds(10).ToOffset(TimeSpan.FromHours(1)); break;
                }
            }
        };
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent(), CancellationToken.None);
        await Assert.That(async () => await observer.CompleteAsync(arm, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await observer.CloseAsync(Intent().Attempt, CancellationToken.None);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task LocalTokenBarrierFenceBypassesServiceCompletion(bool update)
    {
        using var service = new Service { LostRoute = "complete" };
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent(update), CancellationToken.None);
        // Infrastructure-only receipt. The parent must prove the actual token
        // barrier before constructing NotDispatched; this test sends no mutation.
        var fence = LocalFence(arm);
        foreach (MembershipExpiryPhase phase in Enum.GetValues<MembershipExpiryPhase>())
            await observer.ObserveAsync(fence, phase, Sample, CancellationToken.None);
        await observer.CloseAsync(arm.Intent.Attempt, CancellationToken.None);
        await Assert.That(service.CompletionRequests).IsEqualTo(0);
        await Assert.That(service.Registered).IsFalse();
    }

    [Test]
    [Arguments("request")]
    [Arguments("organization")]
    [Arguments("principal")]
    [Arguments("membership")]
    [Arguments("assignment")]
    [Arguments("late")]
    public async Task LocalFenceCannotClaimProviderDispatch(string mode)
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent(), CancellationToken.None);
        var fence = LocalFence(arm);
        fence = mode switch
        {
            "request" => fence with { ProviderRequestId = "request" },
            "organization" => fence with { MutationOrganizationId = arm.Intent.Attempt.Scopes.TargetOrganizationId },
            "principal" => fence with { MutationIdentityId = arm.Intent.Attempt.Scopes.TargetAdministrativeIdentityId },
            "membership" => fence with { TargetMembershipId = null },
            "assignment" => fence with { TemporaryAssignmentId = "assignment" },
            _ => fence with { ExcludesLateCommit = false }
        };
        await Assert.That(async () => await observer.ObserveAsync(fence, MembershipExpiryPhase.BeforeActivation,
            Sample, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(service.CallbackState).IsEqualTo(0);
        await observer.CloseAsync(arm.Intent.Attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("binding")]
    [Arguments("phase")]
    [Arguments("authority")]
    [Arguments("event")]
    [Arguments("sequence")]
    [Arguments("time")]
    [Arguments("utc")]
    [Arguments("runtimeOrg")]
    [Arguments("runtimeIdentity")]
    [Arguments("windowId")]
    [Arguments("eventId")]
    [Arguments("closedAt")]
    public async Task OpenRejectsFalseRuntimeEventBeforeCallback(string mode)
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
                    case "runtimeOrg": facts["runtimeOrganizationId"] = Intent().Attempt.Scopes.OwnerOrganizationId; break;
                    case "runtimeIdentity": facts["runtimeIdentityId"] = Intent().Attempt.Scopes.TargetAdministrativeIdentityId; break;
                    case "windowId": facts["windowId"] = ""; break;
                    case "eventId": facts["eventId"] = ""; break;
                    case "closedAt": facts["closedAt"] = Clock.AddTicks(1); break;
                }
            }
        };
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent(), CancellationToken.None);
        var fence = await observer.CompleteAsync(arm, CancellationToken.None);
        await Assert.That(async () => await observer.ObserveAsync(fence, MembershipExpiryPhase.BeforeActivation,
            _ => { service.CallbackState++; return ValueTask.FromResult(true); }, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(service.CallbackState).IsEqualTo(0);
        await Assert.That(service.WindowOpen).IsFalse();
        await observer.CloseAsync(arm.Intent.Attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("sequence")]
    [Arguments("window")]
    [Arguments("event")]
    [Arguments("authority")]
    [Arguments("binding")]
    [Arguments("opened")]
    [Arguments("backward")]
    [Arguments("utc")]
    [Arguments("runtimeOrg")]
    [Arguments("runtimeIdentity")]
    public async Task ClosureRejectsSubstitutedEvidence(string mode)
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
                    case "binding": facts["binding"]!["arm"]!["clockEpoch"] = "other"; break;
                    case "opened": facts["openedAt"] = Clock.AddTicks(1); break;
                    case "backward": facts["closedAt"] = Clock.AddTicks(-1); break;
                    case "utc": facts["closedAt"] = Clock.ToOffset(TimeSpan.FromHours(1)); break;
                    case "runtimeOrg": facts["runtimeOrganizationId"] = Intent().Attempt.Scopes.OwnerOrganizationId; break;
                    case "runtimeIdentity": facts["runtimeIdentityId"] = Intent().Attempt.Scopes.TargetObserverIdentityId; break;
                }
            }
        };
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent(), CancellationToken.None);
        var fence = await observer.CompleteAsync(arm, CancellationToken.None);
        await Assert.That(async () => await observer.ObserveAsync(fence, MembershipExpiryPhase.BeforeActivation,
            Sample, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(service.WindowOpen).IsFalse();
        await observer.CloseAsync(arm.Intent.Attempt, CancellationToken.None);
    }

    [Test]
    [Arguments(0, true)]
    [Arguments(1, true)]
    [Arguments(2, false)]
    public async Task EntireSampleIntervalMustRemainWithinPhase(int phaseIndex, bool crossover)
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent(), CancellationToken.None);
        var fence = await observer.CompleteAsync(arm, CancellationToken.None);
        for (int phase = 0; phase < phaseIndex; phase++)
            await observer.ObserveAsync(fence, (MembershipExpiryPhase)phase, Sample, CancellationToken.None);
        await Assert.That(async () => await observer.ObserveAsync(fence, (MembershipExpiryPhase)phaseIndex, _ =>
        {
            service.Time = crossover ? phaseIndex == 0 ? arm.StartsAt : arm.EndsAt : arm.EndsAt.AddTicks(-1);
            return ValueTask.FromResult(true);
        }, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(service.WindowOpen).IsFalse();
        await observer.CloseAsync(arm.Intent.Attempt, CancellationToken.None);
    }

    [Test]
    [Arguments(false, false)]
    [Arguments(true, false)]
    [Arguments(false, true)]
    public async Task CallbackFailureStillClosesWithIndependentToken(bool cancel, bool lostClosure)
    {
        using var service = new Service { LostRoute = lostClosure ? "close-window" : null };
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent(), CancellationToken.None);
        var fence = await observer.CompleteAsync(arm, CancellationToken.None);
        using var stop = new CancellationTokenSource();
        var failure = new InvalidOperationException("local-callback");
        Exception? seen = null;
        try
        {
            await observer.ObserveAsync<bool>(fence, MembershipExpiryPhase.BeforeActivation, token =>
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
        if (lostClosure) await Assert.That(seen!.Message).IsEqualTo("cleanup-incomplete");
        else if (cancel) await Assert.That(seen is OperationCanceledException).IsTrue();
        else await Assert.That(ReferenceEquals(seen, failure)).IsTrue();
        await Assert.That(service.WindowOpen).IsFalse();
        await Assert.That(service.ClosedCallbackState).IsEqualTo(1);
        await Assert.That(async () => await observer.ObserveAsync(fence, MembershipExpiryPhase.BeforeActivation,
            Sample, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await observer.CloseAsync(arm.Intent.Attempt, stop.Token);
        await Assert.That(service.Registered).IsFalse();
    }

    [Test]
    public async Task PinnedSessionsRejectSubstitutionReplayAndConcurrentUse()
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var intent = Intent();
        var arm = await observer.ArmAsync(intent, CancellationToken.None);
        await Assert.That(async () => await observer.CompleteAsync(arm with { ClockEpoch = "other" }, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        var fence = await observer.CompleteAsync(arm, CancellationToken.None);
        await Assert.That(async () => await observer.CompleteAsync(arm, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.ObserveAsync(fence with { Sequence = 99 },
            MembershipExpiryPhase.BeforeActivation, Sample, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.ObserveAsync(fence, MembershipExpiryPhase.Active,
            Sample, CancellationToken.None)).Throws<NativeCaseFailureException>();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<OrganizationGroupExpiryObservation<bool>> pending = observer.ObserveAsync(fence,
            MembershipExpiryPhase.BeforeActivation, async token =>
            {
                entered.SetResult();
                await release.Task.WaitAsync(token);
                return true;
            }, CancellationToken.None).AsTask();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(async () => await observer.ObserveAsync(fence, MembershipExpiryPhase.BeforeActivation,
                Sample, CancellationToken.None)).Throws<NativeCaseFailureException>();
            await Assert.That(async () => await observer.CloseAsync(intent.Attempt, CancellationToken.None))
                .Throws<NativeCaseFailureException>();
        }
        finally { release.TrySetResult(); }
        await pending.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(async () => await observer.ObserveAsync(fence, MembershipExpiryPhase.BeforeActivation,
            Sample, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.CloseAsync(intent.Attempt with { RuntimeLinkId = "other" }, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.ArmAsync(intent, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await observer.CloseAsync(intent.Attempt, CancellationToken.None);
        await Assert.That(async () => await observer.ObserveAsync(fence, MembershipExpiryPhase.Active,
            Sample, CancellationToken.None)).Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("windowId")]
    [Arguments("eventId")]
    public async Task WindowAndEventIdsCannotReplayAcrossPhases(string field)
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var arm = await observer.ArmAsync(Intent(), CancellationToken.None);
        var fence = await observer.CompleteAsync(arm, CancellationToken.None);
        var before = await observer.ObserveAsync(fence, MembershipExpiryPhase.BeforeActivation, Sample, CancellationToken.None);
        service.Change = (route, facts) =>
        {
            if (route == "open") facts[field] = field == "windowId" ? before.Window.WindowId : before.Window.EventId;
        };
        await Assert.That(async () => await observer.ObserveAsync(fence, MembershipExpiryPhase.Active,
            _ => { service.CallbackState++; return ValueTask.FromResult(true); }, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(service.CallbackState).IsEqualTo(0);
        await Assert.That(service.WindowOpen).IsFalse();
        await observer.CloseAsync(arm.Intent.Attempt, CancellationToken.None);
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
    public async Task LostArmClosesOriginalAttemptWithSettledEmptyInventory(string mode)
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
        await Assert.That(async () => await observer.ArmAsync(Intent(), CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(service.Registered).IsTrue();
        if (mode == "lost") service.LostRoute = "close";
        await Assert.That(async () => await observer.CloseAsync(Intent().Attempt, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        service.Change = null;
        service.LostRoute = null;
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await observer.CloseAsync(Intent().Attempt, canceled.Token);
        await Assert.That(service.Registered).IsFalse();
    }

    [Test]
    [Arguments("arm")]
    [Arguments("complete")]
    [Arguments("open")]
    [Arguments("close-window")]
    [Arguments("close")]
    public async Task EveryWireFieldIncludingNestedFieldsIsRequired(string route)
    {
        var intent = Intent();
        OrganizationGroupExpiryArm arm = new(intent, "registration", Settings.Identity, "fixture-clock", "epoch",
            Clock, Clock.AddSeconds(10), Clock.AddSeconds(70), 1, true, intent.Attempt.Scopes, true);
        OrganizationGroupExpiryFence fence = new(arm, "provider-request", MembershipExpiryDisposition.Applied,
            intent.Attempt.ExistingTargetMembershipId, Id(15), intent.Attempt.Scopes.TargetOrganizationId,
            intent.Attempt.Scopes.TargetAdministrativeIdentityId, 2, true);
        object evidence = route switch
        {
            "arm" => arm,
            "complete" => fence,
            "open" or "close-window" => new OrganizationGroupExpiryWindow(fence, MembershipExpiryPhase.BeforeActivation,
                "window", "event", 3, Clock, Clock, true, true, intent.Attempt.Scopes.TargetOrganizationId,
                intent.Attempt.Scopes.TargetRuntimeIdentityId),
            _ => new OrganizationGroupExpiryCleanup(intent.Attempt, true, true, true, true, 0, 0)
        };
        foreach (string[] path in FieldPaths(JsonSerializer.SerializeToNode(evidence, Json)!.AsObject(), []))
        {
            using var service = new Service
            {
                Change = (current, facts) =>
                {
                    if (current == route) At(facts, path[..^1]).Remove(path[^1]);
                }
            };
            var observer = service.CreateObserver();
            await Assert.That(async () =>
            {
                var armed = await observer.ArmAsync(intent, CancellationToken.None);
                var bound = await observer.CompleteAsync(armed, CancellationToken.None);
                await observer.ObserveAsync(bound, MembershipExpiryPhase.BeforeActivation, Sample, CancellationToken.None);
                await observer.CloseAsync(intent.Attempt, CancellationToken.None);
            }).Throws<NativeCaseFailureException>();
            service.Change = null;
            await observer.CloseAsync(intent.Attempt, CancellationToken.None);
            await Assert.That(service.Registered).IsFalse();
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task NativeInputSelectionNeverImportsControlledAuthority(bool configured)
    {
        JsonObject family = new();
        if (configured) family["observer"] = JsonSerializer.SerializeToNode(Settings, Json);
        using var document = EnvironmentInput(family);
        using var environment = NativeEnvironment.Create(document.RootElement);
        var observer = InfisicalOrganizationGroupExpiryObserver.FromInputs(environment, Family);
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
        await Assert.That(() => InfisicalOrganizationGroupExpiryObserver.FromInputs(environment, Family))
            .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("endpoint")]
    [Arguments("token")]
    [Arguments("identity")]
    [Arguments("timeoutSeconds")]
    public async Task NativeSettingsRequireEveryChannelField(string field)
    {
        var settings = JsonSerializer.SerializeToNode(Settings, Json)!.AsObject();
        settings.Remove(field);
        using var document = EnvironmentInput(new() { ["observer"] = settings });
        using var environment = NativeEnvironment.Create(document.RootElement);
        await Assert.That(() => InfisicalOrganizationGroupExpiryObserver.FromInputs(environment, Family))
            .Throws<NativeCaseFailureException>();
    }

    private static OrganizationGroupExpiryFence LocalFence(OrganizationGroupExpiryArm arm) =>
        new(arm, null, MembershipExpiryDisposition.NotDispatched, arm.Intent.Attempt.ExistingTargetMembershipId,
            null, null, null, arm.Cursor + 1, true);

    private static ValueTask<bool> Sample(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return ValueTask.FromResult(true);
    }

    private static JsonObject At(JsonObject value, string[] path)
    {
        foreach (string part in path) value = value[part]!.AsObject();
        return value;
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
        ["families"] = new JsonObject { [Family] = family }
    }.ToJsonString());

    private sealed class Service : HttpMessageHandler
    {
        internal Action<string, JsonObject>? Change { get; set; }
        internal string? LostRoute { get; set; }
        internal MembershipExpiryDisposition Disposition { get; init; } = MembershipExpiryDisposition.Applied;
        internal DateTimeOffset ArmedAt { get; init; } = Clock;
        internal bool Registered { get; private set; }
        internal bool WindowOpen { get; private set; }
        internal int CompletionRequests { get; private set; }
        internal int CallbackState { get; set; }
        internal int ClosedCallbackState { get; private set; }
        internal DateTimeOffset Time { get; set; } = Clock;
        private OrganizationGroupExpiryArm? arm;
        private OrganizationGroupExpiryWindow? window;
        private long sequence = 2;

        internal InfisicalOrganizationGroupExpiryObserver CreateObserver(
            MembershipExpirySource source = MembershipExpirySource.ControlledFixture) =>
            new(new(Settings, this), Settings.Identity, source);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            JsonObject body = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
            await Assert.That(request.Method).IsEqualTo(HttpMethod.Post);
            await Assert.That(request.Headers.Authorization!.Parameter).IsEqualTo(Settings.Token);
            string route = request.RequestUri!.AbsolutePath.Split('/').Last();
            await Assert.That(request.RequestUri.AbsolutePath).IsEqualTo("/owned/organization-group-expiry/" + route);
            object evidence;
            switch (route)
            {
                case "arm":
                    var intent = body["intent"]!.Deserialize<OrganizationGroupExpiryIntent>(Json)!;
                    Registered = true;
                    arm = new(intent, "registration", Settings.Identity, "fixture-clock", "epoch", ArmedAt,
                        ArmedAt.AddSeconds(intent.ActivationLeadSeconds), ArmedAt.AddSeconds(intent.ActivationLeadSeconds + 60),
                        1, true, intent.Attempt.Scopes, true);
                    evidence = arm;
                    break;
                case "complete":
                    CompletionRequests++;
                    await Assert.That(body["arm"]!.Deserialize<OrganizationGroupExpiryArm>(Json)).IsEqualTo(arm);
                    evidence = new OrganizationGroupExpiryFence(arm!, "provider-request", Disposition,
                        arm!.Intent.Attempt.ExistingTargetMembershipId ??
                            (Disposition == MembershipExpiryDisposition.Applied ? Id(14) : null),
                        Disposition == MembershipExpiryDisposition.Applied ? Id(15) : null,
                        arm.Intent.Attempt.Scopes.TargetOrganizationId,
                        Disposition == MembershipExpiryDisposition.Applied ? arm.Intent.Attempt.Scopes.TargetAdministrativeIdentityId :
                            arm.Intent.Attempt.Scopes.TargetDeniedIdentityId, sequence, true);
                    break;
                case "open":
                    var binding = body["binding"]!.Deserialize<OrganizationGroupExpiryFence>(Json)!;
                    var phase = body["phase"]!.Deserialize<MembershipExpiryPhase>(Json);
                    await Assert.That(body["priorSequence"]!.GetValue<long>()).IsEqualTo(sequence);
                    Time = phase switch
                    {
                        MembershipExpiryPhase.Active => arm!.StartsAt,
                        MembershipExpiryPhase.Expired => arm!.EndsAt,
                        _ => arm!.ArmedAt
                    };
                    WindowOpen = true;
                    window = new(binding, phase, "window-" + phase, "event-" + phase, ++sequence, Time, Time, true, true,
                        arm!.Intent.Attempt.Scopes.TargetOrganizationId, arm.Intent.Attempt.Scopes.TargetRuntimeIdentityId);
                    evidence = window;
                    break;
                case "close-window":
                    WindowOpen = false;
                    ClosedCallbackState = CallbackState;
                    await Assert.That(body["window"] is JsonObject).IsTrue();
                    evidence = window! with { Sequence = ++sequence, ClosedAt = Time };
                    break;
                case "close":
                    await Assert.That(body["attempt"]!.Deserialize<OrganizationGroupExpiryAttempt>(Json)).IsEqualTo(arm!.Intent.Attempt);
                    Registered = false;
                    WindowOpen = false;
                    evidence = new OrganizationGroupExpiryCleanup(arm.Intent.Attempt, true, true, true, true, 0, 0);
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
