using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Offline HTTP channel characterization, not provider expiry/source certification.
public sealed class InfisicalAuthenticationExpiryObserverTests
{
    private static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private static readonly InfisicalLifecycleObservers.Settings Settings =
        new(new("https://observer.invalid/owned/"), "synthetic-service-token", "capture-service-instance", 30);
    private static readonly DateTimeOffset Clock = DateTimeOffset.UnixEpoch.AddDays(1);
    private static readonly string MetadataId = "00000000-0000-0000-0000-000000000003";
    private static AuthenticationExpiryAttempt Attempt(bool proof = false) =>
        new("attempt", "case", proof ? InfisicalProofAuthenticationEffects.Operation : InfisicalUniversalAuthenticationEffects.Operation,
            proof ? InfisicalProofAuthenticationEffects.Member : InfisicalUniversalAuthenticationEffects.Member,
            "v0.166.3", "deployment", "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002", proof ? "jwt-auth" : "universal-auth",
            new(3600, 7200, 0, 0), 60, 7200, AuthenticationExpirySource.ControlledFixture);

    private static async Task<AuthenticationExpiryArm> Arm(InfisicalAuthenticationExpiryObserver observer,
        AuthenticationExpiryAttempt attempt)
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        try { return await observer.ArmAsync(attempt, key, CancellationToken.None); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task BracketsLocalCallbacksWithCapturedScheduleAndPrivateKey(bool proof)
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var attempt = Attempt(proof);
        byte[] key = RandomNumberGenerator.GetBytes(32);
        try
        {
            service.ExpectedKey = key;
            var arm = await observer.ArmAsync(attempt, key, CancellationToken.None);
            service.ExpectedKey = null;
            var binding = await observer.CompleteAsync(arm, DispatchEvidence.Applied, CancellationToken.None);
            byte[] expected = Service.Witness(key, attempt);
            byte[] returned = Convert.FromBase64String(binding.CredentialWitness);
            try
            {
                await Assert.That(CryptographicOperations.FixedTimeEquals(expected, returned)).IsTrue();
                foreach (AuthenticationExpiryAttempt other in new[]
                {
                    attempt with { CaseIdentity = "other-case" },
                    attempt with { Operation = "other-operation" },
                    attempt with { IdentityId = "00000000-0000-0000-0000-000000000004" }
                })
                {
                    byte[] different = Service.Witness(key, other);
                    try { await Assert.That(CryptographicOperations.FixedTimeEquals(different, returned)).IsFalse(); }
                    finally { CryptographicOperations.ZeroMemory(different); }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expected);
                CryptographicOperations.ZeroMemory(returned);
            }
            // The caller can clear its key; the adapter retains no key for later operations.
            CryptographicOperations.ZeroMemory(key);
            foreach (AuthenticationExpiryPhase phase in Enum.GetValues<AuthenticationExpiryPhase>())
            {
                var observation = await observer.ObserveAsync(binding, phase, token =>
                {
                    token.ThrowIfCancellationRequested();
                    if (!service.WindowOpen) throw new InvalidOperationException("callback-not-bracketed");
                    service.Callbacks++;
                    service.Time = service.Time.AddSeconds(1);
                    return ValueTask.FromResult(service.Callbacks);
                }, CancellationToken.None);
                await Assert.That(observation.Sample).IsEqualTo(service.Callbacks);
                await Assert.That(observation.Window.ClosedAt).IsEqualTo(service.Time);
                await Assert.That(service.WindowOpen).IsFalse();
            }
            var cleanup = await observer.CloseAsync(attempt, CancellationToken.None);
            await Assert.That(cleanup.CorrelationKeyDestroyed).IsTrue();
            await Assert.That(service.Key.All(value => value == 0)).IsTrue();
            await Assert.That(service.Callbacks).IsEqualTo(2);
            await Assert.That(service.PrivateKeyOnlyInArm).IsTrue();
            await Assert.That(observer.ToString()).IsEqualTo("[InfisicalAuthenticationExpiryObserver]");
            await Assert.That(binding.ToString()).IsEqualTo("[AuthenticationExpiryFence]");
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    [Test]
    [Arguments(0d, 0d, 0d, 0d)]
    [Arguments(3600d, 7200d, 0d, 10d)]
    [Arguments(10d, 0d, 3600d, 0d)]
    [Arguments(0.5d, 0.25d, 0.125d, 0.5d)]
    public async Task ConfiguredPolicyDoesNotReplaceCapturedResponseLifetime(double ttl, double max, double period, double uses)
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var attempt = Attempt() with { Policy = new(ttl, max, period, uses), ExpectedReportedMaximumTtl = max };
        var arm = await Arm(observer, attempt);
        var binding = await observer.CompleteAsync(arm, DispatchEvidence.Applied, CancellationToken.None);
        await Assert.That(binding.ResponseExpiresIn).IsEqualTo(60d);
        await Assert.That(binding.ObservedPolicy).IsEqualTo(attempt.Policy);
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("version")]
    [Arguments("operation")]
    [Arguments("member")]
    [Arguments("method")]
    [Arguments("source")]
    [Arguments("organization")]
    [Arguments("identity")]
    [Arguments("text")]
    [Arguments("long")]
    [Arguments("ttl-negative")]
    [Arguments("max-infinite")]
    [Arguments("period-nan")]
    [Arguments("uses-negative")]
    [Arguments("response-zero")]
    [Arguments("response-infinite")]
    [Arguments("reported-negative")]
    [Arguments("key-length")]
    public async Task InvalidAttemptCannotRegister(string mode)
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var attempt = Attempt();
        attempt = mode switch
        {
            "version" => attempt with { ProviderVersion = "v0.166.4" },
            "operation" => attempt with { Operation = "i.runtime.InfisicalPeriodicTokenSession.CreateAsync" },
            "member" => attempt with { Member = InfisicalProofAuthenticationEffects.Member },
            "method" => attempt with { AuthenticationMethod = "jwt-auth" },
            "source" => attempt with { Source = AuthenticationExpirySource.NativeProvider },
            "organization" => attempt with { OrganizationId = "organization" },
            "identity" => attempt with { IdentityId = Guid.Empty.ToString("D") },
            "text" => attempt with { DeploymentId = "bad\nid" },
            "long" => attempt with { CaseIdentity = new string('a', 513) },
            "ttl-negative" => attempt with { Policy = attempt.Policy with { Ttl = -1 } },
            "max-infinite" => attempt with { Policy = attempt.Policy with { MaximumTtl = double.PositiveInfinity } },
            "period-nan" => attempt with { Policy = attempt.Policy with { Period = double.NaN } },
            "uses-negative" => attempt with { Policy = attempt.Policy with { MaximumUses = -1 } },
            "response-zero" => attempt with { ExpectedExpiresIn = 0 },
            "response-infinite" => attempt with { ExpectedExpiresIn = double.PositiveInfinity },
            "reported-negative" => attempt with { ExpectedReportedMaximumTtl = -1 },
            _ => attempt
        };
        byte[] key = RandomNumberGenerator.GetBytes(mode == "key-length" ? 31 : 32);
        try
        {
            await Assert.That(async () => await observer.ArmAsync(attempt, key, CancellationToken.None))
                .Throws<NativeCaseFailureException>();
            await Assert.That(service.Registered).IsFalse();
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    [Test]
    [Arguments("source")]
    [Arguments("clock")]
    [Arguments("epoch")]
    [Arguments("cursor")]
    [Arguments("capture")]
    [Arguments("policyWitness")]
    [Arguments("utc")]
    [Arguments("registration")]
    [Arguments("case")]
    [Arguments("method")]
    [Arguments("deployment")]
    [Arguments("operation")]
    [Arguments("member")]
    [Arguments("policy")]
    public async Task ArmRejectsSubstitutedSourceAndScope(string mode)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route != "arm") return;
                switch (mode)
                {
                    case "source": facts["sourceIdentity"] = "other-source"; break;
                    case "clock": facts["clockAuthority"] = ""; break;
                    case "epoch": facts["clockEpoch"] = ""; break;
                    case "cursor": facts["cursor"] = -1; break;
                    case "capture": facts["captureArmed"] = false; break;
                    case "policyWitness": facts["policyWitness"] = ""; break;
                    case "utc": facts["armedAt"] = Clock.ToOffset(TimeSpan.FromHours(1)); break;
                    case "registration": facts["registrationId"] = "bad\nid"; break;
                    case "case": facts["attempt"]!["caseIdentity"] = "other-case"; break;
                    case "method": facts["attempt"]!["authenticationMethod"] = "jwt-auth"; break;
                    case "deployment": facts["attempt"]!["deploymentId"] = "other-deployment"; break;
                    case "operation": facts["attempt"]!["operation"] = InfisicalProofAuthenticationEffects.Operation; break;
                    case "member": facts["attempt"]!["member"] = InfisicalProofAuthenticationEffects.Member; break;
                    case "policy": facts["attempt"]!["policy"]!["ttl"] = 1; break;
                }
            }
        };
        var observer = service.CreateObserver();
        var attempt = Attempt();
        await Assert.That(async () => await Arm(observer, attempt)).Throws<NativeCaseFailureException>();
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("arm")]
    [Arguments("arm-utc")]
    [Arguments("disposition")]
    [Arguments("request")]
    [Arguments("metadata")]
    [Arguments("handle")]
    [Arguments("witness")]
    [Arguments("short-witness")]
    [Arguments("long-witness")]
    [Arguments("issuance")]
    [Arguments("capture")]
    [Arguments("schedule")]
    [Arguments("late")]
    [Arguments("sequence")]
    [Arguments("issue-before-arm")]
    [Arguments("expiry-before-issue")]
    [Arguments("utc")]
    [Arguments("policy")]
    [Arguments("response")]
    [Arguments("maximum")]
    [Arguments("negative-maximum")]
    public async Task CompleteRequiresCapturedExactIssuanceAndNativeSchedule(string mode)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route != "complete") return;
                switch (mode)
                {
                    case "arm": facts["arm"]!["clockEpoch"] = "other-epoch"; break;
                    case "arm-utc": facts["arm"]!["armedAt"] = Clock.ToOffset(TimeSpan.FromHours(1)); break;
                    case "disposition": facts["disposition"] = "Rejected"; break;
                    case "request": facts["providerRequestId"] = ""; break;
                    case "metadata": facts["tokenMetadataId"] = "singleton-row"; break;
                    case "handle": facts["credentialHandle"] = ""; break;
                    case "witness": facts["credentialWitness"] = new string('!', 44); break;
                    case "short-witness": facts["credentialWitness"] = Convert.ToBase64String(new byte[31]); break;
                    case "long-witness": facts["credentialWitness"] = Convert.ToBase64String(new byte[33]); break;
                    case "issuance": facts["matchedIssuances"] = 2; break;
                    case "capture": facts["issueEventObserved"] = false; break;
                    case "schedule": facts["nativeScheduleObserved"] = false; break;
                    case "late": facts["excludesLateCommit"] = false; break;
                    case "sequence": facts["sequence"] = 1; break;
                    case "issue-before-arm": facts["issuedAt"] = Clock.AddSeconds(-1); break;
                    case "expiry-before-issue": facts["expiresAt"] = Clock; break;
                    case "utc": facts["expiresAt"] = Clock.AddSeconds(61).ToOffset(TimeSpan.FromHours(1)); break;
                    case "policy": facts["observedPolicy"]!["period"] = 1; break;
                    case "response": facts["responseExpiresIn"] = 3600; break;
                    case "maximum": facts["responseMaximumTtl"] = 3600; break;
                    case "negative-maximum": facts["responseMaximumTtl"] = -1; break;
                }
            }
        };
        var observer = service.CreateObserver();
        var attempt = Attempt();
        var arm = await Arm(observer, attempt);
        await Assert.That(async () => await observer.CompleteAsync(arm, DispatchEvidence.Applied, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    [Arguments(DispatchEvidence.NotDispatched)]
    [Arguments(DispatchEvidence.PossiblyDispatched)]
    [Arguments(DispatchEvidence.Rejected)]
    [Arguments((DispatchEvidence)99)]
    public async Task NonAppliedReceiptCannotRequestCompletion(DispatchEvidence receipt)
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var attempt = Attempt();
        var arm = await Arm(observer, attempt);
        await Assert.That(async () => await observer.CompleteAsync(arm, receipt, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(service.Completions).IsEqualTo(0);
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("arm")]
    [Arguments("complete")]
    [Arguments("open")]
    [Arguments("close-window")]
    [Arguments("close")]
    public async Task EveryNestedProtocolFieldIsRequired(string route)
    {
        JsonObject? original = null;
        using (var baseline = new Service { Change = (actual, facts) => { if (actual == route) original = facts.DeepClone().AsObject(); } })
            await Exercise(baseline, route);
        if (original is null) throw new InvalidOperationException("missing-test-evidence");
        foreach (string[] path in FieldPaths(original, []))
        {
            using var service = new Service
            {
                Change = (actual, facts) =>
                {
                    if (actual != route) return;
                    JsonObject parent = facts;
                    foreach (string segment in path[..^1]) parent = parent[segment]!.AsObject();
                    parent.Remove(path[^1]);
                }
            };
            await Assert.That(async () => await Exercise(service, route)).Throws<NativeCaseFailureException>();
            await Assert.That(service.Callbacks).IsEqualTo(0);
        }
    }

    private static async Task Exercise(Service service, string route)
    {
        var observer = service.CreateObserver();
        var attempt = Attempt();
        try
        {
            var arm = await Arm(observer, attempt);
            if (route == "arm") return;
            var binding = await observer.CompleteAsync(arm, DispatchEvidence.Applied, CancellationToken.None);
            if (route == "complete") return;
            if (route != "close") await observer.ObserveAsync(binding, AuthenticationExpiryPhase.Active,
                _ => ValueTask.FromResult(true), CancellationToken.None);
            if (route == "close") await observer.CloseAsync(attempt, CancellationToken.None);
        }
        finally
        {
            service.Change = null;
            if (route != "close" || service.Registered)
                await observer.CloseAsync(attempt, CancellationToken.None);
        }
    }

    [Test]
    [Arguments("binding")]
    [Arguments("binding-utc")]
    [Arguments("phase")]
    [Arguments("authority")]
    [Arguments("event")]
    [Arguments("natural")]
    [Arguments("policy")]
    [Arguments("ip")]
    [Arguments("renewal")]
    [Arguments("revocation")]
    [Arguments("exhaustion")]
    [Arguments("sequence")]
    [Arguments("before-issue")]
    [Arguments("at-expiry")]
    [Arguments("utc")]
    public async Task OpenRejectsUnboundOrConfoundedEvidenceBeforeCallback(string mode)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route != "open") return;
                switch (mode)
                {
                    case "binding": facts["binding"]!["credentialHandle"] = "other"; break;
                    case "binding-utc": facts["binding"]!["issuedAt"] = Clock.AddSeconds(1).ToOffset(TimeSpan.FromHours(1)); break;
                    case "phase": facts["phase"] = "Expired"; break;
                    case "authority": facts["authoritative"] = false; break;
                    case "event": facts["eventObserved"] = false; break;
                    case "natural": facts["naturalExpiryObserved"] = true; break;
                    case "policy": facts["policyUnchanged"] = false; break;
                    case "ip": facts["ipPathUnchanged"] = false; break;
                    case "renewal": facts["noRenewal"] = false; break;
                    case "revocation": facts["noRevocation"] = false; break;
                    case "exhaustion": facts["useLimitNotExhausted"] = false; break;
                    case "sequence": facts["sequence"] = 2; break;
                    case "before-issue": facts["openedAt"] = Clock; facts["closedAt"] = Clock; break;
                    case "at-expiry": facts["openedAt"] = Clock.AddSeconds(61); facts["closedAt"] = Clock.AddSeconds(61); break;
                    case "utc": facts["openedAt"] = Clock.AddSeconds(2).ToOffset(TimeSpan.FromHours(1)); break;
                }
            }
        };
        var observer = service.CreateObserver();
        var attempt = Attempt();
        var binding = await observer.CompleteAsync(await Arm(observer, attempt), DispatchEvidence.Applied, CancellationToken.None);
        await Assert.That(async () => await observer.ObserveAsync(binding, AuthenticationExpiryPhase.Active,
            _ => { service.Callbacks++; return ValueTask.FromResult(true); }, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(service.Callbacks).IsEqualTo(0);
        await Assert.That(service.WindowOpen).IsFalse();
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("expiry-straddle")]
    [Arguments("before-open")]
    [Arguments("binding")]
    [Arguments("event")]
    [Arguments("window")]
    [Arguments("opened")]
    [Arguments("sequence")]
    [Arguments("natural")]
    [Arguments("renewal")]
    public async Task CloseWindowRequiresWholeCallbackInterval(string mode)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route != "close-window") return;
                switch (mode)
                {
                    case "expiry-straddle": facts["closedAt"] = Clock.AddSeconds(61); break;
                    case "before-open": facts["closedAt"] = Clock.AddSeconds(1); break;
                    case "binding": facts["binding"]!["tokenMetadataId"] = Guid.NewGuid().ToString("D"); break;
                    case "event": facts["eventId"] = "other"; break;
                    case "window": facts["windowId"] = "other"; break;
                    case "opened": facts["openedAt"] = Clock.AddSeconds(3); break;
                    case "sequence": facts["sequence"] = 3; break;
                    case "natural": facts["naturalExpiryObserved"] = true; break;
                    case "renewal": facts["noRenewal"] = false; break;
                }
            }
        };
        var observer = service.CreateObserver();
        var attempt = Attempt();
        var binding = await observer.CompleteAsync(await Arm(observer, attempt), DispatchEvidence.Applied, CancellationToken.None);
        await Assert.That(async () => await observer.ObserveAsync(binding, AuthenticationExpiryPhase.Active,
            _ => { service.Callbacks++; return ValueTask.FromResult(true); }, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(service.Callbacks).IsEqualTo(1);
        await Assert.That(service.WindowOpen).IsFalse();
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("duplicate-event")]
    [Arguments("duplicate-window")]
    [Arguments("early-expired")]
    [Arguments("no-natural-expiry")]
    public async Task ExpiredWindowMustFollowActiveWithUniqueEvent(string mode)
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var attempt = Attempt();
        var binding = await observer.CompleteAsync(await Arm(observer, attempt), DispatchEvidence.Applied, CancellationToken.None);
        await observer.ObserveAsync(binding, AuthenticationExpiryPhase.Active, _ => ValueTask.FromResult(true), CancellationToken.None);
        service.Change = (route, facts) =>
        {
            if (route != "open") return;
            switch (mode)
            {
                case "duplicate-event": facts["eventId"] = "event-Active"; break;
                case "duplicate-window": facts["windowId"] = "window-Active"; break;
                case "early-expired": facts["openedAt"] = Clock.AddSeconds(60); facts["closedAt"] = Clock.AddSeconds(60); break;
                case "no-natural-expiry": facts["naturalExpiryObserved"] = false; break;
            }
        };
        await Assert.That(async () => await observer.ObserveAsync(binding, AuthenticationExpiryPhase.Expired,
            _ => { service.Callbacks++; return ValueTask.FromResult(true); }, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(service.Callbacks).IsEqualTo(0);
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    public async Task ClonedFencesReplayAndSkippedPhasesCannotInvokeCallback()
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var attempt = Attempt();
        var arm = await Arm(observer, attempt);
        await Assert.That(async () => await Arm(observer, attempt)).Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.CompleteAsync(arm with { }, DispatchEvidence.Applied, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        var binding = await observer.CompleteAsync(arm, DispatchEvidence.Applied, CancellationToken.None);
        await Assert.That(async () => await observer.CompleteAsync(arm, DispatchEvidence.Applied, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.ObserveAsync(binding with { }, AuthenticationExpiryPhase.Active,
            _ => ValueTask.FromResult(true), CancellationToken.None)).Throws<NativeCaseFailureException>();
        await observer.CloseAsync(attempt, CancellationToken.None);

        using var second = new Service();
        var secondObserver = second.CreateObserver();
        var secondBinding = await secondObserver.CompleteAsync(await Arm(secondObserver, attempt), DispatchEvidence.Applied, CancellationToken.None);
        await Assert.That(async () => await secondObserver.ObserveAsync(secondBinding, AuthenticationExpiryPhase.Expired,
            _ => ValueTask.FromResult(true), CancellationToken.None)).Throws<NativeCaseFailureException>();
        await secondObserver.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    public async Task CompletedActiveWindowCannotBeReplayed()
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var attempt = Attempt();
        var binding = await observer.CompleteAsync(await Arm(observer, attempt), DispatchEvidence.Applied, CancellationToken.None);
        await observer.ObserveAsync(binding, AuthenticationExpiryPhase.Active,
            _ => { service.Callbacks++; return ValueTask.FromResult(true); }, CancellationToken.None);
        await Assert.That(async () => await observer.ObserveAsync(binding, AuthenticationExpiryPhase.Active,
            _ => { service.Callbacks++; return ValueTask.FromResult(true); }, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(service.Callbacks).IsEqualTo(1);
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CallbackFailureStillClosesWindowIndependently(bool cancel)
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var attempt = Attempt();
        var binding = await observer.CompleteAsync(await Arm(observer, attempt), DispatchEvidence.Applied, CancellationToken.None);
        using var canceled = new CancellationTokenSource();
        async Task Observe() => await observer.ObserveAsync<bool>(binding, AuthenticationExpiryPhase.Active, token =>
        {
            service.Callbacks++;
            if (cancel)
            {
                canceled.Cancel();
                token.ThrowIfCancellationRequested();
            }
            throw new InvalidOperationException("synthetic-callback-failure");
        }, canceled.Token);
        if (cancel) await Assert.That(Observe).Throws<OperationCanceledException>();
        else await Assert.That(Observe).Throws<InvalidOperationException>();
        await Assert.That(service.WindowOpen).IsFalse();
        await Assert.That(service.Callbacks).IsEqualTo(1);
        await observer.CloseAsync(attempt, canceled.Token);
    }

    [Test]
    public async Task ConcurrentCallerCannotCrossInFlightCallback()
    {
        using var service = new Service();
        var observer = service.CreateObserver();
        var attempt = Attempt();
        var binding = await observer.CompleteAsync(await Arm(observer, attempt), DispatchEvidence.Applied, CancellationToken.None);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var pending = observer.ObserveAsync(binding, AuthenticationExpiryPhase.Active, async token =>
        {
            service.Callbacks++;
            entered.SetResult();
            await release.Task.WaitAsync(TimeSpan.FromSeconds(10), token);
            return true;
        }, CancellationToken.None).AsTask();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(async () => await observer.ObserveAsync(binding, AuthenticationExpiryPhase.Active,
                _ => ValueTask.FromResult(true), CancellationToken.None)).Throws<NativeCaseFailureException>();
            await Assert.That(async () => await observer.CloseAsync(attempt, CancellationToken.None)).Throws<NativeCaseFailureException>();
        }
        finally { release.TrySetResult(); }
        await pending;
        await Assert.That(service.Callbacks).IsEqualTo(1);
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("arm")]
    [Arguments("complete")]
    [Arguments("open")]
    [Arguments("close-window")]
    public async Task LostReplyStillClosesOriginalAttemptAndDestroysKey(string route)
    {
        using var service = new Service { LostRoute = route };
        var observer = service.CreateObserver();
        var attempt = Attempt();
        await Assert.That(async () =>
        {
            var arm = await Arm(observer, attempt);
            var binding = await observer.CompleteAsync(arm, DispatchEvidence.Applied, CancellationToken.None);
            await observer.ObserveAsync(binding, AuthenticationExpiryPhase.Active, _ => ValueTask.FromResult(true), CancellationToken.None);
        }).Throws<NativeCaseFailureException>();
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.That(async () => await observer.CloseAsync(attempt with { CaseIdentity = "other-case" }, canceled.Token))
            .Throws<NativeCaseFailureException>();
        await observer.CloseAsync(attempt, canceled.Token);
        await Assert.That(service.ClosedAttempt).IsEqualTo(attempt);
        await Assert.That(service.Registered).IsFalse();
        await Assert.That(service.WindowOpen).IsFalse();
        await Assert.That(service.Key.All(value => value == 0)).IsTrue();
    }

    [Test]
    [Arguments("closed")]
    [Arguments("lateCreationFenced")]
    [Arguments("mutationSettled")]
    [Arguments("inventoryComplete")]
    [Arguments("correlationKeyDestroyed")]
    [Arguments("remainingRegistrations")]
    [Arguments("pendingDeliveries")]
    [Arguments("attempt")]
    public async Task CleanupRequiresSettledEmptySourceAndDestroyedKey(string field)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route != "close") return;
                if (field == "attempt") facts["attempt"]!["deploymentId"] = "other";
                else if (field is "remainingRegistrations" or "pendingDeliveries") facts[field] = 1;
                else facts[field] = false;
            }
        };
        var observer = service.CreateObserver();
        var attempt = Attempt();
        await Arm(observer, attempt);
        await Assert.That(async () => await observer.CloseAsync(attempt, CancellationToken.None)).Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("identity")]
    [Arguments("schema")]
    [Arguments("duplicate")]
    public async Task ChannelRejectsReplayedOrDuplicateEnvelope(string mode)
    {
        using var service = new Service { EnvelopeFault = mode };
        var observer = service.CreateObserver();
        var attempt = Attempt();
        await Assert.That(async () => await Arm(observer, attempt)).Throws<NativeCaseFailureException>();
        service.EnvelopeFault = null;
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("ControlledFixture")]
    [Arguments("1")]
    [Arguments("NativeProvider")]
    [Arguments("0")]
    [Arguments("role")]
    public async Task NativeInputsCannotGrantControlledAuthorityOrRoleIdentity(string mode)
    {
        JsonObject settings = JsonSerializer.SerializeToNode(Settings, Json)!.AsObject();
        settings["source"] = mode is "0" or "1" ? JsonValue.Create(int.Parse(mode)) : JsonValue.Create(mode);
        if (mode == "role")
        {
            settings["source"] = "NativeProvider";
            settings["identity"] = "observer";
        }
        using var document = JsonDocument.Parse(new JsonObject
        {
            ["origin"] = "https://infisical.invalid",
            ["setup"] = "setup",
            ["runtime"] = "runtime",
            ["denied"] = "denied",
            ["administrative"] = "administrative",
            ["observer"] = "observer",
            ["families"] = new JsonObject { ["C08-IR-InfisicalUniversalAuthentication"] = new JsonObject { ["observer"] = settings } }
        }.ToJsonString());
        using var environment = NativeEnvironment.Create(document.RootElement);
        if (mode is "NativeProvider" or "0")
            await Assert.That(InfisicalAuthenticationExpiryObserver.FromInputs(environment, "C08-IR-InfisicalUniversalAuthentication") is not null).IsTrue();
        else
            await Assert.That(() => InfisicalAuthenticationExpiryObserver.FromInputs(environment, "C08-IR-InfisicalUniversalAuthentication"))
                .Throws<NativeCaseFailureException>();
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
        internal Action<string, JsonObject>? Change { get; set; }
        internal string? LostRoute { get; set; }
        internal string? EnvelopeFault { get; set; }
        internal byte[]? ExpectedKey { get; set; }
        internal byte[] Key { get; private set; } = [];
        internal bool PrivateKeyOnlyInArm { get; private set; } = true;
        internal bool Registered { get; private set; }
        internal bool WindowOpen { get; private set; }
        internal int Callbacks { get; set; }
        internal int Completions { get; private set; }
        internal AuthenticationExpiryAttempt? ClosedAttempt { get; private set; }
        internal DateTimeOffset Time { get; set; } = Clock;
        private AuthenticationExpiryArm? arm;
        private AuthenticationExpiryWindow? window;
        private long sequence = 2;

        internal InfisicalAuthenticationExpiryObserver CreateObserver() =>
            new(new(Settings, this), Settings.Identity, AuthenticationExpirySource.ControlledFixture);

        // Synthetic credential is bytes, not a captured token or an immutable
        // secret export. The test source owns only the private key until Close.
        internal static byte[] Witness(ReadOnlySpan<byte> key, AuthenticationExpiryAttempt attempt)
        {
            byte[] domain = Encoding.UTF8.GetBytes("secretkit-issued-token-v1\0" + attempt.CaseIdentity +
                "\0" + attempt.Operation + "\0" + attempt.IdentityId + "\0");
            byte[] credential = "synthetic-issued-credential"u8.ToArray();
            byte[] input = new byte[domain.Length + credential.Length];
            try
            {
                domain.CopyTo(input, 0);
                credential.CopyTo(input, domain.Length);
                return HMACSHA256.HashData(key, input);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(domain);
                CryptographicOperations.ZeroMemory(credential);
                CryptographicOperations.ZeroMemory(input);
            }
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync(token);
            try
            {
                using var document = JsonDocument.Parse(requestBytes);
                JsonElement body = document.RootElement;
                string route = request.RequestUri!.AbsolutePath.Split('/').Last();
                await Assert.That(request.RequestUri.AbsolutePath).IsEqualTo("/owned/authentication-expiry/" + route);
                await Assert.That(request.Headers.Authorization!.Parameter).IsEqualTo(Settings.Token);
                if (route != "arm" && body.TryGetProperty("correlationKey", out _)) PrivateKeyOnlyInArm = false;
                object evidence;
                switch (route)
                {
                    case "arm":
                        var attempt = body.GetProperty("attempt").Deserialize<AuthenticationExpiryAttempt>(Json)!;
                        Key = body.GetProperty("correlationKey").GetBytesFromBase64();
                        await Assert.That(Key.Length).IsEqualTo(32);
                        if (ExpectedKey is not null)
                            await Assert.That(CryptographicOperations.FixedTimeEquals(Key, ExpectedKey)).IsTrue();
                        Registered = true;
                        arm = new(attempt, "registration", Settings.Identity, "capture-clock", "epoch",
                            Clock, 1, "policy-witness", true);
                        evidence = arm;
                        break;
                    case "complete":
                        Completions++;
                        await Assert.That(body.GetProperty("receipt").Deserialize<DispatchEvidence>(Json)).IsEqualTo(DispatchEvidence.Applied);
                        byte[] witness = Witness(Key, arm!.Attempt);
                        try
                        {
                            evidence = new AuthenticationExpiryFence(arm, DispatchEvidence.Applied, "provider-request", MetadataId,
                                "opaque-credential-handle", Convert.ToBase64String(witness), arm.Attempt.Policy,
                                arm.Attempt.ExpectedExpiresIn, arm.Attempt.ExpectedReportedMaximumTtl,
                                Clock.AddSeconds(1), Clock.AddSeconds(61), sequence, 1, true, true, true);
                        }
                        finally { CryptographicOperations.ZeroMemory(witness); }
                        break;
                    case "open":
                        var binding = body.GetProperty("binding").Deserialize<AuthenticationExpiryFence>(Json)!;
                        var phase = body.GetProperty("phase").Deserialize<AuthenticationExpiryPhase>(Json);
                        await Assert.That(body.GetProperty("priorSequence").GetInt64()).IsEqualTo(sequence);
                        Time = phase == AuthenticationExpiryPhase.Active ? binding.IssuedAt.AddSeconds(1) : binding.ExpiresAt;
                        WindowOpen = true;
                        window = new(binding, phase, "window-" + phase, "event-" + phase, ++sequence, Time, Time,
                            true, true, phase == AuthenticationExpiryPhase.Expired, true, true, true, true, true);
                        evidence = window;
                        break;
                    case "close-window":
                        token.ThrowIfCancellationRequested();
                        WindowOpen = false;
                        evidence = window! with { Sequence = ++sequence, ClosedAt = Time };
                        break;
                    case "close":
                        ClosedAttempt = body.GetProperty("attempt").Deserialize<AuthenticationExpiryAttempt>(Json)!;
                        Registered = false;
                        WindowOpen = false;
                        CryptographicOperations.ZeroMemory(Key);
                        evidence = new AuthenticationExpiryCleanup(ClosedAttempt, true, true, true, true, true, 0, 0);
                        break;
                    default: throw new InvalidOperationException("unexpected-route");
                }
                if (route == LostRoute) throw new HttpRequestException("synthetic-lost-response");
                JsonObject facts = JsonSerializer.SerializeToNode(evidence, Json)!.AsObject();
                if (facts.ContainsKey("correlationKey") || facts.ContainsKey("accessToken"))
                    throw new InvalidOperationException("private-material-in-evidence");
                Change?.Invoke(route, facts);
                var envelope = new JsonObject
                {
                    ["schemaVersion"] = 1,
                    ["nonce"] = body.GetProperty("nonce").GetString(),
                    ["observerIdentity"] = Settings.Identity,
                    ["observedAt"] = DateTimeOffset.UtcNow,
                    ["facts"] = facts
                };
                switch (EnvelopeFault)
                {
                    case "nonce": envelope["nonce"] = "replayed"; break;
                    case "identity": envelope["observerIdentity"] = "other"; break;
                    case "schema": envelope["schemaVersion"] = 2; break;
                }
                string content = envelope.ToJsonString(Json);
                if (EnvelopeFault == "duplicate") content = content.Insert(1, "\"schemaVersion\":1,");
                return new(HttpStatusCode.OK) { Content = new StringContent(content) };
            }
            finally { CryptographicOperations.ZeroMemory(requestBytes); }
        }

        protected override void Dispose(bool disposing)
        {
            CryptographicOperations.ZeroMemory(Key);
            base.Dispose(disposing);
        }
    }
}
