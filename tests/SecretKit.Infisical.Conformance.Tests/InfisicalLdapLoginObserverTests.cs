using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Offline source protocol tests. This fixture does not qualify a native service.
public sealed class InfisicalLdapLoginObserverTests
{
    private static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private static readonly InfisicalLifecycleObservers.Settings Settings =
        new(new("https://observer.invalid/owned/"), "synthetic-service-token", "ldap-source-instance", 30);
    private static readonly DateTimeOffset Clock = DateTimeOffset.UnixEpoch.AddDays(1);
    private const string Id = "00000000-0000-0000-0000-000000000001";
    private static LdapDirectoryAttempt Attempt() =>
        new("directory", "case", "v0.166.3", "deployment", Id, "owned-root", "ldaps://directory.invalid",
            "cn=service,ou=owned-root", "ou=owned-root", "user", LdapLoginSource.ControlledFixture);
    private static LdapDirectoryCredentials Credentials()
    {
        using var original = SecretMaterial.FromText("original-private");
        using var rotated = SecretMaterial.FromText("rotated-private");
        using var wrongService = SecretMaterial.FromText("wrong-service-private");
        using var user = SecretMaterial.FromText("user-private");
        using var wrongUser = SecretMaterial.FromText("wrong-user-private");
        return new(original, rotated, wrongService, user, wrongUser);
    }
    private static LdapLoginAttempt Login(LdapDirectoryBinding directory, string name = "login",
        LdapServiceCredential credential = LdapServiceCredential.Original, bool wrongUser = false) =>
        new(directory, name, Id, Id, Id, credential, wrongUser);
    private static LdapTemplateAttempt Template(LdapDirectoryBinding directory, bool existing = false) =>
        new(directory, "template", "template.patch", "member", "bindPassword.value", "selected-contract",
            "owned-root-template", existing ? Id : null, LdapServiceCredential.Rotated);
    private static async Task<LdapDirectoryBinding> Open(InfisicalLdapLoginObserver observer, LdapDirectoryAttempt attempt)
    {
        using var credentials = Credentials();
        return await observer.OpenAsync(attempt, credentials, CancellationToken.None);
    }

    [Test]
    public async Task OwnedDirectoryRotatesOnceAndCapturesSuccessfulAndRejectedLogins()
    {
        using var service = new Service();
        var observer = service.Observer();
        var attempt = Attempt();
        var directory = await Open(observer, attempt);
        var first = await observer.ArmAsync(Login(directory, "first"), CancellationToken.None);
        var issued = await observer.CompleteAsync(first, DispatchEvidence.Applied, SecretStatus.Success, CancellationToken.None);
        await Assert.That(issued.TokenMetadataId).IsEqualTo(Id);
        await Assert.That(issued.LastLoginAt).IsEqualTo(Clock.AddSeconds(1));
        var rotation = await observer.RotateAsync(directory, CancellationToken.None);
        await Assert.That(rotation.OriginalServiceRejected && rotation.RotatedServiceAccepted).IsTrue();
        await Assert.That(async () => await observer.RotateAsync(directory, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        var old = await observer.ArmAsync(Login(directory, "old"), CancellationToken.None);
        var denied = await observer.CompleteAsync(old, DispatchEvidence.Rejected, SecretStatus.Denied, CancellationToken.None);
        await Assert.That(denied.ServiceBindAccepted).IsFalse();
        await Assert.That(denied.UserBindAttempted).IsFalse();
        var wrong = await observer.ArmAsync(Login(directory, "wrong", LdapServiceCredential.Rotated, true), CancellationToken.None);
        var userDenied = await observer.CompleteAsync(wrong, DispatchEvidence.Rejected, SecretStatus.Denied, CancellationToken.None);
        await Assert.That(userDenied.ServiceBindAccepted && userDenied.UserBindAttempted && !userDenied.UserBindAccepted).IsTrue();
        var current = await observer.ArmAsync(Login(directory, "current", LdapServiceCredential.Rotated), CancellationToken.None);
        await observer.CompleteAsync(current, DispatchEvidence.Applied, SecretStatus.Success, CancellationToken.None);
        var visibility = await observer.SealAsync(directory, CancellationToken.None);
        await Assert.That(visibility.LoginEvents).IsEqualTo(4);
        await Assert.That(async () => await observer.ArmAsync(Login(directory, "late"), CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.RotateAsync(directory, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.ArmTemplateAsync(Template(directory), CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await observer.CloseAsync(attempt, CancellationToken.None);
        await Assert.That(service.RootExists || service.CredentialsRetained).IsFalse();
        await Assert.That(service.UnrelatedRootExists).IsTrue();
        await Assert.That(service.Buffers.All(buffer => buffer.All(value => value == 0))).IsTrue();
        await Assert.That(service.PrivateOnlyInOpen).IsTrue();
    }

    [Test]
    [Arguments(true, 1, true)]
    [Arguments(true, 9, true)]
    [Arguments(true, 10, false)]
    [Arguments(false, 1, false)]
    public async Task DebounceRequiresPreviouslyObservedSameIdentityWithinTenSeconds(
        bool sameIdentity, int elapsed, bool accepted)
    {
        using var service = new Service();
        var observer = service.Observer();
        var attempt = Attempt();
        var directory = await Open(observer, attempt);
        var first = await observer.ArmAsync(Login(directory, "first"), CancellationToken.None);
        var observed = await observer.CompleteAsync(first, DispatchEvidence.Applied,
            SecretStatus.Success, CancellationToken.None);
        DateTimeOffset prior = observed.LastLoginAt.GetValueOrDefault();
        service.Change = (route, facts) =>
        {
            if (route == "arm") facts["armedAt"] = prior.AddSeconds(elapsed);
            if (route == "complete") facts["lastLoginAt"] = prior;
        };
        var next = Login(directory, "second");
        if (!sameIdentity) next = next with { IdentityId = "00000000-0000-0000-0000-000000000002" };
        var arm = await observer.ArmAsync(next, CancellationToken.None);
        if (accepted)
        {
            var result = await observer.CompleteAsync(arm, DispatchEvidence.Applied,
                SecretStatus.Success, CancellationToken.None);
            await Assert.That(result.LastLoginAt).IsEqualTo(prior);
        }
        else
            await Assert.That(async () => await observer.CompleteAsync(arm, DispatchEvidence.Applied,
                SecretStatus.Success, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    [Arguments(DispatchEvidence.NotDispatched, false, false)]
    [Arguments(DispatchEvidence.Rejected, false, false)]
    [Arguments(DispatchEvidence.Applied, true, false)]
    [Arguments(DispatchEvidence.PossiblyDispatched, true, false)]
    [Arguments(DispatchEvidence.PossiblyDispatched, false, false)]
    [Arguments(DispatchEvidence.NotDispatched, false, true)]
    [Arguments(DispatchEvidence.Rejected, false, true)]
    [Arguments(DispatchEvidence.Applied, true, true)]
    [Arguments(DispatchEvidence.PossiblyDispatched, true, true)]
    [Arguments(DispatchEvidence.PossiblyDispatched, false, true)]
    public async Task TemplateCompletionSettlesActualReceiptWithoutReplay(DispatchEvidence receipt, bool applied, bool existing)
    {
        using var service = new Service { TemplateApplied = applied };
        var observer = service.Observer();
        var attempt = Attempt();
        var directory = await Open(observer, attempt);
        var arm = await observer.ArmTemplateAsync(Template(directory, existing), CancellationToken.None);
        var fence = await observer.CompleteTemplateAsync(arm, receipt, CancellationToken.None);
        await Assert.That(fence.MatchedMutations).IsEqualTo(receipt == DispatchEvidence.NotDispatched ? 0 : 1);
        await Assert.That(fence.Applied).IsEqualTo(applied);
        await Assert.That(fence.TemplateId).IsEqualTo(existing || applied ? Id : null);
        await Assert.That(async () => await observer.CompleteTemplateAsync(arm, receipt, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await observer.SealAsync(directory, CancellationToken.None);
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    [Arguments(DispatchEvidence.NotDispatched, SecretStatus.Invalid)]
    [Arguments(DispatchEvidence.Rejected, SecretStatus.Denied)]
    [Arguments(DispatchEvidence.PossiblyDispatched, SecretStatus.Unknown)]
    public async Task FailedLoginHasNoIssuedMetadata(DispatchEvidence receipt, SecretStatus status)
    {
        using var service = new Service();
        var observer = service.Observer();
        var attempt = Attempt();
        var directory = await Open(observer, attempt);
        var arm = await observer.ArmAsync(Login(directory, wrongUser: true), CancellationToken.None);
        var fence = await observer.CompleteAsync(arm, receipt, status, CancellationToken.None);
        await Assert.That(fence.TokenIssued).IsFalse();
        await Assert.That(fence.MatchedIssuances).IsEqualTo(0);
        await Assert.That(fence.TokenMetadataId).IsNull();
        await observer.SealAsync(directory, CancellationToken.None);
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("open")]
    [Arguments("rotate")]
    [Arguments("arm")]
    [Arguments("complete")]
    [Arguments("arm-template")]
    [Arguments("complete-template")]
    [Arguments("seal")]
    [Arguments("close")]
    public async Task EveryProtocolFieldIncludingNestedBindingsIsRequired(string route)
    {
        JsonObject? baseline = null;
        using (var service = new Service
        {
            Change = (actual, facts) => { if (actual == route) baseline = facts.DeepClone().AsObject(); }
        })
            await Exercise(service, route);
        if (baseline is null) throw new InvalidOperationException("missing-test-evidence");
        foreach (string[] path in FieldPaths(baseline, []))
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
            await Assert.That(service.RootExists || service.CredentialsRetained).IsFalse();
        }
    }

    [Test]
    [Arguments("open", "sourceIdentity", "other")]
    [Arguments("open", "clockAuthority", "")]
    [Arguments("open", "clockEpoch", "")]
    [Arguments("open", "registrationId", "bad\nid")]
    [Arguments("open", "ownedRootCreated", "false")]
    [Arguments("open", "rootInitiallyAbsent", "false")]
    [Arguments("open", "serviceBindAccepted", "false")]
    [Arguments("open", "wrongServiceBindRejected", "false")]
    [Arguments("open", "userBindAccepted", "false")]
    [Arguments("open", "wrongUserBindRejected", "false")]
    [Arguments("open", "sequence", "-1")]
    [Arguments("rotate", "originalServiceRejected", "false")]
    [Arguments("rotate", "rotatedServiceAccepted", "false")]
    [Arguments("rotate", "userCredentialUnchanged", "false")]
    [Arguments("rotate", "ownedRootOnly", "false")]
    [Arguments("rotate", "sequence", "0")]
    [Arguments("rotate", "eventId", "")]
    [Arguments("arm", "registrationId", "directory-registration")]
    [Arguments("arm", "cursor", "0")]
    [Arguments("arm", "captureArmed", "false")]
    [Arguments("complete", "disposition", "Rejected")]
    [Arguments("complete", "disposition", "99")]
    [Arguments("complete", "status", "Denied")]
    [Arguments("complete", "status", "99")]
    [Arguments("complete", "sequence", "0")]
    [Arguments("complete", "providerRequestId", "")]
    [Arguments("complete", "eventId", "")]
    [Arguments("complete", "serviceBindAccepted", "false")]
    [Arguments("complete", "userBindAttempted", "false")]
    [Arguments("complete", "userBindAccepted", "false")]
    [Arguments("complete", "tokenIssued", "false")]
    [Arguments("complete", "tokenMetadataId", "not-uuid")]
    [Arguments("complete", "tokenMetadataId", "00000000-0000-0000-0000-000000000000")]
    [Arguments("complete", "lastLoginAuthMethod", "universal-auth")]
    [Arguments("complete", "matchedRequests", "2")]
    [Arguments("complete", "matchedIssuances", "2")]
    [Arguments("complete", "providerClockObserved", "false")]
    [Arguments("complete", "excludesLateCommit", "false")]
    [Arguments("arm-template", "registrationId", "directory-registration")]
    [Arguments("arm-template", "cursor", "0")]
    [Arguments("arm-template", "captureArmed", "false")]
    [Arguments("complete-template", "disposition", "Rejected")]
    [Arguments("complete-template", "templateId", "not-uuid")]
    [Arguments("complete-template", "providerRequestId", "")]
    [Arguments("complete-template", "sequence", "0")]
    [Arguments("complete-template", "matchedMutations", "2")]
    [Arguments("complete-template", "applied", "false")]
    [Arguments("complete-template", "excludesLateCommit", "false")]
    [Arguments("complete-template", "noReplay", "false")]
    [Arguments("seal", "sequence", "0")]
    [Arguments("seal", "watermark", "")]
    [Arguments("seal", "loginEvents", "2")]
    [Arguments("seal", "complete", "false")]
    [Arguments("seal", "noFurtherLogins", "false")]
    [Arguments("seal", "searchVisibilityEstablished", "false")]
    [Arguments("close", "closed", "false")]
    [Arguments("close", "ownedRootRemoved", "false")]
    [Arguments("close", "unrelatedRootsPreserved", "false")]
    [Arguments("close", "credentialsDestroyed", "false")]
    [Arguments("close", "mutationSettled", "false")]
    [Arguments("close", "lateCreationFenced", "false")]
    [Arguments("close", "remainingRegistrations", "1")]
    [Arguments("close", "pendingDeliveries", "1")]
    public async Task MalformedMeasurementsCannotBecomeEvidence(string route, string field, string value)
    {
        using var service = new Service
        {
            Change = (actual, facts) =>
            {
                if (actual != route) return;
                facts[field] = value is "true" or "false" ? JsonValue.Create(bool.Parse(value)) :
                    int.TryParse(value, out int number) ? JsonValue.Create(number) : JsonValue.Create(value);
            }
        };
        await Assert.That(async () => await Exercise(service, route)).Throws<NativeCaseFailureException>();
        await Assert.That(service.RootExists || service.CredentialsRetained).IsFalse();
    }

    [Test]
    [Arguments("open")]
    [Arguments("rotate")]
    [Arguments("arm")]
    [Arguments("complete")]
    [Arguments("arm-template")]
    [Arguments("complete-template")]
    [Arguments("seal")]
    [Arguments("close")]
    public async Task SubstitutedBindingOrClockCannotBecomeEvidence(string route)
    {
        using var service = new Service
        {
            Change = (actual, facts) =>
            {
                if (actual != route) return;
                var directory = route switch
                {
                    "open" or "close" => null,
                    "rotate" => facts["binding"],
                    "arm" or "arm-template" => facts["attempt"]!["directory"],
                    "complete" or "complete-template" => facts["arm"]!["attempt"]!["directory"],
                    _ => facts["directory"]
                };
                if (directory is null) facts["attempt"]!["deploymentId"] = "other";
                else directory["clockEpoch"] = "other-epoch";
            }
        };
        await Assert.That(async () => await Exercise(service, route)).Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("open", false)]
    [Arguments("arm", false)]
    [Arguments("complete", false)]
    [Arguments("seal", false)]
    [Arguments("arm", true)]
    [Arguments("complete", true)]
    public async Task ProviderTimesMustBeUtcAndNotMoveBackwards(string route, bool backward)
    {
        using var service = new Service
        {
            Change = (actual, facts) =>
            {
                if (actual != route) return;
                string field = route switch { "open" => "openedAt", "arm" => "armedAt", "complete" => "lastLoginAt", _ => "closedAt" };
                facts[field] = backward ? Clock.AddSeconds(-1) : Clock.ToOffset(TimeSpan.FromHours(1));
            }
        };
        await Assert.That(async () => await Exercise(service, route)).Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("open")]
    [Arguments("rotate")]
    [Arguments("arm")]
    [Arguments("complete")]
    [Arguments("arm-template")]
    [Arguments("complete-template")]
    [Arguments("seal")]
    public async Task LostOperationReplyNeverReplaysAndCleanupUsesOriginalAttempt(string route)
    {
        using var service = new Service { LostRoute = route };
        var observer = service.Observer();
        var attempt = Attempt();
        LdapDirectoryBinding? directory = null;
        await Assert.That(async () =>
        {
            directory = await Open(observer, attempt);
            await Through(observer, directory, route);
        }).Throws<NativeCaseFailureException>();
        service.LostRoute = null;
        await Assert.That(async () => await Open(observer, attempt)).Throws<NativeCaseFailureException>();
        if (directory is not null)
            await Assert.That(async () => await observer.RotateAsync(directory, CancellationToken.None))
                .Throws<NativeCaseFailureException>();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.That(async () => await observer.CloseAsync(attempt with { }, cancelled.Token))
            .Throws<NativeCaseFailureException>();
        await observer.CloseAsync(attempt, cancelled.Token);
        await Assert.That(service.ClosedAttempt).IsEqualTo(attempt);
        await Assert.That(service.RootExists || service.CredentialsRetained).IsFalse();
        await Assert.That(service.UnrelatedRootExists).IsTrue();
        await Assert.That(service.Routes.Count(actual => actual == route)).IsEqualTo(1);
        await Assert.That(service.Buffers.All(buffer => buffer.All(value => value == 0))).IsTrue();
    }

    [Test]
    public async Task OriginalReferencesAndOutstandingArmsProtectHostOperations()
    {
        using var service = new Service();
        var observer = service.Observer();
        var attempt = Attempt();
        var directory = await Open(observer, attempt);
        await Assert.That(async () => await observer.RotateAsync(directory with { }, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        var arm = await observer.ArmAsync(Login(directory), CancellationToken.None);
        await Assert.That(async () => await observer.CompleteAsync(arm with { }, DispatchEvidence.Applied,
            SecretStatus.Success, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.SealAsync(directory, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.ArmTemplateAsync(Template(directory), CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.RotateAsync(directory, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await observer.CompleteAsync(arm, DispatchEvidence.Applied, SecretStatus.Success, CancellationToken.None);
        await Assert.That(async () => await observer.ArmAsync(Login(directory), CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        var template = await observer.ArmTemplateAsync(Template(directory), CancellationToken.None);
        await Assert.That(async () => await observer.CompleteTemplateAsync(template with { }, DispatchEvidence.Applied,
            CancellationToken.None)).Throws<NativeCaseFailureException>();
        await Assert.That(async () => await observer.SealAsync(directory, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await observer.CompleteTemplateAsync(template, DispatchEvidence.Applied, CancellationToken.None);
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    public async Task InFlightSourceOperationExcludesOtherAttemptsAndCleanup()
    {
        using var service = new Service { PauseRoute = "open" };
        var observer = service.Observer();
        var attempt = Attempt();
        Task<LdapDirectoryBinding> pending = Open(observer, attempt);
        try
        {
            await service.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(async () => await Open(observer, attempt with { Id = "other" }))
                .Throws<NativeCaseFailureException>();
            await Assert.That(async () => await observer.CloseAsync(attempt, CancellationToken.None))
                .Throws<NativeCaseFailureException>();
        }
        finally { service.Continue.TrySetResult(); }
        await pending;
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    [Arguments(DispatchEvidence.Pending, SecretStatus.Pending)]
    [Arguments(DispatchEvidence.Conflict, SecretStatus.Conflict)]
    [Arguments((DispatchEvidence)99, SecretStatus.Denied)]
    [Arguments(DispatchEvidence.Applied, SecretStatus.Denied)]
    [Arguments(DispatchEvidence.Rejected, SecretStatus.Success)]
    [Arguments(DispatchEvidence.PossiblyDispatched, (SecretStatus)99)]
    public async Task InvalidLoginReceiptAndStatusDoNotDispatch(DispatchEvidence receipt, SecretStatus status)
    {
        using var service = new Service();
        var observer = service.Observer();
        var attempt = Attempt();
        var directory = await Open(observer, attempt);
        var arm = await observer.ArmAsync(Login(directory), CancellationToken.None);
        await Assert.That(async () => await observer.CompleteAsync(arm, receipt, status, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(service.Routes.Contains("complete")).IsFalse();
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("tokenIssued")]
    [Arguments("tokenMetadataId")]
    [Arguments("lastLoginAt")]
    [Arguments("lastLoginAuthMethod")]
    [Arguments("matchedIssuances")]
    [Arguments("userBindAccepted")]
    [Arguments("serviceBindAccepted")]
    public async Task RejectedLoginCannotClaimTokenOrInconsistentStages(string field)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route != "complete") return;
                facts[field] = field switch
                {
                    "tokenMetadataId" => JsonValue.Create(Id),
                    "lastLoginAt" => JsonValue.Create(Clock),
                    "lastLoginAuthMethod" => JsonValue.Create("ldap-auth"),
                    "matchedIssuances" => JsonValue.Create(1),
                    "serviceBindAccepted" => JsonValue.Create(false),
                    _ => JsonValue.Create(true)
                };
            }
        };
        var observer = service.Observer();
        var attempt = Attempt();
        var directory = await Open(observer, attempt);
        var arm = await observer.ArmAsync(Login(directory, wrongUser: true), CancellationToken.None);
        await Assert.That(async () => await observer.CompleteAsync(arm, DispatchEvidence.Rejected,
            SecretStatus.Denied, CancellationToken.None)).Throws<NativeCaseFailureException>();
        service.Change = null;
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("metadata")]
    [Arguments("name")]
    [Arguments("disposition")]
    [Arguments("mutation")]
    [Arguments("request")]
    public async Task TemplateFenceCannotSubstituteOwnedTargetOrDispatchState(string mode)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route != "complete-template") return;
                switch (mode)
                {
                    case "metadata": facts["templateId"] = "00000000-0000-0000-0000-000000000002"; break;
                    case "name": facts["arm"]!["attempt"]!["templateName"] = "unrelated"; break;
                    case "disposition": facts["disposition"] = "PossiblyDispatched"; break;
                    case "mutation": facts["matchedMutations"] = 0; break;
                    case "request": facts["providerRequestId"] = null; break;
                }
            }
        };
        var observer = service.Observer();
        var attempt = Attempt();
        var directory = await Open(observer, attempt);
        var arm = await observer.ArmTemplateAsync(Template(directory, existing: true), CancellationToken.None);
        await Assert.That(async () => await observer.CompleteTemplateAsync(arm, DispatchEvidence.Applied, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        service.Change = null;
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("event")]
    [Arguments("request")]
    [Arguments("registration")]
    [Arguments("cursor")]
    [Arguments("clock")]
    public async Task SequentialSourceEvidenceCannotReuseIdentifiersOrCursor(string mode)
    {
        using var service = new Service();
        var observer = service.Observer();
        var attempt = Attempt();
        var directory = await Open(observer, attempt);
        var first = await observer.ArmAsync(Login(directory, "first"), CancellationToken.None);
        var completed = await observer.CompleteAsync(first, DispatchEvidence.Applied, SecretStatus.Success, CancellationToken.None);
        service.Change = (route, facts) =>
        {
            if (route == "arm")
            {
                if (mode == "registration") facts["registrationId"] = first.RegistrationId;
                if (mode == "cursor") facts["cursor"] = completed.Sequence;
                if (mode == "clock") facts["armedAt"] = Clock;
            }
            if (route == "complete")
            {
                if (mode == "event") facts["eventId"] = completed.EventId;
                if (mode == "request") facts["providerRequestId"] = completed.ProviderRequestId;
            }
        };
        await Assert.That(async () =>
        {
            var second = await observer.ArmAsync(Login(directory, "second"), CancellationToken.None);
            await observer.CompleteAsync(second, DispatchEvidence.Applied, SecretStatus.Success, CancellationToken.None);
        }).Throws<NativeCaseFailureException>();
        service.Change = null;
        await observer.CloseAsync(attempt, CancellationToken.None);
    }

    [Test]
    [Arguments("version")]
    [Arguments("source")]
    [Arguments("organization")]
    [Arguments("url")]
    [Arguments("text")]
    [Arguments("long")]
    public async Task InvalidDirectoryScopeCannotDispatch(string mode)
    {
        using var service = new Service();
        var observer = service.Observer();
        var attempt = mode switch
        {
            "version" => Attempt() with { ProviderVersion = "v0.166.4" },
            "source" => Attempt() with { Source = (LdapLoginSource)99 },
            "organization" => Attempt() with { OrganizationId = "not-uuid" },
            "url" => Attempt() with { Url = "https://directory.invalid" },
            "text" => Attempt() with { BindDn = "bad\nid" },
            _ => Attempt() with { RootNonce = new string('a', 513) }
        };
        await Assert.That(async () => await Open(observer, attempt)).Throws<NativeCaseFailureException>();
        await Assert.That(service.RootExists || service.CredentialsRetained).IsFalse();
        await Assert.That(service.Routes.Count).IsEqualTo(0);
    }

    [Test]
    public async Task DisposedCommandMaterialDoesNotDispatchOrLeakEarlierCopies()
    {
        using var service = new Service();
        var observer = service.Observer();
        var attempt = Attempt();
        using var credentials = Credentials();
        credentials.WrongUser.Dispose();
        await Assert.That(async () => await observer.OpenAsync(attempt, credentials, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(service.Routes.Count).IsEqualTo(0);
        await Assert.That(credentials.Original.Reveal()).IsEqualTo("original-private");
        await observer.CloseAsync(attempt, CancellationToken.None);
        await Assert.That(service.CredentialsRetained).IsFalse();
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("identity")]
    [Arguments("schema")]
    [Arguments("duplicate")]
    [Arguments("unknown")]
    [Arguments("http")]
    public async Task EnvelopeAndHttpFailuresRemainSanitizedAndCleanable(string mode)
    {
        using var service = new Service { EnvelopeFault = mode };
        var observer = service.Observer();
        var attempt = Attempt();
        await Assert.That(async () => await Open(observer, attempt)).Throws<NativeCaseFailureException>();
        service.EnvelopeFault = null;
        await observer.CloseAsync(attempt, CancellationToken.None);
        await Assert.That(service.RootExists || service.CredentialsRetained).IsFalse();
        await Assert.That(service.Buffers.All(buffer => buffer.All(value => value == 0))).IsTrue();
    }

    [Test]
    [Arguments("ControlledFixture")]
    [Arguments("1")]
    [Arguments("NativeProvider")]
    [Arguments("0")]
    [Arguments("role")]
    [Arguments("99")]
    public async Task NativeConfigurationCannotSelectControlledAuthority(string mode)
    {
        JsonObject settings = JsonSerializer.SerializeToNode(Settings, Json)!.AsObject();
        settings["source"] = int.TryParse(mode, out int value) ? JsonValue.Create(value) : JsonValue.Create(mode);
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
            ["families"] = new JsonObject
            {
                ["C08-IR-InfisicalProofAuthentication"] = new JsonObject { ["observer"] = settings }
            }
        }.ToJsonString());
        using var environment = NativeEnvironment.Create(document.RootElement);
        if (mode is "NativeProvider" or "0")
            await Assert.That(InfisicalLdapLoginObserver.FromInputs(environment, "C08-IR-InfisicalProofAuthentication") is not null)
                .IsTrue();
        else
            await Assert.That(() => InfisicalLdapLoginObserver.FromInputs(environment, "C08-IR-InfisicalProofAuthentication"))
                .Throws<NativeCaseFailureException>();
    }

    private static async Task Exercise(Service service, string route)
    {
        var observer = service.Observer();
        var attempt = Attempt();
        try
        {
            var directory = await Open(observer, attempt);
            if (route != "open") await Through(observer, directory, route);
            if (route == "close") await observer.CloseAsync(attempt, CancellationToken.None);
        }
        finally
        {
            service.Change = null;
            if (route != "close") await observer.CloseAsync(attempt, CancellationToken.None);
        }
    }

    private static async Task Through(InfisicalLdapLoginObserver observer, LdapDirectoryBinding directory, string route)
    {
        if (route == "rotate") await observer.RotateAsync(directory, CancellationToken.None);
        else if (route is "arm-template" or "complete-template")
        {
            var arm = await observer.ArmTemplateAsync(Template(directory), CancellationToken.None);
            if (route == "complete-template")
                await observer.CompleteTemplateAsync(arm, DispatchEvidence.Applied, CancellationToken.None);
        }
        else if (route != "close")
        {
            var arm = await observer.ArmAsync(Login(directory), CancellationToken.None);
            if (route != "arm")
                await observer.CompleteAsync(arm, DispatchEvidence.Applied, SecretStatus.Success, CancellationToken.None);
            if (route == "seal") await observer.SealAsync(directory, CancellationToken.None);
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
        internal Action<string, JsonObject>? Change { get; set; }
        internal string? LostRoute { get; set; }
        internal string? EnvelopeFault { get; set; }
        internal string? PauseRoute { get; set; }
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Continue { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal List<byte[]> Buffers { get; } = [];
        internal List<string> Routes { get; } = [];
        internal bool TemplateApplied { get; set; } = true;
        internal bool RootExists { get; private set; }
        internal bool UnrelatedRootExists { get; } = true;
        internal bool CredentialsRetained => privateValues.Count != 0;
        internal bool PrivateOnlyInOpen { get; private set; } = true;
        internal LdapDirectoryAttempt? ClosedAttempt { get; private set; }
        private readonly List<char[]> privateValues = [];
        private byte[]? correlationKey;
        private LdapServiceCredential activeCredential;
        private long sequence;
        private int loginEvents;
        private DateTimeOffset time = Clock;

        internal InfisicalLdapLoginObserver Observer() =>
            new(new(Settings, this, length =>
            {
                byte[] buffer = new byte[length];
                Buffers.Add(buffer);
                return buffer;
            }), Settings.Identity, LdapLoginSource.ControlledFixture);

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
                await Assert.That(request.RequestUri.AbsolutePath).IsEqualTo("/owned/ldap-login/" + route);
                if (route != "open" && body.TryGetProperty("credentials", out _)) PrivateOnlyInOpen = false;
                if (route == PauseRoute)
                {
                    Entered.TrySetResult();
                    await Continue.Task.WaitAsync(TimeSpan.FromSeconds(10), token);
                }
                object evidence;
                switch (route)
                {
                    case "open":
                        var attempt = body.GetProperty("attempt").Deserialize<LdapDirectoryAttempt>(Json)!;
                        var credentials = body.GetProperty("credentials");
                        correlationKey = credentials.GetProperty("correlationKey").GetBytesFromBase64();
                        await Assert.That(correlationKey.Length).IsEqualTo(32);
                        foreach (string name in new[] { "original", "rotated", "wrongService", "user", "wrongUser" })
                        {
                            char[] value = credentials.GetProperty(name).GetString()!.ToCharArray();
                            privateValues.Add(value);
                            await Assert.That(value.Length > 0).IsTrue();
                        }
                        await Assert.That(privateValues[0].AsSpan().SequenceEqual("original-private")).IsTrue();
                        RootExists = true;
                        evidence = new LdapDirectoryBinding(attempt, "directory-registration", Settings.Identity,
                            "provider-clock", "epoch", Clock, ++sequence, true, true, true, true, true, true);
                        break;
                    case "rotate":
                        var directory = body.GetProperty("directory").Deserialize<LdapDirectoryBinding>(Json)!;
                        activeCredential = LdapServiceCredential.Rotated;
                        evidence = new LdapDirectoryRotation(directory, ++sequence, "rotation-event", true, true, true, true);
                        break;
                    case "arm":
                        var login = body.GetProperty("attempt").Deserialize<LdapLoginAttempt>(Json)!;
                        evidence = new LdapLoginArm(login, "login-registration-" + sequence, ++sequence, time, true);
                        break;
                    case "complete":
                        var arm = body.GetProperty("arm").Deserialize<LdapLoginArm>(Json)!;
                        var receipt = body.GetProperty("receipt").Deserialize<DispatchEvidence>(Json);
                        var status = body.GetProperty("status").Deserialize<SecretStatus>(Json);
                        bool dispatched = receipt != DispatchEvidence.NotDispatched;
                        bool serviceAccepted = dispatched && arm.Attempt.ServiceCredential == activeCredential;
                        bool userAccepted = serviceAccepted && !arm.Attempt.WrongUser;
                        bool issued = userAccepted;
                        if (issued) time = time.AddSeconds(1);
                        if (dispatched) loginEvents++;
                        evidence = new LdapLoginFence(arm, receipt, status, dispatched ? "login-request-" + sequence : "",
                            "login-event-" + sequence, ++sequence, serviceAccepted, serviceAccepted, userAccepted,
                            issued, issued ? Id : null, issued ? time : null, issued ? "ldap-auth" : null,
                            dispatched ? 1 : 0, issued ? 1 : 0, true, true,
                            issued ? Convert.ToBase64String(new byte[32]) : null);
                        break;
                    case "arm-template":
                        var template = body.GetProperty("attempt").Deserialize<LdapTemplateAttempt>(Json)!;
                        evidence = new LdapTemplateArm(template, "template-registration-" + sequence, ++sequence, true);
                        break;
                    case "complete-template":
                        var templateArm = body.GetProperty("arm").Deserialize<LdapTemplateArm>(Json)!;
                        var templateReceipt = body.GetProperty("receipt").Deserialize<DispatchEvidence>(Json);
                        bool mutation = templateReceipt != DispatchEvidence.NotDispatched;
                        evidence = new LdapTemplateFence(templateArm, templateReceipt,
                            templateArm.Attempt.TemplateId ?? (TemplateApplied ? Id : null),
                            mutation ? "template-request-" + sequence : null, ++sequence, mutation ? 1 : 0,
                            TemplateApplied, true, true);
                        break;
                    case "seal":
                        evidence = new LdapLoginVisibility(body.GetProperty("directory").Deserialize<LdapDirectoryBinding>(Json)!,
                            ++sequence, "visibility", time, loginEvents, true, true, true);
                        break;
                    case "close":
                        ClosedAttempt = body.GetProperty("attempt").Deserialize<LdapDirectoryAttempt>(Json)!;
                        RootExists = false;
                        foreach (char[] value in privateValues) Array.Clear(value);
                        privateValues.Clear();
                        if (correlationKey is not null) CryptographicOperations.ZeroMemory(correlationKey);
                        correlationKey = null;
                        evidence = new LdapDirectoryCleanup(ClosedAttempt, true, true, true, true, true, true, 0, 0);
                        break;
                    default: throw new InvalidOperationException("unexpected-route");
                }
                if (route == LostRoute) throw new HttpRequestException("original-private");
                JsonObject facts = JsonSerializer.SerializeToNode(evidence, Json)!.AsObject();
                Change?.Invoke(route, facts);
                if (EnvelopeFault == "unknown") facts["credentials"] = "original-private";
                var envelope = new JsonObject
                {
                    ["schemaVersion"] = EnvelopeFault == "schema" ? 2 : 1,
                    ["nonce"] = EnvelopeFault == "nonce" ? "other" : body.GetProperty("nonce").GetString(),
                    ["observerIdentity"] = EnvelopeFault == "identity" ? "other" : Settings.Identity,
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
            foreach (char[] value in privateValues) Array.Clear(value);
            privateValues.Clear();
            if (correlationKey is not null) CryptographicOperations.ZeroMemory(correlationKey);
            correlationKey = null;
            base.Dispose(disposing);
        }
    }
}
