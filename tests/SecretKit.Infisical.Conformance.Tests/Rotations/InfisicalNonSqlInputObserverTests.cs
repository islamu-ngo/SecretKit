using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Synthetic independent journals qualify the protocol, never native provider effects.
public sealed class InfisicalNonSqlInputObserverTests
{
    private static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private static readonly Guid Definition = Guid.Parse("00000000-0000-0000-0000-000000000002");
    private static readonly DateTimeOffset Clock = DateTimeOffset.UnixEpoch.AddDays(1);
    private static readonly InfisicalLifecycleObservers.Settings Settings =
        new(new("https://source.invalid/private/"), "synthetic-token", "nonsql-source-instance", 30);
    private static InfisicalDynamicProfileInput Profile(InfisicalDynamicProvider provider, string name) => provider switch
    {
        InfisicalDynamicProvider.Redis => new(Redis: new(name + ".invalid", 6379, name, "create", "revoke",
            name + "-private-password")),
        InfisicalDynamicProvider.Totp => new(Totp: new("otpauth://totp/" + name +
            "?secret=JBSWY3DPEHPK3PXP&issuer=synthetic")),
        InfisicalDynamicProvider.Ssh => new(Ssh: new([name])),
        _ => throw new InvalidOperationException("unexpected-test-provider")
    };
    private static InfisicalDynamicClientEffects.DynamicInput Input(InfisicalDynamicProvider provider) =>
        new(new("00000000-0000-0000-0000-000000000001", "synthetic", "testing", "environment", "/"),
            null, 60, 120, 60, null, [], [], [],
            NonSqlProfile: Profile(provider, "selected"),
            NonSqlInputWitness: new("deployment", "controlled-fixture", "root-nonce", 30,
                Profile(provider, "baseline")));
    private static NonSqlInputRootAttempt Root(InfisicalDynamicProvider provider = InfisicalDynamicProvider.Redis,
        string id = "root", string nonce = "root-nonce") =>
        new(id, "case", "v0.166.3", "deployment", "controlled-fixture", nonce, provider,
            NonSqlInputPrivateProfiles.Kind(provider), Input(provider).Sandbox.ProjectId, "testing", "/owned",
            NonSqlInputSource.ControlledFixture);
    private static NonSqlInputPrivateProfiles Profiles(InfisicalDynamicProvider provider = InfisicalDynamicProvider.Redis,
        string operation = "UpdateDefinitionAsync")
    {
        var input = Input(provider);
        return new(provider, input.NonSqlInputWitness!, input.NonSqlProfile, null, null, operation, "profile", input);
    }
    private static NonSqlInputAttempt Attempt(NonSqlInputBinding binding,
        string operation = "UpdateDefinitionAsync", NonSqlInputConfiguration configuration = NonSqlInputConfiguration.Selected,
        string id = "attempt") => new(binding, id, "owned-definition", Definition, operation, "profile", "case", configuration);

    private static NativeEnvironment Environment(JsonObject? observer = null) =>
        NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = "https://provider.invalid",
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families = new JsonObject
            {
                [InfisicalDynamicClientEffects.Family] = observer is null ? new JsonObject() :
                    new JsonObject { ["observer"] = observer.DeepClone() }
            }
        }, Json));
    private static ValueTask<NonSqlInputTrial> Trial(Service service, NativeEnvironment environment,
        bool channel = true, InfisicalDynamicProvider provider = InfisicalDynamicProvider.Redis,
        string operation = "UpdateDefinitionAsync")
    {
        var input = Input(provider);
        var row = new NativeCaseDefinition(new("Infisical", "i.runtime.InfisicalDynamicClient." + operation,
            "profile", "offline", "case"), "synthetic-member");
        return NonSqlInputTrial.OpenAsync(environment, row, input, provider, input.NonSqlProfile, null, null,
            "/owned", channel ? service.Observer() : service, CancellationToken.None);
    }

    [Test]
    [Arguments(DispatchEvidence.Applied, true)]
    [Arguments(DispatchEvidence.Rejected, false)]
    [Arguments(DispatchEvidence.NotDispatched, false)]
    [Arguments(DispatchEvidence.PossiblyDispatched, true)]
    [Arguments(DispatchEvidence.PossiblyDispatched, false)]
    public async Task OriginalDispositionAndPrivateCopiesAreFenced(DispatchEvidence receipt, bool applied)
    {
        using var service = new Service { Applied = applied };
        using var env = Environment();
        await using (var trial = await Trial(service, env))
        {
            await trial.ArmAsync("owned", Definition, "UpdateDefinitionAsync", "profile", "case",
                NonSqlInputConfiguration.Selected, CancellationToken.None);
            var fence = await trial.CompleteAsync(receipt, CancellationToken.None);
            await Assert.That(fence.MatchedCommits).IsEqualTo(applied ? 1 : 0);
            await trial.ObserveAsync(Definition, applied ? NonSqlInputConfiguration.Selected :
                NonSqlInputConfiguration.Baseline, CancellationToken.None);
            await Assert.That(async () => await trial.CompleteAsync(receipt, CancellationToken.None))
                .Throws<NativeCaseFailureException>();
        }
        await Assert.That(service.ClosedRoot).IsEqualTo(service.OpenedRoot);
        await Assert.That(service.RootExists || service.PrivateRetained).IsFalse();
        await Assert.That(service.Buffers.All(b => b.All(v => v == 0))).IsTrue();
        await Assert.That(service.PrivateOnlyInOpen).IsTrue();
    }

    [Test]
    [Arguments("InspectDefinitionAsync")]
    [Arguments("ListDefinitionsAsync")]
    [Arguments("DeleteDefinitionAsync")]
    public async Task ReadAndDeleteRetainSaveLineageWithoutInventedMutation(string operation)
    {
        using var service = new Service();
        using var env = Environment();
        await using var trial = await Trial(service, env, operation: operation);
        var configuration = operation == "DeleteDefinitionAsync" ? NonSqlInputConfiguration.Absent :
            NonSqlInputConfiguration.Selected;
        await trial.ArmAsync("owned", Definition, operation, "profile", "case", configuration, CancellationToken.None);
        var fence = await trial.CompleteAsync(DispatchEvidence.Applied, CancellationToken.None);
        await Assert.That(fence.Applied).IsEqualTo(operation == "DeleteDefinitionAsync");
        await Assert.That(fence.MatchedCommits).IsEqualTo(operation == "DeleteDefinitionAsync" ? 1 : 0);
        await Assert.That(fence.DefinitionId).IsEqualTo(Definition);
        await trial.ObserveAsync(Definition, configuration, CancellationToken.None);
    }

    [Test]
    [Arguments(InfisicalDynamicProvider.Totp)]
    [Arguments(InfisicalDynamicProvider.Ssh)]
    public async Task LocalValidationHasTransformationAndNoAdministrativeFacts(InfisicalDynamicProvider provider)
    {
        using var service = new Service();
        using var env = Environment();
        await using var trial = await Trial(service, env, provider: provider);
        await trial.ArmAsync("owned", Definition, "UpdateDefinitionAsync", "profile", "case",
            NonSqlInputConfiguration.Selected, CancellationToken.None);
        await trial.CompleteAsync(DispatchEvidence.Applied, CancellationToken.None);
        await trial.ObserveAsync(Definition, NonSqlInputConfiguration.Selected, CancellationToken.None);
    }

    [Test]
    [Arguments("open", true)]
    [Arguments("arm", true)]
    [Arguments("complete", true)]
    [Arguments("open", false)]
    [Arguments("arm", false)]
    [Arguments("complete", false)]
    public async Task LostResponsesRecoverOriginalRootWithoutReplay(string lost, bool channel)
    {
        using var service = new Service { Lost = lost };
        using var env = Environment();
        await Assert.That(async () => await Exercise(service, env, channel)).Throws<NativeCaseFailureException>();
        await Assert.That(service.ClosedRoot).IsEqualTo(service.OpenedRoot);
        await Assert.That(service.RootExists || service.PrivateRetained).IsFalse();
        await Assert.That(service.Routes.Count(r => r == lost)).IsEqualTo(1);
    }

    [Test]
    [Arguments("open")]
    [Arguments("arm")]
    [Arguments("complete")]
    [Arguments("observe")]
    [Arguments("close")]
    public async Task EveryNestedJsonFieldIsRequired(string route)
    {
        JsonObject? original = null;
        using (var service = new Service
        {
            Change = (r, facts) =>
            {
                if (r == route) original = facts.DeepClone().AsObject();
            }
        })
        using (var env = Environment()) await Exercise(service, env, true);
        if (original is null) throw new InvalidOperationException("missing-test-facts");
        foreach (var path in Paths(original, []))
        {
            using var service = new Service
            {
                Change = (r, facts) =>
                {
                    if (r != route) return;
                    JsonObject parent = facts;
                    foreach (string key in path[..^1]) parent = parent[key]!.AsObject();
                    parent.Remove(path[^1]);
                }
            };
            using var env = Environment();
            await Assert.That(async () => await Exercise(service, env, true)).Throws<NativeCaseFailureException>();
            await Assert.That(service.RootExists || service.PrivateRetained).IsFalse();
        }
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task EveryQualificationCleanupAndContradictionIsChecked(bool channel)
    {
        var faults = new (string Route, string Field, JsonNode? Value, string Code)[]
        {
            ("open", "ownedRootCreated", JsonValue.Create(false), "observer-unavailable"),
            ("open", "rootInitiallyAbsent", JsonValue.Create(false), "observer-unavailable"),
            ("open", "distinctContrasts", JsonValue.Create(false), "observer-unavailable"),
            ("open", "independentStorageQualified", JsonValue.Create(false), "observer-unavailable"),
            ("open", "providerValidationCaptureQualified", JsonValue.Create(false), "observer-unavailable"),
            ("open", "upstreamDispositionCaptureQualified", JsonValue.Create(false), "observer-unavailable"),
            ("open", "deploymentAuthorityQualified", JsonValue.Create(false), "observer-unavailable"),
            ("open", "sourceIdentity", JsonValue.Create("runtime"), "observer-unavailable"),
            ("open", "clockAuthority", JsonValue.Create("host-clock"), "observer-unavailable"),
            ("open", "clockEpoch", JsonValue.Create(""), "observer-unavailable"),
            ("arm", "captureArmed", JsonValue.Create(false), "observer-unavailable"),
            ("arm", "cursor", JsonValue.Create(0), "observer-unavailable"),
            ("arm", "armedAt", JsonValue.Create(Clock), "observer-unavailable"),
            ("complete", "originalAttemptSettled", JsonValue.Create(false), "observer-unavailable"),
            ("complete", "excludesLateCommit", JsonValue.Create(false), "observer-unavailable"),
            ("complete", "matchedRequests", JsonValue.Create(2), "effect-mismatch"),
            ("complete", "matchedCommits", JsonValue.Create(2), "effect-mismatch"),
            ("complete", "noReplay", JsonValue.Create(false), "effect-mismatch"),
            ("complete", "upstreamActionsTerminal", JsonValue.Create(false), "effect-mismatch"),
            ("complete", "pendingUpstreamActions", JsonValue.Create(1), "effect-mismatch"),
            ("observe", "persistedMergeMatches", JsonValue.Create(false), "effect-mismatch"),
            ("observe", "optionsMatch", JsonValue.Create(false), "effect-mismatch"),
            ("observe", "administrativeAction", JsonValue.Create("arbitrary-ping"), "effect-mismatch"),
            ("observe", "administrativePrincipal", null, "effect-mismatch"),
            ("observe", "administrativeTarget", null, "effect-mismatch"),
            ("observe", "actualAdministrativeActionCaptured", JsonValue.Create(false), "effect-mismatch"),
            ("observe", "wrongAuthorityRejected", JsonValue.Create(false), "effect-mismatch"),
            ("observe", "providerSpecificTransportMatches", JsonValue.Create(false), "effect-mismatch"),
            ("observe", "deploymentAuthorityMatches", JsonValue.Create(false), "effect-mismatch"),
            ("observe", "originalValidationMatched", JsonValue.Create(false), "effect-mismatch"),
            ("observe", "borrowedStatePreserved", JsonValue.Create(false), "effect-mismatch"),
            ("observe", "localTransformationMatches", JsonValue.Create(true), "effect-mismatch")
        };
        foreach (var fault in faults)
        {
            using var service = new Service
            {
                Change = (route, facts) =>
                {
                    if (route == fault.Route) facts[fault.Field] = fault.Value?.DeepClone();
                }
            };
            using var env = Environment();
            string? code = null;
            try { await Exercise(service, env, channel); }
            catch (NativeCaseFailureException error) { code = error.Message; }
            await Assert.That(code).IsEqualTo(fault.Code);
        }
        foreach (string field in new[] { "closed", "ownedRootRemoved", "borrowedStatePreserved",
            "definitionsAbsent", "privateProfilesDestroyed", "originalAttemptsSettled", "lateCreationFenced",
            "ownedUpstreamResourcesAbsent", "ownedUpstreamMaterialDisposed", "pendingUpstreamActions",
            "remainingRegistrations", "pendingDeliveries" })
        {
            using var service = new Service
            {
                Change = (route, facts) =>
                {
                    if (route == "close") facts[field] = field is "pendingUpstreamActions" or
                        "remainingRegistrations" or "pendingDeliveries" ? JsonValue.Create(1) : JsonValue.Create(false);
                }
            };
            using var env = Environment();
            string? code = null;
            try { await Exercise(service, env, channel); }
            catch (NativeCaseFailureException error) { code = error.Message; }
            await Assert.That(code).IsEqualTo("cleanup-incomplete");
        }
    }

    [Test]
    [Arguments(InfisicalDynamicProvider.Totp, "administrativeAction")]
    [Arguments(InfisicalDynamicProvider.Ssh, "localKeyLineageMatches")]
    [Arguments(InfisicalDynamicProvider.Totp, "localTransformationMatches")]
    [Arguments(InfisicalDynamicProvider.Redis, "validationKind")]
    public async Task AdministrativeLocalMislabelingFails(InfisicalDynamicProvider provider, string field)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route != "observe") return;
                facts[field] = field switch
                {
                    "administrativeAction" => JsonValue.Create("invented-session"),
                    "validationKind" => JsonValue.Create((int)NonSqlValidationKind.LocalValidation),
                    _ => JsonValue.Create(false)
                };
            }
        };
        using var env = Environment();
        await Assert.That(async () => await Exercise(service, env, false, provider)).Throws<NativeCaseFailureException>();
    }

    [Test]
    public async Task CancelledEmptyJournalDoesNotInventRequestAndArmCannotReplay()
    {
        using var service = new Service { Applied = false, EmptyUncertain = true };
        var observer = service.Observer();
        var root = Root();
        using var profiles = Profiles();
        var binding = await observer.OpenAsync(root, profiles, CancellationToken.None);
        var arm = await observer.ArmAsync(Attempt(binding), CancellationToken.None);
        var fence = await observer.CompleteAsync(arm, DispatchEvidence.PossiblyDispatched, CancellationToken.None);
        await Assert.That(fence.MatchedRequests).IsEqualTo(0);
        await Assert.That(async () => await observer.CompleteAsync(arm,
            DispatchEvidence.PossiblyDispatched, CancellationToken.None)).Throws<NativeCaseFailureException>();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await observer.CloseAsync(root, cancelled.Token);
    }

    [Test]
    [Arguments("registration")]
    [Arguments("event")]
    [Arguments("request")]
    [Arguments("sequence")]
    [Arguments("time")]
    public async Task ReusedOrOutOfOrderEvidenceFails(string fault)
    {
        using var service = new Service();
        var observer = service.Observer();
        var root = Root();
        using var profiles = Profiles();
        var binding = await observer.OpenAsync(root, profiles, CancellationToken.None);
        var first = await observer.ArmAsync(Attempt(binding), CancellationToken.None);
        var fence = await observer.CompleteAsync(first, DispatchEvidence.Applied, CancellationToken.None);
        service.Change = (route, facts) =>
        {
            if (route == "arm" && fault == "registration") facts["registrationId"] = first.RegistrationId;
            if (route != "complete") return;
            if (fault == "event") facts["eventId"] = fence.EventId;
            if (fault == "request") facts["providerRequestId"] = fence.ProviderRequestId;
            if (fault == "sequence") facts["sequence"] = fence.Sequence;
            if (fault == "time") facts["settledAt"] = fence.SettledAt;
        };
        await Assert.That(async () =>
        {
            var second = await observer.ArmAsync(Attempt(binding, id: "second"), CancellationToken.None);
            await observer.CompleteAsync(second, DispatchEvidence.Applied, CancellationToken.None);
        }).Throws<NativeCaseFailureException>();
        service.Change = null;
        await observer.CloseAsync(root, CancellationToken.None);
    }

    [Test]
    public async Task OriginalObjectsAndRootNonceCannotBeReused()
    {
        using var service = new Service();
        var observer = service.Observer();
        var root = Root();
        using var profiles = Profiles();
        var binding = await observer.OpenAsync(root, profiles, CancellationToken.None);
        await Assert.That(async () => await observer.ArmAsync(Attempt(binding with { }), CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        var arm = await observer.ArmAsync(Attempt(binding), CancellationToken.None);
        await Assert.That(async () => await observer.CompleteAsync(arm with { },
            DispatchEvidence.Applied, CancellationToken.None)).Throws<NativeCaseFailureException>();
        await observer.CompleteAsync(arm, DispatchEvidence.Applied, CancellationToken.None);
        await observer.CloseAsync(root, CancellationToken.None);
        await Assert.That(async () => await observer.OpenAsync(Root(id: "second"), profiles, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("InspectDefinitionAsync", "applied")]
    [Arguments("ListDefinitionsAsync", "matchedCommits")]
    [Arguments("DeleteDefinitionAsync", "definitionAbsent")]
    public async Task ReadMutationOrDeleteWithoutAbsenceIsContradiction(string operation, string field)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route != "complete") return;
                facts[field] = field == "matchedCommits" ? JsonValue.Create(1) :
                    JsonValue.Create(field == "applied");
            }
        };
        using var env = Environment();
        await using var trial = await Trial(service, env, operation: operation);
        await trial.ArmAsync("owned", Definition, operation, "profile", "case",
            operation == "DeleteDefinitionAsync" ? NonSqlInputConfiguration.Absent :
                NonSqlInputConfiguration.Selected, CancellationToken.None);
        await Assert.That(async () => await trial.CompleteAsync(DispatchEvidence.Applied, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
    }

    [Test]
    public async Task AbsentCreationIsObservedWithoutInventingDefinitionId()
    {
        using var service = new Service
        {
            Applied = false,
            Change = (route, facts) =>
            {
                if (route != "complete") return;
                facts["definitionId"] = null;
                facts["definitionAbsent"] = true;
            }
        };
        using var env = Environment();
        await using var trial = await Trial(service, env, operation: "CreateDefinitionAsync");
        await trial.ArmAsync("owned", null, "CreateDefinitionAsync", "profile", "case",
            NonSqlInputConfiguration.Selected, CancellationToken.None);
        await trial.CompleteAsync(DispatchEvidence.NotDispatched, CancellationToken.None);
        await trial.ObserveAsync(null, NonSqlInputConfiguration.Absent, CancellationToken.None);
    }

    [Test]
    public async Task UnsettledArmBlocksFurtherMutationButNotOriginalCleanup()
    {
        using var service = new Service { Lost = "arm" };
        using var env = Environment();
        await using var trial = await Trial(service, env);
        await Assert.That(async () => await trial.ArmAsync("owned", Definition, "UpdateDefinitionAsync",
            "profile", "case", NonSqlInputConfiguration.Selected, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(async () => await trial.ArmAsync("owned", Definition, "UpdateDefinitionAsync",
            "profile", "case", NonSqlInputConfiguration.Selected, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(service.Routes.Count(r => r == "arm")).IsEqualTo(1);
    }

    [Test]
    public async Task ConcurrentArmCannotStealInFlightCapture()
    {
        using var service = new Service { GateRoute = "arm" };
        using var env = Environment();
        await using var trial = await Trial(service, env);
        var first = trial.ArmAsync("owned", Definition, "UpdateDefinitionAsync", "profile", "case",
            NonSqlInputConfiguration.Selected, CancellationToken.None).AsTask();
        await service.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        try
        {
            await Assert.That(async () => await trial.ArmAsync("other", Definition, "UpdateDefinitionAsync",
                "profile", "case", NonSqlInputConfiguration.Selected, CancellationToken.None))
                .Throws<NativeCaseFailureException>();
        }
        finally { service.Continue.TrySetResult(); }
        await first.WaitAsync(TimeSpan.FromSeconds(10));
        await trial.CompleteAsync(DispatchEvidence.Applied, CancellationToken.None);
        await Assert.That(service.Routes.Count(r => r == "arm")).IsEqualTo(1);
    }

    [Test]
    [Arguments("binding")]
    [Arguments("provider")]
    [Arguments("epoch")]
    [Arguments("root")]
    public async Task ForeignEvidenceCannotQualify(string foreign)
    {
        using var service = new Service
        {
            Change = (route, facts) =>
            {
                if (route != "arm") return;
                var binding = facts["attempt"]!["binding"]!.AsObject();
                if (foreign == "binding") binding["sourceIdentity"] = "foreign";
                if (foreign == "provider") binding["attempt"]!["provider"] = (int)InfisicalDynamicProvider.Ssh;
                if (foreign == "epoch") binding["clockEpoch"] = "foreign";
                if (foreign == "root") binding["attempt"]!["rootNonce"] = "foreign";
            }
        };
        using var env = Environment();
        await Assert.That(async () => await Exercise(service, env, true)).Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("schemaVersion")]
    [Arguments("nonce")]
    [Arguments("observerIdentity")]
    [Arguments("unknown")]
    public async Task ForeignOrMalformedEnvelopeIsUnavailable(string field)
    {
        using var service = new Service { EnvelopeFault = field };
        using var env = Environment();
        await Assert.That(async () => await Exercise(service, env, true)).Throws<NativeCaseFailureException>();
        await Assert.That(service.RootExists).IsFalse();
    }

    [Test]
    public async Task CleanupFailureOverridesLostOpenAndActiveMaterialCannotQualify()
    {
        using var service = new Service
        {
            Lost = "open",
            Change = (route, facts) =>
            {
                if (route == "close") facts["ownedUpstreamMaterialDisposed"] = false;
            }
        };
        using var env = Environment();
        string? code = null;
        try { await Trial(service, env); }
        catch (NativeCaseFailureException error) { code = error.Message; }
        await Assert.That(code).IsEqualTo("cleanup-incomplete");
    }

    [Test]
    [Arguments("ControlledFixture")]
    [Arguments(1)]
    [Arguments("foreign")]
    public async Task FromInputsAcceptsNativeSourceOnly(object source)
    {
        var configuration = JsonSerializer.SerializeToNode(Settings, Json)!.AsObject();
        configuration["source"] = JsonSerializer.SerializeToNode(source, Json);
        using var env = Environment(configuration);
        await Assert.That(() => InfisicalNonSqlInputObserver.FromInputs(env, InfisicalDynamicClientEffects.Family))
            .Throws<NativeCaseFailureException>();
        configuration["source"] = "NativeProvider";
        using var native = Environment(configuration);
        await Assert.That(InfisicalNonSqlInputObserver.FromInputs(native, InfisicalDynamicClientEffects.Family) is not null).IsTrue();
    }

    [Test]
    public async Task ProfilesZeroizeAndDiagnosticFormattingIsRedacted()
    {
        var profiles = Profiles();
        var arrays = typeof(NonSqlInputPrivateProfiles).GetFields(
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            .Where(f => f.FieldType == typeof(byte[])).Select(f => (byte[])f.GetValue(profiles)!).ToArray();
        await Assert.That(arrays.Any(a => a.Any(b => b != 0))).IsTrue();
        profiles.Dispose();
        await Assert.That(arrays.All(a => a.All(b => b == 0))).IsTrue();
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream);
        await Assert.That(() => profiles.Write(writer)).Throws<ObjectDisposedException>();
        await Assert.That(profiles.ToString()).IsEqualTo("[NonSqlInputPrivateProfiles]");
        await Assert.That(Root().ToString()).IsEqualTo("[NonSqlInputRootAttempt]");
        using var service = new Service();
        await Assert.That(service.Observer().ToString()).IsEqualTo("[InfisicalNonSqlInputObserver]");
    }

    private static async Task Exercise(Service service, NativeEnvironment env, bool channel,
        InfisicalDynamicProvider provider = InfisicalDynamicProvider.Redis)
    {
        await using var trial = await Trial(service, env, channel, provider);
        await trial.ArmAsync("owned", Definition, "UpdateDefinitionAsync", "profile", "case",
            NonSqlInputConfiguration.Selected, CancellationToken.None);
        await trial.CompleteAsync(DispatchEvidence.Applied, CancellationToken.None);
        await trial.ObserveAsync(Definition, NonSqlInputConfiguration.Selected, CancellationToken.None);
    }
    private static IEnumerable<string[]> Paths(JsonObject facts, string[] prefix)
    {
        foreach (var field in facts)
        {
            string[] path = [.. prefix, field.Key];
            yield return path;
            if (field.Value is JsonObject child)
                foreach (var nested in Paths(child, path)) yield return nested;
        }
    }

    private sealed class Service : HttpMessageHandler, IInfisicalNonSqlInputObserver
    {
        internal Action<string, JsonObject>? Change { get; set; }
        internal string? Lost { get; set; }
        internal string? EnvelopeFault { get; set; }
        internal string? GateRoute { get; set; }
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Continue { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool Applied { get; set; } = true;
        internal bool EmptyUncertain { get; set; }
        internal bool RootExists { get; private set; }
        internal bool PrivateRetained => privateCopies.Count != 0;
        internal bool PrivateOnlyInOpen { get; private set; } = true;
        internal NonSqlInputRootAttempt? OpenedRoot { get; private set; }
        internal NonSqlInputRootAttempt? ClosedRoot { get; private set; }
        internal List<byte[]> Buffers { get; } = [];
        internal List<string> Routes { get; } = [];
        private readonly List<byte[]> privateCopies = [];
        private long sequence;
        private NonSqlInputArm? lastArm;

        internal InfisicalNonSqlInputObserver Observer() => new(new(Settings, this, size =>
        {
            var bytes = new byte[size];
            Buffers.Add(bytes);
            return bytes;
        }), Settings.Identity, NonSqlInputSource.ControlledFixture);

        private T Facts<T>(string route, JsonElement body)
        {
            Routes.Add(route);
            if (route != "open" && body.TryGetProperty("profiles", out _)) PrivateOnlyInOpen = false;
            object evidence;
            long cursor = ++sequence;
            var time = Clock.AddTicks(cursor);
            switch (route)
            {
                case "open":
                    OpenedRoot = body.GetProperty("attempt").Deserialize<NonSqlInputRootAttempt>(Json)!;
                    privateCopies.Add(JsonSerializer.SerializeToUtf8Bytes(body.GetProperty("profiles"), Json));
                    RootExists = true;
                    evidence = new NonSqlInputBinding(OpenedRoot, "root-registration", Settings.Identity,
                        "provider-application-clock", "epoch", time, cursor, true, true, true, true, true, true, true);
                    break;
                case "arm":
                    var attempt = body.GetProperty("attempt").Deserialize<NonSqlInputAttempt>(Json)!;
                    lastArm = new(attempt, "arm-" + cursor, cursor, time, true);
                    evidence = lastArm;
                    break;
                case "complete":
                    var arm = body.GetProperty("arm").Deserialize<NonSqlInputArm>(Json)!;
                    var receipt = body.GetProperty("receipt").Deserialize<DispatchEvidence>(Json);
                    bool read = NonSqlInputEvidenceGuard.IsRead(arm.Attempt.Operation);
                    bool applied = Applied && !read;
                    bool empty = receipt == DispatchEvidence.NotDispatched ||
                        receipt == DispatchEvidence.PossiblyDispatched && EmptyUncertain;
                    evidence = new NonSqlInputFence(arm, receipt, "event-" + cursor,
                        empty ? null : "request-" + cursor, cursor, time, empty ? 0 : 1,
                        applied ? 1 : 0, applied, Definition, true,
                        applied && arm.Attempt.Operation == "DeleteDefinitionAsync", true, true, true, true, 0);
                    break;
                case "observe":
                    var binding = body.GetProperty("binding").Deserialize<NonSqlInputBinding>(Json)!;
                    bool local = binding.Attempt.ValidationKind == NonSqlValidationKind.LocalValidation;
                    evidence = new NonSqlInputObservation(binding, body.GetProperty("definitionId").Deserialize<Guid?>(Json),
                        body.GetProperty("configuration").Deserialize<NonSqlInputConfiguration>(Json),
                        lastArm!.Attempt.Id, "event-" + cursor, cursor, time, true, true, true,
                        binding.Attempt.ValidationKind, local ? null : "redis.auth-ping", local ? null : "synthetic-admin",
                        local ? null : "synthetic-target.invalid", !local, !local, local,
                        binding.Attempt.Provider == InfisicalDynamicProvider.Ssh, !local, !local, true, true);
                    break;
                case "close":
                    ClosedRoot = body.GetProperty("attempt").Deserialize<NonSqlInputRootAttempt>(Json)!;
                    RootExists = false;
                    foreach (var bytes in privateCopies) CryptographicOperations.ZeroMemory(bytes);
                    privateCopies.Clear();
                    evidence = new NonSqlInputCleanup(ClosedRoot, true, true, true, true, true, true,
                        true, true, true, 0, 0, 0);
                    break;
                default: throw new InvalidOperationException("unexpected-route");
            }
            if (route == Lost) throw new HttpRequestException("synthetic-private-failure");
            var facts = JsonSerializer.SerializeToNode(evidence, Json)!.AsObject();
            Change?.Invoke(route, facts);
            return facts.Deserialize<T>(Json)!;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token);
            try
            {
                using var document = JsonDocument.Parse(bytes);
                var body = document.RootElement;
                string route = request.RequestUri!.AbsolutePath.Split('/').Last();
                await Assert.That(request.RequestUri.AbsolutePath).IsEqualTo("/private/nonsql-input/" + route);
                // Keep JsonRequired failures inside the channel, not this fixture.
                Action<string, JsonObject>? change = Change;
                Change = null;
                JsonObject facts;
                try { facts = Facts<JsonObject>(route, body); }
                finally { Change = change; }
                if (route == GateRoute)
                {
                    Entered.TrySetResult();
                    await Continue.Task.WaitAsync(token);
                }
                change?.Invoke(route, facts);
                var envelope = new JsonObject
                {
                    ["schemaVersion"] = 1,
                    ["nonce"] = body.GetProperty("nonce").GetString(),
                    ["observerIdentity"] = Settings.Identity,
                    ["observedAt"] = DateTimeOffset.UtcNow,
                    ["facts"] = facts
                };
                if (EnvelopeFault is not null && route != "close")
                {
                    if (EnvelopeFault == "schemaVersion") envelope[EnvelopeFault] = 2;
                    else if (EnvelopeFault == "unknown") facts["privateMaterial"] = "synthetic";
                    else envelope[EnvelopeFault] = "foreign";
                }
                return new(HttpStatusCode.OK) { Content = new StringContent(envelope.ToJsonString(Json)) };
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }

        private ValueTask<T> Direct<T>(string route, object body, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            try { return ValueTask.FromResult(Facts<T>(route, JsonSerializer.SerializeToElement(body, Json))); }
            catch (HttpRequestException) { throw new NativeCaseFailureException("observer-unavailable"); }
        }
        public ValueTask<NonSqlInputBinding> OpenAsync(NonSqlInputRootAttempt attempt,
            NonSqlInputPrivateProfiles profiles, CancellationToken token)
        {
            using var buffer = new InfisicalLifecycleObservers.OwnedJsonBuffer(static size => new byte[size]);
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                writer.WritePropertyName("attempt");
                JsonSerializer.Serialize(writer, attempt, Json);
                profiles.Write(writer);
                writer.WriteEndObject();
            }
            using var document = JsonDocument.Parse(buffer.Buffer.AsMemory(0, buffer.WrittenCount));
            try { return ValueTask.FromResult(Facts<NonSqlInputBinding>("open", document.RootElement)); }
            catch (HttpRequestException) { throw new NativeCaseFailureException("observer-unavailable"); }
        }
        public ValueTask<NonSqlInputArm> ArmAsync(NonSqlInputAttempt attempt, CancellationToken token) =>
            Direct<NonSqlInputArm>("arm", new { attempt }, token);
        public ValueTask<NonSqlInputFence> CompleteAsync(NonSqlInputArm arm, DispatchEvidence receipt, CancellationToken token) =>
            Direct<NonSqlInputFence>("complete", new { arm, receipt }, token);
        public ValueTask<NonSqlInputObservation> ObserveAsync(NonSqlInputBinding binding, Guid? definitionId,
            NonSqlInputConfiguration configuration, CancellationToken token) =>
            Direct<NonSqlInputObservation>("observe", new { binding, definitionId, configuration }, token);
        public ValueTask<NonSqlInputCleanup> CloseAsync(NonSqlInputRootAttempt attempt, CancellationToken token) =>
            Direct<NonSqlInputCleanup>("close", new { attempt }, token);
    }
}
