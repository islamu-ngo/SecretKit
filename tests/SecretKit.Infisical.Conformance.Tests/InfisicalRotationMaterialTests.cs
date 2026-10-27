using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalRotationMaterialTests
{
    public static IEnumerable<(string Method, string Variant, string Boundary)> OriginalCases() =>
        InfisicalLifecycleFamilies.Catalog.Where(a => a.Operation is RotationMaterialEffects.Prefix + "GetAsync" or
            RotationMaterialEffects.Prefix + "ListAsync")
            .SelectMany(a => a.Variants.SelectMany(v => a.Cases.Select(c =>
                (a.Operation[RotationMaterialEffects.Prefix.Length..], v, c))));

    public static IEnumerable<InfisicalRotationProfile> PinnedProfiles() =>
        Enum.GetValues<InfisicalRotationProfile>().Where(p => RotationMaterialProfile.For(p).Pinned);

    private static InfisicalRotationProfile Profile(string variant) => variant.StartsWith("profile.", StringComparison.Ordinal) ?
        Enum.Parse<InfisicalRotationProfile>(variant[8..]) : InfisicalRotationProfile.PostgresCredentials;

    internal static NativeCaseDefinition Row(string method, string variant, string boundary)
    {
        var admission = InfisicalLifecycleFamilies.Catalog.Single(a => a.Operation == RotationMaterialEffects.Prefix + method);
        return new(new("Infisical", admission.Operation, variant, "controlled-material", boundary), admission.Member);
    }

    internal static NativeEnvironment Environment(NativeCaseDefinition row, RotationMaterialInput input)
    {
        var legacy = new InfisicalRotationClientEffects.RotationInput(
            new(input.ProjectId, "project", input.Environment, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "/borrowed"),
            "organization", input.Profile, "dddddddd-dddd-dddd-dddd-dddddddddddd",
            new(input.Profile, "backend.invalid", 5432, "database", "account"),
            "account-a", "account-b", null, 1, false, input.MaximumItems, input.AllowedActions, input.DeniedActions);
        var node = JsonSerializer.SerializeToNode(legacy, InfisicalRotationMaterialFixture.Json)!.AsObject();
        node[RotationMaterialEffects.Selection] = JsonSerializer.SerializeToNode(input, InfisicalRotationMaterialFixture.Json);
        var families = new JsonObject
        {
            [InfisicalRotationClientEffects.Family] = new JsonObject
            {
                ["scopes"] = new JsonObject
                {
                    [row.Key.Scope] = new JsonObject
                    {
                        [row.Key.Operation] = new JsonObject
                        {
                            [row.Key.Variant] = new JsonObject { [row.Key.Case] = node }
                        }
                    }
                }
            }
        };
        return NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = "https://rotation.invalid/",
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families
        }, InfisicalRotationMaterialFixture.Json));
    }

    internal static async Task<NativeCaseResult> Run(InfisicalRotationMaterialFixture fixture, NativeCaseDefinition row,
        RotationMaterialInput? input = null, IInfisicalRotationMaterialSource? injected = null)
    {
        using var environment = Environment(row, input ?? fixture.Input());
        var registry = new NativeCaseRegistry();
        RotationMaterialEffects.Register(registry, environment, [row], injected ?? fixture.Source.Client(),
            fixture.MetadataTransport, role => fixture.Consumer(environment, role));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        return (await NativeCaseRunner.RunAsync(registry, [row], deadline.Token)).Single();
    }

    [Test]
    public async Task ProfileAndOriginalAdmissionDenominatorsStayWhole()
    {
        await Assert.That(Enum.GetValues<InfisicalRotationProfile>().Length).IsEqualTo(30);
        await Assert.That(Enum.GetValues<InfisicalRotationProfile>().Count(p => RotationMaterialProfile.For(p).Pinned)).IsEqualTo(30);
        await Assert.That(OriginalCases().Count()).IsEqualTo(248);
        await Assert.That(Enum.GetValues<InfisicalRotationProfile>().Count(p => !RotationMaterialProfile.For(p).Overlap)).IsEqualTo(5);
    }

    [Test]
    public async Task GcpMappedMaterialPreservesTheWholeJsonFileInOneDestination()
    {
        await using var fixture = new InfisicalRotationMaterialFixture(InfisicalRotationProfile.GcpServiceAccountKey);
        var result = await Run(fixture, Row("GetAsync", "profile.GcpServiceAccountKey", "independent-effect"));
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Fields.Length).IsEqualTo(1);
        await Assert.That(fixture.Fields[0].Field).IsEqualTo("serviceAccountKey");
        using var file = JsonDocument.Parse(fixture.Fields[0].Value);
        await Assert.That(file.RootElement.GetProperty("private_key").GetString()).IsEqualTo("controlled-key");
        await Assert.That(fixture.ReadJournal.Count).IsEqualTo(2);
        await Assert.That(fixture.Residual).IsEqualTo(0);
    }

    [Test]
    [MethodDataSource(nameof(PinnedProfiles))]
    public async Task SourceCalibrationUsesPublicSdkWithoutEffectHandlerOrHostTrial(InfisicalRotationProfile profile)
    {
        await using var fixture = new InfisicalRotationMaterialFixture(profile);
        var input = fixture.Input();
        var row = Row("GetAsync", "profile." + profile, "independent-effect");
        using var environment = Environment(row, input);
        var root = new RotationMaterialRoot(Guid.NewGuid().ToString("D"), Guid.NewGuid().ToString("N"),
            row.Key.Identity, "v0.166.3", input.DeploymentId, input.SourceIdentity, input.ClockEpoch,
            input.Source, input.ProjectId, input.Environment, input.Folder, input.RotationId, input.Profile,
            input.Kind, input.Generation);
        var source = fixture.Source.Client();
        using var packet = new RotationMaterialPacket(profile, input.Kind, input.Generation, input.Fields);
        using var capability = SecretMaterial.FromText(input.SetupCapability);
        // Root and Close ownership are retained BEFORE calling Open.
        try
        {
            var binding = await source.OpenAsync(root, packet, capability, CancellationToken.None);
            await Assert.That(binding.ExactMaterialKnown && binding.IndependentJournals &&
                binding.SetupSettled && binding.NeverEnabled).IsTrue();
            var arm = await source.ArmAsync(binding, CancellationToken.None);
            using var http = new HttpClient(fixture.MetadataTransport, disposeHandler: false);
            var authority = new SecretAuthority();
            var client = new InfisicalRotationClient(environment.Origin, authority,
                new(authority, environment.Tokens(NativeIdentityRole.Runtime), input.ProjectId),
                new() { Transport = InfisicalTransportOptions.HostControlled(http) });
            var got = await client.GetAsync(new(authority, new InfisicalRotationAddress(input.ProjectId,
                input.Environment, input.Folder, profile, input.RotationId)));
            await Assert.That(got.Status).IsEqualTo(SecretStatus.Success);
            await using var consumer = fixture.Consumer(environment, NativeIdentityRole.Runtime);
            using var actual = await RotationMaterialPacket.ReadAsync(consumer, input, false, CancellationToken.None);
            using var wrong = actual.Wrong();
            var auth = await source.AuthenticateAsync(arm, actual, wrong, CancellationToken.None);
            await Assert.That(auth.ExactSuppliedMaterial && auth.CoherentGeneration && auth.IndependentBackend).IsTrue();
            await Assert.That(auth.Valid).IsEqualTo(BackendAuthentication.Accepted);
            await Assert.That(auth.Wrong).IsEqualTo(BackendAuthentication.Rejected);
            await Assert.That(auth.Recheck).IsEqualTo(BackendAuthentication.Accepted);
            await Assert.That(auth.AllowedActions.SequenceEqual(input.AllowedActions) &&
                auth.DeniedActions.SequenceEqual(input.DeniedActions)).IsTrue();
            var window = await source.CompleteAsync(arm, got.Status, CancellationToken.None);
            await Assert.That(window.OriginalSettled && window.ExcludesLateWork &&
                window.IndependentReadWindow && window.ConfigurationUnchanged &&
                window.MappingUnchanged && window.MaterialUnchanged && window.BackendInventoryUnchanged).IsTrue();
            await Assert.That(window.OriginalReads).IsEqualTo(1);
        }
        finally
        {
            var cleanup = await source.CloseAsync(root, CancellationToken.None);
            await Assert.That(cleanup.Root == root && cleanup.CompleteInventory && cleanup.PrivateDestroyed &&
                cleanup.BackendResourcesAbsent && cleanup.MappedSecretsAbsent && cleanup.OwnedSetupAbsent &&
                cleanup.BorrowedPreserved && cleanup.CapturedMaterialRetired).IsTrue();
        }
        await Assert.That(fixture.Source.Buffers.All(b => b.All(v => v == 0))).IsTrue();
        await Assert.That(fixture.Residual).IsEqualTo(0);
    }

    [Test]
    [MethodDataSource(nameof(OriginalCases))]
    public async Task IndependentCalibrationCoversEveryOriginalReadRow(string method, string variant, string boundary)
    {
        await using var fixture = new InfisicalRotationMaterialFixture(Profile(variant));
        var result = await Run(fixture, Row(method, variant, boundary));
        bool pinned = RotationMaterialProfile.For(fixture.Profile).Pinned;
        await Assert.That(result.Passed).IsEqualTo(pinned).Because(result.ReasonCode);
        await Assert.That(result.ReasonCode).IsEqualTo(pinned ? "observed" : "observer-unavailable");
        await Assert.That(fixture.Residual).IsEqualTo(0);
        await Assert.That(fixture.BorrowedPreserved).IsTrue();
        await Assert.That(fixture.Source.Opens).IsEqualTo(pinned ? 1 : 0);
        if (!pinned) return;
        await Assert.That(fixture.MetadataReads).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await Assert.That(fixture.ReadJournal.Count).IsEqualTo(fixture.Fields.Length * 2);
        await Assert.That(fixture.AuthenticationJournal.Select(a => a.Accepted).ToArray())
            .IsEquivalentTo(new[] { true, false, true, true, false });
        await Assert.That(fixture.Source.Measurements).IsEqualTo(1);
        await Assert.That(fixture.Source.Registrations).IsEqualTo(0);
        await Assert.That(fixture.Source.PrivateDestroyed).IsTrue();
        await Assert.That(fixture.Source.Buffers.All(b => b.All(v => v == 0))).IsTrue();
        await Assert.That(fixture.TerminalJournal.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("wrong-material", "effect-mismatch")]
    [Arguments("mixed-generation", "effect-mismatch")]
    [Arguments("wrong-accepted", "effect-mismatch")]
    [Arguments("valid-outage", "effect-mismatch")]
    [Arguments("overbroad-grants", "effect-mismatch")]
    [Arguments("read-mutation", "effect-mismatch")]
    [Arguments("configuration-mutation", "effect-mismatch")]
    [Arguments("mapping-mutation", "effect-mismatch")]
    [Arguments("denied-material-accepted", "effect-mismatch")]
    [Arguments("echo-source", "observer-unavailable")]
    [Arguments("late-work", "cleanup-incomplete")]
    [Arguments("pending-delivery", "cleanup-incomplete")]
    [Arguments("pending-work", "cleanup-incomplete")]
    [Arguments("borrowed-damage", "cleanup-incomplete")]
    [Arguments("incomplete-cleanup", "cleanup-incomplete")]
    [Arguments("lost-open", "observer-unavailable")]
    [Arguments("lost-arm", "observer-unavailable")]
    [Arguments("lost-authenticate", "observer-unavailable")]
    [Arguments("lost-complete", "observer-unavailable")]
    [Arguments("lost-close", "cleanup-incomplete")]
    public async Task IndependentJournalsRejectConcreteFaults(string mode, string code)
    {
        await using var fixture = new InfisicalRotationMaterialFixture(InfisicalRotationProfile.PostgresCredentials, mode);
        var result = await Run(fixture, Row("GetAsync", "profile.PostgresCredentials", "independent-effect"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(code);
        await Assert.That(fixture.Source.Opens).IsEqualTo(1);
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
        await Assert.That(fixture.Source.OriginalRoot == fixture.Source.ClosedRoot).IsTrue();
        await Assert.That(fixture.Source.Buffers.All(b => b.All(v => v == 0))).IsTrue();
        if (mode != "incomplete-cleanup") await Assert.That(fixture.Residual).IsEqualTo(0);
        else await Assert.That(fixture.Residual).IsGreaterThan(0);
    }

    [Test]
    [Arguments("open", "neverEnabled")]
    [Arguments("open", "exactMaterialKnown")]
    [Arguments("arm", "captureArmed")]
    [Arguments("authenticate", "coherentGeneration")]
    [Arguments("authenticate", "wrong")]
    [Arguments("complete", "originalSettled")]
    [Arguments("complete", "excludesLateWork")]
    [Arguments("complete", "noReplay")]
    [Arguments("close", "completeInventory")]
    public async Task ConcreteChannelRejectsOmittedRequiredEvidence(string stage, string field)
    {
        await using var fixture = new InfisicalRotationMaterialFixture(InfisicalRotationProfile.PostgresCredentials);
        fixture.Source.Change = (route, facts) => { if (route == stage) facts.Remove(field); };
        var result = await Run(fixture, Row("ListAsync", "collection.bounded", "selected-contract"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(stage == "close" ? "cleanup-incomplete" : "observer-unavailable");
        await Assert.That(fixture.Residual).IsEqualTo(0);
        await Assert.That(fixture.Source.Buffers.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    public async Task PrivatePacketCopiesAndFailedSerializationClearOwnedCapacity()
    {
        await using var fixture = new InfisicalRotationMaterialFixture(InfisicalRotationProfile.PostgresCredentials);
        var fields = fixture.Fields.Select(f => f with { Value = new string('x', 262144) }).ToArray();
        using var packet = new RotationMaterialPacket(fixture.Profile, fixture.Input().Kind, 7, fields);
        await Assert.That(JsonSerializer.Serialize(packet)).IsEqualTo("{}");
        await Assert.That(packet.ToString()).IsEqualTo("[RotationMaterialPacket]");
        var buffers = new List<byte[]>();
        int allocations = 0;
        using (var storage = new InfisicalLifecycleObservers.OwnedJsonBuffer(length =>
        {
            if (++allocations == 2) throw new InvalidOperationException("controlled-serialization-failure");
            byte[] bytes = new byte[length];
            buffers.Add(bytes);
            return bytes;
        }))
        {
            await Assert.That(() =>
            {
                using var writer = new Utf8JsonWriter(storage);
                writer.WriteStartObject();
                packet.Write(writer, "material");
                writer.WriteEndObject();
                writer.Flush();
            }).Throws<InvalidOperationException>();
        }
        await Assert.That(buffers.Count).IsGreaterThan(0);
        await Assert.That(buffers.All(b => b.All(v => v == 0))).IsTrue();
        packet.Dispose();
        await Assert.That(() =>
        {
            using var writer = new Utf8JsonWriter(Stream.Null);
            writer.WriteStartObject();
            packet.Write(writer, "material");
        }).Throws<ObjectDisposedException>();
        // Disposal of the copied packet cannot erase or mutate caller-owned input.
        await Assert.That(fields.All(f => f.Value.Length == 262144)).IsTrue();
    }

    [Test]
    public async Task UnknownReadCanSettleOneActualServerReadWithoutReplay()
    {
        await using var fixture = new InfisicalRotationMaterialFixture(InfisicalRotationProfile.PostgresCredentials);
        var input = fixture.Input();
        var row = Row("GetAsync", "selector.exact", "cancellation-boundary");
        using var environment = Environment(row, input);
        await using var trial = await RotationMaterialTrial.OpenAsync(fixture.Source.Client(), input, row,
            CancellationToken.None);
        await trial.ArmAsync(CancellationToken.None);
        using var boundary = new LifecycleTransport("lost-response-no-replay", fixture.MetadataTransport);
        using var http = new HttpClient(boundary);
        var authority = new SecretAuthority();
        var client = new InfisicalRotationClient(environment.Origin, authority,
            new(authority, environment.Tokens(NativeIdentityRole.Runtime), input.ProjectId),
            new() { Transport = InfisicalTransportOptions.HostControlled(http) });
        boundary.Arm();
        var result = await client.GetAsync(new(authority, new InfisicalRotationAddress(input.ProjectId,
            input.Environment, input.Folder, input.Profile, input.RotationId)));
        boundary.Disarm();
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(boundary.Reached.Task.IsCompletedSuccessfully).IsTrue();
        await Assert.That(fixture.MetadataReads).IsEqualTo(1);
        await using var consumer = fixture.Consumer(environment, NativeIdentityRole.Runtime);
        using var actual = await RotationMaterialPacket.ReadAsync(consumer, input, false, CancellationToken.None);
        await trial.AuthenticateAsync(actual, CancellationToken.None);
        await trial.CompleteAsync(result.Status, CancellationToken.None);
        await trial.DisposeAsync();
        await Assert.That(fixture.MetadataReads).IsEqualTo(1);
        await Assert.That(fixture.Residual).IsEqualTo(0);
    }

    [Test]
    [Arguments("profile")]
    [Arguments("kind")]
    [Arguments("mapping")]
    [Arguments("version")]
    [Arguments("material")]
    [Arguments("generation")]
    public async Task ProtectedOpenRejectsWrongSelectionBeforeRuntimeRead(string fault)
    {
        await using var fixture = new InfisicalRotationMaterialFixture(InfisicalRotationProfile.PostgresCredentials);
        var input = fixture.Input();
        var fields = input.Fields.ToArray();
        switch (fault)
        {
            case "profile": input = input with { Profile = InfisicalRotationProfile.LdapPassword }; break;
            case "kind": input = input with { Kind = RotationMaterialKind.Token }; break;
            case "mapping": fields[0] = fields[0] with { Destination = "wrong-destination" }; break;
            case "version": fields[0] = fields[0] with { Version = "99" }; break;
            case "material": fields[0] = fields[0] with { Value = "not-the-native-material" }; break;
            case "generation": input = input with { Generation = 99 }; break;
        }
        input = input with { Fields = fields };
        var result = await Run(fixture, Row("GetAsync", "selector.exact", "selected-contract"), input);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.MetadataReads).IsEqualTo(0);
        await Assert.That(fixture.Residual).IsEqualTo(0);
    }

    [Test]
    [Arguments("open", "root")]
    [Arguments("arm", "epoch")]
    [Arguments("authenticate", "version")]
    [Arguments("complete", "sequence")]
    [Arguments("complete", "event")]
    [Arguments("complete", "root")]
    public async Task HostRejectsTamperedInjectedEvidence(string stage, string fault)
    {
        await using var fixture = new InfisicalRotationMaterialFixture(InfisicalRotationProfile.LdapPassword);
        var source = new TamperedSource(fixture.Source.Client(), stage, fault);
        var result = await Run(fixture, Row("GetAsync", "profile.LdapPassword", "independent-effect"), injected: source);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
        await Assert.That(fixture.Residual).IsEqualTo(0);
    }

    private sealed class TamperedSource(IInfisicalRotationMaterialSource inner, string stage, string fault) : IInfisicalRotationMaterialSource
    {
        private RotationMaterialStamp Change(RotationMaterialStamp stamp) => fault switch
        {
            "root" => stamp with { Root = stamp.Root with { Id = "unrelated-root" } },
            "epoch" => stamp with { Root = stamp.Root with { ClockEpoch = "stale-epoch" } },
            "version" => stamp with { Root = stamp.Root with { ProviderVersion = "wrong-version" } },
            "sequence" => stamp with { Sequence = 0 },
            "event" => stamp with { EventId = "event-1" },
            _ => throw new InvalidOperationException("fixture-fault")
        };
        public async ValueTask<RotationMaterialBinding> OpenAsync(RotationMaterialRoot root, RotationMaterialPacket packet,
            SecretMaterial capability, CancellationToken token)
        {
            var result = await inner.OpenAsync(root, packet, capability, token);
            return stage == "open" ? result with { Stamp = Change(result.Stamp) } : result;
        }
        public async ValueTask<RotationMaterialArm> ArmAsync(RotationMaterialBinding binding, CancellationToken token)
        {
            var result = await inner.ArmAsync(binding, token);
            return stage == "arm" ? result with { Stamp = Change(result.Stamp) } : result;
        }
        public async ValueTask<RotationMaterialAuthentication> AuthenticateAsync(RotationMaterialArm arm,
            RotationMaterialPacket actual, RotationMaterialPacket wrong, CancellationToken token)
        {
            var result = await inner.AuthenticateAsync(arm, actual, wrong, token);
            return stage == "authenticate" ? result with { Stamp = Change(result.Stamp) } : result;
        }
        public async ValueTask<RotationMaterialWindow> CompleteAsync(RotationMaterialArm arm, SecretStatus status, CancellationToken token)
        {
            var result = await inner.CompleteAsync(arm, status, token);
            return stage == "complete" ? result with { Stamp = Change(result.Stamp) } : result;
        }
        public ValueTask<RotationMaterialCleanup> CloseAsync(RotationMaterialRoot root, CancellationToken token) =>
            inner.CloseAsync(root, token);
    }
}
