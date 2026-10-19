using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalBulkAuxiliaryEffectTests
{
    public static IEnumerable<(string Method, string Variant, string Boundary)> Cases() =>
        InfisicalBulkAuxiliaryCalibrationTests.Cases();

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task ClosedUnitRetainsAllOriginalVariantAndCaseAxes(string method, string variant, string boundary)
    {
        await using var provider = new InfisicalBulkAuxiliaryFixture();
        var result = await Run(provider, method, variant, boundary);
        bool gated = BulkAuxiliaryContract.Gated(variant);
        await Assert.That(result.Passed == !gated).IsTrue().Because(result.ReasonCode);
        await Assert.That(result.ReasonCode).IsEqualTo(gated ? "observer-unavailable" : "observed");
        await Assert.That(provider.Source.Opens).IsEqualTo(gated ? 0 : 1);
        await Assert.That(provider.Source.Observations).IsEqualTo(gated ? 0 : 1);
        await Assert.That(provider.ResidualCount).IsEqualTo(0);
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
        await Assert.That(provider.StorageReads.Count).IsEqualTo(gated ? 0 : 2);
    }

    [Test]
    public async Task ExplicitPrivateInputProfileUsesSourceWithoutParentRegistrationHook()
    {
        await using var provider = new InfisicalBulkAuxiliaryFixture();
        var input = InfisicalBulkAuxiliaryCalibrationTests.Input("CreateSecretsAsync", "metadata.encrypted", "independent-effect");
        var definition = InfisicalBulkAuxiliaryCalibrationTests.Definition("CreateSecretsAsync", "metadata.encrypted", "independent-effect");
        try
        {
            using var env = provider.Environment(InfisicalBulkAuxiliaryCalibrationTests.Family(definition, input));
            var registry = new NativeCaseRegistry();
            registry.Add(new(definition, async (probe, token) =>
            {
                bool handled = await BulkAuxiliaryEffects.TryExecuteAsync(env, definition, probe, token,
                    provider.Source.CreateObserver());
                probe.Contract(handled, NativeFailure.ContractMismatch);
            }));
            var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
            await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
            await Assert.That(provider.Source.Opens == 1 && provider.Source.Observations == 1 &&
                provider.Source.Registrations == 0 && provider.ResidualCount == 0).IsTrue();
        }
        finally { InfisicalBulkAuxiliaryCalibrationTests.Erase(input); }
    }

    [Test]
    [Arguments("ignored")]
    [Arguments("partial")]
    [Arguments("ignored-comment")]
    [Arguments("plaintext-storage")]
    [Arguments("wrong-material")]
    [Arguments("denied-accepted")]
    [Arguments("extra-row")]
    [Arguments("incomplete-inventory")]
    [Arguments("wrong-plaintext")]
    [Arguments("wrong-shape")]
    [Arguments("metadata-echo")]
    [Arguments("unqualified")]
    [Arguments("borrowed-damage")]
    [Arguments("cleanup")]
    [Arguments("lost-open")]
    [Arguments("collision")]
    [Arguments("replay")]
    [Arguments("late")]
    public async Task IndependentStoragePermissionAndTerminalFaultsCannotPass(string fault)
    {
        await using var provider = new InfisicalBulkAuxiliaryFixture(fault);
        var result = await Run(provider, "UpdateSecretsAsync", "comment.value",
            fault == "denied-accepted" ? "denied-authority" : "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode is "effect-mismatch" or "contract-mismatch" or
            "observer-unavailable" or "cleanup-incomplete").IsTrue().Because(result.ReasonCode);
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        await Assert.That(provider.ResidualCount).IsEqualTo(fault is "cleanup" or "replay" or "late" ? 1 : 0);
        if (fault == "lost-open")
            await Assert.That(provider.Requests.Count).IsEqualTo(0);
        if (fault == "collision")
        {
            await Assert.That(provider.Requests.Count).IsEqualTo(0);
            await Assert.That(provider.Commits.Count).IsEqualTo(0);
        }
    }

    [Test]
    public async Task ExplicitReminderClearMustChangeStorageRatherThanEchoNull()
    {
        await using var provider = new InfisicalBulkAuxiliaryFixture("retained-reminder");
        var result = await Run(provider, "UpdateSecretsAsync", "reminderNote.null", "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
        await Assert.That(provider.ResidualCount).IsEqualTo(0);
    }

    [Test]
    public async Task PrivateProtocolOwnedRequestBuffersAreClearedAfterUse()
    {
        await using var provider = new InfisicalBulkAuxiliaryFixture();
        var buffers = new List<byte[]>();
        var source = provider.Source.CreateObserver(size =>
        {
            var bytes = new byte[size]; buffers.Add(bytes); return bytes;
        });
        var result = await Run(provider, "CreateSecretsAsync", "metadata.encrypted", "independent-effect", source);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(buffers.Count > 0 && buffers.All(b => b.All(value => value == 0))).IsTrue();
        // This assertion covers owned byte buffers, not managed SDK/parser strings.
    }

    [Test]
    public async Task LostSourceCompletionCannotReplayOrResumeObservation()
    {
        await using var provider = new InfisicalBulkAuxiliaryFixture("lost-complete");
        using var env = provider.Environment(new { });
        var input = InfisicalBulkAuxiliaryCalibrationTests.Input("CreateSecretsAsync", "metadata.encrypted", "independent-effect");
        var root = InfisicalBulkAuxiliaryCalibrationTests.Root(env,
            InfisicalBulkAuxiliaryCalibrationTests.Definition("CreateSecretsAsync", "metadata.encrypted", "independent-effect"),
            input, provider.Source.Kind);
        var source = provider.Source.CreateObserver();
        try
        {
            var opened = await source.OpenAsync(root, input.Baseline, CancellationToken.None);
            foreach (var row in opened.Baseline) row.Erase();
            await Assert.That(async () => await source.CompleteAsync(root,
                DispatchEvidence.NotDispatched, CancellationToken.None)).Throws<NativeCaseFailureException>();
            await Assert.That(async () => await source.CompleteAsync(root,
                DispatchEvidence.NotDispatched, CancellationToken.None)).Throws<NativeCaseFailureException>();
            await Assert.That(async () => await source.ObserveAsync(root,
                CancellationToken.None)).Throws<NativeCaseFailureException>();
            await Assert.That(provider.Source.Fences.Count == 1 && provider.Source.Observations == 0 &&
                provider.Requests.Count == 0).IsTrue();
        }
        finally
        {
            var cleanup = await source.CloseAsync(root, CancellationToken.None);
            await Assert.That(cleanup.RootAbsent && cleanup.OriginalSettled && cleanup.LateWorkExcluded).IsTrue();
            InfisicalBulkAuxiliaryCalibrationTests.Erase(input);
        }
    }

    [Test]
    [Arguments("root")]
    [Arguments("identity")]
    [Arguments("revision")]
    [Arguments("clock")]
    [Arguments("nonce")]
    [Arguments("registration")]
    [Arguments("request-count")]
    [Arguments("unsettled")]
    [Arguments("event")]
    [Arguments("cleanup")]
    public async Task HostRejectsUnboundDirectInjectedSourceEvidence(string fault)
    {
        await using var provider = new InfisicalBulkAuxiliaryFixture();
        var result = await Run(provider, "CreateSecretsAsync", "metadata.encrypted", "independent-effect",
            new Tampered(provider.Source, fault));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode is "observer-unavailable" or "cleanup-incomplete").IsTrue();
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        await Assert.That(provider.ResidualCount).IsEqualTo(0);
    }

    [Test]
    public async Task CallerSuppliedExpectedRowsCannotReplaceTypedMutationIntent()
    {
        await using var provider = new InfisicalBulkAuxiliaryFixture();
        var input = InfisicalBulkAuxiliaryCalibrationTests.Input("CreateSecretsAsync", "comment.value", "independent-effect");
        var original = input.Expected.Single(r => r.Key == "ALPHA");
        input = input with
        {
            Expected = input.Expected.Select(r => r.Key == "ALPHA" ?
                r with { Comment = "foreign"u8.ToArray() } : r).ToArray()
        };
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(original.Comment);
        try
        {
            using var env = provider.Environment(new { });
            var definition = InfisicalBulkAuxiliaryCalibrationTests.Definition("CreateSecretsAsync", "comment.value", "independent-effect");
            var result = await Execute(provider, env, definition, input, provider.Source);
            await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
            await Assert.That(provider.Source.Opens).IsEqualTo(0);
        }
        finally { InfisicalBulkAuxiliaryCalibrationTests.Erase(input); }
    }

    internal static async Task<NativeCaseResult> Run(InfisicalBulkAuxiliaryFixture provider,
        string method, string variant, string boundary, IBulkAuxiliarySource? source = null)
    {
        var input = InfisicalBulkAuxiliaryCalibrationTests.Input(method, variant, boundary);
        try
        {
            using var env = provider.Environment(new { });
            var definition = InfisicalBulkAuxiliaryCalibrationTests.Definition(method, variant, boundary);
            provider.Source.LoseResponse = boundary == "lost-response-no-replay";
            return await Execute(provider, env, definition, input, source ?? provider.Source.CreateObserver());
        }
        finally { InfisicalBulkAuxiliaryCalibrationTests.Erase(input); }
    }
    private static async Task<NativeCaseResult> Execute(InfisicalBulkAuxiliaryFixture provider,
        NativeEnvironment env, NativeCaseDefinition definition, BulkAuxiliaryInput input, IBulkAuxiliarySource source)
    {
        var registry = new NativeCaseRegistry();
        registry.Add(new(definition, (probe, token) => InfisicalStaticFamilies.BoundedAsync(probe, token,
            bounded => BulkAuxiliaryEffects.ExecuteAsync(env, definition, probe, input, source, bounded))));
        return (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
    }
    private sealed class Tampered(IBulkAuxiliarySource source, string fault) : IBulkAuxiliarySource
    {
        public BulkAuxiliarySourceKind Kind => source.Kind;
        public string Identity => source.Identity;
        public async ValueTask<BulkAuxiliaryBinding> OpenAsync(BulkAuxiliaryRoot root, BulkAuxiliaryRow[] baseline, CancellationToken token)
        {
            var b = await source.OpenAsync(root, baseline, token);
            return fault switch
            {
                "root" => b with { Root = root with { CaseIdentity = "foreign" } },
                "identity" => b with { SourceIdentity = "foreign" },
                "revision" => b with { Root = root with { ProviderRevision = "foreign" } },
                "clock" => b with { ClockAuthority = "host-clock" },
                "nonce" => b with { Root = root with { Nonce = "foreign" } },
                _ => b
            };
        }
        public async ValueTask<BulkAuxiliaryFence> CompleteAsync(BulkAuxiliaryRoot root, DispatchEvidence receipt, CancellationToken token)
        {
            var f = await source.CompleteAsync(root, receipt, token);
            return fault switch
            {
                "registration" => f with { Registration = "foreign" },
                "request-count" => f with { OriginalRequests = 2 },
                "unsettled" => f with { Settled = false },
                _ => f
            };
        }
        public async ValueTask<BulkAuxiliarySnapshot> ObserveAsync(BulkAuxiliaryRoot root, CancellationToken token)
        {
            var s = await source.ObserveAsync(root, token);
            return fault == "event" ? s with { FenceEvent = "foreign" } : s;
        }
        public async ValueTask<BulkAuxiliaryCleanup> CloseAsync(BulkAuxiliaryRoot root, CancellationToken token)
        {
            var c = await source.CloseAsync(root, token);
            return fault == "cleanup" ? c with { PendingDeliveries = 1 } : c;
        }
    }
}
