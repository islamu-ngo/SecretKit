using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalPeriodicRenewalTests
{
    public static IEnumerable<(string Method, string Variant, string Boundary)> OriginalCases() =>
        InfisicalLifecycleFamilies.Catalog.Where(a => a.Operation.StartsWith(PeriodicRenewalEffects.Prefix, StringComparison.Ordinal))
            .SelectMany(a => a.Variants.SelectMany(v => a.Cases.Select(c =>
                (a.Operation[PeriodicRenewalEffects.Prefix.Length..], v, c))));

    internal static NativeCaseDefinition Row(string method, string variant, string boundary)
    {
        var admission = InfisicalLifecycleFamilies.Catalog.Single(a => a.Operation == PeriodicRenewalEffects.Prefix + method);
        return new(new("Infisical", admission.Operation, variant, "controlled-periodic", boundary), admission.Member);
    }

    internal static NativeEnvironment Environment(InfisicalPeriodicRenewalFixture fixture, NativeCaseDefinition row,
        Action<JsonObject>? change = null)
    {
        var node = JsonSerializer.SerializeToNode(fixture.SessionInput(), InfisicalPeriodicRenewalFixture.Json)!.AsObject();
        node[PeriodicRenewalEffects.Selection] = JsonSerializer.SerializeToNode(
            fixture.Input(row.Key.Case == "denied-authority"), InfisicalPeriodicRenewalFixture.Json);
        change?.Invoke(node);
        var families = new JsonObject
        {
            [InfisicalPeriodicTokenSessionEffects.Family] = new JsonObject
            {
                ["scopes"] = new JsonObject
                {
                    [row.Key.Scope] = new JsonObject
                    {
                        [row.Key.Operation] = new JsonObject
                        { [row.Key.Variant] = new JsonObject { [row.Key.Case] = node } }
                    }
                }
            }
        };
        return NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = fixture.Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families
        }, InfisicalPeriodicRenewalFixture.Json));
    }

    internal static async Task<NativeCaseResult> Run(InfisicalPeriodicRenewalFixture fixture,
        NativeCaseDefinition row, Action<JsonObject>? change = null)
    {
        using var env = Environment(fixture, row, change);
        var registry = new NativeCaseRegistry();
        PeriodicRenewalEffects.Register(registry, env, [row], fixture.Clock, fixture.Source.Client());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        return (await NativeCaseRunner.RunAsync(registry, [row], deadline.Token)).Single();
    }

    [Test]
    public async Task OriginalDenominatorRetainsThirteenVariantsAndFiveBoundaryKinds()
    {
        var cases = OriginalCases().ToArray();
        await Assert.That(cases.Length).IsEqualTo(58);
        await Assert.That(cases.Select(c => (c.Method, c.Variant)).Distinct().Count()).IsEqualTo(13);
        await Assert.That(cases.Select(c => c.Boundary).Distinct().Count()).IsEqualTo(5);
    }

    [Test]
    [MethodDataSource(nameof(OriginalCases))]
    public async Task SelectedEffectsUseOriginalJournalAndPreserveBorrowedState(string method, string variant, string boundary)
    {
        await using var fixture = new InfisicalPeriodicRenewalFixture(variant);
        var result = await Run(fixture, Row(method, variant, boundary));
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Source.Opens).IsEqualTo(1);
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
        await Assert.That(fixture.BorrowedPreserved && fixture.Fenced && fixture.OriginalTerminal).IsTrue();
        await Assert.That(fixture.Source.Registrations + fixture.PendingWork + fixture.CapturedResources).IsEqualTo(0);
        await Assert.That(fixture.Source.CopiesDestroyed && fixture.Source.Buffers.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    [Arguments("good", "NonApplied")]
    [Arguments("cancel-applied", "Applied")]
    [Arguments("partial", "Partial")]
    public async Task CancellationCanSettleWithoutRewritingStoppedReceipt(string mode, string outcome)
    {
        await using var fixture = new InfisicalPeriodicRenewalFixture(mode: mode);
        var result = await Run(fixture, Row("RenewAsync", "lifetime.Finite", "cancellation-boundary"));
        await Assert.That(result.Passed).IsEqualTo(mode != "partial");
        await Assert.That(fixture.Source.Settlement!.Outcome.ToString()).IsEqualTo(outcome);
        await Assert.That(fixture.Source.Settlement.Receipt.Evidence).IsEqualTo(InfisicalRenewalEvidence.PossiblyDispatched);
        await Assert.That(fixture.Source.Deliveries).IsEqualTo(0);
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
    }

    [Test]
    public async Task SameCredentialRenewalCleansCopiesWithoutRevokingBorrowedRow()
    {
        await using var fixture = new InfisicalPeriodicRenewalFixture(mode: "same-credential");
        var result = await Run(fixture, Row("RenewAsync", "lifetime.Finite", "independent-effect"));
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Source.Settlement!.CapturedTokenRow).IsEqualTo("runtime-row");
        await Assert.That(fixture.CapturedResources).IsEqualTo(0);
        await Assert.That(fixture.BorrowedPreserved && fixture.Current.ExpiresAt > fixture.Baseline.ExpiresAt).IsTrue();
    }

    [Test]
    [Arguments("lost-open")]
    [Arguments("lost-arm")]
    [Arguments("lost-settle")]
    [Arguments("echo-source")]
    [Arguments("replacement-denied")]
    public async Task MissingOrFalseEvidenceNeverPassesAndClosesOriginalRoot(string mode)
    {
        await using var fixture = new InfisicalPeriodicRenewalFixture(mode: mode);
        var result = await Run(fixture, Row("RenewAsync", "lifetime.Finite", "independent-effect"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
        await Assert.That(fixture.Source.ClosedRoot is not null && fixture.Source.CopiesDestroyed).IsTrue();
        await Assert.That(fixture.BorrowedPreserved && fixture.OriginalTerminal && fixture.Fenced).IsTrue();
        await Assert.That(fixture.CapturedResources).IsEqualTo(0);
        await Assert.That(fixture.Source.Buffers.All(b => b.All(v => v == 0))).IsTrue();
    }

    public static IEnumerable<(string Route, string Field)> TamperedFacts() => new[]
    {
        ("open", "credentialHandle"), ("open", "exactCredentialRowJoin"), ("open", "independentJournal"),
        ("open", "borrowedIdentityAndGrants"), ("arm", "exclusiveOriginalWindow"), ("arm", "captureArmed"),
        ("arm", "pendingWork"), ("arm", "window"), ("settle", "originalRequests"),
        ("settle", "originalCommits"), ("settle", "foreignRequests"), ("settle", "pendingWork"),
        ("settle", "pendingDeliveries"), ("settle", "originalTerminal"), ("settle", "excludesLateWork"),
        ("settle", "completeInventory"), ("settle", "noReplay"), ("settle", "borrowedIdentityAndGrants"),
        ("settle", "requestId"), ("settle", "credentialHandle"), ("settle", "capturedTokenRow"),
        ("delivery", "exactSuppliedCredential"), ("delivery", "window"), ("delivery", "tokenRow"),
        ("delivery", "credentialHandle"), ("close", "originalTerminal"), ("close", "excludesLateWork"),
        ("close", "completeInventory"), ("close", "borrowedIdentityAndGrants"),
        ("close", "qualifiedLifetimePreserved"), ("close", "ownedCapturedResourcesAbsent"),
        ("close", "privateCopiesDestroyed"), ("close", "registrations"), ("close", "pendingWork"),
        ("close", "pendingDeliveries")
    };

    [Test]
    [MethodDataSource(nameof(TamperedFacts))]
    public async Task IndependentFactCorruptionFailsClosed(string route, string field)
    {
        await using var fixture = new InfisicalPeriodicRenewalFixture();
        fixture.Source.Change = (stage, node) =>
        {
            if (stage != route) return;
            var value = node[field]!;
            if (value.GetValueKind() == JsonValueKind.True) node[field] = false;
            else if (value.GetValueKind() == JsonValueKind.Number) node[field] = 2;
            else node[field] = "";
        };
        var result = await Run(fixture, Row("RenewAsync", "lifetime.Finite", "independent-effect"));
        await Assert.That(result.Passed).IsFalse().Because(route + "/" + field);
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
    }

    public static IEnumerable<(string Route, string Field)> StampTampering() =>
        new[] { "open", "arm", "settle", "delivery" }.SelectMany(route => new[]
        {
            "nonce", "caseIdentity", "operation", "variant", "case", "providerVersion", "deployment",
            "sourceIdentity", "epoch", "identityId", "tokenRow", "registration", "event", "sequence", "clockAuthority"
        }.Select(field => (route, field)));

    [Test]
    [MethodDataSource(nameof(StampTampering))]
    public async Task RootClockAndEventSubstitutionFailsClosed(string route, string field)
    {
        await using var fixture = new InfisicalPeriodicRenewalFixture();
        fixture.Source.Change = (stage, node) =>
        {
            if (stage != route) return;
            var stamp = node["stamp"]!.AsObject();
            if (field == "sequence") stamp[field] = -1;
            else if (field is "registration" or "event" or "clockAuthority") stamp[field] = "";
            else stamp["root"]![field] = "substituted";
        };
        var result = await Run(fixture, Row("RenewAsync", "lifetime.Finite", "independent-effect"));
        await Assert.That(result.Passed).IsFalse().Because(route + "/" + field);
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
    }

    public static IEnumerable<(string Field, string Boundary)> LifetimeCases() =>
        new[] { "originalIssuedAt", "expiresAt", "lifetime", "reportedMaximumTtl", "period", "absoluteLifetimeLimit" }
            .SelectMany(field => new[] { "independent-effect", "denied-authority", "lost-response-no-replay" }
                .Select(boundary => (field, boundary)));

    [Test]
    [MethodDataSource(nameof(LifetimeCases))]
    public async Task AllSixLifetimeFieldsRequireIndependentSourceAgreement(string field, string boundary)
    {
        await using var fixture = new InfisicalPeriodicRenewalFixture();
        fixture.Source.Change = (stage, node) =>
        {
            if (stage != "settle") return;
            var lifetime = node["originalLifetime"]!.AsObject();
            lifetime[field] = field switch
            {
                "lifetime" => JsonValue.Create("Periodic"),
                "period" or "reportedMaximumTtl" => JsonValue.Create("00:00:01"),
                _ => JsonValue.Create(InfisicalPeriodicRenewalFixture.Epoch.AddSeconds(1))
            };
        };
        var result = await Run(fixture, Row("RenewAsync", "lifetime.Finite", boundary));
        await Assert.That(result.Passed).IsFalse().Because(field);
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
    }

    [Test]
    public async Task SnapshotCannotSupplyTheOptionalSourceAndSelectionDoesNotRemoveLegacy()
    {
        await using var fixture = new InfisicalPeriodicRenewalFixture();
        var row = Row("RenewAsync", "lifetime.Finite", "independent-effect");
        using var env = Environment(fixture, row);
        await Assert.That(PeriodicRenewalEffects.Selected(env, row)).IsTrue();
        using var legacy = Environment(fixture, row, node => node.Remove(PeriodicRenewalEffects.Selection));
        await Assert.That(PeriodicRenewalEffects.Selected(legacy, row)).IsFalse();
        var registry = new NativeCaseRegistry();
        registry.Add(new(row, (probe, token) => InfisicalLifecycleFamilies.BoundedAsync(probe, token,
            bounded => PeriodicRenewalEffects.ExecuteAsync(env, row, probe, fixture.Clock, null, bounded))));
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Source.Opens).IsEqualTo(0);
    }

    [Test]
    [Arguments("window")]
    [Arguments("credentialHandle")]
    [Arguments("requestId")]
    [Arguments("boundary")]
    [Arguments("responseHeld")]
    [Arguments("event")]
    public async Task InterruptedAttemptCannotConsumeAnotherRequestEvent(string field)
    {
        await using var fixture = new InfisicalPeriodicRenewalFixture();
        fixture.Source.Change = (stage, node) =>
        {
            if (field == "requestId")
            {
                if (stage == "settle") node[field] = "another-original-request";
            }
            else if (stage == "boundary")
            {
                if (field == "responseHeld") node[field] = false;
                else if (field == "boundary") node[field] = "None";
                else if (field == "event") node["stamp"]!["event"] = "event-2";
                else node[field] = "other-window-or-credential";
            }
        };
        var result = await Run(fixture, Row("RenewAsync", "lifetime.Finite", "lost-response-no-replay"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
        await Assert.That(fixture.OriginalTerminal && fixture.BorrowedPreserved).IsTrue();
    }
}
