using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalIntegrationPermissionHistoryTests
{
    public static IEnumerable<string> Faults() =>
        from journal in Enum.GetValues<IntegrationPermissionJournal>()
        from fault in new[] { "forge", "omit", "duplicate", "reorder", "substitute", "nonterminal" }
        select fault + "-" + journal;
    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task CoordinatorCannotRewriteAnyIndependentlyOwnedCompleteHistory(string fault)
    {
        await using var provider = new InfisicalIntegrationPermissionFixture();
        string operation = IntegrationPermissionContract.Operations[0]; var source = provider.Source.CreateClient();
        var root = provider.Root(operation, IntegrationPermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("integration-capability"); using var verifier = new IntegrationPermissionVerifier(root);
        verifier.Check(await source.StepAsync(root, IntegrationPermissionStep.Reserve, cap, CancellationToken.None), IntegrationPermissionStep.Reserve);
        var packet = await source.StepAsync(root, IntegrationPermissionStep.Open, null, CancellationToken.None);
        try
        {
            // Ingress/access/collection are empty at Open. Their enrollment record
            // is still signed; omission of it must fail just as an intermediate row.
            if (fault.StartsWith("omit-", StringComparison.Ordinal))
            {
                var kind = Enum.Parse<IntegrationPermissionJournal>(fault["omit-".Length..]);
                var j = packet.Journals.Single(j => j.Content.Journal == kind);
                if (j.Content.Events.Length == 1)
                    packet = packet with { Journals = packet.Journals.Select(p => p == j ? p with { Content = p.Content with { Events = [] } } : p).ToArray() };
            }
            if (fault.StartsWith("reorder-", StringComparison.Ordinal))
            {
                var kind = Enum.Parse<IntegrationPermissionJournal>(fault["reorder-".Length..]);
                var j = packet.Journals.Single(j => j.Content.Journal == kind);
                if (j.Content.Events.Length == 1)
                    packet = packet with { Journals = packet.Journals.Select(p => p == j ? p with { Content = p.Content with { Events = [p.Content.Events[0] with { Sequence = 2 }] } } : p).ToArray() };
            }
            var tampered = provider.Source.Tamper(packet, fault);
            await InfisicalIntegrationPermissionSourceTests.Rejected(() => { verifier.Check(tampered, IntegrationPermissionStep.Open); return Task.CompletedTask; });
        }
        finally
        {
            verifier.Check(await source.StepAsync(root, IntegrationPermissionStep.Close, null, CancellationToken.None), IntegrationPermissionStep.Close);
            foreach (var actor in packet.Actors) actor.Erase();
        }
        await InfisicalIntegrationPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CompleteHistoriesSurviveWindowChangesAndOwnedResourceRetirement()
    {
        await using var provider = new InfisicalIntegrationPermissionFixture();
        var result = await InfisicalIntegrationPermissionEffectTests.RunAsync(provider, IntegrationPermissionContract.Operations[0], "permission.Integrations.read", "independent-effect");
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        var packet = provider.ClosedPacket!;
        await Assert.That(packet.Values<IntegrationPermissionRequest>(IntegrationPermissionJournal.Ingress, "request").Length).IsEqualTo(11);
        await Assert.That(packet.Values<IntegrationPermissionDecision>(IntegrationPermissionJournal.Access, "decision").Length).IsEqualTo(11);
        await Assert.That(packet.Values<IntegrationPermissionCollection>(IntegrationPermissionJournal.Collection, "read").Length).IsEqualTo(10);
        await Assert.That(packet.Values<IntegrationPermissionRetirement>(IntegrationPermissionJournal.Storage, "retire").Length).IsEqualTo(provider.Generated);
        await Assert.That(packet.Journals.All(j => j.Content.Fenced && j.Content.Terminal && j.Content.Pending == 0)).IsTrue();
        await InfisicalIntegrationPermissionEffectTests.Clean(provider);
    }
}
