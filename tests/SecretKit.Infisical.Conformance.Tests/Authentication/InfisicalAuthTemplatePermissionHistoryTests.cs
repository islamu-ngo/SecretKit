using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalAuthTemplatePermissionHistoryTests
{
    public static IEnumerable<string> Faults() =>
        from journal in Enum.GetValues<AuthTemplatePermissionJournal>()
        from fault in new[] { "forge", "omit", "duplicate", "reorder", "substitute", "nonterminal" }
        select fault + "-" + journal;
    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task CoordinatorCannotRewriteAnyIndependentlyOwnedCompleteHistory(string fault)
    {
        await using var provider = new InfisicalAuthTemplatePermissionFixture();
        string operation = AuthTemplatePermissionContract.Operations[0]; var source = provider.Source.CreateClient();
        var root = provider.Root(operation, AuthTemplatePermissionAction.Edit, "independent-effect");
        using var cap = SecretMaterial.FromText("auth-template-capability"); using var verifier = new AuthTemplatePermissionVerifier(root);
        verifier.Check(await source.StepAsync(root, AuthTemplatePermissionStep.Reserve, cap, CancellationToken.None), AuthTemplatePermissionStep.Reserve);
        var packet = await source.StepAsync(root, AuthTemplatePermissionStep.Open, null, CancellationToken.None);
        try
        {
            // Ingress/access are empty at Open. Their enrollment record
            // is still signed; omission of it must fail just as an intermediate row.
            if (fault.StartsWith("omit-", StringComparison.Ordinal))
            {
                var kind = Enum.Parse<AuthTemplatePermissionJournal>(fault["omit-".Length..]);
                var j = packet.Journals.Single(j => j.Content.Journal == kind);
                if (j.Content.Events.Length == 1)
                    packet = packet with { Journals = packet.Journals.Select(p => p == j ? p with { Content = p.Content with { Events = [] } } : p).ToArray() };
            }
            if (fault.StartsWith("reorder-", StringComparison.Ordinal))
            {
                var kind = Enum.Parse<AuthTemplatePermissionJournal>(fault["reorder-".Length..]);
                var j = packet.Journals.Single(j => j.Content.Journal == kind);
                if (j.Content.Events.Length == 1)
                    packet = packet with { Journals = packet.Journals.Select(p => p == j ? p with { Content = p.Content with { Events = [p.Content.Events[0] with { Sequence = 2 }] } } : p).ToArray() };
            }
            var tampered = provider.Source.Tamper(packet, fault);
            await InfisicalAuthTemplatePermissionSourceTests.Rejected(() => { verifier.Check(tampered, AuthTemplatePermissionStep.Open); return Task.CompletedTask; });
        }
        finally
        {
            verifier.Check(await source.StepAsync(root, AuthTemplatePermissionStep.Close, null, CancellationToken.None), AuthTemplatePermissionStep.Close);
            foreach (var actor in packet.Actors) actor.Erase();
        }
        await InfisicalAuthTemplatePermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CompleteHistoriesSurviveWindowChangesAndOwnedResourceRetirement()
    {
        await using var provider = new InfisicalAuthTemplatePermissionFixture();
        var result = await InfisicalAuthTemplatePermissionEffectTests.RunAsync(provider, AuthTemplatePermissionContract.Operations[0], AuthTemplatePermissionAction.Edit, "independent-effect");
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        var packet = provider.ClosedPacket!;
        await Assert.That(packet.Values<AuthTemplatePermissionRequest>(AuthTemplatePermissionJournal.Ingress, "request").Length).IsEqualTo(16);
        await Assert.That(packet.Values<AuthTemplatePermissionDecision>(AuthTemplatePermissionJournal.Access, "decision").Length).IsEqualTo(16);
        await Assert.That(packet.Values<AuthTemplatePermissionChange>(AuthTemplatePermissionJournal.Storage, "change").Count(c => c.DecisionHash.Length > 0)).IsEqualTo(10);
        await Assert.That(packet.Values<AuthTemplatePermissionRetirement>(AuthTemplatePermissionJournal.Storage, "retire").Length).IsEqualTo(provider.Generated);
        await Assert.That(packet.Journals.All(j => j.Content.Fenced && j.Content.Terminal && j.Content.Pending == 0)).IsTrue();
        await InfisicalAuthTemplatePermissionEffectTests.Clean(provider);
    }
}
