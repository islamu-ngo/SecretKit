using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalSettingsPermissionHistoryTests
{
    public static IEnumerable<string> Faults() =>
        from journal in Enum.GetValues<SettingsPermissionJournal>()
        from fault in new[] { "forge", "omit", "duplicate", "reorder", "substitute", "nonterminal" }
        select fault + "-" + journal;
    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task CoordinatorCannotRewriteAnyIndependentlyOwnedCompleteHistory(string fault)
    {
        await using var provider = new InfisicalSettingsPermissionFixture();
        string operation = SettingsPermissionContract.Operations[0]; var source = provider.Source.CreateClient();
        var root = provider.Root(operation, SettingsPermissionAction.Edit, "independent-effect");
        using var cap = SecretMaterial.FromText("settings-capability"); using var verifier = new SettingsPermissionVerifier(root);
        verifier.Check(await source.StepAsync(root, SettingsPermissionStep.Reserve, cap, CancellationToken.None), SettingsPermissionStep.Reserve);
        var packet = await source.StepAsync(root, SettingsPermissionStep.Open, null, CancellationToken.None);
        try
        {
            // Ingress/access are empty at Open. Their enrollment record
            // is still signed; omission of it must fail just as an intermediate row.
            if (fault.StartsWith("omit-", StringComparison.Ordinal))
            {
                var kind = Enum.Parse<SettingsPermissionJournal>(fault["omit-".Length..]);
                var j = packet.Journals.Single(j => j.Content.Journal == kind);
                if (j.Content.Events.Length == 1)
                    packet = packet with { Journals = packet.Journals.Select(p => p == j ? p with { Content = p.Content with { Events = [] } } : p).ToArray() };
            }
            if (fault.StartsWith("reorder-", StringComparison.Ordinal))
            {
                var kind = Enum.Parse<SettingsPermissionJournal>(fault["reorder-".Length..]);
                var j = packet.Journals.Single(j => j.Content.Journal == kind);
                if (j.Content.Events.Length == 1)
                    packet = packet with { Journals = packet.Journals.Select(p => p == j ? p with { Content = p.Content with { Events = [p.Content.Events[0] with { Sequence = 2 }] } } : p).ToArray() };
            }
            var tampered = provider.Source.Tamper(packet, fault);
            await InfisicalSettingsPermissionSourceTests.Rejected(() => { verifier.Check(tampered, SettingsPermissionStep.Open); return Task.CompletedTask; });
        }
        finally
        {
            verifier.Check(await source.StepAsync(root, SettingsPermissionStep.Close, null, CancellationToken.None), SettingsPermissionStep.Close);
            foreach (var actor in packet.Actors) actor.Erase();
        }
        await InfisicalSettingsPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CompleteHistoriesSurviveWindowChangesAndOwnedResourceRetirement()
    {
        await using var provider = new InfisicalSettingsPermissionFixture();
        var result = await InfisicalSettingsPermissionEffectTests.RunAsync(provider, SettingsPermissionContract.Operations[0], "permission.Settings.edit", "independent-effect");
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        var packet = provider.ClosedPacket!;
        await Assert.That(packet.Values<SettingsPermissionRequest>(SettingsPermissionJournal.Ingress, "request").Length).IsEqualTo(19);
        await Assert.That(packet.Values<SettingsPermissionDecision>(SettingsPermissionJournal.Access, "decision").Length).IsEqualTo(19);
        await Assert.That(packet.Values<SettingsPermissionChange>(SettingsPermissionJournal.Storage, "change").Count(c => c.DecisionHash.Length > 0)).IsEqualTo(10);
        await Assert.That(packet.Values<SettingsPermissionRetirement>(SettingsPermissionJournal.Storage, "retire").Length).IsEqualTo(provider.Generated);
        await Assert.That(packet.Journals.All(j => j.Content.Fenced && j.Content.Terminal && j.Content.Pending == 0)).IsTrue();
        await InfisicalSettingsPermissionEffectTests.Clean(provider);
    }
}
