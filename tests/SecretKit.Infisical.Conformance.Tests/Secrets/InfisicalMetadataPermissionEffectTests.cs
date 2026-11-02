using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalMetadataPermissionEffectTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary, int Operator)> Cases() =>
        from c in InfisicalMetadataPermissionGateTests.Cases()
        from op in Enum.GetValues<MetadataPermissionOperator>()
        select (c.Operation, c.Variant, c.Boundary, (int)op);
    public static IEnumerable<(string Operation, string Variant, string Boundary)> NativeCases() =>
        InfisicalMetadataPermissionGateTests.Cases();
    public static IEnumerable<(string Operation, string Variant, string Fault)> Faults()
    {
        foreach (var pair in NativeCases().Select(c => (c.Operation, c.Variant)).Distinct())
            foreach (string fault in new[] { "ignored-permissions", "split-entry", "unauthorized-broad-action",
                "wrong-principal", "coordinator-forged-attestation", "cleanup", "lost-open", "partial-open",
                "content-tamper", "strip-commit", "borrowed-change" })
                yield return (pair.Operation, pair.Variant, fault);
        foreach (var pair in NativeCases().Where(c => c.Operation.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal))
            .Select(c => (c.Operation, c.Variant)).Distinct())
            yield return (pair.Operation, pair.Variant, "template-echo");
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task MetadataEffectsUseOriginalSdkAndIndependentSqlPermission(string operation, string variant,
        string boundary, int @operator)
    {
        await using var fixture = new InfisicalMetadataPermissionFixture();
        var result = await RunAsync(fixture, operation, variant, boundary, (MetadataPermissionOperator)@operator);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await Assert.That(fixture.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await CheckClean(fixture);
    }
    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task IndependentFaultsFailTheActualMetadataFlow(string operation, string variant, string fault)
    {
        await using var fixture = new InfisicalMetadataPermissionFixture(fault);
        var result = await RunAsync(fixture, operation, variant, "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await Assert.That(fixture.Closes).IsEqualTo(1);
        await Assert.That(fixture.Registrations).IsEqualTo(0);
        if (fault == "cleanup")
        {
            await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
            await Assert.That(fixture.Remaining > 0).IsTrue();
        }
        else if (fault == "borrowed-change")
        {
            await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
            await Assert.That(fixture.BorrowedPreserved).IsFalse();
            await Assert.That(fixture.Remaining).IsEqualTo(0);
        }
        else await CheckClean(fixture);
        // Every copied field remains valid in this attack. Authentication,
        // rather than a field mismatch, must reject the coordinator's signature.
        if (fault == "coordinator-forged-attestation")
        {
            await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
            await Assert.That(fixture.Originals).IsEqualTo(0);
        }
    }
    [Test]
    [Arguments("lost-nonapplied", 1)]
    [Arguments("partial", 2)]
    public async Task LostOriginalClassifiesActualCommitsWithoutRewritingReceipt(string fault, int expected)
    {
        await using var fixture = new InfisicalMetadataPermissionFixture(fault);
        using var env = fixture.Environment();
        var c = NativeCases().First(c => c.Operation.EndsWith("UpdateProjectRole", StringComparison.Ordinal));
        var root = fixture.Root(c.Operation, c.Variant, "lost-response-no-replay");
        MetadataPermissionTrial? retained = null;
        using var capability = SecretKit.Core.SecretMaterial.FromText("metadata-capability");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            var trial = await MetadataPermissionTrial.OpenAsync(fixture.Source.CreateClient(), root, capability,
                t => retained = t, timeout.Token);
            await MetadataPermissionEffects.WitnessAsync(env, root, trial, false, timeout.Token);
            await trial.ArmAsync(timeout.Token);
            var receipt = await MetadataPermissionEffects.DispatchAsync(env, root, trial.Issued, timeout.Token);
            await trial.SettleAsync(receipt, timeout.Token);
            await Assert.That((int)trial.Outcome).IsEqualTo(expected);
            await Assert.That(trial.Original).IsEqualTo(receipt);
            await Assert.That(receipt.Evidence).IsEqualTo(SecretKit.Core.DispatchEvidence.PossiblyDispatched);
            await Assert.That(receipt.Cancelled).IsTrue();
            if (fault == "lost-nonapplied")
                await MetadataPermissionEffects.WitnessAsync(env, root, trial, true, timeout.Token);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await CheckClean(fixture);
    }
    [Test]
    [MethodDataSource(nameof(NativeCases))]
    public async Task CertificatesRemainExplicitSdkActionGateAcrossEveryMetadataLabel(string operation,
        string variant, string boundary)
    {
        await using var fixture = new InfisicalMetadataPermissionFixture();
        using var env = fixture.Environment(subject: MetadataPermissionSubject.Certificates);
        var d = InfisicalMetadataPermissionGateTests.Definition(operation, variant, boundary);
        await Assert.That(MetadataPermissionContract.Gate(d, fixture.Input(subject: MetadataPermissionSubject.Certificates)))
            .IsEqualTo("certificate-sdk-protected-action-unavailable");
        foreach (var op in Enum.GetValues<MetadataPermissionOperator>())
        {
            bool rejected = false;
            try
            {
                if (MetadataPermissionContract.Template(operation))
                    _ = new ProjectTemplatePermission(ProjectRoleSubject.Certificates, ProjectRoleAction.Read,
                        metadata: MetadataPermissionEffects.TemplateMatch(op));
                else
                    _ = new ProjectRolePermission(ProjectRoleSubject.Certificates, ProjectRoleAction.Read,
                        metadata: MetadataPermissionEffects.Match(op));
            }
            catch (ArgumentException) { rejected = true; }
            await Assert.That(rejected).IsEqualTo(op == MetadataPermissionOperator.NotEqual);
        }
        var result = await RunAsync(fixture, operation, variant, boundary, subject: MetadataPermissionSubject.Certificates);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Opens).IsEqualTo(0);
        await Assert.That(fixture.Originals).IsEqualTo(0);
    }
    [Test]
    public async Task TypedMetadataCannotBeSubstitutedOntoStaticSecrets()
    {
        bool roleRejected = false, templateRejected = false;
        try
        {
            _ = new ProjectRolePermission(ProjectRoleSubject.Secrets, ProjectRoleAction.Read,
            metadata: new(RoleStringClause.Compare(equal: "team"), RoleStringClause.Compare(equal: "blue")));
        }
        catch (ArgumentException) { roleRejected = true; }
        try
        {
            _ = new ProjectTemplatePermission(ProjectRoleSubject.Secrets, ProjectRoleAction.Read,
            metadata: new(ProjectTemplateStringClause.Compare(equal: "team"), ProjectTemplateStringClause.Compare(equal: "blue")));
        }
        catch (ArgumentException) { templateRejected = true; }
        await Assert.That(roleRejected && templateRejected).IsTrue();
        await Assert.That(Cases().Count()).IsEqualTo(280);
        await Assert.That(Faults().Count()).IsEqualTo(92);
    }
    internal static async Task<NativeCaseResult> RunAsync(InfisicalMetadataPermissionFixture fixture,
        string operation, string variant, string boundary, MetadataPermissionOperator op = MetadataPermissionOperator.Equal,
        MetadataPermissionSubject subject = MetadataPermissionSubject.DynamicSecrets)
    {
        using var env = fixture.Environment(op, subject);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var d = InfisicalMetadataPermissionGateTests.Definition(operation, variant, boundary);
        var registry = new NativeCaseRegistry();
        registry.Add(new(d, async (probe, token) =>
        {
            probe.Contract(MetadataPermissionContract.Owns(d), NativeFailure.ContractMismatch);
            string family = MetadataPermissionContract.Template(operation) ? "ProjectTemplates" :
                operation.Contains(".RoleChangeOperations.", StringComparison.Ordinal) ? "RoleChanges" : "IdentityPrivilegeChanges";
            var context = new ProjectFamilyContext(env, family, d, probe);
            try { await MetadataPermissionEffects.ExecuteAsync(context, fixture.Source.CreateClient(), token); }
            finally { await context.CleanupAsync(); }
        }));
        return (await NativeCaseRunner.RunAsync(registry, [d], timeout.Token)).Single();
    }
    internal static async Task CheckClean(InfisicalMetadataPermissionFixture fixture)
    {
        await fixture.DrainAsync();
        await Assert.That(fixture.Closes).IsEqualTo(1);
        await Assert.That(fixture.Remaining).IsEqualTo(0);
        await Assert.That(fixture.Registrations).IsEqualTo(0);
        await Assert.That(fixture.BorrowedPreserved).IsTrue();
        await Assert.That(fixture.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }
}
