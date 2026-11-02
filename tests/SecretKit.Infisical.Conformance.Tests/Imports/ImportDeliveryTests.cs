using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class ImportDeliveryTests
{
    [Test]
    public async Task NativeImportsAndReferencesAreDeliveredOnlyThroughFreshSelectedRuntimeReads() =>
        await IdentitySetupTests.RunAsync(OwnedConformanceScenario.ImportDelivery);

    internal static async Task VerifyAsync(Uri origin, IInfisicalTokenSource adminTokens,
        IInfisicalTokenSource runtimeTokens, IInfisicalTokenSource deniedTokens, string project,
        CancellationToken cancellationToken, OwnedConformanceScenario scenario = OwnedConformanceScenario.ImportDelivery)
    {
        var network = new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true };
        await using var admin = new InfisicalClient(origin, adminTokens, network);
        await using var runtime = new InfisicalClient(origin, runtimeTokens, network);
        await using var denied = new InfisicalClient(origin, deniedTokens, network);
        var administrative = new InfisicalNativeAuthority(admin.Authority, adminTokens, project);
        var dev = await Environment("dev");
        var prod = await Environment("prod");
        var first = await Folder("dev", dev.Id, "sdk-source-first");
        var second = await Folder("dev", dev.Id, "sdk-source-second");
        var destination = await Folder("prod", prod.Id, "sdk-destination");
        using var firstValue = SecretMaterial.FromText("first-" + Guid.NewGuid().ToString("N"));
        using var secondValue = SecretMaterial.FromText("second-" + Guid.NewGuid().ToString("N"));
        using var localValue = SecretMaterial.FromText("local-" + Guid.NewGuid().ToString("N"));
        const string key = "SDK_IMPORTED_VALUE";
        await Write("dev", "/sdk-source-first", key, firstValue);
        await Write("dev", "/sdk-source-second", key, secondValue);

        var importTarget = new SecretReference(admin.Authority,
            new InfisicalImportAddress(project, "prod", "/sdk-destination", destination.Id));
        var destinationAuthority = new InfisicalNativeAuthority(admin.Authority, adminTokens, project, "prod", "/sdk-destination");
        var firstReceipt = new MutationReceipt(importTarget);
        var firstImport = await admin.CreateImportAsync(importTarget,
            new InfisicalImportSource("dev", "/sdk-source-first"), false, destinationAuthority, firstReceipt, cancellationToken);
        Require(firstImport.Status, "first-import-create");
        await Assert.That(firstReceipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        var rawTarget = new SecretReference(runtime.Authority,
            new InfisicalSecretAddress(project, "prod", "/sdk-destination", key));
        await Assert.That((await runtime.ReadAsync(rawTarget, cancellationToken)).Status).IsEqualTo(SecretStatus.Absent);
        await Delivered(firstValue);
        var secondReceipt = new MutationReceipt(importTarget);
        var secondImport = await admin.CreateImportAsync(importTarget,
            new InfisicalImportSource("dev", "/sdk-source-second"), false, destinationAuthority, secondReceipt, cancellationToken);
        Require(secondImport.Status, "second-import-create");
        await Assert.That(secondReceipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Delivered(secondValue);
        await Write("prod", "/sdk-destination", key, localValue);
        await Delivered(localValue);

        var importInspection = new SecretReference(runtime.Authority,
            new InfisicalImportAddress(project, "prod", "/sdk-destination", destination.Id));
        var imported = await runtime.ReadImportedSecretsAsync(importInspection, cancellationToken: cancellationToken);
        Require(imported.Status, "runtime-explicit-import-lookup");
        using (var values = imported.Value)
        {
            await Assert.That(values.IsComplete).IsTrue();
            await Assert.That(values.Items.Count(item => item.Key == key)).IsEqualTo(2);
            await Assert.That(values.Items.Where(item => item.Key == key)
                .All(item => item.Material.Reveal() == firstValue.Reveal() || item.Material.Reveal() == secondValue.Reveal()))
                .IsTrue();
        }
        var deniedRead = await denied.ReadAsync(new SecretReference(denied.Authority,
            new InfisicalSecretAddress(project, "prod", "/sdk-destination", key, includeImports: true)), cancellationToken);
        await Assert.That(deniedRead.Status).IsEqualTo(SecretStatus.Denied);

        const string referenceKey = "SDK_REFERENCE_VALUE";
        using var expression = SecretMaterial.FromText("${" + key + "}");
        await Write("prod", "/sdk-destination", referenceKey, expression);
        var literal = await runtime.ReadAsync(new SecretReference(runtime.Authority,
            new InfisicalSecretAddress(project, "prod", "/sdk-destination", referenceKey)), cancellationToken);
        Require(literal.Status, "raw-reference-read");
        using (var read = literal.Value)
            await Assert.That(read.Material.Reveal() == expression.Reveal()).IsTrue();
        var expanded = await runtime.ReadAsync(new SecretReference(runtime.Authority,
            new InfisicalSecretAddress(project, "prod", "/sdk-destination", referenceKey,
                resolution: InfisicalResolution.ExpandedReferences)), cancellationToken);
        Require(expanded.Status, "expanded-reference-read");
        using (var read = expanded.Value)
            await Assert.That(read.Material.Reveal() == localValue.Reveal()).IsTrue();
        if (scenario is OwnedConformanceScenario.ImportEffects or OwnedConformanceScenario.ImportPolicy)
        {
            var selectedImport = new SecretReference(admin.Authority,
                new InfisicalImportAddress(project, "prod", "/sdk-destination", destination.Id, firstImport.Value.Id));
            var intended = new SecretReference(runtime.Authority,
                new InfisicalSecretAddress(project, "prod", "/sdk-destination", key, includeImports: true));
            var observed = await admin.ObserveImportEffectsAsync(selectedImport, runtime, intended, cancellationToken);
            Require(observed.Status, "fresh-import-effect-observation");
            await Assert.That(observed.Value.VisibilityStatus).IsEqualTo(SecretStatus.Success);
            await Assert.That(observed.Value.ImportCreated).IsEqualTo(InfisicalEffectEvidence.Observed);
            await Assert.That(observed.Value.ReplicationRequested).IsFalse();
            await Assert.That(observed.Value.FreshIntendedReadSucceeded).IsTrue();
            await Assert.That(observed.Value.Destination).IsEqualTo(InfisicalDestinationEvidence.Unknown);
            var deniedObservation = await admin.ObserveImportEffectsAsync(selectedImport, denied,
                new SecretReference(denied.Authority, new InfisicalSecretAddress(project, "prod", "/sdk-destination", key)),
                cancellationToken);
            Require(deniedObservation.Status, "denied-import-effect-observation");
            await Assert.That(deniedObservation.Value.VisibilityStatus).IsEqualTo(SecretStatus.Success);
            await Assert.That(deniedObservation.Value.DeliveryStatus).IsEqualTo(SecretStatus.Denied);
            await Assert.That(deniedObservation.Value.FreshIntendedReadSucceeded).IsFalse();
            await Assert.That(deniedObservation.Value.Destination).IsEqualTo(InfisicalDestinationEvidence.Unknown);
            Console.WriteLine("OWNED_IMPORT_CREATION_AND_FRESH_DENIED_DELIVERY_OBSERVED");
            Console.WriteLine("OWNED_DESTINATION_POLICY_CONTRACT_UNESTABLISHED");
            if (scenario == OwnedConformanceScenario.ImportEffects) return;

            var replicatedFolder = await Folder("prod", prod.Id, "sdk-replicated");
            var replicatedTarget = new SecretReference(admin.Authority,
                new InfisicalImportAddress(project, "prod", "/sdk-replicated", replicatedFolder.Id));
            var replicatedAuthority = new InfisicalNativeAuthority(admin.Authority, adminTokens, project, "prod", "/sdk-replicated");
            var replicationReceipt = new MutationReceipt(replicatedTarget);
            var replicated = await admin.CreateImportAsync(replicatedTarget,
                new InfisicalImportSource("dev", "/sdk-source-first"), true, replicatedAuthority,
                replicationReceipt, cancellationToken);
            if (replicated.Status != SecretStatus.Success)
                throw new InvalidOperationException($"Owned replication request: {replicated.Status}; evidence: {replicationReceipt.Evidence}.");
            await Assert.That(replicationReceipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            var replicationObservation = await admin.ObserveImportEffectsAsync(new SecretReference(admin.Authority,
                new InfisicalImportAddress(project, "prod", "/sdk-replicated", replicatedFolder.Id, replicated.Value.Id)),
                runtime, new SecretReference(runtime.Authority,
                    new InfisicalSecretAddress(project, "prod", "/sdk-replicated", key)), cancellationToken);
            Require(replicationObservation.Status, "replication-observation");
            await Assert.That(replicationObservation.Value.VisibilityStatus).IsEqualTo(SecretStatus.Success);
            await Assert.That(replicationObservation.Value.ReplicationRequested).IsTrue();
            await Assert.That(replicationObservation.Value.Destination).IsEqualTo(InfisicalDestinationEvidence.Unknown);
            // One fresh observation, not a poll or a claim that background replication converged.
            await Assert.That(replicationObservation.Value.DeliveryStatus is SecretStatus.Success or SecretStatus.Absent).IsTrue();
            Console.WriteLine("OWNED_REPLICATION_FRESH_DELIVERY_" + replicationObservation.Value.DeliveryStatus);
            Console.WriteLine("OWNED_DESTINATION_POLICY_CONTRACT_UNESTABLISHED");
        }
        Console.WriteLine("OWNED_IMPORT_PRECEDENCE_AND_REFERENCE_DELIVERY_PASSED");

        async Task<InfisicalEnvironment> Environment(string slug)
        {
            var result = await admin.GetEnvironmentAsync(new SecretReference(admin.Authority,
                new InfisicalEnvironmentAddress(project, slug, InfisicalOrganizationSelector.Slug)), cancellationToken);
            Require(result.Status, "environment-inspection");
            return result.Value;
        }
        async Task<InfisicalFolder> Folder(string environment, string environmentId, string name)
        {
            var target = new SecretReference(admin.Authority,
                new InfisicalFolderAddress(project, environment, environmentId, "/", name: name));
            var receipt = new MutationReceipt(target);
            var result = await admin.CreateFolderAsync(target, administrative, receipt, cancellationToken: cancellationToken);
            Require(result.Status, "folder-create");
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            return result.Value;
        }
        async Task Write(string environment, string path, string name, SecretMaterial material)
        {
            var target = new SecretReference(admin.Authority, new InfisicalSecretAddress(project, environment, path, name));
            var receipt = new MutationReceipt(target);
            Require((await admin.CreateAsync(target, material, receipt, cancellationToken)).Status, "source-or-local-write");
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        }
        async Task Delivered(SecretMaterial expected)
        {
            var result = await runtime.ReadAsync(new SecretReference(runtime.Authority,
                new InfisicalSecretAddress(project, "prod", "/sdk-destination", key, includeImports: true)), cancellationToken);
            Require(result.Status, "fresh-imported-runtime-read");
            using var read = result.Value;
            await Assert.That(read.Material.Reveal() == expected.Reveal()).IsTrue();
        }
    }
    private static void Require(SecretStatus status, string step)
    {
        if (status != SecretStatus.Success)
            throw new InvalidOperationException($"Owned import conformance {step}: {status}.");
    }
}
