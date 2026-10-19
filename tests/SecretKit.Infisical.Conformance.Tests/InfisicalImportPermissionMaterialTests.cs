using System.Security.Cryptography;
using System.Text;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// These controlled setup/observer secret-read prerequisites are explicitly
// UNQUALIFIED native contracts. Runtime import CRUD never grants secret reads.
public sealed class InfisicalImportPermissionMaterialTests
{
    [Test]
    [Arguments("", false)]
    [Arguments("", true)]
    [Arguments("wrong-material", false)]
    public async Task ProtectedMaterialMatchesIndependentNonceSourcesAndClearsBeforeInterruptedWork(string fault, bool interrupt)
    {
        await using var fixture = new InfisicalImportPermissionFixture(fault);
        using var env = fixture.Environment();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var capability = SecretMaterial.FromText("import-capability");
        var root = fixture.Root(ImportPermissionContract.Operations[0], ImportPermissionAction.Read, "independent-effect");
        ImportPermissionTrial? retained = null;
        InfisicalImportedSecrets? owned = null;
        char[]? exported = null; byte[]? bytes = null;
        bool matched = false, interrupted = false;
        try
        {
            var trial = await ImportPermissionTrial.OpenAsync(fixture.Source.CreateClient(), root, capability,
                t => retained = t, deadline.Token);
            var row = trial.Issued.Rows.First(r => r.Principal == root.Authorities.Setup && r.Window == "before" && r.List);
            await using var setup = new InfisicalClient(fixture.Origin, env.Tokens(SecretKit.TestFixtures.NativeIdentityRole.Setup),
                new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
            var target = new SecretReference(setup.Authority, new InfisicalImportAddress(row.Project,
                row.Environment, row.Path, row.FolderId.ToString()));
            var result = await setup.ReadImportedSecretsAsync(target, cancellationToken: deadline.Token);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            owned = result.Value;
            matched = owned.IsComplete && owned.Items.Count > 0 && owned.Items.Select(i => i.Path).Distinct().Count() == owned.Items.Count;
            matched &= owned.Groups.Count == owned.Items.Count && owned.Groups.All(g =>
                trial.Issued.Rows.Any(r => r.SourceFolderId.ToString() == g.FolderId &&
                    ImportPermissionContract.SourcePath(r, false) == g.Path && g.Environment == "source-a") &&
                g.Items.Count == 1);
            foreach (var item in owned.Items)
            {
                var sourceRow = trial.Issued.Rows.Single(r => ImportPermissionContract.SourcePath(r, false) == item.Path);
                exported = item.Material.ExportCharacters(); bytes = Encoding.UTF8.GetBytes(exported);
                try
                {
                    byte[] independentExpected = Encoding.UTF8.GetBytes(root.Nonce + ":" + sourceRow.Id + ":source-a");
                    try
                    {
                        matched &= bytes.AsSpan().SequenceEqual(independentExpected) && item.ProjectId == sourceRow.Project &&
                            item.Environment == "source-a" && item.Key == "IMPORTED" && item.Version == "1";
                    }
                    finally { CryptographicOperations.ZeroMemory(independentExpected); }
                }
                finally { Array.Clear(exported); CryptographicOperations.ZeroMemory(bytes); }
            }
            await Assert.That(matched).IsEqualTo(fault.Length == 0);
            if (interrupt) throw new OperationCanceledException(deadline.Token);
        }
        catch (OperationCanceledException) when (interrupt) { interrupted = true; }
        finally
        {
            // Every exported copy and returned material is retired before cleanup,
            // whether assertions, comparison or interrupted continuation fail.
            if (exported is not null) Array.Clear(exported);
            if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
            owned?.Dispose();
            if (retained is not null) await retained.DisposeAsync();
        }
        await Assert.That(interrupted).IsEqualTo(interrupt);
        await Assert.That(exported!.All(c => c == '\0') && bytes!.All(b => b == 0)).IsTrue();
        foreach (var item in owned!.Items)
        {
            bool disposed = false;
            try { _ = item.Material.ExportCharacters(); } catch (ObjectDisposedException) { disposed = true; }
            await Assert.That(disposed).IsTrue();
        }
        await InfisicalImportPermissionEffectTests.Clean(fixture);
    }
    [Test]
    public async Task SetupDeliveryRequiresExplicitImportsAndEffectObservationKeepsDestinationUnknown()
    {
        await using var fixture = new InfisicalImportPermissionFixture();
        using var env = fixture.Environment();
        using var cap = SecretMaterial.FromText("import-capability");
        ImportPermissionTrial? retained = null;
        try
        {
            var root = fixture.Root(ImportPermissionContract.Operations[0], ImportPermissionAction.Read, "independent-effect");
            var trial = await ImportPermissionTrial.OpenAsync(fixture.Source.CreateClient(), root, cap,
                t => retained = t, CancellationToken.None);
            await trial.BeginAsync(false, CancellationToken.None);
            var row = trial.Issued.Rows.First(r => r.Window == "before" && r.Principal == root.Authorities.Setup &&
                r.Action == ImportPermissionAction.Read && !r.List);
            await using var client = new InfisicalClient(fixture.Origin, env.Tokens(SecretKit.TestFixtures.NativeIdentityRole.Setup),
                new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
            var direct = new SecretReference(client.Authority, new InfisicalSecretAddress(row.Project, row.Environment, row.Path, "IMPORTED"));
            await Assert.That((await client.ReadAsync(direct)).Status).IsEqualTo(SecretStatus.Absent);
            var imported = new SecretReference(client.Authority,
                new InfisicalSecretAddress(row.Project, row.Environment, row.Path, "IMPORTED", includeImports: true));
            var expectedRow = trial.Issued.Rows.First(r => r.Project == row.Project && r.Environment == row.Environment &&
                r.Path == row.Path && r.Action != ImportPermissionAction.Create);
            var delivered = await client.ReadAsync(imported);
            await Assert.That(delivered.IsSuccess).IsTrue();
            using (var read = delivered.Value)
            {
                char[] chars = read.Material.ExportCharacters();
                byte[] bytes = Encoding.UTF8.GetBytes(chars);
                byte[] expected = Encoding.UTF8.GetBytes(root.Nonce + ":" + expectedRow.Id + ":source-a");
                try { await Assert.That(bytes.AsSpan().SequenceEqual(expected)).IsTrue(); }
                finally { Array.Clear(chars); CryptographicOperations.ZeroMemory(bytes); CryptographicOperations.ZeroMemory(expected); }
            }
            var observation = await client.ObserveImportEffectsAsync(new(client.Authority,
                new InfisicalImportAddress(row.Project, row.Environment, row.Path, row.FolderId.ToString(), row.Id.ToString())),
                client, imported);
            await Assert.That(observation.IsSuccess && observation.Value.FreshIntendedReadSucceeded).IsTrue();
            await Assert.That(observation.Value.VisibilityStatus).IsEqualTo(SecretStatus.Success);
            await Assert.That(observation.Value.Destination).IsEqualTo(InfisicalDestinationEvidence.Unknown);
            var changedRow = trial.Issued.Rows.First(r => r.Window == "before" && r.Principal == root.Authorities.Setup &&
                r.Action == ImportPermissionAction.Edit);
            var changeTarget = new SecretReference(client.Authority, new InfisicalImportAddress(changedRow.Project,
                changedRow.Environment, changedRow.Path, changedRow.FolderId.ToString(), changedRow.Id.ToString()));
            var receipt = new MutationReceipt(changeTarget);
            var change = await client.UpdateImportAsync(changeTarget, new(client.Authority,
                env.Tokens(SecretKit.TestFixtures.NativeIdentityRole.Setup), changedRow.Project, changedRow.Environment, changedRow.Path),
                receipt, "source-b", ImportPermissionContract.SourcePath(changedRow, true), 7.5);
            await Assert.That(change.IsSuccess && change.Value.Position == 7.5).IsTrue();
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            var nextDelivery = await client.ReadAsync(imported);
            await Assert.That(nextDelivery.IsSuccess).IsTrue();
            using (var read = nextDelivery.Value)
            {
                char[] chars = read.Material.ExportCharacters(); byte[] bytes = Encoding.UTF8.GetBytes(chars);
                byte[] expected = Encoding.UTF8.GetBytes(root.Nonce + ":" + changedRow.Id + ":source-b");
                try { await Assert.That(bytes.AsSpan().SequenceEqual(expected)).IsTrue(); }
                finally { Array.Clear(chars); CryptographicOperations.ZeroMemory(bytes); CryptographicOperations.ZeroMemory(expected); }
            }
            var bounded = await client.ReadImportedSecretsAsync(new(client.Authority,
                new InfisicalImportAddress(row.Project, row.Environment, row.Path, row.FolderId.ToString())), maximumItems: 1);
            await Assert.That(bounded.IsSuccess).IsTrue();
            using (var material = bounded.Value) await Assert.That(material.IsComplete).IsFalse();
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await InfisicalImportPermissionEffectTests.Clean(fixture);
    }
    [Test]
    [Arguments((int)SecretKit.TestFixtures.NativeIdentityRole.Runtime)]
    [Arguments((int)SecretKit.TestFixtures.NativeIdentityRole.Administrative)]
    [Arguments((int)SecretKit.TestFixtures.NativeIdentityRole.Denied)]
    public async Task ImportPermissionDoesNotSecretlyGrantProtectedSecretRead(int role)
    {
        await using var fixture = new InfisicalImportPermissionFixture();
        using var env = fixture.Environment();
        using var cap = SecretMaterial.FromText("import-capability");
        ImportPermissionTrial? retained = null;
        try
        {
            var root = fixture.Root(ImportPermissionContract.Operations[0], ImportPermissionAction.Read, "independent-effect");
            var trial = await ImportPermissionTrial.OpenAsync(fixture.Source.CreateClient(), root, cap, t => retained = t, CancellationToken.None);
            var row = trial.Issued.Rows[0];
            await using var client = new InfisicalClient(fixture.Origin, env.Tokens((SecretKit.TestFixtures.NativeIdentityRole)role), new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
            var result = await client.ReadImportedSecretsAsync(new(client.Authority,
                new InfisicalImportAddress(row.Project, row.Environment, row.Path, row.FolderId.ToString())));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await InfisicalImportPermissionEffectTests.Clean(fixture);
    }
}
