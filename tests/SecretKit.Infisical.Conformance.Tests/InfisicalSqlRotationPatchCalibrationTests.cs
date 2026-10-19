using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalSqlRotationPatchCalibrationTests
{
    [Test]
    [Arguments("Postgres")]
    [Arguments("MySql")]
    [Arguments("MsSql")]
    public async Task PublicManagementSeamCalibratesSeparatePersistenceMaterialBackendAndJobJournals(string profile)
    {
        await using var store = new InfisicalSqlRotationPatchFixture();
        using var environment = store.Environment();
        var definition = InfisicalSqlRotationPatchFixture.Definition(profile, "patch.empty");
        var c = new ProjectFamilyContext(environment, profile + "SecretRotations", definition, new());
        await c.EnsureProjectAsync(CancellationToken.None, runtimeMember: true);
        string name = ProjectFamilyContext.FreshName();
        await using var fixture = await store.CreateAsync(environment, definition, c.ProjectId, c.Input,
            name, CancellationToken.None);
        var lease = (InfisicalSqlRotationPatchFixture.Lease)fixture;
        var binding = lease.SqlRotationPatch!.Binding;
        await lease.Source.OpenAsync(binding, CancellationToken.None);
        try
        {
            switch (profile)
            {
                case "Postgres":
                    using (var p = new PostgresRotationParameters(fixture.Username1, fixture.Username2,
                        new(24, 2, 2, 2, 2, "!@"), fixture.RotationStatement))
                    using (var changed = new PostgresRotationParameters(fixture.Username1, fixture.Username2,
                        new(24, 2, 2, 2, 2)))
                        await CalibrateAsync(c, lease,
                            () => PostgresSecretRotationOperations.Create(c.OrganizationId, new(fixture.Name,
                                c.ProjectId, fixture.Environment, fixture.SourcePath, fixture.ConnectionId, 2,
                                p, new(fixture.UsernameKey, fixture.PasswordKey), new(2, 3), new(fixture.Name), false)),
                            id => PostgresSecretRotationOperations.Update(c.OrganizationId, Address(id),
                                new(parameters: changed)), s => s.Id);
                    break;
                case "MySql":
                    using (var p = new MySqlRotationParameters(fixture.Username1, fixture.Username2,
                        new(24, 2, 2, 2, 2, "!@"), fixture.RotationStatement))
                    using (var changed = new MySqlRotationParameters(fixture.Username1, fixture.Username2,
                        new(24, 2, 2, 2, 2)))
                        await CalibrateAsync(c, lease,
                            () => MySqlSecretRotationOperations.Create(c.OrganizationId, new(fixture.Name,
                                c.ProjectId, fixture.Environment, fixture.SourcePath, fixture.ConnectionId, 2,
                                p, new(fixture.UsernameKey, fixture.PasswordKey), new(2, 3), new(fixture.Name), false)),
                            id => MySqlSecretRotationOperations.Update(c.OrganizationId, Address(id),
                                new(parameters: changed)), s => s.Id);
                    break;
                default:
                    using (var p = new MsSqlRotationParameters(fixture.Username1, fixture.Username2,
                        new(24, 2, 2, 2, 2, "!@"), fixture.RotationStatement))
                    using (var changed = new MsSqlRotationParameters(fixture.Username1, fixture.Username2,
                        new(24, 2, 2, 2, 2)))
                        await CalibrateAsync(c, lease,
                            () => MsSqlSecretRotationOperations.Create(c.OrganizationId, new(fixture.Name,
                                c.ProjectId, fixture.Environment, fixture.SourcePath, fixture.ConnectionId, 2,
                                p, new(fixture.UsernameKey, fixture.PasswordKey), new(2, 3), new(fixture.Name), false)),
                            id => MsSqlSecretRotationOperations.Update(c.OrganizationId, Address(id),
                                new(parameters: changed)), s => s.Id);
                    break;
            }
        }
        finally
        {
            await lease.SqlRotationPatch.RecoverAsync(CancellationToken.None);
            await lease.CleanupAsync(CancellationToken.None);
            await lease.SqlRotationPatch.CloseAsync(CancellationToken.None);
            await c.CleanupAsync();
        }
        await Assert.That(store.Residual).IsEqualTo(0);
        await Assert.That(store.Projects.Count).IsEqualTo(0);
        await Assert.That(store.BorrowedIntact).IsTrue();

        InfisicalRotationAddress Address(string id) =>
            new(c.ProjectId, fixture.Environment, fixture.SourcePath, fixture.BackendCoordinate.Profile, id);
    }

    private static async Task CalibrateAsync<T>(ProjectFamilyContext c, InfisicalSqlRotationPatchFixture.Lease lease,
        Func<ManagementRequest<T>> creation, Func<string, ManagementRequest<T>> patch, Func<T, string> id) where T : notnull
    {
        T created = await c.NeedAsync(creation, NativeIdentityRole.Setup, CancellationToken.None);
        string rotation;
        try { rotation = id(created); }
        finally { if (created is IDisposable owned) owned.Dispose(); }
        var binding = lease.SqlRotationPatch!.Binding;
        using (var before = await lease.Source.ReadAsync(binding, rotation, CancellationToken.None))
        {
            await Assert.That(before.Statement!.Reveal()).IsEqualTo("owned-original-statement");
            await Assert.That(before.Configuration.PasswordRequirements!.AllowedSymbols).IsEqualTo("!@");
            await Assert.That(before.Attempts).IsEqualTo(0);
        }
        using var controls = await lease.Source.ControlsAsync(binding, rotation, CancellationToken.None);
        await Assert.That(controls.Rows.Length).IsEqualTo(12);
        await Assert.That(controls.Rows.All(r => r.Status == 400 && r.State.Attempts == 0)).IsTrue();
        T changed = await c.NeedAsync(() => patch(rotation), NativeIdentityRole.Administrative, CancellationToken.None);
        if (changed is IDisposable changedOwned) changedOwned.Dispose();
        using var committed = await lease.Source.CompleteAsync(binding, rotation, DispatchEvidence.Applied, CancellationToken.None);
        await Assert.That(committed.Statement).IsNull();
        await Assert.That(committed.Configuration.PasswordRequirements!.AllowedSymbols).IsNull();
        await Assert.That(committed.Configuration.Username1).IsEqualTo(lease.Username1);
        await Assert.That(committed.Configuration.Username2).IsEqualTo(lease.Username2);
        await Assert.That(committed.Attempts).IsEqualTo(1);
        await Assert.That(committed.TerminalAttempts).IsEqualTo(1);
        await Assert.That(committed.Scheduled).IsEqualTo(1);
        using var username = SecretMaterial.FromText(lease.Username1);
        using var password = SecretMaterial.FromText(lease.Password);
        using var wrong = SecretMaterial.FromText("wrong-password");
        var accepted = await lease.Backend.AuthenticateAsync(username, password, CancellationToken.None);
        var rejected = await lease.Backend.AuthenticateAsync(username, wrong, CancellationToken.None);
        await Assert.That(accepted.Selected).IsEqualTo(DatabaseAuthentication.Accepted);
        await Assert.That(rejected.Selected).IsEqualTo(DatabaseAuthentication.Rejected);
        await InfisicalDatabaseFamilies.MappingAsync(c, lease, lease.Environment, lease.SourcePath,
            username, password, true, CancellationToken.None);
        await Assert.That(JsonSerializer.Serialize(committed)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(binding)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(controls)).IsEqualTo("{}");
    }
}
