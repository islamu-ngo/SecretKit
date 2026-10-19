using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using Service = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationFixtureObserverService;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task StatusPrivateUpdateIndependentAuditRejectedCleanupCallerDoesNotLeakBorrowers()
    {
        var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        try
        {
            await f.PrepareAndBaseline();
            var (endpoint, _, parent) = RetainedPrivateUpdateIndependentEndpoint(f.Source, f.Native.Selector.Nonce);
            using var caller = new CancellationTokenSource();
            caller.Cancel();
            try { await endpoint.CleanupAsync(parent, default, caller.Token); }
            catch (InvalidOperationException) { }
            await Assert.That(parent.Busy).IsEqualTo(0);
            await Assert.That(f.PrivateEndpoint!.Requests.Any(r => r.Method == "DELETE")).IsFalse();
            await endpoint.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        }
        finally { await f.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10)); }
    }

    [Test]
    public async Task StatusPrivateUpdateIndependentAuditBindingContinuationRetainsItsOriginalCallerVeto()
    {
        await using var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        await f.PrepareAndBaseline();
        var (endpoint, plan, parent) = RetainedPrivateUpdateIndependentEndpoint(f.Source, f.Native.Selector.Nonce);
        using var caller = new CancellationTokenSource();
        int requests = f.PrivateEndpoint!.Requests.Count;
        var result = await endpoint.CompleteBindingAsync(plan, default, caller.Token);
        await Assert.That(result.State).IsEqualTo(PrivateEndpointFixtureProvisioner.State.Ready);
        await Assert.That(f.PrivateEndpoint.Requests.Count).IsEqualTo(requests);
        await Assert.That(endpoint.OwnsBoundPlan(plan, parent, f.PrivateEndpoint.ConnectionId)).IsTrue();
        caller.Cancel();
        await Assert.That(endpoint.OwnsBoundPlan(plan, parent, f.PrivateEndpoint.ConnectionId)).IsFalse();
    }

    [Test]
    public async Task StatusPrivateUpdateIndependentAuditMissingSelectorCorruptionCannotReviveAfterRestore()
    {
        var f = new PurgeServiceFixture("independent-effect", ManagementMutation.UpdatePrivateConnection,
            statusPrivateUpdateIndependent: true);
        try
        {
            var lease = await f.PrepareAndBaseline();
            await f.Start(lease);
            byte[] original = await File.ReadAllBytesAsync(f.Native.JournalPath);
            int last = 0;
            for (int position = 0; position < original.Length;)
            {
                last = position;
                position += BinaryPrimitives.ReadInt32LittleEndian(original.AsSpan(position, 4)) + 36;
            }
            int length = BinaryPrimitives.ReadInt32LittleEndian(original.AsSpan(last, 4));
            var frame = JsonNode.Parse(original.AsSpan(last + 4, length))!;
            frame["state"]!.AsObject().Remove("selector");
            byte[] payload = JsonSerializer.SerializeToUtf8Bytes(frame, ManagementAdmission.Json);
            byte[] corrupt = new byte[last + payload.Length + 36];
            original.AsSpan(0, last).CopyTo(corrupt);
            BinaryPrimitives.WriteInt32LittleEndian(corrupt.AsSpan(last, 4), payload.Length);
            payload.CopyTo(corrupt, last + 4);
            SHA256.HashData(payload).CopyTo(corrupt, last + 4 + payload.Length);
            Exception? observed = null;
            try
            {
                await File.WriteAllBytesAsync(f.Native.JournalPath, corrupt);
                try { f.Native.Read(); }
                catch (Exception exception) { observed = exception; }
            }
            finally { await File.WriteAllBytesAsync(f.Native.JournalPath, original); }
            bool revived = false;
            try
            {
                f.Source.RetryStatusPrivateConnectionUpdateIndependentPersistence(f.Native.Selector);
                revived = true;
            }
            catch (RoleFixtureJournal.StatusPrivateConnectionUpdateIndependentHistoryException) { }
            catch (InvalidOperationException) { }
            await Assert.That(revived).IsFalse();
            await Assert.That(observed is RoleFixtureJournal.StatusPrivateConnectionUpdateIndependentHistoryException).IsTrue();
            await Assert.That(f.SelectedUpdates).IsEqualTo(1);
        }
        finally
        {
            try { await f.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (RoleFixtureJournal.StatusPrivateConnectionUpdateIndependentHistoryException) { }
        }
    }

    private static (PrivateEndpointFixtureProvisioner Source, PrivateEndpointFixtureProvisioner.Plan Plan,
        VaultFixtureProvisioner.Plan Parent) RetainedPrivateUpdateIndependentEndpoint(Service source, Guid nonce)
    {
        var flags = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic |
            System.Reflection.BindingFlags.Public;
        var sessions = (System.Collections.IDictionary)typeof(Service).GetField("sessions", flags)!.GetValue(source)!;
        var session = sessions[nonce]!;
        return ((PrivateEndpointFixtureProvisioner)session.GetType().GetField("Endpoints", flags)!.GetValue(session)!,
            (PrivateEndpointFixtureProvisioner.Plan)session.GetType().GetField("EndpointPlan", flags)!.GetValue(session)!,
            (VaultFixtureProvisioner.Plan)session.GetType().GetField("Plan", flags)!.GetValue(session)!);
    }
}
