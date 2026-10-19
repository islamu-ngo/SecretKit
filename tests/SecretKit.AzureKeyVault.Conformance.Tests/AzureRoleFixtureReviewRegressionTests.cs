using System.Net;
using System.Text.Json;
using Azure.Core;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureRoleFixtureProvisionerTests
{
    [Test]
    public async Task ExplicitServiceReleaseSettlesRetainedPurgeWithoutMutationReplay()
    {
        await using var fixture = new ServiceFixture();
        var lease = await fixture.Prepare();
        fixture.Native.State.AsyncPurge = true;
        using var first = await fixture.Send("role/release", fixture.Native.Selector);
        var pending = await fixture.Read<RoleFixtureRelease.Measurement>(first);
        await Assert.That(pending.ActiveDispatches).IsGreaterThan(0);
        fixture.Native.State.PurgeState = "Succeeded";
        using var second = await fixture.Send("role/release", fixture.Native.Selector);
        RoleFixtureRelease.Validate(await fixture.Read<RoleFixtureRelease.Measurement>(second),
            fixture.Native.Selector, lease.Facts);
        await Assert.That(fixture.Native.Backends[0].Requests.Count(r => r.Method == HttpMethod.Post)).IsEqualTo(1);
        await Assert.That(fixture.Native.Backends[0].Requests.Any(r =>
            r.Method == HttpMethod.Get && r.Path.Contains("/operationResults/", StringComparison.Ordinal))).IsTrue();
        await Assert.That(fixture.Native.State.VaultExists || fixture.Native.State.DeletedVaultExists).IsFalse();
    }

    [Test]
    public async Task RetainedCompletionCanFinalizeAfterJournalContentionWithoutReplay()
    {
        using var fixture = new Fixture(allowPurge: true);
        var plan = fixture.Plan();
        fixture.State.Applied = new(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.State.Terminate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<RoleFixtureProvisioner.Result> running = fixture.Source.ProvisionAsync(plan, Material).AsTask();
        await fixture.State.Applied.Task.WaitAsync(TimeSpan.FromSeconds(10));
        string path = Path.Combine(fixture.DirectoryPath, fixture.Selector.Nonce.ToString("N") + ".journal");
        using (var held = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            fixture.State.Terminate.TrySetResult();
            await Assert.That(async () => await running).Throws<InvalidOperationException>();
        }
        int writes = fixture.WriteCount;
        await fixture.Source.SettleAsync(plan);
        await Assert.That(fixture.Read().Resources.Single(r => r.Id == plan.VaultId).ActiveDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(fixture.WriteCount).IsEqualTo(writes);
        var released = await fixture.Source.ReleaseAsync("owner", fixture.Selector, purge: true);
        await Assert.That(released.State).IsEqualTo(RoleFixtureProvisioner.State.Released);
    }

    [Test]
    public async Task ServiceRetainsSelectedCompletionWhenJournalFinalizationIsContended()
    {
        await using var fixture = new ServiceFixture(operation: "CreateRoleAssignmentAsync");
        var lease = await fixture.Prepare();
        using var arm = await fixture.Send("role/arm",
            new ObserveLease(lease.Facts.LeaseId, fixture.Native.Selector.Nonce, "subscribe-before-trigger"));
        await fixture.Read<ObservationSubscription>(arm);
        fixture.Native.State.SelectedApplied = new(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Native.State.SelectedTerminate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var running = fixture.CreateSelected(lease).AsTask();
        await fixture.Native.State.SelectedApplied.Task.WaitAsync(TimeSpan.FromSeconds(10));
        string path = Path.Combine(fixture.Native.DirectoryPath, fixture.Native.Selector.Nonce.ToString("N") + ".journal");
        using (var held = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            fixture.Native.State.SelectedTerminate.TrySetResult();
            await running;
        }
        using var release = await fixture.Send("role/release", fixture.Native.Selector);
        RoleFixtureRelease.Validate(await fixture.Read<RoleFixtureRelease.Measurement>(release),
            fixture.Native.Selector, lease.Facts);
        await Assert.That(fixture.SelectedBackend.Requests).IsEqualTo(1);
    }

    [Test]
    public async Task SelectedMutationForwardsExactlyTheValidatedContentSnapshot()
    {
        await using var fixture = new ServiceFixture(operation: "CreateRoleAssignmentAsync");
        var lease = await fixture.Prepare();
        using var arm = await fixture.Send("role/arm",
            new ObserveLease(lease.Facts.LeaseId, fixture.Native.Selector.Nonce, "subscribe-before-trigger"));
        await fixture.Read<ObservationSubscription>(arm);
        using var request = fixture.SelectedTransport.CreateRequest();
        request.Method = RequestMethod.Put;
        request.Uri.Reset(new Uri($"https://management.azure.com/subscriptions/{Subscription:D}/resourceGroups/fixture-group/providers/Microsoft.KeyVault/vaults/{lease.VaultName}/providers/Microsoft.Authorization/roleAssignments/{lease.AssignmentId:D}?api-version=2022-04-01"));
        request.Headers.SetValue("Authorization", "Bearer administrative-arm");
        using var content = new ChangingGrantContent();
        request.Content = content;
        using var message = new HttpMessage(request, new ResponseClassifier());
        await fixture.SelectedTransport.ProcessAsync(message);
        await Assert.That(fixture.Native.State.Principal).IsEqualTo(PrincipalId);
        await Assert.That(content.Writes).IsEqualTo(1);
    }

    private sealed class ChangingGrantContent : RequestContent
    {
        internal int Writes;
        private byte[] Next() => JsonSerializer.SerializeToUtf8Bytes(new
        {
            properties = new
            {
                principalId = ++Writes == 1 ? PrincipalId : Guid.Parse("99999999-9999-9999-9999-999999999999"),
                roleDefinitionId = DefinitionPath
            }
        });
        public override void WriteTo(Stream stream, CancellationToken cancellationToken) => stream.Write(Next());
        public override async Task WriteToAsync(Stream stream, CancellationToken cancellationToken) =>
            await stream.WriteAsync(Next(), cancellationToken);
        public override bool TryComputeLength(out long length) { length = 0; return false; }
        public override void Dispose() { }
    }
}
