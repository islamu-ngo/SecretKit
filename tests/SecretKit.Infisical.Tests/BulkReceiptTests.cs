using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class BulkReceiptTests
{
    [Test]
    [Arguments("foreign")]
    [Arguments("duplicate-row")]
    [Arguments("duplicate-field")]
    [Arguments("malformed")]
    [Arguments("nonpositive-version")]
    public async Task FirstSupportedRowRemainsObservableWhenLaterRowContradicts(string failure)
    {
        const string first = """{"secretKey":"first","type":"shared","workspace":"project","environment":"dev","version":1}""";
        string later = failure switch
        {
            "duplicate-row" => first,
            "duplicate-field" => """{"secretKey":"second","type":"shared","workspace":"project","environment":"dev","version":1,"version":2}""",
            "malformed" => "null",
            "nonpositive-version" => """{"secretKey":"second","type":"shared","workspace":"project","environment":"dev","version":0}""",
            _ => """{"secretKey":"foreign","type":"shared","workspace":"project","environment":"dev","version":1}"""
        };
        using var wire = new BulkWire("{\"secrets\":[" + first + "," + later + "]}");
        await using InfisicalClient client = Phase5TestSupport.Client(wire);
        var target = new SecretReference(client.Authority, new InfisicalBulkAddress("project", "dev", "/"));
        using var material = SecretMaterial.FromText("bulk-material");
        InfisicalBulkSecret[] inputs = [new("first", material), new("second", material)];
        var receipt = new InfisicalBulkReceipt(client, target, inputs, InfisicalBulkOperation.Create);
        IReadOnlyList<InfisicalBulkItemObservation> before = receipt.Items;
        var result = await client.CreateSecretsAsync(target, inputs, Phase5TestSupport.Admin(client), receipt);
        await Assert.That(wire.Committed).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Items[0].Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(receipt.Items[0].Version).IsEqualTo("1");
        await Assert.That(receipt.Items[1].Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(before.All(item => item.Evidence == DispatchEvidence.NotDispatched)).IsTrue();
        await Assert.That(wire.Values["first"]).IsEqualTo("bulk-material");
        await Assert.That(wire.Values["second"]).IsEqualTo("bulk-material");
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.That(async () => await client.CreateSecretsAsync(target, inputs,
            Phase5TestSupport.Admin(client), receipt, canceled.Token)).Throws<OperationCanceledException>();
        await Assert.That(receipt.Items[0].Version).IsEqualTo("1");
        await Assert.That(receipt.Items[1].Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    public async Task PostDispatchCancellationRetainsItemSnapshotsAndCommittedBackendState()
    {
        using var wire = new BulkWire("{}") { Hold = true };
        await using InfisicalClient client = Phase5TestSupport.Client(wire);
        var target = new SecretReference(client.Authority, new InfisicalBulkAddress("project", "dev", "/"));
        using var material = SecretMaterial.FromText("canceled-bulk");
        InfisicalBulkSecret[] inputs = [new("first", material), new("second", material)];
        var receipt = new InfisicalBulkReceipt(client, target, inputs, InfisicalBulkOperation.Create);
        using var canceled = new CancellationTokenSource();
        Task observed = wire.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Task<SecretOutcome<InfisicalBulkObservation>> operation = client.CreateSecretsAsync(target, inputs,
            Phase5TestSupport.Admin(client), receipt, canceled.Token).AsTask();
        try
        {
            await observed;
            IReadOnlyList<InfisicalBulkItemObservation> snapshot = receipt.Items;
            await Assert.That(snapshot.All(item => item.Evidence == DispatchEvidence.PossiblyDispatched)).IsTrue();
            canceled.Cancel();
            await Assert.That(async () => await operation).Throws<OperationCanceledException>();
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            await Assert.That(receipt.Items.Count).IsEqualTo(2);
            await Assert.That(snapshot.All(item => item.Evidence == DispatchEvidence.PossiblyDispatched)).IsTrue();
            await Assert.That(wire.Values["first"]).IsEqualTo("canceled-bulk");
            await Assert.That(wire.Values["second"]).IsEqualTo("canceled-bulk");
        }
        finally { wire.Release.TrySetResult(); }
    }

    [Test]
    public async Task LostResponseRetainsUncertainItemsWithoutEnablingReplay()
    {
        using var wire = new BulkWire("{}") { LoseResponse = true };
        await using InfisicalClient client = Phase5TestSupport.Client(wire);
        var target = new SecretReference(client.Authority, new InfisicalBulkAddress("project", "dev", "/"));
        using var material = SecretMaterial.FromText("lost-bulk");
        InfisicalBulkSecret[] inputs = [new("first", material)];
        var receipt = new InfisicalBulkReceipt(client, target, inputs, InfisicalBulkOperation.Create);
        var result = await client.CreateSecretsAsync(target, inputs, Phase5TestSupport.Admin(client), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Items.Single().Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(wire.Values["first"]).IsEqualTo("lost-bulk");
        var forbidden = new InfisicalNativeAuthority(client.Authority,
            new Phase5TestSupport.Tokens("unused", true), "project");
        await Assert.That((await client.CreateSecretsAsync(target, inputs, forbidden, receipt)).Status)
            .IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    [Arguments("client")]
    [Arguments("target")]
    [Arguments("order")]
    [Arguments("operation")]
    [Arguments("mode")]
    public async Task ForeignOrChangedIntentIsRejectedBeforeCredentialAcquisition(string mismatch)
    {
        using var wire = new BulkWire("{}");
        await using InfisicalClient owner = Phase5TestSupport.Client(wire);
        await using InfisicalClient other = Phase5TestSupport.Client(new BulkWire("{}"));
        var original = new SecretReference(owner.Authority, new InfisicalBulkAddress("project", "dev", "/"));
        using var material = SecretMaterial.FromText("not-dispatched");
        InfisicalBulkSecret[] inputs = [new("first", material), new("second", material)];
        var receipt = new InfisicalBulkReceipt(owner, original, inputs,
            mismatch == "mode" ? InfisicalBulkOperation.Update : InfisicalBulkOperation.Create,
            mismatch == "mode" ? InfisicalBulkUpdateMode.Upsert : InfisicalBulkUpdateMode.FailOnNotFound);
        InfisicalClient selected = mismatch == "client" ? other : owner;
        SecretReference target = mismatch is "client" or "target"
            ? new(selected.Authority, new InfisicalBulkAddress("project", "dev", "/")) : original;
        InfisicalBulkSecret[] submitted = mismatch == "order" ? inputs.Reverse().ToArray() : inputs;
        var forbidden = new InfisicalNativeAuthority(selected.Authority,
            new Phase5TestSupport.Tokens("unused", true), "project");
        var result = mismatch is "operation" or "mode"
            ? await selected.UpdateSecretsAsync(target, submitted, forbidden, receipt)
            : await selected.CreateSecretsAsync(target, submitted, forbidden, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(receipt.Items.All(item => item.Evidence == DispatchEvidence.NotDispatched)).IsTrue();
        await Assert.That(wire.Values.Count).IsEqualTo(0);
    }

    [Test]
    public async Task EmptyBatchDoesNotAcquireAndEmptyObservationCannotMeanAllApplied()
    {
        using var wire = new BulkWire("{}");
        await using InfisicalClient client = Phase5TestSupport.Client(wire);
        var target = new SecretReference(client.Authority, new InfisicalBulkAddress("project", "dev", "/"));
        var receipt = new InfisicalBulkReceipt(client, target, [], InfisicalBulkOperation.Create);
        var forbidden = new InfisicalNativeAuthority(client.Authority,
            new Phase5TestSupport.Tokens("unused", true), "project");
        await Assert.That((await client.CreateSecretsAsync(target, [], forbidden, receipt)).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(new InfisicalBulkObservation([], null).AllApplied).IsFalse();
        await Assert.That(wire.Values.Count).IsEqualTo(0);
    }

    private sealed class BulkWire(string response) : HttpMessageHandler
    {
        internal bool Committed { get; private set; }
        internal bool Hold { get; init; }
        internal bool LoseResponse { get; init; }
        internal Dictionary<string, string?> Values { get; } = new(StringComparer.Ordinal);
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            using var body = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(cancellationToken));
            foreach (JsonElement item in body.RootElement.GetProperty("secrets").EnumerateArray())
                Values[item.GetProperty("secretKey").GetString()!] = item.GetProperty("secretValue").GetString();
            Committed = true;
            Entered.TrySetResult();
            if (Hold) await Release.Task.WaitAsync(cancellationToken);
            if (LoseResponse) throw new HttpRequestException("Fixture lost its response after commit.");
            return new(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
        protected override void Dispose(bool disposing)
        {
            Release.TrySetResult();
            base.Dispose(disposing);
        }
    }
}
