using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Samples.OperatorWorkflow;

namespace SecretKit.Consumer.Tests;

public sealed class OperatorCompositionTests
{
    [Test]
    [Arguments("", SecretStatus.Success, 2)]
    [Arguments("conflict", SecretStatus.Success, 2)]
    [Arguments("lost", SecretStatus.Unknown, 1)]
    [Arguments("wrong-child", SecretStatus.Unknown, 1)]
    public async Task ExplicitPathKeepsEachReceiptAndStopsAfterUncertainCreation(string fault,
        SecretStatus expected, int created)
    {
        using var wire = new FolderWire(fault);
        using var material = SecretMaterial.FromText("operator-admin");
        using var tokens = new InfisicalSuppliedTokenSource(material);
        await using var client = new InfisicalClient(OperatorWorkflow.Origin, tokens, OperatorWorkflow.Network(wire));
        var authority = new InfisicalNativeAuthority(client.Authority, tokens, "project", "dev");
        var receipts = new List<MutationReceipt>();

        SecretStatus result = await CreateReviewedPathAsync(client, authority, receipts);

        await Assert.That(result).IsEqualTo(expected);
        await Assert.That(wire.Folders.Count).IsEqualTo(created);
        await Assert.That(receipts.Count).IsEqualTo(created);
        await Assert.That(receipts[0].Evidence).IsEqualTo(fault switch
        {
            "lost" => DispatchEvidence.PossiblyDispatched,
            "conflict" or "wrong-child" => DispatchEvidence.Conflict,
            _ => DispatchEvidence.Applied
        });
        if (result == SecretStatus.Success)
            await Assert.That(wire.Folders.ContainsKey("/parent/child")).IsTrue();
    }

    // This executable host recipe creates two explicitly reviewed segments, not an SDK auto-create policy.
    private static async Task<SecretStatus> CreateReviewedPathAsync(InfisicalClient client,
        InfisicalNativeAuthority authority, List<MutationReceipt> receipts)
    {
        string parent = "/";
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        foreach (string name in new[] { "parent", "child" })
        {
            string expectedPath = parent == "/" ? "/" + name : parent + "/" + name;
            var scope = new SecretReference(client.Authority,
                new InfisicalFolderAddress("project", "dev", OperatorWorkflow.EnvironmentId, parent));
            var listed = await client.ListFoldersAsync(scope, maximumItems: 10, cancellationToken: budget.Token);
            if (!listed.IsSuccess) return listed.Status;
            if (!listed.Value.IsComplete) return SecretStatus.Unknown;
            var existing = listed.Value.Items.Where(item => item.Name == name && item.Path == expectedPath).ToArray();
            if (existing.Length > 1) return SecretStatus.Unknown;
            if (existing.Length == 0)
            {
                var target = new SecretReference(client.Authority,
                    new InfisicalFolderAddress("project", "dev", OperatorWorkflow.EnvironmentId, parent, name: name));
                var receipt = client.CreateReceipt(target);
                receipts.Add(receipt); // Retain before dispatch; cancellation cannot erase evidence.
                var created = await client.CreateFolderAsync(target, authority, receipt, cancellationToken: budget.Token);
                if (!created.IsSuccess)
                {
                    if (created.Status != SecretStatus.Conflict || receipt.Evidence != DispatchEvidence.Conflict)
                        return created.Status;
                    // One explicit bounded inspection may resolve confirmed conflict; never replay creation.
                    var inspected = await client.ListFoldersAsync(scope, maximumItems: 10, cancellationToken: budget.Token);
                    if (!inspected.IsSuccess || !inspected.Value.IsComplete ||
                        inspected.Value.Items.Count(item => item.Name == name && item.Path == expectedPath) != 1)
                        return SecretStatus.Unknown;
                }
                else if (created.Value.Path != expectedPath) return SecretStatus.Unknown;
            }
            parent = expectedPath;
        }
        return SecretStatus.Success;
    }

    [Test]
    [Arguments(false, SecretStatus.Success, DispatchEvidence.Applied)]
    [Arguments(true, SecretStatus.Unknown, DispatchEvidence.PossiblyDispatched)]
    public async Task OneItemDeleteRetainsReceiptWhenAcknowledgmentIsLost(bool loseResponse,
        SecretStatus expected, DispatchEvidence evidence)
    {
        using var wire = new DeleteWire(loseResponse);
        using var material = SecretMaterial.FromText("operator-admin");
        using var tokens = new InfisicalSuppliedTokenSource(material);
        await using var client = new InfisicalClient(OperatorWorkflow.Origin, tokens, OperatorWorkflow.Network(wire));
        var authority = new InfisicalNativeAuthority(client.Authority, tokens, "project", "dev", "/");
        var target = new SecretReference(client.Authority, new InfisicalBulkAddress("project", "dev", "/"));
        InfisicalBulkSecret[] items = [new("RETIRED")];
        var receipt = new InfisicalBulkReceipt(client, target, items, InfisicalBulkOperation.Delete);

        var result = await client.DeleteSecretsAsync(target, items, authority, receipt);

        await Assert.That(result.Status).IsEqualTo(expected);
        await Assert.That(receipt.Items.Single().Evidence).IsEqualTo(evidence);
        await Assert.That(wire.Exists).IsFalse();
        await Assert.That(wire.Deletes).IsEqualTo(1);
    }

    private sealed class FolderWire(string fault) : HttpMessageHandler
    {
        public Dictionary<string, object> Folders { get; } = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (request.Method == HttpMethod.Get)
            {
                string query = Uri.UnescapeDataString(request.RequestUri!.Query);
                string parent = query.Contains("path=/parent", StringComparison.Ordinal) ? "/parent" : "/";
                return Json(new
                {
                    folders = Folders.Where(pair =>
                        pair.Key[..pair.Key.LastIndexOf('/')] == (parent == "/" ? "" : parent)).Select(pair => pair.Value)
                });
            }
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            string name = body.RootElement.GetProperty("name").GetString()!;
            string path = name == "parent" ? "/parent" : "/parent/child";
            object folder = new
            {
                id = name == "parent" ? OperatorWorkflow.FolderId : "66666666-6666-4666-8666-666666666666",
                envId = OperatorWorkflow.EnvironmentId,
                name,
                path = fault == "wrong-child" ? "/foreign" : path,
                createdAt = "2026-11-01T00:00:00Z",
                updatedAt = "2026-11-01T00:00:00Z"
            };
            Folders[path] = folder;
            if (fault == "lost") throw new HttpRequestException("private-folder-detail");
            return fault is "conflict" or "wrong-child" ? Json(new { }, HttpStatusCode.Conflict) : Json(new { folder });
        }
    }

    private sealed class DeleteWire(bool loseResponse) : HttpMessageHandler
    {
        public bool Exists { get; private set; } = true;
        public int Deletes { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (request.Method != HttpMethod.Delete) return Task.FromResult(Json(new { }, HttpStatusCode.NotFound));
            Exists = false;
            Deletes++;
            if (loseResponse) throw new HttpRequestException("private-delete-detail");
            return Task.FromResult(Json(new
            {
                secrets = new[] { new { secretKey = "RETIRED", type = "shared", workspace = "project", environment = "dev", version = 1 } }
            }));
        }
    }

    private static HttpResponseMessage Json(object value, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json") };
}
