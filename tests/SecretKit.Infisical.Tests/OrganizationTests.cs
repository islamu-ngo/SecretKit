using System.Net;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class OrganizationTests
{
    [Test]
    public async Task EnvironmentLifecycleUsesCurrentRoutesAndSeparateAuthority()
    {
        var backend = new OrganizationBackend();
        await using InfisicalClient client = Phase5TestSupport.Client(backend);
        InfisicalNativeAuthority admin = Phase5TestSupport.Admin(client);
        var create = new SecretReference(client.Authority, new InfisicalEnvironmentAddress("project", "dev", InfisicalOrganizationSelector.Slug));
        var createdReceipt = new MutationReceipt(create);
        InfisicalEnvironment created = (await client.CreateEnvironmentAsync(create, "Development", admin, createdReceipt, 1)).Value;
        await Assert.That(createdReceipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(created.ProjectId).IsEqualTo("project");
        var byId = new SecretReference(client.Authority, new InfisicalEnvironmentAddress("project", created.Id));
        await Assert.That((await client.GetEnvironmentAsync(byId)).Value.Slug).IsEqualTo("dev");
        await Assert.That((await client.GetEnvironmentAsync(create)).Value.Id).IsEqualTo(created.Id);
        var updateReceipt = new MutationReceipt(byId);
        await Assert.That((await client.UpdateEnvironmentAsync(byId, admin, updateReceipt, name: "New name", position: 2)).Value.Name).IsEqualTo("New name");
        await Assert.That((await client.GetEnvironmentAsync(byId)).Value.Position).IsEqualTo(2d);
        var deleteReceipt = new MutationReceipt(byId);
        await Assert.That((await client.DeleteEnvironmentAsync(byId, admin, deleteReceipt)).Value.SoftDeletedAt is not null).IsTrue();
        var restoreReceipt = new MutationReceipt(byId);
        await Assert.That((await client.RestoreEnvironmentAsync(byId, admin, restoreReceipt)).Value.SoftDeletedAt is null).IsTrue();
        await Assert.That(restoreReceipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(JsonSerializer.Serialize(created)).IsEqualTo("{}");
    }

    [Test]
    public async Task TagLifecycleAndBoundedListingRetainNamesWithoutSerialization()
    {
        var backend = new OrganizationBackend();
        await using InfisicalClient client = Phase5TestSupport.Client(backend);
        InfisicalNativeAuthority admin = Phase5TestSupport.Admin(client);
        var create = new SecretReference(client.Authority, new InfisicalTagAddress("project", "protected-tag", InfisicalOrganizationSelector.Slug));
        InfisicalTag created = (await client.CreateTagAsync(create, "#123456", admin, new(create))).Value;
        var byId = new SecretReference(client.Authority, new InfisicalTagAddress("project", created.Id));
        await Assert.That((await client.GetTagAsync(byId)).Value.Slug).IsEqualTo("protected-tag");
        await Assert.That((await client.GetTagAsync(create)).Value.Id).IsEqualTo(created.Id);
        await Assert.That((await client.UpdateTagAsync(byId, "renamed-tag", "#654321", admin, new(byId))).Value.Slug).IsEqualTo("renamed-tag");
        var list = new SecretReference(client.Authority, new InfisicalTagAddress("project"));
        await Assert.That((await client.ListTagsAsync(list)).Value.Items.Single().Slug).IsEqualTo("renamed-tag");
        await Assert.That(JsonSerializer.Serialize((await client.GetTagAsync(byId)).Value)).IsEqualTo("{}");
        await Assert.That((await client.DeleteTagAsync(byId, admin, new(byId))).Value.Id).IsEqualTo(created.Id);
        await Assert.That((await client.ListTagsAsync(list)).Value.Items.Count).IsEqualTo(0);
    }

    [Test]
    public async Task FolderLifecycleBatchAndMoveObserveActualScopedState()
    {
        var backend = new OrganizationBackend();
        await using InfisicalClient client = Phase5TestSupport.Client(backend);
        InfisicalNativeAuthority admin = Phase5TestSupport.Admin(client);
        var create = new SecretReference(client.Authority, new InfisicalFolderAddress("project", "dev", Phase5TestSupport.EnvironmentId, "/", name: "child"));
        InfisicalFolder folder = (await client.CreateFolderAsync(create, admin, new(create), "description")).Value;
        var byId = new SecretReference(client.Authority, new InfisicalFolderAddress("project", "dev", Phase5TestSupport.EnvironmentId, "/", folder.Id));
        await Assert.That((await client.GetFolderAsync(byId)).Value.Name).IsEqualTo("child");
        var list = new SecretReference(client.Authority, new InfisicalFolderAddress("project", "dev", Phase5TestSupport.EnvironmentId, "/"));
        await Assert.That((await client.ListFoldersAsync(list)).Value.Items.Count).IsEqualTo(1);
        var rename = new SecretReference(client.Authority, new InfisicalFolderAddress("project", "dev", Phase5TestSupport.EnvironmentId, "/", folder.Id, "renamed"));
        await Assert.That((await client.UpdateFolderAsync(rename, admin, new(rename), clearDescription: true)).Value.Description is null).IsTrue();
        var batchReceipt = new MutationReceipt(list);
        InfisicalNativeList<InfisicalFolder> batch = (await client.UpdateFoldersAsync(list, [new(folder.Id, "batched")], admin, batchReceipt)).Value;
        await Assert.That(batch.IsComplete).IsTrue();
        await Assert.That(batchReceipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That((await client.GetFolderAsync(byId)).Value.Name).IsEqualTo("batched");
        var moveReceipt = new MutationReceipt(byId);
        InfisicalFolderMove move = (await client.MoveFolderAsync(byId,
            new("project", "prod", Phase5TestSupport.OtherEnvironmentId, "/"), admin, moveReceipt)).Value;
        await Assert.That(move.DestinationEnvironment).IsEqualTo("prod");
        var moved = new SecretReference(client.Authority, new InfisicalFolderAddress("project", "prod", Phase5TestSupport.OtherEnvironmentId, "/", folder.Id));
        await Assert.That((await client.GetFolderAsync(moved)).Value.EnvironmentId).IsEqualTo(Phase5TestSupport.OtherEnvironmentId);
        await Assert.That((await client.DeleteFolderAsync(moved, admin, new(moved))).Value.Id).IsEqualTo(folder.Id);
        await Assert.That((await client.GetFolderAsync(moved)).Status).IsEqualTo(SecretStatus.Absent);
        await Assert.That(JsonSerializer.Serialize(folder)).IsEqualTo("{}");
    }

    [Test]
    public async Task WrongInstanceScopeOrReceiptCannotAcquireTokenOrMutate()
    {
        var backend = new OrganizationBackend();
        await using InfisicalClient client = Phase5TestSupport.Client(backend);
        var target = new SecretReference(client.Authority, new InfisicalTagAddress("project", "tag", InfisicalOrganizationSelector.Slug));
        var forbidden = new Phase5TestSupport.Tokens("admin", forbidden: true);
        var wrongProject = new InfisicalNativeAuthority(client.Authority, forbidden, "other-project");
        var receipt = new MutationReceipt(target);
        await Assert.That((await client.CreateTagAsync(target, "color", wrongProject, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        var wrongClient = new InfisicalNativeAuthority(new SecretAuthority(), forbidden, "project");
        await Assert.That((await client.CreateTagAsync(target, "color", wrongClient, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        var other = new SecretReference(client.Authority, new InfisicalTagAddress("project", "other", InfisicalOrganizationSelector.Slug));
        var native = new InfisicalNativeAuthority(client.Authority, forbidden, "project");
        await Assert.That((await client.CreateTagAsync(target, "color", native, new(other))).Status).IsEqualTo(SecretStatus.Invalid);
        var scoped = new InfisicalNativeAuthority(client.Authority, forbidden, "project", "dev", "/only");
        await Assert.That((await client.CreateTagAsync(target, "color", scoped, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(backend.Tag is null).IsTrue();
        await Assert.That(JsonSerializer.Serialize(native)).IsEqualTo("{}");
        await Assert.That(target.ToString().Contains("tag", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task InputBudgetIsCheckedBeforeCredentialsAndResponseBudgetLeavesUnknownReceipt()
    {
        await using InfisicalClient client = Phase5TestSupport.Client(new OrganizationBackend(), responseLimit: 1024);
        var target = new SecretReference(client.Authority, new InfisicalTagAddress("project", "tag", InfisicalOrganizationSelector.Slug));
        var admin = new InfisicalNativeAuthority(client.Authority, new Phase5TestSupport.Tokens("admin", true), "project");
        var receipt = new MutationReceipt(target);
        await Assert.That((await client.CreateTagAsync(target, new string('x', 1024), admin, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        var backend = new OrganizationBackend { Oversized = true };
        await using InfisicalClient responseClient = Phase5TestSupport.Client(backend, responseLimit: 1024);
        var responseTarget = new SecretReference(responseClient.Authority, new InfisicalTagAddress("project", "tag", InfisicalOrganizationSelector.Slug));
        var responseReceipt = new MutationReceipt(responseTarget);
        await Assert.That((await responseClient.CreateTagAsync(responseTarget, "color", Phase5TestSupport.Admin(responseClient), responseReceipt)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(responseReceipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(backend.Tag is not null).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ConflictAndWrongResponseCoordinatesNeverBecomeApplied(bool wrongCoordinates)
    {
        var backend = new OrganizationBackend { Conflict = !wrongCoordinates, WrongProject = wrongCoordinates };
        await using InfisicalClient client = Phase5TestSupport.Client(backend);
        var target = new SecretReference(client.Authority, new InfisicalTagAddress("project", "tag", InfisicalOrganizationSelector.Slug));
        var receipt = new MutationReceipt(target);
        var result = await client.CreateTagAsync(target, "color", Phase5TestSupport.Admin(client), receipt);
        await Assert.That(result.Status).IsEqualTo(wrongCoordinates ? SecretStatus.Unknown : SecretStatus.Conflict);
        await Assert.That(receipt.Evidence).IsEqualTo(wrongCoordinates ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Conflict);
    }

    [Test]
    public async Task TruncatedListAndPartialFolderBatchDoNotClaimCompleteness()
    {
        var backend = new OrganizationBackend { MultipleTags = true, PartialBatch = true };
        await using InfisicalClient client = Phase5TestSupport.Client(backend);
        InfisicalNativeAuthority admin = Phase5TestSupport.Admin(client);
        var tag = new SecretReference(client.Authority, new InfisicalTagAddress("project", "tag", InfisicalOrganizationSelector.Slug));
        _ = (await client.CreateTagAsync(tag, "color", admin, new(tag))).Value;
        var list = new SecretReference(client.Authority, new InfisicalTagAddress("project"));
        InfisicalNativeList<InfisicalTag> tags = (await client.ListTagsAsync(list, 1)).Value;
        await Assert.That(tags.Items.Count).IsEqualTo(1);
        await Assert.That(tags.IsComplete).IsFalse();
        var folder = new SecretReference(client.Authority, new InfisicalFolderAddress("project", "dev", Phase5TestSupport.EnvironmentId, "/", name: "child"));
        string id = (await client.CreateFolderAsync(folder, admin, new(folder))).Value.Id;
        var scope = new SecretReference(client.Authority, new InfisicalFolderAddress("project", "dev", Phase5TestSupport.EnvironmentId, "/"));
        var receipt = new MutationReceipt(scope);
        var batch = (await client.UpdateFoldersAsync(scope, [new(id, "updated"), new(Phase5TestSupport.OtherId, "missing")], admin, receipt)).Value;
        await Assert.That(batch.IsComplete).IsFalse();
        await Assert.That(batch.Items.Single().Name).IsEqualTo("updated");
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    private sealed class OrganizationBackend : HttpMessageHandler
    {
        private string _environmentName = "Development";
        private double _position = 1;
        private bool _deleted;
        public Dictionary<string, object?>? Tag { get; private set; }
        private Dictionary<string, object?>? _folder;
        private string _folderEnvironment = "dev";
        public bool Oversized { get; init; }
        public bool WrongProject { get; init; }
        public bool Conflict { get; init; }
        public bool MultipleTags { get; init; }
        public bool PartialBatch { get; init; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method != HttpMethod.Get && request.Headers.Authorization?.Parameter != "admin")
            {
                return Phase5TestSupport.Json(403, new { });
            }
            if (Conflict && request.Method != HttpMethod.Get) { return Phase5TestSupport.Json(409, new { }); }
            string path = request.RequestUri!.AbsolutePath;
            using JsonDocument? body = request.Content is null ? null : JsonDocument.Parse(await request.Content.ReadAsByteArrayAsync(cancellationToken));
            if (path.Contains("/environments", StringComparison.Ordinal))
            {
                if (body is not null)
                {
                    if (body.RootElement.TryGetProperty("name", out JsonElement name)) { _environmentName = name.GetString()!; }
                    if (body.RootElement.TryGetProperty("position", out JsonElement position)) { _position = position.GetDouble(); }
                }
                if (request.Method == HttpMethod.Delete) { _deleted = true; }
                if (path.EndsWith("/restore", StringComparison.Ordinal)) { _deleted = false; }
                return Phase5TestSupport.Json(200, new
                {
                    environment = new
                    {
                        id = Phase5TestSupport.EnvironmentId,
                        projectId = "project",
                        name = _environmentName,
                        slug = "dev",
                        position = _position,
                        createdAt = Phase5TestSupport.Date,
                        updatedAt = Phase5TestSupport.Date,
                        softDeletedAt = _deleted ? Phase5TestSupport.Date : (string?)null
                    }
                });
            }
            if (path.Contains("/tags", StringComparison.Ordinal))
            {
                if (request.Method == HttpMethod.Post || request.Method == HttpMethod.Patch)
                {
                    Tag = new Dictionary<string, object?>
                    {
                        ["id"] = Phase5TestSupport.Id,
                        ["projectId"] = WrongProject ? "other-project" : "project",
                        ["slug"] = body!.RootElement.GetProperty("slug").GetString(),
                        ["color"] = body.RootElement.GetProperty("color").GetString(),
                        ["createdAt"] = Phase5TestSupport.Date,
                        ["updatedAt"] = Phase5TestSupport.Date
                    };
                }
                if (Oversized) { return Phase5TestSupport.Json(200, new { tag = Tag, privateText = new string('p', 2048) }); }
                if (request.Method == HttpMethod.Get && path.EndsWith("/tags", StringComparison.Ordinal))
                {
                    return Phase5TestSupport.Json(200, new { tags = Tag is null ? [] : MultipleTags ? new[] { Tag, Tag } : new[] { Tag } });
                }
                Dictionary<string, object?>? result = Tag;
                if (request.Method == HttpMethod.Delete) { Tag = null; }
                return result is null ? Phase5TestSupport.Json(404, new { }) : Phase5TestSupport.Json(200, new { tag = result });
            }
            if (path.StartsWith("/api/v2/folders", StringComparison.Ordinal))
            {
                if (request.Method == HttpMethod.Post && !path.EndsWith("/move", StringComparison.Ordinal))
                {
                    if (body!.RootElement.GetProperty("projectId").GetString() != "project" ||
                        body.RootElement.GetProperty("environment").GetString() != "dev" ||
                        body.RootElement.GetProperty("path").GetString() != "/") { return Phase5TestSupport.Json(400, new { }); }
                    _folder = new Dictionary<string, object?>
                    {
                        ["id"] = Phase5TestSupport.Id,
                        ["envId"] = Phase5TestSupport.EnvironmentId,
                        ["name"] = body.RootElement.GetProperty("name").GetString(),
                        ["description"] = body.RootElement.TryGetProperty("description", out JsonElement description) ? description.GetString() : null,
                        ["createdAt"] = Phase5TestSupport.Date,
                        ["updatedAt"] = Phase5TestSupport.Date
                    };
                }
                if (path.EndsWith("/batch", StringComparison.Ordinal))
                {
                    if (_folder is null) { return Phase5TestSupport.Json(404, new { }); }
                    JsonElement first = body!.RootElement.GetProperty("folders")[0];
                    _folder["name"] = first.GetProperty("name").GetString();
                    return Phase5TestSupport.Json(200, new { folders = new[] { _folder } });
                }
                if (path.EndsWith("/move", StringComparison.Ordinal))
                {
                    if (_folder is null) { return Phase5TestSupport.Json(404, new { }); }
                    string source = _folderEnvironment;
                    _folderEnvironment = body!.RootElement.GetProperty("destinationEnvironment").GetString()!;
                    _folder["envId"] = Phase5TestSupport.OtherEnvironmentId;
                    return Phase5TestSupport.Json(200, new
                    {
                        folderId = _folder["id"],
                        sourceEnvironment = source,
                        sourcePath = "/",
                        destinationEnvironment = _folderEnvironment,
                        destinationPath = "/"
                    });
                }
                if (request.Method == HttpMethod.Patch && _folder is not null)
                {
                    _folder["name"] = body!.RootElement.GetProperty("name").GetString();
                    if (body.RootElement.TryGetProperty("description", out JsonElement description))
                    {
                        _folder["description"] = description.ValueKind == JsonValueKind.Null ? null : description.GetString();
                    }
                }
                if (request.Method == HttpMethod.Get && path == "/api/v2/folders")
                {
                    if (!request.RequestUri.Query.Contains("path=%2F", StringComparison.Ordinal) ||
                        !request.RequestUri.Query.Contains("recursive=false", StringComparison.Ordinal)) { return Phase5TestSupport.Json(400, new { }); }
                    return Phase5TestSupport.Json(200, new { folders = _folder is null ? [] : new[] { _folder } });
                }
                if (_folder is null) { return Phase5TestSupport.Json(404, new { }); }
                var result = new Dictionary<string, object?>(_folder)
                {
                    ["projectId"] = "project",
                    ["path"] = "/",
                    ["environment"] = new { envSlug = _folderEnvironment, envId = _folder["envId"], envName = _folderEnvironment }
                };
                if (request.Method == HttpMethod.Delete) { _folder = null; }
                return Phase5TestSupport.Json(200, new { folder = result });
            }
            throw new InvalidOperationException("Unexpected organization route.");
        }
    }
}

internal static class Phase5TestSupport
{
    internal const string Id = "00000000-0000-4000-8000-000000000001";
    internal const string OtherId = "00000000-0000-4000-8000-000000000002";
    internal const string EnvironmentId = "00000000-0000-4000-8000-000000000003";
    internal const string OtherEnvironmentId = "00000000-0000-4000-8000-000000000004";
    internal const string Date = "2026-10-09T10:00:00Z";
    internal static InfisicalClient Client(HttpMessageHandler handler, string token = "runtime", int responseLimit = 1024 * 1024) =>
        new(new Uri("https://infisical.test"), new Tokens(token),
            new InfisicalNetworkOptions { MaximumResponseBytes = responseLimit }, null, handler);
    internal static InfisicalNativeAuthority Admin(InfisicalClient client, string? environment = null, string? folder = null) =>
        new(client.Authority, new Tokens("admin"), "project", environment, folder);
    internal static HttpResponseMessage Json(int status, object body) =>
        new((HttpStatusCode)status) { Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(body)) };
    internal sealed class Tokens(string token, bool forbidden = false) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (forbidden) { throw new InvalidOperationException("Credentials must not be acquired."); }
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText(token))));
        }
    }
}
