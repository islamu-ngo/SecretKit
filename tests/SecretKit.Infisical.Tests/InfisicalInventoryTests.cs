using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class InfisicalInventoryTests
{
    private const string EnvironmentId = "11111111-1111-1111-1111-111111111111";
    private const string ChildId = "22222222-2222-2222-2222-222222222222";
    private const string TagId = "33333333-3333-3333-3333-333333333333";

    [Test]
    public async Task ValueFreeListQualifiesTheSameRevisionAsAnIndependentNativeRead()
    {
        using var wire = new Wire((request, _) => Task.FromResult(Json(request.RequestUri!.AbsolutePath ==
            "/api/v4/secrets" ? new { secrets = new[] { Row() } } : new { secret = Row() })));
        await using var client = Client(wire);
        var inventory = (await client.InspectNativeAsync(Selection(client))).Value;
        using var read = (await client.ReadNativeAsync(new(client.Authority,
            new InfisicalSecretAddress("project", "test", "/", "key")))).Value;

        await Assert.That(inventory.IsComplete).IsTrue();
        await Assert.That(inventory.Entries.Single().Revision == read.Revision).IsTrue();
        await Assert.That(inventory.Entries.Single().TagIds!.Single()).IsEqualTo(TagId);
        await Assert.That(inventory.Entries.Single().IsRotatedSecret).IsFalse();
        await Assert.That(inventory.Entries.Single().ModifiedAt).IsEqualTo(DateTimeOffset.Parse("2026-11-01T00:00:00Z"));
        string encoded = JsonSerializer.Serialize(inventory) + inventory + inventory.Entries.Single() +
            JsonSerializer.Serialize(inventory.Entries.Single()) + JsonSerializer.Serialize(inventory.Selection);
        foreach (string sensitive in new[] { "key", "project", "private-value", "private-comment", TagId })
            await Assert.That(encoded.Contains(sensitive, StringComparison.Ordinal)).IsFalse();
        await Assert.That(wire.Requests[0].Query).Contains("viewSecretValue=false");
        await Assert.That(wire.Requests[0].Query).Contains("expandSecretReferences=false");
        await Assert.That(wire.Requests[0].Query).Contains("includePersonalOverrides=false");
    }

    [Test]
    [Arguments("id")]
    [Arguments("version")]
    [Arguments("workspace")]
    [Arguments("environment")]
    [Arguments("secretPath")]
    [Arguments("type")]
    public async Task MissingReturnedEvidenceCannotQualifyARevision(string field)
    {
        var row = Row();
        row.Remove(field);
        using var wire = new Wire((_, _) => Task.FromResult(Json(new { secrets = new[] { row } })));
        await using var client = Client(wire);
        var result = (await client.InspectNativeAsync(Selection(client))).Value;
        await Assert.That(result.Entries.Single().Revision is null).IsTrue();
        await Assert.That(result.IsComplete).IsFalse();
        await Assert.That(result.IncompleteReasons).Contains(InfisicalInventoryIncompleteReason.RevisionUnestablished);
    }

    [Test]
    [Arguments("workspace", "\"foreign\"")]
    [Arguments("environment", "\"foreign\"")]
    [Arguments("secretPath", "\"/sibling\"")]
    [Arguments("type", "\"personal\"")]
    public async Task ReturnedScopeContradictionsFailClosed(string field, string encoded)
    {
        var row = Row();
        row[field] = JsonSerializer.Deserialize<JsonElement>(encoded);
        using var wire = new Wire((_, _) => Task.FromResult(Json(new { secrets = new[] { row } })));
        await using var client = Client(wire);
        await Assert.That((await client.InspectNativeAsync(Selection(client))).Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    [Arguments("0")]
    [Arguments("-1")]
    [Arguments("1.5")]
    [Arguments("\"1\"")]
    [Arguments("2147483648")]
    public async Task MalformedVersionsNeverBecomeQualifiedRevisions(string encoded)
    {
        var row = Row();
        row["version"] = JsonSerializer.Deserialize<JsonElement>(encoded);
        using var wire = new Wire((_, _) => Task.FromResult(Json(new { secrets = new[] { row } })));
        await using var client = Client(wire);
        var result = (await client.InspectNativeAsync(Selection(client))).Value;
        await Assert.That(result.Entries.Single().Revision is null).IsTrue();
        await Assert.That(result.IsComplete).IsFalse();
    }

    [Test]
    [Arguments(null)]
    [Arguments("\"false\"")]
    [Arguments("null")]
    public async Task UnreturnedOrMalformedRotationOwnershipRemainsUnknown(string? encoded)
    {
        var row = Row();
        row.Remove("isRotatedSecret");
        if (encoded is not null) row["isRotatedSecret"] = JsonSerializer.Deserialize<JsonElement>(encoded);
        using var wire = new Wire((_, _) => Task.FromResult(Json(new { secrets = new[] { row } })));
        await using var client = Client(wire);
        var result = (await client.InspectNativeAsync(Selection(client))).Value;
        await Assert.That(result.Entries.Single().IsRotatedSecret is null).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task AggregateBytesIncludeDiscardedFieldsAcrossIndividuallyLegalBodies(bool oneOver)
    {
        byte[] first = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { secrets = new[] { Row() }, ignored = new string('x', 700) }));
        byte[] second = Encoding.UTF8.GetBytes("{\"folders\":[]}");
        using var wire = new Wire((request, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new MemoryStream(request.RequestUri!.AbsolutePath == "/api/v4/secrets" ? first : second))
        }));
        await using var client = Client(wire);
        var result = (await client.InspectNativeAsync(new(client.Authority, "project", "test", "/",
            recursive: true, environmentId: EnvironmentId, maximumResponseBytes: first.Length + second.Length - (oneOver ? 1 : 0)))).Value;
        await Assert.That(result.IsComplete).IsEqualTo(!oneOver);
        await Assert.That(result.IncompleteReasons.Contains(InfisicalInventoryIncompleteReason.ByteLimit)).IsEqualTo(oneOver);
    }

    [Test]
    [Arguments(null, false)]
    [Arguments("/sibling/child", true)]
    [Arguments("/child%2Fescape", true)]
    public async Task MissingOrSubstitutedAncestryNeverDescends(string? path, bool invalid)
    {
        using var wire = new Wire((request, _) => Task.FromResult(request.RequestUri!.AbsolutePath == "/api/v4/secrets"
            ? Json(new { secrets = new[] { Row() } })
            : Json(new { folders = new[] { Folder(path) } })));
        await using var client = Client(wire);
        var result = await client.InspectNativeAsync(Selection(client, recursive: true));
        if (invalid) await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        else
        {
            await Assert.That(result.Value.IsComplete).IsFalse();
            await Assert.That(result.Value.IncompleteReasons).Contains(InfisicalInventoryIncompleteReason.AncestryUnestablished);
        }
        await Assert.That(wire.Requests.Count).IsEqualTo(2);
    }

    [Test]
    public async Task ImportedCandidatesRetainGroupsWithoutInventingWinnersOrDirectRevisions()
    {
        var imported = Row("/source", "upstream");
        var group = new { environment = "upstream", secretPath = "/source", secrets = new[] { imported } };
        using var wire = new Wire((_, _) => Task.FromResult(Json(new { secrets = new[] { Row() }, imports = new[] { group, group } })));
        await using var client = Client(wire);
        var result = (await client.InspectNativeAsync(new(client.Authority, "project", "test", "/", includeImports: true))).Value;
        await Assert.That(result.Entries.Count).IsEqualTo(3);
        await Assert.That(result.ImportGroups.Count).IsEqualTo(2);
        await Assert.That(result.ImportGroups.Select(group => group.Order).SequenceEqual([0, 1])).IsTrue();
        foreach (var entry in result.Entries.Skip(1))
        {
            await Assert.That(entry.Reference is null).IsTrue();
            await Assert.That(entry.Revision is null).IsTrue();
            await Assert.That(entry.Origin).IsEqualTo(InfisicalInventoryOrigin.Imported);
            await Assert.That(entry.Folder).IsEqualTo("/");
            await Assert.That(entry.SourcePath).IsEqualTo("/source");
        }
        await Assert.That(result.IsComplete).IsTrue();
        await Assert.That(wire.Requests.Single().Query).Contains("includeImports=true");
    }

    [Test]
    public async Task ResourceRecreationChangesInventoryRevisionWithoutReadingValues()
    {
        string id = "original";
        using var wire = new Wire((_, _) =>
        {
            var row = Row();
            row["id"] = id;
            return Task.FromResult(Json(new { secrets = new[] { row } }));
        });
        await using var client = Client(wire);
        var original = (await client.InspectNativeAsync(Selection(client))).Value.Entries.Single().Revision;
        id = "recreated";
        var recreated = (await client.InspectNativeAsync(Selection(client))).Value.Entries.Single().Revision;
        await Assert.That(original == recreated).IsFalse();
        await Assert.That(wire.Requests.All(uri => uri.AbsolutePath == "/api/v4/secrets" &&
            uri.Query.Contains("viewSecretValue=false", StringComparison.Ordinal))).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DuplicateDirectKeysOrResourceIdsFailClosed(bool duplicateId)
    {
        var second = Row();
        second[duplicateId ? "secretKey" : "id"] = "other";
        using var wire = new Wire((_, _) => Task.FromResult(Json(new { secrets = new[] { Row(), second } })));
        await using var client = Client(wire);
        await Assert.That((await client.InspectNativeAsync(Selection(client))).Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task ForeignAuthorityNeverAcquiresCredentialsOrDispatches()
    {
        using var wire = new Wire((_, _) => throw new InvalidOperationException("Foreign selection dispatched."));
        await using var client = Client(wire, tokens: new Phase5TestSupport.Tokens("token", forbidden: true));
        var result = await client.InspectNativeAsync(new(new SecretAuthority(), "project", "test", "/"));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.AuthorityMismatch);
    }

    [Test]
    [Arguments("/a//b")]
    [Arguments("/a/")]
    [Arguments("/a/../b")]
    [Arguments("/a%2fb")]
    [Arguments("/a%252fb")]
    [Arguments("/a\\b")]
    public async Task NoncanonicalSelectionsAreRejectedBeforeTransport(string path)
    {
        await Assert.That(() => new InfisicalInventorySelection(new(), "project", "test", path)).Throws<ArgumentException>();
    }

    [Test]
    public async Task CommonInventoryKeepsLegacyDirectCoverageWithoutRequiringNativeRevisionEvidence()
    {
        using var wire = new Wire((_, _) => Task.FromResult(Json(new { secrets = new[] { new { secretKey = "key", version = 1 } } })));
        await using var client = Client(wire);
        var result = (await client.InspectAsync(new InfisicalInventoryScope(client.Authority, "project", "test", "/"))).Value;
        await Assert.That(result.IsComplete).IsTrue();
        await Assert.That(result.Items.Single().Version).IsEqualTo("1");
        await Assert.That(result.Items.Single().Reference.BelongsTo(client.Authority)).IsTrue();
    }

    [Test]
    public async Task VerifiedParentIdentityEstablishesChildAncestryWithoutInventingRootProof()
    {
        using var wire = new Wire((request, _) =>
        {
            string path = QueryPath(request.RequestUri!);
            if (request.RequestUri!.AbsolutePath == "/api/v4/secrets")
            {
                var row = Row(path);
                row["id"] = "resource" + path;
                return Task.FromResult(Json(new { secrets = new[] { row } }));
            }
            object[] folders = path switch
            {
                "/" => [Folder("/child")],
                "/child" => [Folder(null, TagId, "next", ChildId)],
                _ => []
            };
            return Task.FromResult(Json(new { folders }));
        });
        await using var client = Client(wire);
        var result = (await client.InspectNativeAsync(Selection(client, true))).Value;
        await Assert.That(result.IsComplete).IsTrue();
        await Assert.That(result.Entries.Select(entry => entry.Folder).SequenceEqual(["/", "/child", "/child/next"])).IsTrue();
        await Assert.That(result.Entries.All(entry => entry.Key == "key" && entry.Revision is not null)).IsTrue();
    }

    [Test]
    [Arguments(0, true)]
    [Arguments(20, true)]
    [Arguments(20, false)]
    public async Task DepthBoundaryChecksChildPresenceInsteadOfClaimingTruncationIsComplete(int depth, bool extraChild)
    {
        using var wire = new Wire((request, _) =>
        {
            string path = QueryPath(request.RequestUri!);
            int current = path == "/" ? 0 : path.Count(character => character == '/');
            if (request.RequestUri!.AbsolutePath == "/api/v4/secrets")
                return Task.FromResult(Json(new { secrets = Array.Empty<object>() }));
            string next = path == "/" ? "/child" : path + "/child";
            object[] folders = current < depth || extraChild
                ? [Folder(next, new Guid(current + 1, 0, 0, new byte[8]).ToString())] : [];
            return Task.FromResult(Json(new { folders }));
        });
        await using var client = Client(wire);
        var result = (await client.InspectNativeAsync(new(client.Authority, "project", "test", "/",
            recursive: true, environmentId: EnvironmentId, maximumDepth: depth))).Value;
        await Assert.That(result.IsComplete).IsEqualTo(!extraChild);
        await Assert.That(result.IncompleteReasons.Contains(InfisicalInventoryIncompleteReason.DepthLimit)).IsEqualTo(extraChild);
        await Assert.That(wire.Requests.Count).IsEqualTo((depth + 1) * 2);
    }

    [Test]
    [Arguments(1, 100, InfisicalInventoryIncompleteReason.FolderLimit)]
    [Arguments(100, 1, InfisicalInventoryIncompleteReason.RequestLimit)]
    public async Task AggregateFolderAndRequestLimitsDoNotPublishCompleteViews(int folders, int requests,
        InfisicalInventoryIncompleteReason expected)
    {
        using var wire = new Wire((request, _) => Task.FromResult(request.RequestUri!.AbsolutePath == "/api/v4/secrets"
            ? Json(new { secrets = new[] { Row() } }) : Json(new { folders = new[] { Folder("/child") } })));
        await using var client = Client(wire);
        var result = (await client.InspectNativeAsync(new(client.Authority, "project", "test", "/", recursive: true,
            environmentId: EnvironmentId, maximumFolders: folders, maximumRequests: requests))).Value;
        await Assert.That(result.IsComplete).IsFalse();
        await Assert.That(result.IncompleteReasons).Contains(expected);
        await Assert.That(result.Entries.Count).IsEqualTo(1);
        await Assert.That(wire.Requests.Count).IsEqualTo(requests == 1 ? 1 : 2);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ItemLimitIsSharedByDirectAndImportedCandidates(bool oneOver)
    {
        object[] imports = oneOver
            ? [new { environment = "upstream", secretPath = "/source", secrets = new[] { Row("/source", "upstream") } }] : [];
        using var wire = new Wire((_, _) => Task.FromResult(Json(new { secrets = new[] { Row() }, imports })));
        await using var client = Client(wire);
        var result = (await client.InspectNativeAsync(new(client.Authority, "project", "test", "/",
            includeImports: true, maximumItems: 1))).Value;
        await Assert.That(result.Entries.Count).IsEqualTo(1);
        await Assert.That(result.IsComplete).IsEqualTo(!oneOver);
        await Assert.That(result.IncompleteReasons.Contains(InfisicalInventoryIncompleteReason.ItemLimit)).IsEqualTo(oneOver);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DuplicateOrCyclicFolderIdentityFailsClosed(bool cycle)
    {
        using var wire = new Wire((request, _) => Task.FromResult(request.RequestUri!.AbsolutePath == "/api/v4/secrets"
            ? Json(new { secrets = Array.Empty<object>() })
            : Json(new
            {
                folders = cycle
                    ? new[] { Folder(QueryPath(request.RequestUri!) == "/" ? "/child" : "/child/child") }
                    : new[] { Folder("/child"), Folder("/child") }
            })));
        await using var client = Client(wire);
        await Assert.That((await client.InspectNativeAsync(Selection(client, true))).Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task FailureBodiesConsumeTheSameAggregateByteAllowance()
    {
        byte[] first = JsonSerializer.SerializeToUtf8Bytes(new { secrets = new[] { Row() }, ignored = new string('x', 700) });
        byte[] failure = JsonSerializer.SerializeToUtf8Bytes(new { message = new string('x', 600) });
        using var wire = new Wire((request, _) =>
        {
            bool success = request.RequestUri!.AbsolutePath == "/api/v4/secrets";
            return Task.FromResult(new HttpResponseMessage(success ? HttpStatusCode.OK : HttpStatusCode.Forbidden)
            { Content = new StreamContent(new MemoryStream(success ? first : failure)) });
        });
        await using var client = Client(wire);
        var result = (await client.InspectNativeAsync(new(client.Authority, "project", "test", "/", recursive: true,
            environmentId: EnvironmentId, maximumResponseBytes: first.Length + failure.Length - 1))).Value;
        await Assert.That(result.IsComplete).IsFalse();
        await Assert.That(result.IncompleteReasons).Contains(InfisicalInventoryIncompleteReason.ByteLimit);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task LateNoncooperativeChildCannotPublishAfterDeadlineOrCallerCancellation(bool callerCancellation)
    {
        var clock = new InfisicalTransportOwnershipTests.ShutdownClock();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        using var wire = new Wire(async (request, _) =>
        {
            if (request.RequestUri!.AbsolutePath == "/api/v4/secrets") return Json(new { secrets = new[] { Row() } });
            entered.SetResult();
            await release.Task;
            return Json(new { folders = Array.Empty<object>() });
        });
        await using var client = Client(wire, clock);
        Task<SecretOutcome<InfisicalInventory>> pending = client.InspectNativeAsync(new(client.Authority, "project", "test", "/",
            recursive: true, environmentId: EnvironmentId, timeout: TimeSpan.FromSeconds(2)), cancellation.Token).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        if (callerCancellation) await cancellation.CancelAsync();
        else clock.Advance(TimeSpan.FromSeconds(3));
        release.SetResult();
        if (callerCancellation)
            await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
        else
        {
            var result = await pending.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unavailable);
            await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.DeadlineExceeded);
        }
    }

    [Test]
    [Arguments(null)]
    [Arguments("/source%2fescape")]
    public async Task UnestablishedOrEscapedImportSourceNeverCreatesLocalTargets(string? source)
    {
        using var wire = new Wire((_, _) => Task.FromResult(Json(new
        {
            secrets = Array.Empty<object>(),
            imports = new[] { new { environment = "upstream", secretPath = source, secrets = new[] { Row("/source", "upstream") } } }
        })));
        await using var client = Client(wire);
        var result = await client.InspectNativeAsync(new(client.Authority, "project", "test", "/", includeImports: true));
        if (source is not null) await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        else
        {
            await Assert.That(result.Value.IsComplete).IsFalse();
            await Assert.That(result.Value.ImportGroups.Single().IsProvenanceEstablished).IsFalse();
            await Assert.That(result.Value.Entries.Single().Reference is null).IsTrue();
            await Assert.That(result.Value.Entries.Single().Revision is null).IsTrue();
        }
    }

    [Test]
    public async Task ContradictoryReturnedParentAndPathFailEvenWhenChildPathLooksCorrect()
    {
        using var wire = new Wire((request, _) =>
        {
            string path = QueryPath(request.RequestUri!);
            return Task.FromResult(request.RequestUri!.AbsolutePath == "/api/v4/secrets"
                ? Json(new { secrets = Array.Empty<object>() })
                : Json(new
                {
                    folders = new[] { path == "/" ? Folder("/child") :
                        Folder("/child/next", TagId, "next", EnvironmentId) }
                }));
        });
        await using var client = Client(wire);
        await Assert.That((await client.InspectNativeAsync(Selection(client, true))).Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task ReturnedEnvironmentCannotBeSubstitutedByCanonicalAncestry()
    {
        using var wire = new Wire((request, _) => Task.FromResult(request.RequestUri!.AbsolutePath == "/api/v4/secrets"
            ? Json(new { secrets = Array.Empty<object>() })
            : Json(new
            {
                folders = new[] { new { id = ChildId, envId = TagId, name = "child", path = "/child",
                    createdAt = "2026-11-01T00:00:00Z", updatedAt = "2026-11-01T00:00:00Z" } }
            })));
        await using var client = Client(wire);
        await Assert.That((await client.InspectNativeAsync(Selection(client, true))).Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task ExpiredCredentialDuringTraversalLeavesCoverageIncompleteWithoutChildDispatch()
    {
        int credentials = 0;
        using var wire = new Wire((_, _) => Task.FromResult(Json(new { secrets = new[] { Row() } })));
        await using var client = Client(wire, tokens: new SelectedTokens(() => new(
            SecretMaterial.FromText("fixture-token"), ++credentials == 1 ? null : DateTimeOffset.MinValue)));
        var result = (await client.InspectNativeAsync(Selection(client, true))).Value;
        await Assert.That(result.IsComplete).IsFalse();
        await Assert.That(result.IncompleteReasons).Contains(InfisicalInventoryIncompleteReason.FolderFailure);
        await Assert.That(result.Entries.Count).IsEqualTo(1);
        await Assert.That(wire.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task ReturnedManagedFlagIsPreservedAndMalformedTagsStayUnestablished()
    {
        var row = Row();
        row["isRotatedSecret"] = true;
        row["tags"] = new[] { new { id = "not-a-native-tag", name = "private-tag" } };
        row["updatedAt"] = "not-a-time";
        using var wire = new Wire((_, _) => Task.FromResult(Json(new { secrets = new[] { row } })));
        await using var client = Client(wire);
        var entry = (await client.InspectNativeAsync(Selection(client))).Value.Entries.Single();
        await Assert.That(entry.IsRotatedSecret).IsTrue();
        await Assert.That(entry.TagIds is null).IsTrue();
        await Assert.That(entry.ModifiedAt is null).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ExactFolderAndRequestLimitsCanStillEstablishAnEmptyTree(bool folderLimit)
    {
        using var wire = new Wire((request, _) => Task.FromResult(request.RequestUri!.AbsolutePath == "/api/v4/secrets"
            ? Json(new { secrets = Array.Empty<object>() }) : Json(new { folders = Array.Empty<object>() })));
        await using var client = Client(wire);
        var result = (await client.InspectNativeAsync(new(client.Authority, "project", "test", "/", recursive: true,
            environmentId: EnvironmentId, maximumFolders: folderLimit ? 1 : 100, maximumRequests: 2))).Value;
        await Assert.That(result.IsComplete).IsTrue();
        await Assert.That(result.Entries.Count).IsEqualTo(0);
    }

    [Test]
    public async Task MalformedSuccessBodyStillConsumesItsBytesBeforeFailure()
    {
        byte[] first = JsonSerializer.SerializeToUtf8Bytes(new { secrets = new[] { Row() }, discarded = new string('x', 700) });
        byte[] malformed = Encoding.UTF8.GetBytes(new string('x', 300));
        using var finalBody = new CountedBody(malformed);
        using var wire = new Wire((request, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(request.RequestUri!.AbsolutePath == "/api/v4/secrets"
                ? new MemoryStream(first) : finalBody)
        }));
        await using var client = Client(wire);
        var result = (await client.InspectNativeAsync(new(client.Authority, "project", "test", "/", recursive: true,
            environmentId: EnvironmentId, maximumResponseBytes: first.Length + 100))).Value;
        await Assert.That(result.IncompleteReasons).Contains(InfisicalInventoryIncompleteReason.ByteLimit);
        await Assert.That(finalBody.Consumed).IsEqualTo(101);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RootFailureContextSurvivesCommonAndNativeProjection(bool native)
    {
        using var wire = new Wire((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent("""{"statusCode":404,"reqId":"private-request","message":"private-prose"}""")
        }));
        await using var client = Client(wire);
        if (native)
        {
            var result = await client.InspectNativeAsync(Selection(client));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
            await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.NotFoundOrInaccessible);
            await Assert.That(result.CorrelationId!.Reveal()).IsEqualTo("private-request");
        }
        else
        {
            var result = await client.InspectAsync(new InfisicalInventoryScope(client.Authority, "project", "test", "/"));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
            await Assert.That(result.Reason).IsEqualTo(SecretFailureReason.NotFoundOrInaccessible);
            await Assert.That(result.CorrelationId!.Reveal()).IsEqualTo("private-request");
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task AdvertisedOversizedBodyMarksByteLimitWithoutClaimingCoverage(bool failure)
    {
        using var body = new CountedBody([]);
        using var wire = new Wire((_, _) =>
        {
            var response = new HttpResponseMessage(failure ? HttpStatusCode.Forbidden : HttpStatusCode.OK)
            { Content = new StreamContent(body) };
            response.Content.Headers.ContentLength = 2 * 1024 * 1024;
            return Task.FromResult(response);
        });
        await using var client = Client(wire);
        var result = (await client.InspectNativeAsync(Selection(client))).Value;
        await Assert.That(result.IsComplete).IsFalse();
        await Assert.That(result.IncompleteReasons).Contains(InfisicalInventoryIncompleteReason.ByteLimit);
        await Assert.That(result.Entries.Count).IsEqualTo(0);
        await Assert.That(body.Consumed).IsEqualTo(0);
    }

    [Test]
    public async Task MissingScopeFieldCannotMaskALaterContradictoryCoordinate()
    {
        var row = Row();
        row["workspace"] = null;
        row["environment"] = "foreign";
        using var wire = new Wire((_, _) => Task.FromResult(Json(new { secrets = new[] { row } })));
        await using var client = Client(wire);
        await Assert.That((await client.InspectNativeAsync(Selection(client))).Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ReturnedChildCannotExceedNativeFolderPathBound(bool parentOnly)
    {
        string longName = new('a', 1024);
        using var wire = new Wire((request, _) =>
        {
            if (request.RequestUri!.AbsolutePath == "/api/v4/secrets")
                return Task.FromResult(Json(new { secrets = Array.Empty<object>() }));
            string path = QueryPath(request.RequestUri);
            object child = parentOnly && path == "/" ? Folder("/child") :
                parentOnly ? Folder(null, TagId, longName, ChildId) : Folder("/" + longName, ChildId, longName);
            return Task.FromResult(Json(new { folders = new[] { child } }));
        });
        await using var client = Client(wire);
        await Assert.That((await client.InspectNativeAsync(Selection(client, true))).Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    [Arguments("project")]
    [Arguments("environment")]
    [Arguments("folder")]
    public async Task CommonScopeRejectsOversizedCoordinatesAtConstruction(string field)
    {
        string oversized = new('a', 1025);
        await Assert.That(() => new InfisicalInventoryScope(new(),
            field == "project" ? oversized : "project",
            field == "environment" ? oversized : "test",
            field == "folder" ? "/" + oversized : "/")).Throws<ArgumentException>();
    }

    [Test]
    public async Task CommonScopeRejectsNoncanonicalPathsAtConstruction()
    {
        await Assert.That(() => new InfisicalInventoryScope(new(), "project", "test", "/a%2fb")).Throws<ArgumentException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RootRejectionSurvivesDetailDeadlineButCallerCancellationPropagates(bool callerCancellation)
    {
        var clock = new InfisicalTransportOwnershipTests.ShutdownClock();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        using var wire = new Wire((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden)
        { Content = new StreamContent(new StalledFailureBody(entered)) }));
        await using var client = Client(wire, clock);
        Task<SecretOutcome<InfisicalInventory>> pending = client.InspectNativeAsync(new(client.Authority,
            "project", "test", "/", timeout: TimeSpan.FromSeconds(2)), cancellation.Token).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        if (callerCancellation) cancellation.Cancel();
        else clock.Advance(TimeSpan.FromSeconds(3));

        if (callerCancellation)
            await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(5))).Throws<OperationCanceledException>();
        else
            await Assert.That((await pending.WaitAsync(TimeSpan.FromSeconds(5))).Status).IsEqualTo(SecretStatus.Denied);
    }

    private sealed class StalledFailureBody(TaskCompletionSource entered) : MemoryStream
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            entered.TrySetResult();
            await new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously).Task.WaitAsync(cancellationToken);
            return 0;
        }
    }

    private sealed class CountedBody(byte[] bytes) : MemoryStream(bytes)
    {
        internal int Consumed { get; private set; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int read = await base.ReadAsync(buffer, cancellationToken);
            Consumed += read;
            return read;
        }
    }

    private sealed class SelectedTokens(Func<InfisicalAccessToken> create) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(create()));
    }

    private static string QueryPath(Uri uri) => Uri.UnescapeDataString(uri.Query.TrimStart('?').Split('&')
        .Single(pair => pair.StartsWith(uri.AbsolutePath == "/api/v4/secrets" ? "secretPath=" : "path=", StringComparison.Ordinal))
        .Split('=', 2)[1]);

    private static InfisicalInventorySelection Selection(InfisicalClient client, bool recursive = false) =>
        new(client.Authority, "project", "test", "/", recursive, recursive ? EnvironmentId : null);

    private static Dictionary<string, object?> Row(string path = "/", string environment = "test") => new()
    {
        ["id"] = "resource",
        ["workspace"] = "project",
        ["environment"] = environment,
        ["secretPath"] = path,
        ["type"] = "shared",
        ["secretKey"] = "key",
        ["version"] = 1,
        ["secretValue"] = "private-value",
        ["secretValueHidden"] = false,
        ["secretComment"] = "private-comment",
        ["isRotatedSecret"] = false,
        ["updatedAt"] = "2026-11-01T00:00:00Z",
        ["tags"] = new[] { new { id = TagId, name = "private-tag" } }
    };

    private static object Folder(string? path, string id = ChildId, string name = "child", string? parentId = null) =>
        new { id, name, envId = EnvironmentId, path, parentId, createdAt = "2026-11-01T00:00:00Z", updatedAt = "2026-11-01T00:00:00Z" };

    private static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK)
    { Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json") };

    private static InfisicalClient Client(Wire wire, TimeProvider? time = null, IInfisicalTokenSource? tokens = null) =>
        new(new Uri("https://inventory.test"), tokens ?? new Tokens(),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) }, time);

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("fixture-token"))));
    }

    private sealed class Wire(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        internal List<Uri> Requests { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!);
            return send(request, cancellationToken);
        }
    }
}
