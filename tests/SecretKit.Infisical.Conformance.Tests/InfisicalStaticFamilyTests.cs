using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalStaticFamilyTests
{
    private const string CreateMember = "SecretKit.Infisical.InfisicalClient.CreateAsync(SecretKit.Core.SecretReference,SecretKit.Core.SecretMaterial,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)";
    private const string ReadMember = "SecretKit.Infisical.InfisicalClient.ReadAsync(SecretKit.Core.SecretReference,System.Threading.CancellationToken)";
    private const string EnvironmentId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    [Test]
    public async Task MissingInputFailsEveryRegisteredAdmissionCase()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        using JsonDocument inventory = JsonDocument.Parse(await File.ReadAllTextAsync(
            Path.Combine(root, "docs/internal/releases/admission/infisical.json")));
        string[] methods = ["ReadAsync", "InspectAsync", "CreateAsync", "UpdateValueAsync",
            "CreateSecretsAsync", "UpdateSecretsAsync", "DeleteSecretsAsync"];
        NativeCaseDefinition[] expected = inventory.RootElement.GetProperty("operations").EnumerateArray()
            .Where(o => methods.Any(m => o.GetProperty("id").GetString() == "i.runtime.InfisicalClient." + m))
            .SelectMany(o => o.GetProperty("variants").EnumerateArray().SelectMany(v =>
                o.GetProperty("requiredCases").EnumerateArray().Select(c => new NativeCaseDefinition(
                    new("Infisical", o.GetProperty("id").GetString()!, v.GetString()!, "local", c.GetString()!),
                    o.GetProperty("member").GetString()!)))).ToArray();
        using NativeEnvironment env = Environment(new Uri("http://127.0.0.1:1"), new { });
        var registry = new NativeCaseRegistry();
        InfisicalStaticFamilies.Register(registry, env, expected);
        IReadOnlyList<NativeCaseResult> results = await NativeCaseRunner.RunAsync(registry, expected, CancellationToken.None);
        await Assert.That(results.Count).IsEqualTo(350);
        await Assert.That(results.All(r => !r.Passed && r.ReasonCode == "missing-input")).IsTrue();
    }

    [Test]
    [Arguments("good", "observed")]
    [Arguments("denied", "observed")]
    [Arguments("bad-effect", "effect-mismatch")]
    [Arguments("cleanup", "cleanup-incomplete")]
    [Arguments("observer", "observer-unavailable")]
    [Arguments("rights", "missing-prerequisite")]
    [Arguments("lost", "observed")]
    [Arguments("cancel", "observed")]
    public async Task StaticMutationRequiresIndependentStateAndOwnedCleanup(string mode, string reason)
    {
        await using var backend = new OfflineBackend(mode);
        string caseName = mode == "denied" ? "denied-authority" :
            mode == "lost" ? "lost-response-no-replay" : mode == "cancel" ?
                "cancellation-boundary" : "independent-effect";
        var definition = new NativeCaseDefinition(new("Infisical", "i.runtime.InfisicalClient.CreateAsync",
            "shared.raw.unversioned.Applied", "local", caseName), CreateMember);
        var input = new InfisicalStaticChangesEffects.StaticChangeInput(
            Fixture(), "TARGET", "new",
            mode == "denied" ? SecretStatus.Denied : SecretStatus.Success,
            mode == "denied" ? DispatchEvidence.Rejected : mode is "lost" or "cancel" ?
                DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied,
            InfisicalChangeDisposition.Applied,
            [new("TARGET", mode is "denied" or "cancel" ? SecretStatus.Absent : SecretStatus.Success,
                mode is "denied" or "cancel" ? null : "new", mode is "denied" or "cancel" ? null : 1)]);
        using NativeEnvironment env = Environment(backend.Origin,
            Family("C08-IR-InfisicalStaticChanges", definition, input));
        NativeCaseResult row = await RunAsync(env, definition);
        await Assert.That(row.ReasonCode).IsEqualTo(reason);
        await Assert.That(row.Passed).IsEqualTo(reason == "observed");
        if (mode != "cleanup") await Assert.That(backend.OwnedFolderCount).IsEqualTo(0);
        if (mode == "lost") await Assert.That(backend.RuntimeMutationCount).IsEqualTo(1);
        if (mode == "cancel") await Assert.That(backend.RuntimeMutationCount).IsEqualTo(0);
    }

    [Test]
    public async Task ReadCancellationSubscribesBeforeSendAndStillObservesState()
    {
        await using var backend = new OfflineBackend("good");
        var definition = new NativeCaseDefinition(new("Infisical", "i.runtime.InfisicalClient.ReadAsync",
            "latest.Raw.direct", "local", "cancellation-boundary"), ReadMember);
        var input = new InfisicalClientEffects.StaticReadInput(
            Fixture(new StaticSeed("TARGET", "seed")),
            "TARGET", null, null, [], SecretStatus.Success, [new("TARGET", SecretStatus.Success, "seed", 1)]);
        using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-InfisicalClient", definition, input));
        NativeCaseResult row = await RunAsync(env, definition);
        await Assert.That(row.ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.OwnedFolderCount).IsEqualTo(0);
    }

    [Test]
    public async Task WrongFullMemberFailsBeforeFixtureCreation()
    {
        await using var backend = new OfflineBackend("good");
        var definition = new NativeCaseDefinition(new("Infisical", "i.runtime.InfisicalClient.ReadAsync",
            "latest.Raw.direct", "local", "selected-contract"), ReadMember + ".wrong");
        using NativeEnvironment env = Environment(backend.Origin, new { });
        NativeCaseResult row = await RunAsync(env, definition);
        await Assert.That(row.ReasonCode).IsEqualTo("contract-mismatch");
        await Assert.That(backend.OwnedFolderCount).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task BulkCreationNeedsObserverAndDeniedIdentity(bool denied)
    {
        await using var backend = new OfflineBackend("good");
        var definition = new NativeCaseDefinition(new("Infisical", "i.runtime.InfisicalClient.CreateSecretsAsync",
            "type.Shared", "local", denied ? "denied-authority" : "independent-effect"),
            "SecretKit.Infisical.InfisicalClient.CreateSecretsAsync(SecretKit.Core.SecretReference,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.InfisicalBulkSecret>,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)");
        var input = new NativeBulkEffects.BulkInput(Fixture(),
            [new("TARGET", "new", null, null, null, null, false, null, null, null, false, false, null,
                InfisicalSecretType.Shared)], InfisicalBulkUpdateMode.FailOnNotFound,
            denied ? SecretStatus.Denied : SecretStatus.Success,
            denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied, true, false,
            [DispatchEvidence.Applied], [new("TARGET", denied ? SecretStatus.Absent : SecretStatus.Success,
                denied ? null : "new", denied ? null : 1)], []);
        using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-NativeBulk", definition, input));
        NativeCaseResult row = await RunAsync(env, definition);
        await Assert.That(row.Passed).IsTrue();
        await Assert.That(backend.OwnedFolderCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("UpdateSecretsAsync")]
    [Arguments("DeleteSecretsAsync")]
    public async Task BulkUpdateAndDeletionObserveDownstreamState(string method)
    {
        await using var backend = new OfflineBackend("good");
        bool delete = method == "DeleteSecretsAsync";
        var definition = new NativeCaseDefinition(new("Infisical", "i.runtime.InfisicalClient." + method,
            "type.Shared", "local", "independent-effect"),
            "SecretKit.Infisical.InfisicalClient." + method +
            "(SecretKit.Core.SecretReference,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.InfisicalBulkSecret>,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt," +
            (delete ? "" : "SecretKit.Infisical.InfisicalBulkUpdateMode,") + "System.Threading.CancellationToken)");
        var input = new NativeBulkEffects.BulkInput(
            Fixture(new StaticSeed("TARGET", "old")),
            [new("TARGET", delete ? null : "new", null, null, null, null, false, null, null, null,
                false, false, null, InfisicalSecretType.Shared)], InfisicalBulkUpdateMode.FailOnNotFound,
            SecretStatus.Success, DispatchEvidence.Applied, true, false, [DispatchEvidence.Applied],
            [new("TARGET", delete ? SecretStatus.Absent : SecretStatus.Success, delete ? null : "new",
                delete ? null : 2)], []);
        using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-NativeBulk", definition, input));
        NativeCaseResult row = await RunAsync(env, definition);
        await Assert.That(row.ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.OwnedFolderCount).IsEqualTo(0);
    }

    [Test]
    public async Task BulkMetadataCannotPassFromAcknowledgementAndMaterialOnly()
    {
        await using var backend = new OfflineBackend("good");
        var definition = new NativeCaseDefinition(new("Infisical", "i.runtime.InfisicalClient.CreateSecretsAsync",
            "metadata.encrypted", "local", "independent-effect"),
            "SecretKit.Infisical.InfisicalClient.CreateSecretsAsync(SecretKit.Core.SecretReference,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.InfisicalBulkSecret>,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)");
        NativeBulkEffects.BulkMetadataInput[] metadata = [new("annotation", "protected", true)];
        var input = new NativeBulkEffects.BulkInput(Fixture(),
            [new("TARGET", "new", null, null, metadata, null, false, null, null, null, false, false, null,
                InfisicalSecretType.Shared)], InfisicalBulkUpdateMode.FailOnNotFound, SecretStatus.Success,
            DispatchEvidence.Applied, true, false, [DispatchEvidence.Applied],
            [new("TARGET", SecretStatus.Success, "new", 1)],
            [new("TARGET", null, metadata, [], [], null, null, null)]);
        using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-NativeBulk", definition, input));
        NativeCaseResult row = await RunAsync(env, definition);
        await Assert.That(row.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(backend.RuntimeMutationCount).IsEqualTo(1);
        await Assert.That(backend.OwnedFolderCount).IsEqualTo(0);
    }

    [Test]
    public async Task StaticUpdateObservesNewMaterialRatherThanReturnedVersion()
    {
        await using var backend = new OfflineBackend("good");
        var definition = new NativeCaseDefinition(new("Infisical", "i.runtime.InfisicalClient.UpdateValueAsync",
            "shared.raw.unversioned.Applied", "local", "independent-effect"),
            "SecretKit.Infisical.InfisicalClient.UpdateValueAsync(SecretKit.Core.SecretReference,SecretKit.Core.SecretMaterial,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)");
        var input = new InfisicalStaticChangesEffects.StaticChangeInput(
            Fixture(new StaticSeed("TARGET", "old")),
            "TARGET", "new", SecretStatus.Success, DispatchEvidence.Applied, InfisicalChangeDisposition.Applied,
            [new("TARGET", SecretStatus.Success, "new", 2)]);
        using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-InfisicalStaticChanges", definition, input));
        await Assert.That((await RunAsync(env, definition)).ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.OwnedFolderCount).IsEqualTo(0);
    }

    [Test]
    public async Task PendingApprovalCannotPassFromDispositionAndAbsentMaterial()
    {
        await using var backend = new OfflineBackend("approval");
        var definition = new NativeCaseDefinition(new("Infisical", "i.runtime.InfisicalClient.CreateAsync",
            "shared.raw.unversioned.SubmittedForApproval", "local", "independent-effect"), CreateMember);
        var input = new InfisicalStaticChangesEffects.StaticChangeInput(
            Fixture(), "TARGET", "new",
            SecretStatus.Success, DispatchEvidence.Pending, InfisicalChangeDisposition.SubmittedForApproval,
            [new("TARGET", SecretStatus.Absent, null, null)]);
        using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-InfisicalStaticChanges", definition, input));
        await Assert.That((await RunAsync(env, definition)).ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(backend.OwnedFolderCount).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task InventoryRequiresFullIndependentStateAndDownstreamAccess(bool budget)
    {
        await using var backend = new OfflineBackend("good");
        var definition = new NativeCaseDefinition(new("Infisical", "i.runtime.InfisicalClient.InspectAsync",
            budget ? "direct-folder.metadata.item-budget" : "direct-folder.metadata.complete",
            "local", "independent-effect"),
            "SecretKit.Infisical.InfisicalClient.InspectAsync(SecretKit.Core.SecretInventoryScope,System.Threading.CancellationToken)");
        var input = new InfisicalClientEffects.StaticInventoryInput(
            Fixture(new("FIRST", "one"), new("SECOND", "two")),
            budget ? 1 : 2, SecretStatus.Success, !budget, budget ? ["FIRST"] : ["FIRST", "SECOND"],
            [new("FIRST", SecretStatus.Success, "one", 1), new("SECOND", SecretStatus.Success, "two", 1)]);
        using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-InfisicalClient", definition, input));
        await Assert.That((await RunAsync(env, definition)).ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.OwnedFolderCount).IsEqualTo(0);
    }

    private static StaticFixtureInput Fixture(params StaticSeed[] seeds) =>
        new("project", "env", EnvironmentId, "/owned", seeds, StaticApiRevision.SecretsV4FoldersV2);

    private static async Task<NativeCaseResult> RunAsync(NativeEnvironment env, NativeCaseDefinition definition)
    {
        var registry = new NativeCaseRegistry();
        InfisicalStaticFamilies.Register(registry, env, [definition]);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }

    private static object Family<T>(string name, NativeCaseDefinition definition, T input) =>
        new Dictionary<string, object>
        {
            [name] = new
            {
                scopes = new Dictionary<string, object>
                {
                    [definition.Key.Scope] = new Dictionary<string, object>
                    {
                        [definition.Key.Operation] = new Dictionary<string, object>
                        {
                            [definition.Key.Variant] = new Dictionary<string, T> { [definition.Key.Case] = input }
                        }
                    }
                }
            }
        };

    private static NativeEnvironment Environment(Uri origin, object families)
    {
        JsonElement settings = JsonSerializer.SerializeToElement(new
        {
            origin = origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families
        }, new JsonSerializerOptions(InfisicalStaticFamilies.Options) { IgnoreReadOnlyProperties = false });
        return NativeEnvironment.Create(settings);
    }

    // A stateful local wire fixture, never conformance evidence. Real public SDK clients
    // use five separately selected credentials against this per-test ephemeral listener.
    private sealed class OfflineBackend : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly ConcurrentBag<Task> connections = [];
        private readonly Dictionary<string, (string Name, string Path)> folders = [];
        private readonly Dictionary<(string Folder, string Key), (string Value, int Version)> secrets = [];
        private readonly Task accept;
        private readonly string mode;
        private int mutationCount;
        internal int RuntimeMutationCount => mutationCount;
        internal int OwnedFolderCount { get { lock (folders) return folders.Count; } }
        internal Uri Origin { get; }

        internal OfflineBackend(string mode)
        {
            this.mode = mode;
            listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
            accept = AcceptAsync();
        }

        private async Task AcceptAsync()
        {
            try
            {
                while (!shutdown.IsCancellationRequested)
                {
                    TcpClient socket = await listener.AcceptTcpClientAsync(shutdown.Token);
                    connections.Add(ServeAsync(socket));
                }
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        }

        private async Task ServeAsync(TcpClient socket)
        {
            using (socket)
            {
                try
                {
                    NetworkStream stream = socket.GetStream();
                    var headers = new List<byte>();
                    byte[] one = new byte[1];
                    while (headers.Count < 32768)
                    {
                        if (await stream.ReadAsync(one, shutdown.Token) == 0) return;
                        headers.Add(one[0]);
                        if (headers.Count >= 4 && headers.TakeLast(4).SequenceEqual("\r\n\r\n"u8.ToArray())) break;
                    }
                    string[] lines = Encoding.ASCII.GetString(headers.ToArray()).Split("\r\n");
                    string[] request = lines[0].Split(' ');
                    string role = lines.Single(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))
                        .Split(' ').Last();
                    int length = int.Parse(lines.FirstOrDefault(l =>
                        l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?.Split(':')[1] ?? "0");
                    if (length is < 0 or > 1024 * 1024) throw new InvalidOperationException("fixture-input");
                    byte[] body = new byte[length];
                    await stream.ReadExactlyAsync(body, shutdown.Token);
                    using JsonDocument document = JsonDocument.Parse(length == 0 ? "{}"u8.ToArray() : body);
                    var uri = new Uri(Origin, request[1]);
                    (int status, object payload) result;
                    lock (folders) result = Handle(request[0], uri, role, document.RootElement);
                    byte[] response = JsonSerializer.SerializeToUtf8Bytes(result.payload);
                    byte[] responseHeaders = Encoding.ASCII.GetBytes($"HTTP/1.1 {result.status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n");
                    await stream.WriteAsync(responseHeaders, shutdown.Token);
                    if (mode == "lost" && role == "runtime" && request[0] == "POST" &&
                        uri.AbsolutePath.StartsWith("/api/v4/secrets/", StringComparison.Ordinal))
                    {
                        // Headers are observable, but the body is withheld until fixture shutdown.
                        // Client cancellation is driven by the subscribed headers event, not time.
                        var released = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                        await released.Task.WaitAsync(shutdown.Token);
                    }
                    await stream.WriteAsync(response, shutdown.Token);
                }
                catch (IOException) { /* The selected cancellation closes its real socket. */ }
                catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            }
        }

        private (int, object) Handle(string method, Uri uri, string role, JsonElement body)
        {
            if (role == "denied" || mode == "rights" && role == "setup") return (403, new { });
            if (mode == "observer" && role == "observer" &&
                uri.AbsolutePath.StartsWith("/api/v4/secrets", StringComparison.Ordinal)) return (403, new { });
            string path = uri.AbsolutePath;
            if (path.StartsWith("/api/v2/folders", StringComparison.Ordinal))
            {
                if (method == "POST")
                {
                    string id = Guid.NewGuid().ToString();
                    string name = body.GetProperty("name").GetString()!;
                    folders.Add(id, (name, body.GetProperty("path").GetString() + "/" + name));
                    return (200, new { folder = Folder(id) });
                }
                if (path == "/api/v2/folders")
                    return (200, new { folders = folders.Keys.Select(Folder).ToArray() });
                string selector = path.Split('/').Last();
                string? found = folders.Keys.FirstOrDefault(id => id == selector || folders[id].Name == selector);
                if (found is null) return (404, new { });
                object folder = Folder(found);
                if (method == "DELETE")
                {
                    if (mode == "cleanup") return (403, new { });
                    string folderPath = folders[found].Path;
                    folders.Remove(found);
                    foreach (var key in secrets.Keys.Where(k => k.Folder == folderPath).ToArray()) secrets.Remove(key);
                }
                return (200, new { folder });
            }
            if (path.StartsWith("/api/v4/secrets", StringComparison.Ordinal))
            {
                string key = Uri.UnescapeDataString(path.Split('/').Last());
                if (method == "GET")
                {
                    string folder = Query(uri, "secretPath");
                    if (path == "/api/v4/secrets")
                        return (200, new
                        {
                            secrets = secrets.Where(s => s.Key.Folder == folder)
                                .Select(s => new { secretKey = s.Key.Key, version = s.Value.Version }).ToArray()
                        });
                    return secrets.TryGetValue((folder, key), out var value) ?
                        (200, new
                        {
                            secret = new
                            {
                                secretKey = key,
                                secretValue = value.Value,
                                secretValueHidden = false,
                                version = value.Version
                            }
                        }) : (404, new { });
                }
                string selectedFolder = body.GetProperty("secretPath").GetString()!;
                if (mode == "approval" && role == "runtime")
                    return (200, new
                    {
                        approval = new
                        {
                            id = Guid.NewGuid(),
                            hasMerged = false
                        }
                    });
                JsonElement[] inputs = path.EndsWith("/batch", StringComparison.Ordinal) ?
                    body.GetProperty("secrets").EnumerateArray().ToArray() : [body];
                var observed = new List<object>();
                foreach (JsonElement input in inputs)
                {
                    string selectedKey = inputs.Length == 1 && !path.EndsWith("/batch", StringComparison.Ordinal) ?
                        key : input.GetProperty("secretKey").GetString()!;
                    var coordinate = (selectedFolder, selectedKey);
                    int version = secrets.TryGetValue(coordinate, out var old) ? old.Version + 1 : 1;
                    if (method == "DELETE") secrets.Remove(coordinate);
                    else
                    {
                        string value = mode == "bad-effect" && role == "runtime" ? "wrong" :
                            input.TryGetProperty("secretValue", out JsonElement material) ? material.GetString()! : old.Value;
                        secrets[coordinate] = (value, version);
                    }
                    if (role == "runtime") mutationCount++;
                    observed.Add(new
                    {
                        secretKey = selectedKey,
                        workspace = "project",
                        environment = "env",
                        version,
                        type = "shared"
                    });
                }
                return path.EndsWith("/batch", StringComparison.Ordinal) ?
                    (200, new { secrets = observed }) : (200, new { secret = observed.Single() });
            }
            return (404, new { });
        }

        private object Folder(string id) => new
        {
            id,
            envId = EnvironmentId,
            name = folders[id].Name,
            path = folders[id].Path,
            projectId = "project",
            environment = new { envSlug = "env" },
            createdAt = "2026-10-12T00:00:00Z",
            updatedAt = "2026-10-12T00:00:00Z"
        };

        private static string Query(Uri uri, string key) => uri.Query.TrimStart('?').Split('&')
            .Select(p => p.Split('=', 2)).Where(p => p.Length == 2 && p[0] == key)
            .Select(p => Uri.UnescapeDataString(p[1])).Single();

        public async ValueTask DisposeAsync()
        {
            await shutdown.CancelAsync();
            try { await accept; }
            finally { listener.Stop(); }
            await Task.WhenAll(connections);
            shutdown.Dispose();
        }
    }
}
