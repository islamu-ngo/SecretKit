using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.LiveProvisioner;

namespace SecretKit.Consumer.Tests;

public sealed class LiveProvisionerTests
{
    [Test]
    [Arguments("http://example.test")]
    [Arguments("https://example.test/subpath")]
    [Arguments("invalid")]
    public async Task LiveProvisionerRejectsInvalidRemoteOriginWithoutDisclosingInput(string origin)
    {
        string input = EnvironmentText(origin);
        var failure = await Assert.That(() => LiveEnvConfig.Parse(input, "/fixture", LiveTarget.Remote))
            .Throws<ProvisioningException>();
        await Assert.That(failure!.Message).DoesNotContain("test-sensitive");
        await Assert.That(failure.Message).DoesNotContain(origin);
    }

    [Test]
    public async Task LiveProvisionerRejectsDuplicateCredentialsAndRedactsValidConfiguration()
    {
        string input = EnvironmentText("https://example.test");
        using var config = LiveEnvConfig.Parse(input, "/fixture", LiveTarget.Remote);
        await Assert.That(config.ToString()).DoesNotContain("test-sensitive");
        var failure = await Assert.That(() => LiveEnvConfig.Parse(
            input + "\nINFISICAL_REMOTE_AUTOMATION_CLIENT_SECRET=duplicate-sensitive", "/fixture", LiveTarget.Remote))
            .Throws<ProvisioningException>();
        await Assert.That(failure!.Message).DoesNotContain("duplicate-sensitive");
    }

    [Test]
    public async Task LiveProvisionerCleanupPreviewsAndThenDeletesOnlyOwnedProjects()
    {
        using var fixture = new TemporaryClone();
        fixture.WriteEnv(EnvironmentText("https://example.test") + Scope + $"\nINFISICAL_REMOTE_PROJECT_A_ID={Id(1)}");
        using var config = LiveEnvConfig.Load(fixture.Checkout);
        using var wire = new ProviderWire();
        wire.Projects.Add("sdk-live-a", Id(1));
        wire.Projects.Add("sdk-conformance-old", Id(2));
        wire.Projects.Add("sdk-live", Id(3));
        wire.Projects.Add("business", Id(4));
        using var pipeline = new HttpClient(wire);
        var cleaner = new ResourceCleaner(pipeline);
        await Assert.That(await cleaner.CleanAsync(config, null, null, false, default)).IsEqualTo(2);
        await Assert.That(wire.Projects.Count).IsEqualTo(4);
        await Assert.That(() => cleaner.CleanAsync(config, "business", null, false, default)).Throws<ProvisioningException>();
        await Assert.That(() => cleaner.CleanAsync(config, "sdk-live-a", null, true, default)).Throws<ProvisioningException>();
        await Assert.That(() => cleaner.CleanAsync(config, null, null, true, default)).Throws<ProvisioningException>();
        await Assert.That(() => cleaner.CleanAsync(config, null, Id(4), true, default)).Throws<ProvisioningException>();
        await Assert.That(await cleaner.CleanAsync(config, null, Id(1), true, default)).IsEqualTo(1);
        await Assert.That(string.Join(",", wire.Projects.Keys.Order())).IsEqualTo("business,sdk-conformance-old,sdk-live");
        using var reloaded = LiveEnvConfig.Load(fixture.Checkout);
        await Assert.That(reloaded.Pin("PROJECT_A_ID")).IsNull();
    }

    [Test]
    [Arguments(400)]
    [Arguments(403)]
    public async Task LiveProvisionerDoesNotTurnPlanErrorsOrIncompleteInventoryIntoSuccess(int code)
    {
        using var config = LiveEnvConfig.Parse(EnvironmentText("https://example.test"), "/fixture");
        using var wire = new ProviderWire { Status = code, ProjectStatus = code };
        using var pipeline = new HttpClient(wire);
        using var output = new StringWriter();
        var status = await Assert.That(() => ProviderStatus.ReportAsync(config, output, default, pipeline))
            .Throws<ProvisioningException>();
        await Assert.That(status!.Message).Contains($"HTTP {code}").And.Contains("plan/edition").And.DoesNotContain("response-private");
        async Task Reconcile()
        {
            using var result = await new FixtureReconciler(pipeline).ReconcileAsync(config, default, issueCredentials: false);
        }
        var outcome = await Assert.That(Reconcile)
            .Throws<ProvisioningException>();
        await Assert.That(outcome!.Message).Contains(code == 400 ? "Invalid" : "Denied").And.Contains("plan/edition");
        wire.ProjectStatus = 200;
        wire.IncompleteProjects = true;
        var incomplete = await Assert.That(Reconcile)
            .Throws<ProvisioningException>();
        await Assert.That(incomplete!.Message).Contains("Incomplete");
        await Assert.That(wire.Projects.Count).IsEqualTo(0);
    }

    [Test]
    public async Task LiveProvisionerReportsHealthWithoutInventingAnEdition()
    {
        using var config = LiveEnvConfig.Parse(EnvironmentText("https://example.test"), "/fixture");
        using var pipeline = new HttpClient(new ProviderWire());
        using var output = new StringWriter();
        await ProviderStatus.ReportAsync(config, output, default, pipeline);
        await Assert.That(output.ToString()).Contains("HTTP 200").And.Contains("unverified").And.DoesNotContain("response-private");
    }

    [Test]
    public async Task LiveProvisionerDoesNotSendAutomationCredentialsWhenLocalOwnershipFails()
    {
        using var config = LiveEnvConfig.Parse(EnvironmentText("http://127.0.0.1:18080")
            .Replace("remote", "local", StringComparison.Ordinal).Replace("REMOTE", "LOCAL", StringComparison.Ordinal) +
            "\nINFISICAL_LOCAL_OWNER=secretkit-sdk-01234567", "/fixture");
        using var wire = new ProviderWire();
        using var pipeline = new HttpClient(wire);
        async Task Open()
        {
            using var session = await ProvisioningSession.OpenAsync(config, pipeline, default,
                (_, _, _, _) => throw new ProvisioningException("Sandbox mismatch."));
        }
        await Assert.That(Open).Throws<ProvisioningException>();
        await Assert.That(wire.Authentications).IsEqualTo(0);
    }

    [Test]
    public async Task LiveProvisionerUsesTheCommonRootAndRefusesLinkedEnvFiles()
    {
        using var fixture = new TemporaryClone();
        await Assert.That(RepositoryEnvironment.FindRoot(fixture.Checkout)).IsEqualTo(fixture.Root);
        string path = Path.Combine(fixture.Root, ".env");
        File.CreateSymbolicLink(path, Path.Combine(fixture.Root, "missing-env-target"));
        var failure = await Assert.That(() => LiveEnvConfig.Load(fixture.Checkout, LiveTarget.Remote))
            .Throws<ProvisioningException>();
        await Assert.That(failure!.Message).Contains("symbolic-link");
    }

    private sealed class TemporaryClone : IDisposable
    {
        internal string Root { get; } = Directory.CreateTempSubdirectory("secretkit-live-config-").FullName;
        internal string Checkout => Path.Combine(Root, ".worktrees", "fixture");
        internal string EnvPath => Path.Combine(Root, ".env");

        internal TemporaryClone()
        {
            // Minimal Git metadata synthesized in an isolated fixture; no worktree is created using Git.
            string common = Path.Combine(Root, ".git");
            string metadata = Path.Combine(common, "worktrees", "fixture");
            Directory.CreateDirectory(Path.Combine(common, "objects"));
            Directory.CreateDirectory(Path.Combine(common, "refs"));
            Directory.CreateDirectory(metadata);
            Directory.CreateDirectory(Checkout);
            File.WriteAllText(Path.Combine(Root, "SecretKit.slnx"), "<Solution />");
            File.WriteAllText(Path.Combine(common, "HEAD"), "ref: refs/heads/main\n");
            File.WriteAllText(Path.Combine(metadata, "HEAD"), "ref: refs/heads/fixture\n");
            File.WriteAllText(Path.Combine(metadata, "commondir"), "../..\n");
            File.WriteAllText(Path.Combine(Checkout, ".git"), $"gitdir: {metadata}\n");
        }

        public void Dispose() => Directory.Delete(Root, recursive: true);

        internal void WriteEnv(string text)
        {
            if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
            using var file = new FileStream(EnvPath, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
            });
            using var writer = new StreamWriter(file);
            writer.Write(text);
        }
    }

    private static string Id(int index) => $"11111111-0000-4000-8000-{index:D12}";
    private static string Scope => $"\nINFISICAL_REMOTE_ENROLLMENT_ORIGIN=https://example.test/\nINFISICAL_REMOTE_ENROLLMENT_ORGANIZATION_ID={Id(100)}";

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task LiveProvisionerRefusesUnpinnedIdentityOrProjectCollisionBeforeMutation(bool identity)
    {
        using var fixture = new TemporaryClone();
        fixture.WriteEnv(EnvironmentText("https://example.test"));
        using var config = LiveEnvConfig.Load(fixture.Checkout);
        using var wire = new ProviderWire();
        if (identity)
            wire.Identities.Add("sdk-live-setup", (Id(9), "no-access"));
        else
            wire.Projects.Add("sdk-live-a", Id(9));
        using var pipeline = new HttpClient(wire);
        async Task Reconcile()
        {
            using var result = await new FixtureReconciler(pipeline).ReconcileAsync(config, default, issueCredentials: false);
        }
        var failure = await Assert.That(Reconcile).Throws<ProvisioningException>();
        await Assert.That(failure!.Message).Contains("refusing adoption");
        await Assert.That(wire.Mutations).IsEqualTo(0);
        if (identity)
            await Assert.That(wire.Identities["sdk-live-setup"].Role).IsEqualTo("no-access");
        else
            await Assert.That(wire.Projects["sdk-live-a"]).IsEqualTo(Id(9));
    }

    [Test]
    public async Task LiveProvisionerRefusesStaleDuplicateAndRetargetedPins()
    {
        string text = EnvironmentText("https://example.test") + Scope + $"\nINFISICAL_REMOTE_PROJECT_A_ID={Id(1)}";
        await Assert.That(() => LiveEnvConfig.Parse(text + $"\nINFISICAL_REMOTE_SETUP_IDENTITY_ID={Id(1)}", "/fixture"))
            .Throws<ProvisioningException>();
        await Assert.That(() => LiveEnvConfig.Parse(text.Replace("https://example.test\n", "https://other.test\n", StringComparison.Ordinal), "/fixture"))
            .Throws<ProvisioningException>();
        using var fixture = new TemporaryClone();
        fixture.WriteEnv(text);
        using var config = LiveEnvConfig.Load(fixture.Checkout);
        using var wire = new ProviderWire();
        using var pipeline = new HttpClient(wire);
        async Task Reconcile()
        {
            using var result = await new FixtureReconciler(pipeline).ReconcileAsync(config, default, issueCredentials: false);
        }
        var failure = await Assert.That(Reconcile).Throws<ProvisioningException>();
        await Assert.That(failure!.Message).Contains("enrolled resource is missing");
        await Assert.That(wire.Mutations).IsEqualTo(0);
    }

    [Test]
    public async Task LiveProvisionerStopsAfterConfirmedCreationIfTheEnvironmentChangedBeforeCheckpoint()
    {
        using var fixture = new TemporaryClone();
        fixture.WriteEnv(EnvironmentText("https://example.test"));
        using var config = LiveEnvConfig.Load(fixture.Checkout);
        using var wire = new ProviderWire { OnProjectCreated = () => File.AppendAllText(fixture.EnvPath, "\n# operator edit\n") };
        using var pipeline = new HttpClient(wire);
        var reconciler = new FixtureReconciler(pipeline);
        async Task Reconcile(LiveEnvConfig loaded)
        {
            using var result = await reconciler.ReconcileAsync(loaded, default, issueCredentials: false);
        }
        var failure = await Assert.That(() => Reconcile(config)).Throws<ProvisioningException>();
        await Assert.That(failure!.Message).Contains(".env changed");
        await Assert.That(string.Join(",", wire.Projects.Keys)).IsEqualTo("sdk-live-a");
        await Assert.That(File.ReadAllText(fixture.EnvPath)).Contains("# operator edit").And.DoesNotContain("PROJECT_A_ID");
        using var reloaded = LiveEnvConfig.Load(fixture.Checkout);
        var replay = await Assert.That(() => Reconcile(reloaded)).Throws<ProvisioningException>();
        await Assert.That(replay!.Message).Contains("refusing adoption");
        await Assert.That(wire.Projects.Count).IsEqualTo(1);
    }

    [Test]
    public async Task LiveProvisionerReusesFivePrincipalsAndResetsNarrativeAndImportState()
    {
        const string optional = "SDK_OPTIONAL_PACKAGE_VALUE";
        const string conformance = "SDK_CONFORMANCE_VALUE";
        using var fixture = new TemporaryClone();
        const string otherMode = "\n# retain other mode\nINFISICAL_LOCAL_ORIGIN=http://127.0.0.1:18080\n";
        fixture.WriteEnv(EnvironmentText("https://example.test") + Scope + $"\nINFISICAL_REMOTE_PROJECT_A_ID={Id(1)}" + otherMode);
        using var config = LiveEnvConfig.Load(fixture.Checkout);
        using var wire = new ProviderWire();
        wire.Projects.Add("sdk-live-a", Id(1));
        wire.Secrets[(Id(1), "dev", "/", optional)] = "stale";
        using var pipeline = new HttpClient(wire);
        var reconciler = new FixtureReconciler(pipeline);
        using var first = await reconciler.ReconcileAsync(config, default, issueCredentials: false);
        wire.Secrets[(first.ProjectBId, "dev", "/", optional)] = "stale";
        wire.Secrets[(first.ImportProjectId, "prod", "/sdk-destination", "SDK_IMPORTED_VALUE")] = "stale";
        using var reloaded = LiveEnvConfig.Load(fixture.Checkout);
        using var second = await reconciler.ReconcileAsync(reloaded, default, issueCredentials: false);

        await Assert.That(first.ProjectAId).IsEqualTo(Id(1));
        await Assert.That(first.ProjectBId).IsEqualTo(second.ProjectBId);
        await Assert.That(first.ImportProjectId).IsEqualTo(second.ImportProjectId);
        await Assert.That(wire.Projects.Count).IsEqualTo(3);
        string[] actors = [second.Setup.IdentityId, second.Runtime.IdentityId, second.Denied.IdentityId,
            second.Administrative.IdentityId, second.Observer.IdentityId];
        await Assert.That(actors.Distinct().Count()).IsEqualTo(5);
        await Assert.That(wire.Identities.Count).IsEqualTo(5);
        foreach (string project in new[] { second.ProjectAId, second.ProjectBId, second.ImportProjectId })
        {
            await Assert.That(wire.Memberships[(project, second.Setup.IdentityId)]).IsEqualTo("admin");
            await Assert.That(wire.Memberships[(project, second.Administrative.IdentityId)]).IsEqualTo("admin");
        }
        await Assert.That(wire.Memberships.ContainsKey((second.ProjectAId, second.Runtime.IdentityId))).IsTrue();
        await Assert.That(wire.Memberships.Keys.Any(k => k.Identity == second.Denied.IdentityId)).IsFalse();
        await Assert.That(wire.Secrets.Keys.Any(k => k.Key == optional)).IsFalse();
        await Assert.That(wire.Secrets[(second.ProjectAId, "dev", "/", conformance)]).IsEqualTo(second.ExpectedA.Reveal());
        await Assert.That(wire.Secrets[(second.ProjectBId, "dev", "/", conformance)]).IsEqualTo(second.ExpectedB.Reveal());
        await Assert.That(second.ExpectedA.Reveal()).IsNotEqualTo(second.ExpectedB.Reveal());
        await Assert.That(wire.ImportSource).IsEqualTo("/sdk-source");
        await Assert.That(wire.Secrets.ContainsKey((second.ImportProjectId, "prod", "/sdk-destination", "SDK_IMPORTED_VALUE"))).IsFalse();
        await Assert.That(File.ReadAllText(fixture.EnvPath)).Contains(otherMode);
    }

    private static string EnvironmentText(string origin) => $"""
        INFISICAL_MODE=remote
        INFISICAL_REMOTE_ORIGIN={origin}
        INFISICAL_REMOTE_ORGANIZATION_ID={Id(100)}
        INFISICAL_REMOTE_AUTOMATION_CLIENT_ID=fixture-client
        INFISICAL_REMOTE_AUTOMATION_CLIENT_SECRET=test-sensitive
        """;

    private sealed class ProviderWire : HttpMessageHandler
    {
        private const string Stamp = "2026-01-01T00:00:00Z";
        internal Dictionary<string, string> Projects { get; } = new(StringComparer.Ordinal);
        internal int Status { get; set; } = 200;
        internal int ProjectStatus { get; set; } = 200;
        internal bool IncompleteProjects { get; set; }
        internal Action? OnProjectCreated { get; init; }
        internal int Authentications { get; private set; }
        internal int Mutations { get; private set; }
        internal Dictionary<string, (string Id, string Role)> Identities { get; } = new(StringComparer.Ordinal);
        internal Dictionary<(string Project, string Identity), string> Memberships { get; } = [];
        internal Dictionary<(string Project, string Env, string Path, string Key), string> Secrets { get; } = [];
        internal string? ImportSource { get; private set; }
        private readonly HashSet<string> _universal = [];
        private readonly Dictionary<string, string> _folders = [];
        private int _nextId = 10;
        private string NextId() => Id(_nextId++);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string path = request.RequestUri!.AbsolutePath.TrimEnd('/');
            var method = request.Method;
            if (method != HttpMethod.Get && path != "/api/v1/auth/universal-auth/login")
                Mutations++;
            using var document = request.Content is null ? null : JsonDocument.Parse(await request.Content.ReadAsStringAsync(cancellationToken));
            JsonElement body = document?.RootElement ?? default;
            string Field(string name) => body.GetProperty(name).GetString()!;
            var query = System.Web.HttpUtility.ParseQueryString(request.RequestUri.Query);
            object Project(string slug, string id, bool list = false, bool deleted = false)
            {
                var row = new Dictionary<string, object>
                {
                    ["id"] = id,
                    ["name"] = slug,
                    ["slug"] = slug,
                    ["orgId"] = Id(100),
                    ["type"] = "secret-manager",
                    ["createdAt"] = Stamp,
                    ["updatedAt"] = Stamp
                };
                if (!deleted)
                {
                    row["_id"] = id;
                    row["environments"] = Array.Empty<object>();
                    row["deletedEnvironments"] = Array.Empty<object>();
                }
                if (list) row["roles"] = Array.Empty<object>();
                return row;
            }
            object Identity(string name, string id) => new
            {
                id,
                name,
                orgId = Id(100),
                createdAt = Stamp,
                updatedAt = Stamp,
                metadata = Array.Empty<object>(),
                authMethods = _universal.Contains(id) ? new[] { "universal-auth" } : Array.Empty<string>()
            };
            object Member(string project, string identity, string role) => new
            {
                id = identity,
                identityId = identity,
                createdAt = Stamp,
                updatedAt = Stamp,
                identity = new
                {
                    id = identity,
                    name = Identities.Single(p => p.Value.Id == identity).Key,
                    orgId = Id(100),
                    authMethods = new[] { "universal-auth" },
                    activeLockoutAuthMethods = Array.Empty<string>()
                },
                roles = new[] { new { id = identity, role, isTemporary = false } }
            };
            if (path == "/api/status")
                return Reply(new { message = "response-private" }, Status);
            if (path == "/api/v1/auth/universal-auth/login")
            {
                Authentications++;
                return Reply(new { accessToken = "synthetic-bearer", expiresIn = 120, accessTokenMaxTTL = 0, tokenType = "Bearer" });
            }
            if (path == "/api/v1/identities" && method == HttpMethod.Get)
                return Reply(new
                {
                    identities = Identities.Select(p => new
                    {
                        id = p.Value.Id,
                        identityId = p.Value.Id,
                        orgId = Id(100),
                        role = p.Value.Role,
                        createdAt = Stamp,
                        updatedAt = Stamp,
                        identity = new
                        {
                            id = p.Value.Id,
                            name = p.Key,
                            authMethods = new[] { "universal-auth" }
                        }
                    }),
                    totalCount = Identities.Count
                });
            if (path == "/api/v1/identities" && method == HttpMethod.Post)
            {
                string name = Field("name"), id = NextId();
                Identities.Add(name, (id, Field("role")));
                return Reply(new { identity = Identity(name, id) });
            }
            if (path.StartsWith("/api/v1/auth/universal-auth/identities/", StringComparison.Ordinal))
            {
                string id = path.Split('/')[^1];
                if (method == HttpMethod.Post && !_universal.Add(id))
                    return Reply(new { message = "duplicate" }, 409);
                return Reply(new
                {
                    identityUniversalAuth = new
                    {
                        id = Id(101),
                        identityId = id,
                        clientId = id,
                        createdAt = Stamp,
                        updatedAt = Stamp,
                        accessTokenTTL = 3600,
                        accessTokenMaxTTL = 7200,
                        accessTokenPeriod = 0,
                        accessTokenNumUsesLimit = 0,
                        lockoutEnabled = false
                    }
                });
            }
            if (path == "/api/v1/projects" && method == HttpMethod.Get)
                return Reply(new
                {
                    projects = Projects.Select(pair => Project(pair.Key, pair.Value, list: true)).ToArray(),
                    totalCount = Projects.Count + (IncompleteProjects ? 1 : 0)
                }, ProjectStatus);
            if (path == "/api/v1/projects" && method == HttpMethod.Post)
            {
                string slug = Field("slug"), id = NextId();
                Projects.Add(slug, id);
                OnProjectCreated?.Invoke();
                return Reply(new { project = Project(slug, id) });
            }
            const string projectPath = "/api/v1/projects/";
            if (path.StartsWith(projectPath, StringComparison.Ordinal))
            {
                string[] segments = path[projectPath.Length..].Split('/');
                string id = segments[0];
                if (segments is [_, "memberships", "identities"])
                {
                    var rows = Memberships.Where(p => p.Key.Project == id).Select(p => Member(id, p.Key.Identity, p.Value)).ToArray();
                    return Reply(new { identityMemberships = rows, totalCount = rows.Length });
                }
                if (segments is [_, "memberships", "identities", var member])
                {
                    string role = body.GetProperty("roles")[0].GetProperty("role").GetString()!;
                    Memberships.Add((id, member), role);
                    return Reply(new
                    {
                        identityMembership = new
                        {
                            id = member,
                            identityId = member,
                            projectId = id,
                            createdAt = Stamp,
                            updatedAt = Stamp
                        }
                    });
                }
                if (segments is [_, "environments", "slug", var env])
                    return Reply(new
                    {
                        environment = new
                        {
                            id = EnvId(env),
                            projectId = id,
                            name = env,
                            slug = env,
                            position = 1,
                            createdAt = Stamp,
                            updatedAt = Stamp
                        }
                    });
                var pair = Projects.Single(item => item.Value == id);
                if (method == HttpMethod.Delete)
                    Projects.Remove(pair.Key);
                return Reply(new { project = Project(pair.Key, id, deleted: method == HttpMethod.Delete) });
            }
            if (path == "/api/v2/folders")
            {
                object Folder(string name, string env, string id) => new { id, name, envId = EnvId(env), createdAt = Stamp, updatedAt = Stamp };
                string environment = method == HttpMethod.Get ? query["environment"]! : Field("environment");
                if (method == HttpMethod.Get)
                    return Reply(new
                    {
                        folders = _folders.TryGetValue(environment, out var id)
                        ? new[] { Folder(environment == "dev" ? "sdk-source" : "sdk-destination", environment, id) } : []
                    });
                string folderId = NextId();
                _folders.Add(environment, folderId);
                return Reply(new { folder = Folder(Field("name"), environment, folderId) });
            }
            if (path == "/api/v2/secret-imports")
            {
                string folder = _folders["prod"];
                object Link(string source) => new
                {
                    id = Id(104),
                    folderId = folder,
                    importEnv = new { id = EnvId("dev"), name = "dev", slug = "dev" },
                    importPath = source,
                    position = 1,
                    isReplication = false,
                    createdAt = Stamp,
                    updatedAt = Stamp
                };
                if (method == HttpMethod.Get)
                    return Reply(new { secretImports = ImportSource is null ? [] : new[] { Link(ImportSource) } });
                ImportSource = body.GetProperty("import").GetProperty("path").GetString();
                return Reply(new { secretImport = Link(ImportSource!) });
            }
            const string secretPath = "/api/v4/secrets";
            if (path.StartsWith(secretPath, StringComparison.Ordinal))
            {
                string project = method == HttpMethod.Get ? query["projectId"]! : Field("projectId");
                string environment = method == HttpMethod.Get ? query["environment"]! : Field("environment");
                string folder = method == HttpMethod.Get ? query["secretPath"]! : Field("secretPath");
                object Secret(string name) => new
                {
                    id = "secret-" + name,
                    secretKey = name,
                    workspace = project,
                    environment,
                    secretPath = folder,
                    type = "shared",
                    version = 1
                };
                if (method == HttpMethod.Get)
                    return Reply(new
                    {
                        secrets = Secrets.Keys.Where(k => (k.Project, k.Env, k.Path) == (project, environment, folder))
                        .Select(k => Secret(k.Key)).ToArray()
                    });
                if (method == HttpMethod.Delete)
                {
                    string[] keys = body.GetProperty("secrets").EnumerateArray().Select(item => item.GetProperty("secretKey").GetString()!).ToArray();
                    foreach (string key in keys)
                        if (!Secrets.Remove((project, environment, folder, key)))
                            return Reply(new { message = "not found" }, 404);
                    return Reply(new { secrets = keys.Select(Secret).ToArray() });
                }
                string name = path.Split('/')[^1];
                var keyScope = (project, environment, folder, name);
                if ((method == HttpMethod.Post) == Secrets.ContainsKey(keyScope))
                    return Reply(new { message = "conflict" }, 409);
                Secrets[keyScope] = Field("secretValue");
                return Reply(new { secret = Secret(name) });
            }
            throw new NotSupportedException($"Unexpected synthetic provider route: {method} {path}");
        }

        private static string EnvId(string env) => Id(env == "dev" ? 102 : 103);

        private static HttpResponseMessage Reply(object body, int status = 200) =>
            new((HttpStatusCode)status)
            {
                Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
            };
    }
}
