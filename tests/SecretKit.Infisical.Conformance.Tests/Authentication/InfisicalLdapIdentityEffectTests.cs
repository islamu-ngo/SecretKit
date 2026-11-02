using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalLdapIdentityEffectTests
{
    [Test]
    public async Task LdapControlledDirectoryChecksServiceAndUserCredentialsIndependently()
    {
        await using var fixture = new LdapIdentityFixture("good");
        await fixture.CalibrateAsync();
        await Assert.That(fixture.Source.SuccessfulIdentityCount).IsEqualTo(1);
        await Assert.That(fixture.AllowedReads).IsEqualTo(1);
        await Assert.That(fixture.DeniedReads).IsEqualTo(1);
    }

    [Test]
    [Arguments("unsettled")]
    [Arguments("cleanup-failure")]
    [Arguments("lost-metadata-only")]
    public async Task LdapLostTemplateResponseNeedsTerminalSourceAndOwnedCleanup(string mode)
    {
        await using var fixture = new LdapIdentityFixture(mode);
        var result = await fixture.RunAsync("UpdateIdentityTemplateConfiguration",
            "IdentityTemplateLdapFields.bindPassword.value", "lost-response-no-replay");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Source.TemplateArms > 0).IsTrue();
        await Assert.That(fixture.SelectedMutations).IsEqualTo(1);
    }
}

// Controlled native-shaped HTTP state. Source evidence comes from this backend's
// event journal, never from the caller's expected disposition or status.
internal sealed class LdapIdentityFixture : IAsyncDisposable
{
    internal const string Org = "00000000-0000-0000-0000-000000000001";
    private const string Date = "2026-10-13T00:00:00.000Z";
    internal const string Original = "service-original";
    internal const string Rotated = "service-rotated";
    internal const string WrongService = "service-wrong";
    internal const string User = "user-valid";
    internal const string WrongUser = "user-wrong";
    private readonly InfisicalIdentitySearchEffectTests.Backend backend;
    private readonly Dictionary<string, JsonObject> templates = [];
    private readonly Dictionary<string, string> templatePasswords = [];
    private readonly Dictionary<string, (string Template, string Password)> consumers = [];
    private readonly Dictionary<string, (string Identity, string Metadata)> issued = [];
    private readonly Dictionary<(string Project, string Key), string> secrets = [];
    private readonly List<TemplateEvent> mutations = [];
    private readonly string nonce = Guid.NewGuid().ToString("N");
    private readonly string allowedProject = Guid.NewGuid().ToString();
    private readonly string deniedProject = Guid.NewGuid().ToString();
    internal string Mode { get; }
    internal LdapFixtureSource Source { get; }
    internal int SelectedMutations { get; private set; }
    internal int AllowedReads { get; private set; }
    internal int DeniedReads { get; private set; }
    internal int AscendingSearches { get; private set; }
    internal int DescendingSearches { get; private set; }
    internal int ProjectFallbackRows { get; private set; }
    internal bool LoginNamesOpposeOrder { get; private set; }
    internal int ResidualCount => templates.Count + consumers.Count + issued.Count + backend.OwnedCount;
    internal Uri Origin => backend.Origin;
    internal string ServicePassword { get; set; } = Original;
    internal long Sequence { get; private set; }
    internal DateTimeOffset Clock => DateTimeOffset.Parse(Date).AddSeconds(Sequence);
    internal long Tick() => ++Sequence;
    private sealed record TemplateEvent(long Sequence, string Id, string Name, string Role, bool Applied);
    internal sealed record LoginEvent(long Sequence, string Identity, bool Service, bool User,
        string? Metadata, DateTimeOffset? At, SecretStatus Status, string Name, string Template, string Membership);
    internal List<LoginEvent> Logins { get; } = [];

    internal LdapIdentityFixture(string mode)
    {
        Mode = mode;
        backend = new(mode == "inventory-incomplete" ? mode : "good") { Ldap = this };
        Source = new(this);
        foreach (string project in new[] { allowedProject, deniedProject })
        {
            backend.projects[project] = new()
            {
                ["id"] = project,
                ["_id"] = project,
                ["orgId"] = Org,
                ["type"] = "secret-manager",
                ["name"] = "ldap-canary-" + project,
                ["slug"] = "ldap-canary-" + project,
                ["createdAt"] = Date,
                ["updatedAt"] = Date,
                ["hasDeleteProtection"] = false,
                ["environments"] = new JsonArray(new JsonObject
                {
                    ["id"] = Guid.NewGuid().ToString(),
                    ["name"] = "Witness",
                    ["slug"] = "witness"
                }),
                ["deletedEnvironments"] = new JsonArray()
            };
            secrets[(project, "ldap-canary")] = "controlled-ldap-canary";
        }
    }

    internal bool IsPreprovisionedCanaryProject(string project) => project == allowedProject || project == deniedProject;

    internal async Task<NativeCaseResult> RunAsync(string operation, string variant,
        string caseName = "independent-effect")
    {
        string family = operation == "SearchIdentities" ? "IdentitySearchOperations" : "IdentityTemplateOperations";
        string id = "i.management." + family + "." + operation;
        var definition = new NativeCaseDefinition(new("Infisical", id, variant, "local", caseName),
            InfisicalIdentityFamilies.Bindings[id].Member);
        var input = new Dictionary<string, object>
        {
            ["organizationId"] = Org,
            ["identityRole"] = "member",
            ["projectIdentityRole"] = "viewer",
            ["updatedIdentityRole"] = "admin",
            ["identitySearchExcludedRole"] = "no-access",
            ["administrativeIdentityId"] = "00000000-0000-0000-0000-000000000002",
            ["observerIdentityId"] = "00000000-0000-0000-0000-000000000003",
            ["runtimeIdentityId"] = "00000000-0000-0000-0000-000000000004",
            ["ldapWitness"] = new { deploymentId = "controlled-ldap", sourceProfile = "controlled-fixture", caseTimeoutSeconds = 15 },
            ["ldapRootNonce"] = nonce,
            ["ldapUrl"] = "ldaps://" + nonce + ".ldap.invalid",
            ["bindDn"] = "cn=service,ou=" + nonce + ",dc=fixture",
            ["searchBase"] = "ou=" + nonce + ",dc=fixture",
            ["originalBindPassword"] = Original,
            ["bindPassword"] = Rotated,
            ["wrongBindPassword"] = WrongService,
            ["ldapUsername"] = "login-user",
            ["ldapUserPassword"] = User,
            ["ldapWrongUserPassword"] = WrongUser,
            ["ldapSearchFilter"] = "(uid={{username}})",
            ["ldapCanaries"] = new
            {
                allowed = new { projectId = allowedProject, environment = "witness", path = "/", key = "ldap-canary" },
                denied = new { projectId = deniedProject, environment = "witness", path = "/", key = "ldap-canary" }
            },
            ["ldapCanaryValue"] = "controlled-ldap-canary",
            ["baselineLdapUrl"] = "ldaps://" + nonce + ".ldap.invalid:636",
            ["baselineBindDn"] = "cn=original-service,ou=" + nonce + ",dc=fixture",
            ["baselineSearchBase"] = "ou=prior,ou=" + nonce + ",dc=fixture",
            ["ldapCaCertificate"] = "controlled-ca"
        };
        using var environment = NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            administrative = "administrative",
            observer = "observer",
            runtime = "runtime",
            denied = "denied",
            families = new Dictionary<string, object>
            {
                ["C08-IM-" + InfisicalIdentityFamilies.Family(definition)] =
                    new { scopes = new Dictionary<string, object> { ["local"] = input } }
            }
        }));
        var registry = new NativeCaseRegistry();
        InfisicalIdentityFamilies.Register(registry, environment, [definition], Source);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        return (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
    }

    internal (int, JsonNode)? Handle(string method, Uri uri, string role, JsonObject body)
    {
        string[] path = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (path.Length < 3) return null;
        if (path[2] == "identity-templates")
        {
            if (role == "denied")
            {
                mutations.Add(new(Tick(), path.Length > 3 ? path[3] : "", Text(body, "name"), role, false));
                return (403, new JsonObject());
            }
            if (path.Length == 3 && method == "POST")
            {
                string id = Guid.NewGuid().ToString();
                var fields = body["templateFields"]!.DeepClone().AsObject();
                templatePasswords[id] = Text(fields, "bindPass");
                fields.Remove("bindPass");
                fields["hasBindPass"] = true;
                templates[id] = new()
                {
                    ["id"] = id,
                    ["orgId"] = Org,
                    ["name"] = body["name"]!.DeepClone(),
                    ["authMethod"] = "ldap",
                    ["templateFields"] = fields,
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date
                };
                RecordMutation(id, role);
                return (200, templates[id].DeepClone());
            }
            if (path.Length == 3 || path[^1] == "search")
                return (200, path.Length == 3 ? new JsonArray(templates.Values.Select(t => t.DeepClone()).ToArray()) :
                    new JsonObject { ["templates"] = new JsonArray(templates.Values.Select(t => t.DeepClone()).ToArray()), ["totalCount"] = templates.Count });
            string selected = path[3];
            if (path[^1] == "usage")
                return (200, new JsonArray(consumers.Where(c => c.Value.Template == selected).Select(c => (JsonNode)new JsonObject
                {
                    ["id"] = c.Key,
                    ["identityId"] = c.Key,
                    ["templateId"] = selected,
                    ["identityName"] = Text(backend.identities[c.Key], "name")
                }).ToArray()));
            if (!templates.TryGetValue(selected, out var template)) return (404, new JsonObject());
            if (method == "PATCH")
            {
                if (body["name"] is { } name) template["name"] = name.DeepClone();
                if (body["templateFields"] is JsonObject fields)
                {
                    foreach (var pair in fields)
                        if (pair.Key == "bindPass")
                        {
                            if (Mode != "ignored-password") templatePasswords[selected] = pair.Value!.GetValue<string>();
                        }
                        else template["templateFields"]![pair.Key] = pair.Value?.DeepClone();
                    if (!fields.ContainsKey("bindPass") && Mode == "omission-overwrites") templatePasswords[selected] = "";
                    foreach (string identity in consumers.Where(c => c.Value.Template == selected).Select(c => c.Key).ToArray())
                        if (Mode != "linked-consumer-stale") consumers[identity] = (selected, templatePasswords[selected]);
                }
                RecordMutation(selected, role);
            }
            if (method == "DELETE")
            {
                if (Mode == "cleanup-failure") return (403, new JsonObject());
                templates.Remove(selected); templatePasswords.Remove(selected);
                return (200, new JsonObject { ["message"] = "deleted" });
            }
            return (200, template.DeepClone());
        }
        if (path[2] == "auth" && path.Length > 3 && path[3] == "ldap-auth")
        {
            if (path[^1] == "login") return Login(body);
            string identity = path[^1];
            if (method == "POST")
            {
                string template = Text(body, "templateId");
                consumers[identity] = (template, Mode == "fresh-consumer-wrong" ? WrongService : templatePasswords[template]);
                backend.identities[identity]["authMethods"] = new JsonArray("ldap-auth");
            }
            if (!consumers.TryGetValue(identity, out var consumer)) return (404, new JsonObject());
            var config = templates[consumer.Template]["templateFields"]!.DeepClone().AsObject();
            config.Remove("hasBindPass");
            config["id"] = identity; config["identityId"] = identity; config["templateId"] = consumer.Template;
            config["bindDN"] = config["bindDN"]?.DeepClone() ?? config["bindDn"]?.DeepClone() ?? "cn=service";
            config["searchFilter"] = "(uid={{username}})";
            config["accessTokenTTL"] = 300; config["accessTokenMaxTTL"] = 1200; config["accessTokenNumUsesLimit"] = 0;
            config["accessTokenTrustedIps"] = new JsonArray();
            config["createdAt"] = Date; config["updatedAt"] = Date;
            if (method != "GET")
            {
                config.Remove("bindDN");
                config.Remove("ldapCaCertificate");
            }
            if (method == "DELETE") consumers.Remove(identity);
            return (200, new JsonObject { ["identityLdapAuth"] = config });
        }
        if (path[2] == "secrets" && (path.Length == 4 && path[1] == "v4" ||
            path.Length > 4 && path[3] == "raw"))
        {
            string key = Uri.UnescapeDataString(path[^1]);
            var query = uri.Query.TrimStart('?').Split('&').Select(p => p.Split('=', 2))
                .Where(p => p.Length == 2).ToDictionary(p => p[0], p => Uri.UnescapeDataString(p[1]));
            string project = body["workspaceId"]?.GetValue<string>() ?? body["projectId"]?.GetValue<string>() ??
                query.GetValueOrDefault("workspaceId") ?? query.GetValueOrDefault("projectId") ?? "";
            bool tokenIssued = issued.TryGetValue(role, out var token);
            bool allowed = role is "setup" or "observer" ||
                tokenIssued && backend.memberships.ContainsKey((project, token.Identity));
            if (tokenIssued && Mode == "canary-bypass") allowed = true;
            if (tokenIssued) { if (allowed) AllowedReads++; else DeniedReads++; }
            if (!allowed) return (403, new JsonObject());
            if (method == "POST") secrets[(project, key)] = Text(body, "secretValue");
            if (method == "DELETE") { secrets.Remove((project, key)); return (200, new JsonObject { ["message"] = "deleted" }); }
            if (!secrets.TryGetValue((project, key), out string? value)) return (404, new JsonObject());
            return (200, new JsonObject
            {
                ["secret"] = new JsonObject
                {
                    ["id"] = Guid.NewGuid().ToString(),
                    ["secretKey"] = key,
                    ["secretValue"] = value,
                    ["secretValueHidden"] = false,
                    ["version"] = 1,
                    ["type"] = "shared",
                    ["projectId"] = project,
                    ["workspace"] = project,
                    ["environment"] = "witness",
                    ["secretPath"] = "/"
                }
            });
        }
        if (path[2] == "projects" && path.Length > 4 && path[4] == "environments")
            return (200, new JsonObject
            {
                ["environment"] = new JsonObject
                {
                    ["id"] = Guid.NewGuid().ToString(),
                    ["name"] = "Witness",
                    ["slug"] = "witness",
                    ["position"] = 1,
                    ["projectId"] = path[3]
                }
            });
        return null;
    }

    private void RecordMutation(string id, string role)
    {
        if (role == "administrative") SelectedMutations++;
        mutations.Add(new(Tick(), id, Text(templates[id], "name"), role, true));
    }

    private (int, JsonNode) Login(JsonObject body)
    {
        string identity = Text(body, "identityId");
        bool service = consumers.TryGetValue(identity, out var config) && config.Password == ServicePassword;
        bool user = service && Text(body, "username") == "login-user" &&
            (Text(body, "password") == User || Mode == "login-wronguser");
        long sequence = Tick();
        string? metadata = user ? Guid.NewGuid().ToString() : null;
        DateTimeOffset? at = user ? Clock : null;
        Logins.Add(new(sequence, identity, service, user, metadata, at, user ? SecretStatus.Success : SecretStatus.Denied,
            backend.identities.TryGetValue(identity, out var configured) ? Text(configured, "name") : "",
            config.Template ?? "", identity));
        var successful = Logins.Where(l => l.Metadata is not null).DistinctBy(l => l.Identity).Take(2).ToArray();
        LoginNamesOpposeOrder = successful.Length == 2 &&
            StringComparer.Ordinal.Compare(successful[0].Name, successful[1].Name) > 0;
        if (!user) return (403, new JsonObject());
        string material = Guid.NewGuid().ToString("N");
        string? prior = issued.Keys.FirstOrDefault();
        issued[material] = (identity, metadata!);
        return (200, new JsonObject
        {
            ["accessToken"] = Mode == "same-authority-substitution" && prior is not null ? prior : material,
            ["tokenType"] = "Bearer",
            ["expiresIn"] = 300,
            ["accessTokenMaxTTL"] = 1200
        });
    }

    internal void RemoveIdentity(string id)
    {
        consumers.Remove(id);
        foreach (string material in issued.Where(t => t.Value.Identity == id).Select(t => t.Key).ToArray()) issued.Remove(material);
    }

    internal void AddLoginFields(JsonObject row, string identity)
    {
        var login = Logins.LastOrDefault(l => l.Identity == identity && l.Metadata is not null);
        row["lastLoginTime"] = login?.At?.ToString("O");
        row["lastLoginAuthMethod"] = login is null ? null : "ldap-auth";
    }

    internal List<JsonObject> SearchRows(List<JsonObject> rows, JsonObject body)
    {
        foreach (var row in rows) AddLoginFields(row, Text(row, "identityId"));
        if (Text(body, "orderBy") != "lastLogin") return rows;
        bool descending = Text(body, "orderDirection") == "desc";
        if (descending) DescendingSearches++; else AscendingSearches++;
        DateTimeOffset? At(JsonObject r) => r["lastLoginTime"] is { } value ? DateTimeOffset.Parse(value.GetValue<string>()) : null;
        rows = rows.OrderBy(r => At(r) is null).ThenBy(r => descending ? -(At(r)?.Ticks ?? 0) : At(r)?.Ticks ?? 0)
            .ThenBy(r => Text(r, "id"), StringComparer.Ordinal).ToList();
        ProjectFallbackRows += rows.Count(r => Text(r, "scope") == "project" && At(r) is not null);
        if (Mode == "tie-reversed")
            rows = rows.GroupBy(At).SelectMany(group => group.Reverse()).ToList();
        if (Mode == "project-fallback-poison")
            foreach (var row in rows.Where(r => Text(r, "scope") == "project" && At(r) is not null))
                row["lastLoginTime"] = At(row)!.Value.AddHours(1).ToString("O");
        if (Mode == "name-sorted") rows = rows.OrderBy(r => Text(r["identity"]!.AsObject(), "name"), StringComparer.Ordinal).ToList();
        if (Mode == "reversed") rows.Reverse();
        if (Mode == "null-first") rows = rows.OrderBy(r => At(r) is not null).ToList();
        if (Mode == "omitted-authmethod") foreach (var row in rows) row.Remove("lastLoginAuthMethod");
        if (Mode == "duplicate" && rows.Count > 0) rows.Add(rows[0].DeepClone().AsObject());
        if (Mode == "missing-membership" && rows.Count > 0) rows.RemoveAt(0);
        if (Mode == "pages" && rows.Count > 1) rows.RemoveRange(1, rows.Count - 1);
        return rows;
    }

    internal async Task CalibrateAsync()
    {
        string id = Guid.NewGuid().ToString();
        string template = Guid.NewGuid().ToString();
        consumers[id] = (template, Original);
        string project = Guid.NewGuid().ToString(), outside = Guid.NewGuid().ToString();
        backend.memberships[(project, id)] = new();
        secrets[(project, "canary")] = "owned-canary"; secrets[(outside, "canary")] = "outside-canary";
        using var auth = new InfisicalProofAuthentication(Origin, new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
        foreach (string password in new[] { WrongUser, User })
        {
            using var material = SecretMaterial.FromText(password);
            using var proof = InfisicalLoginProof.Ldap(id, "login-user", material);
            var outcome = await auth.LoginAsync(proof, auth.CreateReceipt());
            await Assert.That(outcome.Status).IsEqualTo(password == User ? SecretStatus.Success : SecretStatus.Denied);
            if (!outcome.IsSuccess) continue;
            using var login = outcome.Value;
            await using var client = new InfisicalClient(Origin, new AuthenticationTokenSource(login.Token.Material),
                new() { AllowLoopbackDevelopmentHttp = true });
            var allowed = await client.ReadAsync(new(client.Authority, new InfisicalSecretAddress(project, "witness", "/", "canary")));
            await Assert.That(allowed.Status).IsEqualTo(SecretStatus.Success);
            using var read = allowed.Value;
            await Assert.That(read.Material.Reveal()).IsEqualTo("owned-canary");
            var denied = await client.ReadAsync(new(client.Authority, new InfisicalSecretAddress(outside, "witness", "/", "canary")));
            await Assert.That(denied.Status).IsEqualTo(SecretStatus.Denied);
        }
        ServicePassword = Rotated;
        using var valid = SecretMaterial.FromText(User);
        using var staleProof = InfisicalLoginProof.Ldap(id, "login-user", valid);
        var stale = await auth.LoginAsync(staleProof, auth.CreateReceipt());
        await Assert.That(stale.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(Logins[^1].Service).IsFalse();
    }

    internal LdapTemplateFence TemplateFence(LdapTemplateArm arm)
    {
        var events = mutations.Where(e => e.Sequence > arm.Cursor &&
            (e.Id == arm.Attempt.TemplateId || e.Name == arm.Attempt.TemplateName)).ToArray();
        var applied = events.LastOrDefault(e => e.Applied);
        return new(arm, applied is not null ? DispatchEvidence.Applied : events.Length > 0 ? DispatchEvidence.Rejected : DispatchEvidence.NotDispatched,
            applied?.Id ?? arm.Attempt.TemplateId, events.Length == 0 ? null : "request-" + events[^1].Sequence,
            events.Length == 0 ? Tick() : events[^1].Sequence, events.Length, applied is not null,
            Mode is not ("unsettled" or "lost-metadata-only"), events.Length <= 1);
    }

    private static string Text(JsonObject value, string key) => value[key]?.GetValue<string>() ?? "";
    internal void ClearSourceJournal() { Logins.Clear(); mutations.Clear(); }
    internal string CredentialWitness(LdapLoginAttempt attempt, string metadata, byte[] key)
    {
        string material = issued.Single(pair => pair.Value.Metadata == metadata).Key;
        byte[] message = Encoding.UTF8.GetBytes("secretkit-ldap-login-v1\0" + attempt.Directory.Attempt.Id + "\0" +
            attempt.Id + "\0" + attempt.Directory.Attempt.OrganizationId + "\0" + attempt.IdentityId + "\0" +
            attempt.MembershipId + "\0" + attempt.TemplateId + "\0" + metadata + "\0" + material);
        byte[]? digest = null;
        try
        {
            digest = HMACSHA256.HashData(key, message);
            return Convert.ToBase64String(digest);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(message);
            if (digest is not null) CryptographicOperations.ZeroMemory(digest);
        }
    }
    public async ValueTask DisposeAsync()
    {
        await backend.DisposeAsync();
        Source.DestroyCredentials();
        templatePasswords.Clear(); consumers.Clear(); issued.Clear(); secrets.Clear();
        ClearSourceJournal();
    }
}

internal sealed class LdapFixtureSource(LdapIdentityFixture backend) : ILdapLoginObserver
{
    private LdapDirectoryCredentials? credentials;
    private byte[]? correlationKey;
    private readonly HashSet<string> registrations = [];
    private bool root;
    internal bool Opened { get; private set; }
    internal bool Closed { get; private set; }
    internal bool Sealed { get; private set; }
    internal int TemplateArms { get; private set; }
    private int completedSuccessfulIdentities;
    internal int SuccessfulIdentityCount => Closed ? completedSuccessfulIdentities :
        backend.Logins.Where(l => l.Metadata is not null).Select(l => l.Identity).Distinct().Count();

    public ValueTask<LdapDirectoryBinding> OpenAsync(LdapDirectoryAttempt attempt, LdapDirectoryCredentials packet, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (root || !attempt.Url.StartsWith("ldaps://", StringComparison.Ordinal) ||
            !attempt.Url.Contains(attempt.RootNonce, StringComparison.Ordinal) ||
            !attempt.BindDn.Contains(attempt.RootNonce, StringComparison.Ordinal) ||
            !attempt.SearchBase.Contains(attempt.RootNonce, StringComparison.Ordinal))
            throw new NativeCaseFailureException("missing-input");
        credentials = new(packet.Original, packet.Rotated, packet.WrongService, packet.User, packet.WrongUser);
        correlationKey = packet.CorrelationKey.ToArray();
        var passwords = new[] { credentials.Original.Reveal(), credentials.Rotated.Reveal(), credentials.WrongService.Reveal(),
            credentials.User.Reveal(), credentials.WrongUser.Reveal() };
        if (passwords.Distinct(StringComparer.Ordinal).Count() != 5) throw new NativeCaseFailureException("missing-input");
        backend.ServicePassword = credentials.Original.Reveal();
        root = true; Opened = true;
        return ValueTask.FromResult(new LdapDirectoryBinding(attempt, Guid.NewGuid().ToString(), "controlled-source",
            "provider-application-clock", "controlled-epoch", backend.Clock, backend.Tick(), true, true,
            backend.ServicePassword == LdapIdentityFixture.Original,
            credentials.WrongService.Reveal() != backend.ServicePassword,
            credentials.User.Reveal() == LdapIdentityFixture.User, credentials.WrongUser.Reveal() != LdapIdentityFixture.User));
    }

    public ValueTask<LdapDirectoryRotation> RotateAsync(LdapDirectoryBinding directory, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        backend.ServicePassword = credentials!.Rotated.Reveal();
        return ValueTask.FromResult(new LdapDirectoryRotation(directory, backend.Tick(), Guid.NewGuid().ToString(),
            credentials.Original.Reveal() != backend.ServicePassword, backend.ServicePassword == LdapIdentityFixture.Rotated,
            credentials.User.Reveal() == LdapIdentityFixture.User, root));
    }

    public ValueTask<LdapLoginArm> ArmAsync(LdapLoginAttempt attempt, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        string registration = Guid.NewGuid().ToString();
        registrations.Add(registration);
        return ValueTask.FromResult(new LdapLoginArm(attempt, registration, backend.Sequence, backend.Clock, root && !Sealed));
    }

    public ValueTask<LdapLoginFence> CompleteAsync(LdapLoginArm arm, DispatchEvidence receipt, SecretStatus status, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var events = backend.Logins.Where(e => e.Sequence > arm.Cursor && e.Identity == arm.Attempt.IdentityId &&
            e.Template == arm.Attempt.TemplateId && e.Membership == arm.Attempt.MembershipId).ToArray();
        var last = events.LastOrDefault();
        registrations.Remove(arm.RegistrationId);
        return ValueTask.FromResult(new LdapLoginFence(arm,
            last is null ? DispatchEvidence.NotDispatched : last.Metadata is null ? DispatchEvidence.Rejected : DispatchEvidence.Applied,
            last?.Status ?? SecretStatus.Unknown, last is null ? "" : "request-" + last.Sequence,
            last is null ? "" : "event-" + last.Sequence, last?.Sequence ?? backend.Tick(),
            last?.Service ?? false, last?.Service ?? false, last?.User ?? false, last?.Metadata is not null,
            last?.Metadata, backend.Mode == "source-timestamp-poison" ? last?.At?.AddHours(1) : last?.At,
            last?.Metadata is null ? null : "ldap-auth", events.Length, events.Count(e => e.Metadata is not null),
            last is not null, true,
            last?.Metadata is { } metadata ? backend.CredentialWitness(arm.Attempt, metadata, correlationKey!) : null));
    }

    public ValueTask<LdapTemplateArm> ArmTemplateAsync(LdapTemplateAttempt attempt, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        TemplateArms++;
        string registration = Guid.NewGuid().ToString();
        registrations.Add(registration);
        return ValueTask.FromResult(new LdapTemplateArm(attempt, registration, backend.Sequence, root));
    }

    public ValueTask<LdapTemplateFence> CompleteTemplateAsync(LdapTemplateArm arm, DispatchEvidence receipt, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        registrations.Remove(arm.RegistrationId);
        return ValueTask.FromResult(backend.TemplateFence(arm));
    }

    public ValueTask<LdapLoginVisibility> SealAsync(LdapDirectoryBinding directory, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        Sealed = true;
        return ValueTask.FromResult(new LdapLoginVisibility(directory, backend.Tick(), "watermark-" + backend.Sequence,
            backend.Clock, backend.Logins.Count, true, true, backend.Mode != "no-visibility"));
    }

    public ValueTask<LdapDirectoryCleanup> CloseAsync(LdapDirectoryAttempt attempt, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        completedSuccessfulIdentities = SuccessfulIdentityCount;
        root = false; Closed = true; DestroyCredentials();
        backend.ClearSourceJournal();
        return ValueTask.FromResult(new LdapDirectoryCleanup(attempt, true, backend.Mode != "cleanup-failure", true, true,
            backend.Mode != "unsettled", backend.Mode != "unsettled", registrations.Count, 0));
    }

    internal void DestroyCredentials()
    {
        credentials?.Dispose();
        credentials = null;
        if (correlationKey is not null) CryptographicOperations.ZeroMemory(correlationKey);
        correlationKey = null;
    }
}
