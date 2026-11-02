using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// A controlled provider, not a vendor emulator claiming native acceptance.
// Source coordination cannot write its authenticated ingress/reviewer/token/
// access journals. Native HTTP parses actual SDK requests; verification uses
// RSA signatures and an actual independently authenticated HTTP TokenReview.
internal sealed class InfisicalWorkloadTransitionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal static WorkloadTransitionAuthorities Authorities { get; } =
        new("setup-principal", "runtime-principal", "denied-principal", "administrative-principal", "observer-principal");
    internal object Gate { get; } = new();
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal InfisicalWorkloadTransitionFixtureSource Source { get; }
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly HttpClient reviewerHttp = new(new SocketsHttpHandler
    { AllowAutoRedirect = false, UseCookies = false, ActivityHeadersPropagator = null });
    private readonly Dictionary<string, WorkloadTransitionResource> resources = [];
    private readonly List<WorkloadTransitionResource> enrolled = [];
    private readonly Dictionary<string, RSA> issuerKeys = [];
    private readonly Dictionary<string, (string Identity, string Id)> tokens = [];
    private readonly Dictionary<string, string> reviewerCredentials = [];
    private readonly Dictionary<string, long> sequences = [];
    private WorkloadTransitionRoot? owner;
    private WorkloadTransitionIssuance? issuance;
    private WorkloadTransitionConfiguration? target, control;
    private string? window, arm;
    private bool creationFence, dispatchFence;
    private int originals;
    private readonly WorkloadTransitionBorrowed[] baselineBorrowed = [new("project", "borrowed-project", "revision-1")];
    private WorkloadTransitionBorrowed[] borrowed = [new("project", "borrowed-project", "revision-1")];
    internal List<WorkloadTransitionIngress> Ingress { get; } = [];
    internal List<WorkloadTransitionStorage> Storage { get; } = [];
    internal List<WorkloadTransitionReview> Reviews { get; } = [];
    internal List<WorkloadTransitionToken> IssuedTokens { get; } = [];
    internal List<WorkloadTransitionAccess> Access { get; } = [];
    internal List<WorkloadTransitionResource> Cleanup { get; } = [];
    internal List<string> LateRejections { get; } = [];
    internal ConcurrentBag<byte[]> Copies { get; } = [];
    internal int Remaining { get { lock (Gate) return resources.Count; } }
    internal bool BorrowedPreserved => WorkloadTransitionContract.Borrowed(baselineBorrowed, borrowed);
    internal WorkloadTransitionResource[] Inventory => enrolled.ToArray();
    internal WorkloadTransitionResource[] RemainingInventory => resources.Values.ToArray();
    internal WorkloadTransitionBorrowed[] Borrowed => borrowed.ToArray();
    internal WorkloadTransitionConfiguration Target => target!;
    internal WorkloadTransitionConfiguration Control => control!;
    internal int Originals => originals;
    internal bool Owns(WorkloadTransitionRoot root) => owner is not null && WorkloadTransitionContract.SameRoot(owner, root);

    internal InfisicalWorkloadTransitionFixture(string fault = "")
    {
        Fault = fault;
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Source = new(this);
        accept = AcceptAsync();
    }
    internal NativeEnvironment Environment(object families) => NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
    {
        origin = Origin.AbsoluteUri,
        allowLoopbackDevelopmentHttp = true,
        setup = "setup",
        runtime = "runtime",
        denied = "denied",
        administrative = "administrative",
        observer = "observer",
        families
    }, WorkloadTransitionContract.Options));
    internal void Reserve(WorkloadTransitionRoot root)
    {
        if (owner is not null || creationFence || Fault == "collision")
            throw new NativeCaseFailureException("observer-unavailable");
        owner = root;
    }
    internal void Enroll(string kind, string id)
    {
        if (owner is null || creationFence)
        { LateRejections.Add("creation"); throw new NativeCaseFailureException("observer-unavailable"); }
        var resource = new WorkloadTransitionResource(owner.Id, owner.Nonce, kind, id);
        enrolled.Add(resource); // enrollment precedes physical creation
    }
    private void Create(string kind, string id)
    {
        if (creationFence || !enrolled.Any(r => r.Kind == kind && r.Id == id))
            throw new NativeCaseFailureException("observer-unavailable");
        resources.Add(kind + "/" + id, enrolled.Single(r => r.Kind == kind && r.Id == id));
    }
    internal WorkloadTransitionIssuance Bootstrap(WorkloadTransitionStamp stamp)
    {
        var root = owner!;
        Create("issuer-work", root.Id);
        string[] identity = [Guid.NewGuid().ToString(), Guid.NewGuid().ToString()];
        string[] project = [Guid.NewGuid().ToString(), Guid.NewGuid().ToString()];
        string[] template = [Guid.NewGuid().ToString(), Guid.NewGuid().ToString()];
        string[] reviewer = [Guid.NewGuid().ToString(), Guid.NewGuid().ToString()];
        for (int i = 0; i < 2; i++)
        {
            Enroll("identity", identity[i]); Create("identity", identity[i]);
            if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
            Enroll("project", project[i]); Create("project", project[i]);
            Enroll("template", template[i]); Create("template", template[i]);
            Enroll("reviewer", reviewer[i]); Create("reviewer", reviewer[i]);
            reviewerCredentials[reviewer[i]] = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        }
        string issuer = Origin.AbsoluteUri + "issuer", audience = "workload-audience", subject = "workload-subject";
        var proofs = new List<WorkloadTransitionProof>();
        foreach (string name in new[] { "old", "new", "wrong" })
        {
            Enroll("issuer-key", name);
            var key = RSA.Create(2048); issuerKeys.Add(name, key); Create("issuer-key", name);
            Enroll("proof", name);
            string jwt = Sign(key, issuer, audience, subject, Guid.NewGuid().ToString());
            Create("proof", name);
            proofs.Add(new(name, jwt, key.ExportSubjectPublicKeyInfoPem(), subject));
        }
        WorkloadTransitionPrincipal Principal(int index)
        {
            string key = "K" + Guid.NewGuid().ToString("N");
            Enroll("secret", project[index] + "/" + key); Create("secret", project[index] + "/" + key);
            return new(identity[index], project[index], key, Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
        }
        var selected = Principal(0); var contrast = Principal(1);
        bool kubernetes = root.Operation.Contains("Kubernetes", StringComparison.Ordinal);
        var a = new WorkloadTransitionConfiguration(true, "template-a-1", template[0], proofs[0].PublicKey,
            subject, kubernetes ? reviewer[0] : null, issuer, audience);
        var b = new WorkloadTransitionConfiguration(true, "template-b-1", template[1], proofs[1].PublicKey,
            subject, kubernetes ? reviewer[1] : null, issuer, audience);
        bool attach = root.Operation.Contains(".Attach", StringComparison.Ordinal);
        bool linked = root.Variant.Contains("templateId", StringComparison.Ordinal);
        target = a with { Attached = !attach, Revision = "target-0", Template = !attach && linked ? template[0] : null };
        control = b;
        issuance = new(stamp, true, selected, contrast, template[0], template[1], reviewer[0], reviewer[1],
            reviewerCredentials[reviewer[1]], WorkloadTransitionContract.Hash(reviewerCredentials[reviewer[0]]),
            WorkloadTransitionContract.Hash(reviewerCredentials[reviewer[1]]), issuer, audience,
            target, a, b, proofs.ToArray(), Inventory);
        return issuance;
    }
    internal void Begin(string selectedWindow) => window = selectedWindow;
    internal void End() => window = null;
    internal void Arm(string selectedArm)
    {
        if (arm is not null || dispatchFence) throw new NativeCaseFailureException("observer-unavailable");
        arm = selectedArm;
    }
    internal void SealDispatch() => dispatchFence = true;
    internal void SealCreation() => creationFence = true;
    internal WorkloadTransitionStorage[] Snapshot(string selectedWindow)
    {
        var result = new[]
        {
            new WorkloadTransitionStorage(Event("storage", selectedWindow), "snapshot", issuance!.Target.Identity, target!.Revision, target),
            new WorkloadTransitionStorage(Event("storage", selectedWindow), "snapshot", issuance.Control.Identity, control!.Revision, control)
        };
        Storage.AddRange(result);
        return result;
    }
    internal void Close()
    {
        creationFence = dispatchFence = true;
        foreach (var resource in enrolled.AsEnumerable().Reverse())
        {
            if (Fault == "cleanup-residual" && resource.Kind == "identity") continue;
            resources.Remove(resource.Kind + "/" + resource.Id); Cleanup.Add(resource);
        }
        foreach (var key in issuerKeys.Values) key.Dispose();
        issuerKeys.Clear(); reviewerCredentials.Clear(); tokens.Clear(); window = null;
    }
    private WorkloadTransitionEvent Event(string journal, string selectedWindow)
    {
        var root = owner!;
        var profile = root.Profile.Journals.Single(j => j.Kind == journal);
        long sequence = sequences.GetValueOrDefault(journal) + 1; sequences[journal] = sequence;
        return new(root.Id, root.Nonce, root.Profile.Deployment, root.Profile.Epoch, root.Profile.Revision,
            journal, profile.Writer, profile.Schema, Guid.NewGuid().ToString(), sequence, selectedWindow);
    }
    private async Task AcceptAsync()
    {
        try
        {
            while (!shutdown.IsCancellationRequested)
                connections.Add(ServeAsync(await listener.AcceptTcpClientAsync(shutdown.Token)));
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
    }
    internal TaskCompletionSource? ResponseRelease { get; set; }
    internal TaskCompletionSource ResponseWritten { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private async Task ServeAsync(TcpClient socket)
    {
        using (socket)
        {
            byte[] header = new byte[32768], body = [], response = [];
            Copies.Add(header);
            try
            {
                var stream = socket.GetStream();
                int length = 0;
                while (length < header.Length)
                {
                    if (await stream.ReadAsync(header.AsMemory(length, 1), shutdown.Token) == 0) return;
                    length++;
                    if (length >= 4 && header.AsSpan(length - 4, 4).SequenceEqual("\r\n\r\n"u8)) break;
                }
                string[] lines = Encoding.ASCII.GetString(header, 0, length).Split("\r\n");
                string[] request = lines[0].Split(' ');
                int size = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?
                    .Split(':')[1].Trim() ?? "0");
                if (size is < 0 or > 131072) throw new InvalidOperationException("fixture-budget");
                body = new byte[size]; Copies.Add(body);
                await stream.ReadExactlyAsync(body, shutdown.Token);
                string bearer = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?
                    .Split(' ').Last() ?? "";
                var uri = new Uri(Origin, request[1]);
                (int Status, object Payload) result;
                using var document = JsonDocument.Parse(size == 0 ? "{}"u8.ToArray() : body);
                if (uri.AbsolutePath.EndsWith("-auth/login", StringComparison.Ordinal))
                    result = await LoginAsync(uri, document.RootElement);
                else
                    lock (Gate) result = uri.AbsolutePath == "/review" ? Review(document.RootElement, bearer) :
                        Handle(request[0], uri, bearer, document.RootElement);
                response = JsonSerializer.SerializeToUtf8Bytes(result.Payload); Copies.Add(response);
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {result.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"), shutdown.Token);
                await stream.WriteAsync(response, shutdown.Token);
                if (ResponseRelease is { } release)
                {
                    ResponseWritten.TrySetResult();
                    await release.Task.WaitAsync(shutdown.Token);
                }
            }
            catch (IOException) { }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            finally
            {
                CryptographicOperations.ZeroMemory(header);
                CryptographicOperations.ZeroMemory(body);
                CryptographicOperations.ZeroMemory(response);
            }
        }
    }
    private string Actor(string token) => token switch
    {
        "setup" => Authorities.Setup,
        "runtime" => Authorities.Runtime,
        "denied" => Authorities.Denied,
        "administrative" => Authorities.Administrative,
        "observer" => Authorities.Observer,
        _ => tokens.GetValueOrDefault(token).Identity ?? "unknown"
    };
    private (int, object) Handle(string method, Uri uri, string bearer, JsonElement body)
    {
        if (uri.AbsolutePath.StartsWith("/api/v4/secrets/", StringComparison.Ordinal))
            return Read(uri, bearer);
        if (issuance is null) return (404, new { });
        if (!uri.AbsolutePath.StartsWith("/api/v1/auth/", StringComparison.Ordinal)) return (404, new { });
        if (method == "GET") return (200, Wire(target!));
        if (method is not ("POST" or "PATCH")) return (404, new { });
        if (arm is null || dispatchFence || window is not null || originals != 0)
        { LateRejections.Add("dispatch"); return (409, new { }); }
        originals++;
        string actor = Actor(bearer), request = Guid.NewGuid().ToString();
        var templateMode = Field(body, "templateId");
        var reviewerMode = Field(body, "tokenReviewerJwt");
        var intent = new WorkloadTransitionIntent(method, uri.AbsolutePath, templateMode,
            templateMode == WorkloadTransitionField.Value ? body.GetProperty("templateId").GetString() : null,
            reviewerMode, reviewerMode == WorkloadTransitionField.Value ?
                WorkloadTransitionContract.Hash(body.GetProperty("tokenReviewerJwt").GetString()!) : null,
            body.TryGetProperty("publicKeys", out var keys) && keys.GetArrayLength() == 0);
        bool allowed = actor == Authorities.Administrative || Fault == "denied-accepted";
        // This is an intent fingerprint, never an invented SDK request ID.
        // The actual authenticated ingress owns 'request'. Hash the FULL native
        // body plus action, independently of the SDK's caller-held target hash.
        byte[] exact = new byte[131072]; Copies.Add(exact);
        string fingerprint;
        try
        {
            using var stream = new MemoryStream(exact, writable: true);
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartArray();
                writer.WriteStringValue((method == "POST" ? "attach-" : "patch-") +
                    (uri.AbsolutePath.Contains("kubernetes", StringComparison.Ordinal) ? "kubernetes" : "oidc"));
                body.WriteTo(writer); writer.WriteEndArray();
            }
            fingerprint = Convert.ToHexString(SHA256.HashData(exact.AsSpan(0, checked((int)stream.Position))));
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
        Ingress.Add(new(Event("ingress", arm), request, actor, issuance.Target.Identity, method, uri.AbsolutePath,
            intent, null, null, allowed, Fault == "intent-hash" ? "unrelated-intent" : fingerprint));
        if (!allowed) return (403, new { });
        // No accepted-empty response is manufactured by this fixture.
        if (intent.EmptyKeys) return (400, new { });
        var previous = target!;
        var changed = previous;
        if (method == "POST") changed = issuance.TemplateConfigurationB with { Template = null, Reviewer = null };
        if (templateMode == WorkloadTransitionField.Value && intent.TemplateId == issuance.TemplateB)
            changed = issuance.TemplateConfigurationB;
        else if (templateMode == WorkloadTransitionField.Null) changed = changed with { Template = null };
        if (reviewerMode == WorkloadTransitionField.Value)
        {
            string credential = body.GetProperty("tokenReviewerJwt").GetString()!;
            string? reviewer = reviewerCredentials.SingleOrDefault(p => p.Value == credential).Key;
            if (reviewer is null) return (400, new { });
            changed = changed with { Reviewer = reviewer, PublicKey = issuance.TemplateConfigurationB.PublicKey };
        }
        if (reviewerMode == WorkloadTransitionField.Null) changed = changed with { Reviewer = null };
        changed = changed with { Attached = true, Revision = "target-1" };
        if (Fault == "template-copy-unchanged")
            changed = changed with { PublicKey = previous.PublicKey, Subject = previous.Subject, Reviewer = previous.Reviewer };
        if (Fault == "partial") changed = changed with { Audience = "partial-audience" };
        if (Fault is not ("ignored-mutation" or "lost-nonapplied" or "source-echo"))
        {
            target = changed;
            Storage.Add(new(Event("storage", arm), request, issuance.Target.Identity, previous.Revision, changed));
        }
        if (Fault == "borrowed-mutated") borrowed = [baselineBorrowed[0] with { Revision = "damaged" }];
        return (200, Wire(changed)); // an echo never supplies independent evidence
    }
    private static WorkloadTransitionField Field(JsonElement input, string name) =>
        !input.TryGetProperty(name, out var value) ? WorkloadTransitionField.Omitted :
        value.ValueKind == JsonValueKind.Null ? WorkloadTransitionField.Null : WorkloadTransitionField.Value;
    private object Wire(WorkloadTransitionConfiguration config)
    {
        var row = new Dictionary<string, object?>
        {
            ["id"] = issuance!.Target.Identity,
            ["identityId"] = issuance.Target.Identity,
            ["createdAt"] = "2040-01-01T00:00:00Z",
            ["updatedAt"] = "2040-01-01T00:00:00Z",
            ["accessTokenTTL"] = 600,
            ["accessTokenMaxTTL"] = 1800,
            ["accessTokenNumUsesLimit"] = 2000,
            ["templateId"] = config.Template,
            ["caCert"] = ""
        };
        bool kube = owner!.Operation.Contains("Kubernetes", StringComparison.Ordinal);
        if (kube)
        {
            row["allowedNames"] = config.Subject; row["allowedNamespaces"] = "workload";
            row["allowedAudience"] = config.Audience; row["kubernetesHost"] = Origin.AbsoluteUri + "review";
            row["gatewayId"] = null; row["gatewayPoolId"] = null; row["tokenReviewMode"] = "api";
            row["verifyTlsCertificate"] = true; row["isTokenReviewerJwtTemplateSourced"] = config.Template is not null;
            // Deliberately omit encrypted reviewer readback: not a semantic oracle.
        }
        else
        {
            row["oidcDiscoveryUrl"] = Origin.AbsoluteUri + ".well-known/openid-configuration";
            row["boundIssuer"] = config.Issuer; row["boundAudiences"] = config.Audience; row["boundSubject"] = config.Subject;
        }
        return new Dictionary<string, object> { [kube ? "identityKubernetesAuth" : "identityOidcAuth"] = row };
    }
    private async Task<(int, object)> LoginAsync(Uri uri, JsonElement body)
    {
        string identity = body.GetProperty("identityId").GetString()!, jwt = body.GetProperty("jwt").GetString()!;
        WorkloadTransitionConfiguration config;
        string request = Guid.NewGuid().ToString(), selectedWindow, reviewer, credential, proofHash = WorkloadTransitionContract.Hash(jwt);
        bool kube = uri.AbsolutePath.Contains("kubernetes", StringComparison.Ordinal);
        lock (Gate)
        {
            if (window is null || issuance is null || creationFence) return (403, new { });
            selectedWindow = window;
            config = identity == issuance.Target.Identity ? target! : identity == issuance.Control.Identity ? control! : target! with { Attached = false };
            reviewer = config.Reviewer ?? "client-proof";
            if (Fault == "wrong-reviewer" && kube) reviewer = issuance.ReviewerA;
            if (Fault == "fallback-reviewer" && kube) reviewer = "client-proof";
            credential = reviewer == "client-proof" ? jwt : reviewerCredentials[reviewer];
        }
        bool valid;
        string reviewId;
        if (kube)
        {
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new { request, identity, jwt, config, window = selectedWindow },
                WorkloadTransitionContract.Options); Copies.Add(bytes);
            try
            {
                using var message = new HttpRequestMessage(HttpMethod.Post, new Uri(Origin, "review"));
                message.Headers.Authorization = new("Bearer", credential);
                message.Content = new ByteArrayContent(bytes);
                using var response = await reviewerHttp.SendAsync(message, shutdown.Token);
                byte[] payload = await response.Content.ReadAsByteArrayAsync(shutdown.Token); Copies.Add(payload);
                try
                {
                    using var parsed = JsonDocument.Parse(payload);
                    valid = parsed.RootElement.GetProperty("allowed").GetBoolean();
                    reviewId = parsed.RootElement.GetProperty("eventId").GetString()!;
                }
                finally { CryptographicOperations.ZeroMemory(payload); }
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        else
        {
            lock (Gate)
            {
                valid = config.Attached && Verify(jwt, config.PublicKey, config.Issuer, config.Audience, config.Subject);
                var review = new WorkloadTransitionReview(Event("reviewer", selectedWindow), request, identity,
                    config.Revision, proofHash, "oidc-signature", WorkloadTransitionContract.Hash(config.PublicKey), valid);
                Reviews.Add(review); reviewId = review.Event.Id;
            }
        }
        lock (Gate)
        {
            if (creationFence || window != selectedWindow) return (403, new { });
            Ingress.Add(new(Event("ingress", selectedWindow), request, identity, identity, "POST", uri.AbsolutePath,
                null, proofHash, config.Revision, valid));
            if (!valid) return (403, new { });
            string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)), id = Guid.NewGuid().ToString();
            Enroll("token", id); Create("token", id);
            string principal = Fault == "wrong-issued-principal" ? issuance!.Control.Identity : identity;
            tokens.Add(token, (principal, id));
            IssuedTokens.Add(new(Event("issuance", selectedWindow), request,
                Fault == "issuer-join" ? "unrelated-review" : reviewId, principal, config.Revision,
                WorkloadTransitionContract.Hash(token), id));
            return (200, new { accessToken = token, tokenType = "Bearer", expiresIn = 600, accessTokenMaxTTL = 1800 });
        }
    }
    private (int, object) Review(JsonElement body, string credential)
    {
        string request = body.GetProperty("request").GetString()!, identity = body.GetProperty("identity").GetString()!;
        string jwt = body.GetProperty("jwt").GetString()!, selectedWindow = body.GetProperty("window").GetString()!;
        var config = body.GetProperty("config").Deserialize<WorkloadTransitionConfiguration>(WorkloadTransitionContract.Options)!;
        string? reviewer = reviewerCredentials.SingleOrDefault(p => p.Value == credential).Key;
        string publicKey = reviewer == issuance!.ReviewerA ? issuance.TemplateConfigurationA.PublicKey :
            reviewer == issuance.ReviewerB ? issuance.TemplateConfigurationB.PublicKey : config.PublicKey;
        bool client = reviewer is null && credential == jwt;
        bool allowed = config.Attached && (reviewer is not null || client) &&
            Verify(jwt, publicKey, config.Issuer, config.Audience, config.Subject);
        var fact = new WorkloadTransitionReview(Event("reviewer", selectedWindow), request, identity, config.Revision,
            WorkloadTransitionContract.Hash(jwt), reviewer ?? (client ? "client-proof" : "unknown"),
            WorkloadTransitionContract.Hash(credential), allowed);
        Reviews.Add(fact);
        return (200, new { allowed, eventId = fact.Event.Id });
    }
    private (int, object) Read(Uri uri, string bearer)
    {
        if (window is null || issuance is null || creationFence) return (403, new { });
        var query = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(v => v.Split('=', 2)).ToDictionary(v => v[0], v => Uri.UnescapeDataString(v[1]));
        string project = query.GetValueOrDefault("projectId") ?? "", key = Uri.UnescapeDataString(uri.Segments.Last());
        string actor = Actor(bearer);
        var principal = project == issuance.Target.Project ? issuance.Target : issuance.Control;
        bool allowed = actor == Authorities.Observer || actor == principal.Identity;
        if (Fault == "runtime-fallback" && actor == Authorities.Runtime) allowed = true;
        Access.Add(new(Event("access", window), Guid.NewGuid().ToString(), WorkloadTransitionContract.Hash(bearer),
            actor, project, key, allowed));
        if (!allowed) return (403, new { });
        return (200, new
        {
            secret = new
            {
                id = Guid.NewGuid().ToString(),
                secretKey = principal.CanaryKey,
                secretValue = principal.CanaryValue,
                secretValueHidden = false,
                version = 1,
                type = "shared",
                environment = "witness",
                secretPath = "/",
                projectId = project
            }
        });
    }
    private static string Sign(RSA key, string issuer, string audience, string subject, string nonce)
    {
        string header = Base64("{\"alg\":\"RS256\",\"typ\":\"JWT\"}"u8.ToArray());
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new
        { iss = issuer, aud = audience, sub = subject, jti = nonce, iat = 2208988800L, exp = 2208992400L });
        byte[] data = Encoding.ASCII.GetBytes(header + "." + Base64(payload));
        try { return Encoding.ASCII.GetString(data) + "." + Base64(key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)); }
        finally { CryptographicOperations.ZeroMemory(payload); CryptographicOperations.ZeroMemory(data); }
    }
    private static bool Verify(string jwt, string pem, string issuer, string audience, string subject)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3) return false;
        byte[] data = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), signature = Decode(parts[2]), payload = Decode(parts[1]);
        try
        {
            using var key = RSA.Create(); key.ImportFromPem(pem);
            if (!key.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) return false;
            using var claims = JsonDocument.Parse(payload);
            var value = claims.RootElement;
            return value.GetProperty("iss").GetString() == issuer && value.GetProperty("aud").GetString() == audience &&
                value.GetProperty("sub").GetString() == subject && value.GetProperty("iat").GetInt64() <= 2208988800L &&
                value.GetProperty("exp").GetInt64() > 2208988800L;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data); CryptographicOperations.ZeroMemory(signature);
            CryptographicOperations.ZeroMemory(payload);
        }
    }
    private static string Base64(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/').PadRight((value.Length + 3) / 4 * 4, '='));
    internal Task DrainAsync(CancellationToken token) => Task.WhenAll(connections).WaitAsync(token);

    public async ValueTask DisposeAsync()
    {
        shutdown.Cancel(); listener.Stop();
        await accept; await Task.WhenAll(connections);
        foreach (var key in issuerKeys.Values) key.Dispose();
        reviewerHttp.Dispose(); shutdown.Dispose();
    }
}
