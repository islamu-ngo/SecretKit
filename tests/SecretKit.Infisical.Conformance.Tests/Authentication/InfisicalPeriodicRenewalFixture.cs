using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// An independently journaled controlled provider. Actual public SDK traffic
// reaches this socket; source facts are read from backend rows and request work,
// never from trial/effect expectations. This is not native qualification.
internal sealed class InfisicalPeriodicRenewalFixture : IAsyncDisposable
{
    internal static readonly DateTimeOffset Epoch = new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero);
    internal static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    { IgnoreReadOnlyProperties = false };
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource terminal = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Dictionary<string, Credential> credentials = new(StringComparer.Ordinal);
    private bool armed;
    private bool fenced;
    private bool suppressResponse;
    private string selected = "";
    private PeriodicRenewalRoot? root;
    private Credential? captured;
    private string window = "";
    internal TaskCompletionSource Arrived { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal ManualClock Clock { get; } = new(Epoch.AddSeconds(20));
    internal Uri Origin { get; }
    internal string Mode { get; }
    internal string Variant { get; }
    internal InfisicalPeriodicRenewalFixtureSource Source { get; }
    internal List<RequestEntry> Requests { get; } = [];
    internal List<CommitEntry> Commits { get; } = [];
    internal List<(string Row, string Key, bool Accepted)> Reads { get; } = [];
    internal List<string> Terminals { get; } = [];
    internal int ForeignRequests { get; private set; }
    internal bool BorrowedPreserved => credentials.ContainsKey("runtime") && credentials.ContainsKey("denied") &&
        credentials["runtime"].Identity == "borrowed-identity" && credentials["runtime"].CanRead &&
        credentials["denied"].Identity == "denied-identity" && !credentials["denied"].CanRead;
    internal bool Fenced => fenced;
    internal bool OriginalTerminal => Requests.Count == 0 || terminal.Task.IsCompletedSuccessfully;
    internal int PendingWork => OriginalTerminal ? 0 : 1;
    internal int CapturedResources => credentials.Values.Count(c => c.Owned);
    internal PeriodicRenewalLifetime Baseline { get; }
    internal PeriodicRenewalLifetime Current => credentials[selected].Lifetime;
    internal string SelectedHandle => credentials[selected].Handle;
    internal Credential? Captured => captured;
    internal string RequestId => Requests.Count == 0 ? "" : Requests[0].RequestId;
    internal string Window => window;

    internal sealed record RequestEntry(string RequestId, string Window, string Nonce,
        string Row, string Identity, string CredentialHandle);
    internal sealed record CommitEntry(string RequestId, string Row, DateTimeOffset Before,
        DateTimeOffset After, string CapturedRow);
    internal sealed class Credential(string row, string identity, SecretMaterial material,
        PeriodicRenewalLifetime lifetime, bool canRead, bool owned) : IDisposable
    {
        internal string Row { get; } = row;
        internal string Identity { get; } = identity;
        internal string Handle { get; } = Guid.NewGuid().ToString("N");
        internal SecretMaterial Material { get; } = material;
        internal PeriodicRenewalLifetime Lifetime { get; set; } = lifetime;
        internal bool CanRead { get; } = canRead;
        internal bool Owned { get; } = owned;
        public void Dispose() => Material.Dispose();
    }

    internal InfisicalPeriodicRenewalFixture(string variant = "lifetime.Finite", string mode = "good")
    {
        Variant = variant;
        Mode = mode;
        bool periodic = variant.StartsWith("lifetime.Periodic.", StringComparison.Ordinal);
        Baseline = new(Epoch, Epoch.AddSeconds(60),
            variant == "lifetime.Unknown.recovery-required" ? InfisicalTokenLifetime.Unknown :
                periodic ? InfisicalTokenLifetime.Periodic : InfisicalTokenLifetime.Finite,
            periodic ? TimeSpan.Zero : TimeSpan.FromSeconds(120),
            periodic ? TimeSpan.FromSeconds(60) : null,
            variant == "lifetime.Periodic.absolute-limit" ? Epoch.AddSeconds(120) : null);
        credentials.Add("runtime", new("runtime-row", "borrowed-identity",
            SecretMaterial.FromText("runtime"), Baseline, true, false));
        credentials.Add("denied", new("denied-row", "denied-identity",
            SecretMaterial.FromText("denied"), Baseline, false, false));
        Source = new(this);
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        accept = AcceptAsync();
    }

    internal InfisicalPeriodicTokenSessionEffects.SessionInput SessionInput() => new(
        new("project", "project", "env", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "/borrowed"),
        new()
        {
            OriginalIssuedAt = Baseline.OriginalIssuedAt,
            ExpiresAt = Baseline.ExpiresAt,
            Lifetime = Baseline.Lifetime,
            ReportedMaximumTtl = Baseline.ReportedMaximumTtl,
            Period = Baseline.Period,
            AbsoluteLifetimeLimit = Baseline.AbsoluteLifetimeLimit
        }, 10, 15, Variant == "session.recovery-required", "canary-value");

    internal PeriodicRenewalInput Input(bool denied = false) => new("controlled-deployment",
        "periodic-original-source", "controlled-epoch", PeriodicRenewalSourceKind.ControlledFixture,
        denied ? "denied-identity" : "borrowed-identity", denied ? "denied-row" : "runtime-row",
        "private-capability", "allowed", "forbidden");

    internal Credential Open(PeriodicRenewalRoot value, string material, string capability)
    {
        lock (gate)
        {
            if (root is not null || capability != "private-capability" ||
                !credentials.TryGetValue(material, out var credential) ||
                value.TokenRow != credential.Row || value.IdentityId != credential.Identity ||
                value.Deployment != "controlled-deployment" || value.Epoch != "controlled-epoch" ||
                value.Source != PeriodicRenewalSourceKind.ControlledFixture)
                throw new InvalidOperationException("fixture-binding");
            root = value;
            selected = material;
            return credential;
        }
    }

    internal string Arm()
    {
        lock (gate)
        {
            if (armed || root is null || fenced) throw new InvalidOperationException("fixture-arm");
            armed = true;
            return window = Guid.NewGuid().ToString("N");
        }
    }

    internal async ValueTask FenceAsync(CancellationToken token)
    {
        lock (gate)
        {
            fenced = true;
            suppressResponse = true;
            release.TrySetResult();
        }
        if (Requests.Count != 0) await terminal.Task.WaitAsync(token);
    }

    internal bool CloseOwned()
    {
        lock (gate)
        {
            foreach (var key in credentials.Where(p => p.Value.Owned).Select(p => p.Key).ToArray())
            {
                credentials[key].Dispose();
                credentials.Remove(key);
            }
            captured = null;
            return BorrowedPreserved && CapturedResources == 0;
        }
    }

    internal Credential? Find(string material)
    {
        lock (gate) return credentials.GetValueOrDefault(material);
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

    private async Task ServeAsync(TcpClient socket)
    {
        bool original = false;
        byte[] headers = new byte[32768];
        byte[] body = [];
        byte[] response = [];
        using (socket)
        {
            try
            {
                var stream = socket.GetStream();
                int count = 0;
                while (count < headers.Length)
                {
                    if (await stream.ReadAsync(headers.AsMemory(count, 1), shutdown.Token) == 0) return;
                    count++;
                    if (count >= 4 && headers.AsSpan(count - 4, 4).SequenceEqual("\r\n\r\n"u8)) break;
                }
                string[] lines = Encoding.ASCII.GetString(headers, 0, count).Split("\r\n");
                string[] request = lines[0].Split(' ');
                string credentialText = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?
                    .Split(' ').Last() ?? "";
                int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?
                    .Split(':')[1] ?? "0");
                if (length is < 0 or > 65536) throw new InvalidOperationException("fixture-budget");
                body = new byte[length];
                await stream.ReadExactlyAsync(body, shutdown.Token);
                int status;
                object payload;
                var uri = new Uri(Origin, request[1]);
                if (uri.AbsolutePath == "/api/v1/auth/token/renew" && request[0] == "POST")
                {
                    using var json = JsonDocument.Parse(body);
                    string supplied = json.RootElement.GetProperty("accessToken").GetString()!;
                    Credential? credential;
                    lock (gate)
                    {
                        credential = credentials.GetValueOrDefault(supplied);
                        if (!armed || fenced || supplied != selected || Requests.Count != 0)
                        {
                            ForeignRequests++;
                            credential = null;
                        }
                        else
                        {
                            original = true;
                            Requests.Add(new(Guid.NewGuid().ToString("N"), window, root!.Nonce,
                                credential!.Row, credential.Identity, credential.Handle));
                        }
                    }
                    if (!original) { status = 403; payload = new { }; }
                    else
                    {
                        if (root!.Boundary == PeriodicRenewalBoundary.RequestCaptured)
                        {
                            Arrived.TrySetResult();
                            await release.Task.WaitAsync(shutdown.Token);
                        }
                        lock (gate)
                        {
                            bool apply = credential!.CanRead &&
                                (root.Boundary != PeriodicRenewalBoundary.RequestCaptured ||
                                    Mode is "cancel-applied" or "partial") && Mode != "non-applied";
                            if (apply)
                            {
                                var before = credential.Lifetime.ExpiresAt;
                                var after = Clock.GetUtcNow().AddSeconds(60);
                                if (credential.Lifetime.AbsoluteLifetimeLimit is { } limit && after > limit) after = limit;
                                credential.Lifetime = credential.Lifetime with { ExpiresAt = after };
                                var replacement = Mode == "same-credential" ? credential :
                                    new Credential("replacement-row", credential.Identity,
                                        SecretMaterial.FromText("replacement-" + Guid.NewGuid().ToString("N")),
                                        credential.Lifetime, Mode != "replacement-denied", true);
                                if (!ReferenceEquals(replacement, credential))
                                    credentials.Add(replacement.Material.Reveal(), replacement);
                                captured = replacement;
                                Commits.Add(new(RequestId, credential.Row, before, after, replacement.Row));
                                payload = new
                                {
                                    accessToken = replacement.Material.Reveal(),
                                    accessTokenMaxTTL = replacement.Lifetime.ReportedMaximumTtl.TotalSeconds,
                                    expiresIn = (after - Clock.GetUtcNow()).TotalSeconds,
                                    tokenType = "Bearer"
                                };
                                status = 200;
                            }
                            else { status = 403; payload = new { }; }
                        }
                        if (root.Boundary == PeriodicRenewalBoundary.ResponseWithheld)
                        {
                            Arrived.TrySetResult();
                            await release.Task.WaitAsync(shutdown.Token);
                        }
                        lock (gate) if (suppressResponse) return;
                    }
                }
                else if (uri.AbsolutePath.StartsWith("/api/v4/secrets/", StringComparison.Ordinal) && request[0] == "GET")
                {
                    string key = Uri.UnescapeDataString(uri.AbsolutePath.Split('/').Last());
                    lock (gate)
                    {
                        var credential = credentials.GetValueOrDefault(credentialText);
                        bool accepted = key == "allowed" && (credentialText == "observer" ||
                            credential is { CanRead: true } && credential.Lifetime.ExpiresAt > Clock.GetUtcNow());
                        Reads.Add((credential?.Row ?? credentialText, key, accepted));
                        status = accepted ? 200 : 403;
                        payload = accepted ? new
                        {
                            secret = new
                            {
                                secretKey = key,
                                secretValue = "canary-value",
                                secretValueHidden = false,
                                version = 1
                            }
                        } : new { };
                    }
                }
                else { status = 404; payload = new { }; }
                response = JsonSerializer.SerializeToUtf8Bytes(payload);
                await stream.WriteAsync(Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"),
                    shutdown.Token);
                await stream.WriteAsync(response, shutdown.Token);
            }
            catch (IOException) { }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            finally
            {
                CryptographicOperations.ZeroMemory(headers);
                CryptographicOperations.ZeroMemory(body);
                CryptographicOperations.ZeroMemory(response);
                if (original)
                {
                    lock (gate) Terminals.Add(RequestId);
                    terminal.TrySetResult();
                }
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        release.TrySetResult();
        shutdown.Cancel();
        listener.Stop();
        await accept;
        await Task.WhenAll(connections);
        foreach (var credential in credentials.Values) credential.Dispose();
        Source.Dispose();
        shutdown.Dispose();
    }

    internal sealed class ManualClock(DateTimeOffset now) : TimeProvider
    {
        private long ticks = now.UtcTicks;
        public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref ticks), TimeSpan.Zero);
        internal void AdvanceTo(DateTimeOffset value) => Interlocked.Exchange(ref ticks, value.UtcTicks);
    }
}
