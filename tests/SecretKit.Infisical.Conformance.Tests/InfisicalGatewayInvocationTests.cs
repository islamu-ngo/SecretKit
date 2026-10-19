using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalGatewayInvocationTests
{
    private const string Organization = "00000000-0000-0000-0000-000000000001";
    private const string Gateway = "00000000-0000-0000-0000-000000000002";
    private const string Identity = "00000000-0000-0000-0000-000000000003";
    private static readonly DateTimeOffset Baseline = DateTimeOffset.Parse(
        "2026-10-12T00:00:00Z", CultureInfo.InvariantCulture);

    [Test]
    [Arguments("Create", "replay", "effect-mismatch")]
    [Arguments("Get", "replay", "effect-mismatch")]
    [Arguments("Update", "replay", "effect-mismatch")]
    [Arguments("Create", "advance", "observed")]
    [Arguments("Get", "advance", "observed")]
    [Arguments("Update", "advance", "observed")]
    [Arguments("Create", "absent-to-present", "observed")]
    [Arguments("Create", "backwards", "effect-mismatch")]
    [Arguments("Create", "missing-heartbeat", "effect-mismatch")]
    [Arguments("Create", "omitted-heartbeat", "observer-unavailable")]
    [Arguments("Create", "omitted-baseline", "observer-unavailable")]
    [Arguments("Create", "unavailable", "observer-unavailable")]
    [Arguments("GenerateEnrollmentToken", "replay", "effect-mismatch")]
    [Arguments("GenerateEnrollmentToken", "advance", "observed")]
    [Arguments("GenerateEnrollmentToken", "absent-to-present", "observed")]
    [Arguments("GenerateEnrollmentToken", "omitted-heartbeat", "observer-unavailable")]
    public async Task NativeHeartbeatMustWitnessThisInvocation(string operation, string mode, string reason)
    {
        await using var backend = new Backend(mode);
        using NativeEnvironment environment = NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = backend.Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup-token",
            administrative = "administrative-token",
            runtime = "runtime-token",
            observer = "observer-token",
            denied = "denied-token",
            families = new Dictionary<string, object>
            {
                ["C08-IM-GatewayAdministration"] = new
                {
                    scopes = new Dictionary<string, object> { ["local"] = new { organizationId = Organization } }
                }
            }
        }));
        backend.Client = environment.CreateManagementClient();
        string id = "i.management.GatewayAdministrationOperations." + operation;
        var definition = new NativeCaseDefinition(new("Infisical", id,
            operation == "Create" ? "auth.Token" : operation == "Update" ? "name.value" :
            operation == "Get" ? "selector.exact" : "input.organizationId-gatewayId", "local", "independent-effect"),
            InfisicalGovernanceFamilies.Bindings[id].Member);
        var registry = new NativeCaseRegistry();
        InfisicalGovernanceFamilies.Register(registry, environment, [definition], new() { Gateway = backend });
        NativeCaseResult result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None))[0];
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(result.Passed).IsEqualTo(reason == "observed");
        await Assert.That(backend.Exists).IsFalse();
    }

    // The observer can replay credible agent facts (and even enrollment counters).
    // Independent public SDK GETs still read the loopback provider's actual state.
    private sealed class Backend : IAsyncDisposable, IGatewayAgentObserver
    {
        private readonly string mode;
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource stop = new();
        private readonly ConcurrentBag<Task> connections = [];
        private readonly Task accepting;
        private readonly object gate = new();
        private JsonObject? gateway;
        private int issued;
        private int enrolled;
        public Uri Origin { get; }
        public ManagementClient Client { get; set; } = null!;
        public bool Exists { get { lock (gate) return gateway is not null; } }

        public Backend(string mode)
        {
            this.mode = mode;
            listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
            accepting = AcceptAsync();
        }

        private async Task AcceptAsync()
        {
            try
            {
                while (!stop.IsCancellationRequested)
                    connections.Add(HandleAsync(await listener.AcceptTcpClientAsync(stop.Token)));
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            catch (SocketException) when (stop.IsCancellationRequested) { }
        }

        private async Task HandleAsync(TcpClient connection)
        {
            using (connection)
            {
                NetworkStream stream = connection.GetStream();
                var header = new List<byte>();
                byte[] one = new byte[1];
                while (header.Count < 65536)
                {
                    if (await stream.ReadAsync(one, stop.Token) == 0) return;
                    header.Add(one[0]);
                    if (header.Count >= 4 && header[^4] == 13 && header[^3] == 10 &&
                        header[^2] == 13 && header[^1] == 10) break;
                }
                string[] lines = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
                string[] request = lines[0].Split(' ');
                var headers = lines.Skip(1).Select(line => line.Split(':', 2))
                    .ToDictionary(parts => parts[0], parts => parts[1].Trim(), StringComparer.OrdinalIgnoreCase);
                int length = headers.TryGetValue("Content-Length", out string? size) ?
                    int.Parse(size, CultureInfo.InvariantCulture) : 0;
                byte[] bytes = new byte[length];
                await stream.ReadExactlyAsync(bytes, stop.Token);
                JsonObject body = length == 0 ? new() : JsonNode.Parse(bytes)!.AsObject();
                (int status, JsonObject body) reply;
                lock (gate) reply = Respond(request[0], new Uri(Origin, request[1]).AbsolutePath, body);
                byte[] response = Encoding.UTF8.GetBytes(reply.body.ToJsonString());
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {reply.status} Response\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"), stop.Token);
                await stream.WriteAsync(response, stop.Token);
            }
        }

        private (int, JsonObject) Respond(string method, string path, JsonObject body)
        {
            if (method == "POST" && path.EndsWith("/gateways", StringComparison.Ordinal))
            {
                gateway = new()
                {
                    ["id"] = Gateway,
                    ["name"] = body["name"]!.DeepClone(),
                    ["createdAt"] = Baseline.ToString("O"),
                    ["updatedAt"] = Baseline.ToString("O"),
                    ["canRevoke"] = true,
                    ["authMethod"] = new JsonObject { ["method"] = "token", ["config"] = new JsonObject() },
                    ["heartbeat"] = mode == "absent-to-present" ? null : Baseline.ToString("O"),
                    ["identityId"] = Identity,
                    ["directAddress"] = null
                };
                if (mode == "omitted-baseline") gateway.Remove("heartbeat");
            }
            else if (gateway is null) return (404, new());
            else if (method == "POST")
            {
                issued++;
                return (200, new() { ["token"] = "owned-enrollment-token", ["expiresAt"] = "2099-01-01T00:00:00Z" });
            }
            else if (method == "PATCH") gateway["name"] = body["name"]!.DeepClone();
            return (200, gateway!.DeepClone().AsObject());
        }

        public async ValueTask<SecretOutcome<GatewaySummary>> FindOwnedAsync(string organizationId, string name,
            IInfisicalTokenSource observer, CancellationToken token)
        {
            lock (gate)
                if (gateway is null || gateway["name"]!.GetValue<string>() != name)
                    return SecretOutcome<GatewaySummary>.Failure(SecretStatus.Absent);
            using ManagementRequest<GatewaySummary> request = GatewayAdministrationOperations.Get(organizationId, Gateway);
            var authority = new ManagementAuthority(Client.Authority, observer, organizationId);
            return await Client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                cancellationToken: token);
        }

        public ValueTask<GatewayAgentFacts> AuthenticateAsync(string organizationId, GatewaySummary selected,
            IInfisicalTokenSource runtime, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (mode == "unavailable") throw new NativeCaseFailureException("observer-unavailable");
            DateTimeOffset heartbeat = mode == "backwards" ? Baseline.AddSeconds(-1) :
                mode is "advance" or "absent-to-present" or "omitted-baseline" ? Baseline.AddSeconds(1) : Baseline;
            lock (gate)
            {
                gateway!["heartbeat"] = mode == "missing-heartbeat" ? null : heartbeat.ToString("O");
                if (mode == "omitted-heartbeat") gateway.Remove("heartbeat");
            }
            return ValueTask.FromResult(new GatewayAgentFacts(Gateway, Identity, selected.Authentication.Method, heartbeat, 1));
        }

        public ValueTask<GatewayAgentFacts> EnrollAsync(string organizationId, GatewaySummary selected,
            SecretMaterial enrollmentToken, IInfisicalTokenSource runtime, CancellationToken token)
        {
            if (enrollmentToken.Reveal() != "owned-enrollment-token")
                throw new NativeCaseFailureException("effect-mismatch");
            // Counters alone cannot prove that the returned heartbeat belongs to this invocation.
            enrolled++;
            return AuthenticateAsync(organizationId, selected, runtime, token);
        }

        public ValueTask<GatewayEnrollmentFacts> ObserveEnrollmentAsync(string gatewayId, CancellationToken token) =>
            ValueTask.FromResult(new GatewayEnrollmentFacts(gatewayId, issued, enrolled));

        public ValueTask<SecretStatus> RemoveOwnedAsync(string organizationId, string name,
            IInfisicalTokenSource setup, CancellationToken token)
        {
            lock (gate) gateway = null;
            return ValueTask.FromResult(SecretStatus.Success);
        }

        public async ValueTask DisposeAsync()
        {
            await stop.CancelAsync();
            listener.Stop();
            await accepting;
            await Task.WhenAll(connections);
            stop.Dispose();
        }
    }
}
