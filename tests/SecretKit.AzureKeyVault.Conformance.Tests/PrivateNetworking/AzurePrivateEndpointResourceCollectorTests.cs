using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.Core;
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.PrivateEndpointResourceCollector;
using R = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzurePrivateEndpointResourceCollectorTests
{
    private const string Subscription = "11111111-1111-1111-1111-111111111111";
    private const string Group = "/subscriptions/" + Subscription + "/resourceGroups/endpoint-group";
    private const string Endpoint = Group + "/providers/Microsoft.Network/privateEndpoints/owned-endpoint";
    private const string Vault = Group + "/providers/Microsoft.KeyVault/vaults/owned-vault";
    private const string Subnet = Group + "/providers/Microsoft.Network/virtualNetworks/borrowed-network/subnets/borrowed-subnet";
    private const string Nic = Group + "/providers/Microsoft.Network/networkInterfaces/owned-nic";
    private const string Origin = "https://management.azure.com";
    private static readonly DateTimeOffset Now = new(2026, 10, 16, 0, 0, 0, TimeSpan.Zero);
    private static readonly R.Limits Bounds = new(65536, 32768, 4096, 64, 16, TimeSpan.FromSeconds(20));
    private static string NicBody => JsonSerializer.Serialize(new
    {
        id = Nic,
        name = "owned-nic",
        type = "Microsoft.Network/networkInterfaces",
        location = "eastus",
        properties = new { provisioningState = "Succeeded" }
    });

    [Test]
    [Arguments("Approved")]
    [Arguments("Rejected")]
    public async Task StructuralEndpointMatchDoesNotWidenPendingOnlySetupAdmission(string state)
    {
        using var f = new Fixture();
        f.Body = f.Body.Replace("\"Pending\"", "\"" + state + "\"", StringComparison.Ordinal);
        var result = await f.Read();
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.ManualConnectionState).IsEqualTo(state);
        await Assert.That(result.MatchesDeclarationConfiguration).IsTrue();
        await Assert.That(result.MatchesDeclaration).IsFalse();
        await Assert.That(result.OwnershipProven || result.PrincipalQualified || result.EgressQualified).IsFalse();
        await Cleared(f);
    }

    [Test]
    [Arguments("subnet")]
    [Arguments("owner")]
    [Arguments("nic")]
    [Arguments("denied")]
    public async Task StructuralEndpointMatchStillRequiresAllNativeConfiguration(string fault)
    {
        using var f = new Fixture();
        f.Body = f.Body.Replace("\"Pending\"", "\"Approved\"", StringComparison.Ordinal);
        if (fault == "subnet") f.Body = f.Body.Replace(Subnet, Subnet + "-foreign", StringComparison.Ordinal);
        if (fault == "owner") f.Body = f.Body.Replace("controlled-owner", "foreign-owner", StringComparison.Ordinal);
        if (fault == "nic") f.Body = f.Body.Replace(Nic, Nic + "-foreign", StringComparison.Ordinal);
        if (fault == "denied") { f.Status = 403; f.Body = """{"error":{"code":"Forbidden"}}"""; }
        var result = await f.Read();
        await Assert.That(result.MatchesDeclarationConfiguration || result.MatchesDeclaration).IsFalse();
        await Cleared(f);
    }

    [Test]
    public async Task ManagedNicPresenceIsObservedWithoutEndpointReadinessOrMutationAuthority()
    {
        using var f = new Fixture() { Body = NicBody };
        var result = await f.ReadNic();
        await Assert.That(result.Kind).IsEqualTo(C.ReadKind.NicAbsence);
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.NativeState).IsEqualTo("Succeeded");
        await Assert.That(result.ManualConnectionState).IsNull();
        await Assert.That(result.MatchesDeclaration || result.OwnershipProven || result.NativeSettlementProven).IsFalse();
        await Assert.That(f.Requests.Single()).IsEqualTo("GET " + Origin + Nic + "?api-version=" + C.Revision);
        await Cleared(f);
    }

    [Test]
    public async Task OnlyAConcreteDeclaredNicReadCanEstablishItsObservedAbsence()
    {
        using var f = new Fixture() { Status = 404, Body = """{"error":{"code":"NotFound","message":"controlled"}}""" };
        var result = await f.ReadNic();
        await Assert.That(result.Kind).IsEqualTo(C.ReadKind.NicAbsence);
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Absent);
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.MatchesDeclaration || result.OwnershipProven).IsFalse();
        await Assert.That(f.Requests.Single()).IsEqualTo("GET " + Origin + Nic + "?api-version=" + C.Revision);
    }

    [Test]
    public async Task EndpointAbsenceCannotBeImportedAsManagedNicAbsence()
    {
        using var f = new Fixture() { Status = 404, Body = """{"error":{"code":"NotFound","message":"controlled"}}""" };
        var endpoint = await f.Read();
        f.Status = 200;
        f.Body = NicBody;
        await Assert.That(() => f.Source.ArmNicAbsence(f.Binding)).Throws<InvalidOperationException>();
        var reader = new C(new("independent-nic-reader", f.Credential, f.Transport), Bounds, f.Clock);
        var window = reader.ArmNicAbsence(f.Binding);
        await Assert.That(async () => await f.Source.CollectAsync(window, f.Binding)).Throws<InvalidOperationException>();
        var nic = await reader.CollectAsync(window, f.Binding);
        await Assert.That(endpoint.Kind).IsEqualTo(C.ReadKind.Endpoint);
        await Assert.That(endpoint.ResourceStatus).IsEqualTo(SecretStatus.Absent);
        await Assert.That(nic.Kind).IsEqualTo(C.ReadKind.NicAbsence);
        await Assert.That(nic.ResourceStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(nic.MatchesDeclaration).IsFalse();
        await Assert.That(f.Requests.Count).IsEqualTo(2);
    }

    [Test]
    public async Task DeniedManagedNicReadIsNotAbsenceOrEndpointReadiness()
    {
        using var f = new Fixture() { Status = 403, Body = """{"error":{"code":"Forbidden","message":"controlled"}}""" };
        var result = await f.ReadNic();
        await Assert.That(result.Kind).IsEqualTo(C.ReadKind.NicAbsence);
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Denied);
        await Assert.That(result.MatchesDeclaration).IsFalse();
    }

    [Test]
    [Arguments("endpoint-body")]
    [Arguments("type")]
    [Arguments("location")]
    [Arguments("name")]
    public async Task ManagedNicReadRequiresItsOwnExactNativeIdentity(string fault)
    {
        using var f = new Fixture();
        if (fault != "endpoint-body")
        {
            var body = JsonNode.Parse(NicBody)!;
            body[fault] = "foreign";
            f.Body = body.ToJsonString();
        }
        var result = await f.ReadNic();
        await Assert.That(result.Kind).IsEqualTo(C.ReadKind.NicAbsence);
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(result.ResponseComplete || result.MatchesDeclaration).IsFalse();
        await Assert.That(result.NativeState).IsNull();
        await Cleared(f);
    }

    [Test]
    public async Task UnknownNicStateIsObservedWithoutInventingAbsenceOrSettlement()
    {
        using var f = new Fixture() { Body = NicBody.Replace("Succeeded", "future-state", StringComparison.Ordinal) };
        var result = await f.ReadNic();
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.NativeState).IsEqualTo("future-state");
        await Assert.That(result.MatchesDeclaration || result.NativeSettlementProven).IsFalse();
    }

    [Test]
    public async Task UnsafeManagedNicCoordinatesCannotReachAnyNativeAuthority()
    {
        using var f = new Fixture() { Body = NicBody };
        await Assert.That(() => f.Source.ArmNicAbsence(f.Binding with { NicId = Origin + Nic })).Throws<ArgumentException>();
        await Assert.That(f.Credential.Scopes.Count + f.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task OriginalManagedNicWindowCannotBeReplayedOrUseCopiedBinding()
    {
        using var f = new Fixture() { Body = NicBody };
        var window = f.Source.ArmNicAbsence(f.Binding);
        await Assert.That(async () => await f.Source.CollectAsync(window, f.Binding with { })).Throws<InvalidOperationException>();
        var result = await f.Source.CollectAsync(window, f.Binding);
        await Assert.That(result.Kind).IsEqualTo(C.ReadKind.NicAbsence);
        await Assert.That(async () => await f.Source.CollectAsync(window, f.Binding)).Throws<InvalidOperationException>();
        await Assert.That(f.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task ExactNativeEndpointMetadataMatchesDeclarationWithoutGrantingOwnership()
    {
        using var f = new Fixture();
        var result = await f.Read();
        await Assert.That(result.Kind).IsEqualTo(C.ReadKind.Endpoint);
        await Assert.That(result.ResponseComplete && result.MatchesDeclaration).IsTrue();
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.NativeState).IsEqualTo("Succeeded");
        await Assert.That(result.ManualConnectionState).IsEqualTo("Pending");
        await Assert.That(result.Binding).IsEqualTo(f.Binding);
        await Assert.That(result.WindowId != Guid.Empty).IsTrue();
        await Assert.That(result.Identity).IsEqualTo("independent-endpoint-reader");
        await Assert.That(result.NativeRequestId).IsEqualTo("endpoint-native-read");
        await Assert.That(f.Requests.Single()).IsEqualTo("GET " + Origin + Endpoint + "?api-version=" + C.Revision);
        await Assert.That(f.Credential.Scopes.Single()).IsEqualTo(Origin + "/.default");
        await Assert.That(result.OwnershipProven || result.NativeSettlementProven ||
            result.PrincipalQualified || result.EgressQualified).IsFalse();
        await Assert.That(JsonSerializer.Serialize(result)).IsEqualTo("{}");
        await Assert.That(result.ToString()!.Contains(Subscription, StringComparison.Ordinal)).IsFalse();
        await Cleared(f);
    }

    [Test]
    [Arguments("value")]
    [Arguments("Location")]
    [Arguments("error")]
    [Arguments("nextLink")]
    [Arguments("Properties")]
    public async Task OrdinaryTagNamesDoNotBecomeResponseSchemaFields(string name)
    {
        using var f = new Fixture();
        var body = JsonNode.Parse(f.Body)!;
        body["tags"]![name] = "ordinary-tag";
        f.Body = body.ToJsonString();
        var result = await f.Read();
        await Assert.That(result.ResponseComplete && result.MatchesDeclaration).IsTrue();
        await Assert.That(result.NativeState).IsEqualTo("Succeeded");
        await Cleared(f);
    }

    [Test]
    [Arguments("value")]
    [Arguments("Value")]
    public async Task TagDictionaryExceptionDoesNotAdmitDuplicateKeys(string second)
    {
        using var f = new Fixture();
        f.Body = f.Body.Replace("\"tags\":{", "\"tags\":{\"value\":\"first\",\"" + second + "\":\"second\",", StringComparison.Ordinal);
        var result = await f.Read();
        await Assert.That(result.ResponseComplete || result.MatchesDeclaration).IsFalse();
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Unavailable);
        await Cleared(f);
    }

    [Test]
    [Arguments("connection")]
    [Arguments("subnet")]
    [Arguments("nic")]
    [Arguments("target")]
    [Arguments("owner")]
    [Arguments("location")]
    [Arguments("group")]
    public async Task DifferentNativeDependenciesAreFactsNotAdoptedResources(string fault)
    {
        using var f = new Fixture();
        var body = JsonNode.Parse(f.Body)!;
        var p = body["properties"]!;
        if (fault == "connection") p["manualPrivateLinkServiceConnections"]![0]!["name"] = "foreign-connection";
        if (fault == "subnet") p["subnet"]!["id"] = Subnet + "-foreign";
        if (fault == "nic") p["networkInterfaces"]![0]!["id"] = Nic + "-foreign";
        if (fault == "target") p["manualPrivateLinkServiceConnections"]![0]!["properties"]!["privateLinkServiceId"] = Vault + "-foreign";
        if (fault == "owner") body["tags"]!["fixture-owner"] = "foreign-owner";
        if (fault == "location") body["location"] = "westus";
        if (fault == "group") p["manualPrivateLinkServiceConnections"]![0]!["properties"]!["groupIds"]![0] = "foreign-group";
        f.Body = body.ToJsonString();
        var result = await f.Read();
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.MatchesDeclaration || result.OwnershipProven).IsFalse();
        await Assert.That(f.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("manual")]
    [Arguments("nic")]
    [Arguments("automatic")]
    public async Task AmbiguousOrAutomaticEndpointConnectionsCannotMatch(string fault)
    {
        using var f = new Fixture();
        var body = JsonNode.Parse(f.Body)!;
        var p = body["properties"]!;
        string field = fault == "nic" ? "networkInterfaces" : "manualPrivateLinkServiceConnections";
        if (fault == "automatic") p["privateLinkServiceConnections"] = p[field]!.DeepClone();
        else p[field]!.AsArray().Add(p[field]![0]!.DeepClone());
        f.Body = body.ToJsonString();
        var result = await f.Read();
        await Assert.That(result.MatchesDeclaration).IsFalse();
        await Assert.That(result.OwnershipProven || result.NativeSettlementProven).IsFalse();
    }

    [Test]
    [Arguments("tags")]
    [Arguments("manualPrivateLinkServiceConnections")]
    [Arguments("subnet")]
    public async Task MissingNativeConfigurationCannotBecomePreparationReadiness(string field)
    {
        using var f = new Fixture();
        var body = JsonNode.Parse(f.Body)!;
        if (field == "tags") body.AsObject().Remove(field);
        else body["properties"]!.AsObject().Remove(field);
        f.Body = body.ToJsonString();
        var result = await f.Read();
        await Assert.That(result.MatchesDeclaration || result.OwnershipProven).IsFalse();
    }

    [Test]
    [Arguments("Updating", "Pending")]
    [Arguments("Failed", "Pending")]
    [Arguments("future-state", "Pending")]
    [Arguments("Succeeded", "Approved")]
    public async Task RequestedPreparationDoesNotReplaceNativeProvisioningOrManualApproval(string state, string manual)
    {
        using var f = new Fixture();
        var body = JsonNode.Parse(f.Body)!;
        body["properties"]!["provisioningState"] = state;
        body["properties"]!["manualPrivateLinkServiceConnections"]![0]!["properties"]!["privateLinkServiceConnectionState"]!["status"] = manual;
        f.Body = body.ToJsonString();
        var result = await f.Read();
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.MatchesDeclaration || result.NativeSettlementProven).IsFalse();
    }

    [Test]
    [Arguments("duplicate")]
    [Arguments("case")]
    [Arguments("redirect")]
    [Arguments("nextLink")]
    [Arguments("encoding")]
    [Arguments("foreign-id")]
    public async Task MalformedOrUnboundedEndpointRepliesRemainUnavailable(string fault)
    {
        using var f = new Fixture();
        if (fault == "duplicate") f.Body = f.Body.Insert(1, "\"id\":\"" + Endpoint + "\",");
        if (fault == "case") f.Body = f.Body.Replace("\"properties\"", "\"Properties\"", StringComparison.Ordinal);
        if (fault == "redirect") { f.Status = 302; f.Header = "Location"; }
        if (fault == "nextLink") f.Body = f.Body.Insert(1, "\"nextLink\":\"https://foreign.invalid/next\",");
        if (fault == "encoding") f.Header = "Content-Encoding";
        if (fault == "foreign-id") f.Body = f.Body.Replace(Endpoint, Endpoint + "-foreign", StringComparison.Ordinal);
        var result = await f.Read();
        await Assert.That(result.ResponseComplete || result.MatchesDeclaration).IsFalse();
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Unavailable);
        await Cleared(f);
    }

    [Test]
    [Arguments(404, SecretStatus.Absent)]
    [Arguments(403, SecretStatus.Denied)]
    public async Task NativeErrorCannotGrantEndpointOwnershipOrCompletion(int status, SecretStatus expected)
    {
        using var f = new Fixture() { Status = status, Body = """{"error":{"code":"Controlled","message":"controlled"}}""" };
        var result = await f.Read();
        await Assert.That(result.ResourceStatus).IsEqualTo(expected);
        await Assert.That(result.MatchesDeclaration || result.OwnershipProven || result.NativeSettlementProven).IsFalse();
    }

    [Test]
    public async Task OriginalWindowCannotBeReplayedOrTransferredBetweenSources()
    {
        using var f = new Fixture();
        using var other = new Fixture();
        var window = f.Source.Arm(f.Binding);
        await Assert.That(async () => await other.Source.CollectAsync(window, f.Binding)).Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Source.CollectAsync(window, f.Binding with { })).Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Source.CollectAsync(window, f.Binding with { LeaseId = Guid.NewGuid() }))
            .Throws<InvalidOperationException>();
        var result = await f.Source.CollectAsync(window, f.Binding);
        await Assert.That(result.MatchesDeclaration).IsTrue();
        await Assert.That(async () => await f.Source.CollectAsync(window, f.Binding)).Throws<InvalidOperationException>();
        await Assert.That(f.Requests.Count).IsEqualTo(1);
        await Assert.That(other.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("credential", false)]
    [Arguments("send", false)]
    [Arguments("body", false)]
    [Arguments("credential", true)]
    [Arguments("send", true)]
    [Arguments("body", true)]
    public async Task CancellationDrainsActualNativeBorrowerBeforeClearingResponseStorage(string barrier, bool nic)
    {
        using var f = new Fixture() { Barrier = barrier };
        if (nic) f.Body = NicBody;
        using var cancellation = new CancellationTokenSource();
        var task = (nic ? f.ReadNic(cancellation.Token) : f.Read(cancellation.Token)).AsTask();
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            cancellation.Cancel();
            await f.Canceled.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(task.IsCompleted).IsFalse();
            if (barrier == "body") await Assert.That(f.Buffers.Any(b => b.Any(v => v != 0))).IsTrue();
        }
        finally { f.Resume.TrySetResult(); }
        await Assert.That(async () => await task.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
        await Cleared(f);
    }

    [Test]
    [Arguments(false, false)]
    [Arguments(true, false)]
    [Arguments(false, true)]
    [Arguments(true, true)]
    public async Task ExpiredWindowCannotReachTheCredentialOrTransport(bool monotonic, bool nic)
    {
        using var f = new Fixture();
        var window = nic ? f.Source.ArmNicAbsence(f.Binding) : f.Source.Arm(f.Binding);
        if (monotonic) f.Clock.Ticks = TimeSpan.FromSeconds(21).Ticks;
        else f.Clock.Wall = TimeSpan.FromSeconds(21).Ticks;
        var result = await f.Source.CollectAsync(window, f.Binding);
        await Assert.That(result.Kind).IsEqualTo(nic ? C.ReadKind.NicAbsence : C.ReadKind.Endpoint);
        await Assert.That(result.MatchesDeclaration).IsFalse();
        await Assert.That(f.Credential.Scopes.Count + f.Requests.Count).IsEqualTo(0);
    }

    private static async Task Cleared(Fixture f)
    {
        await Assert.That(f.Buffers.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    [Arguments("response")]
    [Arguments("row")]
    [Arguments("nodes")]
    [Arguments("rows")]
    [Arguments("depth")]
    [Arguments("headers")]
    public async Task NativeEndpointBudgetsFailBeforePublishingMatchingMetadata(string fault)
    {
        using var f = new Fixture();
        if (fault == "response") f.Body = new string('x', 65537);
        if (fault == "row") f.Body = f.Body.Insert(1, "\"padding\":\"" + new string('x', 33000) + "\",");
        if (fault == "nodes") f.Body = f.Body.Insert(1, "\"padding\":[" + string.Join(',', Enumerable.Repeat("0", 4096)) + "],");
        if (fault == "rows") f.Body = f.Body.Insert(1, "\"padding\":[" + string.Join(',', Enumerable.Repeat("{}", 65)) + "],");
        if (fault == "depth") f.Body = f.Body.Insert(1, "\"padding\":" + new string('[', 17) + "0" + new string(']', 17) + ",");
        if (fault == "headers") f.ManyHeaders = true;
        var result = await f.Read();
        await Assert.That(result.ResponseComplete || result.MatchesDeclaration).IsFalse();
        await Assert.That(result.ResourceStatus).IsEqualTo(SecretStatus.Unavailable);
        if (fault != "depth") await Assert.That(result.Failure).IsEqualTo(R.Failure.Budget);
        await Assert.That(result.NativeState).IsNull();
        await Cleared(f);
    }

    [Test]
    [Arguments("endpoint-url")]
    [Arguments("subnet-subscription")]
    [Arguments("nic-group")]
    [Arguments("connection")]
    [Arguments("lease")]
    [Arguments("owner")]
    public async Task InvalidEndpointDeclarationCannotReserveWindowOrUseAuthority(string fault)
    {
        using var f = new Fixture();
        var binding = fault switch
        {
            "endpoint-url" => f.Binding with { EndpointId = Origin + Endpoint },
            "subnet-subscription" => f.Binding with { SubnetId = Subnet.Replace(Subscription, "22222222-2222-2222-2222-222222222222", StringComparison.Ordinal) },
            "nic-group" => f.Binding with { NicId = Nic.Replace("endpoint-group", "foreign-group", StringComparison.Ordinal) },
            "connection" => f.Binding with { ConnectionName = "unsafe/name" },
            "lease" => f.Binding with { LeaseId = Guid.Empty },
            _ => f.Binding with { OwnerTagValue = "\nunsafe" }
        };
        await Assert.That(() => f.Source.Arm(binding)).Throws<ArgumentException>();
        await Assert.That(f.Credential.Scopes.Count + f.Requests.Count).IsEqualTo(0);
        var actual = await f.Read();
        await Assert.That(actual.MatchesDeclaration).IsTrue();
    }

    private sealed class Fixture : IDisposable
    {
        internal readonly C Source;
        internal readonly C.Binding Binding = new(new(Guid.NewGuid(), "controlled-endpoint",
            ManagementOperationEffects.Members[0].Operation, "operation.UpdatePrivateConnection", "selected-contract"),
            Guid.NewGuid(), Endpoint, Vault, Subnet, Nic, "network-side-name", "eastus", "fixture-owner", "controlled-owner");
        internal readonly Credential Credential;
        internal readonly HttpPipelineTransport Transport;
        internal readonly Clock Clock = new();
        internal readonly List<string> Requests = [];
        internal readonly List<byte[]> Buffers = [];
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Resume = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Canceled = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly HttpClient http;
        internal string? Barrier, Header;
        internal bool ManyHeaders;
        internal int Status = 200;
        internal string Body = JsonSerializer.Serialize(new
        {
            id = Endpoint,
            name = "owned-endpoint",
            type = "Microsoft.Network/privateEndpoints",
            location = "eastus",
            tags = new Dictionary<string, string> { ["fixture-owner"] = "controlled-owner" },
            properties = new
            {
                provisioningState = "Succeeded",
                subnet = new { id = Subnet },
                networkInterfaces = new[] { new { id = Nic } },
                manualPrivateLinkServiceConnections = new[]
                {
                    new
                    {
                        name = "network-side-name",
                        properties = new
                        {
                            privateLinkServiceId = Vault,
                            groupIds = new[] { "vault" },
                            privateLinkServiceConnectionState = new { status = "Pending" }
                        }
                    }
                },
                privateLinkServiceConnections = Array.Empty<object>()
            }
        });

        internal Fixture()
        {
            Credential = new(this);
            http = new(new Handler(async (request, token) =>
            {
                Requests.Add(request.Method + " " + request.RequestUri!.AbsoluteUri);
                if (Barrier == "send") await Pause(token);
                var response = new HttpResponseMessage((HttpStatusCode)Status)
                {
                    Content = new StreamContent(new BodyStream(Encoding.UTF8.GetBytes(Body), this))
                };
                response.Content.Headers.ContentType = new("application/json");
                response.Headers.Add("x-ms-request-id", "endpoint-native-read");
                if (ManyHeaders)
                    for (int i = 0; i < 33; i++) response.Headers.Add("x-extra-" + i, "controlled");
                if (Header == "Content-Encoding") response.Content.Headers.ContentEncoding.Add("gzip");
                else if (Header is not null) response.Headers.Add(Header, "https://foreign.invalid/next");
                return response;
            }));
            Transport = new HttpClientTransport(http);
            Source = new(new("independent-endpoint-reader", Credential, Transport), Bounds, Clock);
        }
        internal ValueTask<C.Measurement> Read(CancellationToken token = default) =>
            Source.CollectAsync(Source.Arm(Binding), Binding, token);
        internal ValueTask<C.Measurement> ReadNic(CancellationToken token = default) =>
            Source.CollectAsync(Source.ArmNicAbsence(Binding), Binding, token);
        internal async Task Pause(CancellationToken token)
        {
            using var registration = token.Register(() => Canceled.TrySetResult());
            Entered.TrySetResult();
            await Resume.Task;
        }
        public void Dispose() => http.Dispose();
    }

    private sealed class Credential(Fixture fixture) : TokenCredential
    {
        internal readonly List<string> Scopes = [];
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken token) =>
            throw new InvalidOperationException("controlled-async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken token)
        {
            Scopes.AddRange(context.Scopes);
            if (fixture.Barrier == "credential") await fixture.Pause(token);
            return new AccessToken("controlled-independent-reader", DateTimeOffset.MaxValue);
        }
    }

    private sealed class Clock : TimeProvider
    {
        internal long Ticks, Wall;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Ticks;
        public override DateTimeOffset GetUtcNow() => Now.AddTicks(Wall);
    }

    private sealed class BodyStream(byte[] bytes, Fixture fixture) : MemoryStream(bytes, false)
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var segment) && segment.Array is { } array)
                fixture.Buffers.Add(array);
            if (fixture.Barrier == "body" && !fixture.Resume.Task.IsCompleted)
            {
                buffer.Span[0] = 17;
                await fixture.Pause(token);
            }
            return await base.ReadAsync(buffer, CancellationToken.None);
        }
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) =>
            send(request, token);
    }
}
