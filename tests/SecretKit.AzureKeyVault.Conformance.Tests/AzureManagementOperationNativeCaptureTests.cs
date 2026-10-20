using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Capture = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationNativeCapture;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    private const string Subscription = "11111111-1111-1111-1111-111111111111";
    private const string Tenant = "22222222-2222-2222-2222-222222222222";
    private const string Assignment = "33333333-3333-3333-3333-333333333333";
    private const string OperationId = "44444444-4444-4444-4444-444444444444";
    private const string Vault = "/subscriptions/" + Subscription +
        "/resourceGroups/capture-group/providers/Microsoft.KeyVault/vaults/capture-vault";
    private const string Deleted = "/subscriptions/" + Subscription +
        "/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/capture-vault";
    private const string Notification = Vault + "/providers/Microsoft.EventGrid/eventSubscriptions/capture-notification";
    private const string Connection = Vault + "/privateEndpointConnections/capture-connection";
    private const string Role = Vault + "/providers/Microsoft.Authorization/roleAssignments/" + Assignment;
    private const string Origin = "https://management.azure.com";
    private const string StatusUrl = Origin + "/subscriptions/" + Subscription +
        "/providers/Microsoft.KeyVault/locations/eastus/operations/" + OperationId + "?api-version=2026-02-01";
    private const string Material = "https://delivery.example.test/events?key=private-webhook-material";

    [Test]
    [Arguments("UpdatePrivateConnection", 200)]
    [Arguments("DeletePrivateConnection", 200)]
    [Arguments("DeletePrivateConnection", 204)]
    [Arguments("DeletePrivateConnection", 202)]
    public async Task PrivateConnectionCompletionCannotIssueAnotherProfilesProof(string name, int status)
    {
        using var f = new Fixture(name);
        f.Backend.StartStatus = status;
        if (name == "DeletePrivateConnection")
        {
            f.Backend.StartBody = "";
            if (status == 202)
            {
                f.Backend.Targets.Add(("Location", StatusUrl));
                f.Backend.Targets.Add(("Azure-AsyncOperation", StatusUrl));
                f.Backend.StatusBody = """{"status":"Succeeded"}""";
            }
        }
        Task? original = null, completion = null;
        await Assert.That(await f.Start(retained: task => original = task)).IsEqualTo(SecretStatus.Success);
        var result = await f.Check(retained: task => completion = task);
        await Assert.That(result).IsEqualTo(name == "UpdatePrivateConnection" ? SecretStatus.Success :
            status == 202 ? SecretStatus.Invalid : SecretStatus.Unknown);
        await Assert.That(original!.IsCompletedSuccessfully && completion!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(f.Handle!.State).IsEqualTo(name == "UpdatePrivateConnection" ?
            NativeProvisioningState.Succeeded : NativeProvisioningState.Pending);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(status == 202 ? 2 : 1);
        await Assert.That(f.Window.Status!.Attempts.Count).IsEqualTo(status == 202 ? 1 : 0);
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
        if (name == "UpdatePrivateConnection")
        {
            using var body = JsonDocument.Parse(f.Backend.RequestBytes);
            await Assert.That(body.RootElement.GetProperty("properties")
                .GetProperty("privateLinkServiceConnectionState").GetProperty("status").GetString()).IsEqualTo("Approved");
        }
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments(200)]
    [Arguments(204)]
    [Arguments(202)]
    public async Task OriginalPrivateConnectionDeletionWithoutCaptureDoesNotEstablishCompletion(int status)
    {
        using var f = new Fixture("DeletePrivateConnection");
        f.Backend.StartStatus = status;
        if (status == 202)
        {
            f.Backend.Targets.Add(("Location", StatusUrl));
            f.Backend.Targets.Add(("Azure-AsyncOperation", StatusUrl));
            f.Backend.StatusBody = """{"status":"Succeeded"}""";
        }
        var client = new VaultAdministration(f.Credential, f.Backend);
        var receipt = client.PrepareReceipt(f.Scope, ManagementMutation.DeletePrivateConnection);
        var started = await client.DeletePrivateConnectionAsync((PrivateConnectionScope)f.Scope, receipt);
        await Assert.That(started.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        var result = await started.Value!.CheckStatusAsync();
        await Assert.That(result).IsEqualTo(status == 202 ? SecretStatus.Invalid : SecretStatus.Unknown);
        await Assert.That(started.Value.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(status == 202 ? 2 : 1);
    }

    [Test]
    public async Task OriginalPrivateConnectionDeletionWithoutCaptureCompletesWithNativeResourceBody()
    {
        using var f = new Fixture("DeletePrivateConnection");
        f.Backend.StartStatus = 200;
        f.Backend.StartBody = JsonSerializer.Serialize(new
        {
            id = Connection,
            name = "capture-connection",
            type = "Microsoft.KeyVault/vaults/privateEndpointConnections",
            properties = new
            {
                provisioningState = "Succeeded",
                privateLinkServiceConnectionState = new { status = "Disconnected" },
                privateEndpoint = new { id = Vault + "/private-test-endpoint" }
            }
        });
        var client = new VaultAdministration(f.Credential, f.Backend);
        var receipt = client.PrepareReceipt(f.Scope, ManagementMutation.DeletePrivateConnection);
        var started = await client.DeletePrivateConnectionAsync((PrivateConnectionScope)f.Scope, receipt);
        await Assert.That(started.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(await started.Value!.CheckStatusAsync()).IsEqualTo(SecretStatus.Success);
        await Assert.That(started.Value.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Backend.Requests.Single()).IsEqualTo(("DELETE", Connection, "?api-version=2026-02-01"));
    }

    [Test]
    public async Task OriginalRoleDeletion204UsesOneDeleteAndNoRemoteStatusWitness()
    {
        using var f = new Fixture("DeleteRoleAssignment");
        f.Backend.StartStatus = 204;
        f.Backend.StartBody = "";
        Task? actual = null;
        await Assert.That(await f.Start(retained: task => actual = task)).IsEqualTo(SecretStatus.Success);
        await Assert.That(actual!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Backend.Requests.Single()).IsEqualTo(("DELETE", Role, "?api-version=2022-04-01"));
        await Assert.That(f.Window.Status!.Attempts.Count).IsEqualTo(0);
        await Assert.That(f.Source.TryGetStatusTarget(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task QualifiedOriginalRoleDeletionRequiresItsOwnSynchronousProof()
    {
        using var f = new Fixture("DeleteRoleAssignment");
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out var issued)).IsTrue();
        var proof = issued ?? throw new InvalidOperationException("missing-role-delete-proof");
        await Assert.That(f.Source.OwnsSynchronousDeleteProof(proof, f.Binding, f.Client, f.Scope, f.Receipt, f.Handle!)).IsTrue();
        await Assert.That(proof.HttpStatus).IsEqualTo(204);
        await Assert.That(proof.ResponseBytes).IsEqualTo(0);
        await Assert.That(proof.StartDispatch).IsEqualTo(f.Window.Start!.Attempts.Single().Dispatch);
        await f.Source.SealAsync(f.Window);
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out var same)).IsTrue();
        await Assert.That(ReferenceEquals(proof, same)).IsTrue();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("Location")]
    [Arguments("Azure-AsyncOperation")]
    [Arguments("Operation-Location")]
    [Arguments("Retry-After")]
    [Arguments("Content-Encoding")]
    [Arguments("Transfer-Encoding")]
    public async Task RoleDeletionProofRejectsUnqualifiedResponseHeaders(string header)
    {
        using var f = new Fixture("DeleteRoleAssignment");
        f.Backend.ExtraHeaders.Add((header, header == "Retry-After" ? "1" :
            header == "Content-Encoding" ? "gzip" : header == "Transfer-Encoding" ? "chunked" :
                Origin + Role + "?api-version=2022-04-01"));
        _ = await f.Start();
        await f.Source.SealAsync(f.Window);
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
    }

    [Test]
    [Arguments("http200")]
    [Arguments("http202")]
    [Arguments("denied")]
    [Arguments("nonempty204")]
    [Arguments("length")]
    [Arguments("lost")]
    public async Task RoleDeletionProofRejectsUnqualifiedResponsesDespiteDiagnosticSuccess(string fault)
    {
        using var f = new Fixture("DeleteRoleAssignment");
        f.Backend.StartStatus = fault == "http200" ? 200 : fault == "http202" ? 202 : fault == "denied" ? 403 : 204;
        if (fault == "nonempty204") f.Backend.StartBody = """{"status":"Succeeded"}""";
        if (fault == "length") f.Backend.DeclaredLength = 1;
        if (fault == "lost") f.Backend.LoseStart = true;
        _ = await f.Start();
        await f.Source.SealAsync(f.Window);
        f.Window.Start!.Outcome = SecretStatus.Success;
        f.Window.Start.WrapperState = NativeProvisioningState.Succeeded;
        foreach (var attempt in f.Window.Start.Attempts)
        {
            attempt.HttpStatus = 204;
            attempt.Valid = attempt.ResponseObserved = attempt.TransportTerminated = true;
            attempt.State = Capture.WireState.Succeeded;
        }
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
    }

    [Test]
    [Arguments("status.Succeeded", "selected-contract")]
    [Arguments("operation.DeleteRoleAssignment", "independent-effect")]
    [Arguments("operation.DeleteRoleAssignment", "denied-authority")]
    [Arguments("operation.DeleteRoleAssignment", "cancellation-boundary")]
    public async Task RoleDeletionProofRequiresExactOperationAndCase(string variant, string boundary)
    {
        using var f = new Fixture("DeleteRoleAssignment", variant, boundary: boundary);
        _ = await f.Start();
        await f.Source.SealAsync(f.Window);
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
    }

    [Test]
    [Arguments("revision")]
    [Arguments("ancestor")]
    public async Task RoleDeletionProofRejectsUnsupportedBindingBeforeNativeWork(string fault)
    {
        using var f = new Fixture("DeleteRoleAssignment");
        var vault = (VaultScope)((RoleAssignmentScope)f.Scope).Parent;
        var binding = fault == "revision" ? f.Binding with { ApiRevision = "2025-02-15" } :
            f.Binding with { Resource = new RoleAssignmentScope(vault.ResourceGroup, Guid.NewGuid()) };
        await Assert.That(() => f.Source.Arm(binding)).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
    }

    [Test]
    public async Task RoleDeletionProofCannotTransferAcrossOperationSourceOrOriginalReferences()
    {
        using var role = new Fixture("DeleteRoleAssignment");
        using var notification = new Fixture("DeleteNotification");
        using var other = new Fixture("DeleteRoleAssignment");
        await role.Start();
        await notification.Start();
        await other.Start();
        await Assert.That(role.Source.TryGetSynchronousDeleteProof(role.Window, role.Binding, out var issuedRole)).IsTrue();
        await Assert.That(notification.Source.TryGetSynchronousDeleteProof(notification.Window, notification.Binding, out var issuedChild)).IsTrue();
        var proof = issuedRole ?? throw new InvalidOperationException("missing-role-proof");
        var childProof = issuedChild ?? throw new InvalidOperationException("missing-child-proof");
        await Assert.That(role.Source.OwnsSynchronousDeleteProof(childProof, role.Binding, role.Client, role.Scope, role.Receipt, role.Handle!)).IsFalse();
        await Assert.That(notification.Source.OwnsSynchronousDeleteProof(proof, notification.Binding, notification.Client,
            notification.Scope, notification.Receipt, notification.Handle!)).IsFalse();
        var copied = new Capture.SynchronousDeleteProof(proof.Binding, proof.StartDispatch, proof.HttpStatus, proof.ResponseBytes, proof.ResponseSha256);
        await Assert.That(role.Source.OwnsSynchronousDeleteProof(copied, role.Binding, role.Client, role.Scope, role.Receipt, role.Handle!)).IsFalse();
        await Assert.That(other.Source.OwnsSynchronousDeleteProof(proof, role.Binding, role.Client, role.Scope, role.Receipt, role.Handle!)).IsFalse();
        await Assert.That(role.Source.OwnsSynchronousDeleteProof(proof, role.Binding, other.Client, role.Scope, role.Receipt, role.Handle!)).IsFalse();
        var replacementScope = new RoleAssignmentScope(((RoleAssignmentScope)role.Scope).Parent, Guid.Parse(Role.Split('/')[^1]));
        await Assert.That(role.Source.OwnsSynchronousDeleteProof(proof, role.Binding, role.Client, replacementScope, role.Receipt, role.Handle!)).IsFalse();
        var replacementReceipt = role.Client.PrepareReceipt(role.Scope, ManagementMutation.DeleteRoleAssignment);
        await Assert.That(role.Source.OwnsSynchronousDeleteProof(proof, role.Binding, role.Client, role.Scope, replacementReceipt, role.Handle!)).IsFalse();
        await Assert.That(role.Source.OwnsSynchronousDeleteProof(proof, role.Binding, role.Client, role.Scope, role.Receipt, other.Handle!)).IsFalse();
        await Assert.That(role.Source.OwnsSynchronousDeleteProof(proof, role.Binding with
        { Selector = role.Binding.Selector with { Nonce = Guid.NewGuid() } }, role.Client, role.Scope, role.Receipt, role.Handle!)).IsFalse();
        await Assert.That(role.Source.OwnsSynchronousDeleteProof(proof, role.Binding with
        { LeaseId = Guid.NewGuid() }, role.Client, role.Scope, role.Receipt, role.Handle!)).IsFalse();
        var window = new Capture.Window(role.Window.Owner, role.Binding, role.Window.Path, role.Window.Method)
        { Start = role.Window.Start };
        await Assert.That(role.Source.TryGetSynchronousDeleteProof(window, role.Binding, out _)).IsFalse();
        await role.Source.SealAsync(role.Window);
        await notification.Source.SealAsync(notification.Window);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    public async Task RoleDeletionProofRetainsTheActualScopeInsteadOfItsCoordinateTemplate()
    {
        using var f = new Fixture("DeleteRoleAssignment");
        var scope = new RoleAssignmentScope(((RoleAssignmentScope)f.Scope).Parent, Guid.Parse(Role.Split('/')[^1]));
        var receipt = f.Client.PrepareReceipt(scope, ManagementMutation.DeleteRoleAssignment);
        var result = await f.Source.StartAsync(f.Window, f.Binding.Selector, f.Client, scope, f.Input, receipt);
        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out var proof)).IsTrue();
        await Assert.That(f.Source.OwnsSynchronousDeleteProof(proof!, f.Binding, f.Client, scope, receipt, result.Value!)).IsTrue();
        await Assert.That(f.Source.OwnsSynchronousDeleteProof(proof!, f.Binding, f.Client, f.Scope, receipt, result.Value!)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task RoleDeletionProofCannotChangeProfilesWithinTheSameCaptureSource()
    {
        using var role = new Fixture("DeleteRoleAssignment");
        using var child = new Fixture("DeleteNotification");
        var source = new Capture(new DeleteProfileTransport(role.Backend, child.Backend), 65536);
        var client = new VaultAdministration(role.Credential, source.SelectedTransport);
        var roleWindow = source.Arm(role.Binding);
        var childWindow = source.Arm(child.Binding);
        var roleReceipt = client.PrepareReceipt(role.Scope, ManagementMutation.DeleteRoleAssignment);
        var childReceipt = client.PrepareReceipt(child.Scope, ManagementMutation.DeleteNotification);
        var roleStart = await source.StartAsync(roleWindow, role.Binding.Selector, client, role.Scope, role.Input, roleReceipt);
        var childStart = await source.StartAsync(childWindow, child.Binding.Selector, client, child.Scope, child.Input, childReceipt);
        await Assert.That(roleStart.IsSuccess && childStart.IsSuccess).IsTrue();
        await Assert.That(source.TryGetSynchronousDeleteProof(roleWindow, role.Binding, out var roleProof)).IsTrue();
        await Assert.That(source.TryGetSynchronousDeleteProof(childWindow, child.Binding, out var childProof)).IsTrue();
        await Assert.That(source.OwnsSynchronousDeleteProof(roleProof!, role.Binding, client, role.Scope, roleReceipt, roleStart.Value!)).IsTrue();
        await Assert.That(source.OwnsSynchronousDeleteProof(childProof!, child.Binding, client, child.Scope, childReceipt, childStart.Value!)).IsTrue();
        await Assert.That(source.OwnsSynchronousDeleteProof(roleProof!, child.Binding, client, role.Scope, roleReceipt, roleStart.Value!)).IsFalse();
        await Assert.That(source.OwnsSynchronousDeleteProof(childProof!, role.Binding, client, child.Scope, childReceipt, childStart.Value!)).IsFalse();
        await Assert.That(source.TryGetSynchronousDeleteProof(roleWindow, child.Binding, out _)).IsFalse();
        await Assert.That(source.TryGetSynchronousDeleteProof(childWindow, role.Binding, out _)).IsFalse();
        await source.SealAsync(roleWindow);
        await source.SealAsync(childWindow);
        await Assert.That(role.Backend.Requests.Count + child.Backend.Requests.Count).IsEqualTo(2);
    }

    private sealed class DeleteProfileTransport(HttpPipelineTransport role, HttpPipelineTransport child) : HttpPipelineTransport
    {
        public override Request CreateRequest() => role.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override ValueTask ProcessAsync(HttpMessage message) => message.Request.Uri.ToUri().AbsolutePath switch
        {
            Role => role.ProcessAsync(message),
            Notification => child.ProcessAsync(message),
            _ => throw new InvalidOperationException("unadmitted-test-profile")
        };
    }

    [Test]
    [Arguments(200)]
    [Arguments(204)]
    public async Task OriginalSynchronousNotificationDeletionIssuesOnlyItsPrivateResponseProof(int status)
    {
        using var f = new Fixture("DeleteNotification");
        f.Backend.StartStatus = status;
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
        Task? originalTask = null;
        await Assert.That(await f.Start(retained: task => originalTask = task)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out var issued)).IsTrue();
        var proof = issued ?? throw new InvalidOperationException("missing-synchronous-proof");
        await Assert.That(f.Source.OwnsSynchronousDeleteProof(proof, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, f.Handle!)).IsTrue();
        await Assert.That(proof.HttpStatus).IsEqualTo(status);
        await Assert.That(proof.ResponseBytes).IsEqualTo(0);
        await Assert.That(proof.ResponseSha256).IsEqualTo(Convert.ToHexString(SHA256.HashData(Array.Empty<byte>())));
        await Assert.That(proof.StartDispatch).IsEqualTo(f.Window.Start!.Attempts.Single().Dispatch);
        await Assert.That(f.Backend.RequestBytes.Length).IsEqualTo(0);
        await Assert.That(f.Backend.Requests.Single()).IsEqualTo(("DELETE", Notification, "?api-version=2025-02-15"));
        await Assert.That(originalTask!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Window.Status!.Attempts.Count).IsEqualTo(0);
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
        await Assert.That(f.Source.TryGetStatusTarget(f.Window, f.Binding, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out var same)).IsTrue();
        await Assert.That(ReferenceEquals(same, proof)).IsTrue();
        await Assert.That(JsonSerializer.Serialize(proof)).IsEqualTo("{}");
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Backend.Disposed).IsFalse();
        await Assert.That(f.Window.Start.Owned.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    [Arguments("Location")]
    [Arguments("Azure-AsyncOperation")]
    [Arguments("Operation-Location")]
    [Arguments("Retry-After")]
    [Arguments("Content-Encoding")]
    [Arguments("Content-Range")]
    public async Task SynchronousDeletionProofRejectsAsynchronousOrPartialResponseHeaders(string header)
    {
        using var f = new Fixture("DeleteNotification");
        f.Backend.ExtraHeaders.Add((header, header == "Retry-After" ? "1" :
            header == "Content-Encoding" ? "gzip" : header == "Content-Range" ? "bytes 0-0/1" :
                Origin + Notification + "?api-version=2025-02-15"));
        _ = await f.Start();
        await f.Source.SealAsync(f.Window);
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
    }

    [Test]
    [Arguments("accepted202")]
    [Arguments("denied")]
    [Arguments("nonempty200")]
    [Arguments("nonempty204")]
    [Arguments("declared-length")]
    [Arguments("lost")]
    public async Task SynchronousDeletionProofCannotBeReconstructedFromIneligibleNativeResponses(string fault)
    {
        using var f = new Fixture("DeleteNotification");
        f.Backend.StartStatus = fault == "accepted202" ? 202 : fault == "denied" ? 403 :
            fault == "nonempty200" ? 200 : 204;
        if (fault.StartsWith("nonempty", StringComparison.Ordinal)) f.Backend.StartBody = """{"status":"Succeeded"}""";
        if (fault == "declared-length") f.Backend.DeclaredLength = 1;
        if (fault == "lost") f.Backend.LoseStart = true;
        _ = await f.Start();
        await f.Source.SealAsync(f.Window);
        // Public diagnostic mutation cannot turn cached success or unknown wire
        // outcome into source-owned terminal response authority.
        f.Window.Start!.Outcome = SecretStatus.Success;
        f.Window.Start.WrapperState = NativeProvisioningState.Succeeded;
        f.Window.Start.HasNativeHandle = true;
        f.Window.Start.Canceled = false;
        foreach (var attempt in f.Window.Start.Attempts)
        {
            attempt.Valid = attempt.ResponseObserved = attempt.TransportTerminated = true;
            attempt.HttpStatus = 204;
            attempt.State = Capture.WireState.Succeeded;
        }
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
    }

    [Test]
    [Arguments("status.Succeeded", "selected-contract")]
    [Arguments("operation.DeleteNotification", "independent-effect")]
    [Arguments("operation.DeleteNotification", "denied-authority")]
    [Arguments("operation.DeleteNotification", "cancellation-boundary")]
    public async Task SynchronousDeletionProofRequiresItsExactOriginalSelection(string variant, string boundary)
    {
        using var f = new Fixture("DeleteNotification", variant, boundary: boundary);
        _ = await f.Start();
        await f.Source.SealAsync(f.Window);
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
    }

    [Test]
    public async Task SynchronousDeletionProofRejectsCopiedAuthorityAndSubstitutedOriginalReferences()
    {
        using var f = new Fixture("DeleteNotification");
        using var other = new Fixture("DeleteNotification");
        await f.Start();
        await other.Start();
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out var issued)).IsTrue();
        var proof = issued ?? throw new InvalidOperationException("missing-synchronous-proof");
        var copy = new Capture.SynchronousDeleteProof(proof.Binding, proof.StartDispatch, proof.HttpStatus,
            proof.ResponseBytes, proof.ResponseSha256);
        await Assert.That(f.Source.OwnsSynchronousDeleteProof(copy, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, f.Handle!)).IsFalse();
        await Assert.That(other.Source.OwnsSynchronousDeleteProof(proof, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, f.Handle!)).IsFalse();
        await Assert.That(other.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
        var copiedWindow = new Capture.Window(f.Window.Owner, f.Binding, f.Window.Path, f.Window.Method)
        { Start = f.Window.Start, Continuation = f.Window.Continuation };
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(copiedWindow, f.Binding, out _)).IsFalse();
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window,
            f.Binding with { LeaseId = Guid.NewGuid() }, out _)).IsFalse();
        await Assert.That(f.Source.OwnsSynchronousDeleteProof(proof, f.Binding, other.Client,
            (NotificationScope)f.Scope, f.Receipt, f.Handle!)).IsFalse();
        var sameCoordinate = new NotificationScope(((NotificationScope)f.Scope).Vault, "capture-notification");
        await Assert.That(f.Source.OwnsSynchronousDeleteProof(proof, f.Binding, f.Client,
            sameCoordinate, f.Receipt, f.Handle!)).IsFalse();
        var sameScopeReceipt = f.Client.PrepareReceipt(f.Scope, ManagementMutation.DeleteNotification);
        await Assert.That(f.Source.OwnsSynchronousDeleteProof(proof, f.Binding, f.Client,
            (NotificationScope)f.Scope, sameScopeReceipt, f.Handle!)).IsFalse();
        await Assert.That(f.Source.OwnsSynchronousDeleteProof(proof, f.Binding, f.Client,
            (NotificationScope)f.Scope, f.Receipt, other.Handle!)).IsFalse();
        await Assert.That(async () => await f.Start()).Throws<InvalidOperationException>();
        await f.Source.SealAsync(f.Window);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    public async Task SynchronousDeletionProofBindsTheActualOriginalScopeNotTheCoordinateTemplate()
    {
        using var f = new Fixture("DeleteNotification");
        var originalScope = new NotificationScope(((NotificationScope)f.Scope).Vault, "capture-notification");
        var originalReceipt = f.Client.PrepareReceipt(originalScope, ManagementMutation.DeleteNotification);
        var result = await f.Source.StartAsync(f.Window, f.Binding.Selector, f.Client,
            originalScope, f.Input, originalReceipt);
        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out var proof)).IsTrue();
        await Assert.That(f.Source.OwnsSynchronousDeleteProof(proof!, f.Binding, f.Client,
            originalScope, originalReceipt, result.Value!)).IsTrue();
        await Assert.That(f.Source.OwnsSynchronousDeleteProof(proof!, f.Binding, f.Client,
            (NotificationScope)f.Scope, originalReceipt, result.Value!)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("hook", "DeleteNotification")]
    [Arguments("snapshot", "DeleteNotification")]
    [Arguments("cancellation", "DeleteNotification")]
    [Arguments("hook", "DeleteRoleAssignment")]
    [Arguments("snapshot", "DeleteRoleAssignment")]
    [Arguments("cancellation", "DeleteRoleAssignment")]
    public async Task SynchronousDeletionProofRequiresCleanOriginalFinalization(string fault, string operation)
    {
        using var f = new Fixture(operation);
        using var cancellation = new CancellationTokenSource();
        async Task Run() => _ = await f.Start(cancellation.Token, _ =>
        {
            if (fault == "hook") throw new InvalidOperationException("host-retention-failure");
            if (fault == "snapshot") f.Window.Start!.Snapshots.Add(new DisposalProbe(true));
            if (fault == "cancellation") cancellation.Cancel();
        });
        if (fault == "cancellation")
        {
            try { await Run(); } catch (OperationCanceledException) { }
        }
        else await Assert.That(Run).Throws<InvalidOperationException>();
        await f.Source.SealAsync(f.Window);
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(f.Window.Start!.Owned.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    [Arguments("credential", false, "DeleteNotification")]
    [Arguments("credential", true, "DeleteNotification")]
    [Arguments("send", false, "DeleteNotification")]
    [Arguments("send", true, "DeleteNotification")]
    [Arguments("body", false, "DeleteNotification")]
    [Arguments("body", true, "DeleteNotification")]
    [Arguments("sdk", false, "DeleteNotification")]
    [Arguments("sdk", true, "DeleteNotification")]
    [Arguments("credential", false, "DeleteRoleAssignment")]
    [Arguments("credential", true, "DeleteRoleAssignment")]
    [Arguments("send", false, "DeleteRoleAssignment")]
    [Arguments("send", true, "DeleteRoleAssignment")]
    [Arguments("body", false, "DeleteRoleAssignment")]
    [Arguments("body", true, "DeleteRoleAssignment")]
    [Arguments("sdk", false, "DeleteRoleAssignment")]
    [Arguments("sdk", true, "DeleteRoleAssignment")]
    public async Task SynchronousDeletionProofWaitsForActualOriginalBorrowers(string barrier, bool cancel, string operation)
    {
        SynchronousDeleteSdkBarrier? sdk = null;
        using var f = new Fixture(operation, decorate: inner => sdk = new(inner));
        f.Credential.Block = barrier == "credential";
        f.Backend.BlockRequestRead = barrier == "send";
        f.Backend.BlockBody = barrier == "body";
        sdk!.Block = barrier == "sdk";
        using var cancellation = new CancellationTokenSource();
        var starting = f.Start(cancellation.Token);
        var entered = barrier switch
        {
            "credential" => f.Credential.Entered.Task,
            "send" => f.Backend.RequestEntered.Task,
            "body" => f.Backend.BodyEntered.Task,
            _ => sdk.Entered.Task
        };
        Task<Capture.Capture>? sealing = null;
        try
        {
            await entered.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
            sealing = f.Source.SealAsync(f.Window);
            if (cancel) cancellation.Cancel();
            await Assert.That(starting.IsCompleted || sealing.IsCompleted).IsFalse();
            if (barrier == "sdk")
                await Assert.That(f.Window.Start!.Snapshots.Count > 0).IsTrue();
        }
        finally
        {
            f.Credential.Release.TrySetResult();
            f.Backend.AllowRequestRead.TrySetResult();
            f.Backend.ReleaseBody.TrySetResult();
            sdk.Release.TrySetResult();
        }
        if (cancel)
        {
            try { await starting.WaitAsync(TimeSpan.FromSeconds(10)); } catch (OperationCanceledException) { }
        }
        else await Assert.That(await starting.WaitAsync(TimeSpan.FromSeconds(10))).IsEqualTo(SecretStatus.Success);
        await sealing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsEqualTo(!cancel);
        await Assert.That(f.Window.Start!.Owned.All(b => b.All(v => v == 0))).IsTrue();
        await Assert.That(f.Backend.Disposed).IsFalse();
    }

    private sealed class SynchronousDeleteSdkBarrier(HttpPipelineTransport inner) : HttpPipelineTransport
    {
        internal bool Block;
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            if (!Block) return;
            Entered.TrySetResult();
            await Release.Task;
            message.CancellationToken.ThrowIfCancellationRequested();
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SynchronousDeletionProofCannotBeMintedByDiagnosticMutationDuringSdkReturn(bool accepted202)
    {
        SynchronousDeleteSdkBarrier? sdk = null;
        using var f = new Fixture("DeleteNotification", decorate: inner => sdk = new(inner));
        f.Backend.StartStatus = accepted202 ? 202 : 200;
        f.Backend.StartBody = accepted202 ? "" : """{"status":"Succeeded"}""";
        sdk!.Block = true;
        var starting = f.Start();
        try
        {
            await sdk.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var invocation = f.Window.Start!;
            invocation.Outcome = SecretStatus.Success;
            invocation.WrapperState = NativeProvisioningState.Succeeded;
            invocation.HasNativeHandle = true;
            invocation.Terminated = true;
            invocation.Canceled = false;
            var attempt = invocation.Attempts.Single();
            attempt.HttpStatus = 204;
            attempt.Valid = attempt.ResponseObserved = attempt.TransportTerminated = true;
            attempt.HasProviderContinuation = false;
            attempt.ResponseSha256 = Convert.ToHexString(SHA256.HashData(Array.Empty<byte>()));
            attempt.State = Capture.WireState.Succeeded;
            f.Window.Continuation = null;
            await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
        }
        finally { sdk.Release.TrySetResult(); }
        _ = await starting.WaitAsync(TimeSpan.FromSeconds(10));
        await f.Source.SealAsync(f.Window);
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
    }

    [Test]
    [Arguments("fields", "DeleteNotification")]
    [Arguments("drained", "DeleteNotification")]
    [Arguments("window", "DeleteNotification")]
    [Arguments("fields", "DeleteRoleAssignment")]
    [Arguments("drained", "DeleteRoleAssignment")]
    [Arguments("window", "DeleteRoleAssignment")]
    public async Task SynchronousDeletionProofRetainsPrivateTaskAndBuffersWhenDiagnosticsAreCleared(string mutation, string operation)
    {
        SynchronousDeleteSdkBarrier? sdk = null;
        using var f = new Fixture(operation, decorate: inner => sdk = new(inner));
        sdk!.Block = true;
        var starting = f.Start();
        Task<Capture.Capture>? sealing = null;
        MemoryStream[] snapshots = [];
        try
        {
            await sdk.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            snapshots = f.Window.Start!.Snapshots.OfType<MemoryStream>().ToArray();
            await Assert.That(snapshots.Length > 0).IsTrue();
            var diagnostic = f.Window.Start;
            diagnostic.SdkTask = Task.CompletedTask;
            diagnostic.Outcome = SecretStatus.Success;
            diagnostic.WrapperState = NativeProvisioningState.Succeeded;
            diagnostic.Terminated = true;
            diagnostic.Snapshots.Clear();
            diagnostic.Owned.Clear();
            if (mutation == "drained") diagnostic.Drained.TrySetResult();
            if (mutation == "window") f.Window.Start = null;
            sealing = f.Source.SealAsync(f.Window);
            await Assert.That(starting.IsCompleted || sealing.IsCompleted).IsFalse();
            await Assert.That(snapshots.All(s => s.CanRead)).IsTrue();
            await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
        }
        finally { sdk.Release.TrySetResult(); }
        await Assert.That(await starting.WaitAsync(TimeSpan.FromSeconds(10))).IsEqualTo(SecretStatus.Success);
        await sealing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(snapshots.All(s => !s.CanRead)).IsTrue();
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsTrue();
    }

    [Test]
    public async Task SynchronousDeletionProofRejectsOriginalDeleteRequestTransferFraming()
    {
        using var f = new Fixture("DeleteNotification");
        f.Credential.BeforeToken = () => f.Backend.LastRequest!.Headers.Add("Transfer-Encoding", "chunked");
        _ = await f.Start();
        await f.Source.SealAsync(f.Window);
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OnlyIssuedImmutableTargetsCarryTheActualSourceStart(bool notification)
    {
        using var fixture = new Fixture(notification ? "CreateOrUpdateNotification" : "PurgeDeletedVault");
        if (notification)
        {
            fixture.Backend.StartBody = fixture.Backend.StartBody.Replace("Succeeded", "Updating", StringComparison.Ordinal);
            fixture.Backend.Targets.Add(("Location", Origin + Notification + "?api-version=" + fixture.Revision));
        }
        else fixture.AsyncStart();
        await Assert.That(fixture.Source.TryGetStatusTarget(fixture.Window, fixture.Binding, out _)).IsFalse();
        await Assert.That(await fixture.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(fixture.Source.TryGetStatusTarget(fixture.Window, fixture.Binding, out var issued)).IsTrue();
        var target = issued ?? throw new InvalidOperationException("missing-issued-target");
        await Assert.That(fixture.Source.OwnsStatusTarget(target, fixture.Binding)).IsTrue();
        await Assert.That(target.Binding).IsEqualTo(fixture.Binding);
        await Assert.That(target.StartDispatch).IsEqualTo(fixture.Window.Start!.Attempts.Single().Dispatch);
        await Assert.That(target.StartResponseSha256).IsEqualTo(Convert.ToHexString(SHA256.HashData(fixture.Backend.ResponseBytes)));
        await Assert.That(target.TargetSha256).IsEqualTo(Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(target.TargetUri.AbsoluteUri))));
        await Assert.That(target.Kind).IsEqualTo(notification ? Capture.StatusTargetKind.SelectedResource : Capture.StatusTargetKind.Operation);
        var copy = new Capture.StatusTarget(target.Binding, target.StartDispatch, target.Kind,
            target.TargetUri, target.TargetSha256, target.StartResponseSha256);
        await Assert.That(fixture.Source.OwnsStatusTarget(copy, fixture.Binding)).IsFalse();
        using var other = new Fixture("PurgeDeletedVault");
        await Assert.That(other.Source.OwnsStatusTarget(target, fixture.Binding)).IsFalse();
        await Assert.That(other.Source.TryGetStatusTarget(fixture.Window, fixture.Binding, out _)).IsFalse();
        await Assert.That(fixture.Source.OwnsStatusTarget(target, fixture.Binding with { LeaseId = Guid.NewGuid() })).IsFalse();
        await Assert.That(fixture.Source.TryGetStatusTarget(fixture.Window,
            fixture.Binding with { LeaseId = Guid.NewGuid() }, out _)).IsFalse();
        await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(fixture.Source.TryGetStatusTarget(fixture.Window, fixture.Binding, out var same)).IsTrue();
        await Assert.That(ReferenceEquals(same, target)).IsTrue();
        await Assert.That(fixture.Source.OwnsStatusTarget(target, fixture.Binding)).IsTrue();
        await Assert.That(JsonSerializer.Serialize(target)).IsEqualTo("{}");
    }

    [Test]
    public async Task CapturedCoordinatesAreFrozenBeforeBorrowedWindowChanges()
    {
        using var fixture = new Fixture("PurgeDeletedVault");
        fixture.AsyncStart();
        await fixture.Start();
        fixture.Window.Continuation = StatusUrl.Replace(OperationId, Assignment, StringComparison.Ordinal);
        await Assert.That(fixture.Source.TryGetStatusTarget(fixture.Window, fixture.Binding, out var issued)).IsTrue();
        var target = issued ?? throw new InvalidOperationException("missing-issued-target");
        await Assert.That(target.TargetUri.AbsoluteUri).IsEqualTo(StatusUrl);
        await fixture.Source.SealAsync(fixture.Window);
    }

    [Test]
    public async Task CopiedWindowEvidenceCannotIssueATargetForAnotherLease()
    {
        using var fixture = new Fixture("PurgeDeletedVault");
        fixture.AsyncStart();
        await fixture.Start();
        var binding = fixture.Binding with
        {
            LeaseId = Guid.NewGuid(),
            Selector = fixture.Binding.Selector with { Nonce = Guid.NewGuid() }
        };
        var copy = new Capture.Window(fixture.Window.Owner, binding, fixture.Window.Path, fixture.Window.Method)
        {
            Start = fixture.Window.Start,
            Continuation = fixture.Window.Continuation
        };
        await Assert.That(fixture.Source.TryGetStatusTarget(copy, binding, out _)).IsFalse();
        await fixture.Source.SealAsync(fixture.Window);
    }

    [Test]
    [Arguments("sync")]
    [Arguments("denied")]
    [Arguments("lost")]
    [Arguments("rejected202")]
    public async Task UnqualifiedStartsCannotIssueStatusTargets(string kind)
    {
        using var fixture = new Fixture(kind == "sync" ? "DeleteVault" :
            kind == "rejected202" ? "CreateOrUpdateVault" : "PurgeDeletedVault");
        if (kind != "sync") fixture.AsyncStart();
        if (kind == "denied") fixture.Backend.StartStatus = 403;
        if (kind == "lost") fixture.Backend.LoseStart = true;
        _ = await fixture.Start();
        await Assert.That(fixture.Source.TryGetStatusTarget(fixture.Window, fixture.Binding, out _)).IsFalse();
        await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(fixture.Source.TryGetStatusTarget(fixture.Window, fixture.Binding, out _)).IsFalse();
    }

    [Test]
    public async Task OriginalCaseSelectorScopeIsNotReplacedWithProviderName()
    {
        using var fixture = new Fixture("DeleteVault");
        var member = ManagementOperationEffects.Members.Single();
        var definition = new NativeCaseDefinition(new("AzureKeyVault", member.Operation,
            "operation.DeleteVault", "controlled", "selected-contract"), member.Member);
        var selector = FixtureSelector.For(definition);
        var binding = fixture.Binding with { Selector = selector, LeaseId = Guid.NewGuid() };
        var window = fixture.Source.Arm(binding);
        await Assert.That((await fixture.Source.StartAsync(window, selector, fixture.Client, fixture.Scope,
            fixture.Input, fixture.Receipt)).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That((await fixture.Source.SealAsync(window)).Binding.Selector).IsEqualTo(selector);
    }

    [Test]
    [Arguments("CreateOrUpdateVault")]
    [Arguments("RecoverVault")]
    [Arguments("DeleteVault")]
    [Arguments("PurgeDeletedVault")]
    [Arguments("UpdatePrivateConnection")]
    [Arguments("DeletePrivateConnection")]
    [Arguments("DeleteRoleAssignment")]
    [Arguments("CreateOrUpdateNotification")]
    [Arguments("UpdateNotification")]
    [Arguments("DeleteNotification")]
    public async Task AllTenSelectedStartsUseRealInstalledNativeSdk(string name)
    {
        using var fixture = new Fixture(name);
        Task? native = null;
        SecretStatus result = await fixture.Start(retained: task => native = task);
        var capture = await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(result).IsEqualTo(SecretStatus.Success);
        await Assert.That(ReferenceEquals(native, capture.Start!.SdkTask)).IsTrue();
        await Assert.That(native!.IsCompleted).IsTrue();
        await Assert.That(capture.Start.Terminated).IsTrue();
        var wire = capture.Start.Attempts.Single();
        await Assert.That(wire.Valid && wire.ResponseObserved && wire.TransportTerminated).IsTrue();
        await Assert.That(wire.HttpStatus).IsEqualTo(fixture.Backend.StartStatus);
        await Assert.That(wire.HasProviderContinuation).IsFalse();
        await Assert.That(wire.Dispatch != Guid.Empty).IsTrue();
        await Assert.That(wire.RequestSha256).IsEqualTo(fixture.Backend.RequestBytes.Length == 0 ? null :
            Convert.ToHexString(SHA256.HashData(fixture.Backend.RequestBytes)));
        await Assert.That(wire.ResponseSha256).IsEqualTo(Convert.ToHexString(SHA256.HashData(fixture.Backend.ResponseBytes)));
        await Assert.That(fixture.Backend.Requests.Single())
            .IsEqualTo((fixture.Backend.ExpectedMethod, fixture.Backend.ExpectedPath, "?api-version=" + fixture.Revision));
        await Assert.That(fixture.Credential.Audiences.Single()).IsEqualTo("https://management.azure.com/.default");
        await Assert.That(fixture.Backend.Authorizations.Single()).IsEqualTo("Bearer selected-capture-token");
        if (name is "CreateOrUpdateVault" or "RecoverVault")
        {
            using var body = JsonDocument.Parse(fixture.Backend.RequestBytes);
            await Assert.That(body.RootElement.GetProperty("location").GetString()).IsEqualTo("eastus");
            if (name == "RecoverVault")
                await Assert.That(body.RootElement.GetProperty("properties").GetProperty("createMode").GetString())
                    .IsEqualTo("recover");
        }
        if (name is "CreateOrUpdateNotification" or "UpdateNotification")
        {
            using var body = JsonDocument.Parse(fixture.Backend.RequestBytes);
            var properties = name == "UpdateNotification" ? body.RootElement : body.RootElement.GetProperty("properties");
            await Assert.That(properties.GetProperty("destination").GetProperty("properties").GetProperty("endpointUrl").GetString())
                .IsEqualTo(Material);
        }
        await Assert.That(capture.Start.Owned.All(b => b.All(v => v == 0))).IsTrue();
        await Assert.That(fixture.Backend.Disposed).IsFalse();
    }

    [Test]
    [Arguments("CreateOrUpdateVault")]
    [Arguments("RecoverVault")]
    [Arguments("UpdatePrivateConnection")]
    public async Task NativeTerminalStatusPreservesActualAdapterFollowUpContract(string name)
    {
        using var fixture = new Fixture(name);
        fixture.AsyncStart();
        fixture.Backend.StartStatus = name == "UpdatePrivateConnection" ? 200 : 201;
        fixture.Backend.StartBody = fixture.Backend.FinalBody!.Replace("Succeeded", "Updating", StringComparison.Ordinal);
        fixture.Backend.StatusBody = """{"status":"Succeeded"}""";
        await Assert.That(await fixture.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(await fixture.Check()).IsEqualTo(SecretStatus.Success);
        var capture = await fixture.Source.SealAsync(fixture.Window);
        if (name == "UpdatePrivateConnection")
        {
            // This installed adapter supplies a completed wrapper for HTTP200.
            // Its success cannot substitute for independent pending wire state.
            await Assert.That(capture.Start!.Attempts.Single().State).IsEqualTo(Capture.WireState.Pending);
            await Assert.That(capture.Status!.Evidence).IsEqualTo(Capture.WireState.Unavailable);
            await Assert.That(capture.Status.Attempts.Count).IsEqualTo(0);
            await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(1);
            return;
        }
        await Assert.That(capture.Status!.Attempts.Count > 0).IsTrue();
        await Assert.That(capture.Status!.Attempts.All(a => a.Valid && a.TransportTerminated)).IsTrue();
        await Assert.That(capture.Status.WrapperState).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(capture.Status.Attempts.Count).IsEqualTo(2);
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(3);
        await Assert.That(fixture.Source.OwnsNativeStatusCompletion(fixture.Window, fixture.Binding)).IsTrue();
        await Assert.That(fixture.Source.OwnsNativeStatusCompletion(fixture.Window,
            fixture.Binding with { LeaseId = Guid.NewGuid() })).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task MutableStatusDiagnosticsCannotMintNativeCompletion(bool duringRetainedCallback)
    {
        using var fixture = new Fixture("RecoverVault");
        await fixture.Start();
        void Forge()
        {
            for (int i = 0; i < 2; i++)
                fixture.Window.Status!.Attempts.Add(new()
                {
                    Dispatch = Guid.NewGuid(),
                    HttpStatus = 200,
                    Valid = true,
                    ResponseObserved = true,
                    TransportTerminated = true,
                    State = Capture.WireState.Succeeded
                });
        }
        await Assert.That(await fixture.Check(retained: _ => { if (duringRetainedCallback) Forge(); }))
            .IsEqualTo(SecretStatus.Success);
        if (!duringRetainedCallback) Forge();
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(fixture.Source.OwnsNativeStatusCompletion(fixture.Window, fixture.Binding)).IsFalse();
    }

    [Test]
    [Arguments("DeleteVault")]
    [Arguments("DeleteRoleAssignment")]
    [Arguments("DeleteNotification")]
    public async Task SynchronousCompletedWrappersHaveNoRemoteStatusWitness(string name)
    {
        using var fixture = new Fixture(name);
        await fixture.Start();
        await Assert.That(await fixture.Check()).IsEqualTo(SecretStatus.Success);
        var capture = await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(capture.Start!.Attempts.Single().HttpStatus).IsEqualTo(204);
        await Assert.That(capture.Status!.Evidence).IsEqualTo(Capture.WireState.Unavailable);
        await Assert.That(capture.Status.Attempts.Count).IsEqualTo(0);
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task BorrowedWriterAliasCannotChangeSnapshotAndOnlyOwnedBuffersAreZeroed()
    {
        using var fixture = new Fixture("CreateOrUpdateVault");
        using var content = new BorrowedContent(() => { });
        fixture.Credential.BeforeToken = () => fixture.Backend.LastRequest!.Content = content;
        fixture.Backend.BlockRequestRead = true;
        var invocation = fixture.Start();
        try
        {
            await fixture.Backend.RequestEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            content.Alias.Span.Fill((byte)'x');
            fixture.Backend.AllowRequestRead.TrySetResult();
            await Assert.That(await invocation).IsEqualTo(SecretStatus.Success);
            var capture = await fixture.Source.SealAsync(fixture.Window);
            await Assert.That(content.Writes).IsEqualTo(1);
            using var json = JsonDocument.Parse(fixture.Backend.RequestBytes);
            await Assert.That(json.RootElement.GetProperty("location").GetString()).IsEqualTo("eastus");
            await Assert.That(capture.Start!.Attempts.Single().RequestSha256)
                .IsEqualTo(Convert.ToHexString(SHA256.HashData(fixture.Backend.RequestBytes)));
            await Assert.That(content.Alias.Span.IndexOfAnyExcept((byte)0)).IsEqualTo(-1);
            await Assert.That(fixture.Backend.RequestBytes.Any(v => v != 0)).IsTrue();
            await Assert.That(fixture.Backend.ResponseBytes.Any(v => v != 0)).IsTrue();
            await Assert.That(fixture.Backend.Disposed).IsFalse();
        }
        finally
        {
            fixture.Backend.AllowRequestRead.TrySetResult();
            await invocation;
        }
    }

    [Test]
    [Arguments("CreateOrUpdateVault")]
    [Arguments("RecoverVault")]
    [Arguments("DeleteVault")]
    [Arguments("PurgeDeletedVault")]
    [Arguments("UpdatePrivateConnection")]
    [Arguments("DeletePrivateConnection")]
    [Arguments("DeleteRoleAssignment")]
    [Arguments("CreateOrUpdateNotification")]
    [Arguments("UpdateNotification")]
    [Arguments("DeleteNotification")]
    public async Task AllTenRetainWire202WhenNativeContractCannotSupplyHandle(string name)
    {
        using var fixture = new Fixture(name);
        fixture.AsyncStart();
        // RBAC has no admitted async status-route contract in this capture.
        if (name == "DeleteRoleAssignment") fixture.Backend.Targets.Clear();
        _ = await fixture.Start();
        if (!fixture.Window.Start!.HasNativeHandle)
            await Assert.That(async () => await fixture.Check()).Throws<InvalidOperationException>();
        var capture = await fixture.Source.SealAsync(fixture.Window);
        var wire = capture.Start!.Attempts.Single();
        await Assert.That(wire.HttpStatus).IsEqualTo(202);
        await Assert.That(wire.State).IsEqualTo(Capture.WireState.Pending);
        await Assert.That(wire.Valid && capture.Start.Terminated).IsTrue();
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("CreateOrUpdateVault")]
    [Arguments("RecoverVault")]
    [Arguments("DeleteVault")]
    [Arguments("PurgeDeletedVault")]
    [Arguments("UpdatePrivateConnection")]
    [Arguments("DeletePrivateConnection")]
    [Arguments("DeleteRoleAssignment")]
    [Arguments("CreateOrUpdateNotification")]
    [Arguments("UpdateNotification")]
    [Arguments("DeleteNotification")]
    public async Task DeniedStartsNeverProduceStatusAuthority(string name)
    {
        using var fixture = new Fixture(name);
        fixture.Backend.StartStatus = 403;
        fixture.Backend.StartBody = """{"error":{"code":"Forbidden","message":"private-native-error"}}""";
        await Assert.That(await fixture.Start()).IsEqualTo(SecretStatus.Denied);
        await Assert.That(async () => await fixture.Check()).Throws<InvalidOperationException>();
        var capture = await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(capture.Start!.Attempts.Single().State).IsEqualTo(Capture.WireState.Denied);
        await Assert.That(capture.Status).IsNull();
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("InProgress", 200, "Pending")]
    [Arguments("Succeeded", 200, "Succeeded")]
    [Arguments("Failed", 200, "Failed")]
    [Arguments("Canceled", 200, "Canceled")]
    [Arguments("provider-new-state", 200, "Unknown")]
    [Arguments("Succeeded", 403, "Denied")]
    [Arguments("Succeeded", 404, "Unknown")]
    public async Task StatusEvidenceComesFromWireNotRequestedSucceededVariant(string state, int status,
        string expected)
    {
        using var fixture = new Fixture("PurgeDeletedVault", "status.Succeeded");
        fixture.AsyncStart();
        fixture.Backend.StatusStatus = status;
        fixture.Backend.StatusBody = JsonSerializer.Serialize(new
        {
            status = state,
            error = new { code = "private-code", message = "private-native-error" }
        });
        await Assert.That(await fixture.Start()).IsEqualTo(SecretStatus.Success);
        Task? actualStatus = null;
        _ = await fixture.Check(retained: task => actualStatus = task);
        var capture = await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(capture.Start!.Attempts.Single().State).IsEqualTo(Capture.WireState.Pending);
        await Assert.That(capture.Status!.Attempts.Count).IsEqualTo(state == "Succeeded" && status == 200 ? 2 : 1);
        await Assert.That(capture.Status.Attempts.All(a => a.State == Enum.Parse<Capture.WireState>(expected))).IsTrue();
        await Assert.That(ReferenceEquals(actualStatus, capture.Status.SdkTask)).IsTrue();
        await Assert.That(capture.Status.Terminated && actualStatus!.IsCompleted).IsTrue();
        await Assert.That(fixture.Backend.Requests.Last()).IsEqualTo(("GET",
            new Uri(StatusUrl).AbsolutePath, "?api-version=2026-02-01"));
        await Assert.That(fixture.Backend.Authorizations.Distinct().Single()).IsEqualTo("Bearer selected-capture-token");
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(state == "Succeeded" && status == 200 ? 3 : 2);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task MissingAndLostStatusResponsesCannotManufactureSuccess(bool lost)
    {
        using var fixture = new Fixture("PurgeDeletedVault");
        fixture.AsyncStart();
        fixture.Backend.LoseStatus = lost;
        fixture.Backend.StatusBody = "{}";
        await fixture.Start();
        _ = await fixture.Check();
        var capture = await fixture.Source.SealAsync(fixture.Window);
        var attempt = capture.Status!.Attempts.Single();
        await Assert.That(attempt.State).IsEqualTo(lost ? Capture.WireState.Lost : Capture.WireState.Unknown);
        await Assert.That(attempt.ResponseObserved).IsEqualTo(!lost);
        await Assert.That(attempt.TransportTerminated).IsTrue();
        await Assert.That(capture.Status.Terminated).IsTrue();
    }

    [Test]
    [Arguments("PurgeDeletedVault")]
    [Arguments("DeletePrivateConnection")]
    [Arguments("DeleteNotification")]
    public async Task AsyncAcceptanceIsNotSettledByCachedNativeWrapper(string name)
    {
        using var fixture = new Fixture(name);
        fixture.AsyncStart();
        var result = await fixture.Start();
        await Assert.That(result).IsEqualTo(SecretStatus.Success);
        _ = await fixture.Check();
        var capture = await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(capture.Start!.Attempts.Single().HttpStatus).IsEqualTo(202);
        await Assert.That(capture.Start.Attempts.Single().State).IsEqualTo(Capture.WireState.Pending);
        // Some installed DELETE operations return completed wrappers for 202.
        // A cached CheckStatus success has no wire witness and is not settlement.
        if (capture.Status!.Attempts.Count == 0)
        {
            await Assert.That(capture.Status.Evidence).IsEqualTo(Capture.WireState.Unavailable);
            await Assert.That(capture.Status.WrapperState).IsNotNull();
            await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(1);
        }
        else
            await Assert.That(capture.Status.Attempts.Single().State).IsEqualTo(Capture.WireState.Pending);
    }

    [Test]
    [Arguments(301)]
    [Arguments(302)]
    [Arguments(307)]
    [Arguments(308)]
    public async Task RedirectsAreRecordedButNeverFollowedOrRetainedAsHandles(int status)
    {
        using var fixture = new Fixture("PurgeDeletedVault");
        fixture.Backend.StartStatus = status;
        fixture.Backend.Targets.Add(("Location", StatusUrl));
        await Assert.That(await fixture.Start() == SecretStatus.Success).IsFalse();
        await Assert.That(async () => await fixture.Check()).Throws<InvalidOperationException>();
        var capture = await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(capture.Start!.Attempts.Single().HttpStatus).IsEqualTo(status);
        await Assert.That(capture.Start.Attempts.Single().Valid).IsFalse();
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task ExplicitStatusInvocationIsSingleUseAndCannotBorrowAnotherStart()
    {
        using var first = new Fixture("PurgeDeletedVault");
        using var other = new Fixture("PurgeDeletedVault");
        first.AsyncStart();
        other.AsyncStart();
        await first.Start();
        await other.Start();
        await Assert.That(async () => await first.Source.CheckStatusAsync(first.Window, other.Binding.Selector, first.Handle!))
            .Throws<InvalidOperationException>();
        await first.Check();
        await Assert.That(async () => await first.Check()).Throws<InvalidOperationException>();
        var capture = await first.Source.SealAsync(first.Window);
        await Assert.That(capture.Status!.Attempts.Single().State).IsEqualTo(Capture.WireState.Pending);
        await Assert.That(other.Backend.Requests.Count).IsEqualTo(1);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    public async Task MissingAsyncTargetRemainsExplicitPendingWithoutInventedUrl()
    {
        using var fixture = new Fixture("PurgeDeletedVault");
        fixture.Backend.StartStatus = 202;
        fixture.Backend.StartBody = "";
        var outcome = await fixture.Start();
        if (outcome == SecretStatus.Success) _ = await fixture.Check();
        var capture = await fixture.Source.SealAsync(fixture.Window);
        var attempt = capture.Start!.Attempts.Single();
        await Assert.That(attempt.State).IsEqualTo(Capture.WireState.Pending);
        await Assert.That(attempt.HasProviderContinuation).IsFalse();
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(capture.Status is null || capture.Status.Attempts.Count == 0).IsTrue();
    }

    [Test]
    public async Task LostStartIsRetainedWithoutReplayOrImportedHandle()
    {
        using var fixture = new Fixture("PurgeDeletedVault");
        fixture.Backend.LoseStart = true;
        await Assert.That(await fixture.Start() == SecretStatus.Success).IsFalse();
        await Assert.That(async () => await fixture.Check()).Throws<InvalidOperationException>();
        var capture = await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(capture.Start!.Attempts.Single().State).IsEqualTo(Capture.WireState.Lost);
        await Assert.That(capture.Start.Attempts.Single().ResponseObserved).IsFalse();
        await Assert.That(capture.Start.Terminated).IsTrue();
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("host")]
    [Arguments("scheme")]
    [Arguments("port")]
    [Arguments("userinfo")]
    [Arguments("fragment")]
    [Arguments("subscription")]
    [Arguments("location")]
    [Arguments("revision")]
    [Arguments("query")]
    [Arguments("operation")]
    [Arguments("route")]
    [Arguments("relative")]
    [Arguments("missing-revision")]
    [Arguments("duplicate")]
    [Arguments("mismatch")]
    public async Task ForgedOrAmbiguousAsyncTargetsCannotBecomeSourceHandles(string fault)
    {
        using var fixture = new Fixture("PurgeDeletedVault");
        fixture.AsyncStart();
        string url = fault switch
        {
            "host" => StatusUrl.Replace("management.azure.com", "attacker.example.test", StringComparison.Ordinal),
            "scheme" => StatusUrl.Replace("https:", "http:", StringComparison.Ordinal),
            "port" => StatusUrl.Replace(".com/", ".com:444/", StringComparison.Ordinal),
            "userinfo" => StatusUrl.Replace("https://", "https://user@", StringComparison.Ordinal),
            "fragment" => StatusUrl + "#private",
            "subscription" => StatusUrl.Replace(Subscription, Tenant, StringComparison.Ordinal),
            "location" => StatusUrl.Replace("eastus", "westus", StringComparison.Ordinal),
            "revision" => StatusUrl.Replace("2026-02-01", "2022-04-01", StringComparison.Ordinal),
            "query" => StatusUrl + "&secret=private",
            "operation" => StatusUrl.Replace(OperationId, "fake-handle", StringComparison.Ordinal),
            "route" => Origin + Vault + "?api-version=2026-02-01",
            "relative" => new Uri(StatusUrl).PathAndQuery,
            "missing-revision" => StatusUrl.Split('?')[0],
            _ => StatusUrl
        };
        fixture.Backend.Targets.Clear();
        fixture.Backend.Targets.Add(("Azure-AsyncOperation", url));
        if (fault == "duplicate") fixture.Backend.Targets.Add(("Azure-AsyncOperation", url));
        if (fault == "mismatch") fixture.Backend.Targets.Add(("Location",
            StatusUrl.Replace(OperationId, Assignment, StringComparison.Ordinal)));
        await Assert.That(await fixture.Start() == SecretStatus.Success).IsFalse();
        await Assert.That(async () => await fixture.Check()).Throws<InvalidOperationException>();
        var capture = await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(capture.Start!.Attempts.Single().Valid).IsFalse();
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("scope")]
    [Arguments("operation")]
    [Arguments("variant")]
    [Arguments("case")]
    public async Task InvocationRequiresFullSelectorAndSourceOwnership(string field)
    {
        using var fixture = new Fixture("DeleteVault");
        var selector = fixture.Binding.Selector;
        var foreign = field switch
        {
            "nonce" => selector with { Nonce = Guid.NewGuid() },
            "scope" => selector with { Scope = "foreign" },
            "operation" => selector with { Operation = "foreign" },
            "variant" => selector with { Variant = "operation.RecoverVault" },
            _ => selector with { Case = "foreign" }
        };
        await Assert.That(async () => await fixture.Source.StartAsync(fixture.Window, foreign, fixture.Client,
            fixture.Scope, fixture.Input, fixture.Receipt))
            .Throws<InvalidOperationException>();
        using var other = new Fixture("DeleteVault");
        await Assert.That(async () => await other.Source.StartAsync(fixture.Window, selector, fixture.Client,
            fixture.Scope, fixture.Input, fixture.Receipt))
            .Throws<InvalidOperationException>();
        await Assert.That(async () => await other.Source.SealAsync(fixture.Window)).Throws<InvalidOperationException>();
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(0);
        await fixture.Start();
        await Assert.That(async () => await fixture.Start()).Throws<InvalidOperationException>();
        await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(async () => await fixture.Check()).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("lease")]
    [Arguments("revision")]
    [Arguments("scope")]
    [Arguments("operation")]
    [Arguments("location")]
    public async Task InvalidOrReplayedBindingCannotArm(string field)
    {
        using var fixture = new Fixture("PurgeDeletedVault");
        var binding = field switch
        {
            "nonce" => fixture.Binding with { Selector = fixture.Binding.Selector with { Nonce = Guid.Empty } },
            "lease" => fixture.Binding with { LeaseId = Guid.Empty },
            "revision" => fixture.Binding with { ApiRevision = "2025-02-15" },
            "scope" => fixture.Binding with { Resource = new VaultScope(new(new(Guid.Parse(Subscription)), "capture-group"), "capture-vault") },
            "operation" => fixture.Binding with { Operation = ManagementMutation.UpdateVault },
            _ => fixture.Binding with { Location = "westus" }
        };
        await Assert.That(() => fixture.Source.Arm(binding)).Throws<InvalidOperationException>();
        await Assert.That(() => fixture.Source.Arm(fixture.Binding)).Throws<InvalidOperationException>();
        await Assert.That(() => fixture.Source.Arm(fixture.Binding with
        {
            Selector = fixture.Binding.Selector with { Nonce = Guid.NewGuid() }
        })).Throws<InvalidOperationException>();
        await Assert.That(() => fixture.Source.Arm(fixture.Binding with { LeaseId = Guid.NewGuid() }))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("path")]
    [Arguments("host")]
    [Arguments("revision")]
    [Arguments("query")]
    [Arguments("duplicate-revision")]
    [Arguments("method")]
    [Arguments("headers")]
    [Arguments("writer-path")]
    [Arguments("writer-header")]
    public async Task RequestSubstitutionNeverReachesIndependentBackend(string fault)
    {
        using var fixture = new Fixture("CreateOrUpdateVault");
        fixture.Credential.BeforeToken = () =>
        {
            Request request = fixture.Backend.LastRequest!;
            if (fault.StartsWith("writer-", StringComparison.Ordinal))
            {
                request.Content = new BorrowedContent(() =>
                {
                    if (fault == "writer-path") request.Uri.Reset(new Uri(Origin + Vault + "-foreign?api-version=2026-02-01"));
                    else request.Headers.SetValue("x-private-substitution", "private");
                });
            }
            else if (fault == "method") request.Method = RequestMethod.Delete;
            else if (fault == "headers") request.Headers.SetValue("x-private-oversize", new string('x', 4097));
            else
            {
                string uri = Origin + Vault + "?api-version=2026-02-01";
                uri = fault switch
                {
                    "path" => uri.Replace("capture-vault?", "other-vault?", StringComparison.Ordinal),
                    "host" => uri.Replace("management.azure.com", "attacker.example.test", StringComparison.Ordinal),
                    "revision" => uri.Replace("2026-02-01", "2022-04-01", StringComparison.Ordinal),
                    "query" => uri + "&secret=private",
                    _ => uri + "&api-version=2026-02-01"
                };
                request.Uri.Reset(new Uri(uri));
            }
        };
        await Assert.That(await fixture.Start() == SecretStatus.Success).IsFalse();
        var capture = await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(0);
        await Assert.That(capture.Start!.Attempts.Count).IsEqualTo(0);
        await Assert.That(capture.Start.Owned.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    [Arguments("request")]
    [Arguments("response")]
    [Arguments("headers")]
    [Arguments("header-rows")]
    [Arguments("declared-length")]
    [Arguments("rows")]
    [Arguments("depth")]
    [Arguments("duplicates")]
    [Arguments("next-link")]
    public async Task MaterialBudgetsAndAmbiguousJsonFailBeforeNativeDeserialization(string fault)
    {
        using var fixture = new Fixture("CreateOrUpdateVault", maximumBytes: fault == "rows" ? 65536 : 1024);
        if (fault == "request")
            fixture.Credential.BeforeToken = () => fixture.Backend.LastRequest!.Content =
                RequestContent.Create(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { value = new string('x', 2048) })));
        else if (fault == "response") fixture.Backend.StartBody = new string('x', 1025);
        else if (fault == "headers") fixture.Backend.ExtraHeaders.Add(("x-private", new string('x', 4097)));
        else if (fault == "header-rows")
            fixture.Backend.ExtraHeaders.AddRange(Enumerable.Range(0, 34).Select(i => ("x-private-" + i, "value")));
        else if (fault == "declared-length") fixture.Backend.DeclaredLength = 1025;
        else if (fault == "rows") fixture.Backend.StartBody = "{\"value\":[" + string.Join(',', Enumerable.Repeat("0", 513)) + "]}";
        else if (fault == "depth") fixture.Backend.StartBody = new string('[', 18) + "0" + new string(']', 18);
        else if (fault == "duplicates") fixture.Backend.StartBody = """{"status":"Succeeded","status":"Failed"}""";
        else fixture.Backend.StartBody = """{"nextLink":"https://attacker.example.test/private"}""";
        await Assert.That(await fixture.Start() == SecretStatus.Success).IsFalse();
        var capture = await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(capture.Start!.Terminated).IsTrue();
        await Assert.That(capture.Start.Attempts.All(a => !a.Valid)).IsTrue();
        await Assert.That(capture.Start.Owned.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    [Arguments(false, false)]
    [Arguments(false, true)]
    [Arguments(true, false)]
    [Arguments(true, true)]
    public async Task WholeNativeTaskAndBuffersOutliveSendAndCancellation(bool status, bool cancel)
    {
        using var fixture = new Fixture(status ? "PurgeDeletedVault" : "CreateOrUpdateVault");
        if (status)
        {
            fixture.AsyncStart();
            await fixture.Start();
        }
        fixture.Backend.BlockAfterCapture = true;
        using var cancellation = new CancellationTokenSource();
        Task? native = null;
        Task<SecretStatus> invocation = status
            ? fixture.Check(cancellation.Token, task => native = task)
            : fixture.Start(cancellation.Token, task => native = task);
        try
        {
            await fixture.Backend.SendEnded.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await fixture.Backend.BodyEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var retained = status ? fixture.Window.Status! : fixture.Window.Start!;
            await Assert.That(ReferenceEquals(native, retained.SdkTask)).IsTrue();
            await Assert.That(native!.IsCompleted).IsFalse();
            await Assert.That(retained.Terminated).IsFalse();
            await Assert.That(retained.Attempts.Single().TransportTerminated).IsTrue();
            await Assert.That(fixture.Backend.CapturedBuffer!.Any(v => v != 0)).IsTrue();
            var seal = fixture.Source.SealAsync(fixture.Window);
            if (cancel)
            {
                cancellation.Cancel();
                await fixture.Backend.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(10));
            }
            await Assert.That(seal.IsCompleted).IsFalse();
            await Assert.That(invocation.IsCompleted).IsFalse();
            if (!status) await Assert.That(retained.Owned.Any(b => b.Any(v => v != 0))).IsTrue();
            fixture.Backend.ReleaseBody.TrySetResult();
            if (cancel) await Assert.That(async () => await invocation).Throws<OperationCanceledException>();
            else await invocation;
            _ = await seal.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(native.IsCompleted && retained.Terminated).IsTrue();
            await Assert.That(retained.Owned.All(b => b.All(v => v == 0))).IsTrue();
            await Assert.That(fixture.Backend.CapturedBuffer!.All(v => v == 0)).IsTrue();
            await Assert.That(fixture.Backend.ResponseBytes.Any(v => v != 0)).IsTrue();
            await Assert.That(fixture.Backend.Disposed).IsFalse();
        }
        finally
        {
            fixture.Backend.ReleaseBody.TrySetResult();
            try { await invocation; } catch (OperationCanceledException) { }
        }
    }

    [Test]
    public async Task CancellationBeforeStartHasNoWireAttempt()
    {
        using var fixture = new Fixture("DeleteVault");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.That(async () => await fixture.Start(cancellation.Token)).Throws<OperationCanceledException>();
        var capture = await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(capture.Start!.Canceled && capture.Start.Terminated).IsTrue();
        await Assert.That(capture.Start.Attempts.Count).IsEqualTo(0);
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task ThrowingRetentionHookCannotAbandonActualNativeTask()
    {
        using var fixture = new Fixture("CreateOrUpdateVault");
        fixture.Backend.BlockBody = true;
        var invocation = fixture.Start(retained: _ => throw new InvalidOperationException("private-host-hook"));
        try
        {
            await fixture.Backend.BodyEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var seal = fixture.Source.SealAsync(fixture.Window);
            await Assert.That(invocation.IsCompleted || seal.IsCompleted).IsFalse();
            fixture.Backend.ReleaseBody.TrySetResult();
            await Assert.That(async () => await invocation).Throws<InvalidOperationException>();
            var capture = await seal;
            await Assert.That(capture.Start!.SdkTask!.IsCompleted && capture.Start.Terminated).IsTrue();
            await Assert.That(capture.Start.Owned.All(b => b.All(v => v == 0))).IsTrue();
        }
        finally
        {
            fixture.Backend.ReleaseBody.TrySetResult();
            try { await invocation; } catch (InvalidOperationException) { }
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OriginalTaskReceiptAndHandleSurviveWarmAndColdCredentialPaths(bool cold)
    {
        using var fixture = new Fixture("PurgeDeletedVault");
        fixture.AsyncStart();
        fixture.Credential.Block = cold;
        Task? retained = null;
        var invocation = fixture.Source.StartAsync(fixture.Window, fixture.Binding.Selector, fixture.Client,
            fixture.Scope, fixture.Input, fixture.Receipt, retained: task => retained = task);
        try
        {
            await fixture.Credential.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(ReferenceEquals(retained, fixture.Window.Start!.SdkTask)).IsTrue();
            if (cold)
            {
                await Assert.That(retained!.IsCompleted || invocation.IsCompleted).IsFalse();
                await Assert.That(fixture.Source.TryGetStatusTarget(fixture.Window, fixture.Binding, out _)).IsFalse();
                await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(0);
            }
            fixture.Credential.Release.TrySetResult();
            var result = await invocation.WaitAsync(TimeSpan.FromSeconds(10));
            var original = await ((Task<SecretOutcome<ManagementOperation>>)retained!);
            await Assert.That(result.IsSuccess).IsTrue();
            await Assert.That(ReferenceEquals(result.Value, original.Value)).IsTrue();
            await Assert.That(fixture.Receipt.Evidence == DispatchEvidence.Pending ||
                fixture.Receipt.Evidence == DispatchEvidence.Applied).IsTrue();
            Task? statusTask = null;
            var status = await fixture.Source.CheckStatusAsync(fixture.Window, fixture.Binding.Selector,
                result.Value, retained: task => statusTask = task);
            await Assert.That(ReferenceEquals(statusTask, fixture.Window.Status!.SdkTask)).IsTrue();
            await Assert.That(status).IsEqualTo(await ((Task<SecretStatus>)statusTask!));
            await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(2);
            await fixture.Source.SealAsync(fixture.Window);
        }
        finally
        {
            fixture.Credential.Release.TrySetResult();
            await invocation;
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SealDrainsOriginalCredentialBorrowerEvenAfterCancellation(bool cancel)
    {
        using var fixture = new Fixture("DeleteVault");
        fixture.Credential.Block = true;
        using var cancellation = new CancellationTokenSource();
        var task = fixture.Start(cancellation.Token);
        try
        {
            await fixture.Credential.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var seal = fixture.Source.SealAsync(fixture.Window);
            if (cancel)
            {
                cancellation.Cancel();
                await fixture.Credential.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(10));
            }
            await Assert.That(seal.IsCompleted || task.IsCompleted || fixture.Window.Start!.SdkTask!.IsCompleted).IsFalse();
            await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(0);
            fixture.Credential.Release.TrySetResult();
            if (cancel)
                await Assert.That(async () => await task.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
            else
                await Assert.That(await task.WaitAsync(TimeSpan.FromSeconds(10))).IsEqualTo(SecretStatus.Success);
            await seal.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(fixture.Window.Start!.Terminated).IsTrue();
            await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(cancel ? 0 : 1);
            await Assert.That(fixture.Backend.Disposed).IsFalse();
        }
        finally
        {
            fixture.Credential.Release.TrySetResult();
            try { await task; } catch (OperationCanceledException) { }
        }
    }

    [Test]
    public async Task ConcurrentOriginalInvocationsKeepSeparateAmbientWindows()
    {
        using var fixture = new Fixture("DeleteVault");
        fixture.Credential.Block = true;
        var first = fixture.Start();
        try
        {
            await fixture.Credential.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var binding = fixture.Binding with
            {
                Selector = fixture.Binding.Selector with { Nonce = Guid.NewGuid() },
                LeaseId = Guid.NewGuid()
            };
            var secondWindow = fixture.Source.Arm(binding);
            var secondClient = new VaultAdministration(new Credential(), fixture.Source.SelectedTransport);
            var secondReceipt = secondClient.PrepareReceipt(fixture.Scope, binding.Operation);
            var second = await fixture.Source.StartAsync(secondWindow, binding.Selector, secondClient,
                fixture.Scope, fixture.Input, secondReceipt);
            await Assert.That(second.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(first.IsCompleted).IsFalse();
            await Assert.That(fixture.Window.Start!.Attempts.Count).IsEqualTo(0);
            await Assert.That(secondWindow.Start!.Attempts.Count).IsEqualTo(1);
            fixture.Credential.Release.TrySetResult();
            await Assert.That(await first.WaitAsync(TimeSpan.FromSeconds(10))).IsEqualTo(SecretStatus.Success);
            await Assert.That(fixture.Window.Start.Attempts.Single().Dispatch !=
                secondWindow.Start.Attempts.Single().Dispatch).IsTrue();
            await Assert.That(ReferenceEquals(fixture.Handle, second.Value)).IsFalse();
            await fixture.Check();
            await fixture.Source.CheckStatusAsync(secondWindow, binding.Selector, second.Value);
            await fixture.Source.SealAsync(fixture.Window);
            await fixture.Source.SealAsync(secondWindow);
            await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(2);
        }
        finally
        {
            fixture.Credential.Release.TrySetResult();
            await first;
        }
    }

    [Test]
    public async Task BindingCoordinatesDoNotReplaceOriginalReceiptBoundScope()
    {
        using var fixture = new Fixture("PurgeDeletedVault");
        var originalScope = new DeletedVaultScope(new(Guid.Parse(Subscription)), "eastus", "capture-vault");
        var originalReceipt = fixture.Client.PrepareReceipt(originalScope, fixture.Binding.Operation);
        await Assert.That(ReferenceEquals(originalScope, fixture.Binding.Resource)).IsFalse();
        var result = await fixture.Source.StartAsync(fixture.Window, fixture.Binding.Selector, fixture.Client,
            originalScope, fixture.Input, originalReceipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(originalReceipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(fixture.Receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(1);
        await fixture.Source.SealAsync(fixture.Window);
    }

    [Test]
    [Arguments("client")]
    [Arguments("scope")]
    [Arguments("operation")]
    [Arguments("used")]
    public async Task OriginalReceiptRejectsSubstitutionsWithoutCaptureReplacement(string fault)
    {
        using var fixture = new Fixture("DeleteVault");
        var client = fault == "client" ? new VaultAdministration(fixture.Credential, fixture.Source.SelectedTransport) : fixture.Client;
        ManagementScope scope = fault == "scope"
            ? new VaultScope(new(new(Guid.Parse(Subscription)), "capture-group"), "capture-vault") : fixture.Scope;
        var receipt = fault == "operation"
            ? fixture.Client.PrepareReceipt(fixture.Scope, ManagementMutation.CreateOrUpdateVault) : fixture.Receipt;
        if (fault == "used")
        {
            await Assert.That(await fixture.Start()).IsEqualTo(SecretStatus.Success);
            var binding = fixture.Binding with
            {
                Selector = fixture.Binding.Selector with { Nonce = Guid.NewGuid() },
                LeaseId = Guid.NewGuid()
            };
            var window = fixture.Source.Arm(binding);
            var replay = await fixture.Source.StartAsync(window, binding.Selector, client, scope, fixture.Input, receipt);
            await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(window.Start!.Attempts.Count).IsEqualTo(0);
            await fixture.Source.SealAsync(window);
        }
        else
        {
            var rejected = await fixture.Source.StartAsync(fixture.Window, fixture.Binding.Selector,
                client, scope, fixture.Input, receipt);
            await Assert.That(rejected.Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(fixture.Window.Start!.Attempts.Count).IsEqualTo(0);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        }
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(fault == "used" ? 1 : 0);
        await fixture.Source.SealAsync(fixture.Window);
    }

    [Test]
    [Arguments("CreateOrUpdateVault")]
    [Arguments("RecoverVault")]
    [Arguments("DeleteVault")]
    [Arguments("PurgeDeletedVault")]
    [Arguments("UpdatePrivateConnection")]
    [Arguments("DeletePrivateConnection")]
    [Arguments("DeleteRoleAssignment")]
    [Arguments("CreateOrUpdateNotification")]
    [Arguments("UpdateNotification")]
    [Arguments("DeleteNotification")]
    public async Task OperationVariantUsesItsBindingInsteadOfUnrelatedStatusInput(string name)
    {
        using var fixture = new Fixture(name);
        var result = await fixture.Source.StartAsync(fixture.Window, fixture.Binding.Selector, fixture.Client,
            fixture.Scope, fixture.Input with { StatusOperation = ManagementMutation.UpdateVault }, fixture.Receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(fixture.Backend.Requests.Single().Method).IsEqualTo(fixture.Backend.ExpectedMethod);
        await fixture.Source.SealAsync(fixture.Window);
    }

    [Test]
    [Arguments("status-operation")]
    [Arguments("subscription")]
    [Arguments("location")]
    [Arguments("resource-group")]
    [Arguments("scope-coordinate")]
    public async Task OriginalInvocationMustStillMatchImmutableBinding(string fault)
    {
        using var fixture = new Fixture("DeleteVault", "status.Succeeded");
        var input = fault switch
        {
            "status-operation" => fixture.Input with { StatusOperation = ManagementMutation.PurgeDeletedVault },
            "subscription" => fixture.Input with { SubscriptionId = Guid.Parse(Tenant) },
            "location" => fixture.Input with { Location = "westus" },
            "resource-group" => fixture.Input with { ResourceGroup = "foreign-group" },
            _ => fixture.Input
        };
        ManagementScope scope = fault == "scope-coordinate"
            ? new VaultScope(new(new(Guid.Parse(Subscription)), "capture-group"), "foreign-vault") : fixture.Scope;
        await Assert.That(async () => await fixture.Source.StartAsync(fixture.Window, fixture.Binding.Selector,
            fixture.Client, scope, input, fixture.Receipt)).Throws<InvalidOperationException>();
        await Assert.That(fixture.Window.Start).IsNull();
        await Assert.That(fixture.Credential.Audiences.Count).IsEqualTo(0);
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(0);
        await fixture.Source.SealAsync(fixture.Window);
    }

    [Test]
    public async Task StatusRequiresExactReturnedHandleAndPrivateContinuation()
    {
        using var fixture = new Fixture("PurgeDeletedVault");
        using var other = new Fixture("PurgeDeletedVault");
        fixture.AsyncStart();
        other.AsyncStart();
        await fixture.Start();
        await other.Start();
        await Assert.That(async () => await fixture.Source.CheckStatusAsync(fixture.Window, fixture.Binding.Selector,
            other.Handle!)).Throws<InvalidOperationException>();
        await Assert.That(fixture.Window.Status).IsNull();
        fixture.Window.Continuation = StatusUrl.Replace(OperationId, Assignment, StringComparison.Ordinal);
        await Assert.That(await fixture.Check()).IsEqualTo(SecretStatus.Pending);
        await Assert.That(fixture.Backend.Requests.Last().Path).IsEqualTo(new Uri(StatusUrl).AbsolutePath);
        await Assert.That(other.Backend.Requests.Count).IsEqualTo(1);
        await fixture.Source.SealAsync(fixture.Window);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    public async Task SelectedTransportCannotReuseAnAmbientInvocationAfterItReturns()
    {
        using var fixture = new Fixture("DeleteVault");
        await fixture.Start();
        var receipt = fixture.Client.PrepareReceipt(fixture.Scope, fixture.Binding.Operation);
        var outside = await ManagementOperationEffects.StartAsync(fixture.Client, fixture.Scope,
            fixture.Binding.Operation, fixture.Input, receipt, CancellationToken.None);
        await Assert.That(outside.IsSuccess).IsFalse();
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(1);
        await fixture.Source.SealAsync(fixture.Window);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ThrowingSnapshotDisposerStillErasesAllBuffersAndReleasesSeal(bool status)
    {
        using var fixture = new Fixture(status ? "PurgeDeletedVault" : "CreateOrUpdateVault");
        if (status) { fixture.AsyncStart(); await fixture.Start(); }
        fixture.Backend.BlockBody = true;
        Task<SecretStatus> task = status ? fixture.Check() : fixture.Start();
        var first = new DisposalProbe(true);
        var second = new DisposalProbe(false);
        try
        {
            await fixture.Backend.BodyEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var invocation = status ? fixture.Window.Status! : fixture.Window.Start!;
            invocation.Snapshots.Add(first);
            invocation.Snapshots.Add(second);
            byte[] owned = [1, 2, 3];
            invocation.Owned.Add(owned);
            var seal = fixture.Source.SealAsync(fixture.Window);
            await Assert.That(seal.IsCompleted).IsFalse();
            fixture.Backend.ReleaseBody.TrySetResult();
            try
            {
                await task.WaitAsync(TimeSpan.FromSeconds(10));
                throw new InvalidOperationException("test-expected-finalization-failure");
            }
            catch (InvalidOperationException exception)
            {
                await Assert.That(exception.Message).IsEqualTo("management-capture-finalization");
                await Assert.That(exception.InnerException).IsNull();
            }
            await seal.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(first.Disposed && second.Disposed).IsTrue();
            await Assert.That(invocation.Terminated && invocation.SdkTask!.IsCompleted).IsTrue();
            await Assert.That(invocation.Owned.All(bytes => bytes.All(value => value == 0))).IsTrue();
            await Assert.That(invocation.Snapshots.Count).IsEqualTo(0);
            await Assert.That(fixture.Backend.Disposed).IsFalse();
        }
        finally
        {
            fixture.Backend.ReleaseBody.TrySetResult();
            try { await task; } catch (InvalidOperationException) { }
        }
    }

    private sealed class DisposalProbe(bool throws) : IDisposable
    {
        internal bool Disposed;
        public void Dispose()
        {
            Disposed = true;
            if (throws) throw new InvalidOperationException(Material);
        }
    }

    [Test]
    public async Task SourceBindingsTasksAndEvidenceHaveOnlyRedactedRepresentations()
    {
        using var fixture = new Fixture("CreateOrUpdateNotification");
        await fixture.Start();
        var capture = await fixture.Source.SealAsync(fixture.Window);
        foreach (object value in new object[] { fixture.Source, fixture.Binding, fixture.Window, capture,
            capture.Start!, capture.Start!.Attempts.Single() })
        {
            await Assert.That(JsonSerializer.Serialize(value)).IsEqualTo("{}");
            await Assert.That(value.ToString()!.Contains(Material, StringComparison.Ordinal)).IsFalse();
            await Assert.That(value.ToString()!.Contains(Subscription, StringComparison.Ordinal)).IsFalse();
            await Assert.That(value.ToString()!.Contains(fixture.Binding.Selector.Nonce.ToString(), StringComparison.Ordinal)).IsFalse();
        }
        await Assert.That(fixture.Backend.Disposed).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CredentialReentrantClientCannotBorrowOriginalCaptureOrEscapeDrain(bool originalReceipt)
    {
        using var fixture = new Fixture("PurgeDeletedVault");
        fixture.AsyncStart();
        fixture.Backend.BlockBody = true;
        var retained = new TaskCompletionSource<Task>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<SecretOutcome<ManagementOperation>>? nested = null;
        fixture.Credential.BeforeToken = () =>
        {
            fixture.Credential.BeforeToken = null;
            var client = originalReceipt ? fixture.Client : new VaultAdministration(new Credential(), fixture.Source.SelectedTransport);
            var receipt = originalReceipt ? fixture.Receipt : client.PrepareReceipt(fixture.Scope, fixture.Binding.Operation);
            nested = ManagementOperationEffects.StartAsync(client, fixture.Scope, fixture.Binding.Operation,
                fixture.Input, receipt, default).AsTask();
        };
        var original = fixture.Source.StartAsync(fixture.Window, fixture.Binding.Selector, fixture.Client,
            fixture.Scope, fixture.Input, fixture.Receipt, retained: task => retained.TrySetResult(task));
        Task<Capture.Capture>? sealing = null;
        try
        {
            await fixture.Backend.BodyEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var actual = await retained.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(actual.IsCompleted).IsFalse();
            if (originalReceipt)
                await Assert.That((await nested!.WaitAsync(TimeSpan.FromSeconds(10))).Status).IsEqualTo(SecretStatus.Invalid);
            sealing = fixture.Source.SealAsync(fixture.Window);
            await Assert.That(sealing.IsCompleted).IsFalse();
            await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(1);
        }
        finally
        {
            fixture.Backend.ReleaseBody.TrySetResult();
            await original.WaitAsync(TimeSpan.FromSeconds(10));
            if (nested is not null) await nested.WaitAsync(TimeSpan.FromSeconds(10));
            if (sealing is not null) await sealing.WaitAsync(TimeSpan.FromSeconds(10));
        }
        await Assert.That((await original).IsSuccess).IsTrue();
        await Assert.That(nested is not null && !(await nested).IsSuccess).IsTrue();
        await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task OriginalDeleteVaultKeepsNativeTargetSeparateFromCachedSdkCompletion()
    {
        DeleteTerminalTrace? trace = null;
        using var fixture = new Fixture("DeleteVault", decorate: transport => trace = new(transport));
        fixture.AsyncStart();
        // Delete's installed adapter admits200/204, not purge's202.
        fixture.Backend.StartStatus = 200;
        fixture.Backend.StartBody = """{"status":"InProgress"}""";
        fixture.Backend.StatusBody = """{"status":"Succeeded"}""";
        await Assert.That(await fixture.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(fixture.Source.TryGetStatusTarget(fixture.Window, fixture.Binding, out var target)).IsTrue();
        Task? originalStatusTask = null;
        var status = await fixture.Check(retained: task => originalStatusTask = task);
        var captured = await fixture.Source.SealAsync(fixture.Window);
        var reads = trace!.Requests.Where(r => r.Method == RequestMethod.Get).ToArray();
        await Assert.That(fixture.Source.OwnsStatusTarget(target!, fixture.Binding)).IsTrue();
        await Assert.That(status).IsEqualTo(SecretStatus.Success);
        await Assert.That(fixture.Handle!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(captured.Start!.Attempts.Single().State).IsEqualTo(Capture.WireState.Pending);
        await Assert.That(reads.Length).IsEqualTo(0);
        await Assert.That(captured.Status!.Attempts.Count).IsEqualTo(0);
        await Assert.That(captured.Status.Evidence).IsEqualTo(Capture.WireState.Unavailable);
        await Assert.That(captured.Status.Terminated && originalStatusTask!.IsCompleted).IsTrue();
        await Assert.That(ReferenceEquals(originalStatusTask, captured.Status.SdkTask)).IsTrue();
        await Assert.That(fixture.Backend.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
        await Assert.That(trace.Requests.Count).IsEqualTo(1);
    }

    private sealed class DeleteTerminalTrace(HttpPipelineTransport inner) : HttpPipelineTransport
    {
        internal readonly List<(RequestMethod Method, string Uri)> Requests = [];
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            Requests.Add((message.Request.Method, message.Request.Uri.ToUri().AbsoluteUri));
            await inner.ProcessAsync(message);
        }
    }

    private sealed class Fixture : IDisposable
    {
        internal readonly Backend Backend;
        internal readonly Credential Credential = new();
        internal readonly Capture Source;
        internal readonly Capture.Binding Binding;
        internal readonly Capture.Window Window;
        internal readonly ManagementOperationEffects.Input Input;
        internal readonly VaultAdministration Client;
        internal readonly ManagementScope Scope;
        internal readonly ManagementReceipt Receipt;
        internal ManagementOperation? Handle;
        internal readonly string Revision;
        private readonly bool statusPrivateDeleteSelected;
        private readonly bool statusNotificationDeleteIndependent;
        private readonly bool statusSucceededDeleteVault;
        private readonly bool statusSucceededDeleteVaultIndependent;
        private readonly bool statusSucceededDeleteVaultCancellation;
        private readonly bool statusRoleDeleteIndependent;
        private readonly bool statusNotificationUpdateIndependent, statusUnknownNotificationUpdate, statusUnknownNotificationUpdateIndependent, statusUnknownNotificationUpdateCancellation;
        internal Task? UnknownCanceledTask;
        private readonly bool statusDeniedPurge;
        private readonly bool statusDeniedNotificationUpdate;
        private readonly bool statusDeniedPrivateConnectionDelete;
        private readonly bool statusDeniedVaultUpdate;
        private readonly bool statusNotificationCreateIndependent;
        private readonly bool statusPrivateUpdateIndependent;
        private readonly bool statusPendingPurge, statusPendingPurgeIndependent, statusPendingPurgeCancellation, statusFailedPurge, statusFailedPurgeIndependent, statusFailedPurgeCancellation, statusCanceledPurge, statusCanceledPurgeIndependent, statusCanceledPurgeCancellation;
        private bool PurgeStatusWire => statusPendingPurge || statusPendingPurgeIndependent || statusPendingPurgeCancellation || statusFailedPurge || statusFailedPurgeIndependent || statusFailedPurgeCancellation || statusCanceledPurge || statusCanceledPurgeIndependent || statusCanceledPurgeCancellation;
        internal Capture.StatusPendingPurgeClockWindow? PendingClock;
        private readonly bool statusPrivateDeleteIndependent;

        internal Fixture(string name, string? variant = null, int maximumBytes = 65536,
            Func<HttpPipelineTransport, HttpPipelineTransport>? decorate = null, string boundary = "selected-contract",
            bool statusPrivateDeleteSelected = false, bool statusNotificationDeleteIndependent = false,
            bool statusSucceededDeleteVault = false, bool statusPrivateDeleteIndependent = false,
            bool statusSucceededDeleteVaultIndependent = false, bool statusSucceededDeleteVaultCancellation = false,
            bool statusRoleDeleteIndependent = false, bool statusNotificationUpdateIndependent = false,
            bool statusNotificationCreateIndependent = false, bool statusPrivateUpdateIndependent = false,
            bool statusPendingPurge = false, bool statusPendingPurgeIndependent = false, bool statusPendingPurgeCancellation = false, bool statusFailedPurge = false, bool statusFailedPurgeIndependent = false, bool statusFailedPurgeCancellation = false, bool statusCanceledPurge = false, bool statusCanceledPurgeIndependent = false, bool statusCanceledPurgeCancellation = false, bool statusUnknownNotificationUpdate = false, bool statusUnknownNotificationUpdateIndependent = false, bool statusUnknownNotificationUpdateCancellation = false,
            bool statusDeniedPurge = false, bool statusDeniedNotificationUpdate = false,
            bool statusDeniedPrivateConnectionDelete = false, bool statusDeniedVaultUpdate = false)
        {
            this.statusPrivateDeleteSelected = statusPrivateDeleteSelected;
            this.statusDeniedPurge = statusDeniedPurge;
            this.statusDeniedNotificationUpdate = statusDeniedNotificationUpdate;
            this.statusDeniedPrivateConnectionDelete = statusDeniedPrivateConnectionDelete;
            this.statusDeniedVaultUpdate = statusDeniedVaultUpdate;
            this.statusNotificationDeleteIndependent = statusNotificationDeleteIndependent;
            this.statusSucceededDeleteVault = statusSucceededDeleteVault;
            this.statusSucceededDeleteVaultIndependent = statusSucceededDeleteVaultIndependent;
            this.statusSucceededDeleteVaultCancellation = statusSucceededDeleteVaultCancellation;
            this.statusRoleDeleteIndependent = statusRoleDeleteIndependent;
            this.statusNotificationUpdateIndependent = statusNotificationUpdateIndependent;
            this.statusUnknownNotificationUpdate = statusUnknownNotificationUpdate;
            this.statusUnknownNotificationUpdateIndependent = statusUnknownNotificationUpdateIndependent;
            this.statusUnknownNotificationUpdateCancellation = statusUnknownNotificationUpdateCancellation;
            this.statusNotificationCreateIndependent = statusNotificationCreateIndependent;
            this.statusPrivateUpdateIndependent = statusPrivateUpdateIndependent;
            this.statusPendingPurge = statusPendingPurge;
            this.statusPendingPurgeIndependent = statusPendingPurgeIndependent;
            this.statusPendingPurgeCancellation = statusPendingPurgeCancellation;
            this.statusFailedPurge = statusFailedPurge;
            this.statusFailedPurgeIndependent = statusFailedPurgeIndependent;
            this.statusFailedPurgeCancellation = statusFailedPurgeCancellation;
            this.statusCanceledPurge = statusCanceledPurge;
            this.statusCanceledPurgeIndependent = statusCanceledPurgeIndependent;
            this.statusCanceledPurgeCancellation = statusCanceledPurgeCancellation;
            if ((statusPendingPurge ? 1 : 0) + (statusPendingPurgeIndependent ? 1 : 0) + (statusPendingPurgeCancellation ? 1 : 0) + (statusFailedPurge ? 1 : 0) + (statusFailedPurgeIndependent ? 1 : 0) + (statusFailedPurgeCancellation ? 1 : 0) + (statusCanceledPurge ? 1 : 0) + (statusCanceledPurgeIndependent ? 1 : 0) + (statusCanceledPurgeCancellation ? 1 : 0) > 1) throw new InvalidOperationException("test-profile-conflict");
            this.statusPrivateDeleteIndependent = statusPrivateDeleteIndependent;
            var operation = Enum.Parse<ManagementMutation>(name);
            var vault = new VaultScope(new(new(Guid.Parse(Subscription)), "capture-group"), "capture-vault");
            ManagementScope scope = operation switch
            {
                ManagementMutation.PurgeDeletedVault => new DeletedVaultScope(vault.ResourceGroup.Subscription, "eastus", vault.VaultName),
                ManagementMutation.UpdatePrivateConnection or ManagementMutation.DeletePrivateConnection => new PrivateConnectionScope(vault, "capture-connection"),
                ManagementMutation.DeleteRoleAssignment => new RoleAssignmentScope(vault, Guid.Parse(Assignment)),
                ManagementMutation.CreateOrUpdateNotification or ManagementMutation.UpdateNotification or
                    ManagementMutation.DeleteNotification => new NotificationScope(vault, "capture-notification"),
                _ => vault
            };
            Revision = scope is NotificationScope ? "2025-02-15" : scope is RoleAssignmentScope ? "2022-04-01" : "2026-02-01";
            Binding = new(new(Guid.NewGuid(), "AzureKeyVault", ManagementOperationEffects.Members[0].Operation,
                variant ?? "operation." + name, boundary), Guid.NewGuid(), scope, operation, "eastus", Revision);
            Input = new(null!, null!, Guid.Parse(Subscription), "capture-group", "eastus", Guid.Parse(Tenant),
                VaultSku.Standard, 7, operation, Material, Guid.Parse(Assignment));
            if (statusDeniedVaultUpdate || PurgeStatusWire || statusDeniedPurge)
            {
                AudienceToken Arm(string role) => new(role, DateTimeOffset.MaxValue, "https://management.azure.com/.default");
                Input = Input with { Arm = new(Arm("setup"), Arm("selected"), Arm("denied"), Arm("observer")) };
            }
            Backend = new(name, Revision);
            if (PurgeStatusWire || statusDeniedPurge)
            {
                Backend.StartStatus = 202;
                Backend.StartBody = "{\"status\":\"InProgress\"}";
                Backend.Targets.Add(("Location", StatusUrl));
                Backend.Targets.Add(("Azure-AsyncOperation", StatusUrl));
                Backend.ExtraHeaders.Add(("x-ms-request-id", "controlled-pending-purge"));
            }
            if (operation == ManagementMutation.DeletePrivateConnection &&
                (boundary == "cancellation-boundary" || statusPrivateDeleteSelected || statusPrivateDeleteIndependent))
            {
                Backend.StartStatus = 200;
                Backend.ExtraHeaders.Add(("x-ms-request-id", "controlled-private-delete-cancellation"));
                Backend.StartBody = JsonSerializer.Serialize(new
                {
                    id = Connection,
                    name = "capture-connection",
                    type = "Microsoft.KeyVault/vaults/privateEndpointConnections",
                    properties = new
                    {
                        provisioningState = "Succeeded",
                        privateLinkServiceConnectionState = new { status = "Disconnected" },
                        privateEndpoint = new
                        {
                            id = $"/subscriptions/{Subscription}/resourceGroups/capture-group/providers/Microsoft.Network/privateEndpoints/capture-private-endpoint"
                        }
                    }
                });
            }
            if (operation == ManagementMutation.UpdatePrivateConnection &&
                (boundary == "cancellation-boundary" || statusPrivateUpdateIndependent))
            {
                Backend.ExtraHeaders.Add(("x-ms-request-id", "controlled-private-update-cancellation"));
                var body = JsonNode.Parse(Backend.StartBody)!;
                body["properties"]!["privateEndpoint"]!["id"] =
                    $"/subscriptions/{Subscription}/resourceGroups/capture-group/providers/Microsoft.Network/privateEndpoints/capture-private-endpoint";
                Backend.StartBody = body.ToJsonString();
            }
            if (operation is ManagementMutation.UpdateNotification or ManagementMutation.CreateOrUpdateNotification &&
                (boundary == "cancellation-boundary" ||
                    statusNotificationUpdateIndependent && operation == ManagementMutation.UpdateNotification ||
                    (statusUnknownNotificationUpdate || statusUnknownNotificationUpdateIndependent || statusUnknownNotificationUpdateCancellation) && operation == ManagementMutation.UpdateNotification ||
                    statusDeniedNotificationUpdate ||
                    statusNotificationCreateIndependent && operation == ManagementMutation.CreateOrUpdateNotification))
            {
                Backend.ExtraHeaders.Add(("x-ms-request-id", "controlled-notification-update-cancellation"));
                Backend.Targets.Add(("Location", Origin + Notification + "?api-version=" + Revision));
                var body = JsonNode.Parse(Backend.StartBody)!;
                body["properties"]!["provisioningState"] = "Updating";
                body["properties"]!["labels"] = new JsonArray("secretkit-fixture-" + Binding.Selector.Nonce.ToString("N"));
                body["properties"]!["filter"] = new JsonObject
                {
                    ["includedEventTypes"] = new JsonArray("Microsoft.KeyVault.SecretNewVersionCreated")
                };
                body["properties"]!["destination"]!["properties"]!["deliveryAttributeMappings"] = new JsonArray();
                Backend.StartBody = body.ToJsonString();
                body["properties"]!["provisioningState"] = statusUnknownNotificationUpdate || statusUnknownNotificationUpdateIndependent || statusUnknownNotificationUpdateCancellation ? "Unknown" : "Succeeded";
                Backend.StatusBody = body.ToJsonString();
                Backend.StatusPath = Notification;
            }
            Source = new(Backend, maximumBytes);
            Window = statusDeniedVaultUpdate ? Source.ArmStatusDeniedVaultUpdate(Binding) :
                statusDeniedPrivateConnectionDelete ? Source.ArmStatusDeniedPrivateConnectionDelete(Binding) :
                statusDeniedPurge ? Source.ArmStatusDeniedPurge(Binding) : Source.Arm(Binding);
            Scope = scope;
            Client = new(Credential, decorate?.Invoke(Source.SelectedTransport) ?? Source.SelectedTransport, maximumBytes);
            Receipt = Client.PrepareReceipt(Scope, operation);
            if (statusDeniedVaultUpdate)
            {
                Backend.StartBody = JsonSerializer.Serialize(new
                {
                    id = Vault, name = "capture-vault", type = "Microsoft.KeyVault/vaults", location = "eastus",
                    tags = new Dictionary<string, string> { ["secretkit-fixture"] = Binding.Selector.Nonce.ToString("N") },
                    properties = new
                    {
                        tenantId = Tenant, sku = new { family = "A", name = "standard" },
                        provisioningState = "Updating", vaultUri = "https://capture-vault.vault.azure.net/",
                        enableRbacAuthorization = true, enableSoftDelete = true, enablePurgeProtection = false,
                        softDeleteRetentionInDays = 7, publicNetworkAccess = "Enabled", createMode = "default",
                        accessPolicies = Array.Empty<object>(), privateEndpointConnections = Array.Empty<object>()
                    }
                });
                Backend.StartStatus = 201;
                Backend.Targets.Add(("Location", StatusUrl));
                Backend.Targets.Add(("Azure-AsyncOperation", StatusUrl));
                Backend.ExtraHeaders.Add(("x-ms-request-id", "controlled-vault-update-denied"));
            }
            if (statusDeniedPrivateConnectionDelete)
            {
                AsyncStart();
                Backend.ExtraHeaders.Add(("x-ms-request-id", "controlled-private-delete-denied"));
            }
        }
        internal void AsyncStart()
        {
            Backend.FinalBody = Backend.StartBody;
            Backend.StartStatus = 202;
            Backend.StartBody = "";
            string target = Binding.Resource is NotificationScope ? Origin + Notification + "?api-version=2025-02-15" : StatusUrl;
            Backend.Targets.Add(("Location", target));
            if (Binding.Resource is not NotificationScope) Backend.Targets.Add(("Azure-AsyncOperation", target));
            Backend.StatusPath = new Uri(target).AbsolutePath;
        }
        internal async Task<SecretStatus> Start(CancellationToken token = default, Action<Task>? retained = null)
        {
            if (statusFailedPurgeCancellation)
                PendingClock ??= Source.EnrollStatusFailedPurgeCancellation(Window, Binding, Client, (DeletedVaultScope)Scope,
                    Receipt, Input.Arm.Administrative.ExpiresAt, new(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30)),
                    TimeSpan.FromSeconds(20), token);
            if (statusFailedPurgeIndependent)
                PendingClock ??= Source.EnrollStatusFailedPurgeIndependent(Window, Binding, Client, (DeletedVaultScope)Scope,
                    Receipt, Input.Arm.Administrative.ExpiresAt, new(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30)),
                    TimeSpan.FromSeconds(20), token);
            if (statusCanceledPurgeCancellation)
                PendingClock ??= Source.EnrollStatusCanceledPurgeCancellation(Window, Binding, Client, (DeletedVaultScope)Scope,
                    Receipt, Input.Arm.Administrative.ExpiresAt, new(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30)),
                    TimeSpan.FromSeconds(20), token);
            if (statusCanceledPurgeIndependent)
                PendingClock ??= Source.EnrollStatusCanceledPurgeIndependent(Window, Binding, Client, (DeletedVaultScope)Scope,
                    Receipt, Input.Arm.Administrative.ExpiresAt, new(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30)),
                    TimeSpan.FromSeconds(20), token);
            if (statusCanceledPurge)
                PendingClock ??= Source.EnrollStatusCanceledPurge(Window, Binding, Client, (DeletedVaultScope)Scope,
                    Receipt, Input.Arm.Administrative.ExpiresAt, new(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30)),
                    TimeSpan.FromSeconds(20), token);
            if (statusFailedPurge)
                PendingClock ??= Source.EnrollStatusFailedPurge(Window, Binding, Client, (DeletedVaultScope)Scope,
                    Receipt, Input.Arm.Administrative.ExpiresAt, new(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30)),
                    TimeSpan.FromSeconds(20), token);
            if (statusPendingPurgeCancellation)
                PendingClock ??= Source.EnrollStatusPendingPurgeCancellation(Window, Binding, Client, (DeletedVaultScope)Scope,
                    Receipt, Input.Arm.Administrative.ExpiresAt, new(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30)),
                    TimeSpan.FromSeconds(20), token);
            if (statusPendingPurgeIndependent)
                PendingClock ??= Source.EnrollStatusPendingPurgeIndependent(Window, Binding, Client, (DeletedVaultScope)Scope,
                    Receipt, Input.Arm.Administrative.ExpiresAt, new(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30)),
                    TimeSpan.FromSeconds(20), token);
            if (statusPendingPurge)
                PendingClock ??= Source.EnrollStatusPendingPurge(Window, Binding, Client, (DeletedVaultScope)Scope,
                    Receipt, Input.Arm.Administrative.ExpiresAt, new(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30)),
                    TimeSpan.FromSeconds(20), token);
            var result = statusDeniedVaultUpdate
                ? await Source.StartStatusDeniedVaultUpdateAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained)
                : statusDeniedPurge
                ? await Source.StartStatusDeniedPurgeAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained)
                : statusDeniedPrivateConnectionDelete
                ? await Source.StartStatusDeniedPrivateConnectionDeleteAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained)
                : statusDeniedNotificationUpdate
                ? await Source.StartStatusDeniedNotificationUpdateAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained)
                : statusUnknownNotificationUpdateCancellation
                ? await Source.StartStatusUnknownNotificationUpdateCancellationAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained)
                : statusUnknownNotificationUpdateIndependent
                ? await Source.StartStatusUnknownNotificationUpdateIndependentAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained)
                : statusUnknownNotificationUpdate
                ? await Source.StartStatusUnknownNotificationUpdateAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained)
                : statusCanceledPurgeCancellation
                ? await Source.StartStatusCanceledPurgeCancellationAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained)
                : statusCanceledPurgeIndependent
                ? await Source.StartStatusCanceledPurgeIndependentAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained)
                : statusCanceledPurge
                ? await Source.StartStatusCanceledPurgeAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained)
                : statusFailedPurgeCancellation
                ? await Source.StartStatusFailedPurgeCancellationAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained)
                : statusFailedPurgeIndependent
                ? await Source.StartStatusFailedPurgeIndependentAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained)
                : statusFailedPurge
                ? await Source.StartStatusFailedPurgeAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained)
                : statusPendingPurgeCancellation
                ? await Source.StartStatusPendingPurgeCancellationAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained)
                : statusPendingPurgeIndependent
                ? await Source.StartStatusPendingPurgeIndependentAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained)
                : statusPendingPurge
                ? await Source.StartStatusPendingPurgeAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained)
                : statusPrivateUpdateIndependent
                ? await Source.StartPrivateConnectionUpdateIndependentAsync(Window, Binding.Selector, Client,
                    Scope, Input, Receipt, token, retained)
                : statusNotificationCreateIndependent
                ? await Source.StartNotificationCreateIndependentAsync(Window, Binding.Selector, Client,
                    Scope, Input, Receipt, token, retained)
                : statusNotificationUpdateIndependent
                ? await Source.StartNotificationUpdateIndependentAsync(Window, Binding.Selector, Client,
                    Scope, Input, Receipt, token, retained)
                : statusRoleDeleteIndependent
                ? await Source.StartRoleDeleteIndependentAsync(Window, Binding.Selector, Client,
                    (RoleAssignmentScope)Scope, Input, Receipt, token, retained)
                : statusPrivateDeleteIndependent
                ? await Source.StartPrivateConnectionDeleteIndependentAsync(Window, Binding.Selector, Client,
                    (PrivateConnectionScope)Scope, Input, Receipt, token, retained)
                : statusSucceededDeleteVaultCancellation
                ? await Source.StartStatusSucceededDeleteVaultCancellationAsync(Window, Binding.Selector, Client,
                    (VaultScope)Scope, Input, Receipt, token, retained)
                : statusSucceededDeleteVaultIndependent
                ? await Source.StartStatusSucceededDeleteVaultIndependentAsync(Window, Binding.Selector, Client,
                    (VaultScope)Scope, Input, Receipt, token, retained)
                : statusSucceededDeleteVault
                ? await Source.StartStatusSucceededDeleteVaultAsync(Window, Binding.Selector, Client, (VaultScope)Scope, Input, Receipt, token, retained)
                : statusNotificationDeleteIndependent
                ? await Source.StartNotificationDeleteIndependentAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained)
                : await Source.StartAsync(Window, Binding.Selector, Client, Scope, Input, Receipt, token, retained,
                    statusPrivateDeleteSelectedProfile: statusPrivateDeleteSelected);
            if (result.IsSuccess) Handle = result.Value;
            return result.Status;
        }
        internal Task<SecretStatus> Check(CancellationToken token = default, Action<Task>? retained = null) =>
            statusDeniedVaultUpdate
                ? Source.CheckStatusDeniedVaultUpdateAsync(Window, Binding.Selector, Handle!, token, retained)
                : statusDeniedPurge
                ? Source.CheckStatusDeniedPurgeAsync(Window, Binding.Selector, Handle!, token, retained).AsTask()
                : statusDeniedPrivateConnectionDelete
                ? Source.CheckStatusDeniedPrivateConnectionDeleteAsync(Window, Binding.Selector, Handle!, token, retained).AsTask()
                : statusDeniedNotificationUpdate
                ? Source.CheckStatusDeniedNotificationUpdateAsync(Window, Binding.Selector, Handle!, token, retained).AsTask()
                : statusUnknownNotificationUpdateCancellation
                ? CheckUnknownCancellation(token, retained)
                : statusCanceledPurgeCancellation
                ? Source.CheckStatusCanceledPurgeCancellationAsync(Window, Binding.Selector, Handle!, token, retained).AsTask()
                : statusCanceledPurgeIndependent
                ? Source.CheckStatusCanceledPurgeIndependentAsync(Window, Binding.Selector, Handle!, token, retained).AsTask()
                : statusCanceledPurge
                ? Source.CheckStatusCanceledPurgeAsync(Window, Binding.Selector, Handle!, token, retained).AsTask()
                : statusFailedPurgeCancellation
                ? Source.CheckStatusFailedPurgeCancellationAsync(Window, Binding.Selector, Handle!, token, retained).AsTask()
                : statusFailedPurgeIndependent
                ? Source.CheckStatusFailedPurgeIndependentAsync(Window, Binding.Selector, Handle!, token, retained).AsTask()
                : statusFailedPurge
                ? Source.CheckStatusFailedPurgeAsync(Window, Binding.Selector, Handle!, token, retained).AsTask()
                : Source.CheckStatusAsync(Window, Binding.Selector, Handle!, token, retained);
        private async Task<SecretStatus> CheckUnknownCancellation(CancellationToken token, Action<Task>? retained)
        {
            if (UnknownCanceledTask is null && !token.IsCancellationRequested) await CancelUnknownCheck();
            return await Source.CheckStatusAsync(Window, Binding.Selector, Handle!, token, retained).ConfigureAwait(false);
        }
        internal async Task CancelUnknownCheck()
        {
            using var canceled = new CancellationTokenSource();
            canceled.Cancel();
            await Assert.That(async () => await Source.CheckStatusUnknownNotificationUpdateCancellationCanceledAsync(
                Window, Binding.Selector, Handle!, canceled.Token, task => UnknownCanceledTask = task))
                .Throws<OperationCanceledException>();
            await Assert.That(UnknownCanceledTask is { IsCanceled: true }).IsTrue();
        }
        public void Dispose() => Backend.Dispose();
    }

    private sealed class Credential : TokenCredential
    {
        internal Action? BeforeToken;
        internal bool Block;
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource CancellationObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly List<string> Audiences = [];
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken token) =>
            throw new InvalidOperationException("test-async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            using var registration = token.Register(() => CancellationObserved.TrySetResult());
            Entered.TrySetResult();
            if (Block) await Release.Task.ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            BeforeToken?.Invoke();
            Audiences.AddRange(context.Scopes);
            return new AccessToken("selected-capture-token", DateTimeOffset.MaxValue);
        }
    }

    // Independent HTTP backend: expected routes and provider responses are not
    // computed by the capture component and no operation-success dummy is used.
    private sealed class Backend : HttpPipelineTransport, IDisposable
    {
        private readonly HttpClient http;
        private readonly HttpClientTransport transport;
        internal readonly string ExpectedMethod, ExpectedPath, Revision;
        internal readonly List<(string Method, string Path, string Query)> Requests = [];
        internal readonly List<string?> Authorizations = [];
        internal readonly List<(string Name, string Value)> Targets = [], ExtraHeaders = [];
        internal readonly TaskCompletionSource SendEnded = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource BodyEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource ReleaseBody = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource CancellationObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource RequestEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource AllowRequestRead = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Request? LastRequest;
        internal string StartBody, StatusBody = """{"status":"InProgress"}""";
        internal string? FinalBody;
        internal string StatusPath = new Uri(StatusUrl).AbsolutePath;
        internal int StartStatus, StatusStatus = 200;
        internal bool LoseStart, LoseStatus, BlockBody, BlockAfterCapture, BlockRequestRead, Disposed;
        internal bool NullResponseStream;
        internal long? DeclaredLength;
        internal byte[] ResponseBytes = [];
        internal byte[]? CapturedBuffer;
        internal byte[] RequestBytes = [];
        internal Backend(string name, string revision)
        {
            Revision = revision;
            ExpectedPath = name switch
            {
                "PurgeDeletedVault" => Deleted + "/purge",
                "UpdatePrivateConnection" or "DeletePrivateConnection" => Connection,
                "DeleteRoleAssignment" => Role,
                "CreateOrUpdateNotification" or "UpdateNotification" or "DeleteNotification" => Notification,
                _ => Vault
            };
            ExpectedMethod = name switch
            {
                "CreateOrUpdateVault" or "RecoverVault" or "UpdatePrivateConnection" or "CreateOrUpdateNotification" => "PUT",
                "PurgeDeletedVault" => "POST",
                "UpdateNotification" => "PATCH",
                _ => "DELETE"
            };
            StartStatus = ExpectedMethod == "DELETE" ? 204 : name is "CreateOrUpdateVault" or "RecoverVault" or
                "CreateOrUpdateNotification" or "UpdateNotification" ? 201 : 200;
            StartBody = ExpectedMethod == "DELETE" || name == "PurgeDeletedVault" ? "" : name switch
            {
                "CreateOrUpdateNotification" or "UpdateNotification" => JsonSerializer.Serialize(new
                {
                    id = Notification,
                    name = "capture-notification",
                    type = "Microsoft.EventGrid/eventSubscriptions",
                    properties = new
                    {
                        topic = Vault,
                        provisioningState = "Succeeded",
                        destination = new { endpointType = "WebHook", properties = new { endpointUrl = Material } }
                    }
                }),
                "UpdatePrivateConnection" => JsonSerializer.Serialize(new
                {
                    id = Connection,
                    name = "capture-connection",
                    type = "Microsoft.KeyVault/vaults/privateEndpointConnections",
                    properties = new
                    {
                        provisioningState = "Succeeded",
                        privateLinkServiceConnectionState = new { status = "Approved" },
                        privateEndpoint = new { id = Vault + "/private-test-endpoint" }
                    }
                }),
                _ => JsonSerializer.Serialize(new
                {
                    id = Vault,
                    name = "capture-vault",
                    type = "Microsoft.KeyVault/vaults",
                    location = "eastus",
                    properties = new
                    {
                        tenantId = Tenant,
                        sku = new { family = "A", name = "standard" },
                        provisioningState = "Succeeded",
                        vaultUri = "https://capture-vault.vault.azure.net/"
                    }
                })
            };
            http = new(new Handler(Respond));
            transport = new(http);
        }
        public override Request CreateRequest() => LastRequest = transport.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("test-async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await transport.ProcessAsync(message).ConfigureAwait(false);
            if (NullResponseStream)
            {
                message.Response.ContentStream?.Dispose();
                message.Response.ContentStream = null;
            }
            if (BlockAfterCapture) message.Response = new WatchedResponse(message.Response, this, message.CancellationToken);
            SendEnded.TrySetResult();
        }
        private async Task<HttpResponseMessage> Respond(HttpRequestMessage request, CancellationToken token)
        {
            var uri = request.RequestUri!;
            bool status = request.Method == HttpMethod.Get;
            bool final = status && uri.AbsolutePath == ExpectedPath && ExpectedPath != StatusPath;
            if (uri.GetLeftPart(UriPartial.Authority) != Origin || uri.Query != "?api-version=" + Revision ||
                (status ? !final && uri.AbsolutePath != StatusPath :
                    uri.AbsolutePath != ExpectedPath || request.Method.Method != ExpectedMethod))
                throw new InvalidOperationException("independent-native-route");
            Requests.Add((request.Method.Method, uri.AbsolutePath, uri.Query));
            Authorizations.Add(request.Headers.Authorization?.ToString());
            if (BlockRequestRead)
            {
                RequestEntered.TrySetResult();
                await AllowRequestRead.Task.ConfigureAwait(false);
            }
            RequestBytes = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(token);
            if (status ? LoseStatus : LoseStart) throw new HttpRequestException("private-response-loss");
            ResponseBytes = Encoding.UTF8.GetBytes(status ? final ? FinalBody ?? StartBody : StatusBody : StartBody);
            Stream input = BlockBody ? new BarrierStream(ResponseBytes, this, token) : new MemoryStream(ResponseBytes, false);
            var response = new HttpResponseMessage((HttpStatusCode)(status ? StatusStatus : StartStatus))
            {
                Content = new StreamContent(input)
            };
            response.Content.Headers.ContentType = new("application/json");
            if (DeclaredLength is { } length) response.Content.Headers.ContentLength = length;
            foreach (var (name, value) in ExtraHeaders)
                if (!response.Headers.TryAddWithoutValidation(name, value))
                    response.Content.Headers.TryAddWithoutValidation(name, value);
            if (!status) foreach (var (name, value) in Targets) response.Headers.TryAddWithoutValidation(name, value);
            return response;
        }
        public void Dispose() { Disposed = true; http.Dispose(); }
        public override string ToString() => "[ControlledManagementBackend]";

        private sealed class WatchedResponse(Response inner, Backend backend, CancellationToken token) : Response
        {
            private bool replaced;
            public override int Status => inner.Status;
            public override string ReasonPhrase => inner.ReasonPhrase;
            public override string ClientRequestId { get => inner.ClientRequestId; set => inner.ClientRequestId = value; }
            public override Stream? ContentStream
            {
                get => inner.ContentStream;
                set
                {
                    if (!replaced && value is MemoryStream memory && memory.TryGetBuffer(out var bytes))
                    {
                        replaced = true;
                        backend.CapturedBuffer = bytes.Array;
                        // Only the SDK's next read is gated. The capture send has
                        // already buffered and validated its real wire response.
                        inner.ContentStream = new BarrierStream(bytes.Array!, bytes.Offset, bytes.Count, backend, token);
                    }
                    else inner.ContentStream = value;
                }
            }
            public override void Dispose() => inner.Dispose();
            protected override bool ContainsHeader(string name) => inner.Headers.Contains(name);
            protected override IEnumerable<HttpHeader> EnumerateHeaders() => inner.Headers;
            protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value) =>
                inner.Headers.TryGetValue(name, out value);
            protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values) =>
                inner.Headers.TryGetValues(name, out values);
        }
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token);
    }

    private sealed class BarrierStream(byte[] bytes, int offset, int count, Backend backend, CancellationToken actualToken)
        : MemoryStream(bytes, offset, count, false, true)
    {
        internal BarrierStream(byte[] bytes, Backend backend, CancellationToken token) : this(bytes, 0, bytes.Length, backend, token) { }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            using var registration = actualToken.Register(() => backend.CancellationObserved.TrySetResult());
            using var readRegistration = token.Register(() => backend.CancellationObserved.TrySetResult());
            backend.BodyEntered.TrySetResult();
            // Deliberately ignore cancellation until the exact termination
            // barrier. Canceling a send is not evidence that it has terminated.
            await backend.ReleaseBody.Task.ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            return await base.ReadAsync(buffer, token).ConfigureAwait(false);
        }
    }

    private sealed class BorrowedContent(Action afterWrite) : RequestContent
    {
        private static readonly byte[] Bytes = Encoding.UTF8.GetBytes("""{"location":"eastus","properties":{}}""");
        internal Memory<byte> Alias;
        internal int Writes;
        public override bool TryComputeLength(out long length) { length = Bytes.Length; return true; }
        public override void WriteTo(Stream stream, CancellationToken token)
        {
            CaptureAlias(stream);
            stream.Write(Bytes);
            afterWrite();
        }
        public override async Task WriteToAsync(Stream stream, CancellationToken token)
        {
            CaptureAlias(stream);
            await stream.WriteAsync(Bytes, token);
            afterWrite();
        }
        private void CaptureAlias(Stream stream)
        {
            Writes++;
            if (stream is MemoryStream memory && memory.TryGetBuffer(out var bytes)) Alias = bytes.AsMemory();
        }
        public override void Dispose() { }
    }
}
