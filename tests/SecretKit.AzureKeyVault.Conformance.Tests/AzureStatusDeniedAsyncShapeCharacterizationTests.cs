using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager;
using Azure.ResourceManager.Authorization;
using Azure.ResourceManager.KeyVault;
using Azure.ResourceManager.KeyVault.Models;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    // These are response hypotheses, not Azure service contracts or D proof sources.
    [Test]
    [Arguments("DeleteVault", 200, "pending", true)]
    [Arguments("DeleteVault", 204, "empty", false)]
    [Arguments("DeleteVault", 201, "pending", true)]
    [Arguments("DeleteVault", 202, "empty", true)]
    [Arguments("DeleteVault", 202, "pending", true)]
    [Arguments("UpdatePrivateConnection", 200, "terminal", false)]
    [Arguments("UpdatePrivateConnection", 200, "pending", false)]
    [Arguments("UpdatePrivateConnection", 200, "pending", true)]
    [Arguments("UpdatePrivateConnection", 201, "pending", true)]
    [Arguments("UpdatePrivateConnection", 202, "empty", true)]
    [Arguments("UpdatePrivateConnection", 202, "pending", true)]
    [Arguments("DeleteRoleAssignment", 204, "empty", false)]
    [Arguments("DeleteRoleAssignment", 200, "empty", false)]
    [Arguments("DeleteRoleAssignment", 200, "role", false)]
    [Arguments("DeleteRoleAssignment", 200, "pending", false)]
    [Arguments("DeleteRoleAssignment", 201, "role", false)]
    [Arguments("DeleteRoleAssignment", 202, "role", false)]
    public async Task AsyncShapeUnchangedWrapperPreservesOriginalOutcome(
        string name, int status, string body, bool continuation)
    {
        string revision = name == "DeleteRoleAssignment" ? "2022-04-01" : "2026-02-01";
        using var backend = new Backend(name, revision);
        ConfigureAsyncShape(backend, name, status, body, continuation);
        var client = new VaultAdministration(new Credential(), backend);
        var vault = new VaultScope(new(new(Guid.Parse(Subscription)), "capture-group"), "capture-vault");
        ManagementScope scope = name switch
        {
            "UpdatePrivateConnection" => new PrivateConnectionScope(vault, "capture-connection"),
            "DeleteRoleAssignment" => new RoleAssignmentScope(vault, Guid.Parse(Assignment)),
            _ => vault
        };
        var receipt = client.PrepareReceipt(scope, Enum.Parse<ManagementMutation>(name));
        Task<SecretOutcome<ManagementOperation>> start = name switch
        {
            "UpdatePrivateConnection" => client.UpdatePrivateConnectionAsync(
                (PrivateConnectionScope)scope, PrivateConnectionState.Approved, receipt).AsTask(),
            "DeleteRoleAssignment" => client.DeleteRoleAssignmentAsync((RoleAssignmentScope)scope, receipt).AsTask(),
            _ => client.DeleteVaultAsync(vault, receipt).AsTask()
        };
        var result = await start;
        await Assert.That(start.IsCompletedSuccessfully).IsTrue();
        await Assert.That(backend.Requests.Count).IsEqualTo(1);
        if (status is 201 or 202)
        {
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            return;
        }
        if (name == "DeleteRoleAssignment" && status == 200 && body is "empty" or "pending")
        {
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            return;
        }
        await Assert.That(result.IsSuccess).IsTrue();
        var handle = result.Value;
        await Assert.That(handle.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        Task<SecretStatus> check = handle.CheckStatusAsync().AsTask();
        await Assert.That(await check).IsEqualTo(SecretStatus.Success);
        await Assert.That(check.IsCompletedSuccessfully).IsTrue();
        await Assert.That(backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("DeleteVault", 200, "pending", true)]
    [Arguments("DeleteVault", 204, "empty", false)]
    [Arguments("DeleteVault", 201, "pending", true)]
    [Arguments("DeleteVault", 202, "empty", true)]
    [Arguments("DeleteVault", 202, "pending", true)]
    [Arguments("UpdatePrivateConnection", 200, "terminal", false)]
    [Arguments("UpdatePrivateConnection", 200, "pending", false)]
    [Arguments("UpdatePrivateConnection", 200, "pending", true)]
    [Arguments("UpdatePrivateConnection", 201, "pending", true)]
    [Arguments("UpdatePrivateConnection", 202, "empty", true)]
    [Arguments("UpdatePrivateConnection", 202, "pending", true)]
    [Arguments("DeleteRoleAssignment", 204, "empty", false)]
    [Arguments("DeleteRoleAssignment", 200, "empty", false)]
    [Arguments("DeleteRoleAssignment", 200, "role", false)]
    [Arguments("DeleteRoleAssignment", 200, "pending", false)]
    [Arguments("DeleteRoleAssignment", 201, "role", false)]
    [Arguments("DeleteRoleAssignment", 202, "role", false)]
    public async Task AsyncShapeInstalledNativePreservesExactCompletion(
        string name, int status, string body, bool continuation)
    {
        string revision = name == "DeleteRoleAssignment" ? "2022-04-01" : "2026-02-01";
        using var backend = new Backend(name, revision);
        ConfigureAsyncShape(backend, name, status, body, continuation);
        var trace = new DeleteTerminalTrace(new AsyncShapeBufferedTransport(backend));
        var options = new ArmClientOptions { Transport = trace };
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        options.SetApiVersion("Microsoft.KeyVault/vaults", revision);
        options.SetApiVersion("Microsoft.KeyVault/vaults/privateEndpointConnections", revision);
        options.SetApiVersion("Microsoft.Authorization/roleAssignments", revision);
        var client = new ArmClient(new Credential(), Subscription, options);
        bool? completed = null;
        string? error = null;
        int? failedStatus = null;
        Func<Task<Response>>? update = null;
        Task? retainedStart = null;
        try
        {
            switch (name)
            {
                case "DeleteVault":
                    {
                        var task = client.GetKeyVaultResource(new ResourceIdentifier(Vault)).DeleteAsync(WaitUntil.Started);
                        retainedStart = task;
                        var operation = await task;
                        completed = operation.HasCompleted;
                        update = async () => await operation.UpdateStatusAsync();
                        break;
                    }
                case "UpdatePrivateConnection":
                    {
                        var data = new KeyVaultPrivateEndpointConnectionData
                        {
                            ConnectionState = new KeyVaultPrivateLinkServiceConnectionState
                            {
                                Status = KeyVaultPrivateEndpointServiceConnectionStatus.Approved
                            }
                        };
                        var task = client.GetKeyVaultPrivateEndpointConnectionResource(new ResourceIdentifier(Connection))
                            .UpdateAsync(WaitUntil.Started, data);
                        retainedStart = task;
                        var operation = await task;
                        completed = operation.HasCompleted;
                        update = async () => await operation.UpdateStatusAsync();
                        break;
                    }
                default:
                    {
                        var task = client.GetRoleAssignmentResource(new ResourceIdentifier(Role)).DeleteAsync(WaitUntil.Started);
                        retainedStart = task;
                        var operation = await task;
                        completed = operation.HasCompleted;
                        update = async () => await operation.UpdateStatusAsync();
                        break;
                    }
            }
        }
        catch (Exception exception) when (exception is RequestFailedException or JsonException or
            NullReferenceException or ArgumentNullException)
        {
            error = exception.GetType().Name;
            failedStatus = (exception as RequestFailedException)?.Status;
        }
        await Assert.That(retainedStart is not null && retainedStart.IsCompleted).IsTrue();
        await Assert.That(trace.Requests.Count).IsEqualTo(1);
        await Assert.That(backend.Requests.Count).IsEqualTo(1);
        await Assert.That(trace.Requests[0].Method.ToString()).IsEqualTo(backend.ExpectedMethod);
        await Assert.That(trace.Requests[0].Uri).IsEqualTo(
            Origin + backend.ExpectedPath + "?api-version=" + revision);
        await Assert.That(backend.Authorizations.Single()).IsEqualTo("Bearer selected-capture-token");
        string? expectedError = (name, status, body) switch
        {
            ("DeleteRoleAssignment", 204, _) => nameof(NullReferenceException),
            ("DeleteRoleAssignment", 200, "empty") => "JsonReaderException",
            ("DeleteRoleAssignment", 200, "pending") => nameof(ArgumentNullException),
            ("DeleteRoleAssignment", 201 or 202, _) => nameof(RequestFailedException),
            ("UpdatePrivateConnection", 202, "empty") => "JsonReaderException",
            _ => null
        };
        await Assert.That(error).IsEqualTo(expectedError);
        if (expectedError is not null)
        {
            await Assert.That(completed).IsNull();
            await Assert.That(retainedStart!.IsFaulted).IsTrue();
            await Assert.That(failedStatus).IsEqualTo(
                expectedError == nameof(RequestFailedException) ? (int?)status : null);
            return;
        }
        await Assert.That(completed).IsTrue();
        await Assert.That(retainedStart!.IsCompletedSuccessfully).IsTrue();
        var check = update!();
        await check;
        await Assert.That(check.IsCompletedSuccessfully).IsTrue();
        await Assert.That(trace.Requests.Count).IsEqualTo(1);
        await Assert.That(backend.Requests.Count).IsEqualTo(1);
    }

    private static void ConfigureAsyncShape(Backend backend, string name, int status, string body, bool continuation)
    {
        backend.StartStatus = status;
        backend.StartBody = body switch
        {
            "empty" => "",
            "role" => JsonSerializer.Serialize(new
            {
                id = Role,
                name = Assignment,
                type = "Microsoft.Authorization/roleAssignments",
                properties = new
                {
                    scope = Vault,
                    principalId = Tenant,
                    principalType = "ServicePrincipal",
                    roleDefinitionId = "/subscriptions/" + Subscription +
                        "/providers/Microsoft.Authorization/roleDefinitions/" + OperationId
                }
            }),
            "pending" when name == "UpdatePrivateConnection" =>
                backend.StartBody.Replace("Succeeded", "Updating", StringComparison.Ordinal),
            "pending" => """{"status":"InProgress"}""",
            _ => backend.StartBody
        };
        if (continuation)
        {
            backend.Targets.Add(("Location", StatusUrl));
            backend.Targets.Add(("Azure-AsyncOperation", StatusUrl));
        }
        backend.ExtraHeaders.Add(("x-ms-request-id", "controlled-async-shape"));
        backend.StatusStatus = 403;
        backend.StatusBody = """{"error":{"code":"AuthorizationFailed","message":"controlled-status-denial"}}""";
    }

    // The installed KeyVault model reader requires a buffered response, just as
    // the production boundary supplies. Preserve status/headers and actual EOF.
    private sealed class AsyncShapeBufferedTransport(HttpPipelineTransport inner) : HttpPipelineTransport
    {
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            if (message.Response.ContentStream is not { } stream) return;
            using var bytes = new MemoryStream();
            await stream.CopyToAsync(bytes, message.CancellationToken);
            await stream.DisposeAsync();
            message.Response.ContentStream = new MemoryStream(bytes.ToArray(), false);
        }
    }
}
