using System.Security.Cryptography;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal sealed partial class RoleFixtureObserverService
{
    // The host must qualify exclusive native egress through this source-owned
    // channel. Merely supplying a label, token string or this object is not proof
    // that another process cannot bypass the channel with the same credentials.
    internal HttpPipelineTransport CreateSelectedTransport(HttpPipelineTransport inner, Func<FixtureSelector> selection)
    {
        lock (sessions)
        {
            Require(!disposed && !selectedTransportConfigured);
            selectedTransportConfigured = true;
        }
        return new SelectedTransport(this, inner, selection);
    }

    private sealed class SelectedTransport(RoleFixtureObserverService service, HttpPipelineTransport inner,
        Func<FixtureSelector> selection) : HttpPipelineTransport
    {
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => ProcessAsync(message).AsTask().GetAwaiter().GetResult();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            FixtureSelector selector = selection();
            Session session;
            lock (service.sessions)
            {
                Require(!service.disposed);
                if (!service.sessions.TryGetValue(selector.Nonce, out Session? found)) throw Failure();
                session = found;
                service.activeRequests++;
            }
            bool entered = false, settled = false;
            Guid dispatch = Guid.Empty;
            string resource = "";
            byte[]? validatedBody = null;
            RequestContent? originalContent = message.Request.Content, snapshotContent = null;
            try
            {
                RoleAdministrationCollector.Binding binding;
                lock (session)
                {
                    Require(!session.Closed && session.Selector == selector && session.Window is not null &&
                        session.Binding is not null && session.SelectedRequests < 100);
                    binding = session.Binding!;
                    session.Active++;
                    session.SelectedActive++;
                    entered = true;
                }
                bool create = selector.Operation.EndsWith(".CreateRoleAssignmentAsync", StringComparison.Ordinal);
                bool delete = selector.Operation.EndsWith(".DeleteRoleAssignmentAsync", StringComparison.Ordinal);
                bool listAssignments = selector.Operation.EndsWith(".ListRoleAssignmentsAsync", StringComparison.Ordinal);
                bool listDefinitions = selector.Operation.EndsWith(".ListRoleDefinitionsAsync", StringComparison.Ordinal);
                bool definition = selector.Operation.EndsWith(".GetRoleDefinitionAsync", StringComparison.Ordinal);
                string subscription = $"/subscriptions/{service.scope.SubscriptionId:D}";
                resource = RoleAdministrationEffects.ParentId(binding.Target.Parent) +
                    $"/providers/Microsoft.Authorization/roleAssignments/{binding.Target.AssignmentId:D}";
                string path = listAssignments ? binding.Vault.ExportResourceId() + "/providers/Microsoft.Authorization/roleAssignments" :
                    listDefinitions ? subscription + "/providers/Microsoft.Authorization/roleDefinitions" :
                    definition ? subscription + $"/providers/Microsoft.Authorization/roleDefinitions/{binding.DefinitionId:D}" : resource;
                Uri uri = message.Request.Uri.ToUri();
                Require(uri.Scheme == "https" && uri.IsDefaultPort && uri.UserInfo.Length == 0 &&
                    uri.Fragment.Length == 0 && uri.GetLeftPart(UriPartial.Authority) == RoleAdministrationCollector.ArmOrigin &&
                    uri.AbsolutePath.Equals(path, StringComparison.OrdinalIgnoreCase) &&
                    message.Request.Method == (create ? RequestMethod.Put : delete ? RequestMethod.Delete : RequestMethod.Get));
                var query = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (string pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
                {
                    string[] parts = pair.Split('=', 2);
                    Require(parts.Length == 2 && query.TryAdd(Uri.UnescapeDataString(parts[0]), Uri.UnescapeDataString(parts[1])));
                }
                Require(query.TryGetValue("api-version", out string? revision) && revision == RoleAdministrationCollector.ArmRevision &&
                    query.All(p => p.Key == "api-version" || (listAssignments || listDefinitions) &&
                        (p.Key is "$filter" or "$skiptoken") && p.Value.Length <= 2048 && !p.Value.Any(char.IsControl)));
                if (create)
                {
                    Require(message.Request.Content is not null);
                    validatedBody = new byte[65536];
                    using (var output = new MemoryStream(validatedBody, writable: true))
                    {
                        await message.Request.Content!.WriteToAsync(output, message.CancellationToken).ConfigureAwait(false);
                        int length = checked((int)output.Position);
                        using JsonDocument json = JsonDocument.Parse(validatedBody.AsMemory(0, length));
                        var properties = json.RootElement.GetProperty("properties");
                        Require(properties.GetProperty("principalId").GetGuid() == service.scope.IntendedPrincipalId &&
                            properties.GetProperty("roleDefinitionId").GetString()!.Equals(
                                subscription + $"/providers/Microsoft.Authorization/roleDefinitions/{binding.DefinitionId:D}",
                                StringComparison.OrdinalIgnoreCase));
                        snapshotContent = RequestContent.Create(validatedBody.AsMemory(0, length));
                        message.Request.Content = snapshotContent;
                    }
                }
                lock (session)
                {
                    Require(!session.Closed);
                    if (create || delete)
                        dispatch = service.provisioner.BeginSelectedDispatch(service.owner, selector, resource, delete);
                    session.SelectedRequests++;
                }
                await inner.ProcessAsync(message).ConfigureAwait(false);
                int status = message.Response.Status;
                // Role-assignment HTTP200/201/204 and explicit rejection are
                // terminal native responses. No selected result/ack substitutes
                // for the independently collected effect afterward.
                settled = status is 200 or 201 or 204 or 401 or 403 or 404 &&
                    !message.Response.Headers.TryGetValue("Azure-AsyncOperation", out _) &&
                    !message.Response.Headers.TryGetValue("Operation-Location", out _);
            }
            finally
            {
                try
                {
                    if (dispatch != Guid.Empty)
                        service.provisioner.EndSelectedDispatch(service.owner, selector, resource, dispatch, settled);
                }
                finally
                {
                    message.Request.Content = originalContent;
                    snapshotContent?.Dispose();
                    if (validatedBody is not null) CryptographicOperations.ZeroMemory(validatedBody);
                    if (entered)
                    {
                        lock (session) session.SelectedActive--;
                        End(session);
                    }
                    lock (service.sessions)
                        if (--service.activeRequests == 0 && service.disposed) service.requestsDrained.TrySetResult();
                }
            }
        }
        public override string ToString() => "[RoleFixtureSelectedTransport]";
    }
}
