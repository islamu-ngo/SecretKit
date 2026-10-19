using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Authenticated source routes. TLS/socket ownership belongs to the host; native
// credentials and source components remain borrowed. No route executes a caller
// URL or accepts a selected-operation result as observation evidence.
internal sealed partial class RoleFixtureObserverService : IAsyncDisposable
{
    private readonly Uri origin;
    private readonly string owner, observerIdentity;
    private readonly SecretMaterial capability;
    private readonly RoleFixtureProvisioner.HostScope scope;
    private readonly RoleAssignmentScope[] ancestors;
    private readonly RoleFixtureProvisioner provisioner;
    private readonly RoleAdministrationCollector collector;
    private readonly TimeProvider time;
    private readonly Dictionary<Guid, Session> sessions = [];
    private bool disposed;
    private Task? disposal;
    private bool selectedTransportConfigured;
    private int activeRequests;
    private readonly CancellationTokenSource lifetime = new();
    private readonly TaskCompletionSource requestsDrained = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private sealed class Session(FixtureSelector selector)
    {
        internal FixtureSelector Selector { get; } = selector;
        internal CancellationTokenSource Stop { get; } = new();
        internal int Active;
        internal bool Closed;
        internal int SelectedRequests, SelectedActive;
        internal SecretMaterial? Canary;
        internal RoleAdministrationEffects.Lease? Lease;
        internal RoleAdministrationCollector.Binding? Binding;
        internal RoleAdministrationCollector.Window? Window;
    }

    internal RoleFixtureObserverService(Uri origin, string owner, string observerIdentity, SecretMaterial capability,
        RoleFixtureProvisioner.HostScope scope, RoleAssignmentScope[] ancestors,
        RoleFixtureProvisioner provisioner, RoleAdministrationCollector collector, TimeProvider? time = null)
    {
        Require(origin.IsAbsoluteUri && origin.Scheme == "https" && origin.AbsolutePath == "/" &&
            origin.UserInfo.Length == 0 && origin.Query.Length == 0 && origin.Fragment.Length == 0 &&
            !string.IsNullOrWhiteSpace(owner) && !string.IsNullOrWhiteSpace(observerIdentity));
        this.origin = origin;
        this.owner = owner;
        this.observerIdentity = observerIdentity;
        this.capability = capability;
        this.scope = scope;
        this.ancestors = ancestors.ToArray();
        this.provisioner = provisioner;
        this.collector = collector;
        this.time = time ?? TimeProvider.System;
    }

    internal async Task<HttpResponseMessage> DispatchAsync(HttpRequestMessage request, CancellationToken token)
    {
        if (!Authenticate(request)) return Error(HttpStatusCode.Unauthorized);
        if (request.Method != HttpMethod.Post || request.RequestUri is not { } uri ||
            uri.GetLeftPart(UriPartial.Authority) != origin.GetLeftPart(UriPartial.Authority) ||
            uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.UserInfo.Length != 0)
            return Error(HttpStatusCode.BadRequest);
        lock (sessions)
        {
            if (disposed) return Error(HttpStatusCode.ServiceUnavailable);
            activeRequests++;
        }
        using var linkedRequest = CancellationTokenSource.CreateLinkedTokenSource(token, lifetime.Token);
        token = linkedRequest.Token;
        try
        {
            using JsonDocument body = await Body(request, token).ConfigureAwait(false);
            switch (uri.AbsolutePath)
            {
                case "/role/prepare":
                    return await PrepareAsync(body.RootElement.Deserialize<RoleAdministrationEffects.Prepare>(
                        ManagementAdmission.Json) ?? throw Failure(), token).ConfigureAwait(false);
                case "/role/arm":
                case "/role/observe":
                    return await ObserveAsync(uri.AbsolutePath, body.RootElement.Deserialize<ObserveLease>(
                        ManagementAdmission.Json) ?? throw Failure(), token).ConfigureAwait(false);
                case "/role/release":
                    return await ReleaseAsync(body.RootElement.Deserialize<FixtureSelector>(
                        ManagementAdmission.Json) ?? throw Failure(), token).ConfigureAwait(false);
                default:
                    return Error(HttpStatusCode.NotFound);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception) { return Error(HttpStatusCode.ServiceUnavailable); }
        finally
        {
            lock (sessions)
                if (--activeRequests == 0 && disposed) requestsDrained.TrySetResult();
        }
    }

    private async Task<HttpResponseMessage> PrepareAsync(RoleAdministrationEffects.Prepare input, CancellationToken token)
    {
        Require(selectedTransportConfigured && input.SubscriptionId == scope.SubscriptionId && input.ResourceGroup == scope.ResourceGroup &&
            input.Location == scope.Location && input.TenantId == scope.TenantId &&
            input.RoleDefinitionId == scope.IntendedRoleDefinitionId && input.IntendedPrincipalId == scope.IntendedPrincipalId &&
            input.Selection.Nonce != Guid.Empty && RoleAdministrationEffects.Members.Any(m =>
                m.Operation == input.Selection.Operation && m.Variants.Contains(input.Selection.Variant)));
        Session session;
        lock (sessions)
        {
            Require(!disposed && !sessions.ContainsKey(input.Selection.Nonce));
            session = new(input.Selection) { Active = 1 };
            sessions.Add(input.Selection.Nonce, session);
        }
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
            byte[] entropy = RandomNumberGenerator.GetBytes(32);
            SecretMaterial canary;
            try { canary = SecretMaterial.FromText(Convert.ToHexString(entropy)); }
            finally { CryptographicOperations.ZeroMemory(entropy); }
            lock (session)
            {
                if (session.Closed) { canary.Dispose(); throw Failure(); }
                session.Canary = canary;
            }
            bool createAssignment = !input.Selection.Operation.EndsWith(".CreateRoleAssignmentAsync", StringComparison.Ordinal);
            RoleAssignmentScope? borrowedGroup = ancestors.SingleOrDefault(a => a.Parent is ResourceGroupScope);
            RoleAssignmentScope? borrowedSubscription = ancestors.SingleOrDefault(a => a.Parent is SubscriptionScope);
            Require(input.Selection.Variant != "scope.resource-group" || borrowedGroup is not null);
            Require(input.Selection.Variant != "scope.subscription" || borrowedSubscription is not null);
            var plan = provisioner.PlanFixture(owner, input.Selection,
                new(borrowedGroup?.AssignmentId, borrowedSubscription?.AssignmentId, []), createAssignment);
            var prepared = await provisioner.ProvisionAsync(plan, canary.Reveal(), linked.Token).ConfigureAwait(false);
            Require(prepared.State == RoleFixtureProvisioner.State.Ready && prepared.CanaryVersion is not null &&
                prepared.CanarySha256 is not null);
            var subscription = new SubscriptionScope(scope.SubscriptionId);
            var group = new ResourceGroupScope(subscription, scope.ResourceGroup);
            var vault = new VaultScope(group, plan.VaultName);
            var target = input.Selection.Variant switch
            {
                "scope.resource-group" => borrowedGroup ?? throw Failure(),
                "scope.subscription" => borrowedSubscription ?? throw Failure(),
                _ => new RoleAssignmentScope(vault, Guid.Parse(plan.AssignmentId[(plan.AssignmentId.LastIndexOf('/') + 1)..]))
            };
            var binding = new RoleAdministrationCollector.Binding(input.Selection, plan.LeaseId, vault, target,
                scope.IntendedRoleDefinitionId, RoleFixtureProvisioner.Canary, prepared.CanaryVersion!, ancestors);
            var before = await collector.CollectAsync(collector.Arm(binding), binding,
                RoleAdministrationCollector.Phase.After, linked.Token).ConfigureAwait(false);
            Require(before.Complete && before.Intended.Status is SecretStatus.Success or SecretStatus.Denied &&
                before.Denied.Status == SecretStatus.Denied && before.Observer.Status == SecretStatus.Success &&
                before.Observer.Sha256 == prepared.CanarySha256);
            var journal = prepared.Journal ?? throw Failure();
            var facts = new LeaseFacts(input.Selection.Nonce, plan.LeaseId, observerIdentity,
                RoleAdministrationCollector.ArmOrigin, RoleAdministrationCollector.ArmRevision, time.GetUtcNow(),
                journal.Resources.Where(r => !r.Borrowed).Select(r => r.Id).ToArray());
            var lease = new RoleAdministrationEffects.Lease(facts, plan.VaultName,
                Guid.Parse(plan.AssignmentId[(plan.AssignmentId.LastIndexOf('/') + 1)..]), binding.SecretName,
                prepared.CanaryVersion!, prepared.CanarySha256!, before.Intended.Status,
                borrowedGroup?.AssignmentId, borrowedSubscription?.AssignmentId);
            lock (session)
            {
                Require(!session.Closed);
                session.Binding = binding;
                session.Lease = lease;
                session.Canary?.Dispose();
                session.Canary = null;
            }
            return Reply(lease);
        }
        finally
        {
            lock (session) if (session.Lease is null) session.Closed = true;
            End(session);
        }
    }

    private async Task<HttpResponseMessage> ObserveAsync(string route, ObserveLease request, CancellationToken token)
    {
        Session session;
        RoleAdministrationCollector.Binding binding;
        RoleAdministrationCollector.Window window;
        lock (sessions) Require(sessions.TryGetValue(request.Nonce, out session!));
        lock (session)
        {
            Require(!session.Closed && session.Binding is not null && session.Lease?.Facts.LeaseId == request.LeaseId);
            binding = session.Binding!;
            if (route == "/role/arm")
            {
                Require(session.Window is null && request.SubscriptionId is null &&
                    request.Phase == "subscribe-before-trigger");
                window = collector.Arm(binding);
                session.Window = window;
                return Reply(new ObservationSubscription(request.LeaseId, request.Nonce, window.Id, window.ArmedAt));
            }
            Require(session.Window is not null && request.SubscriptionId == session.Window.Id);
            window = session.Window!;
            session.Active++;
        }
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
            var phase = request.Phase switch
            {
                "assignment-baseline-before-dispatch" => RoleAdministrationCollector.Phase.Baseline,
                "assignment-and-effective-permission" => RoleAdministrationCollector.Phase.After,
                _ => throw Failure()
            };
            lock (session)
                if (phase == RoleAdministrationCollector.Phase.After)
                    Require(session.SelectedRequests > 0 && session.SelectedActive == 0);
            var measured = await collector.CollectAsync(window, binding, phase, linked.Token).ConfigureAwait(false);
            return Reply(RoleAdministrationEffects.ProjectMeasurement(measured, observerIdentity));
        }
        finally { End(session); }
    }

    private async Task<HttpResponseMessage> ReleaseAsync(FixtureSelector selector, CancellationToken token)
    {
        Session? session;
        lock (sessions) sessions.TryGetValue(selector.Nonce, out session);
        if (session is not null)
        {
            lock (session)
            {
                Require(session.Selector == selector);
                session.Closed = true;
                session.Stop.Cancel();
                if (session.Active == 0) EndClosed(session);
            }
        }
        int active = 0;
        if (session is not null) lock (session) active = session.Active;
        if (active == 0)
        {
            // Explicit release performs one bounded status step on retained
            // native handles, never a mutation replay or polling loop.
            provisioner.CloseSelectedRoot(owner, selector);
            await provisioner.SettleAsync(owner, selector, token).ConfigureAwait(false);
        }
        var state = active > 0 ? provisioner.CloseSelectedRoot(owner, selector) :
            (await provisioner.ReleaseAsync(owner, selector, purge: scope.AllowPurge,
                cancellationToken: token).ConfigureAwait(false)).Journal ?? throw Failure();
        return Reply(new RoleFixtureRelease.Measurement(selector, state.Closing,
            state.Resources.Count(r => r.ActiveDispatch != Guid.Empty) + active,
            state.Resources.Where(r => !r.Borrowed).Select(r => r.Id).ToArray(),
            state.Resources.Where(r => r.Borrowed).Select(r => r.Id).ToArray(),
            state.Resources.Where(r => !r.Borrowed && r.Absent).Select(r => r.Id).ToArray(),
            state.Resources.Where(r => !r.Borrowed && !r.Absent).Select(r => r.Id).ToArray()));
    }

    private bool Authenticate(HttpRequestMessage request)
    {
        if (request.Headers.Authorization is not { Scheme: "Bearer", Parameter: { Length: > 0 and <= 8192 } token }) return false;
        char[] expected = capability.ExportCharacters();
        byte[] expectedBytes = Encoding.UTF8.GetBytes(expected), supplied = Encoding.UTF8.GetBytes(token);
        try { return CryptographicOperations.FixedTimeEquals(SHA256.HashData(expectedBytes), SHA256.HashData(supplied)); }
        finally
        {
            Array.Clear(expected);
            CryptographicOperations.ZeroMemory(expectedBytes);
            CryptographicOperations.ZeroMemory(supplied);
        }
    }

    private static async Task<JsonDocument> Body(HttpRequestMessage request, CancellationToken token)
    {
        Require(request.Content is not null && request.Content.Headers.ContentLength is >= 0 and <= 65536);
        byte[] bytes = new byte[65537];
        try
        {
            using var stream = await request.Content!.ReadAsStreamAsync(token).ConfigureAwait(false);
            int count = 0, read;
            while (count < bytes.Length && (read = await stream.ReadAsync(bytes.AsMemory(count), token).ConfigureAwait(false)) != 0)
                count += read;
            Require(count <= 65536 && count == request.Content.Headers.ContentLength);
            var reader = new Utf8JsonReader(bytes.AsSpan(0, count), new JsonReaderOptions { MaxDepth = 32 });
            JsonDocument document = JsonDocument.ParseValue(ref reader);
            try
            {
                Require(!reader.Read());
                Unique(document.RootElement);
                return document;
            }
            catch { document.Dispose(); throw; }
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        static void Unique(JsonElement node)
        {
            if (node.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in node.EnumerateObject()) { Require(names.Add(property.Name)); Unique(property.Value); }
            }
            else if (node.ValueKind == JsonValueKind.Array)
                foreach (var item in node.EnumerateArray()) Unique(item);
        }
    }

    private static HttpResponseMessage Reply<T>(T value) => new(HttpStatusCode.OK)
    {
        Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(value, ManagementAdmission.Json))
    };
    private static HttpResponseMessage Error(HttpStatusCode status) => new(status)
    {
        Content = new StringContent("{\"error\":\"role-source-unavailable\"}", Encoding.UTF8, "application/json")
    };
    private static void End(Session session)
    {
        lock (session)
        {
            session.Active--;
            if (session.Closed && session.Active == 0) EndClosed(session);
        }
    }
    private static void EndClosed(Session session)
    {
        session.Canary?.Dispose();
        session.Canary = null;
    }
    public ValueTask DisposeAsync()
    {
        lock (sessions)
        {
            if (disposal is not null) return new(disposal);
            disposed = true;
            if (activeRequests == 0) requestsDrained.TrySetResult();
            disposal = DrainAsync(sessions.Values.ToArray());
            return new(disposal);
        }
    }
    private async Task DrainAsync(Session[] owned)
    {
        lifetime.Cancel();
        foreach (var session in owned)
            lock (session)
            {
                session.Closed = true;
                session.Stop.Cancel();
                if (session.Active == 0) EndClosed(session);
            }
        await requestsDrained.Task.ConfigureAwait(false);
        foreach (var session in owned) session.Stop.Dispose();
        lifetime.Dispose();
    }
    private static void Require(bool condition) { if (!condition) throw Failure(); }
    private static InvalidOperationException Failure() => new("role-source-unavailable");
    public override string ToString() => "[RoleFixtureObserverService]";
}
