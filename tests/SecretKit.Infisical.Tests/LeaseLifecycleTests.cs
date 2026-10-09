using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class LeaseLifecycleTests
{
    [Test]
    public async Task InspectionNeverIssuesMaterialAndIndependentCopiesOutliveLocalDisposal()
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        InfisicalDynamicDefinition definition = await wire.CreateDatabaseAsync(client);
        await Assert.That((await client.ListDefinitionsAsync()).Value.Items.Count).IsEqualTo(1);
        await Assert.That((await client.InspectDefinitionAsync(definition.Target)).Value.Id).IsEqualTo(definition.Id);
        await Assert.That((await client.ListLeasesAsync(definition)).Value.Items.Count).IsEqualTo(0);
        await Assert.That(wire.LeaseCount).IsEqualTo(0);
        var receipt = new InfisicalDynamicMutationReceipt(definition.Target, InfisicalDynamicOperation.Acquire);
        using InfisicalDatabaseLease lease = (await client.AcquireDatabaseAsync(definition, receipt)).Value;
        using InfisicalDatabaseCredentials first = lease.CopyCredentials().Value;
        using InfisicalDatabaseCredentials second = lease.CopyCredentials().Value;
        string expected = first.RevealPassword();
        first.Dispose();
        await Assert.That(second.RevealPassword()).IsEqualTo(expected);
        await Assert.That((await client.InspectLeaseAsync(lease.Reference)).Value.Reference.Id).IsEqualTo(lease.Reference.Id);
        await Assert.That((await client.ListLeasesAsync(definition)).Value.Items.Count).IsEqualTo(1);
        lease.Dispose();
        await Assert.That(second.RevealPassword()).IsEqualTo(expected);
        await Assert.That(wire.LeaseCount).IsEqualTo(1);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        foreach (object value in new object[] { client, client.Scope, definition, lease.Reference, lease, second, receipt })
        {
            string formatted = value + JsonSerializer.Serialize(value);
            await Assert.That(formatted.Contains(expected, StringComparison.Ordinal)).IsFalse();
            await Assert.That(formatted.Contains(wire.Project, StringComparison.Ordinal)).IsFalse();
            await Assert.That(formatted.Contains(lease.Reference.Id.ToString(), StringComparison.Ordinal)).IsFalse();
        }
        // Explicit retained-reference cleanup remains available after material disposal.
        var cleanup = new InfisicalDynamicMutationReceipt(lease.Reference, InfisicalDynamicOperation.Revoke);
        await Assert.That((await client.RevokeLeaseAsync(lease.Reference, cleanup)).IsSuccess).IsTrue();
        await Assert.That(wire.LeaseCount).IsEqualTo(0);
        await Assert.That(() => second.RevealPassword()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task NativeRenewalCapsDeadlineAndExpiredConsumptionAndRenewalFailClosed()
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        InfisicalDynamicDefinition definition = await wire.CreateDatabaseAsync(client);
        using InfisicalDatabaseLease lease = (await client.AcquireDatabaseAsync(definition,
            new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using InfisicalDatabaseCredentials copy = lease.CopyCredentials().Value;
        DateTimeOffset initial = lease.Observation.ExpiresAt;
        wire.Time.Advance(TimeSpan.FromSeconds(10));
        var renewal = new InfisicalDynamicMutationReceipt(lease.Reference, InfisicalDynamicOperation.Renew);
        InfisicalLeaseObservation observed =
            (await client.RenewAsync(lease, renewal, new(TimeSpan.FromHours(1)))).Value;
        await Assert.That(observed.ExpiresAt).IsEqualTo(lease.Observation.CreatedAt + TimeSpan.FromSeconds(120));
        await Assert.That(observed.ExpiresAt > initial).IsTrue();
        await Assert.That(wire.LeaseVersion(lease.Reference.Id)).IsEqualTo(2);
        await Assert.That(renewal.Evidence).IsEqualTo(DispatchEvidence.Applied);
        wire.Time.Advance(TimeSpan.FromSeconds(110));
        await Assert.That(lease.State).IsEqualTo(InfisicalLeaseLocalState.Expired);
        await Assert.That(lease.CopyCredentials().Status).IsEqualTo(SecretStatus.Expired);
        await Assert.That(() => copy.RevealPassword()).Throws<InvalidOperationException>();
        var expired = new InfisicalDynamicMutationReceipt(lease.Reference, InfisicalDynamicOperation.Renew);
        await Assert.That((await client.RenewAsync(lease, expired)).Status).IsEqualTo(SecretStatus.Expired);
        await Assert.That(expired.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(wire.LeaseVersion(lease.Reference.Id)).IsEqualTo(2);
        await Assert.That(wire.LeaseCount).IsEqualTo(1);
    }

    [Test]
    public async Task ExplicitScopedRevocationInvalidatesCopiesButNotOtherLeases()
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        InfisicalDynamicDefinition definition = await wire.CreateDatabaseAsync(client);
        using InfisicalDatabaseLease first = (await client.AcquireDatabaseAsync(definition,
            new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using InfisicalDatabaseLease second = (await client.AcquireDatabaseAsync(definition,
            new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using InfisicalDatabaseCredentials copy = first.CopyCredentials().Value;
        var revoke = new InfisicalDynamicMutationReceipt(first.Reference, InfisicalDynamicOperation.Revoke);
        InfisicalDynamicDeletion deleted = (await client.RevokeAsync(first, revoke)).Value;
        await Assert.That(wire.LeaseCount).IsEqualTo(1);
        await Assert.That(first.State).IsEqualTo(InfisicalLeaseLocalState.Revoked);
        await Assert.That(() => copy.RevealUsername()).Throws<InvalidOperationException>();
        using InfisicalDatabaseCredentials other = second.CopyCredentials().Value;
        await Assert.That(other.RevealUsername().Length > 0).IsTrue();
        await Assert.That(deleted.ExternalRevocationVerified).IsFalse();
        await Assert.That(deleted.ForcedRecordRemoval).IsFalse();
        await Assert.That(revoke.Evidence).IsEqualTo(DispatchEvidence.Applied);
    }

    [Test]
    public async Task LostCommittedAcquisitionIsUnknownAndCannotReplayOrGuessCleanup()
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        InfisicalDynamicDefinition definition = await wire.CreateDatabaseAsync(client);
        wire.DropNextMutation = true;
        var acquire = new InfisicalDynamicMutationReceipt(definition.Target, InfisicalDynamicOperation.Acquire);
        await Assert.That((await client.AcquireDatabaseAsync(definition, acquire)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(acquire.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(wire.LeaseCount).IsEqualTo(1);
        await Assert.That((await client.AcquireDatabaseAsync(definition, acquire)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.LeaseCount).IsEqualTo(1);
        await Assert.That((await client.ListLeasesAsync(definition)).Value.Items.Count).IsEqualTo(1);
    }

    [Test]
    public async Task LostCommittedRenewalRetainsUnknownAndDoesNotReplayOrRevoke()
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        InfisicalDynamicDefinition definition = await wire.CreateDatabaseAsync(client);
        using InfisicalDatabaseLease lease = (await client.AcquireDatabaseAsync(definition,
            new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using InfisicalDatabaseCredentials copy = lease.CopyCredentials().Value;
        wire.DropNextMutation = true;
        var receipt = new InfisicalDynamicMutationReceipt(lease.Reference, InfisicalDynamicOperation.Renew);
        await Assert.That((await client.RenewAsync(lease, receipt)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(wire.LeaseVersion(lease.Reference.Id)).IsEqualTo(2);
        await Assert.That(lease.State).IsEqualTo(InfisicalLeaseLocalState.EffectUnknown);
        await Assert.That(() => copy.RevealPassword()).Throws<InvalidOperationException>();
        await Assert.That((await client.RenewAsync(lease, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.LeaseCount).IsEqualTo(1);
        await Assert.That(wire.LeaseVersion(lease.Reference.Id)).IsEqualTo(2);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task PreSendAndPostCommitCancellationPreserveCallerHeldAcquisitionReceipt(bool afterSend)
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        InfisicalDynamicDefinition definition = await wire.CreateDatabaseAsync(client);
        using var cancellation = new CancellationTokenSource();
        var receipt = new InfisicalDynamicMutationReceipt(definition.Target, InfisicalDynamicOperation.Acquire);
        TaskCompletionSource committed = wire.ArmCommitBarrier();
        if (!afterSend) { cancellation.Cancel(); }
        Task<SecretOutcome<InfisicalDatabaseLease>> pending =
            client.AcquireDatabaseAsync(definition, receipt, cancellationToken: cancellation.Token).AsTask();
        if (afterSend)
        {
            await committed.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancellation.Cancel();
        }
        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(afterSend ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.NotDispatched);
        await Assert.That(wire.LeaseCount).IsEqualTo(afterSend ? 1 : 0);
    }

    [Test]
    public async Task CancelCommittedRenewalAndConcurrentRevokePreserveTruthfulState()
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        InfisicalDynamicDefinition definition = await wire.CreateDatabaseAsync(client);
        using InfisicalDatabaseLease lease = (await client.AcquireDatabaseAsync(definition,
            new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        TaskCompletionSource committed = wire.ArmCommitBarrier();
        using var cancellation = new CancellationTokenSource();
        var renew = new InfisicalDynamicMutationReceipt(lease.Reference, InfisicalDynamicOperation.Renew);
        Task<SecretOutcome<InfisicalLeaseObservation>> pending =
            client.RenewAsync(lease, renew, cancellationToken: cancellation.Token).AsTask();
        await committed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var revoke = new InfisicalDynamicMutationReceipt(lease.Reference, InfisicalDynamicOperation.Revoke);
        await Assert.That((await client.RevokeAsync(lease, revoke)).Status).IsEqualTo(SecretStatus.Conflict);
        await Assert.That(revoke.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        cancellation.Cancel();
        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await Assert.That(renew.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(lease.State).IsEqualTo(InfisicalLeaseLocalState.EffectUnknown);
        await Assert.That(wire.LeaseVersion(lease.Reference.Id)).IsEqualTo(2);
        await Assert.That(wire.LeaseCount).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RevocationCancellationRetainsPreDispatchOrLostCommittedDeletion(bool afterSend)
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        InfisicalDynamicDefinition definition = await wire.CreateDatabaseAsync(client);
        using InfisicalDatabaseLease lease = (await client.AcquireDatabaseAsync(definition,
            new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        using var cancellation = new CancellationTokenSource();
        var receipt = new InfisicalDynamicMutationReceipt(lease.Reference, InfisicalDynamicOperation.Revoke);
        TaskCompletionSource committed = wire.ArmCommitBarrier();
        if (!afterSend) { cancellation.Cancel(); }
        Task<SecretOutcome<InfisicalDynamicDeletion>> pending =
            client.RevokeAsync(lease, receipt, cancellationToken: cancellation.Token).AsTask();
        if (afterSend)
        {
            await committed.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancellation.Cancel();
        }
        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(afterSend ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.NotDispatched);
        await Assert.That(wire.LeaseCount).IsEqualTo(afterSend ? 0 : 1);
        await Assert.That(lease.State).IsEqualTo(afterSend ? InfisicalLeaseLocalState.EffectUnknown : InfisicalLeaseLocalState.Active);
    }

    [Test]
    public async Task ClientDisposalDoesNotDisposeHostTransportOrImplicitlyRevokeLeases()
    {
        using var wire = new DynamicWireFixture();
        InfisicalDynamicClient first = wire.Client();
        InfisicalDynamicDefinition definition = await wire.CreateDatabaseAsync(first);
        using InfisicalDatabaseLease lease = (await first.AcquireDatabaseAsync(definition,
            new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        await first.DisposeAsync();
        using InfisicalDatabaseCredentials credentials = lease.CopyCredentials().Value;
        await Assert.That(credentials.RevealPassword().Length > 0).IsTrue();
        await Assert.That(wire.LeaseCount).IsEqualTo(1);
        await using InfisicalDynamicClient second = wire.Client();
        InfisicalDynamicDefinition inspected = (await second.InspectDefinitionAsync(second.Definition(definition.Target.Name))).Value;
        await Assert.That((await second.ListLeasesAsync(inspected)).Value.Items.Count).IsEqualTo(1);
    }

    [Test]
    public async Task ForeignScopesAndWrongOperationReceiptsFailBeforeMutation()
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient first = wire.Client();
        await using InfisicalDynamicClient second = wire.Client();
        InfisicalDynamicDefinition definition = await wire.CreateDatabaseAsync(first);
        var acquire = new InfisicalDynamicMutationReceipt(definition.Target, InfisicalDynamicOperation.Acquire);
        await Assert.That((await second.AcquireDatabaseAsync(definition, acquire)).Status).IsEqualTo(SecretStatus.Invalid);
        var wrong = new InfisicalDynamicMutationReceipt(definition.Target, InfisicalDynamicOperation.DeleteDefinition);
        await Assert.That((await first.AcquireDatabaseAsync(definition, wrong)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(acquire.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(wire.LeaseCount).IsEqualTo(0);
        using InfisicalDatabaseLease lease = (await first.AcquireDatabaseAsync(definition, acquire)).Value;
        using InfisicalDatabaseLease other = (await first.AcquireDatabaseAsync(definition,
            new(definition.Target, InfisicalDynamicOperation.Acquire))).Value;
        var wrongLease = new InfisicalDynamicMutationReceipt(other.Reference, InfisicalDynamicOperation.Revoke);
        await Assert.That((await first.RevokeAsync(lease, wrongLease)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.LeaseCount).IsEqualTo(2);
    }

    [Test]
    public async Task ForeignReturnedLeaseCoordinatesAndPolicyCannotBecomeUsableMaterial()
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        InfisicalDynamicDefinition definition = await wire.CreateDatabaseAsync(client);
        foreach (string fault in new[] { "folder", "definition", "name", "max-expiry", "missing-data" })
        {
            wire.FaultNextAcquisition = fault;
            var receipt = new InfisicalDynamicMutationReceipt(definition.Target, InfisicalDynamicOperation.Acquire);
            await Assert.That((await client.AcquireDatabaseAsync(definition, receipt)).Status).IsEqualTo(SecretStatus.Unknown);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        }
        await Assert.That(wire.LeaseCount).IsEqualTo(5);
    }
}

/// <summary>Managed public wire seam with actual in-memory native resources, no SDK implementation reuse.</summary>
internal sealed class DynamicWireFixture : HttpMessageHandler
{
    internal string Project { get; } = "project-" + Guid.NewGuid().ToString("N");
    internal string Environment { get; } = "environment-" + Guid.NewGuid().ToString("N");
    internal string FolderPath { get; } = "/folder-" + Guid.NewGuid().ToString("N");
    internal Guid FolderId { get; } = Guid.NewGuid();
    internal ManualTime Time { get; } = new();
    private readonly object _gate = new();
    private readonly Dictionary<string, DefinitionRow> _definitions = new(StringComparer.Ordinal);
    private readonly Dictionary<Guid, LeaseRow> _leases = new();
    internal bool DropNextMutation { get; set; }
    internal string? FaultNextAcquisition { get; set; }
    internal string? RawNextResponse { get; set; }
    internal HttpContent? NextStreamingResponse { get; set; }
    internal HttpStatusCode? StatusNextResponse { get; set; }
    internal TaskCompletionSource? _committed;
    private TaskCompletionSource? _held;
    internal int LeaseCount { get { lock (_gate) { return _leases.Count; } } }
    internal int DefinitionCount { get { lock (_gate) { return _definitions.Count; } } }
    internal int LeaseVersion(Guid id) { lock (_gate) { return _leases[id].Version; } }
    internal JsonElement Inputs(string name) { lock (_gate) { return _definitions[name].Inputs; } }
    internal InfisicalDynamicClient Client(int maximumItems = 128, int maximumBytes = 1024 * 1024) =>
        new(new Uri("https://dynamic.test"), new Tokens(), new(Project, Environment, FolderPath, FolderId),
            new InfisicalNetworkOptions { MaximumResponseBytes = maximumBytes }, Time, this, maximumItems);
    internal TaskCompletionSource ArmCommitBarrier()
    {
        _committed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        _held = new(TaskCreationOptions.RunContinuationsAsynchronously);
        return _committed;
    }
    internal async Task<InfisicalDynamicDefinition> CreateDatabaseAsync(InfisicalDynamicClient client)
    {
        using var profile = new NativeSqlDefinitionProfile(NativeSqlEngine.Postgres, "database.test", 5432,
            Material(), Material(), "database", "CREATE {{username}}", "DROP {{username}}");
        InfisicalDynamicTarget target = client.Definition("database");
        return (await client.CreateDefinitionAsync(target, profile, new(TimeSpan.FromSeconds(60)),
            new(TimeSpan.FromSeconds(120)), new(target, InfisicalDynamicOperation.CreateDefinition))).Value;
    }
    internal static string Material() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request.RequestUri?.GetLeftPart(UriPartial.Authority) != "https://dynamic.test" ||
            request.Headers.Authorization?.Scheme != "Bearer")
        {
            return Json(HttpStatusCode.Forbidden, new { });
        }
        if (NextStreamingResponse is { } streaming)
        {
            NextStreamingResponse = null;
            return new(HttpStatusCode.OK) { Content = streaming };
        }
        if (RawNextResponse is { } raw)
        {
            RawNextResponse = null;
            HttpStatusCode status = StatusNextResponse ?? HttpStatusCode.OK;
            StatusNextResponse = null;
            return new(status) { Content = new StringContent(raw, Encoding.UTF8, "application/json") };
        }
        string path = request.RequestUri.AbsolutePath;
        JsonElement? body = null;
        if (request.Content is not null)
        {
            using JsonDocument document = JsonDocument.Parse(await request.Content.ReadAsByteArrayAsync(cancellationToken));
            body = document.RootElement.Clone();
        }
        if (!MatchesScope(request.RequestUri, body))
        {
            return Json(HttpStatusCode.Forbidden, new { });
        }
        HttpResponseMessage response;
        bool mutation = request.Method != HttpMethod.Get;
        lock (_gate)
        {
            if (path == "/api/v1/dynamic-secrets" && request.Method == HttpMethod.Post)
            {
                JsonElement input = body!.Value;
                string name = input.GetProperty("name").GetString()!;
                JsonElement provider = input.GetProperty("provider");
                if (_definitions.ContainsKey(name))
                {
                    return Json(HttpStatusCode.Conflict, new { });
                }
                var row = new DefinitionRow
                {
                    Name = name,
                    Type = provider.GetProperty("type").GetString()!,
                    DefaultTtl = input.GetProperty("defaultTTL").GetString()!,
                    MaximumTtl = input.TryGetProperty("maxTTL", out JsonElement max) ? max.GetString() : null,
                    Inputs = provider.GetProperty("inputs").Clone()
                };
                _definitions.Add(name, row);
                response = Json(HttpStatusCode.OK, new { dynamicSecret = DefinitionWire(row) });
            }
            else if (path == "/api/v1/dynamic-secrets" && request.Method == HttpMethod.Get)
            {
                response = Json(HttpStatusCode.OK, new { dynamicSecrets = _definitions.Values.Select(row => DefinitionWire(row)).ToArray() });
            }
            else if (path == "/api/v1/dynamic-secrets/leases" && request.Method == HttpMethod.Post)
            {
                string name = body!.Value.GetProperty("dynamicSecretName").GetString()!;
                if (!_definitions.TryGetValue(name, out DefinitionRow? definition))
                {
                    return Json(HttpStatusCode.NotFound, new { });
                }
                var row = new LeaseRow { Definition = definition, Created = Time.GetUtcNow(), Expires = Time.GetUtcNow() + Seconds(definition.DefaultTtl) };
                _leases.Add(row.Id, row);
                string? fault = FaultNextAcquisition;
                FaultNextAcquisition = null;
                response = Json(HttpStatusCode.OK, new
                {
                    dynamicSecret = DefinitionWire(definition, fault),
                    lease = LeaseWire(row, fault),
                    data = fault == "missing-data" ? null : new { DB_USERNAME = row.Username, DB_PASSWORD = row.Password }
                });
            }
            else if (path.StartsWith("/api/v1/dynamic-secrets/leases/", StringComparison.Ordinal))
            {
                string[] parts = path.Split('/');
                if (!Guid.TryParse(parts[5], out Guid id) || !_leases.TryGetValue(id, out LeaseRow? row))
                {
                    return Json(HttpStatusCode.NotFound, new { });
                }
                if (request.Method == HttpMethod.Post && parts.Length == 7 && parts[6] == "renew")
                {
                    TimeSpan increment = body!.Value.TryGetProperty("ttl", out JsonElement ttl)
                        ? Seconds(ttl.GetString()!) : Seconds(row.Definition.DefaultTtl);
                    DateTimeOffset extended = row.Expires + increment;
                    DateTimeOffset maximum = row.Created + Seconds(row.Definition.MaximumTtl ?? "31536000s");
                    row.Expires = extended > maximum ? maximum : extended;
                    row.Version++;
                    response = Json(HttpStatusCode.OK, new { lease = LeaseWire(row) });
                }
                else if (request.Method == HttpMethod.Delete)
                {
                    _leases.Remove(id);
                    response = Json(HttpStatusCode.OK, new { lease = LeaseWire(row) });
                }
                else
                {
                    response = Json(HttpStatusCode.OK, new { lease = LeaseWire(row, includeDefinition: true) });
                }
            }
            else
            {
                string[] parts = path.Split('/');
                string name = Uri.UnescapeDataString(parts[4]);
                if (!_definitions.TryGetValue(name, out DefinitionRow? definition))
                {
                    return Json(HttpStatusCode.NotFound, new { });
                }
                if (parts.Length == 6 && parts[5] == "leases")
                {
                    response = Json(HttpStatusCode.OK, new
                    {
                        leases = _leases.Values.Where(row => row.Definition.Id == definition.Id).Select(row => LeaseWire(row)).ToArray()
                    });
                }
                else if (request.Method == HttpMethod.Patch)
                {
                    JsonElement policy = body!.Value.GetProperty("data");
                    if (policy.TryGetProperty("defaultTTL", out JsonElement defaultTtl))
                    {
                        definition.DefaultTtl = defaultTtl.GetString()!;
                    }
                    if (policy.TryGetProperty("maxTTL", out JsonElement maximumTtl))
                    {
                        definition.MaximumTtl = maximumTtl.GetString();
                    }
                    if (policy.TryGetProperty("inputs", out JsonElement inputs))
                    {
                        definition.Inputs = inputs.Clone();
                    }
                    if (policy.TryGetProperty("newName", out JsonElement newName))
                    {
                        _definitions.Remove(name);
                        definition.Name = newName.GetString()!;
                        _definitions.Add(definition.Name, definition);
                    }
                    definition.Version++;
                    response = Json(HttpStatusCode.OK, new { dynamicSecret = DefinitionWire(definition) });
                }
                else if (request.Method == HttpMethod.Delete)
                {
                    _definitions.Remove(name);
                    foreach (Guid id in _leases.Where(pair => pair.Value.Definition.Id == definition.Id).Select(pair => pair.Key).ToArray())
                    {
                        _leases.Remove(id);
                    }
                    response = Json(HttpStatusCode.OK, new { dynamicSecret = DefinitionWire(definition) });
                }
                else
                {
                    response = Json(HttpStatusCode.OK, new { dynamicSecret = DefinitionWire(definition) });
                }
            }
        }
        if (mutation && _committed is { } committed && _held is { } held)
        {
            _committed = null;
            _held = null;
            committed.TrySetResult();
            try { await held.Task.WaitAsync(cancellationToken); }
            catch { response.Dispose(); throw; }
        }
        if (mutation && DropNextMutation)
        {
            DropNextMutation = false;
            response.Dispose();
            throw new HttpRequestException(Material() + Project);
        }
        return response;
    }
    private bool MatchesScope(Uri uri, JsonElement? body)
    {
        if (body is { } value)
        {
            return value.GetProperty("projectSlug").GetString() == Project &&
                value.GetProperty("environmentSlug").GetString() == Environment && value.GetProperty("path").GetString() == FolderPath;
        }
        Dictionary<string, string> query = uri.Query.TrimStart('?').Split('&').Select(pair => pair.Split('=', 2))
            .ToDictionary(pair => pair[0], pair => Uri.UnescapeDataString(pair[1]), StringComparer.Ordinal);
        return query.GetValueOrDefault("projectSlug") == Project && query.GetValueOrDefault("environmentSlug") == Environment &&
            query.GetValueOrDefault("path") == FolderPath;
    }
    private object DefinitionWire(DefinitionRow row, string? fault = null) => new
    {
        id = row.Id,
        name = fault == "name" ? "foreign" : row.Name,
        type = row.Type,
        folderId = fault == "folder" ? Guid.NewGuid() : FolderId,
        defaultTTL = row.DefaultTtl,
        maxTTL = row.MaximumTtl,
        createdAt = Time.GetUtcNow(),
        updatedAt = Time.GetUtcNow(),
        version = row.Version,
        inputs = row.Inputs,
        status = (string?)null
    };
    private object LeaseWire(LeaseRow row, string? fault = null, bool includeDefinition = false) => new
    {
        id = row.Id,
        dynamicSecretId = fault == "definition" ? Guid.NewGuid() : row.Definition.Id,
        createdAt = row.Created,
        expireAt = fault == "max-expiry" ? row.Created + TimeSpan.FromHours(1) : row.Expires,
        updatedAt = Time.GetUtcNow(),
        version = row.Version,
        externalEntityId = row.Username,
        status = (string?)null,
        dynamicSecret = includeDefinition ? DefinitionWire(row.Definition) : null
    };
    private static TimeSpan Seconds(string value) => TimeSpan.FromSeconds(long.Parse(value[..^1], System.Globalization.CultureInfo.InvariantCulture));
    private static HttpResponseMessage Json(HttpStatusCode status, object value) => new(status)
    {
        Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json")
    };
    private sealed class DefinitionRow
    {
        internal Guid Id { get; } = Guid.NewGuid();
        internal required string Name { get; set; }
        internal required string Type { get; init; }
        internal required string DefaultTtl { get; set; }
        internal string? MaximumTtl { get; set; }
        internal JsonElement Inputs { get; set; }
        internal int Version { get; set; } = 1;
    }
    private sealed class LeaseRow
    {
        internal Guid Id { get; } = Guid.NewGuid();
        internal required DefinitionRow Definition { get; init; }
        internal DateTimeOffset Created { get; init; }
        internal DateTimeOffset Expires { get; set; }
        internal string Username { get; } = Material();
        internal string Password { get; } = Material();
        internal int Version { get; set; } = 1;
    }
    internal sealed class ManualTime : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 9, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        internal void Advance(TimeSpan duration) => _now += duration;
    }
    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText(Material()))));
        }
    }
}
