using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Infisical.Dynamic;

// Installed public APIs only. These synthetic native records establish local lifecycle
// evidence, never database revocation, consumer delivery, or live provider qualification.
// allow: SIZE_OK - the installed witness and its wire fixtures must remain self-contained in this owned file.
internal static class SqlLifecycleScenario
{
    private static readonly Uri Origin = new("https://sql-lifecycle.invalid");
    private static readonly Guid Folder = Guid.Parse("9818e9e1-4ae7-4f3c-b884-d4d33e1ac920");
    private static readonly Guid Rotation = Guid.Parse("82e9b60a-cbb8-40f2-bb70-320afab59353");
    private const string Project = "synthetic-project";
    private const string Username = "synthetic-sql-user";
    private const string Password = "synthetic-sql-password";
    private const string Token = "synthetic-access-token";
    private static readonly DateTimeOffset Now = new(2026, 11, 6, 0, 0, 0, TimeSpan.Zero);

    internal static async Task RunAsync()
    {
        using var wire = new SqlWire();
        var tokens = new Tokens();
        await using var client = new InfisicalDynamicClient(Origin, tokens,
            new(Project, "synthetic-env", "/", Folder),
            new() { Transport = InfisicalTransportOptions.HostControlled(wire) }, new Clock());
        InfisicalDynamicDefinition definition =
            (await client.InspectDefinitionAsync(client.Definition("database"))).Value;
        var acquire = new InfisicalDynamicMutationReceipt(definition.Target, InfisicalDynamicOperation.Acquire);
        using InfisicalDatabaseLease lease = (await client.AcquireDatabaseAsync(definition, acquire)).Value;
        using InfisicalDatabaseCredentials first = lease.CopyCredentials().Value;
        using InfisicalDatabaseCredentials second = lease.CopyCredentials().Value;
        Check(first.RevealUsername() == Username && second.RevealPassword() == Password &&
            wire.Leases.Count == 1 && acquire.Evidence == DispatchEvidence.Applied, "acquire and copies");
        Protected(lease, first, second, definition, acquire);
        InfisicalLeaseReference alias = (await client.ListLeasesAsync(definition)).Value.Items.Single().Reference;
        var revoke = new InfisicalDynamicMutationReceipt(alias, InfisicalDynamicOperation.Revoke);
        InfisicalDynamicDeletion revoked = (await client.RevokeLeaseAsync(alias, revoke)).Value;
        Check(wire.Leases.Count == 0 && revoke.Evidence == DispatchEvidence.Applied &&
            !revoked.ExternalRevocationVerified && lease.State == InfisicalLeaseLocalState.Revoked,
            "listed alias revocation");
        Denied(first);
        Denied(second);
        Check(!lease.CopyCredentials().IsSuccess, "revoked lease copy");

        var childAcquire = new InfisicalDynamicMutationReceipt(definition.Target, InfisicalDynamicOperation.Acquire);
        using InfisicalDatabaseLease child = (await client.AcquireDatabaseAsync(definition, childAcquire)).Value;
        using InfisicalDatabaseCredentials childCopy = child.CopyCredentials().Value;
        Check(childCopy.RevealPassword() == Password && wire.Leases.Count == 1 &&
            childAcquire.Evidence == DispatchEvidence.Applied, "child acquisition");
        var delete = new InfisicalDynamicMutationReceipt(definition.Target, InfisicalDynamicOperation.DeleteDefinition);
        InfisicalDynamicDeletion deleted = (await client.DeleteDefinitionAsync(definition, delete)).Value;
        Check(wire.Definitions.Count == 0 && wire.Leases.Count == 0 &&
            delete.Evidence == DispatchEvidence.Applied && !deleted.ExternalRevocationVerified &&
            child.State == InfisicalLeaseLocalState.Revoked, "parent deletion");
        Denied(childCopy);
        Check(!child.CopyCredentials().IsSuccess, "deleted parent copy");

        wire.Seed("original", Guid.Parse("7997993c-51ec-40f4-95df-89a10dbdce17"));
        InfisicalDynamicDefinition stale = (await client.InspectDefinitionAsync(client.Definition("original"))).Value;
        var rename = new InfisicalDynamicMutationReceipt(stale.Target, InfisicalDynamicOperation.UpdateDefinition);
        InfisicalDynamicDefinition renamed = (await client.UpdateDefinitionAsync(stale,
            new(newName: "renamed"), rename)).Value;
        Check(renamed.Id == stale.Id && renamed.Target.Name == "renamed" &&
            wire.Definitions["renamed"].Id == stale.Id && !wire.Definitions.ContainsKey("original") &&
            rename.Evidence == DispatchEvidence.Applied, "validated rename");
        // An independent provider actor reuses the old name with a distinct identity.
        Guid replacement = Guid.Parse("4dc2e299-b8fa-4f04-b1b0-0659f67ff60c");
        wire.Seed("original", replacement);
        int acquiredTokens = tokens.Acquisitions;
        int sent = wire.Requests;
        var staleAcquire = new InfisicalDynamicMutationReceipt(stale.Target, InfisicalDynamicOperation.Acquire);
        var staleUpdate = new InfisicalDynamicMutationReceipt(stale.Target, InfisicalDynamicOperation.UpdateDefinition);
        var staleDelete = new InfisicalDynamicMutationReceipt(stale.Target, InfisicalDynamicOperation.DeleteDefinition);
        Check((await client.AcquireDatabaseAsync(stale, staleAcquire)).Status == SecretStatus.Invalid, "stale acquire");
        Check((await client.UpdateDefinitionAsync(stale, new(newName: "hijacked"), staleUpdate)).Status ==
            SecretStatus.Invalid, "stale update");
        Check((await client.DeleteDefinitionAsync(stale, staleDelete)).Status == SecretStatus.Invalid, "stale delete");
        Check(tokens.Acquisitions == acquiredTokens && wire.Requests == sent &&
            staleAcquire.Evidence == DispatchEvidence.NotDispatched &&
            staleUpdate.Evidence == DispatchEvidence.NotDispatched &&
            staleDelete.Evidence == DispatchEvidence.NotDispatched &&
            wire.Definitions.Count == 2 && wire.Definitions["original"].Id == replacement &&
            wire.Definitions["original"].Version == 1 && wire.Definitions["renamed"].Id == stale.Id &&
            wire.Leases.Count == 0, "replacement preserved pre-credential");

        await RotationDrainAsync();
        Console.WriteLine("SQL_LIFECYCLE_OK");
    }

    private static async Task RotationDrainAsync()
    {
        using var wire = new RotationWire();
        var tokens = new Tokens();
        var authority = new SecretAuthority();
        await using var client = new InfisicalRotationClient(Origin, authority,
            new(authority, tokens, Project),
            new() { Transport = InfisicalTransportOptions.HostControlled(wire), ShutdownTimeout = TimeSpan.FromSeconds(30) });
        var target = new SecretReference(authority,
            new InfisicalRotationAddress(Project, "synthetic-env", "/", InfisicalRotationProfile.PostgresCredentials,
                Rotation.ToString("D")));
        var receipt = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
        Task<SecretOutcome<InfisicalRotationProgress>> pending = client.RotateSecretsAsync(target, receipt).AsTask();
        Task? draining = null;
        try
        {
            await wire.Reserved.Task.WaitAsync(TimeSpan.FromSeconds(10));
            draining = client.DisposeAsync().AsTask();
            Check(!draining.IsCompleted && !pending.IsCompleted &&
                receipt.Dispatch == InfisicalRotationDispatch.ResponseUnknown && wire.Pending,
                "disposal waits for reserved response");
            int acquiredTokens = tokens.Acquisitions;
            var rejected = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
            bool disposed = false;
            try { await client.RotateSecretsAsync(target, rejected); }
            catch (ObjectDisposedException) { disposed = true; }
            Check(disposed && tokens.Acquisitions == acquiredTokens && wire.Requests == 1 &&
                rejected.Dispatch == InfisicalRotationDispatch.NotDispatched, "disposed admission");
            wire.Release.TrySetResult();
            SecretOutcome<InfisicalRotationProgress> result = await pending.WaitAsync(TimeSpan.FromSeconds(10));
            await draining.WaitAsync(TimeSpan.FromSeconds(10));
            Check(result.IsSuccess && result.Value.NativeStatus == "pending" && wire.Pending &&
                receipt.Dispatch == InfisicalRotationDispatch.ResponseObserved &&
                receipt.Effect == InfisicalRotationEffect.AcceptedPending &&
                !result.Value.ConsumerDeliveryVerified && !result.Value.FleetConvergenceVerified &&
                wire.Requests == 1, "reserved rotation settles accepted pending");
            Protected(receipt, result.Value);
        }
        finally
        {
            wire.Release.TrySetResult();
            await pending.WaitAsync(TimeSpan.FromSeconds(10));
            if (draining is not null) await draining.WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    private static void Check(bool condition, string contract)
    {
        if (!condition) throw new InvalidOperationException("Installed SQL lifecycle failed: " + contract);
    }

    private static void Denied(InfisicalDatabaseCredentials credentials)
    {
        foreach (Func<string> reveal in new Func<string>[] { credentials.RevealUsername, credentials.RevealPassword })
        {
            bool denied = false;
            try { _ = reveal(); }
            catch (InvalidOperationException exception)
            {
                denied = true;
                Protected(exception.Message);
            }
            Check(denied, "governed export denied");
        }
    }

    private static void Protected(params object[] values)
    {
        foreach (object value in values)
        {
            string formatted = value + JsonSerializer.Serialize(value);
            foreach (string sensitive in new[] { Username, Password, Token, Project })
                Check(!formatted.Contains(sensitive, StringComparison.Ordinal), "protected formatting");
        }
    }

    private sealed class Clock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        internal int Acquisitions { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Acquisitions++;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText(Token))));
        }
    }

    private sealed class DefinitionRow(Guid id, string name)
    {
        internal Guid Id { get; } = id;
        internal string Name { get; set; } = name;
        internal int Version { get; set; } = 1;
        internal object Wire => new { id = Id, name = Name, type = "sql-database", folderId = Folder,
            defaultTTL = "60s", maxTTL = "120s", version = Version, createdAt = Now, updatedAt = Now };
    }

    private sealed class SqlWire : HttpMessageHandler
    {
        private int _issued;
        internal Dictionary<string, DefinitionRow> Definitions { get; } = new(StringComparer.Ordinal);
        internal Dictionary<Guid, DefinitionRow> Leases { get; } = [];
        internal int Requests { get; private set; }
        internal SqlWire() => Seed("database", Guid.Parse("6cf9b026-15d9-4fe1-b786-387b0ba24394"));
        internal void Seed(string name, Guid id) => Definitions.Add(name, new(id, name));
        private static object Lease(Guid id, DefinitionRow definition) => new { id,
            dynamicSecretId = definition.Id, createdAt = Now, updatedAt = Now,
            expireAt = Now.AddSeconds(60), version = 1, externalEntityId = Username, status = (string?)null };

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            Check(request.RequestUri?.GetLeftPart(UriPartial.Authority) == Origin.AbsoluteUri.TrimEnd('/') &&
                request.Headers.Authorization?.Parameter == Token, "synthetic dynamic authority");
            string path = request.RequestUri!.AbsolutePath;
            using JsonDocument? body = request.Content is null ? null :
                JsonDocument.Parse(await request.Content.ReadAsByteArrayAsync(cancellationToken));
            if (path == "/api/v1/dynamic-secrets/leases" && request.Method == HttpMethod.Post)
            {
                DefinitionRow definition = Definitions[body!.RootElement.GetProperty("dynamicSecretName").GetString()!];
                Guid id = Guid.Parse($"39f8c2e9-4c53-4701-9cf5-{++_issued:D12}");
                Leases.Add(id, definition);
                return Json(new { dynamicSecret = definition.Wire, lease = Lease(id, definition),
                    data = new { DB_USERNAME = Username, DB_PASSWORD = Password } });
            }
            if (path.StartsWith("/api/v1/dynamic-secrets/leases/", StringComparison.Ordinal) &&
                request.Method == HttpMethod.Delete)
            {
                Guid id = Guid.Parse(path.Split('/')[5]);
                DefinitionRow definition = Leases[id];
                Leases.Remove(id);
                return Json(new { lease = Lease(id, definition) });
            }
            string[] segments = path.Split('/');
            string name = Uri.UnescapeDataString(segments[4]);
            DefinitionRow selected = Definitions[name];
            if (segments.Length == 6 && segments[5] == "leases" && request.Method == HttpMethod.Get)
                return Json(new { leases = Leases.Where(pair => pair.Value.Id == selected.Id)
                    .Select(pair => Lease(pair.Key, pair.Value)).ToArray() });
            if (request.Method == HttpMethod.Patch)
            {
                Definitions.Remove(name);
                selected.Name = body!.RootElement.GetProperty("data").GetProperty("newName").GetString()!;
                selected.Version++;
                Definitions.Add(selected.Name, selected);
            }
            else if (request.Method == HttpMethod.Delete)
            {
                Definitions.Remove(name);
                foreach (Guid id in Leases.Where(pair => pair.Value.Id == selected.Id).Select(pair => pair.Key).ToArray())
                    Leases.Remove(id);
            }
            else Check(request.Method == HttpMethod.Get && segments.Length == 5, "synthetic dynamic route");
            return Json(new { dynamicSecret = selected.Wire });
        }
    }

    private sealed class RotationWire : HttpMessageHandler
    {
        internal TaskCompletionSource Reserved { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool Pending { get; private set; }
        internal int Requests { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            Check(request.Method == HttpMethod.Post &&
                request.RequestUri == new Uri(Origin, $"/api/v2/secret-rotations/postgres-credentials/{Rotation:D}/rotate-secrets") &&
                request.Headers.Authorization?.Parameter == Token, "synthetic rotation route");
            Pending = true;
            Reserved.TrySetResult();
            await Release.Task.WaitAsync(cancellationToken);
            return Json(new { secretRotation = new { id = Rotation, projectId = Project,
                type = "postgres-credentials", environment = new { slug = "synthetic-env" }, folder = new { path = "/" },
                rotationStatus = "pending", isAutoRotationEnabled = true, isLastRotationManual = true,
                lastRotationAttemptedAt = Now, lastRotatedAt = Now.AddDays(-1), lastRotationJobId = "synthetic-job" } });
        }
    }

    private static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json")
    };
}
