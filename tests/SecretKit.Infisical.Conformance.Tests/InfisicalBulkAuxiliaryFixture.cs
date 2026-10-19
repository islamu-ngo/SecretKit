using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Independently authored, controlled provider. Its committed storage, request,
// commit, consumer-material, permission and cleanup journals are separate.
// This measures local authoring only; native qualification is always zero.
internal sealed class InfisicalBulkAuxiliaryFixture : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly byte[] storageKey = RandomNumberGenerator.GetBytes(32);
    private readonly Dictionary<string, Dictionary<string, StoredRow>> storage = [];
    private readonly Dictionary<string, BulkAuxiliaryRoot> roots = [];
    private readonly HashSet<string> sealedRoots = [];
    private readonly Dictionary<string, string> borrowed = new() { ["outside-root"] = "preserved" };
    internal object Gate { get; } = new();
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal InfisicalBulkAuxiliaryFixtureSource Source { get; }
    internal DateTimeOffset Now => new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private long sequence;
    internal long Tick() => ++sequence;
    internal List<RequestEvent> Requests { get; } = [];
    internal List<(string Root, int Rows)> Commits { get; } = [];
    internal List<(string Root, int Rows)> StorageReads { get; } = [];
    internal List<(string Folder, string Key, bool Delivered)> Materials { get; } = [];
    internal List<(string Role, bool Allowed)> Permissions { get; } = [];
    internal List<(string Root, bool Removed)> Cleanups { get; } = [];
    internal int ResidualCount { get { lock (Gate) return storage.Count; } }
    internal bool BorrowedPreserved => borrowed.Count == 1 && borrowed.GetValueOrDefault("outside-root") == "preserved";

    internal sealed record RequestEvent(string Id, string Root, string Method, string Shape,
        string Project, string Environment, string Folder, NativeIdentityRole Role, int Count);
    private sealed record StoredMetadata(string Key, byte[] Bytes, bool Encrypted);
    private sealed record StoredRow(string Key, byte[] Material, byte[] Comment,
        StoredMetadata[] Metadata, string[] Tags, Dictionary<string, string> Creation,
        bool? Multiline, byte[]? Reminder, double? Days, int Version);

    internal InfisicalBulkAuxiliaryFixture(string fault = "")
    {
        Fault = fault;
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Source = new(this);
        accept = AcceptAsync();
    }
    internal NativeEnvironment Environment(object families)
    {
        return NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families
        }, BulkAuxiliaryContract.Options));
    }
    internal void Open(BulkAuxiliaryRoot root, BulkAuxiliaryRow[] baseline)
    {
        // No setup before collision checks. The root is retained even when the
        // Open response is lost. Neither baseline nor expectations are borrowed.
        BulkAuxiliaryContract.Require(!roots.ContainsKey(root.Id) && !storage.ContainsKey(root.Folder) &&
            !roots.Values.Any(r => r.Nonce == root.Nonce || r.Folder == root.Folder) &&
            Fault != "collision");
        roots.Add(root.Id, root);
        storage.Add(root.Folder, baseline.ToDictionary(r => r.Key, r => Store(r)));
    }
    internal BulkAuxiliaryRow[] Storage(BulkAuxiliaryRoot root)
    {
        var actual = storage.TryGetValue(root.Folder, out var rows) ? rows.Values.Select(Read).ToArray() : [];
        StorageReads.Add((root.Id, actual.Length));
        return actual;
    }
    internal void Seal(BulkAuxiliaryRoot root) => sealedRoots.Add(root.Id);
    internal bool Close(BulkAuxiliaryRoot root, bool settled)
    {
        bool removed = false;
        if (settled && Fault != "cleanup")
        {
            if (storage.Remove(root.Folder, out var rows))
                foreach (var row in rows.Values) Erase(row);
            roots.Remove(root.Id);
            removed = true;
        }
        Cleanups.Add((root.Id, removed));
        return removed;
    }
    private StoredRow Store(BulkAuxiliaryRow row, bool applyFault = false) => new(row.Key,
        Encrypt(row.Material), Encrypt(row.Comment),
        row.Metadata.Select(m => new StoredMetadata(m.Key,
            m.Encrypted && !(applyFault && Fault == "plaintext-storage") ? Encrypt(m.Plaintext) : m.Plaintext.ToArray(),
            m.Encrypted && !(applyFault && Fault == "plaintext-storage"))).ToArray(),
        row.TagIds.ToArray(), new(row.CreationMetadata), row.SkipMultilineEncoding,
        row.ReminderNote is null ? null : Encrypt(row.ReminderNote), row.ReminderRepeatDays, row.Version);
    private BulkAuxiliaryRow Read(StoredRow row) => new(row.Key, Decrypt(row.Material), Decrypt(row.Comment),
        row.Metadata.Select(m => new BulkAuxiliaryMetadata(m.Key,
            m.Encrypted ? Decrypt(m.Bytes) : m.Bytes.ToArray(), m.Encrypted, m.Bytes.ToArray(), m.Encrypted)).ToArray(),
        row.Tags.ToArray(), new(row.Creation), row.Multiline,
        row.Reminder is null ? null : Decrypt(row.Reminder), row.Days, row.Version);
    private byte[] Encrypt(byte[] plain)
    {
        byte[] stored = new byte[plain.Length + 28];
        RandomNumberGenerator.Fill(stored.AsSpan(0, 12));
        using var aes = new AesGcm(storageKey, 16);
        aes.Encrypt(stored.AsSpan(0, 12), plain, stored.AsSpan(28), stored.AsSpan(12, 16));
        return stored;
    }
    private byte[] Decrypt(byte[] stored)
    {
        byte[] plain = new byte[stored.Length - 28];
        using var aes = new AesGcm(storageKey, 16);
        aes.Decrypt(stored.AsSpan(0, 12), stored.AsSpan(28), stored.AsSpan(12, 16), plain);
        return plain;
    }
    private static void Erase(StoredRow row)
    {
        CryptographicOperations.ZeroMemory(row.Material);
        CryptographicOperations.ZeroMemory(row.Comment);
        if (row.Reminder is not null) CryptographicOperations.ZeroMemory(row.Reminder);
        foreach (var m in row.Metadata) CryptographicOperations.ZeroMemory(m.Bytes);
    }
    private async Task AcceptAsync()
    {
        try
        {
            while (!shutdown.IsCancellationRequested)
            {
                var socket = await listener.AcceptTcpClientAsync(shutdown.Token);
                connections.Add(ServeAsync(socket));
            }
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
    }
    private async Task ServeAsync(TcpClient socket)
    {
        using (socket)
        {
            byte[]? body = null, response = null;
            try
            {
                var stream = socket.GetStream();
                var headers = new List<byte>();
                byte[] one = new byte[1];
                while (headers.Count < 32768)
                {
                    if (await stream.ReadAsync(one, shutdown.Token) == 0) return;
                    headers.Add(one[0]);
                    if (headers.Count >= 4 && headers.TakeLast(4).SequenceEqual("\r\n\r\n"u8.ToArray())) break;
                }
                string[] lines = Encoding.ASCII.GetString(headers.ToArray()).Split("\r\n");
                string[] request = lines[0].Split(' ');
                string role = lines.Single(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))
                    .Split(' ').Last();
                int length = int.Parse(lines.FirstOrDefault(l =>
                    l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?.Split(':')[1] ?? "0");
                if (length is < 0 or > 1024 * 1024) throw new InvalidOperationException("fixture-input");
                body = new byte[length];
                await stream.ReadExactlyAsync(body, shutdown.Token);
                using var document = JsonDocument.Parse(length == 0 ? "{}"u8.ToArray() : body);
                (int Status, object Payload) result;
                lock (Gate) result = Handle(request[0], new Uri(Origin, request[1]), role, document.RootElement);
                response = JsonSerializer.SerializeToUtf8Bytes(result.Payload);
                byte[] responseHeaders = Encoding.ASCII.GetBytes($"HTTP/1.1 {result.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(responseHeaders, shutdown.Token);
                // The real BCL response-headers event cancels lost-response cases.
                // No arbitrary delay, polling or background mutation is introduced.
                if (request[0] != "GET" && Source.LoseResponse)
                    await Source.ResponseRelease.Task.WaitAsync(shutdown.Token);
                await stream.WriteAsync(response, shutdown.Token);
            }
            catch (IOException) { }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            finally
            {
                if (body is not null) CryptographicOperations.ZeroMemory(body);
                if (response is not null) CryptographicOperations.ZeroMemory(response);
            }
        }
    }
    private (int, object) Handle(string method, Uri uri, string role, JsonElement body)
    {
        bool denied = role == "denied" && Fault != "denied-accepted";
        Permissions.Add((role, !denied));
        if (method == "GET")
        {
            if (denied) return (403, new { });
            string folder = Query(uri, "secretPath");
            var rows = storage.GetValueOrDefault(folder);
            if (uri.AbsolutePath == "/api/v4/secrets")
                return (200, new { secrets = rows?.Values.Select(r => new { secretKey = r.Key, version = r.Version }).ToArray() ?? [] });
            string key = Uri.UnescapeDataString(uri.AbsolutePath.Split('/').Last());
            bool found = rows is not null && rows.TryGetValue(key, out _);
            Materials.Add((folder, key, found));
            if (!found) return (404, new { });
            byte[] material = Decrypt(rows![key].Material);
            try
            {
                return (200, new
                {
                    secret = new
                    {
                        secretKey = key,
                        secretValue = Fault == "wrong-material" ? "incorrect" : Encoding.UTF8.GetString(material),
                        secretValueHidden = false,
                        version = rows[key].Version
                    }
                });
            }
            finally { CryptographicOperations.ZeroMemory(material); }
        }
        if (uri.AbsolutePath != "/api/v4/secrets/batch") return (404, new { });
        string selectedFolder = body.GetProperty("secretPath").GetString()!;
        var root = roots.Values.SingleOrDefault(r => r.Folder == selectedFolder);
        if (root is null || sealedRoots.Contains(root.Id)) return (409, new { });
        var mode = body.TryGetProperty("mode", out var m) ? m.GetString() switch
        {
            "ignore" => InfisicalBulkUpdateMode.Ignore,
            "upsert" => InfisicalBulkUpdateMode.Upsert,
            _ => InfisicalBulkUpdateMode.FailOnNotFound
        } : InfisicalBulkUpdateMode.FailOnNotFound;
        var inputs = body.GetProperty("secrets").EnumerateArray().Select(Parse).ToArray();
        var actualRole = role == "denied" ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime;
        bool exactPaths = body.GetProperty("secrets").EnumerateArray().All(row =>
            !row.TryGetProperty("secretPath", out var path) || path.GetString() == selectedFolder);
        Requests.Add(new(Guid.NewGuid().ToString("D"), root.Id, method,
            exactPaths ? BulkAuxiliaryContract.Shape(inputs, mode) : "foreign-row-path",
            body.GetProperty("projectId").GetString()!,
            body.GetProperty("environment").GetString()!, selectedFolder, actualRole, Fault == "replay" ? 2 : 1));
        if (denied) return (403, new { });
        var owned = storage[selectedFolder];
        if (method == "PATCH" && mode == InfisicalBulkUpdateMode.FailOnNotFound && inputs.Any(i => !owned.ContainsKey(i.Key)))
            return (404, new { });
        var results = new List<object>();
        int committed = 0;
        foreach (var input in inputs)
        {
            owned.TryGetValue(input.Key, out var previous);
            if (method == "PATCH" && previous is null && mode == InfisicalBulkUpdateMode.Ignore) continue;
            int version = (previous?.Version ?? 0) + 1;
            if (method == "DELETE")
            {
                if (owned.Remove(input.Key, out var removed)) { Erase(removed); committed++; }
            }
            else if (Fault != "ignored" && !(Fault == "partial" && committed == 1))
            {
                using var before = new RowLease(previous is null ? null : Read(previous));
                var old = before.Row;
                var next = new BulkAuxiliaryRow(input.NewName ?? input.Key,
                    BulkAuxiliaryContract.Bytes(input.Value ?? (old is null ? "" : Encoding.UTF8.GetString(old.Material))),
                    BulkAuxiliaryContract.Bytes(Fault == "ignored-comment" ? "" :
                        input.Comment ?? (old is null ? "" : Encoding.UTF8.GetString(old.Comment))),
                    input.Metadata is null ? CopyMetadata(old?.Metadata ?? []) :
                        input.Metadata.Select(x => new BulkAuxiliaryMetadata(x.Key, BulkAuxiliaryContract.Bytes(x.Value ?? ""),
                            x.Encrypted, [], false)).ToArray(),
                    input.TagIds ?? old?.TagIds.ToArray() ?? [],
                    input.CreationMetadata is null ? new(old?.CreationMetadata ?? []) : new(input.CreationMetadata),
                    input.SkipMultilineEncoding ?? old?.SkipMultilineEncoding ?? false,
                    input.ClearReminderNote ? null : input.ReminderNote is not null ? BulkAuxiliaryContract.Bytes(input.ReminderNote) :
                        old?.ReminderNote?.ToArray(),
                    input.ClearReminderRepeatDays ? null : input.ReminderRepeatDays ?? old?.ReminderRepeatDays, version);
                if (Fault == "retained-reminder" && old is not null)
                    next = next with { ReminderNote = old.ReminderNote?.ToArray(), ReminderRepeatDays = old.ReminderRepeatDays };
                if (previous is not null) { owned.Remove(input.Key); Erase(previous); }
                owned[next.Key] = Store(next, true);
                next.Erase();
                committed++;
            }
            results.Add(new
            {
                secretKey = input.NewName ?? input.Key,
                type = "shared",
                workspace = root.ProjectId,
                environment = root.Environment,
                version
            });
        }
        Commits.Add((root.Id, committed));
        if (Fault == "borrowed-damage") borrowed.Clear();
        return (200, new { secrets = results });
    }
    private static BulkAuxiliaryMetadata[] CopyMetadata(BulkAuxiliaryMetadata[] fields) =>
        fields.Select(m => new BulkAuxiliaryMetadata(m.Key, m.Plaintext.ToArray(), m.Encrypted, [], false)).ToArray();
    private sealed class RowLease(BulkAuxiliaryRow? row) : IDisposable
    {
        internal BulkAuxiliaryRow? Row => row;
        public void Dispose() => row?.Erase();
    }
    // Parse only the declared public batch input vocabulary. No vendor algorithm
    // is imported, and no source expectation is used by the provider's writes.
    private static NativeBulkEffects.BulkSecretInput Parse(JsonElement row)
    {
        static string? Text(JsonElement r, string name) =>
            r.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null ? v.GetString() : null;
        return new(row.GetProperty("secretKey").GetString()!, Text(row, "secretValue"), Text(row, "newSecretName"),
            Text(row, "secretComment"),
            row.TryGetProperty("secretMetadata", out var fields) ? fields.EnumerateArray().Select(m =>
                new NativeBulkEffects.BulkMetadataInput(m.GetProperty("key").GetString()!, Text(m, "value"),
                    m.TryGetProperty("isEncrypted", out var encrypted) && encrypted.GetBoolean())).ToArray() : null,
            row.TryGetProperty("tagIds", out var tags) ? tags.EnumerateArray().Select(t => t.GetString()!).ToArray() : null,
            row.TryGetProperty("secretPath", out _),
            row.TryGetProperty("skipMultilineEncoding", out var multiline) ? multiline.GetBoolean() : null,
            Text(row, "secretReminderNote"),
            row.TryGetProperty("secretReminderRepeatDays", out var days) && days.ValueKind != JsonValueKind.Null ? days.GetDouble() : null,
            row.TryGetProperty("secretReminderNote", out var note) && note.ValueKind == JsonValueKind.Null,
            row.TryGetProperty("secretReminderRepeatDays", out var repeat) && repeat.ValueKind == JsonValueKind.Null,
            row.TryGetProperty("metadata", out var creation) ?
                creation.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString()!) : null,
            Text(row, "type") == "personal" ? InfisicalSecretType.Personal : InfisicalSecretType.Shared);
    }
    private static string Query(Uri uri, string key) => uri.Query.TrimStart('?').Split('&')
        .Select(p => p.Split('=', 2)).Where(p => p.Length == 2 && p[0] == key)
        .Select(p => Uri.UnescapeDataString(p[1])).Single();
    public async ValueTask DisposeAsync()
    {
        Source.ResponseRelease.TrySetResult();
        await shutdown.CancelAsync();
        await accept;
        listener.Stop();
        await Task.WhenAll(connections);
        lock (Gate)
        {
            foreach (var rows in storage.Values) foreach (var row in rows.Values) Erase(row);
            storage.Clear(); roots.Clear();
            CryptographicOperations.ZeroMemory(storageKey);
        }
        shutdown.Dispose();
    }
}
