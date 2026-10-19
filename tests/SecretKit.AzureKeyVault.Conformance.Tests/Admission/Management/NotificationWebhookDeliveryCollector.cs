using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.AzureKeyVault.Management;
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.NotificationRuntimeTriggerCapture;
using N = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.NotificationAdministrationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Positive, authenticated HTTP observations linked to an original native write.
// Closing this receiver does NOT close the provider's delivery pipeline or prove
// exclusion. The host must keep the native capture alive through projection.
internal sealed class NotificationWebhookDeliveryCollector : IAsyncDisposable
{
    internal sealed record Limits(int MaximumBodyBytes, int MaximumRequests, int MaximumEvents,
        int MaximumNodes, int MaximumDepth, int MaximumHeaders, int MaximumHeaderBytes, TimeSpan Timeout);
    internal sealed record Binding([property: JsonIgnore] C.Binding Trigger,
        [property: JsonIgnore] string NotificationName, [property: JsonIgnore] string Correlation)
    {
        public override string ToString() => "[NotificationWebhookBinding]";
    }
    internal enum Failure { None, Bounds, Protocol, Unavailable }
    internal sealed class Window
    {
        internal Guid Id { get; } = Guid.NewGuid();
        public override string ToString() => "[NotificationWebhookWindow]";
    }
    internal sealed class ObservedDelivery
    {
        internal ObservedDelivery(Candidate candidate, Binding binding)
        {
            EventId = candidate.Id;
            Correlation = binding.Correlation;
            SubscriptionName = binding.NotificationName;
            VaultResourceId = VaultId(binding.Trigger);
            EventType = candidate.Kind;
            ReceivedAt = candidate.ReceivedAt;
            Headers = Array.AsReadOnly(candidate.Headers.ToArray());
        }
        internal string EventId { get; }
        internal string Correlation { get; }
        internal string SubscriptionName { get; }
        internal string VaultResourceId { get; }
        internal VaultNotificationEvent EventType { get; }
        internal DateTimeOffset ReceivedAt { get; }
        internal ReadOnlyCollection<N.Header> Headers { get; }
        internal N.Delivery Project() => new(EventId, Correlation, SubscriptionName, VaultResourceId,
            EventType, ReceivedAt, Headers.ToArray());
        public override string ToString() => "[ObservedNotificationDelivery]";
    }
    internal sealed class Measurement
    {
        private Measurement(Entry entry, ObservedDelivery[] deliveries, string[] requestIds)
        {
            Binding = entry.Binding;
            WindowId = entry.Window.Id;
            ArmedAt = entry.ArmedAt;
            AdmissionClosedAt = entry.AdmissionClosedAt;
            Failure = entry.Failure;
            Deliveries = Array.AsReadOnly(deliveries);
            NativeTriggerRequestIds = Array.AsReadOnly(requestIds);
            UnlinkedEvents = entry.Candidates.Count - deliveries.Length;
        }
        internal static Measurement Issue(NotificationWebhookDeliveryCollector source, Window window)
        {
            lock (source.gate)
            {
                var entry = source.Registered(window);
                Require(entry.Closing && entry.Active == 0 && entry.AdmissionClosedAt >= entry.ArmedAt);
                ObservedDelivery[] deliveries = entry.Candidates.Where(c => Linked(entry, c))
                    .Select(c => new ObservedDelivery(c, entry.Binding)).ToArray();
                string[] ids = deliveries.Length == 0 ? [] : [entry.Capture!.Measurement.NativeRequestId!];
                return new(entry, deliveries, ids);
            }
        }
        [JsonIgnore] internal Binding Binding { get; }
        internal Guid WindowId { get; }
        internal DateTimeOffset ArmedAt { get; }
        internal DateTimeOffset AdmissionClosedAt { get; }
        internal Failure Failure { get; }
        internal bool TaskDrained => true;
        internal bool Available => Failure == Failure.None && Deliveries.Count > 0;
        internal bool NativeWindowClosureEstablished => false;
        internal bool NativeFilterExclusionEstablished => false;
        internal bool ProviderIdentityEstablished => false;
        internal int UnlinkedEvents { get; }
        internal ReadOnlyCollection<ObservedDelivery> Deliveries { get; }
        internal ReadOnlyCollection<string> NativeTriggerRequestIds { get; }
        public override string ToString() => "[NotificationWebhookMeasurement]";
    }

    private sealed record Capture(C Source, C.Window Window, C.Measurement Measurement);
    internal sealed record Candidate(string Id, string Version, string SecretName, VaultNotificationEvent Kind,
        DateTimeOffset EventTime, DateTimeOffset ReceivedAt, string Digest, N.Header[] Headers);
    private sealed class Entry(Window window, Binding binding, DateTimeOffset armedAt,
        string[] headerNames, HashSet<string> secretNames)
    {
        internal readonly Window Window = window;
        internal readonly Binding Binding = binding;
        internal readonly DateTimeOffset ArmedAt = armedAt;
        internal readonly string[] HeaderNames = headerNames;
        internal readonly HashSet<string> SecretNames = secretNames;
        internal readonly List<Candidate> Candidates = [];
        internal readonly CancellationTokenSource Stop = new();
        internal readonly TaskCompletionSource Drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Linked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<Measurement>? Closed;
        internal Capture? Capture;
        internal int Active, Requests;
        internal bool Closing;
        internal Failure Failure;
        internal DateTimeOffset AdmissionClosedAt, LatestAdmission;
    }

    private readonly object gate = new();
    private readonly RoleFixtureJournal journal;
    private readonly string owner;
    private readonly Uri endpoint;
    private readonly byte[] path;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly Dictionary<Window, Entry> windows = new(ReferenceEqualityComparer.Instance);
    private readonly HashSet<Guid> nonces = [];
    private TaskCompletionSource? disposal;
    private bool disposed;

    internal NotificationWebhookDeliveryCollector(RoleFixtureJournal journal, string owner,
        Uri endpoint, Limits limits, TimeProvider? time = null)
    {
        Require(journal is not null && Text(owner, 128) && endpoint is
        { IsAbsoluteUri: true, Scheme: "https", UserInfo.Length: 0, Query.Length: 0, Fragment.Length: 0 } &&
            endpoint.AbsolutePath.Length is >= 32 and <= 2048 && limits is not null &&
            limits.MaximumBodyBytes is >= 1024 and <= 1024 * 1024 &&
            limits.MaximumRequests is > 0 and <= 4096 && limits.MaximumEvents is > 0 and <= 4096 &&
            limits.MaximumNodes is >= 16 and <= 65536 && limits.MaximumDepth is >= 4 and <= 32 &&
            limits.MaximumHeaders is >= 2 and <= 128 && limits.MaximumHeaderBytes is >= 256 and <= 65536 &&
            limits.Timeout > TimeSpan.Zero && limits.Timeout <= TimeSpan.FromMinutes(2));
        this.journal = journal;
        this.owner = owner;
        this.endpoint = endpoint;
        path = Encoding.UTF8.GetBytes(endpoint.AbsolutePath);
        this.limits = limits;
        this.time = time ?? TimeProvider.System;
    }

    internal Window Arm(Binding binding, string[] headerNames)
    {
        Require(binding is not null && binding.Trigger is not null && headerNames is { Length: <= 16 } &&
            headerNames.All(n => Text(n, 128) && n.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') &&
                !new[] { "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie" }.Contains(n, StringComparer.OrdinalIgnoreCase)) &&
            headerNames.Distinct(StringComparer.OrdinalIgnoreCase).Count() == headerNames.Length &&
            Text(binding.Correlation, 256) && binding.Trigger.ObservationId != Guid.Empty);
        var input = binding with { Trigger = binding.Trigger with { Selector = binding.Trigger.Selector with { } } };
        var vault = new VaultScope(new(new(input.Trigger.AzureSubscriptionId), input.Trigger.ResourceGroup), input.Trigger.VaultName);
        var scope = new NotificationScope(vault, input.NotificationName);
        string notification = vault.ExportResourceId() + VaultFixtureProvisioner.NotificationPrefix + scope.SubscriptionName;
        var root = journal.Read(owner, input.Trigger.Selector);
        Require(!root.Closing && root.LeaseId == input.Trigger.LeaseId && root.LeaseId != Guid.Empty &&
            root.Resources.All(r => r.ActiveDispatch == Guid.Empty) &&
            root.Resources.Any(r => r.Id == vault.ExportResourceId() &&
                r is { Borrowed: false, CleanupOnly: false, CreateAttempted: true, DeleteAttempted: false, Absent: false }) &&
            root.Resources.Any(r => r.Id == vault.ExportResourceId() + "/secrets/" + input.Trigger.RuntimeSecretName &&
                r is { Borrowed: false, CleanupOnly: false, CreateAttempted: true, DeleteAttempted: false, Absent: false }) &&
            root.Resources.Any(r => r.Id.Equals(notification, StringComparison.OrdinalIgnoreCase) &&
                r is { Borrowed: false, CleanupOnly: false }));
        string prefix = vault.ExportResourceId() + "/secrets/";
        var names = root.Resources.Where(r => !r.Borrowed && !r.CleanupOnly &&
                r.Id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && !r.Id[prefix.Length..].Contains('/'))
            .Select(r => r.Id[prefix.Length..]).ToHashSet(StringComparer.OrdinalIgnoreCase);
        string[] headers = headerNames.ToArray();
        var armedAt = time.GetUtcNow();
        lock (gate)
        {
            Require(!disposed && windows.Count < 32 && !nonces.Contains(input.Trigger.Selector.Nonce));
            var current = journal.Read(owner, input.Trigger.Selector);
            Require(!current.Closing && current.LeaseId == root.LeaseId &&
                current.Resources.All(r => r.ActiveDispatch == Guid.Empty));
            var window = new Window();
            windows.Add(window, new(window, input, armedAt, headers, names));
            nonces.Add(input.Trigger.Selector.Nonce);
            return window;
        }
    }

    internal void AttachCapture(Window window, C source, C.Window capture)
    {
        Binding binding;
        lock (gate) binding = Open(window).Binding;
        var measurement = source.Read(capture, binding.Trigger);
        source.ValidateMeasurement(journal, owner, capture, binding.Trigger, measurement);
        Require(measurement.TaskDrained && measurement.NativeAcknowledged && measurement.NativeSettled &&
            measurement.Status == SecretKit.Core.SecretStatus.Success && Text(measurement.Version, 128) &&
            Text(measurement.NativeRequestId, 128));
        lock (gate)
        {
            var entry = Open(window);
            Require(entry.Capture is null && measurement.StartedAt >= entry.ArmedAt);
            entry.Capture = new(source, capture, measurement);
            if (entry.Candidates.Any(c => Linked(entry, c))) entry.Linked.TrySetResult();
        }
    }

    internal Task WaitForLinkedDeliveryAsync(Window window, CancellationToken cancellationToken)
    {
        lock (gate) return Open(window).Linked.Task.WaitAsync(cancellationToken);
    }

    internal async Task<HttpResponseMessage> ReceiveAsync(Window window, HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (!Authenticate(request)) return Error(HttpStatusCode.Unauthorized);
        var admittedAt = time.GetUtcNow();
        Entry entry;
        lock (gate)
        {
            entry = Registered(window);
            if (disposed || entry.Closing) return Error(HttpStatusCode.Gone);
            if (++entry.Requests > limits.MaximumRequests)
            {
                entry.Failure = Failure.Bounds;
                return Error(HttpStatusCode.RequestEntityTooLarge);
            }
            entry.Active++;
            if (admittedAt > entry.LatestAdmission) entry.LatestAdmission = admittedAt;
        }
        byte[]? bytes = null;
        try
        {
            bytes = new byte[limits.MaximumBodyBytes + 1];
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token, entry.Stop.Token);
            var content = request.Content;
            Require(request.Method == HttpMethod.Post && content is not null);
            var headers = Headers(request, entry);
            Require(content.Headers.ContentType?.MediaType?.Equals("application/json", StringComparison.OrdinalIgnoreCase) == true &&
                content.Headers.ContentEncoding.Count == 0 && content.Headers.ContentLength is null or >= 0 &&
                (content.Headers.ContentLength is null || content.Headers.ContentLength <= limits.MaximumBodyBytes));
            string kind = Single(request, "aeg-event-type");
            Require(Single(request, "aeg-subscription-name").Equals(entry.Binding.NotificationName, StringComparison.OrdinalIgnoreCase) &&
                kind is "Notification" or "SubscriptionValidation");
            var stream = await content.ReadAsStreamAsync(linked.Token).ConfigureAwait(false);
            int count = 0;
            while (true)
            {
                int read = await stream.ReadAsync(bytes.AsMemory(count, bytes.Length - count), linked.Token).ConfigureAwait(false);
                linked.Token.ThrowIfCancellationRequested();
                if (read == 0) break;
                count += read;
                Require(count <= limits.MaximumBodyBytes);
            }
            using var document = JsonDocument.Parse(bytes.AsMemory(0, count), new JsonDocumentOptions { MaxDepth = limits.MaximumDepth });
            int nodes = 0;
            Unique(document.RootElement, ref nodes);
            Require(document.RootElement.ValueKind == JsonValueKind.Array &&
                document.RootElement.GetArrayLength() is > 0 &&
                document.RootElement.GetArrayLength() <= limits.MaximumEvents);
            var candidates = new List<Candidate>();
            string? validation = null;
            foreach (var value in document.RootElement.EnumerateArray())
            {
                Require(Only(value, "id", "topic", "subject", "eventType", "eventTime", "data", "dataVersion", "metadataVersion"));
                Require(String(value, "topic", 2048).Equals(VaultId(entry.Binding.Trigger), StringComparison.OrdinalIgnoreCase));
                _ = String(value, "id", 256);
                Require(String(value, "dataVersion", 16) == "1" && String(value, "metadataVersion", 16) == "1");
                var data = value.GetProperty("data");
                if (kind == "SubscriptionValidation")
                {
                    Require(document.RootElement.GetArrayLength() == 1 &&
                        String(value, "eventType", 128) == "Microsoft.EventGrid.SubscriptionValidationEvent" &&
                        Only(data, "validationCode", "validationUrl"));
                    validation = String(data, "validationCode", 512);
                    if (data.TryGetProperty("validationUrl", out var url))
                        Require(url.ValueKind == JsonValueKind.String && Text(url.GetString(), 2048) &&
                            Uri.TryCreate(url.GetString(), UriKind.Absolute, out var uri) && uri.Scheme == "https" && uri.UserInfo.Length == 0);
                    continue; // A handshake is not a delivery.
                }
                Require(Only(data, "Id", "VaultName", "ObjectType", "ObjectName", "Version", "NBF", "EXP") &&
                    String(data, "VaultName", 128).Equals(entry.Binding.Trigger.VaultName, StringComparison.OrdinalIgnoreCase) &&
                    String(data, "ObjectType", 32) == "Secret");
                string name = String(data, "ObjectName", 128), version = String(data, "Version", 128);
                Require(String(value, "subject", 128).Equals(name, StringComparison.OrdinalIgnoreCase) && entry.SecretNames.Contains(name));
                string id = String(data, "Id", 2048);
                Require(Uri.TryCreate(id, UriKind.Absolute, out var target) && target.Scheme == "https" &&
                    target.UserInfo.Length == 0 && target.Query.Length == 0 && target.Fragment.Length == 0 &&
                    target.GetLeftPart(UriPartial.Authority).Equals("https://" + entry.Binding.Trigger.VaultName + ".vault.azure.net", StringComparison.OrdinalIgnoreCase) &&
                    target.AbsolutePath == "/secrets/" + name + "/" + version);
                string type = String(value, "eventType", 128);
                var eventType = type switch
                {
                    "Microsoft.KeyVault.SecretNewVersionCreated" => VaultNotificationEvent.SecretNewVersionCreated,
                    "Microsoft.KeyVault.SecretNearExpiry" => VaultNotificationEvent.SecretNearExpiry,
                    "Microsoft.KeyVault.SecretExpired" => VaultNotificationEvent.SecretExpired,
                    _ => throw Invalid()
                };
                var eventTime = value.GetProperty("eventTime").GetDateTimeOffset();
                byte[] raw = Encoding.UTF8.GetBytes(value.GetRawText());
                string digest;
                try { digest = Convert.ToHexString(SHA256.HashData(raw)); }
                finally { CryptographicOperations.ZeroMemory(raw); }
                candidates.Add(new(String(value, "id", 256), version, name, eventType, eventTime,
                    admittedAt, digest, headers));
            }
            lock (gate)
            {
                Require(!disposed && !entry.Closing);
                foreach (var candidate in candidates)
                {
                    var previous = entry.Candidates.SingleOrDefault(c => c.Id == candidate.Id);
                    if (previous is not null)
                    {
                        Require(previous.Digest == candidate.Digest && previous.Headers.SequenceEqual(candidate.Headers));
                        continue;
                    }
                    Require(entry.Candidates.Count < limits.MaximumEvents);
                    entry.Candidates.Add(candidate);
                }
                if (entry.Candidates.Any(c => Linked(entry, c))) entry.Linked.TrySetResult();
            }
            return validation is null ? new(HttpStatusCode.OK) : Json(new { validationResponse = validation });
        }
        catch (Exception)
        {
            lock (gate) entry.Failure = Failure.Protocol;
            if (cancellationToken.IsCancellationRequested) throw;
            return Error(HttpStatusCode.BadRequest);
        }
        finally
        {
            if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
            lock (gate) if (--entry.Active == 0 && entry.Closing) entry.Drained.TrySetResult();
        }
    }

    internal Task<Measurement> CloseAsync(Window window, Binding binding, CancellationToken cancellationToken)
    {
        var observedAt = time.GetUtcNow();
        Entry entry;
        bool start;
        Task<Measurement> task;
        lock (gate)
        {
            entry = Registered(window);
            Require(!disposed && entry.Binding == binding);
            start = StartClose(entry, observedAt);
            task = entry.Closed!.Task;
        }
        if (start) _ = CompleteClose(entry);
        return task.WaitAsync(cancellationToken);
    }

    private bool StartClose(Entry entry, DateTimeOffset observedAt)
    {
        if (entry.Closed is not null) return false;
        entry.Closing = true;
        entry.AdmissionClosedAt = observedAt >= entry.LatestAdmission ? observedAt : entry.LatestAdmission;
        entry.Closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        if (entry.Active == 0) entry.Drained.TrySetResult();
        return true;
    }
    private async Task CompleteClose(Entry entry)
    {
        try
        {
            try { entry.Stop.Cancel(); }
            catch (Exception) { lock (gate) entry.Failure = Failure.Unavailable; }
            await entry.Drained.Task.ConfigureAwait(false);
            var capture = entry.Capture;
            if (capture is not null)
            {
                capture.Source.ValidateMeasurement(journal, owner, capture.Window, entry.Binding.Trigger, capture.Measurement);
            }
            lock (gate)
            {
                Require(entry.AdmissionClosedAt >= entry.ArmedAt);
                entry.Closed!.TrySetResult(Measurement.Issue(this, entry.Window));
            }
        }
        catch (Exception) { entry.Closed!.TrySetException(Invalid()); }
        finally { if (!entry.Linked.Task.IsCompleted) entry.Linked.TrySetException(Invalid()); }
    }

    private static bool Linked(Entry entry, Candidate candidate) => entry.Capture is { } capture &&
        candidate.Kind == VaultNotificationEvent.SecretNewVersionCreated &&
        candidate.SecretName.Equals(entry.Binding.Trigger.RuntimeSecretName, StringComparison.OrdinalIgnoreCase) &&
        candidate.Version == capture.Measurement.Version && candidate.EventTime >= capture.Measurement.StartedAt &&
        candidate.ReceivedAt >= entry.ArmedAt;

    private bool Authenticate(HttpRequestMessage request)
    {
        if (request.RequestUri is not { IsAbsoluteUri: true } uri || uri.Scheme != "https" ||
            uri.GetLeftPart(UriPartial.Authority) != endpoint.GetLeftPart(UriPartial.Authority) ||
            uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.UserInfo.Length != 0 || uri.AbsolutePath.Length > 2048)
            return false;
        byte[] actual = Encoding.UTF8.GetBytes(uri.AbsolutePath);
        try { lock (gate) return !disposed && CryptographicOperations.FixedTimeEquals(actual, path); }
        finally { CryptographicOperations.ZeroMemory(actual); }
    }
    private N.Header[] Headers(HttpRequestMessage request, Entry entry)
    {
        Require(request.Content is not null);
        int count = 0, bytes = 0;
        foreach (var header in request.Headers.Concat(request.Content.Headers))
            foreach (string value in header.Value)
            {
                Require(++count <= limits.MaximumHeaders && Text(header.Key, 128) && Text(value, limits.MaximumHeaderBytes));
                bytes += Encoding.UTF8.GetByteCount(header.Key) + Encoding.UTF8.GetByteCount(value);
                Require(bytes <= limits.MaximumHeaderBytes);
            }
        return entry.HeaderNames.Where(n => request.Headers.Contains(n))
            .Select(n => new N.Header(n, Single(request, n))).ToArray();
    }
    private static string Single(HttpRequestMessage request, string name)
    {
        Require(request.Headers.TryGetValues(name, out var values));
        string[] all = values.ToArray();
        Require(all.Length == 1 && Text(all[0], 8192));
        return all[0];
    }
    private void Unique(JsonElement value, ref int nodes)
    {
        Require(++nodes <= limits.MaximumNodes);
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in value.EnumerateObject())
            {
                Require(names.Add(property.Name));
                Unique(property.Value, ref nodes);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var child in value.EnumerateArray()) Unique(child, ref nodes);
    }
    private static bool Only(JsonElement value, params string[] names) => value.ValueKind == JsonValueKind.Object &&
        value.EnumerateObject().All(p => names.Contains(p.Name, StringComparer.Ordinal));
    private static string String(JsonElement value, string name, int maximum)
    {
        var item = value.GetProperty(name);
        Require(item.ValueKind == JsonValueKind.String && Text(item.GetString(), maximum));
        return item.GetString()!;
    }
    private static string VaultId(C.Binding binding) =>
        new VaultScope(new(new(binding.AzureSubscriptionId), binding.ResourceGroup), binding.VaultName).ExportResourceId();
    private Entry Registered(Window window)
    {
        Require(window is not null);
        Require(windows.TryGetValue(window, out var entry));
        return entry;
    }
    private Entry Open(Window window)
    {
        var entry = Registered(window);
        Require(!disposed && !entry.Closing);
        return entry;
    }
    private static bool Text(string? value, int maximum) => value is { Length: > 0 } && value.Length <= maximum &&
        !string.IsNullOrWhiteSpace(value) && value.All(c => !char.IsControl(c));
    private static HttpResponseMessage Error(HttpStatusCode status) => new(status)
    {
        Content = new StringContent("{\"error\":\"notification-webhook-unavailable\"}", Encoding.UTF8, "application/json")
    };
    private static HttpResponseMessage Json<T>(T value) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(value, ManagementAdmission.Json), Encoding.UTF8, "application/json")
    };
    public ValueTask DisposeAsync()
    {
        Entry[] entries;
        TaskCompletionSource completion;
        lock (gate)
        {
            if (disposal is not null) return new(disposal.Task);
            disposed = true;
            completion = disposal = new(TaskCreationOptions.RunContinuationsAsynchronously);
            entries = windows.Values.ToArray();
        }
        _ = Drain(entries, completion);
        return new(completion.Task);
    }
    private async Task Drain(Entry[] entries, TaskCompletionSource completion)
    {
        bool failed = false;
        foreach (var entry in entries)
        {
            bool start;
            lock (gate) start = StartClose(entry, entry.LatestAdmission > entry.ArmedAt ? entry.LatestAdmission : entry.ArmedAt);
            if (start) _ = CompleteClose(entry);
            try { await entry.Closed!.Task.ConfigureAwait(false); }
            catch (Exception) { failed = true; }
            finally { entry.Stop.Dispose(); }
        }
        CryptographicOperations.ZeroMemory(path);
        if (failed) completion.TrySetException(Invalid());
        else completion.TrySetResult();
    }
    private static void Require([DoesNotReturnIf(false)] bool condition) { if (!condition) throw Invalid(); }
    private static InvalidOperationException Invalid() => new("notification-webhook-unavailable");
    public override string ToString() => "[NotificationWebhookDeliveryCollector]";
}
