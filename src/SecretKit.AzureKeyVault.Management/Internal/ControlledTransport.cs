using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management;

/// <summary>Last controlled SDK send boundary. Host transport internals remain host responsibility.</summary>
internal sealed class ControlledTransport(HttpPipelineTransport inner, Uri origin, string? path,
    RequestMethod method, string? apiVersion, int[] statuses, int maximumBytes,
    ManagementReceipt? receipt = null) : HttpPipelineTransport
{
    private readonly Lock _gate = new();
    private readonly HashSet<string> _statusUrls = new(StringComparer.Ordinal);
    private StatusCheckScope? _activeStatusCheck;
    private int _lastStatus;
    private int? _definitiveMutationStatus;
    private bool _hasContinuation;
    private string? _sdkRequest;

    internal void CaptureInitialRequest(HttpMessage message)
    {
        if (path is not null) return;
        Uri uri = message.Request.Uri.ToUri();
        if (!Trusted(uri) || message.Request.Method != method || !Revision(uri))
            throw new BoundaryException();
        lock (_gate)
        {
            if (_sdkRequest is not null) throw new BoundaryException();
            _sdkRequest = uri.AbsoluteUri;
        }
    }

    internal int LastStatus
    {
        get { lock (_gate) return _lastStatus; }
    }

    internal int? DefinitiveMutationStatus
    {
        get { lock (_gate) return _definitiveMutationStatus; }
    }

    internal bool HasContinuation
    {
        get { lock (_gate) return _hasContinuation; }
    }

    internal StatusCheckScope BeginStatusCheck()
    {
        lock (_gate)
        {
            if (_activeStatusCheck is not null)
                throw new InvalidOperationException("A status check is already active on this transport.");
            var scope = new StatusCheckScope(this);
            _activeStatusCheck = scope;
            return scope;
        }
    }

    internal sealed class StatusCheckScope : IDisposable
    {
        private readonly ControlledTransport _transport;
        private int _requests;
        private bool _disposed;
        private NativeProvisioningState _operationState = NativeProvisioningState.Unknown;

        internal StatusCheckScope(ControlledTransport transport) => _transport = transport;

        internal NativeProvisioningState OperationState
        {
            get { lock (_transport._gate) return _operationState; }
        }

        internal bool TryBeginRequest()
        {
            lock (_transport._gate)
            {
                return !_disposed && ++_requests <= 2;
            }
        }

        internal void RecordState(NativeProvisioningState state)
        {
            lock (_transport._gate)
            {
                if (!_disposed && ReferenceEquals(_transport._activeStatusCheck, this))
                    _operationState = state;
            }
        }

        public void Dispose()
        {
            lock (_transport._gate)
            {
                _disposed = true;
                _operationState = NativeProvisioningState.Unknown;
                if (ReferenceEquals(_transport._activeStatusCheck, this))
                    _transport._activeStatusCheck = null;
            }
        }
    }

    public override Request CreateRequest() => inner.CreateRequest();
    public override void Process(HttpMessage message) => throw new InvalidOperationException("Use asynchronous operations.");

    public override async ValueTask ProcessAsync(HttpMessage message)
    {
        var uri = message.Request.Uri.ToUri();
        bool sameTarget = path is null
            ? string.Equals(uri.AbsoluteUri, _sdkRequest, StringComparison.Ordinal)
            : uri.AbsolutePath.Equals(path, StringComparison.OrdinalIgnoreCase);
        StatusCheckScope? statusCheck;
        bool knownStatusUrl;
        lock (_gate)
        {
            statusCheck = _activeStatusCheck;
            knownStatusUrl = statusCheck is not null && _statusUrls.Contains(uri.AbsoluteUri);
        }
        bool checkingStatus = statusCheck is not null;
        bool status = checkingStatus && message.Request.Method == RequestMethod.Get &&
            ((sameTarget && Revision(uri)) || knownStatusUrl);
        if (!Trusted(uri) || (!status &&
                (!sameTarget || message.Request.Method != method || !Revision(uri))) ||
            (statusCheck is not null && (!status || !statusCheck.TryBeginRequest())))
        {
            throw new BoundaryException();
        }

        message.CancellationToken.ThrowIfCancellationRequested();
        if (message.Request.Content is { } content &&
            (!content.TryComputeLength(out var length) || length > maximumBytes))
        {
            throw new BoundaryException();
        }

        message.BufferResponse = false;
        if (!checkingStatus && receipt is not null && message.Request.Headers.Contains("Authorization"))
        {
            receipt.BeginDispatch();
        }

        await inner.ProcessAsync(message).ConfigureAwait(false);
        int responseStatus = message.Response.Status;
        lock (_gate)
        {
            _lastStatus = responseStatus;
            if (!checkingStatus && receipt?.Evidence == DispatchEvidence.PossiblyDispatched &&
                SecretKit.AzureKeyVault.AzureFailureClassification.IsDefinitiveMutationRejection(responseStatus))
            {
                _definitiveMutationStatus = responseStatus;
                receipt.Record(responseStatus == (int)System.Net.HttpStatusCode.Conflict ?
                    DispatchEvidence.Conflict : DispatchEvidence.Rejected);
            }
        }
        if (checkingStatus && responseStatus >= 400)
        {
            // Do not let the original ARM handle cache an observation failure as its
            // terminal operation exception. A later explicit check uses this same handle.
            var failure = Failure(new RequestFailedException(responseStatus, "Status observation failed."));
            message.Response.Dispose();
            throw new ObservationException(failure);
        }
        if (responseStatus < 400 && (checkingStatus
                ? responseStatus is not (200 or 201 or 202 or 204)
                : !statuses.Contains(responseStatus)))
        {
            message.Response.Dispose();
            throw new BoundaryException();
        }

        // Event Grid DELETE also issues the documented2025-02-15 operation URLs.
        // Retain exact issued membership; this is not a generic ARM polling escape.
        if (receipt is not null)
        {
            foreach (string header in new[] { "Azure-AsyncOperation", "Location", "Operation-Location" })
            {
                if (message.Response.Headers.TryGetValue(header, out var value))
                {
                    if (!Uri.TryCreate(uri, value, out var next) || !Trusted(next) || !Revision(next) ||
                        !(receipt.Scope is NotificationScope
                            ? next.AbsolutePath.Equals(path, StringComparison.OrdinalIgnoreCase) ||
                                receipt.Operation == ManagementMutation.DeleteNotification &&
                                header != "Operation-Location" && IsNotificationOperationTarget(next, value)
                            : IsOperationPath(next.AbsolutePath)))
                    {
                        message.Response.Dispose();
                        throw new BoundaryException();
                    }

                    bool originallyIssued;
                    lock (_gate)
                    {
                        originallyIssued = _statusUrls.Contains(next.AbsoluteUri);
                        if (!checkingStatus) _statusUrls.Add(next.AbsoluteUri);
                    }
                    if (checkingStatus && !originallyIssued)
                    {
                        message.Response.Dispose();
                        throw new BoundaryException();
                    }
                }
            }
        }

        if (message.Response.Headers.TryGetValue("Content-Length", out var declared) &&
            long.TryParse(declared, out var bytes) && bytes > maximumBytes)
        {
            message.Response.Dispose();
            throw new BoundaryException();
        }

        if (message.Response.ContentStream is { } stream)
        {
            // ARM's generated model readers require Response.Content (fully buffered).
            // Buffer here, after the raw budget has been enforced, not in the SDK transport.
            var buffer = new MemoryStream();
            try
            {
                using var bounded = new BudgetStream(stream, maximumBytes);
                var scratch = ArrayPool<byte>.Shared.Rent(Math.Min(8192, maximumBytes + 1));
                try
                {
                    int count;
                    while ((count = await bounded.ReadAsync(scratch.AsMemory(), message.CancellationToken)
                        .ConfigureAwait(false)) != 0)
                        buffer.Write(scratch, 0, count);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(scratch);
                    ArrayPool<byte>.Shared.Return(scratch);
                }
                buffer.Position = 0;
                if (apiVersion is not null && responseStatus < 400 && buffer.Length != 0)
                {
                    // Parse the buffered body in place; the document is disposed before the stream is published.
                    using var document = JsonDocument.Parse(buffer.GetBuffer().AsMemory(0, (int)buffer.Length),
                        new JsonDocumentOptions { AllowDuplicateProperties = false, MaxDepth = 32 });
                    var root = document.RootElement;
                    if (statusCheck is not null && root.TryGetProperty("status", out var state) &&
                        state.ValueKind == JsonValueKind.String)
                    {
                        statusCheck.RecordState(state.GetString()?.ToLowerInvariant() switch
                        {
                            "succeeded" => NativeProvisioningState.Succeeded,
                            "failed" => NativeProvisioningState.Failed,
                            "canceled" or "cancelled" => NativeProvisioningState.Canceled,
                            "inprogress" or "running" or "accepted" => NativeProvisioningState.Pending,
                            _ => NativeProvisioningState.Unknown
                        });
                    }

                    bool continuation = root.TryGetProperty("nextLink", out var nextLink) &&
                        nextLink.ValueKind != JsonValueKind.Null;
                    lock (_gate) { _hasContinuation = continuation; }
                    if (continuation && (!Uri.TryCreate(nextLink.GetString(), UriKind.Absolute, out var next) ||
                        !Trusted(next) || !Revision(next) ||
                        !next.AbsolutePath.Equals(path, StringComparison.OrdinalIgnoreCase)))
                    {
                        throw new BoundaryException();
                    }

                    bool resourceMutation = receipt?.Operation is ManagementMutation.CreateOrUpdateVault or
                        ManagementMutation.RecoverVault or ManagementMutation.UpdateVault or
                        ManagementMutation.UpdatePrivateConnection or ManagementMutation.AddAccessPolicy or
                        ManagementMutation.ReplaceAccessPolicy or ManagementMutation.RemoveAccessPolicy or
                        ManagementMutation.CreateOrUpdateNotification or ManagementMutation.UpdateNotification;
                    if (!checkingStatus && resourceMutation &&
                        (!root.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String ||
                            !string.Equals(id.GetString(), receipt!.Scope.ResourceId, StringComparison.OrdinalIgnoreCase)))
                    {
                        throw new BoundaryException();
                    }
                    if (receipt?.Scope is NotificationScope notification && root.TryGetProperty("id", out _) &&
                        (!root.TryGetProperty("id", out var notificationId) ||
                            notificationId.ValueKind != JsonValueKind.String ||
                            !string.Equals(notificationId.GetString(), notification.ResourceId, StringComparison.OrdinalIgnoreCase) ||
                            !root.TryGetProperty("name", out var notificationName) ||
                            notificationName.ValueKind != JsonValueKind.String ||
                            !string.Equals(notificationName.GetString(), notification.SubscriptionName, StringComparison.OrdinalIgnoreCase) ||
                            !root.TryGetProperty("properties", out var properties) ||
                            !properties.TryGetProperty("topic", out var topic) || topic.ValueKind != JsonValueKind.String ||
                            !string.Equals(topic.GetString(), notification.Vault.ResourceId, StringComparison.OrdinalIgnoreCase)))
                    {
                        throw new BoundaryException();
                    }
                    if (!checkingStatus && receipt?.Operation is
                            ManagementMutation.CreateOrUpdateNotification or ManagementMutation.UpdateNotification &&
                        (!root.TryGetProperty("properties", out var notificationProperties) ||
                            !notificationProperties.TryGetProperty("provisioningState", out var notificationState) ||
                            notificationState.ValueKind != JsonValueKind.String ||
                            notificationState.GetString()?.ToLowerInvariant() is not
                                ("succeeded" or "creating" or "updating" or "accepted" or "running" or "inprogress")))
                    {
                        throw new BoundaryException();
                    }
                }

                message.Response.ContentStream = buffer;
            }
            catch
            {
                buffer.Dispose();
                message.Response.Dispose();
                throw;
            }
        }
    }

    private bool Trusted(Uri uri) => uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttps &&
        uri.Scheme == origin.Scheme && uri.Host.Equals(origin.Host, StringComparison.OrdinalIgnoreCase) &&
        uri.Port == origin.Port &&
        uri.UserInfo.Length == 0 && uri.Fragment.Length == 0;

    private bool Revision(Uri uri)
    {
        if (apiVersion is null)
        {
            return uri.Query.Length == 0;
        }

        if (uri.Query.Length == 0) return false;
        string? revision = null;
        foreach (string parameter in uri.Query[1..].Split('&'))
        {
            int separator = parameter.IndexOf('=');
            string key = separator < 0 ? parameter : parameter[..separator];
            if (!Uri.UnescapeDataString(key).Equals("api-version", StringComparison.OrdinalIgnoreCase)) continue;
            if (revision is not null || separator < 0 || separator == parameter.Length - 1) return false;
            revision = parameter[(separator + 1)..];
        }
        return revision == apiVersion;
    }

    private bool IsOperationPath(string candidate)
    {
        if (path is null) return false;
        string[] origin = path.Split('/');
        string[] parts = candidate.Split('/');
        return origin.Length > 2 && parts.Length == 9 &&
            parts[1].Equals("subscriptions", StringComparison.OrdinalIgnoreCase) &&
            parts[2].Equals(origin[2], StringComparison.OrdinalIgnoreCase) &&
            parts[3].Equals("providers", StringComparison.OrdinalIgnoreCase) &&
            parts[4].Equals("Microsoft.KeyVault", StringComparison.OrdinalIgnoreCase) &&
            parts[5].Equals("locations", StringComparison.OrdinalIgnoreCase) &&
            parts[6].Length is >= 1 and <= 50 && parts[6].All(char.IsAsciiLetterOrDigit) &&
            (parts[7].Equals("operations", StringComparison.OrdinalIgnoreCase) ||
                parts[7].Equals("operationResults", StringComparison.OrdinalIgnoreCase)) &&
            Guid.TryParse(parts[8], out _);
    }

    private bool IsNotificationOperationTarget(Uri candidate, string issued)
    {
        if (path is null || candidate.AbsoluteUri != issued || issued.Contains('%') ||
            candidate.Query != $"?api-version={apiVersion}")
            return false;
        string[] origin = path.Split('/');
        string[] parts = candidate.AbsolutePath.Split('/');
        return parts.Length == 13 &&
            parts.Take(5).SequenceEqual(origin.Take(5), StringComparer.OrdinalIgnoreCase) &&
            parts[5].Equals("providers", StringComparison.OrdinalIgnoreCase) &&
            parts[6].Equals("Microsoft.EventGrid", StringComparison.OrdinalIgnoreCase) &&
            parts[7] == "locations" &&
            parts[8].Length is >= 1 and <= 50 && parts[8].All(char.IsAsciiLetterOrDigit) &&
            (parts[9] == "operationResults" && Guid.TryParseExact(parts[10], "D", out _) &&
                parts[11].Length is >= 1 and <= 50 && parts[11].All(char.IsAsciiLetterOrDigit) && parts[12] == "default" ||
             parts[9] == "operationStatus" && parts[10] == "default" &&
                parts[11] == "operationId" && Guid.TryParseExact(parts[12], "D", out _));
    }

    internal sealed class BoundaryException() : IOException("Management boundary validation failed.");

    private sealed class BudgetStream(Stream inner, int maximum) : Stream
    {
        private int _read;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            int count = inner.Read(buffer[..Math.Min(buffer.Length, maximum - _read + 1)]);
            _read += count;
            if (_read > maximum)
            {
                throw new BoundaryException();
            }

            return count;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int count = await inner.ReadAsync(buffer[..Math.Min(buffer.Length, maximum - _read + 1)],
                cancellationToken).ConfigureAwait(false);
            _read += count;
            if (_read > maximum)
            {
                throw new BoundaryException();
            }

            return count;
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    internal static SecretStatus Failure(Exception exception) => exception switch
    {
        ObservationException observation => observation.Status,
        RequestFailedException { InnerException: BoundaryException } => SecretStatus.Invalid,
        BoundaryException or ArgumentException or FormatException => SecretStatus.Invalid,
        _ => SecretKit.AzureKeyVault.AzureFailureClassification.Status(exception)
    };

    internal sealed class ObservationException(SecretStatus status) : IOException("Status observation failed.")
    {
        internal SecretStatus Status { get; } = status;
    }
}
