using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management;

/// <summary>Last controlled SDK send boundary. Host transport internals remain host responsibility.</summary>
internal sealed class ControlledTransport(HttpPipelineTransport inner, string host, string path,
    RequestMethod method, string? apiVersion, int[] statuses, int maximumBytes,
    ManagementReceipt? receipt = null) : HttpPipelineTransport
{
    private readonly HashSet<string> _statusUrls = new(StringComparer.OrdinalIgnoreCase);
    internal bool CheckingStatus;
    internal int StatusRequests;
    internal int LastStatus;
    internal bool HasContinuation;
    internal NativeProvisioningState LastOperationState;

    public override Request CreateRequest() => inner.CreateRequest();
    public override void Process(HttpMessage message) => throw new InvalidOperationException("Use asynchronous operations.");

    public override async ValueTask ProcessAsync(HttpMessage message)
    {
        var uri = message.Request.Uri.ToUri();
        bool sameTarget = uri.AbsolutePath.Equals(path, StringComparison.OrdinalIgnoreCase);
        bool status = CheckingStatus && message.Request.Method == RequestMethod.Get &&
            ((sameTarget && Revision(uri)) || _statusUrls.Contains(uri.AbsoluteUri));
        if (!Trusted(uri) || (!status &&
                (!sameTarget || message.Request.Method != method || !Revision(uri))) ||
            (CheckingStatus && (!status || ++StatusRequests > 2)))
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
        if (!CheckingStatus && receipt is not null && message.Request.Headers.Contains("Authorization"))
        {
            receipt.Receipt.BeginDispatch(receipt.Target);
        }

        await inner.ProcessAsync(message).ConfigureAwait(false);
        LastStatus = message.Response.Status;
        if (LastStatus < 400 && (CheckingStatus
                ? LastStatus is not (200 or 201 or 202 or 204)
                : !statuses.Contains(LastStatus)))
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

                    _statusUrls.Add(next.AbsoluteUri);
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
                await bounded.CopyToAsync(buffer, message.CancellationToken).ConfigureAwait(false);
                buffer.Position = 0;
                if (apiVersion is not null && LastStatus < 400 && buffer.Length != 0)
                {
                    using var document = JsonDocument.Parse(buffer.ToArray());
                    var root = document.RootElement;
                    if (CheckingStatus && root.TryGetProperty("status", out var state) &&
                        state.ValueKind == JsonValueKind.String)
                    {
                        LastOperationState = state.GetString()?.ToLowerInvariant() switch
                        {
                            "succeeded" => NativeProvisioningState.Succeeded,
                            "failed" => NativeProvisioningState.Failed,
                            "canceled" or "cancelled" => NativeProvisioningState.Canceled,
                            "inprogress" or "running" or "accepted" => NativeProvisioningState.Pending,
                            _ => NativeProvisioningState.Unknown
                        };
                    }

                    HasContinuation = root.TryGetProperty("nextLink", out var nextLink) &&
                        nextLink.ValueKind != JsonValueKind.Null;
                    if (HasContinuation && (!Uri.TryCreate(nextLink.GetString(), UriKind.Absolute, out var next) ||
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
                    if (!CheckingStatus && resourceMutation &&
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
                    if (!CheckingStatus && receipt?.Operation is
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

    private bool Trusted(Uri uri) => uri.IsAbsoluteUri && uri.Scheme == "https" &&
        uri.Host.Equals(host, StringComparison.OrdinalIgnoreCase) && uri.IsDefaultPort &&
        uri.UserInfo.Length == 0 && uri.Fragment.Length == 0;

    private bool Revision(Uri uri)
    {
        if (apiVersion is null)
        {
            return uri.Query.Length == 0;
        }

        string[] revisions = uri.Query.TrimStart('?').Split('&')
            .Where(v => v.StartsWith("api-version=", StringComparison.OrdinalIgnoreCase)).ToArray();
        return revisions.Length == 1 && revisions[0] == $"api-version={apiVersion}";
    }

    private bool IsOperationPath(string candidate)
    {
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
        if (candidate.AbsoluteUri != issued || issued.Contains('%') ||
            candidate.Query != "?api-version=2025-02-15")
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
                parts[11] == "Spring" && parts[12] == "default" ||
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
        RequestFailedException { InnerException: BoundaryException } => SecretStatus.Invalid,
        RequestFailedException { Status: 0 } => SecretStatus.Unavailable,
        BoundaryException or ArgumentException => SecretStatus.Invalid,
        RequestFailedException { Status: 401 or 403 } => SecretStatus.Denied,
        RequestFailedException { Status: 404 } => SecretStatus.Absent,
        RequestFailedException { Status: 409 } => SecretStatus.Conflict,
        RequestFailedException { Status: 429 } => SecretStatus.Throttled,
        RequestFailedException { Status: 400 } => SecretStatus.Invalid,
        RequestFailedException { Status: >= 500 } or HttpRequestException => SecretStatus.Unavailable,
        _ => SecretStatus.Unknown
    };
}
