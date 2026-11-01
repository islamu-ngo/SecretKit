using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.NotificationRuntimeTriggerCapture;
using W = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.NotificationWebhookDeliveryCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Nonpackable receiver only. Keep outside Admission source links: an installed
// package consumer does not need ASP.NET just to use the capture/collector.
// One host owns one collector window and borrows the original capture, journal,
// authentication policy and server certificate. None is a native identity proof.
internal sealed class NotificationWebhookHost : IAsyncDisposable
{
    internal sealed record Configuration(
        [property: JsonIgnore] IPAddress Address,
        int Port,
        [property: JsonIgnore] string CallbackPath,
        [property: JsonIgnore] Uri? PublicAuthority = null)
    {
        public override string ToString() => "[NotificationWebhookHostConfiguration]";
    }

    private readonly object gate = new();
    private readonly int maximumRequests, maximumBodyBytes;
    private readonly TaskCompletionSource controlsDrained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource requestsDrained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private WebApplication? application;
    private W? collector;
    private C? capture;
    private W.Window? window;
    private W.Binding? binding;
    private Uri? endpoint, listenerEndpoint;
    private bool armClaimed, admissionClosed, stopping;
    private int controls, requests;
    private TaskCompletionSource? stopped;

    private NotificationWebhookHost(C capture, W.Limits limits)
    {
        this.capture = capture;
        maximumRequests = limits.MaximumRequests;
        maximumBodyBytes = limits.MaximumBodyBytes;
    }

    // Start cancellation applies to startup, not to the returned host's lifetime.
    // Port 0 is bound by Kestrel itself; no reserve/release/rebind race exists.
    internal static async Task<NotificationWebhookHost> StartAsync(Configuration configuration,
        X509Certificate2 certificate, RoleFixtureJournal journal, string owner, C capture, W.Limits limits,
        TimeProvider? time = null, NotificationDeliveryAuthentication? authentication = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Require(configuration is not null && configuration.Address is not null &&
            configuration.Port is >= 0 and <= 65535 &&
            configuration.CallbackPath is { Length: >= 32 and <= 2048 } path &&
            path.StartsWith('/') && !path.StartsWith("//", StringComparison.Ordinal) &&
            Uri.TryCreate("https://localhost" + path, UriKind.Absolute, out var canonical) &&
            canonical.AbsolutePath == path && canonical.Query.Length == 0 && canonical.Fragment.Length == 0 &&
            canonical.Authority == "localhost" &&
            certificate is not null && certificate.HasPrivateKey && journal is not null && capture is not null &&
            limits is not null && limits.MaximumBodyBytes is >= 1024 and <= 1024 * 1024 &&
            limits.MaximumRequests is > 0 and <= 4096 && limits.MaximumHeaders is >= 2 and <= 128 &&
            limits.MaximumHeaderBytes is >= 256 and <= 65536 &&
            limits.Timeout > TimeSpan.Zero && limits.Timeout <= TimeSpan.FromMinutes(2));
        var authority = configuration.PublicAuthority;
        Require(authority is null || authority is
        {
            IsAbsoluteUri: true, Scheme: "https", UserInfo.Length: 0, Query.Length: 0,
            Fragment.Length: 0, AbsolutePath: "/", Port: > 0
        });
        Require(authority is not null ||
            !configuration.Address.Equals(IPAddress.Any) && !configuration.Address.Equals(IPAddress.IPv6Any));
        var address = IPAddress.Parse(configuration.Address.ToString());
        var host = new NotificationWebhookHost(capture, limits);
        try
        {
            // No environment-selected endpoints, forwarded headers, request
            // logging, HTTPS redirects, or arbitrary host service callbacks.
            var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions
            {
                Args = [],
                ApplicationName = typeof(NotificationWebhookHost).Assembly.GetName().Name,
                EnvironmentName = Environments.Production
            });
            builder.Logging.ClearProviders();
            builder.Services.Configure<HostOptions>(options => options.ShutdownTimeout = limits.Timeout);
            builder.WebHost.UseKestrel(options =>
            {
                options.AddServerHeader = false;
                options.Limits.MaxConcurrentConnections = limits.MaximumRequests;
                options.Limits.MaxRequestBodySize = limits.MaximumBodyBytes + 1L;
                options.Limits.MaxRequestHeaderCount = limits.MaximumHeaders;
                options.Limits.MaxRequestHeadersTotalSize = limits.MaximumHeaderBytes;
                options.Limits.MaxRequestLineSize = 4096;
                options.Limits.RequestHeadersTimeout = limits.Timeout;
                options.Limits.KeepAliveTimeout = limits.Timeout;
                options.Listen(address, configuration.Port, listener =>
                {
                    listener.Protocols = HttpProtocols.Http1;
                    listener.UseHttps(certificate);
                });
            });
            host.application = builder.Build();
            host.application.Run(host.ReceiveAsync);
            await host.application.StartAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            var addresses = host.application.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()?.Addresses;
            Require(addresses is { Count: 1 });
            var actual = new Uri(addresses.Single(), UriKind.Absolute);
            Require(actual.Scheme == "https" && actual.Port > 0);
            var listening = new Uri(actual, configuration.CallbackPath);
            var callback = new Uri(authority ?? actual, configuration.CallbackPath);
            // Only now is the exact callback origin known. Requests reaching the
            // listener before Arm are refused without opening the request body.
            var receiver = new W(journal, owner, callback, limits, time, authentication);
            lock (host.gate)
            {
                host.listenerEndpoint = listening;
                host.endpoint = callback;
                host.collector = receiver;
            }
            cancellationToken.ThrowIfCancellationRequested();
            return host;
        }
        catch (Exception)
        {
            try { await host.StopAsync().ConfigureAwait(false); }
            catch (Exception) { throw Invalid(); }
            cancellationToken.ThrowIfCancellationRequested();
            throw Invalid();
        }
    }

    [JsonIgnore]
    internal Uri Endpoint
    {
        get { lock (gate) { Require(!stopping && endpoint is not null); return endpoint; } }
    }

    [JsonIgnore]
    internal Uri ListenerEndpoint
    {
        get { lock (gate) { Require(!stopping && listenerEndpoint is not null); return listenerEndpoint; } }
    }

    internal void Arm(W.Binding input, string[] headerNames)
    {
        W receiver;
        lock (gate)
        {
            Require(!stopping && !armClaimed && collector is not null);
            armClaimed = true;
            controls++;
            receiver = collector;
        }
        try
        {
            var armed = receiver.Arm(input, headerNames);
            lock (gate)
            {
                Require(!stopping);
                window = armed;
                binding = input;
            }
        }
        finally { LeaveControl(); }
    }

    internal void AttachCapture(C.Window original)
    {
        var owned = EnterControl();
        try { owned.Collector.AttachCapture(owned.Window, owned.Capture, original); }
        finally { LeaveControl(); }
    }

    internal Task WaitForLinkedDeliveryAsync(CancellationToken cancellationToken)
    {
        var owned = EnterControl();
        try { return owned.Collector.WaitForLinkedDeliveryAsync(owned.Window, cancellationToken); }
        finally { LeaveControl(); }
    }

    internal async Task<W.Measurement> CloseAsync(CancellationToken cancellationToken)
    {
        var owned = EnterControl();
        try
        {
            lock (gate) admissionClosed = true;
            return await owned.Collector.CloseAsync(owned.Window, owned.Binding, cancellationToken).ConfigureAwait(false);
        }
        finally { LeaveControl(); }
    }

    private (W Collector, W.Window Window, W.Binding Binding, C Capture) EnterControl()
    {
        lock (gate)
        {
            Require(!stopping && collector is not null && window is not null && binding is not null && capture is not null);
            controls++;
            return (collector, window, binding, capture);
        }
    }

    private void LeaveControl()
    {
        lock (gate) if (--controls == 0 && stopping) controlsDrained.TrySetResult();
    }

    private async Task ReceiveAsync(HttpContext context)
    {
        W? receiver;
        W.Window? selected;
        int rejection;
        lock (gate)
        {
            receiver = collector;
            selected = window;
            rejection = stopping || admissionClosed ? 410 :
                receiver is null || selected is null ? 503 : requests >= maximumRequests ? 429 : 0;
            if (rejection == 0) requests++;
        }
        // HTTP/1 only. Do not ask Kestrel to drain an unauthenticated request's
        // unused body in order to reuse its connection.
        context.Response.Headers.Connection = "close";
        try
        {
            if (rejection != 0)
            {
                await Error(context, rejection).ConfigureAwait(false);
                return;
            }
            var raw = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
            if (!context.Request.IsHttps || raw is not { Length: > 0 and <= 4096 } ||
                !raw.StartsWith('/') || raw.StartsWith("//", StringComparison.Ordinal) || raw.Contains('#') ||
                !Uri.TryCreate("https://" + context.Request.Host.ToUriComponent() + raw, UriKind.Absolute, out var target) ||
                raw != target.PathAndQuery)
            {
                await Error(context, 401).ConfigureAwait(false);
                return;
            }
            // Host, path and query remain the actual incoming values. The
            // collector compares them to the explicitly selected callback URI.
            // IsHttps is Kestrel TLS, never a forwarded assertion.
            using var request = new HttpRequestMessage(new HttpMethod(context.Request.Method), target)
            {
                Content = new StreamContent(new BorrowedBody(context.Request.Body, maximumBodyBytes + 1))
            };
            foreach (var header in context.Request.Headers)
            {
                string[] values = header.Value.Select(value => value!).ToArray();
                if (!request.Headers.TryAddWithoutValidation(header.Key, values) &&
                    !request.Content.Headers.TryAddWithoutValidation(header.Key, values))
                {
                    await Error(context, 400).ConfigureAwait(false);
                    return;
                }
            }
            using var response = await receiver!.ReceiveAsync(selected!, request, context.RequestAborted).ConfigureAwait(false);
            context.Response.StatusCode = (int)response.StatusCode;
            if (response.Content is { } content)
            {
                if (content.Headers.ContentType is { } type) context.Response.ContentType = type.ToString();
                if (content.Headers.ContentLength is { } length) context.Response.ContentLength = length;
                await content.CopyToAsync(context.Response.Body, context.RequestAborted).ConfigureAwait(false);
            }
        }
        catch (Exception) when (context.RequestAborted.IsCancellationRequested) { context.Abort(); }
        catch (Exception)
        {
            if (context.Response.HasStarted) context.Abort();
            else
            {
                context.Response.ContentLength = null;
                await Error(context, 500).ConfigureAwait(false);
            }
        }
        finally
        {
            if (rejection == 0)
                lock (gate) if (--requests == 0 && stopping) requestsDrained.TrySetResult();
        }
    }

    private static Task Error(HttpContext context, int status)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json";
        return context.Response.WriteAsync("{\"error\":\"notification-webhook-unavailable\"}", context.RequestAborted);
    }

    // Cancellation abandons only this caller's wait. The single shared teardown
    // still owns every request/server task and is joined by DisposeAsync.
    internal Task StopAsync(CancellationToken cancellationToken = default)
    {
        TaskCompletionSource completion;
        bool start;
        lock (gate)
        {
            start = stopped is null;
            completion = stopped ??= new(TaskCreationOptions.RunContinuationsAsynchronously);
            stopping = admissionClosed = true;
            if (controls == 0) controlsDrained.TrySetResult();
            if (requests == 0) requestsDrained.TrySetResult();
        }
        if (start) _ = CompleteStop(completion);
        cancellationToken.ThrowIfCancellationRequested();
        return completion.Task.WaitAsync(cancellationToken);
    }

    private async Task CompleteStop(TaskCompletionSource completion)
    {
        bool failed = false;
        try
        {
            // Arm/attachment may call the supplied time provider or original
            // capture. Let those actual invocations exit before disposal.
            await controlsDrained.Task.ConfigureAwait(false);
            try
            {
                if (collector is { } receiver) await receiver.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception) { failed = true; }
            // Collector cancellation releases pending body reads first. Kestrel
            // then drains responses, aborting connections at its shutdown bound.
            // This is cooperative I/O teardown, not a time-kill of host callbacks.
            try
            {
                if (application is { } server) await server.StopAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception) { failed = true; }
            finally
            {
                try
                {
                    if (application is { } server) await server.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception) { failed = true; }
            }
            await requestsDrained.Task.ConfigureAwait(false);
        }
        catch (Exception) { failed = true; }
        finally
        {
            lock (gate)
            {
                // The collector owns its candidate storage and clears its path
                // bytes on disposal. Release all host references, including the
                // window/binding; already-exported measurements remain caller-owned.
                collector = null;
                window = null;
                binding = null;
                capture = null;
                endpoint = listenerEndpoint = null;
                application = null;
            }
            if (failed) completion.TrySetException(Invalid());
            else completion.TrySetResult();
        }
    }

    public ValueTask DisposeAsync() => new(StopAsync());

    // StreamContent owns this adapter, not Kestrel's request stream. No buffering
    // occurs here; the collector owns and zeroes its bounded body buffer.
    private sealed class BorrowedBody(Stream inner, int remaining) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Require(remaining > 0);
            int read = await inner.ReadAsync(buffer[..Math.Min(buffer.Length, remaining)], cancellationToken).ConfigureAwait(false);
            remaining -= read;
            return read;
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static void Require([DoesNotReturnIf(false)] bool condition) { if (!condition) throw Invalid(); }
    private static InvalidOperationException Invalid() => new("notification-webhook-unavailable");
    public override string ToString() => "[NotificationWebhookHost]";
}
