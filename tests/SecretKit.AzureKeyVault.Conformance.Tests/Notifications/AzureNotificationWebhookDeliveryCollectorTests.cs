using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.Core;
using Webhook = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.NotificationWebhookDeliveryCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    private static readonly Uri WebhookEndpoint = new("https://observer.example/notification/0123456789abcdef0123456789abcdef");
    private static Webhook Receiver(NotificationCaptureScope f) => new(f.Fixture.Journal, Owner,
        WebhookEndpoint, new(4096, 16, 16, 128, 8, 16, 4096, TimeSpan.FromSeconds(10)), f.Clock);
    private static Webhook.Binding WebhookBinding(NotificationCaptureScope f) => new(f.Binding, "owned-notification", "selected-correlation");
    private static HttpRequestMessage Packet(NotificationCaptureScope f, string fault = "")
    {
        string vault = $"/subscriptions/{Subscription:D}/resourceGroups/fixture-group/providers/Microsoft.KeyVault/vaults/{f.Binding.VaultName}";
        string version = fault == "version" ? Version : NotificationCaptureScope.FreshVersion;
        var body = new JsonArray(new JsonObject
        {
            ["id"] = "native-event-id",
            ["topic"] = fault == "topic" ? vault + "-foreign" : vault,
            ["subject"] = "canary",
            ["eventType"] = "Microsoft.KeyVault.SecretNewVersionCreated",
            ["eventTime"] = f.Clock.GetUtcNow().ToString("O"),
            ["dataVersion"] = "1",
            ["metadataVersion"] = "1",
            ["data"] = new JsonObject
            {
                ["Id"] = $"https://{f.Binding.VaultName}.vault.azure.net/secrets/canary/{version}",
                ["VaultName"] = f.Binding.VaultName,
                ["ObjectType"] = "Secret",
                ["ObjectName"] = "canary",
                ["Version"] = version
            }
        });
        var request = new HttpRequestMessage(HttpMethod.Post,
            fault == "endpoint" ? new Uri(WebhookEndpoint.AbsoluteUri + "-foreign") : WebhookEndpoint)
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
        };
        request.Headers.Add("aeg-event-type", "Notification");
        request.Headers.Add("aeg-subscription-name", fault == "subscription" ? "foreign" : "owned-notification");
        request.Headers.Add("x-correlation", "selected-correlation");
        return request;
    }
    private static async Task<NotificationRuntimeTriggerCapture.Window> Trigger(NotificationCaptureScope f)
    {
        using var material = SecretMaterial.FromText(NotificationCaptureScope.Value);
        var capture = f.Source.Arm(f.Binding, material);
        var target = f.Target();
        var result = await f.Source.RunSetAsync(f.Binding.Selector, f.Client, new(target, material), new(target), default);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        return capture;
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task WebhookLinksActualNativeVersionBeforeOrAfterCaptureAttachment(bool early)
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        await using var receiver = Receiver(f);
        var binding = WebhookBinding(f);
        var window = receiver.Arm(binding, ["x-correlation"]);
        var arrived = receiver.WaitForLinkedDeliveryAsync(window, default);
        var capture = await Trigger(f);
        if (!early) receiver.AttachCapture(window, f.Source, capture);
        using var request = Packet(f);
        using var response = await receiver.ReceiveAsync(window, request, default);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        if (early)
        {
            await Assert.That(arrived.IsCompleted).IsFalse();
            receiver.AttachCapture(window, f.Source, capture);
        }
        await arrived.WaitAsync(TimeSpan.FromSeconds(10));
        using var duplicate = Packet(f);
        using var repeated = await receiver.ReceiveAsync(window, duplicate, default);
        var measured = await receiver.CloseAsync(window, binding, default);
        await Assert.That(measured.Available).IsTrue();
        await Assert.That(measured.Deliveries.Count).IsEqualTo(1);
        await Assert.That(measured.NativeTriggerRequestIds.Single()).IsEqualTo("native-original-write");
        await Assert.That(measured.NativeWindowClosureEstablished || measured.NativeFilterExclusionEstablished ||
            measured.ProviderIdentityEstablished).IsFalse();
        var projection = measured.Deliveries[0].Project();
        await Assert.That(projection.SubscriptionName).IsEqualTo("owned-notification");
        await Assert.That(projection.Headers.Single().Value).IsEqualTo("selected-correlation");
        using var closed = Packet(f);
        using var rejected = await receiver.ReceiveAsync(window, closed, default);
        await Assert.That(rejected.StatusCode).IsEqualTo(HttpStatusCode.Gone);
    }

    [Test]
    [Arguments("endpoint", HttpStatusCode.Unauthorized)]
    [Arguments("subscription", HttpStatusCode.BadRequest)]
    [Arguments("topic", HttpStatusCode.BadRequest)]
    [Arguments("version", HttpStatusCode.OK)]
    public async Task WebhookNeverTurnsForeignOrOldEventsIntoPositiveEvidence(string fault, HttpStatusCode status)
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        await using var receiver = Receiver(f);
        var binding = WebhookBinding(f);
        var window = receiver.Arm(binding, []);
        receiver.AttachCapture(window, f.Source, await Trigger(f));
        using var request = Packet(f, fault);
        using var response = await receiver.ReceiveAsync(window, request, default);
        await Assert.That(response.StatusCode).IsEqualTo(status);
        var measured = await receiver.CloseAsync(window, binding, default);
        await Assert.That(measured.Available).IsFalse();
        await Assert.That(measured.Deliveries.Count).IsEqualTo(0);
        await Assert.That(measured.NativeFilterExclusionEstablished || measured.NativeWindowClosureEstablished).IsFalse();
        await Assert.That(measured.UnlinkedEvents).IsEqualTo(fault == "version" ? 1 : 0);
    }

    [Test]
    public async Task WebhookRequiresOriginalDeclaredNotificationAndPreparedVault()
    {
        await using var f = await NotificationCaptureScope.Create();
        await using var receiver = Receiver(f);
        await Assert.That(() => receiver.Arm(WebhookBinding(f), [])).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task WebhookDisposalDrainsActualBodyReadWithoutOwningCallerStream()
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        await using var receiver = Receiver(f);
        var window = receiver.Arm(WebhookBinding(f), []);
        using var request = Packet(f);
        using var stream = new WebhookBlockedStream();
        request.Content!.Dispose();
        request.Content = new StreamContent(stream);
        request.Content.Headers.ContentType = new("application/json");
        var receiving = receiver.ReceiveAsync(window, request, default);
        Task? disposing = null;
        try
        {
            await stream.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            disposing = receiver.DisposeAsync().AsTask();
            await Assert.That(receiving.IsCompleted || disposing.IsCompleted).IsFalse();
            await Assert.That(stream.Disposed).IsFalse();
        }
        finally { stream.Resume.TrySetResult(); }
        using var response = await receiving.WaitAsync(TimeSpan.FromSeconds(10));
        await disposing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(stream.Disposed).IsFalse();
    }

    private sealed class WebhookBlockedStream : Stream
    {
        internal readonly TaskCompletionSource Entered = Signal(), Resume = Signal();
        internal bool Disposed;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Entered.TrySetResult();
            await Resume.Task; // Actual I/O exit, deliberately not cancellation cooperation.
            return 0;
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }

    [Test]
    public async Task WebhookTimerFailureCannotStrandAdmittedBorrower()
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        await using var receiver = new Webhook(f.Fixture.Journal, Owner, WebhookEndpoint,
            new(4096, 16, 16, 128, 8, 16, 4096, TimeSpan.FromSeconds(10)), new WebhookFailingTimer());
        var binding = WebhookBinding(f);
        var window = receiver.Arm(binding, []);
        using var request = Packet(f);
        using var response = await receiver.ReceiveAsync(window, request, default);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        var measured = await receiver.CloseAsync(window, binding, default).WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(measured.TaskDrained).IsTrue();
        await Assert.That(measured.Available).IsFalse();
    }

    private sealed class WebhookFailingTimer : TimeProvider
    {
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            throw new InvalidOperationException("controlled-timer-failure");
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ReviewWebhookContentHeadersShareTheIngressBudget(bool many)
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        await using var receiver = Receiver(f);
        var binding = WebhookBinding(f);
        var window = receiver.Arm(binding, []);
        receiver.AttachCapture(window, f.Source, await Trigger(f));
        using var request = Packet(f);
        if (many)
            for (int i = 0; i < 17; i++) request.Content!.Headers.Add("X-Content-" + i, "value");
        else request.Content!.Headers.Add("X-Content-Large", new string('x', 4097));
        using var response = await receiver.ReceiveAsync(window, request, default);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        var measured = await receiver.CloseAsync(window, binding, default);
        await Assert.That(measured.Available).IsFalse();
    }
}
