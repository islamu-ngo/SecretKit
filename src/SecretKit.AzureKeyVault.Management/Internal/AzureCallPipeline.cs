using Azure.Core;
using Azure.Core.Pipeline;

namespace SecretKit.AzureKeyVault.Management;

// The SDK pipeline is shared. A ControlledTransport, including its set of issued status
// URLs, belongs to exactly one logical call and any original operation handle it returns.
internal sealed class AzureCallPipeline(HttpPipelineTransport inner) : HttpPipelineTransport
{
    private static readonly AsyncLocal<ControlledTransport?> Ambient = new();

    internal static IDisposable Bind(ControlledTransport route)
    {
        if (Ambient.Value is not null) throw new InvalidOperationException("Nested Azure dispatch.");
        Ambient.Value = route;
        return new Binding();
    }

    private sealed class Binding : IDisposable
    {
        public void Dispose() => Ambient.Value = null;
    }

    internal sealed class CapturePolicy : HttpPipelineSynchronousPolicy
    {
        public override void OnSendingRequest(HttpMessage message)
        {
            var route = Ambient.Value ?? throw new ControlledTransport.BoundaryException();
            Ambient.Value = null;
            route.CaptureInitialRequest(message);
            message.SetProperty(typeof(ControlledTransport), route);
        }
    }

    public override Request CreateRequest() => inner.CreateRequest();
    public override void Process(HttpMessage message) => throw new InvalidOperationException("Use asynchronous operations.");
    public override ValueTask ProcessAsync(HttpMessage message) =>
        message.TryGetProperty(typeof(ControlledTransport), out var value) && value is ControlledTransport route
            ? route.ProcessAsync(message)
            : throw new ControlledTransport.BoundaryException();
}
