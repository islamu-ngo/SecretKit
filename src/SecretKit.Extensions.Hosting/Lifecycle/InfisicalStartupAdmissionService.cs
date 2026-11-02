using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.Extensions.Hosting;

internal sealed class InfisicalStartupAdmissionService(InfisicalRuntimeSession runtime,
    ILogger<InfisicalStartupAdmissionService> logger) : IHostedLifecycleService
{
    public async Task StartingAsync(CancellationToken cancellationToken)
    {
        var outcome = await runtime.EnsureAuthenticatedAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            InfisicalHostingLog.Authentication(logger, outcome.Status, outcome.Reason,
                runtime.OpeningAttempt.LoginReceipt?.Evidence ?? DispatchEvidence.NotDispatched);
        }
        catch (Exception) { } // A host logger cannot change authentication evidence or expose its own exception.
        _ = outcome.GetValueOrThrow();
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StoppingAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StopAsync(CancellationToken cancellationToken) => runtime.StopAsync().WaitAsync(cancellationToken);
    public Task StoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
