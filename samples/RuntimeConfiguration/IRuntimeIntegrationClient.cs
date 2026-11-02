namespace SecretKit.Samples.RuntimeConfiguration;

/// <summary>Application-defined work; acceptance and client construction belong to the validator.</summary>
public interface IRuntimeIntegrationClient : IAsyncDisposable
{
    ValueTask<string> ExecuteAsync(CancellationToken cancellationToken = default);
}
