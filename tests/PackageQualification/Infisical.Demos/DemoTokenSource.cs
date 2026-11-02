using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.Samples.Infisical;

internal sealed class DemoTokenSource(SecretMaterial token) : IInfisicalTokenSource
{
    public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(token.Copy())));
    }
}
