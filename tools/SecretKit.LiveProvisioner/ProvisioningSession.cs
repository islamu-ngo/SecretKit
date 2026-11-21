using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Infisical.Management;

namespace SecretKit.LiveProvisioner;

internal sealed class ProvisioningSession : IDisposable
{
    private readonly InfisicalAccessToken _token;
    private readonly ManagementTransport _transport;
    private readonly ManagementClient _client;
    private readonly IInfisicalTokenSource _tokens;
    private readonly InfisicalNetworkOptions _network;
    private readonly Uri _origin;
    internal string OrganizationId { get; }

    internal ProvisioningSession(Uri origin, string organizationId, InfisicalAccessToken token, InfisicalNetworkOptions network)
    {
        _origin = origin;
        OrganizationId = organizationId;
        _network = network;
        _token = token;
        _tokens = new SelectedToken(token);
        _transport = new(origin, network);
        _client = new(_transport);
    }

    internal static InfisicalNetworkOptions Network(LiveTarget target, HttpClient? pipeline) => new()
    {
        AllowLoopbackDevelopmentHttp = target == LiveTarget.Local,
        Transport = pipeline is null ? new InfisicalNetworkOptions().Transport : InfisicalTransportOptions.HostControlled(pipeline)
    };

    internal static async Task<ProvisioningSession> OpenAsync(LiveEnvConfig config, HttpClient? pipeline, CancellationToken ct,
        Func<string, string, Uri, CancellationToken, Task>? verifySandbox = null)
    {
        if (config.Target == LiveTarget.Local)
            await (verifySandbox ?? LocalSandboxReadiness.VerifyAsync)(config.RepositoryRoot, config.Owner!, config.Origin, ct);
        var network = Network(config.Target, pipeline);
        using var authentication = new InfisicalUniversalAuthentication(config.Origin, network);
        var receipt = authentication.CreateReceipt();
        using var issued = Require(await authentication.LoginAsync(config.AutomationClientId, config.AutomationClientSecret,
            receipt, cancellationToken: ct), "automation login", receipt.Evidence);
        var token = new InfisicalAccessToken(issued.Token.Material.Copy(), issued.Token.ExpiresAt);
        try { return new(config.Origin, config.OrganizationId, token, network); }
        catch { token.Dispose(); throw; }
    }

    internal InfisicalClient CreateSecretsClient() => new(_origin, _tokens, _network);

    internal InfisicalNativeAuthority NativeAuthority(InfisicalClient client, string project, string environment, string folder) =>
        new(client.Authority, _tokens, project, environment, folder);

    internal async Task<T> Apply<T>(ManagementRequest<T> request, string step, CancellationToken ct) where T : notnull
    {
        using (request)
        {
            var receipt = request.IsMutation ? _client.CreateReceipt(request) : null;
            var authority = new ManagementAuthority(_client.Authority, _tokens, OrganizationId, request.Target.ProjectId);
            var result = await _client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                receipt, ct);
            return Require(result, step, receipt?.Evidence);
        }
    }

    internal static T Require<T>(SecretOutcome<T> outcome, string step, DispatchEvidence? evidence = null) where T : notnull
    {
        if (outcome.IsSuccess)
            return outcome.Value;
        string restriction = outcome.Status is SecretStatus.Invalid or SecretStatus.Denied
            ? " Check the selected identity permissions, request contract, and organization plan/edition." : "";
        throw new ProvisioningException($"{step}: {outcome.Status} ({outcome.Reason}); dispatch: {evidence?.ToString() ?? "read"}.{restriction}");
    }

    public void Dispose()
    {
        _transport.Dispose();
        _token.Dispose();
    }

    private sealed class SelectedToken(InfisicalAccessToken token) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(token.Material.Copy(), token.ExpiresAt)));
        }
    }
}
