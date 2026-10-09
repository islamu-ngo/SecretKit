using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Secrets;
using SecretKit.Core;
using SecretKit.Extensions.Configuration;

namespace SecretKit.ConsumerBaseline;

internal interface IConsumerPath
{
    string Name { get; }
    Task<SafeResult> BootstrapAsync(string expected, CancellationToken token);
    Task<SafeResult> AssessAsync(string scenario, CancellationToken token);
}

// These consumers implement a bounded subset of the actual sample requirements.
// No vendor switches occur in either workflow; binding stays in Program.cs.
internal sealed class KitPath(string name, ISecretReader reader, ISecretInventory admin,
    Func<string, SecretReference> bind, SecretInventoryScope scope) : IConsumerPath
{
    public string Name => name;

    public async Task<SafeResult> BootstrapAsync(string expected, CancellationToken token)
    {
        using var loader = new SecretSnapshotLoader([
            new SecretSelection("first", reader, bind("first")),
            new SecretSelection("second", reader, bind("second"))
        ]);
        SecretOutcome<long> outcome = await loader.RefreshAsync(token);
        if (!outcome.IsSuccess)
            return new(false, outcome.Status.ToString(), 0);
        using SecretSnapshotHandle generation = loader.Acquire();
        using SecretRead first = generation.Read("first");
        using SecretRead second = generation.Read("second");
        first.Dispose();
        if (second.Material.Reveal() != expected || generation.RemoteSnapshotGuaranteed)
            throw new InvalidOperationException("Generation contract failed.");
        using SecretConfigurationExport export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(
            generation, [
                new SecretConfigurationMapping("first", "controlled:first"),
                new SecretConfigurationMapping("second", "controlled:second")
            ]);
        var builder = new Microsoft.Extensions.Configuration.ConfigurationBuilder();
        builder.Add(new Microsoft.Extensions.Configuration.Memory.MemoryConfigurationSource
        {
            InitialData = new Dictionary<string, string?>
            {
                ["controlled:first"] = "local-default",
                ["uncontrolled"] = "local-only"
            }
        });
        builder.Add(export);
        using var configuration = (Microsoft.Extensions.Configuration.ConfigurationRoot)builder.Build();
        if (configuration["controlled:first"] != expected || configuration["controlled:second"] != expected ||
            configuration["uncontrolled"] != "local-only")
            throw new InvalidOperationException("Controlled precedence failed.");
        return new(true, "Success", 0);
    }

    public async Task<SafeResult> AssessAsync(string scenario, CancellationToken token)
    {
        SecretOutcome<SecretInventory> inspection = await admin.InspectAsync(scope, token);
        if (!inspection.IsSuccess || !inspection.Value.IsComplete || inspection.Value.Items.Count != 2)
            throw new InvalidOperationException("Separate administrative inventory failed.");
        if (scenario == "not-checked")
            return new(false, "Unverified", 2);
        SecretOutcome<SecretRead> outcome = await reader.ReadAsync(bind("second"), token);
        if (!outcome.IsSuccess)
            return new(false, outcome.Status switch
            {
                SecretStatus.Absent => "Absent",
                SecretStatus.Denied => "Denied",
                SecretStatus.Invalid or SecretStatus.Expired => "Unusable",
                _ => "Unverified"
            }, 2);
        using SecretRead delivered = outcome.Value;
        string state = delivered.Observation.Validity switch
        {
            SecretValidity.Valid => scenario == "indirect" ? "Indirect" : "Ready",
            SecretValidity.Unknown => "Unverified",
            _ => "Unusable"
        };
        return new(state == "Ready", state, 2);
    }
}

// Independently authored application-owned direct SDK binding and normalization.
// Core is used for owned material/outcome vocabulary, not a SecretKit provider read.
internal sealed class DirectAzurePath : IConsumerPath
{
    private readonly SecretClient _runtime;
    private readonly SecretClient _admin;
    private readonly SecretAuthority _authority = new();

    public DirectAzurePath(TokenCredential credential, HttpPipelineTransport transport)
    {
        var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01)
        {
            DisableChallengeResourceVerification = false,
            Transport = transport
        };
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        options.Retry.MaxRetries = 0;
        _runtime = new SecretClient(Fixture.Vault, credential, options);
        _admin = new SecretClient(Fixture.Vault, credential, options);
    }

    public string Name => "direct-azure-sdk";

    private async Task<SecretOutcome<SecretRead>> ReadAsync(string name, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        try
        {
            KeyVaultSecret delivered = (await _runtime.GetSecretAsync(name, cancellationToken: token)).Value;
            token.ThrowIfCancellationRequested();
            SecretProperties p = delivered.Properties;
            Uri? id = p.Id;
            if (id is null || id.Scheme != Fixture.Vault.Scheme || id.Host != Fixture.Vault.Host ||
                id.Port != Fixture.Vault.Port ||
                !string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))
                return SecretOutcome<SecretRead>.Failure(SecretStatus.Invalid);
            if (delivered.Value is null)
                return SecretOutcome<SecretRead>.Failure(SecretStatus.Unknown);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            SecretValidity validity = p.Enabled == false ? SecretValidity.Disabled :
                p.NotBefore > now ? SecretValidity.NotYetValid :
                p.ExpiresOn <= now ? SecretValidity.Expired :
                p.Enabled is null ? SecretValidity.Unknown : SecretValidity.Valid;
            if (validity != SecretValidity.Valid)
                return SecretOutcome<SecretRead>.Failure(
                    validity == SecretValidity.Expired ? SecretStatus.Expired : SecretStatus.Invalid);
            return SecretOutcome<SecretRead>.Success(new SecretRead(
                SecretMaterial.FromText(delivered.Value),
                new SecretObservation(new SecretReference(_authority,
                    new SecretKit.AzureKeyVault.AzureSecretAddress(name, p.Version)),
                    p.Version, now, validity, p.ExpiresOn)));
        }
        catch (OperationCanceledException) { throw; }
        catch (RequestFailedException failure)
        {
            token.ThrowIfCancellationRequested();
            return SecretOutcome<SecretRead>.Failure(failure.Status switch
            {
                401 or 403 => SecretStatus.Denied,
                404 => SecretStatus.Absent,
                429 => SecretStatus.Throttled,
                400 => SecretStatus.Invalid,
                409 => SecretStatus.Conflict,
                >= 500 => SecretStatus.Unavailable,
                _ => SecretStatus.Unknown
            });
        }
    }

    public async Task<SafeResult> BootstrapAsync(string expected, CancellationToken token)
    {
        var collected = new List<SecretRead>();
        try
        {
            foreach (string name in new[] { "first", "second" })
            {
                SecretOutcome<SecretRead> outcome = await ReadAsync(name, token);
                if (!outcome.IsSuccess)
                    return new(false, outcome.Status.ToString(), 0);
                collected.Add(outcome.Value);
            }
            token.ThrowIfCancellationRequested();
            using SecretMaterial independent = collected[1].Material.Copy();
            collected[1].Dispose();
            if (independent.Reveal() != expected)
                throw new InvalidOperationException("Independent ownership failed.");
            var configuration = new Dictionary<string, string>
            {
                ["controlled:first"] = "local-default",
                ["uncontrolled"] = "local-only"
            };
            configuration["controlled:first"] = collected[0].Material.Reveal();
            configuration["controlled:second"] = independent.Reveal();
            if (configuration["controlled:first"] != expected || configuration["controlled:second"] != expected ||
                configuration["uncontrolled"] != "local-only")
                throw new InvalidOperationException("Controlled precedence failed.");
            return new(true, "Success", 0);
        }
        finally
        {
            foreach (SecretRead read in collected)
                read.Dispose();
        }
    }

    public async Task<SafeResult> AssessAsync(string scenario, CancellationToken token)
    {
        int visible = 0;
        await foreach (Page<SecretProperties> page in _admin.GetPropertiesOfSecretsAsync(token).AsPages(pageSizeHint: 2))
        {
            if (page.ContinuationToken is not null || page.Values.Count != 2 ||
                page.Values.Any(p => p.Id is null || p.Id.Scheme != Fixture.Vault.Scheme ||
                    p.Id.Host != Fixture.Vault.Host || p.Id.Port != Fixture.Vault.Port))
                throw new InvalidOperationException("Bounded administrative inventory failed.");
            visible = page.Values.Count;
            break;
        }
        if (visible != 2)
            throw new InvalidOperationException("Administrative inventory was incomplete.");
        if (scenario == "not-checked")
            return new(false, "Unverified", visible);
        SecretOutcome<SecretRead> outcome = await ReadAsync("second", token);
        if (!outcome.IsSuccess)
            return new(false, outcome.Status switch
            {
                SecretStatus.Absent => "Absent",
                SecretStatus.Denied => "Denied",
                SecretStatus.Invalid or SecretStatus.Expired => "Unusable",
                _ => "Unverified"
            }, visible);
        using SecretRead read = outcome.Value;
        string state = scenario == "indirect" ? "Indirect" : "Ready";
        return new(state == "Ready", state, visible);
    }
}
