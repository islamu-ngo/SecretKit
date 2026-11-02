using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SecretKit.Core;
using SecretKit.Extensions.Hosting;
using SecretKit.Infisical;

string? origin = Environment.GetEnvironmentVariable("SECRETKIT_ORIGIN");
string? clientId = Environment.GetEnvironmentVariable("SECRETKIT_CLIENT_ID");
string? project = Environment.GetEnvironmentVariable("SECRETKIT_PROJECT_ID");
string? environment = Environment.GetEnvironmentVariable("SECRETKIT_ENVIRONMENT");
string? clientSecret = Environment.GetEnvironmentVariable("SECRETKIT_CLIENT_SECRET");
string? key = Environment.GetEnvironmentVariable("SECRETKIT_KEY");
if (new[] { origin, clientId, project, environment, clientSecret, key }.Any(string.IsNullOrWhiteSpace))
{
    Console.WriteLine("Set SECRETKIT_ORIGIN, CLIENT_ID, PROJECT_ID, ENVIRONMENT, CLIENT_SECRET and KEY (all prefixed SECRETKIT_) for this read-only worker.");
    return;
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddSecretKitInfisical(options =>
{
    options.Runtime = new InfisicalRuntimeOptions
    {
        Origin = new Uri(origin!),
        ClientId = clientId!,
        ProjectId = project!,
        Lifetime = InfisicalTokenLifetime.Finite,
        OriginalIssuedAt = DateTimeOffset.UtcNow
    };
    // The host owns this ordinary input string and its lifetime.
    options.ClientSecret = _ => ValueTask.FromResult(SecretMaterial.FromText(clientSecret!));
}).WithDefaultScope(project!, environment!).WithStartupAdmission();
using IHost host = builder.Build();
await host.StartAsync();
try
{
    var scope = host.Services.GetRequiredService<InfisicalSecretScope>();
    using SecretRead read = await scope.GetSecretAsync(key!);
    read.Material.Use(static _ => { /* Supply this borrowed span to your application operation. */ });
    Console.WriteLine("One authenticated operation completed without printing secret material.");
}
finally { await host.StopAsync(); }
