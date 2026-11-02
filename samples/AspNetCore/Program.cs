using SecretKit.Core;
using SecretKit.Extensions.Hosting;
using SecretKit.Infisical;

string? origin = Environment.GetEnvironmentVariable("SECRETKIT_ORIGIN");
string? clientId = Environment.GetEnvironmentVariable("SECRETKIT_CLIENT_ID");
string? project = Environment.GetEnvironmentVariable("SECRETKIT_PROJECT_ID");
string? environment = Environment.GetEnvironmentVariable("SECRETKIT_ENVIRONMENT");
string? clientSecret = Environment.GetEnvironmentVariable("SECRETKIT_CLIENT_SECRET");
if (new[] { origin, clientId, project, environment, clientSecret }.Any(string.IsNullOrWhiteSpace))
{
    Console.WriteLine("Set SECRETKIT_ORIGIN, CLIENT_ID, PROJECT_ID, ENVIRONMENT and CLIENT_SECRET (all prefixed SECRETKIT_) to run against your authorized Infisical instance.");
    return;
}

var builder = WebApplication.CreateBuilder(args);
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
    // Environment variables and this string are host-owned plaintext; SDK disposal cannot erase them.
    options.ClientSecret = _ => ValueTask.FromResult(SecretMaterial.FromText(clientSecret!));
}).WithDefaultScope(project!, environment!).WithStartupAdmission().WithHealthChecks();
var app = builder.Build();
app.MapGet("/", () => Results.Ok(new { status = "started-after-authentication" }));
app.Run("http://127.0.0.1:5080");
