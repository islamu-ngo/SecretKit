using Microsoft.Extensions.DependencyInjection;

namespace SecretKit.Extensions.Hosting;

/// <summary>Explicit host integration choices for one unkeyed or keyed runtime.</summary>
public interface ISecretKitInfisicalBuilder
{
    /// <summary>The collection receiving this runtime's registrations.</summary>
    IServiceCollection Services { get; }

    /// <summary>Registers a borrowed secret scope with explicit coordinates for this runtime.</summary>
    ISecretKitInfisicalBuilder WithDefaultScope(string projectId, string environment, string folder = "/");

    /// <summary>Authenticates once before hosted services start; failure prevents startup.</summary>
    ISecretKitInfisicalBuilder WithStartupAdmission();

    /// <summary>Registers a material-free health check without provider I/O or authentication.</summary>
    ISecretKitInfisicalBuilder WithHealthChecks();
}
