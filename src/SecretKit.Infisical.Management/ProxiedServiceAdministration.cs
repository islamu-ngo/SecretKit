using System.Text.Json;

namespace SecretKit.Infisical.Management;

/// <summary>Typed proxy configuration only, not proxy runtime, backend transport or principal acquisition.</summary>
public static class ProxiedServiceAdministrationOperations
{
    // Original wire-facts-0555 through 0563. Delete has no credentials; reads add canProxy.
    private const string Path = "/api/v1/proxied-services";

    /// <summary>Builds disposable proxy-service inventory for exact project/environment and optional path; dispose the successful list.</summary>
    public static ManagementRequest<ProxiedServiceList> List(string organizationId, string projectId,
        string environment, string? secretPath = null) =>
        new("infisical.get.v1.proxied.services", HttpMethod.Get, Path + Query(projectId, environment, secretPath),
            ListTarget(organizationId, projectId, environment, secretPath), null, root => new(root), false);

    /// <summary>Builds independent list approval intent; null path omits filtering and differs from empty path.</summary>
    public static ManagementTarget ListTarget(string organizationId, string projectId, string environment, string? secretPath = null)
    {
        Query(projectId, environment, secretPath);
        return GatewayJson.BodyTarget(organizationId, projectId, environment, writer => WriteSelection(writer, environment, secretPath));
    }

    /// <summary>Builds proxy configuration creation; does not start proxy traffic or acquire backend credentials.</summary>
    public static ManagementRequest<ProxiedServiceSummary> Create(string organizationId, ProxiedServiceCreation creation)
    {
        ArgumentNullException.ThrowIfNull(creation);
        return new("infisical.post.v1.proxied.services", HttpMethod.Post, Path, CreationTarget(organizationId, creation),
            creation.Write, root => new(ManagementJson.Object(root, "service"), true, false, name: creation.Name));
    }

    /// <summary>Builds independent approval for the complete copied proxy creation body.</summary>
    public static ManagementTarget CreationTarget(string organizationId, ProxiedServiceCreation creation)
    {
        ArgumentNullException.ThrowIfNull(creation);
        return GatewayJson.BodyTarget(organizationId, creation.ProjectId, creation.Name, creation.Write);
    }

    /// <summary>Builds exact proxy configuration inspection; dispose returned placeholder material after use.</summary>
    public static ManagementRequest<ProxiedServiceSummary> Get(string organizationId, string projectId, string serviceId) =>
        new("infisical.get.v1.proxied.services.by.serviceId", HttpMethod.Get, ServicePath(serviceId),
            new(organizationId, projectId, serviceId), null,
            root => new(ManagementJson.Object(root, "service"), true, true, serviceId), false);

    /// <summary>Known PATCH inputs/results; nested replacement, merge, persistence and backend effects remain unverified.</summary>
    public static ManagementRequest<ProxiedServiceSummary> Update(string organizationId, string projectId,
        string serviceId, ProxiedServiceUpdate update)
    {
        ArgumentNullException.ThrowIfNull(update);
        return new("infisical.patch.v1.proxied.services.by.serviceId", HttpMethod.Patch, ServicePath(serviceId),
            UpdateTarget(organizationId, projectId, serviceId, update), update.Write,
            root => new(ManagementJson.Object(root, "service"), true, false, serviceId));
    }

    /// <summary>Builds independent approval for the selected service UUID and complete patch body.</summary>
    public static ManagementTarget UpdateTarget(string organizationId, string projectId, string serviceId, ProxiedServiceUpdate update)
    {
        ArgumentNullException.ThrowIfNull(update);
        GatewayJson.UuidInput(serviceId);
        return GatewayJson.BodyTarget(organizationId, projectId, serviceId, update.Write);
    }

    /// <summary>Builds proxy configuration deletion; deletion metadata omits credentials and does not attest backend cleanup.</summary>
    public static ManagementRequest<ProxiedServiceSummary> Delete(string organizationId, string projectId, string serviceId) =>
        new("infisical.delete.v1.proxied.services.by.serviceId", HttpMethod.Delete, ServicePath(serviceId),
            new(organizationId, projectId, serviceId), null,
            root => new(ManagementJson.Object(root, "service"), false, false, serviceId));

    /// <summary>Builds name-based proxy configuration lookup under exact native scope.</summary>
    public static ManagementRequest<ProxiedServiceSummary> GetByName(string organizationId, string projectId,
        string environment, string name, string? secretPath = null) =>
        new("infisical.get.v1.proxied.services.slug.by.name", HttpMethod.Get,
            Path + "/slug/" + Uri.EscapeDataString(Name(name)) + Query(projectId, environment, secretPath),
            NameTarget(organizationId, projectId, environment, name, secretPath), null,
            root => new(ManagementJson.Object(root, "service"), true, true, name: name), false);

    /// <summary>Builds independent name-lookup approval preserving optional path omission.</summary>
    public static ManagementTarget NameTarget(string organizationId, string projectId, string environment, string name, string? secretPath = null)
    {
        Name(name);
        Query(projectId, environment, secretPath);
        return GatewayJson.BodyTarget(organizationId, projectId, name, writer => WriteSelection(writer, environment, secretPath));
    }

    private static void WriteSelection(Utf8JsonWriter writer, string environment, string? secretPath)
    {
        writer.WriteStartObject();
        writer.WriteString("environment", environment);
        if (secretPath is not null) writer.WriteString("secretPath", secretPath);
        writer.WriteEndObject();
    }

    private static string Name(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        GatewayJson.InputText(name, 64, 1);
        return name;
    }

    private static string ServicePath(string id)
    {
        GatewayJson.UuidInput(id);
        return Path + "/" + id;
    }

    private static string Query(string project, string environment, string? secretPath)
    {
        ManagementJson.Text(project);
        ManagementJson.Text(environment);
        GatewayJson.InputText(secretPath, 16384);
        return "?projectId=" + Uri.EscapeDataString(project) + "&environment=" + Uri.EscapeDataString(environment) +
            (secretPath is null ? "" : "&secretPath=" + Uri.EscapeDataString(secretPath));
    }
}
