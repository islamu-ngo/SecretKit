using System.Text.Json;

namespace SecretKit.Infisical.Management;

/// <summary>Typed proxy configuration only, not proxy runtime, backend transport or principal acquisition.</summary>
public static class ProxiedServiceAdministrationOperations
{
    // Original wire-facts-0555 through 0563. Delete has no credentials; reads add canProxy.
    private const string Path = "/api/v1/proxied-services";

    public static ManagementRequest<ProxiedServiceList> List(string organizationId, string projectId,
        string environment, string? secretPath = null) =>
        new("infisical.get.v1.proxied.services", HttpMethod.Get, Path + Query(projectId, environment, secretPath),
            ListTarget(organizationId, projectId, environment, secretPath), null, root => new(root), false);

    public static ManagementTarget ListTarget(string organizationId, string projectId, string environment, string? secretPath = null)
    {
        Query(projectId, environment, secretPath);
        return GatewayJson.BodyTarget(organizationId, projectId, environment, writer => WriteSelection(writer, environment, secretPath));
    }

    public static ManagementRequest<ProxiedServiceSummary> Create(string organizationId, ProxiedServiceCreation creation)
    {
        ArgumentNullException.ThrowIfNull(creation);
        return new("infisical.post.v1.proxied.services", HttpMethod.Post, Path, CreationTarget(organizationId, creation),
            creation.Write, root => new(ManagementJson.Object(root, "service"), true, false, name: creation.Name));
    }

    public static ManagementTarget CreationTarget(string organizationId, ProxiedServiceCreation creation)
    {
        ArgumentNullException.ThrowIfNull(creation);
        return GatewayJson.BodyTarget(organizationId, creation.ProjectId, creation.Name, creation.Write);
    }

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

    public static ManagementTarget UpdateTarget(string organizationId, string projectId, string serviceId, ProxiedServiceUpdate update)
    {
        ArgumentNullException.ThrowIfNull(update);
        GatewayJson.UuidInput(serviceId);
        return GatewayJson.BodyTarget(organizationId, projectId, serviceId, update.Write);
    }

    public static ManagementRequest<ProxiedServiceSummary> Delete(string organizationId, string projectId, string serviceId) =>
        new("infisical.delete.v1.proxied.services.by.serviceId", HttpMethod.Delete, ServicePath(serviceId),
            new(organizationId, projectId, serviceId), null,
            root => new(ManagementJson.Object(root, "service"), false, false, serviceId));

    public static ManagementRequest<ProxiedServiceSummary> GetByName(string organizationId, string projectId,
        string environment, string name, string? secretPath = null) =>
        new("infisical.get.v1.proxied.services.slug.by.name", HttpMethod.Get,
            Path + "/slug/" + Uri.EscapeDataString(Name(name)) + Query(projectId, environment, secretPath),
            NameTarget(organizationId, projectId, environment, name, secretPath), null,
            root => new(ManagementJson.Object(root, "service"), true, true, name: name), false);

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
