using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

public enum IdentityTemplateAuthMethod
{
    Ldap,
    Kubernetes,
    Oidc
}

/// <summary>OIDC creation fields. Null optional arguments omit fields; empty strings are explicit values.</summary>
public sealed class IdentityTemplateOidcFields : IdentityTemplateFields
{
    public IdentityTemplateOidcFields(string discoveryUrl, string boundIssuer,
        string? boundAudiences = null, string? caCertificate = null) : base("oidc")
    {
        ManagementJson.Text(discoveryUrl, 2048);
        ManagementJson.Text(boundIssuer, 2048);
        if (!Uri.TryCreate(discoveryUrl, UriKind.Absolute, out _))
            throw new ArgumentException("Invalid identity template discovery URL.");
        DiscoveryUrl = discoveryUrl;
        BoundIssuer = boundIssuer;
        IdentityTemplateWire.Text(boundAudiences, 2048);
        IdentityTemplateWire.Text(caCertificate, 102400);
        BoundAudiences = boundAudiences;
        CaCertificate = caCertificate;
    }

    [JsonIgnore] public string DiscoveryUrl { get; }
    [JsonIgnore] public string BoundIssuer { get; }
    [JsonIgnore] public string? BoundAudiences { get; }
    [JsonIgnore] public string? CaCertificate { get; }
    internal override void Write(Utf8JsonWriter writer)
    {
        writer.WriteString("oidcDiscoveryUrl", DiscoveryUrl);
        writer.WriteString("boundIssuer", BoundIssuer);
        IdentityTemplateWire.String(writer, "boundAudiences", BoundAudiences);
        IdentityTemplateWire.String(writer, "caCert", CaCertificate);
    }
    public override string ToString() => "[IdentityTemplateOidcFields]";
}

/// <summary>Protected settings and metadata, not stored credential material or effective-permission evidence.</summary>
public sealed class IdentityTemplateSummary
{
    internal IdentityTemplateSummary(JsonElement value, string organizationId, string? templateId = null,
        string? name = null, string? authMethod = null)
    {
        ManagementJson.RequireEqual(value, "orgId", organizationId);
        if (templateId is not null) ManagementJson.RequireEqual(value, "id", templateId);
        if (name is not null) ManagementJson.RequireEqual(value, "name", name);
        string method = ManagementJson.Required(value, "authMethod");
        if (authMethod is not null && method != authMethod)
            throw new ManagementContractException(SecretStatus.Invalid);
        JsonElement fields = ManagementJson.Object(value, "templateFields");
        AuthMethod = method switch
        {
            "ldap" => IdentityTemplateAuthMethod.Ldap,
            "kubernetes" => IdentityTemplateAuthMethod.Kubernetes,
            "oidc" => IdentityTemplateAuthMethod.Oidc,
            _ => throw new ManagementContractException(SecretStatus.Unknown)
        };
        if (AuthMethod == IdentityTemplateAuthMethod.Ldap)
            HasStoredCredential = ManagementJson.Boolean(fields, "hasBindPass");
        else if (AuthMethod == IdentityTemplateAuthMethod.Kubernetes)
            HasStoredCredential = ManagementJson.Boolean(fields, "hasTokenReviewerJwt");
        Configuration = new(fields, AuthMethod);
        Id = ManagementJson.Required(value, "id");
        if (!Guid.TryParseExact(Id, "D", out _))
            throw new ManagementContractException(SecretStatus.Unknown);
        OrganizationId = organizationId;
        Name = ManagementJson.Required(value, "name");
        CreatedAt = ManagementJson.Required(value, "createdAt");
        UpdatedAt = ManagementJson.Required(value, "updatedAt");
    }

    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string OrganizationId { get; }
    [JsonIgnore] public string Name { get; }
    [JsonIgnore] public IdentityTemplateAuthMethod AuthMethod { get; }
    [JsonIgnore] public bool? HasStoredCredential { get; }
    [JsonIgnore] public string CreatedAt { get; }
    [JsonIgnore] public string UpdatedAt { get; }
    [JsonIgnore] public IdentityTemplateConfigurationSummary Configuration { get; }
    public bool IncludesConfiguration => true;
    public override string ToString() => "[IdentityTemplateSummary]";
}

/// <summary>Protected association metadata. Usage responses do not attest organization, template, permissions or delivery.</summary>
public sealed class IdentityTemplateUsage
{
    internal IdentityTemplateUsage(JsonElement value, bool deleted, string? identityId = null)
    {
        if (identityId is not null) ManagementJson.RequireEqual(value, "identityId", identityId);
        IdentityId = ManagementJson.Required(value, "identityId");
        IdentityName = ManagementJson.Required(value, "identityName");
        AuthId = deleted ? ManagementJson.Required(value, "authId") : null;
        if (string.IsNullOrWhiteSpace(IdentityId) || deleted && string.IsNullOrWhiteSpace(AuthId))
            throw new ManagementContractException(SecretStatus.Unknown);
    }

    [JsonIgnore] public string IdentityId { get; }
    [JsonIgnore] public string IdentityName { get; }
    [JsonIgnore] public string? AuthId { get; }
    public override string ToString() => "[IdentityTemplateUsage]";
}

/// <summary>Native deletion acknowledgement only; the response has no scope coordinates.</summary>
public sealed class IdentityTemplateDeletion
{
    internal IdentityTemplateDeletion(JsonElement value) => Message = ManagementJson.Required(value, "message");
    [JsonIgnore] public string Message { get; }
    public override string ToString() => "[IdentityTemplateDeletion]";
}

/// <summary>
/// Typed native identity-template operations. Results are metadata, never
/// effective permission, configuration persistence or delivery proof.
/// </summary>
public static partial class IdentityTemplateOperations
{
    public static ManagementRequest<ManagementPage<IdentityTemplateSummary>> ListIdentityTemplates(
        string organizationId, IdentityTemplateAuthMethod authMethod)
    {
        string method = NativeMethod(authMethod);
        return new("infisical.get.v1.identity.templates", HttpMethod.Get, "/api/v1/identity-templates?authMethod=" + method,
            new(organizationId, secondaryId: method), null,
            root => new(ManagementJson.Array(root).Select(value =>
                new IdentityTemplateSummary(value, organizationId, authMethod: method)), true), false);
    }

    public static ManagementRequest<ManagementPage<IdentityTemplateSummary>> SearchIdentityTemplates(
        string organizationId, string? search = null, int offset = 0, int limit = 5)
    {
        string query = TemplateSearchQuery(search, offset, limit);
        return new("infisical.get.v1.identity.templates.search", HttpMethod.Get, "/api/v1/identity-templates/search?" + query,
            InventorySelectorWire.Intent(organizationId, null, query), null, root =>
            {
                IdentityTemplateSummary[] rows = ManagementJson.Array(root, "templates")
                    .Select(value => new IdentityTemplateSummary(value, organizationId)).ToArray();
                int total = ManagementJson.Integer(root, "totalCount");
                int end = offset + rows.Length;
                if (total < 0 || rows.Length > limit || rows.Length > 0 && total < end ||
                    rows.Length == 0 && total > offset)
                    throw new ManagementContractException(SecretStatus.Unknown);
                return new(rows, end >= total, end < total ? end : null);
            }, false);
    }

    /// <summary>Independently approved whole template search, including paging.</summary>
    public static ManagementTarget IdentityTemplateSearchTarget(string organizationId,
        string? search = null, int offset = 0, int limit = 5) =>
        InventorySelectorWire.Intent(organizationId, null, TemplateSearchQuery(search, offset, limit));

    private static string TemplateSearchQuery(string? search, int offset, int limit)
    {
        string query = ManagementJson.Paging(offset, limit);
        if (search is not null)
        {
            ManagementJson.Text(search);
            query += "&search=" + ManagementJson.Escape(search);
        }
        return query;
    }

    public static ManagementRequest<IdentityTemplateSummary> GetIdentityTemplate(string organizationId, string templateId) =>
        new("infisical.get.v1.identity.templates.by.templateId", HttpMethod.Get, TemplatePath(templateId),
            new(organizationId, resourceId: templateId), null,
            root => new(root, organizationId, templateId), false);

    public static ManagementRequest<IdentityTemplateSummary> CreateIdentityTemplate(string organizationId,
        string name, IdentityTemplateOidcFields fields)
        => Create(organizationId, name, fields);

    public static ManagementRequest<IdentityTemplateSummary> UpdateIdentityTemplate(string organizationId,
        string templateId, string? name = null)
        => Update(organizationId, templateId, name, null);

    public static ManagementRequest<IdentityTemplateDeletion> DeleteIdentityTemplate(string organizationId, string templateId) =>
        new("infisical.delete.v1.identity.templates.by.templateId", HttpMethod.Delete, TemplatePath(templateId),
            new(organizationId, resourceId: templateId), null, root => new(root));

    public static ManagementRequest<ManagementPage<IdentityTemplateUsage>> GetIdentityTemplateUsage(
        string organizationId, string templateId) =>
        new("infisical.get.v1.identity.templates.by.templateId.usage", HttpMethod.Get, TemplatePath(templateId) + "/usage",
            new(organizationId, resourceId: templateId), null,
            root => new(ManagementJson.Array(root).Select(value => new IdentityTemplateUsage(value, false)), true), false);

    /// <summary>Unlinks exactly one caller-selected identity with a full change-intent grant and single-use receipt.</summary>
    public static ManagementRequest<ManagementPage<IdentityTemplateUsage>> DeleteIdentityTemplateUsage(
        string organizationId, string templateId, string identityId)
        => DeleteIdentityTemplateUsages(organizationId, templateId, [identityId]);

    private static string TemplatePath(string templateId) => "/api/v1/identity-templates/" + ManagementJson.Escape(templateId);

    private static string NativeMethod(IdentityTemplateAuthMethod method) => method switch
    {
        IdentityTemplateAuthMethod.Ldap => "ldap",
        IdentityTemplateAuthMethod.Kubernetes => "kubernetes",
        IdentityTemplateAuthMethod.Oidc => "oidc",
        _ => throw new ArgumentOutOfRangeException(nameof(method))
    };
}
