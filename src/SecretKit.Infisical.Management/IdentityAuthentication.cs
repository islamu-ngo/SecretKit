using System.Text.Json;
using Refit;

namespace SecretKit.Infisical.Management;

/// <summary>Credential administration uses independently selected grants and caller-held receipts.</summary>
public static class IdentityAuthenticationOperations
{
    private const string Universal = "/api/v1/auth/universal-auth";
    private const string Token = "/api/v1/auth/token-auth";
    private const string UniversalId = "v1.auth.universal.auth.identities.by.identityId";
    private const string TokenId = "v1.auth.token.auth.identities.by.identityId";

    public static ManagementTarget UniversalAuthConfigurationTarget(string organizationId, string identityId,
        UniversalAuthConfigurationInput input, bool update = false)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (update) AuthenticationJson.Number(input.AccessTokenPeriod, 0, 315360000);
        return AuthenticationJson.Intent(organizationId, identityId, update ? "patch-universal" : "attach-universal",
            writer => Write(writer, input.Write));
    }
    public static ManagementTarget TokenAuthConfigurationTarget(string organizationId, string identityId,
        TokenAuthConfigurationInput input, bool update = false)
    {
        ArgumentNullException.ThrowIfNull(input);
        return AuthenticationJson.Intent(organizationId, identityId, update ? "patch-token" : "attach-token",
            writer => Write(writer, input.Write));
    }
    public static ManagementTarget ClientSecretCreateTarget(string organizationId, string identityId,
        string? description = null, double? numUsesLimit = null, double? ttl = null)
    {
        ValidateSecretCreate(description, numUsesLimit, ttl);
        return AuthenticationJson.Intent(organizationId, identityId, "create-client-secret",
            writer => SecretCreate(writer, description, numUsesLimit, ttl));
    }
    public static ManagementTarget TokenCreateTarget(string organizationId, string identityId,
        string? name = null, string? organizationSlug = null)
    {
        ValidateTokenCreate(name, organizationSlug);
        return AuthenticationJson.Intent(organizationId, identityId, "create-token",
            writer => TokenCreate(writer, name, organizationSlug));
    }
    public static ManagementTarget TokenRenameTarget(string organizationId, string tokenId, string? name = null)
    {
        AuthenticationJson.OptionalText(name, 1024);
        return AuthenticationJson.Intent(organizationId, tokenId, "rename-token",
            writer => Rename(writer, name));
    }

    public static ManagementRequest<IdentityAuthenticationConfiguration> AttachUniversalAuth(string organizationId,
        string identityId, UniversalAuthConfigurationInput input) =>
        Configuration(organizationId, identityId, true, HttpMethod.Post,
            UniversalAuthConfigurationTarget(organizationId, identityId, input), input.Write);
    public static ManagementRequest<IdentityAuthenticationConfiguration> UpdateUniversalAuth(string organizationId,
        string identityId, UniversalAuthConfigurationInput input) =>
        Configuration(organizationId, identityId, true, HttpMethod.Patch,
            UniversalAuthConfigurationTarget(organizationId, identityId, input, true), input.Write);
    public static ManagementRequest<IdentityAuthenticationConfiguration> GetUniversalAuth(string organizationId, string identityId) =>
        Configuration(organizationId, identityId, true, HttpMethod.Get, new(organizationId, resourceId: identityId), null);
    /// <summary>Deletes the identity's Universal Auth configuration, not an individual client secret.</summary>
    public static ManagementRequest<IdentityAuthenticationConfiguration> DeleteUniversalAuth(string organizationId, string identityId) =>
        Configuration(organizationId, identityId, true, HttpMethod.Delete, new(organizationId, resourceId: identityId), null);

    public static ManagementRequest<IdentityAuthenticationConfiguration> AttachTokenAuth(string organizationId,
        string identityId, TokenAuthConfigurationInput input) =>
        Configuration(organizationId, identityId, false, HttpMethod.Post,
            TokenAuthConfigurationTarget(organizationId, identityId, input), input.Write);
    public static ManagementRequest<IdentityAuthenticationConfiguration> UpdateTokenAuth(string organizationId,
        string identityId, TokenAuthConfigurationInput input) =>
        Configuration(organizationId, identityId, false, HttpMethod.Patch,
            TokenAuthConfigurationTarget(organizationId, identityId, input, true), input.Write);
    public static ManagementRequest<IdentityAuthenticationConfiguration> GetTokenAuth(string organizationId, string identityId) =>
        Configuration(organizationId, identityId, false, HttpMethod.Get, new(organizationId, resourceId: identityId), null);
    /// <summary>Deletes the identity's Token Auth configuration, not an individual token.</summary>
    public static ManagementRequest<IdentityAuthenticationConfiguration> DeleteTokenAuth(string organizationId, string identityId) =>
        Configuration(organizationId, identityId, false, HttpMethod.Delete, new(organizationId, resourceId: identityId), null);

    public static ManagementRequest<UniversalAuthClientSecretCreation> CreateUniversalClientSecret(string organizationId,
        string identityId, string? description = null, double? numUsesLimit = null, double? ttl = null) =>
        new("infisical.post." + UniversalId + ".client.secrets", HttpMethod.Post, IdentityPath(Universal, identityId) + "/client-secrets",
            ClientSecretCreateTarget(organizationId, identityId, description, numUsesLimit, ttl),
            writer => SecretCreate(writer, description, numUsesLimit, ttl), root => new(root));
    public static ManagementRequest<ManagementPage<UniversalAuthClientSecret>> ListUniversalClientSecrets(
        string organizationId, string identityId) =>
        new("infisical.get." + UniversalId + ".client.secrets", HttpMethod.Get, IdentityPath(Universal, identityId) + "/client-secrets",
            new(organizationId, resourceId: identityId), null,
            root =>
            {
                AuthenticationJson.ClosedObject(root, "clientSecretData");
                return new(ManagementJson.Array(root, "clientSecretData").Select(value => new UniversalAuthClientSecret(value)), true);
            }, false);
    public static ManagementRequest<UniversalAuthClientSecret> GetUniversalClientSecret(string organizationId,
        string identityId, string clientSecretId) => ClientSecret(organizationId, identityId, clientSecretId, false);
    public static ManagementRequest<UniversalAuthClientSecret> RevokeUniversalClientSecret(string organizationId,
        string identityId, string clientSecretId) => ClientSecret(organizationId, identityId, clientSecretId, true);
    public static ManagementRequest<IdentityAuthenticationAcknowledgement> ClearUniversalAuthLockouts(
        string organizationId, string identityId) =>
        new("infisical.post." + UniversalId + ".clear.lockouts", HttpMethod.Post, IdentityPath(Universal, identityId) + "/clear-lockouts",
            new(organizationId, resourceId: identityId), null, root => new(root, true));

    public static ManagementRequest<TokenAuthTokenCreation> CreateToken(string organizationId, string identityId,
        string? name = null, string? organizationSlug = null) =>
        new("infisical.post." + TokenId + ".tokens", HttpMethod.Post, IdentityPath(Token, identityId) + "/tokens",
            TokenCreateTarget(organizationId, identityId, name, organizationSlug),
            writer => TokenCreate(writer, name, organizationSlug), root => new(root, identityId));
    public static ManagementRequest<ManagementPage<TokenAuthToken>> ListTokens(string organizationId, string identityId) =>
        new("infisical.get." + TokenId + ".tokens", HttpMethod.Get, IdentityPath(Token, identityId) + "/tokens",
            new(organizationId, resourceId: identityId), null,
            root =>
            {
                AuthenticationJson.ClosedObject(root, "tokens");
                return new(ManagementJson.Array(root, "tokens").Select(value => new TokenAuthToken(value, identityId)), true);
            }, false);
    public static ManagementRequest<TokenAuthToken> GetToken(string organizationId, string tokenId) =>
        new("infisical.get.v1.auth.token.auth.tokens.by.tokenId", HttpMethod.Get, TokenPath(tokenId),
            new(organizationId, resourceId: tokenId), null,
            root => new(AuthenticationJson.Object(root, "token"), tokenId: tokenId), false);
    /// <summary>Native metadata PATCH; an omitted name emits an empty object, not an explicit null or a persistence promise.</summary>
    public static ManagementRequest<TokenAuthToken> RenameToken(string organizationId, string tokenId, string? name = null) =>
        new("infisical.patch.v1.auth.token.auth.tokens.by.tokenId", HttpMethod.Patch, TokenPath(tokenId),
            TokenRenameTarget(organizationId, tokenId, name), writer => Rename(writer, name),
            root => new(AuthenticationJson.Object(root, "token"), tokenId: tokenId));
    public static ManagementRequest<IdentityAuthenticationAcknowledgement> RevokeToken(string organizationId, string tokenId) =>
        new("infisical.post.v1.auth.token.auth.tokens.by.tokenId.revoke", HttpMethod.Post, TokenPath(tokenId) + "/revoke",
            new(organizationId, resourceId: tokenId), null, root => new(root, false));

    private static ManagementRequest<IdentityAuthenticationConfiguration> Configuration(string organizationId, string identityId,
        bool universal, HttpMethod method, ManagementTarget target, Action<Utf8JsonWriter>? fields) =>
        new("infisical." + method.Method.ToLowerInvariant() + "." + (universal ? UniversalId : TokenId),
            method, IdentityPath(universal ? Universal : Token, identityId), target,
            fields is null ? null : writer => Write(writer, fields),
            root => new(AuthenticationJson.Object(root, universal ? "identityUniversalAuth" : "identityTokenAuth"), identityId, universal),
            method != HttpMethod.Get);
    private static ManagementRequest<UniversalAuthClientSecret> ClientSecret(string organizationId, string identityId,
        string clientSecretId, bool revoke) =>
        new("infisical." + (revoke ? "post" : "get") + "." + UniversalId + ".client.secrets.by.clientSecretId" + (revoke ? ".revoke" : ""),
            revoke ? HttpMethod.Post : HttpMethod.Get, IdentityPath(Universal, identityId) + "/client-secrets/" +
                ManagementJson.Escape(clientSecretId) + (revoke ? "/revoke" : ""),
            new(organizationId, resourceId: identityId, secondaryId: clientSecretId), null,
            root => new(AuthenticationJson.Object(root, "clientSecretData"), clientSecretId), revoke);
    private static string IdentityPath(string strategy, string identityId) => strategy + "/identities/" + ManagementJson.Escape(identityId);
    private static string TokenPath(string tokenId) => Token + "/tokens/" + ManagementJson.Escape(tokenId);
    private static void Write(Utf8JsonWriter writer, Action<Utf8JsonWriter> fields)
    {
        writer.WriteStartObject();
        fields(writer);
        writer.WriteEndObject();
    }
    private static void ValidateSecretCreate(string? description, double? uses, double? ttl)
    {
        AuthenticationJson.OptionalText(description, 1024);
        AuthenticationJson.Number(uses, 0, double.MaxValue);
        AuthenticationJson.Number(ttl, 0, 315360000);
    }
    private static void SecretCreate(Utf8JsonWriter writer, string? description, double? uses, double? ttl) =>
        Write(writer, json =>
        {
            if (description is not null) json.WriteString("description", description);
            AuthenticationJson.Number(json, "numUsesLimit", uses);
            AuthenticationJson.Number(json, "ttl", ttl);
        });
    private static void ValidateTokenCreate(string? name, string? slug)
    {
        AuthenticationJson.OptionalText(name, 1024);
        if (slug is not null) ManagementJson.Text(slug, 64);
    }
    private static void TokenCreate(Utf8JsonWriter writer, string? name, string? slug) =>
        Write(writer, json =>
        {
            if (name is not null) json.WriteString("name", name);
            if (slug is not null) json.WriteString("organizationSlug", slug);
        });
    private static void Rename(Utf8JsonWriter writer, string? name) => Write(writer, json =>
    {
        if (name is not null) json.WriteString("name", name);
    });
}

// Handwritten native routes. Only request construction, never dispatch.
internal interface IIdentityAuthenticationAdministrationApi
{
    [Post("/api/v1/auth/universal-auth/identities/{identityId}")]
    Task<HttpRequestMessage> AttachUniversal(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/auth/universal-auth/identities/{identityId}")]
    Task<HttpRequestMessage> UpdateUniversal(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v1/auth/universal-auth/identities/{identityId}")]
    Task<HttpRequestMessage> Universal(string identityId, CancellationToken cancellationToken);
    [Delete("/api/v1/auth/universal-auth/identities/{identityId}")]
    Task<HttpRequestMessage> DeleteUniversal(string identityId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/universal-auth/identities/{identityId}/client-secrets")]
    Task<HttpRequestMessage> CreateSecret(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v1/auth/universal-auth/identities/{identityId}/client-secrets")]
    Task<HttpRequestMessage> Secrets(string identityId, CancellationToken cancellationToken);
    [Get("/api/v1/auth/universal-auth/identities/{identityId}/client-secrets/{clientSecretId}")]
    Task<HttpRequestMessage> Secret(string identityId, string clientSecretId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/universal-auth/identities/{identityId}/client-secrets/{clientSecretId}/revoke")]
    Task<HttpRequestMessage> RevokeSecret(string identityId, string clientSecretId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/universal-auth/identities/{identityId}/clear-lockouts")]
    Task<HttpRequestMessage> ClearLockouts(string identityId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/token-auth/identities/{identityId}")]
    Task<HttpRequestMessage> AttachToken(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/auth/token-auth/identities/{identityId}")]
    Task<HttpRequestMessage> UpdateToken(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v1/auth/token-auth/identities/{identityId}")]
    Task<HttpRequestMessage> Token(string identityId, CancellationToken cancellationToken);
    [Delete("/api/v1/auth/token-auth/identities/{identityId}")]
    Task<HttpRequestMessage> DeleteToken(string identityId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/token-auth/identities/{identityId}/tokens")]
    Task<HttpRequestMessage> CreateAccessToken(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v1/auth/token-auth/identities/{identityId}/tokens")]
    Task<HttpRequestMessage> AccessTokens(string identityId, CancellationToken cancellationToken);
    [Get("/api/v1/auth/token-auth/tokens/{tokenId}")]
    Task<HttpRequestMessage> AccessToken(string tokenId, CancellationToken cancellationToken);
    [Patch("/api/v1/auth/token-auth/tokens/{tokenId}")]
    Task<HttpRequestMessage> RenameAccessToken(string tokenId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Post("/api/v1/auth/token-auth/tokens/{tokenId}/revoke")]
    Task<HttpRequestMessage> RevokeAccessToken(string tokenId, CancellationToken cancellationToken);
}
