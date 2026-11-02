using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Transport-owned typed Refit builders with independent request validation, never a raw route executor.</summary>
internal sealed class ManagementRequestBuilder
{
    internal readonly IGroupAdministrationApi Groups;
    internal readonly IProjectAdministrationApi Projects;
    internal readonly IProjectTemplateAdministrationApi Templates;
    internal readonly IIdentityTemplateAdministrationApi IdentityTemplates;
    internal readonly IOrganizationIdentityMembershipApi OrganizationIdentityMemberships;
    internal readonly IIdentityAdministrationApi Identities;
    internal readonly IIdentitySearchApi IdentitySearch;
    internal readonly IMembershipAdministrationApi Memberships;
    internal readonly IGovernanceAdministrationApi Governance;
    internal readonly IPrivilegeAdministrationApi Privileges;
    internal readonly ILegacyIdentityPrivilegeApi LegacyPrivileges;
    internal readonly IIdentityPrivilegeChangeApi PrivilegeChanges;
    internal readonly IIdentityAuthenticationAdministrationApi IdentityAuthentication;
    internal readonly IWorkloadIdentityAuthenticationApi WorkloadIdentityAuthentication;
    internal readonly ICloudIdentityAuthenticationApi CloudIdentityAuthentication;
    internal readonly IExternalIdentityAuthenticationApi ExternalIdentityAuthentication;
    internal readonly IPostgresSecretRotationApi PostgresRotations;
    internal readonly IGatewayAdministrationApi Gateways;
    internal readonly IProxiedServiceAdministrationApi ProxiedServices;
    internal readonly IMySqlSecretRotationApi MySqlRotations;
    internal readonly IMsSqlSecretRotationApi MsSqlRotations;
    private readonly Uri _origin;

    internal ManagementRequestBuilder(HttpClient client)
    {
        _origin = client.BaseAddress!;
        var settings = new RefitSettings
        {
            // Builders do not receive responses. Also prevent a future interface
            // return-type change from creating payload-bearing ApiExceptions.
            ExceptionFactory = _ => ValueTask.FromResult<Exception?>(null)
        };
        Groups = RestService.ForGenerated<IGroupAdministrationApi>(client, settings);
        Projects = RestService.ForGenerated<IProjectAdministrationApi>(client, settings);
        Templates = RestService.ForGenerated<IProjectTemplateAdministrationApi>(client, settings);
        IdentityTemplates = RestService.ForGenerated<IIdentityTemplateAdministrationApi>(client, settings);
        OrganizationIdentityMemberships = RestService.ForGenerated<IOrganizationIdentityMembershipApi>(client, settings);
        Identities = RestService.ForGenerated<IIdentityAdministrationApi>(client, settings);
        IdentitySearch = RestService.ForGenerated<IIdentitySearchApi>(client, settings);
        Memberships = RestService.ForGenerated<IMembershipAdministrationApi>(client, settings);
        Governance = RestService.ForGenerated<IGovernanceAdministrationApi>(client, settings);
        Privileges = RestService.ForGenerated<IPrivilegeAdministrationApi>(client, settings);
        LegacyPrivileges = RestService.ForGenerated<ILegacyIdentityPrivilegeApi>(client, settings);
        PrivilegeChanges = RestService.ForGenerated<IIdentityPrivilegeChangeApi>(client, settings);
        IdentityAuthentication = RestService.ForGenerated<IIdentityAuthenticationAdministrationApi>(client, settings);
        WorkloadIdentityAuthentication = RestService.ForGenerated<IWorkloadIdentityAuthenticationApi>(client, settings);
        CloudIdentityAuthentication = RestService.ForGenerated<ICloudIdentityAuthenticationApi>(client, settings);
        ExternalIdentityAuthentication = RestService.ForGenerated<IExternalIdentityAuthenticationApi>(client, settings);
        PostgresRotations = RestService.ForGenerated<IPostgresSecretRotationApi>(client, settings);
        Gateways = RestService.ForGenerated<IGatewayAdministrationApi>(client, settings);
        ProxiedServices = RestService.ForGenerated<IProxiedServiceAdministrationApi>(client, settings);
        MySqlRotations = RestService.ForGenerated<IMySqlSecretRotationApi>(client, settings);
        MsSqlRotations = RestService.ForGenerated<IMsSqlSecretRotationApi>(client, settings);
    }

    internal async Task<HttpRequestMessage> BuildAsync<T>(ManagementRequest<T> request,
        HttpContent? body, CancellationToken cancellationToken) where T : notnull
    {
        Uri expected = new(_origin, request.Path);
        Dictionary<string, List<string>> repeatedValues = request.RepeatedQueryKeys.ToDictionary(
            key => key, _ => new List<string>(), StringComparer.Ordinal);
        Dictionary<string, string> query = Query(expected, repeatedValues);
        HttpRequestMessage message = await request.Build(this, body, cancellationToken).ConfigureAwait(false);

        // Independently verify typed construction before the selected credential is attached.
        try
        {
            Uri? actual = message.RequestUri;
            if (actual is not null && !actual.IsAbsoluteUri)
            {
                actual = new Uri(_origin, actual);
                message.RequestUri = actual;
            }
            Dictionary<string, List<string>> actualRepeatedValues = request.RepeatedQueryKeys.ToDictionary(
                key => key, _ => new List<string>(), StringComparer.Ordinal);
            if (actual is null || expected.Scheme != _origin.Scheme || expected.Authority != _origin.Authority ||
                expected.UserInfo.Length != 0 || expected.Fragment.Length != 0 ||
                actual.Scheme != _origin.Scheme || actual.Authority != _origin.Authority ||
                actual.AbsolutePath != expected.AbsolutePath || actual.UserInfo.Length != 0 ||
                actual.Fragment.Length != 0 || message.Method != request.Method ||
                !Query(actual, actualRepeatedValues).OrderBy(pair => pair.Key, StringComparer.Ordinal)
                    .SequenceEqual(query.OrderBy(pair => pair.Key, StringComparer.Ordinal)) ||
                repeatedValues.Any(pair => !pair.Value.SequenceEqual(actualRepeatedValues[pair.Key])))
                throw new ManagementContractException(SecretStatus.Invalid);
            return message;
        }
        catch
        {
            message.Dispose();
            throw;
        }
    }

    private static Dictionary<string, string> Query(Uri uri, Dictionary<string, List<string>> repeatedValues)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string component in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] pair = component.Split('=', 2);
            string key = Uri.UnescapeDataString(pair[0]);
            string value = pair.Length == 2 ? Uri.UnescapeDataString(pair[1]) : "";
            if (repeatedValues.TryGetValue(key, out List<string>? repeated))
            {
                repeated.Add(value);
                continue;
            }
            if (!values.TryAdd(key, value)) throw new ManagementContractException(SecretStatus.Invalid);
        }
        return values;
    }
}
