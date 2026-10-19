using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class InfisicalIdentityFamilies
{
    internal static readonly Dictionary<string, ProjectFamilyBinding> Bindings = new(StringComparer.Ordinal)
    {
        ["i.management.IdentityOperations.CreateOrganizationIdentity"] = new("SecretKit.Infisical.Management.IdentityOperations.CreateOrganizationIdentity(System.String,System.String,System.String,System.Boolean,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.Management.IdentityAttribute>)",
            ["deleteProtection.false", "deleteProtection.true", "metadata.omitted", "metadata.value", "metadata.empty", "metadata.values"], true),
        ["i.management.IdentityOperations.CreateProjectIdentity"] = new("SecretKit.Infisical.Management.IdentityOperations.CreateProjectIdentity(System.String,System.String,System.String,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.Management.MembershipRole>,System.Boolean,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.Management.IdentityAttribute>)",
            ["roles.omitted", "roles.value", "deleteProtection.false", "deleteProtection.true", "metadata.omitted", "metadata.value", "metadata.empty", "metadata.values", "roles.empty", "roles.permanent", "roles.relative-time"], true),
        ["i.management.IdentityOperations.DeleteOrganizationIdentity"] = new("SecretKit.Infisical.Management.IdentityOperations.DeleteOrganizationIdentity(System.String,System.String)",
            ["input.organizationId-identityId"], true),
        ["i.management.IdentityOperations.DeleteProjectIdentity"] = new("SecretKit.Infisical.Management.IdentityOperations.DeleteProjectIdentity(System.String,System.String,System.String)",
            ["input.organizationId-projectId-identityId"], true),
        ["i.management.IdentityOperations.GetOrganizationIdentity"] = new("SecretKit.Infisical.Management.IdentityOperations.GetOrganizationIdentity(System.String,System.String)",
            ["selector.exact"], false),
        ["i.management.IdentityOperations.GetProjectIdentity"] = new("SecretKit.Infisical.Management.IdentityOperations.GetProjectIdentity(System.String,System.String,System.String)",
            ["selector.exact"], false),
        ["i.management.IdentityOperations.GetSelectedIdentityOrganization"] = new("SecretKit.Infisical.Management.IdentityOperations.GetSelectedIdentityOrganization(System.String)",
            ["selector.exact"], false),
        ["i.management.IdentityOperations.ListOrganizationIdentities"] = new("SecretKit.Infisical.Management.IdentityOperations.ListOrganizationIdentities(System.String)",
            ["collection.bounded"], false),
        ["i.management.IdentityOperations.ListProjectIdentities"] = new("SecretKit.Infisical.Management.IdentityOperations.ListProjectIdentities(System.String,System.String,System.Int32,System.Int32,System.String)",
            ["search.omitted", "search.value"], false),
        ["i.management.IdentityOperations.UpdateOrganizationIdentity"] = new("SecretKit.Infisical.Management.IdentityOperations.UpdateOrganizationIdentity(System.String,System.String,System.String,System.String,System.Nullable<System.Boolean>,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.Management.IdentityAttribute>)",
            ["name.omitted", "name.value", "role.omitted", "role.value", "deleteProtection.omitted", "deleteProtection.false", "deleteProtection.true", "metadata.omitted", "metadata.value", "metadata.empty", "metadata.values"], true),
        ["i.management.IdentityOperations.UpdateProjectIdentity"] = new("SecretKit.Infisical.Management.IdentityOperations.UpdateProjectIdentity(System.String,System.String,System.String,System.String,System.Nullable<System.Boolean>,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.Management.IdentityAttribute>)",
            ["name.omitted", "name.value", "deleteProtection.omitted", "deleteProtection.false", "deleteProtection.true", "metadata.omitted", "metadata.value", "metadata.empty", "metadata.values"], true),
        ["i.management.IdentitySearchOperations.CountIdentities"] = new("SecretKit.Infisical.Management.IdentitySearchOperations.CountIdentities(System.String,SecretKit.Infisical.Management.IdentitySearchScope,SecretKit.Infisical.Management.IdentitySearchFilter)",
            ["scope.Organization", "scope.Projects", "filter.omitted", "filter.value", "scope.Organization-Projects", "filter.empty", "filter.all", "filter.anyOf.empty", "filter.anyOf.clauses", "name.shorthand", "name.eq", "name.contains", "name.in", "role.shorthand", "role.eq", "role.contains", "role.in"], false),
        ["i.management.IdentitySearchOperations.SearchIdentities"] = new("SecretKit.Infisical.Management.IdentitySearchOperations.SearchIdentities(System.String,SecretKit.Infisical.Management.IdentitySearchScope,SecretKit.Infisical.Management.IdentitySearchFilter,System.Int32,System.Int32,SecretKit.Infisical.Management.IdentitySearchOrder,SecretKit.Infisical.Management.ManagementListOrder)",
            ["scope.Organization", "scope.Projects", "filter.omitted", "filter.value", "order.Name", "order.Role", "order.LastLogin", "direction.Ascending", "direction.Descending", "scope.Organization-Projects", "filter.empty", "filter.all", "filter.anyOf.empty", "filter.anyOf.clauses", "name.shorthand", "name.eq", "name.contains", "name.in", "role.shorthand", "role.eq", "role.contains", "role.in"], false),
        ["i.management.IdentityTemplateOperations.CreateIdentityTemplate"] = new("SecretKit.Infisical.Management.IdentityTemplateOperations.CreateIdentityTemplate(System.String,System.String,SecretKit.Infisical.Management.IdentityTemplateOidcFields)",
            ["IdentityTemplateOidcFields.boundAudiences.omitted", "IdentityTemplateOidcFields.boundAudiences.value", "IdentityTemplateOidcFields.caCertificate.omitted", "IdentityTemplateOidcFields.caCertificate.value"], true),
        ["i.management.IdentityTemplateOperations.CreateKubernetesIdentityTemplate"] = new("SecretKit.Infisical.Management.IdentityTemplateOperations.CreateKubernetesIdentityTemplate(System.String,System.String,SecretKit.Infisical.Management.IdentityTemplateKubernetesFields)",
            ["IdentityTemplateKubernetesFields.tokenReviewMode.Api", "IdentityTemplateKubernetesFields.tokenReviewMode.Gateway", "IdentityTemplateKubernetesFields.tokenReviewMode.omitted", "IdentityTemplateKubernetesFields.kubernetesHost.omitted", "IdentityTemplateKubernetesFields.kubernetesHost.value", "IdentityTemplateKubernetesFields.caCertificate.omitted", "IdentityTemplateKubernetesFields.caCertificate.value", "IdentityTemplateKubernetesFields.verifyTlsCertificate.omitted", "IdentityTemplateKubernetesFields.verifyTlsCertificate.false", "IdentityTemplateKubernetesFields.verifyTlsCertificate.true", "IdentityTemplateKubernetesFields.tokenReviewerJwt.omitted", "IdentityTemplateKubernetesFields.tokenReviewerJwt.value", "IdentityTemplateKubernetesFields.gatewayId.omitted", "IdentityTemplateKubernetesFields.gatewayId.value", "IdentityTemplateKubernetesFields.gatewayPoolId.omitted", "IdentityTemplateKubernetesFields.gatewayPoolId.value", "IdentityTemplateKubernetesFields.allowedAudience.omitted", "IdentityTemplateKubernetesFields.allowedAudience.value"], true),
        ["i.management.IdentityTemplateOperations.CreateLdapIdentityTemplate"] = new("SecretKit.Infisical.Management.IdentityTemplateOperations.CreateLdapIdentityTemplate(System.String,System.String,SecretKit.Infisical.Management.IdentityTemplateLdapFields)",
            ["IdentityTemplateLdapFields.url.omitted", "IdentityTemplateLdapFields.url.value", "IdentityTemplateLdapFields.bindDn.omitted", "IdentityTemplateLdapFields.bindDn.value", "IdentityTemplateLdapFields.bindPassword.omitted", "IdentityTemplateLdapFields.bindPassword.value", "IdentityTemplateLdapFields.searchBase.omitted", "IdentityTemplateLdapFields.searchBase.value", "IdentityTemplateLdapFields.caCertificate.omitted", "IdentityTemplateLdapFields.caCertificate.value"], true),
        ["i.management.IdentityTemplateOperations.DeleteIdentityTemplate"] = new("SecretKit.Infisical.Management.IdentityTemplateOperations.DeleteIdentityTemplate(System.String,System.String)",
            ["response.authMethod.Ldap", "response.authMethod.Kubernetes", "response.authMethod.Oidc"], true),
        ["i.management.IdentityTemplateOperations.DeleteIdentityTemplateUsage"] = new("SecretKit.Infisical.Management.IdentityTemplateOperations.DeleteIdentityTemplateUsage(System.String,System.String,System.String)",
            ["input.organizationId-templateId-identityId"], true),
        ["i.management.IdentityTemplateOperations.DeleteIdentityTemplateUsages"] = new("SecretKit.Infisical.Management.IdentityTemplateOperations.DeleteIdentityTemplateUsages(System.String,System.String,System.Collections.Generic.IReadOnlyList<System.String>)",
            ["input.organizationId-templateId-identityIds"], true),
        ["i.management.IdentityTemplateOperations.GetIdentityTemplate"] = new("SecretKit.Infisical.Management.IdentityTemplateOperations.GetIdentityTemplate(System.String,System.String)",
            ["selector.exact", "response.authMethod.Ldap", "response.authMethod.Kubernetes", "response.authMethod.Oidc"], false),
        ["i.management.IdentityTemplateOperations.GetIdentityTemplateUsage"] = new("SecretKit.Infisical.Management.IdentityTemplateOperations.GetIdentityTemplateUsage(System.String,System.String)",
            ["selector.exact"], false),
        ["i.management.IdentityTemplateOperations.ListIdentityTemplates"] = new("SecretKit.Infisical.Management.IdentityTemplateOperations.ListIdentityTemplates(System.String,SecretKit.Infisical.Management.IdentityTemplateAuthMethod)",
            ["authMethod.Ldap", "authMethod.Kubernetes", "authMethod.Oidc"], false),
        ["i.management.IdentityTemplateOperations.SearchIdentityTemplates"] = new("SecretKit.Infisical.Management.IdentityTemplateOperations.SearchIdentityTemplates(System.String,System.String,System.Int32,System.Int32)",
            ["search.omitted", "search.value", "response.authMethod.Ldap", "response.authMethod.Kubernetes", "response.authMethod.Oidc"], false),
        ["i.management.IdentityTemplateOperations.UpdateIdentityTemplate"] = new("SecretKit.Infisical.Management.IdentityTemplateOperations.UpdateIdentityTemplate(System.String,System.String,System.String)",
            ["name.omitted", "name.value"], true),
        ["i.management.IdentityTemplateOperations.UpdateIdentityTemplateConfiguration"] = new("SecretKit.Infisical.Management.IdentityTemplateOperations.UpdateIdentityTemplateConfiguration(System.String,System.String,SecretKit.Infisical.Management.IdentityTemplateFields,System.String)",
            ["name.omitted", "name.value", "fields.OidcFull", "fields.OidcPatch", "fields.Ldap", "fields.Kubernetes", "IdentityTemplateOidcPatch.discoveryUrl.omitted", "IdentityTemplateOidcPatch.discoveryUrl.value", "IdentityTemplateOidcPatch.boundIssuer.omitted", "IdentityTemplateOidcPatch.boundIssuer.value", "IdentityTemplateOidcPatch.boundAudiences.omitted", "IdentityTemplateOidcPatch.boundAudiences.value", "IdentityTemplateOidcPatch.caCertificate.omitted", "IdentityTemplateOidcPatch.caCertificate.value", "IdentityTemplateLdapFields.url.omitted", "IdentityTemplateLdapFields.url.value", "IdentityTemplateLdapFields.bindDn.omitted", "IdentityTemplateLdapFields.bindDn.value", "IdentityTemplateLdapFields.bindPassword.omitted", "IdentityTemplateLdapFields.bindPassword.value", "IdentityTemplateLdapFields.searchBase.omitted", "IdentityTemplateLdapFields.searchBase.value", "IdentityTemplateLdapFields.caCertificate.omitted", "IdentityTemplateLdapFields.caCertificate.value", "IdentityTemplateKubernetesFields.tokenReviewMode.Api", "IdentityTemplateKubernetesFields.tokenReviewMode.Gateway", "IdentityTemplateKubernetesFields.tokenReviewMode.omitted", "IdentityTemplateKubernetesFields.kubernetesHost.omitted", "IdentityTemplateKubernetesFields.kubernetesHost.value", "IdentityTemplateKubernetesFields.caCertificate.omitted", "IdentityTemplateKubernetesFields.caCertificate.value", "IdentityTemplateKubernetesFields.verifyTlsCertificate.omitted", "IdentityTemplateKubernetesFields.verifyTlsCertificate.false", "IdentityTemplateKubernetesFields.verifyTlsCertificate.true", "IdentityTemplateKubernetesFields.tokenReviewerJwt.omitted", "IdentityTemplateKubernetesFields.tokenReviewerJwt.value", "IdentityTemplateKubernetesFields.gatewayId.omitted", "IdentityTemplateKubernetesFields.gatewayId.value", "IdentityTemplateKubernetesFields.gatewayPoolId.omitted", "IdentityTemplateKubernetesFields.gatewayPoolId.value", "IdentityTemplateKubernetesFields.allowedAudience.omitted", "IdentityTemplateKubernetesFields.allowedAudience.value"], true),
    };

    internal static bool Owns(string operation) => Bindings.ContainsKey(operation);
    internal static bool Valid(NativeCaseDefinition d) => d.Key.Provider == "Infisical" &&
        !string.IsNullOrWhiteSpace(d.Key.Scope) && Bindings.TryGetValue(d.Key.Operation, out var b) &&
        d.Member == b.Member && b.Variants.Contains(d.Key.Variant, StringComparer.Ordinal) &&
        (d.Key.Case is "selected-contract" or "independent-effect" or "denied-authority" or "cancellation-boundary" ||
            b.Mutation && d.Key.Case == "lost-response-no-replay");

    internal static string Family(NativeCaseDefinition d) => d.Key.Operation.Split('.')[2] switch
    {
        "IdentityOperations" => "Identities",
        "IdentitySearchOperations" => "IdentitySearch",
        _ => d.Key.Operation.Split('.')[3] is "CreateKubernetesIdentityTemplate" or "CreateLdapIdentityTemplate" or
            "DeleteIdentityTemplateUsages" or "UpdateIdentityTemplateConfiguration" ? "IdentityTemplateVariants" : "IdentityTemplates"
    };
    internal static string? UnavailableReason(NativeCaseDefinition d) => !Valid(d) ? "contract-mismatch"
        : d.Key.Operation == "i.management.IdentitySearchOperations.SearchIdentities" && d.Key.Variant == "order.LastLogin"
            ? "identity-search-distinct-native-login-witnesses-unestablished"
        : d.Key.Case is "selected-contract" or "independent-effect" or "lost-response-no-replay" &&
            (d.Key.Operation == "i.management.IdentityTemplateOperations.CreateLdapIdentityTemplate" &&
                d.Key.Variant is not ("IdentityTemplateLdapFields.url.omitted" or
                    "IdentityTemplateLdapFields.bindDn.omitted" or "IdentityTemplateLdapFields.bindPassword.omitted" or
                    "IdentityTemplateLdapFields.searchBase.omitted") ||
            d.Key.Operation == "i.management.IdentityTemplateOperations.UpdateIdentityTemplateConfiguration" &&
                d.Key.Variant is "IdentityTemplateLdapFields.bindPassword.value" or "fields.Ldap")
            ? "ldap-bind-password-content-external-witness-unestablished" : null;

    public static void Register(NativeCaseRegistry registry, NativeEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected, ILdapLoginObserver? ldapObserver = null)
    {
        foreach (var d in expected.Where(d => Owns(d.Key.Operation)))
            registry.Add(new(d, (probe, token) => RunAsync(environment, d, probe, ldapObserver, token)));
    }

    private static async ValueTask RunAsync(NativeEnvironment environment, NativeCaseDefinition d,
        NativeCaseProbe probe, ILdapLoginObserver? ldapObserver, CancellationToken token)
    {
        probe.Contract(Valid(d), NativeFailure.ContractMismatch);
        ProjectFamilyContext? context = null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(45));
        try
        {
            context = new(environment, Family(d), d, probe) { LdapObserver = ldapObserver };
            if (context.Input.TryGetProperty("ldapWitness", out var profile))
            {
                if (profile.ValueKind != System.Text.Json.JsonValueKind.Object ||
                    !profile.TryGetProperty("caseTimeoutSeconds", out var timeout) ||
                    timeout.ValueKind != System.Text.Json.JsonValueKind.Number ||
                    !timeout.TryGetInt32(out int seconds) || seconds is < 1 or > 900)
                    throw new NativeCaseFailureException("missing-input");
                deadline.CancelAfter(TimeSpan.FromSeconds(seconds));
            }
            switch (Family(d))
            {
                case "Identities": await IdentitiesEffects.ExecuteAsync(context, deadline.Token); break;
                case "IdentitySearch": await IdentitySearchEffects.ExecuteAsync(context, deadline.Token); break;
                case "IdentityTemplates": await IdentityTemplatesEffects.ExecuteAsync(context, deadline.Token); break;
                default: await IdentityTemplateVariantsEffects.ExecuteAsync(context, deadline.Token); break;
            }
            // Execute feasible operations and metadata/consumer witnesses first. The stored
            // password marker cannot certify which password the external LDAP server accepted.
            if (UnavailableReason(d) is not null && !context.LdapWitnessObserved)
                probe.Effect(NativeObservation.Unavailable);
        }
        catch (NativeCaseFailureException error)
        {
            probe.Contract(false, error.Message switch
            {
                "missing-input" => NativeFailure.MissingInput,
                "missing-prerequisite" => NativeFailure.MissingPrerequisite,
                "observer-unavailable" => NativeFailure.ObserverUnavailable,
                "effect-mismatch" => NativeFailure.EffectMismatch,
                "cleanup-incomplete" => NativeFailure.CleanupIncomplete,
                "contract-mismatch" => NativeFailure.ContractMismatch,
                _ => NativeFailure.UnexpectedFailure
            });
        }
        catch (OperationCanceledException)
        {
            probe.Contract(false, token.IsCancellationRequested ? NativeFailure.UnexpectedCancellation : NativeFailure.DeadlineExceeded);
        }
        catch (Exception error) when (error is ArgumentException or System.Text.Json.JsonException or KeyNotFoundException)
        {
            probe.Contract(false, NativeFailure.MissingInput);
        }
        finally { if (context is not null) await context.CleanupAsync(); }
    }
}
