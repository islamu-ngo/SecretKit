using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class IdentityTemplatesEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, CancellationToken token)
    {
        IdentityTemplateAuthMethod method = IdentityTemplateVariantsEffects.Method(c);
        bool invalidLdapCreate = c.Operation == "CreateLdapIdentityTemplate" &&
            c.Variant is "IdentityTemplateLdapFields.url.omitted" or "IdentityTemplateLdapFields.bindDn.omitted" or
                "IdentityTemplateLdapFields.bindPassword.omitted" or "IdentityTemplateLdapFields.searchBase.omitted";
        if (method == IdentityTemplateAuthMethod.Ldap &&
            (c.Operation == "CreateLdapIdentityTemplate" && !invalidLdapCreate ||
                c.Operation == "UpdateIdentityTemplateConfiguration" &&
                c.Variant is "IdentityTemplateLdapFields.bindPassword.value" or
                    "IdentityTemplateLdapFields.bindPassword.omitted" or "fields.Ldap"))
        {
            var trial = await LdapLoginTrial.CreateAsync(c, token);
            if (trial is not null)
            {
                await PasswordAsync(c, trial, token);
                return;
            }
        }
        string name = ProjectFamilyContext.FreshName();
        string changed = ProjectFamilyContext.FreshName();
        bool create = c.Operation.StartsWith("Create", StringComparison.Ordinal);
        bool update = c.Operation.StartsWith("Update", StringComparison.Ordinal);
        bool unlink = c.Operation is "DeleteIdentityTemplateUsage" or "DeleteIdentityTemplateUsages";
        bool usage = unlink || c.Operation == "GetIdentityTemplateUsage";
        bool delete = c.Operation == "DeleteIdentityTemplate";
        Action<string> acknowledge = Own(c, method, update ? [name, changed] : [name]);
        using TemplateFields selected = IdentityTemplateVariantsEffects.Build(c, method,
            c.Operation == "UpdateIdentityTemplateConfiguration");
        if (create && method == IdentityTemplateAuthMethod.Ldap &&
            c.Variant is "IdentityTemplateLdapFields.url.omitted" or "IdentityTemplateLdapFields.bindDn.omitted" or
                "IdentityTemplateLdapFields.bindPassword.omitted" or "IdentityTemplateLdapFields.searchBase.omitted")
        {
            bool rejected = false;
            try { using var invalid = Create(c, name, selected.Fields); }
            catch (ArgumentException) { rejected = true; }
            c.Probe.Contract(rejected, NativeFailure.ContractMismatch);
            var absent = await c.NeedAsync(() => IdentityTemplateOperations.ListIdentityTemplates(c.OrganizationId,
                method), NativeIdentityRole.Observer, token);
            c.Probe.Effect(absent.IsComplete && absent.Items.All(x => x.Name != name)
                ? NativeObservation.Matched : NativeObservation.Mismatched);
            return;
        }

        string id = "";
        IdentityTemplateSummary? baseline = null;
        string? newName = update && c.Variant != "name.omitted" ? changed : null;
        if (!create)
        {
            using TemplateFields setup = IdentityTemplateVariantsEffects.Build(c, method, false, baseline: true,
                desired: c.Operation == "UpdateIdentityTemplateConfiguration" ? selected : null);
            var prepared = await c.NeedAsync(() => Create(c, name, setup.Fields), NativeIdentityRole.Setup, token);
            id = prepared.Id;
            acknowledge(id);
            baseline = await c.NeedAsync(() => IdentityTemplateOperations.GetIdentityTemplate(c.OrganizationId, id),
                NativeIdentityRole.Observer, token);
            if (c.Operation == "UpdateIdentityTemplateConfiguration")
                foreach (var field in selected.Expected.Where(x => x.Key is not ("stored" or "password-content")))
                {
                    using var single = new TemplateFields(new IdentityTemplateOidcPatch(),
                        new() { [field.Key] = field.Value });
                    c.Probe.Contract(!single.Matches(baseline), NativeFailure.MissingInput);
                }
        }
        var ownedPositives = new List<IdentityTemplateSummary>();
        string? excludedId = null;
        bool collection = c.Operation is "ListIdentityTemplates" or "SearchIdentityTemplates";
        if (collection)
        {
            ownedPositives.Add(baseline!);
            string peerName = name + "-peer";
            Action<string> peerOwnership = Own(c, method, [peerName]);
            using TemplateFields peerFields = IdentityTemplateVariantsEffects.Build(c, method, false, baseline: true);
            var peer = await c.NeedAsync(() => Create(c, peerName, peerFields.Fields), NativeIdentityRole.Setup, token);
            peerOwnership(peer.Id);
            ownedPositives.Add(await c.NeedAsync(() => IdentityTemplateOperations.GetIdentityTemplate(c.OrganizationId,
                peer.Id), NativeIdentityRole.Observer, token));
            string otherName = ProjectFamilyContext.FreshName();
            IdentityTemplateAuthMethod otherMethod = c.Operation == "ListIdentityTemplates"
                ? method == IdentityTemplateAuthMethod.Oidc ? IdentityTemplateAuthMethod.Kubernetes : IdentityTemplateAuthMethod.Oidc
                : method;
            Action<string> otherOwnership = Own(c, otherMethod, [otherName]);
            using TemplateFields otherFields = c.Operation == "ListIdentityTemplates" && otherMethod == IdentityTemplateAuthMethod.Kubernetes
                ? new(new IdentityTemplateKubernetesFields(), [])
                : IdentityTemplateVariantsEffects.Build(c, otherMethod, false, baseline: true);
            var other = await c.NeedAsync(() => Create(c, otherName, otherFields.Fields), NativeIdentityRole.Setup, token);
            otherOwnership(other.Id);
            other = await c.NeedAsync(() => IdentityTemplateOperations.GetIdentityTemplate(c.OrganizationId, other.Id),
                NativeIdentityRole.Observer, token);
            if (c.Operation == "SearchIdentityTemplates" && c.Variant == "search.omitted") ownedPositives.Add(other);
            else excludedId = other.Id;
        }

        bool CollectionMatches(ManagementPage<IdentityTemplateSummary> page) => page.IsComplete &&
            page.Items.Select(x => x.Id).Distinct(StringComparer.Ordinal).Count() == page.Items.Count &&
            (excludedId is null || page.Items.All(x => x.Id != excludedId)) &&
            ownedPositives.All(expected => page.Items.Count(x => x.Id == expected.Id &&
                x.Name == expected.Name && x.AuthMethod == expected.AuthMethod && Preserved(expected, x, [])) == 1);
        string[] identities = [];
        if (usage)
        {
            // Set up two independently owned usages so single unlink cannot silently unlink both.
            identities = new string[2];
            for (int i = 0; i < identities.Length; i++)
            {
                var identity = await IdentitiesEffects.PrepareOrganizationAsync(c, ProjectFamilyContext.FreshName(), token);
                identities[i] = identity.Id;
                await AttachAsync(c, method, id, identity.Id, token);
            }
        }

        async ValueTask<bool> Observe(bool applied, CancellationToken t)
        {
            if (create)
            {
                var list = await c.NeedAsync(() => IdentityTemplateOperations.ListIdentityTemplates(c.OrganizationId,
                    method), NativeIdentityRole.Observer, t);
                if (!list.IsComplete) throw new NativeCaseFailureException("observer-unavailable");
                var found = list.Items.Where(x => x.Name == name).ToArray();
                if (!applied) return found.Length == 0;
                if (found.Length != 1) return false;
                if (id.Length != 0 && id != found[0].Id) return false;
                id = found[0].Id;
            }
            var read = await c.ExecuteAsync(() => IdentityTemplateOperations.GetIdentityTemplate(c.OrganizationId, id),
                NativeIdentityRole.Observer, t);
            if (delete && applied) return read.Status == SecretStatus.Absent;
            if (!read.IsSuccess || read.Value.AuthMethod != method ||
                read.Value.Name != (applied && update ? newName ?? name : name)) return false;
            if (collection)
                foreach (var positive in ownedPositives)
                {
                    var positiveRead = await c.NeedAsync(() => IdentityTemplateOperations.GetIdentityTemplate(
                        c.OrganizationId, positive.Id), NativeIdentityRole.Observer, t);
                    if (positiveRead.Name != positive.Name || positiveRead.AuthMethod != positive.AuthMethod ||
                        !Preserved(positive, positiveRead, [])) return false;
                }
            if (applied && (create || c.Operation == "UpdateIdentityTemplateConfiguration") &&
                !selected.Matches(read.Value)) return false;
            if (baseline is not null)
            {
                // Independently read every unchanged projected field, not just the patched ones.
                if (!Preserved(baseline, read.Value, applied && c.Operation == "UpdateIdentityTemplateConfiguration"
                    ? selected.Expected.Keys : [])) return false;
            }
            if (usage)
            {
                string[] removed = unlink && applied
                    ? c.Operation == "DeleteIdentityTemplateUsage" ? [identities[0]] : identities : [];
                var usages = await c.NeedAsync(() => IdentityTemplateOperations.GetIdentityTemplateUsage(
                    c.OrganizationId, id), NativeIdentityRole.Observer, t);
                if (!usages.IsComplete || !usages.Items.Select(x => x.IdentityId).Order()
                    .SequenceEqual(identities.Except(removed).Order())) return false;
                foreach (string identity in identities)
                    if (!await AcceptedAsync(c, method, id, identity, !removed.Contains(identity), t)) return false;
                return true;
            }
            if (applied && (create || update))
            {
                if (selected.HasUnavailableContents) throw new NativeCaseFailureException("observer-unavailable");
                // Consumer acceptance is a separate attachment and observer GET on a fresh identity.
                // It proves template consumption, not external issuer authentication or permission.
                var consumer = await IdentitiesEffects.PrepareOrganizationAsync(c, ProjectFamilyContext.FreshName(), t);
                await AttachAsync(c, method, id, consumer.Id, t);
                return await AcceptedAsync(c, method, id, consumer.Id, true, t,
                    method == IdentityTemplateAuthMethod.Kubernetes && selected.Expected.ContainsKey("stored"));
            }
            return true;
        }

        bool Match(IdentityTemplateSummary value)
        {
            if (!create) return value.Id == id;
            acknowledge(value.Id);
            id = value.Id;
            return value.Name == name && value.AuthMethod == method;
        }
        if (create)
            await c.CaseAsync(() => Create(c, name, selected.Fields), Match, Observe, token);
        else if (c.Operation == "UpdateIdentityTemplateConfiguration")
            await c.CaseAsync(() => IdentityTemplateOperations.UpdateIdentityTemplateConfiguration(
                c.OrganizationId, id, selected.Fields, newName), Match, Observe, token);
        else if (update)
            await c.CaseAsync(() => IdentityTemplateOperations.UpdateIdentityTemplate(c.OrganizationId, id, newName),
                Match, Observe, token);
        else if (delete)
            await c.CaseAsync(() => IdentityTemplateOperations.DeleteIdentityTemplate(c.OrganizationId, id),
                _ => true, Observe, token);
        else if (unlink)
            await c.CaseAsync(() => c.Operation == "DeleteIdentityTemplateUsage"
                ? IdentityTemplateOperations.DeleteIdentityTemplateUsage(c.OrganizationId, id, identities[0])
                : IdentityTemplateOperations.DeleteIdentityTemplateUsages(c.OrganizationId, id, identities),
                page => page.IsComplete && page.Items.Select(x => x.IdentityId).Order().SequenceEqual(
                    (c.Operation == "DeleteIdentityTemplateUsage" ? [identities[0]] : identities).Order()),
                Observe, token);
        else if (usage)
            await c.CaseAsync(() => IdentityTemplateOperations.GetIdentityTemplateUsage(c.OrganizationId, id),
                page => page.IsComplete && page.Items.Select(x => x.IdentityId).Order().SequenceEqual(identities.Order()),
                Observe, token);
        else if (c.Operation is "ListIdentityTemplates" or "SearchIdentityTemplates")
            await c.CaseAsync(() => c.Operation == "ListIdentityTemplates"
                ? IdentityTemplateOperations.ListIdentityTemplates(c.OrganizationId, method)
                : IdentityTemplateOperations.SearchIdentityTemplates(c.OrganizationId,
                    c.Variant == "search.omitted" ? null : name, limit: 100),
                CollectionMatches,
                Observe, token);
        else
            await c.CaseAsync(() => IdentityTemplateOperations.GetIdentityTemplate(c.OrganizationId, id),
                value => Match(value) && value.Name == name && value.AuthMethod == method, Observe, token);
    }

    private static async ValueTask PasswordAsync(ProjectFamilyContext c, LdapLoginTrial trial,
        CancellationToken token)
    {
        bool create = c.Operation == "CreateLdapIdentityTemplate";
        bool omit = c.Variant == "IdentityTemplateLdapFields.bindPassword.omitted";
        bool selectedMutation = c.Definition.Key.Case is "selected-contract" or "independent-effect" or "lost-response-no-replay";
        bool changeCredential = !omit && selectedMutation;
        string name = ProjectFamilyContext.FreshName(), changed = ProjectFamilyContext.FreshName();
        Action<string> acknowledge = Own(c, IdentityTemplateAuthMethod.Ldap, [name, changed]);
        using TemplateFields selected = IdentityTemplateVariantsEffects.Build(c, IdentityTemplateAuthMethod.Ldap, !create);
        string id = "";
        string? linked = null;
        string? controlTemplate = null, controlIdentity = null;
        IdentityTemplateSummary? baseline = null;
        LdapServiceCredential accepted = changeCredential ? LdapServiceCredential.Rotated : LdapServiceCredential.Original;
        if (create && !selectedMutation)
        {
            controlTemplate = await trial.CreateTemplateAsync(ProjectFamilyContext.FreshName(),
                LdapServiceCredential.Original, token);
            controlIdentity = (await IdentitiesEffects.PrepareOrganizationAsync(c,
                ProjectFamilyContext.FreshName(), token)).Id;
            await trial.GrantCanaryAsync(controlIdentity, token);
            await trial.AttachAsync(controlTemplate, controlIdentity, token);
            await trial.LoginAsync(controlIdentity, controlTemplate, LdapServiceCredential.Original, false, true, token);
            await trial.LoginAsync(controlIdentity, controlTemplate, LdapServiceCredential.Original, true, false, token);
        }
        if (!create)
        {
            using var oldPassword = SecretMaterial.FromText(c.Required("originalBindPassword"));
            using var setup = new IdentityTemplateLdapFields(trial.Directory.Attempt.Url,
                trial.Directory.Attempt.BindDn, oldPassword, trial.Directory.Attempt.SearchBase,
                c.Optional("ldapCaCertificate"));
            var prepared = await c.NeedAsync(() => Create(c, name, setup), NativeIdentityRole.Setup, token);
            id = prepared.Id;
            acknowledge(id);
            baseline = await c.NeedAsync(() => IdentityTemplateOperations.GetIdentityTemplate(c.OrganizationId, id),
                NativeIdentityRole.Observer, token);
            linked = (await IdentitiesEffects.PrepareOrganizationAsync(c, ProjectFamilyContext.FreshName(), token)).Id;
            await trial.GrantCanaryAsync(linked, token);
            await trial.AttachAsync(id, linked, token);
            try
            {
                await trial.LoginAsync(linked, id, LdapServiceCredential.Original, false, true, token);
                await trial.LoginAsync(linked, id, LdapServiceCredential.Original, true, false, token);
            }
            catch (NativeCaseFailureException)
            {
                // Even a failed prerequisite has a source-fenced non-dispatch.
                // Never send the selected mutation after a failed login control.
                var notSent = await trial.ArmTemplateAsync(name, id, omit ? null : accepted, token);
                await trial.CompleteTemplateAsync(notSent, DispatchEvidence.NotDispatched, token);
                throw;
            }
        }
        if (changeCredential)
        {
            await trial.RotateAsync(token);
            if (linked is not null)
                await trial.LoginAsync(linked, id, LdapServiceCredential.Original, false, false, token);
        }
        var arm = await trial.ArmTemplateAsync(name, create ? null : id,
            omit ? null : LdapServiceCredential.Rotated, token);
        async ValueTask<bool> Observe(bool applied, CancellationToken ct)
        {
            if (create)
            {
                var page = await c.NeedAsync(() => IdentityTemplateOperations.ListIdentityTemplates(
                    c.OrganizationId, IdentityTemplateAuthMethod.Ldap), NativeIdentityRole.Observer, ct);
                if (!page.IsComplete) throw new NativeCaseFailureException("effect-mismatch");
                var owned = page.Items.Where(x => x.Name == name).ToArray();
                if (!applied)
                {
                    if (owned.Length != 0) return false;
                    await trial.LoginAsync(controlIdentity!, controlTemplate!, LdapServiceCredential.Original,
                        false, true, ct);
                    await trial.LoginAsync(controlIdentity!, controlTemplate!, LdapServiceCredential.Original,
                        true, false, ct);
                    await trial.SealAsync(ct);
                    c.LdapWitnessObserved = true;
                    return true;
                }
                if (owned.Length != 1 || id.Length != 0 && id != owned[0].Id) return false;
                id = owned[0].Id;
                acknowledge(id);
            }
            var read = await c.NeedAsync(() => IdentityTemplateOperations.GetIdentityTemplate(c.OrganizationId, id),
                NativeIdentityRole.Observer, ct);
            if (read.Name != (applied && !create ? changed : name) ||
                read.AuthMethod != IdentityTemplateAuthMethod.Ldap ||
                applied && !selected.Matches(read) ||
                baseline is not null && !Preserved(baseline, read, applied ? selected.Expected.Keys : []))
                return false;
            if (linked is not null)
            {
                await trial.LoginAsync(linked, id, applied ? accepted : LdapServiceCredential.Original,
                    false, true, ct);
                await trial.LoginAsync(linked, id, applied ? accepted : LdapServiceCredential.Original,
                    true, false, ct);
            }
            for (int index = 0; index < (create ? 2 : 1); index++)
            {
                var fresh = await IdentitiesEffects.PrepareOrganizationAsync(c, ProjectFamilyContext.FreshName(), ct);
                await trial.GrantCanaryAsync(fresh.Id, ct);
                await trial.AttachAsync(id, fresh.Id, ct);
                await trial.LoginAsync(fresh.Id, id, applied ? accepted : LdapServiceCredential.Original,
                    false, true, ct);
                await trial.LoginAsync(fresh.Id, id, applied ? accepted : LdapServiceCredential.Original,
                    true, false, ct);
            }
            await trial.SealAsync(ct);
            c.LdapWitnessObserved = true;
            return true;
        }
        bool Match(IdentityTemplateSummary result)
        {
            if (!create) return result.Id == id;
            id = result.Id;
            acknowledge(id);
            return result.Name == name && result.AuthMethod == IdentityTemplateAuthMethod.Ldap;
        }
        if (create)
            await c.CaseAsync(() => Create(c, name, selected.Fields), Match, Observe, token,
                (receipt, ct) => trial.CompleteTemplateAsync(arm, receipt, ct));
        else
            await c.CaseAsync(() => IdentityTemplateOperations.UpdateIdentityTemplateConfiguration(
                c.OrganizationId, id, selected.Fields, changed), Match, Observe, token,
                (receipt, ct) => trial.CompleteTemplateAsync(arm, receipt, ct));
    }

    internal static ManagementRequest<IdentityTemplateSummary> Create(ProjectFamilyContext c, string name,
        IdentityTemplateFields fields) => fields switch
        {
            IdentityTemplateOidcFields oidc => IdentityTemplateOperations.CreateIdentityTemplate(c.OrganizationId, name, oidc),
            IdentityTemplateLdapFields ldap => IdentityTemplateOperations.CreateLdapIdentityTemplate(c.OrganizationId, name, ldap),
            IdentityTemplateKubernetesFields kubernetes => IdentityTemplateOperations.CreateKubernetesIdentityTemplate(c.OrganizationId, name, kubernetes),
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };

    internal static Action<string> Own(ProjectFamilyContext c, IdentityTemplateAuthMethod method, string[] names)
    {
        string? acknowledgedId = null;
        c.Cleanup(async token =>
        {
            var list = await c.ExecuteAsync(() => IdentityTemplateOperations.ListIdentityTemplates(c.OrganizationId, method),
                NativeIdentityRole.Observer, token);
            if (!list.IsSuccess || !list.Value.IsComplete) return false;
            var owned = list.Value.Items.Where(x => names.Contains(x.Name)).ToArray();
            if (owned.Length > 1) return false;
            if (acknowledgedId is not null && owned.Any(x => x.Id != acknowledgedId)) return false;
            if (acknowledgedId is not null && owned.Length == 0)
            {
                var missing = await c.ExecuteAsync(() => IdentityTemplateOperations.GetIdentityTemplate(
                    c.OrganizationId, acknowledgedId), NativeIdentityRole.Observer, token);
                return missing.Status == SecretStatus.Absent;
            }
            foreach (var template in owned)
            {
                var usages = await c.ExecuteAsync(() => IdentityTemplateOperations.GetIdentityTemplateUsage(
                    c.OrganizationId, template.Id), NativeIdentityRole.Observer, token);
                if (!usages.IsSuccess || !usages.Value.IsComplete || usages.Value.Items.Count != 0) return false;
                var deleted = await c.ExecuteAsync(() => IdentityTemplateOperations.DeleteIdentityTemplate(c.OrganizationId,
                    template.Id), NativeIdentityRole.Setup, token);
                var absent = await c.ExecuteAsync(() => IdentityTemplateOperations.GetIdentityTemplate(c.OrganizationId,
                    template.Id), NativeIdentityRole.Observer, token);
                if (!deleted.IsSuccess || absent.Status != SecretStatus.Absent) return false;
            }
            var observed = await c.ExecuteAsync(() => IdentityTemplateOperations.ListIdentityTemplates(c.OrganizationId, method),
                NativeIdentityRole.Observer, token);
            return observed.IsSuccess && observed.Value.IsComplete && observed.Value.Items.All(x => !names.Contains(x.Name));
        });
        return id => acknowledgedId = id;
    }

    internal static async ValueTask AttachAsync(ProjectFamilyContext c, IdentityTemplateAuthMethod method,
        string template, string identity, CancellationToken token)
    {
        if (method == IdentityTemplateAuthMethod.Oidc)
            await c.NeedAsync(() => WorkloadIdentityAuthenticationOperations.AttachOidcAuth(c.OrganizationId, identity,
                new(boundClaims: new Dictionary<string, string> { ["sub"] = c.Required("boundSubject") },
                    templateId: WorkloadAuthNullableText.FromValue(template))), NativeIdentityRole.Setup, token);
        else if (method == IdentityTemplateAuthMethod.Kubernetes)
        {
            using var input = new KubernetesAuthConfigurationInput(c.Required("allowedNames"), c.Required("allowedNamespaces"),
                templateId: WorkloadAuthNullableText.FromValue(template));
            using var result = await c.NeedAsync(() => WorkloadIdentityAuthenticationOperations.AttachKubernetesAuth(
                c.OrganizationId, identity, input), NativeIdentityRole.Setup, token);
        }
        else
        {
            using var input = LdapAuthConfigurationInput.FromTemplate(template);
            using var result = await c.NeedAsync(() => ExternalIdentityAuthenticationOperations.AttachLdapAuth(
                c.OrganizationId, identity, input), NativeIdentityRole.Setup, token);
        }
    }

    private static async ValueTask<bool> AcceptedAsync(ProjectFamilyContext c, IdentityTemplateAuthMethod method,
        string template, string identity, bool expected, CancellationToken token, bool verifyReviewer = false)
    {
        IdentityTemplateConfigurationSummary settings = (await c.NeedAsync(
            () => IdentityTemplateOperations.GetIdentityTemplate(c.OrganizationId, template),
            NativeIdentityRole.Observer, token)).Configuration;
        if (method == IdentityTemplateAuthMethod.Oidc)
        {
            var result = await c.ExecuteAsync(() => WorkloadIdentityAuthenticationOperations.GetOidcAuth(
                c.OrganizationId, identity), NativeIdentityRole.Observer, token);
            if (expected && result.IsSuccess && (result.Value.OidcDiscoveryUrl != settings.OidcDiscoveryUrl ||
                result.Value.BoundIssuer != settings.BoundIssuer ||
                settings.BoundAudiences is not null && result.Value.BoundAudiences != settings.BoundAudiences ||
                settings.CaCertificate is not null && result.Value.CaCert != settings.CaCertificate)) return false;
            return !expected && result.Status == SecretStatus.Absent || result.IsSuccess &&
                (result.Value.TemplateId.IsPresent && !result.Value.TemplateId.IsNull &&
                    result.Value.TemplateId.Value == template) == expected;
        }
        if (method == IdentityTemplateAuthMethod.Kubernetes)
        {
            var result = await c.ExecuteAsync(() => WorkloadIdentityAuthenticationOperations.GetKubernetesAuth(
                c.OrganizationId, identity), NativeIdentityRole.Observer, token);
            if (!result.IsSuccess) return !expected && result.Status == SecretStatus.Absent;
            using var owned = result.Value;
            if (expected && (settings.AllowedAudience is not null && owned.AllowedAudience != settings.AllowedAudience ||
                settings.TokenReviewMode is not null && owned.TokenReviewMode != settings.TokenReviewMode ||
                settings.VerifyTlsCertificate is not null && owned.VerifyTlsCertificate != settings.VerifyTlsCertificate ||
                settings.CaCertificate is not null && owned.CaCert != settings.CaCertificate ||
                settings.HasKubernetesHost && (!owned.KubernetesHost.IsPresent ||
                    (owned.KubernetesHost.IsNull ? null : owned.KubernetesHost.Value) != settings.KubernetesHost) ||
                settings.HasGatewayId && (!owned.GatewayId.IsPresent ||
                    (owned.GatewayId.IsNull ? null : owned.GatewayId.Value) != settings.GatewayId) ||
                settings.HasGatewayPoolId && (!owned.GatewayPoolId.IsPresent ||
                    (owned.GatewayPoolId.IsNull ? null : owned.GatewayPoolId.Value) != settings.GatewayPoolId))) return false;
            if (expected && verifyReviewer)
            {
                if (!owned.TokenReviewerJwt.IsPresent || owned.TokenReviewerJwt.IsNull)
                    throw new NativeCaseFailureException("observer-unavailable");
                if (owned.TokenReviewerJwt.Value.Reveal() != c.Required("tokenReviewerJwt")) return false;
            }
            return (owned.TemplateId.IsPresent && !owned.TemplateId.IsNull && owned.TemplateId.Value == template) == expected;
        }
        var ldap = await c.ExecuteAsync(() => ExternalIdentityAuthenticationOperations.GetLdapAuth(
            c.OrganizationId, identity), NativeIdentityRole.Observer, token);
        if (!ldap.IsSuccess) return !expected && ldap.Status == SecretStatus.Absent;
        using var configuration = ldap.Value;
        if (expected && (settings.Url is not null && configuration.Url != settings.Url ||
            settings.BindDn is not null && configuration.BindDN != settings.BindDn ||
            settings.SearchBase is not null && configuration.SearchBase != settings.SearchBase ||
            settings.LdapCaCertificate is not null &&
                configuration.LdapCaCertificate?.Reveal() != settings.LdapCaCertificate)) return false;
        return (configuration.TemplateId.IsPresent && !configuration.TemplateId.IsNull &&
            configuration.TemplateId.Value == template) == expected;
    }

    private static bool Preserved(IdentityTemplateSummary before, IdentityTemplateSummary after,
        IEnumerable<string> changed)
    {
        var a = before.Configuration;
        var b = after.Configuration;
        Dictionary<string, object?> prior = new()
        {
            ["discovery"] = a.OidcDiscoveryUrl,
            ["issuer"] = a.BoundIssuer,
            ["audiences"] = a.BoundAudiences,
            ["ca"] = a.CaCertificate,
            ["url"] = a.Url,
            ["dn"] = a.BindDn,
            ["base"] = a.SearchBase,
            ["ldapCa"] = a.LdapCaCertificate,
            ["stored"] = before.HasStoredCredential,
            ["mode"] = a.TokenReviewMode,
            ["host"] = a.KubernetesHost,
            ["gateway"] = a.GatewayId,
            ["pool"] = a.GatewayPoolId,
            ["audience"] = a.AllowedAudience,
            ["tls"] = a.VerifyTlsCertificate
        };
        string[] changedFields = changed.ToArray();
        foreach (string key in changedFields) prior.Remove(key);
        using var expectation = new TemplateFields(new IdentityTemplateOidcPatch(), prior);
        return expectation.Matches(after) && (changedFields.Contains("host") || a.HasKubernetesHost == b.HasKubernetesHost) &&
            (changedFields.Contains("gateway") || a.HasGatewayId == b.HasGatewayId) &&
            (changedFields.Contains("pool") || a.HasGatewayPoolId == b.HasGatewayPoolId);
    }
}
