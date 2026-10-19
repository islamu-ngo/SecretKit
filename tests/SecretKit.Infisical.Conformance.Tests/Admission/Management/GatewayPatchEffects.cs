using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class GatewayPatchEffects
{
    internal const string Operation = "i.management.GatewayAdministrationOperations.Update";
    internal static bool RetainsAuthentication(string variant) => variant is
        "patch.empty" or "authentication.omitted" or "response.auth.Identity";
    internal static bool Renames(string variant) => variant is "name.value" or "authentication.omitted" or "patch.persistence-unestablished";

    internal static GatewayPatchAuthenticationInput Select(string v, GatewayPatchAuthenticationInput selected)
    {
        GatewayAuthenticationMethod method = v switch
        {
            "auth.Token" or "response.auth.Token" => GatewayAuthenticationMethod.Token,
            "response.auth.Identity" => GatewayAuthenticationMethod.Identity,
            _ when v.Contains("Aws", StringComparison.Ordinal) => GatewayAuthenticationMethod.Aws,
            _ when v.Contains("Gcp", StringComparison.Ordinal) => GatewayAuthenticationMethod.Gcp,
            _ => selected.Method
        };
        string? Field(string field, string? value) => v.EndsWith("." + field + ".omitted", StringComparison.Ordinal) ?
            null : v.EndsWith("." + field + ".empty", StringComparison.Ordinal) ? "" : value;
        return selected with
        {
            Method = method,
            AllowedAccountIds = Field("allowedAccountIds", selected.AllowedAccountIds),
            AllowedPrincipalArns = Field("allowedPrincipalArns", selected.AllowedPrincipalArns),
            AllowedProjects = Field("allowedProjects", selected.AllowedProjects),
            AllowedServiceAccounts = Field("allowedServiceAccounts", selected.AllowedServiceAccounts),
            AllowedZones = Field("allowedZones", selected.AllowedZones),
            GcpType = v == "auth.Gcp.type-omitted" ? null : v == "auth.Gcp.Gce" ? GatewayGcpType.Gce :
                v == "auth.Gcp.Iam" ? GatewayGcpType.Iam : selected.GcpType,
            TokenReviewMode = v == "auth.Kubernetes.review-omitted" ? null :
                v == "auth.Kubernetes.Api" ? GatewayTokenReviewMode.Api :
                v == "auth.Kubernetes.Gateway" ? GatewayTokenReviewMode.Gateway : selected.TokenReviewMode,
            VerifyTlsCertificate = v == "verifyTlsCertificate.omitted" ? null :
                v == "verifyTlsCertificate.false" ? false : v == "verifyTlsCertificate.true" ? true : selected.VerifyTlsCertificate,
            GatewayId = v is "gatewayId.omitted" or "gatewayId.null" ? null : selected.GatewayId,
            ClearGatewayId = v == "gatewayId.null",
            GatewayPoolId = v is "gatewayPoolId.omitted" or "gatewayPoolId.null" ? null : selected.GatewayPoolId,
            ClearGatewayPoolId = v == "gatewayPoolId.null",
            TokenReviewerJwt = Field("tokenReviewerJwt", selected.TokenReviewerJwt),
            KubernetesHost = Field("kubernetesHost", selected.KubernetesHost),
            CaCertificate = Field("caCertificate", selected.CaCertificate)
        };
    }

    // Parent routes only a validated original Update key with a witness profile.
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, IGatewayAgentObserver backend,
        IGatewayPatchObserver? injected, CancellationToken token)
    {
        c.Probe.Contract(c.Definition.Key.Operation == Operation &&
            c.Definition.Member == InfisicalGovernanceFamilies.Bindings[Operation].Member &&
            InfisicalGovernanceFamilies.Bindings[Operation].Variants.Contains(c.Variant),
            NativeFailure.ContractMismatch);
        if (!c.Input.TryGetProperty("gatewayPatchWitness", out var input))
            throw new NativeCaseFailureException("missing-input");
        GatewayPatchWitnessInput settings;
        try { settings = input.Deserialize<GatewayPatchWitnessInput>(InfisicalLifecycleFamilies.Options)!; }
        catch (JsonException) { throw new NativeCaseFailureException("missing-input"); }
        if (settings is null || settings.Baseline is null || settings.Selected is null ||
            (injected is not null && settings.SourceProfile != "controlled-fixture") ||
            (settings.SourceProfile == "controlled-fixture" && injected is null))
            throw new NativeCaseFailureException("missing-input");
        var source = injected ?? InfisicalGatewayPatchObserver.FromInputs(c.Environment) ??
            throw new NativeCaseFailureException("observer-unavailable");
        string name = ProjectFamilyContext.FreshName(), renamed = ProjectFamilyContext.FreshName();
        GatewayPatchTrial? retained = null;
        // First cleanup registered, last run; even project bootstrap failure closes
        // an already opened root. The original trial is retained before Open.
        c.Cleanup(async _ => { if (retained is not null) await retained.DisposeAsync(); return true; });
        var selected = Select(c.Variant, settings.Selected);
        var root = new GatewayPatchRootAttempt(Guid.NewGuid().ToString("D"),
            Operation + "/" + c.Variant + "/" + c.Definition.Key.Case, "v0.166.3",
            settings.DeploymentId, settings.SourceProfile, settings.RootNonce, c.OrganizationId, name, renamed,
            settings.SourceProfile == "controlled-fixture" ? GatewayPatchSource.ControlledFixture : GatewayPatchSource.NativeProvider);
        var trial = await GatewayPatchTrial.OpenAsync(source, root, settings.Baseline, selected,
            settings.CaseTimeoutSeconds, opened => retained = opened, token);
        await c.EnsureProjectAsync(token);
        string? id = null;
        foreach (string owned in new[] { name, renamed })
            c.Cleanup(async ct =>
            {
                // A malformed or nonterminal fence must not authorize deletion
                // while the original PATCH could still apply.
                if (!trial.CleanupSafe) return false;
                var found = await backend.FindOwnedAsync(c.OrganizationId, owned,
                    c.Environment.Tokens(NativeIdentityRole.Observer), ct);
                if (found.Status == SecretStatus.Absent) return true;
                if (!found.IsSuccess || id is not null && found.Value.Id != id) return false;
                var removed = await backend.RemoveOwnedAsync(c.OrganizationId, owned,
                    c.Environment.Tokens(NativeIdentityRole.Setup), ct);
                var absent = await backend.FindOwnedAsync(c.OrganizationId, owned,
                    c.Environment.Tokens(NativeIdentityRole.Observer), ct);
                return removed is SecretStatus.Success or SecretStatus.Absent && absent.Status == SecretStatus.Absent;
            });
        GatewaySummary original;
        if (settings.Baseline.Method == GatewayAuthenticationMethod.Identity)
        {
            var found = await backend.FindOwnedAsync(c.OrganizationId, name,
                c.Environment.Tokens(NativeIdentityRole.Observer), token);
            if (!found.IsSuccess || found.Value.Authentication.Method != GatewayAuthenticationMethod.Identity)
                throw new NativeCaseFailureException("missing-prerequisite");
            original = found.Value;
        }
        else
        {
            using var authentication = settings.Baseline.Create();
            await trial.ArmAsync("Create", "seed", "selected-contract", null, token);
            trial.Dispatching();
            original = await c.NeedAsync(() => GatewayAdministrationOperations.Create(c.OrganizationId,
                new(name, authentication)), NativeIdentityRole.Setup, token);
            id = original.Id;
            await trial.CompleteAsync(DispatchEvidence.Applied, token);
            await trial.ObserveAsync(token);
        }
        id = original.Id;
        using var changed = RetainsAuthentication(c.Variant) ? null : selected.Create();
        var update = new GatewayUpdate(Renames(c.Variant) ? renamed : null, changed);
        await trial.ArmAsync("Update", c.Variant, c.Definition.Key.Case, id, token);
        trial.Dispatching();
        await c.CaseAsync(() => GatewayAdministrationOperations.Update(c.OrganizationId, id, update),
            result => result.Id == id, async (_, ct) =>
            {
                var fence = trial.Fence!;
                var current = await c.NeedAsync(() => GatewayAdministrationOperations.Get(c.OrganizationId, id),
                    NativeIdentityRole.Observer, ct);
                if (current.Name != (fence.NameApplied && Renames(c.Variant) ? renamed : name)) return false;
                await trial.ObserveAsync(ct);
                return true;
            }, token, complete: trial.CompleteAsync);
    }
}
