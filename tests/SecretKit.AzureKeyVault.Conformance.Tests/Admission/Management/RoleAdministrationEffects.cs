using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal static class RoleAdministrationEffects
{
    private const string Prefix = "a.management.VaultAdministration.";
    private const string Type = "SecretKit.AzureKeyVault.Management.";
    internal static readonly ManagementMember[] Members =
    [
        Member("CreateRoleAssignmentAsync", Type + "RoleAssignmentScope," + Type +
            "RoleDefinitionScope,System.Guid," + Type + "ManagementReceipt", ["scope.vault"], true),
        Member("DeleteRoleAssignmentAsync", Type + "RoleAssignmentScope," + Type + "ManagementReceipt", ["scope.vault"], true),
        Member("GetRoleAssignmentAsync", Type + "RoleAssignmentScope",
            ["selector.exact", "scope.vault", "scope.resource-group", "scope.subscription"]),
        Member("GetRoleDefinitionAsync", Type + "RoleDefinitionScope", ["selector.exact"]),
        Member("ListRoleAssignmentsAsync", Type + "VaultScope," + Type + "CollectionLimits",
            ["collection.bounded", "scope.vault", "scope.resource-group", "scope.subscription"]),
        Member("ListRoleDefinitionsAsync", Type + "SubscriptionScope," + Type + "CollectionLimits", ["collection.bounded"])
    ];
    private static ManagementMember Member(string name, string arguments, string[] variants, bool mutation = false) =>
        new(Prefix + name, Type + "VaultAdministration." + name + "(" + arguments + ",System.Threading.CancellationToken)",
            variants, mutation);
    internal sealed record Input(ObserverEndpoint Observer, ManagementIdentities Arm, Guid SubscriptionId,
        string ResourceGroup, string Location, Guid TenantId, Guid RoleDefinitionId, Guid IntendedPrincipalId,
        int MaximumPages, int MaximumItems, TimeSpan Timeout)
    {
        public override string ToString() => "[RoleInput]";
    }
    internal sealed record Prepare(FixtureSelector Selection, Guid SubscriptionId, string ResourceGroup,
        string Location, Guid TenantId, Guid RoleDefinitionId, Guid IntendedPrincipalId)
    {
        public override string ToString() => "[RolePrepare]";
    }
    internal sealed record Lease(LeaseFacts Facts, string VaultName, Guid AssignmentId, string RuntimeSecretName,
        string RuntimeSecretVersion, string RuntimeSecretSha256, SecretStatus BaselineRuntimeStatus,
        Guid? BorrowedGroupAssignmentId = null, Guid? BorrowedSubscriptionAssignmentId = null)
    {
        public override string ToString() => "[RoleLease]";
    }
    internal sealed record Permission(string[] Actions, string[] NotActions, string[] DataActions, string[] NotDataActions);
    internal sealed record Definition(Guid Id, string? Name, string? Description, string? RoleType,
        string[] AssignableScopes, Permission[] Permissions)
    {
        public override string ToString() => "[RoleDefinitionMeasurement]";
    }
    internal sealed record Assignment(Guid Id, string ParentResourceId, Guid DefinitionId, Guid PrincipalId,
        string? PrincipalType, string? Description, string? Condition, string? ConditionVersion)
    {
        public override string ToString() => "[RoleAssignmentMeasurement]";
    }
    internal sealed record ReadObservation([property: JsonRequired] SecretStatus Status, string? Sha256,
        string NativeRequestId, [property: JsonRequired] bool Complete)
    {
        public override string ToString() => "[RoleReadObservation]";
    }
    internal sealed record Coordinates(string VaultResourceId, string TargetParentResourceId, Guid AssignmentId,
        Guid DefinitionId, string SecretName, string SecretVersion)
    {
        public override string ToString() => "[RoleObservationCoordinates]";
    }
    internal sealed record Measurement(Guid LeaseId, Guid Nonce, FixtureSelector Selector, string ObserverIdentity,
        DateTimeOffset StartedAt, DateTimeOffset ObservedAt, Guid SubscriptionId, long Sequence,
        [property: JsonRequired] RoleAdministrationCollector.Phase Phase, Coordinates Coordinates,
        Assignment[] Assignments, Definition[] Definitions, ReadObservation Intended,
        ReadObservation Denied, ReadObservation Observer, bool? TargetPresent = null,
        bool? AssignmentsComplete = null, bool? DefinitionsComplete = null)
    {
        public override string ToString() => "[RoleMeasurement]";
    }
    internal sealed record Result(SecretStatus Status, ManagementOperation? Operation = null,
        RoleAssignmentObservation? Assignment = null, RoleDefinitionObservation? Definition = null,
        ManagementInventory<RoleAssignmentObservation>? Assignments = null,
        ManagementInventory<RoleDefinitionObservation>? Definitions = null);

    internal static void ValidateMutation(string operation, bool denied, RoleAssignmentScope scope,
        Guid principalId, Guid definitionId, Assignment[]? baseline, Assignment[] observed)
    {
        ValidateBaseline(operation, scope, principalId, definitionId, baseline);
        ValidateAssignments(observed);
        if (denied)
        {
            ManagementAdmission.Require(baseline!.Length == observed.Length &&
                baseline.All(a => observed.Any(b => SameAssignment(a, b))), NativeFailure.EffectMismatch);
            return;
        }
        Assignment? exact = observed.SingleOrDefault(a => a.Id == scope.AssignmentId &&
            a.ParentResourceId.Equals(ParentId(scope.Parent), StringComparison.OrdinalIgnoreCase));
        if (operation == "DeleteRoleAssignmentAsync")
            ManagementAdmission.Require(exact is null, NativeFailure.EffectMismatch);
        else if (operation == "CreateRoleAssignmentAsync")
            ManagementAdmission.Require(exact is not null && exact.PrincipalId == principalId &&
                exact.DefinitionId == definitionId, NativeFailure.EffectMismatch);
    }

    internal static void ValidateBaseline(string operation, RoleAssignmentScope scope, Guid principalId,
        Guid definitionId, Assignment[]? baseline)
    {
        ManagementAdmission.Require(baseline is not null, NativeFailure.ObserverUnavailable);
        ValidateAssignments(baseline!);
        Assignment? target = baseline!.SingleOrDefault(a => a.Id == scope.AssignmentId &&
            a.ParentResourceId.Equals(ParentId(scope.Parent), StringComparison.OrdinalIgnoreCase));
        ManagementAdmission.Require(operation switch
        {
            "CreateRoleAssignmentAsync" => target is null,
            "DeleteRoleAssignmentAsync" => target is not null && target.PrincipalId == principalId &&
                target.DefinitionId == definitionId,
            _ => false
        }, NativeFailure.EffectMismatch);
    }

    internal static void ValidateTargetMeasurement(Measurement measured, RoleAssignmentScope scope)
    {
        ValidateAssignments(measured.Assignments);
        // A missing JSON boolean is unknown, never evidence of absence.
        ManagementAdmission.Require(measured.AssignmentsComplete == true && measured.TargetPresent.HasValue &&
            measured.TargetPresent.Value == measured.Assignments.Any(a => a.Id == scope.AssignmentId &&
                a.ParentResourceId.Equals(ParentId(scope.Parent), StringComparison.OrdinalIgnoreCase)),
            NativeFailure.ObserverUnavailable);
    }

    internal static void ValidateInventory(Result result, Measurement observed, int maximumItems)
    {
        if (result.Assignments is { } assignments)
        {
            ValidateAssignments(observed.Assignments);
            ManagementAdmission.Require(assignments.Items.Count > 0 && assignments.Items.Count <= maximumItems);
            ManagementAdmission.Require(observed.AssignmentsComplete == true &&
                assignments.Items.Select(a => (a.Scope.AssignmentId, ParentId(a.Scope.Parent).ToUpperInvariant()))
                    .Distinct().Count() == assignments.Items.Count, NativeFailure.EffectMismatch);
            foreach (var row in assignments.Items) MatchAssignment(row, observed.Assignments);
            if (assignments.Complete) ManagementAdmission.Require(assignments.Items.Count == observed.Assignments.Length,
                NativeFailure.EffectMismatch);
        }
        if (result.Definitions is { } definitions)
        {
            ValidateDefinitions(observed.Definitions);
            ManagementAdmission.Require(definitions.Items.Count > 0 && definitions.Items.Count <= maximumItems);
            ManagementAdmission.Require(observed.DefinitionsComplete == true &&
                definitions.Items.Select(d => d.Scope.DefinitionId).Distinct().Count() == definitions.Items.Count,
                NativeFailure.EffectMismatch);
            foreach (var row in definitions.Items) MatchDefinition(row, observed.Definitions);
            if (definitions.Complete) ManagementAdmission.Require(definitions.Items.Count == observed.Definitions.Length,
                NativeFailure.EffectMismatch);
        }
    }

    public static void Register(NativeCaseRegistry registry, OwnedAzureEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected, Func<ObserverEndpoint, OwnedManagementObserver>? createObserver = null,
        HttpPipelineTransport? managementTransport = null, HttpPipelineTransport? runtimeTransport = null) =>
        ManagementAdmission.Register(registry, env, expected, Members,
            (d, p, t) => ExecuteAsync(env, d, p, t, createObserver, managementTransport, runtimeTransport));

    private static async ValueTask ExecuteAsync(OwnedAzureEnvironment env, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token, Func<ObserverEndpoint, OwnedManagementObserver>? createObserver,
        HttpPipelineTransport? managementTransport, HttpPipelineTransport? runtimeTransport)
    {
        Input input = ManagementAdmission.Input<Input>(env, "RoleAdministration");
        ManagementAdmission.Require(input.IntendedPrincipalId != Guid.Empty && input.RoleDefinitionId != Guid.Empty);
        using OwnedManagementObserver service = createObserver is null ? new(input.Observer) : createObserver(input.Observer);
        FixtureSelector selector = FixtureSelector.For(definition);
        LeaseFacts? known = null;
        try
        {
            Lease lease = await service.PostAsync<Prepare, Lease>("role/prepare",
                new(selector, input.SubscriptionId, input.ResourceGroup, input.Location, input.TenantId,
                    input.RoleDefinitionId, input.IntendedPrincipalId), token).ConfigureAwait(false);
            lease.Facts.Claim(selector);
            lease.Facts.Validate(selector, "2022-04-01");
            known = lease.Facts;
            var subscription = new SubscriptionScope(input.SubscriptionId);
            var group = new ResourceGroupScope(subscription, input.ResourceGroup);
            var vault = new VaultScope(group, lease.VaultName);
            ManagementAdmission.Require(lease.Facts.OwnedResourceIds.Contains(vault.ExportResourceId(), StringComparer.OrdinalIgnoreCase) &&
                lease.AssignmentId != Guid.Empty && lease.RuntimeSecretVersion.Length == 32 &&
                lease.RuntimeSecretVersion.All(char.IsAsciiHexDigit) && lease.RuntimeSecretSha256.Length == 64 &&
                lease.RuntimeSecretSha256.All(char.IsAsciiHexDigit));
            ManagementScope parent = definition.Key.Variant switch
            {
                "scope.resource-group" => group,
                "scope.subscription" => subscription,
                _ => vault
            };
            Guid selectedAssignment = definition.Key.Variant switch
            {
                "scope.resource-group" => lease.BorrowedGroupAssignmentId ?? Guid.Empty,
                "scope.subscription" => lease.BorrowedSubscriptionAssignmentId ?? Guid.Empty,
                _ => lease.AssignmentId
            };
            ManagementAdmission.Require(selectedAssignment != Guid.Empty);
            var scope = new RoleAssignmentScope(parent, selectedAssignment);
            var role = new RoleDefinitionScope(subscription, input.RoleDefinitionId);
            string operation = definition.Key.Operation[Prefix.Length..];
            using var clients = new ManagementClients(input.Arm, definition.Key.Case, token, hostTransport: managementTransport);
            ManagementReceipt? receipt = operation switch
            {
                "CreateRoleAssignmentAsync" => clients.Selected.PrepareReceipt(scope, ManagementMutation.CreateRoleAssignment),
                "DeleteRoleAssignmentAsync" => clients.Selected.PrepareReceipt(scope, ManagementMutation.DeleteRoleAssignment),
                _ => null
            };
            ObservationSubscription armed = await service.SubscribeAsync("role", lease.Facts, token).ConfigureAwait(false);
            Measurement? baseline = null;
            if (receipt is not null)
            {
                baseline = await service.PostAsync<ObserveLease, Measurement>("role/observe",
                    new(lease.Facts.LeaseId, selector.Nonce, "assignment-baseline-before-dispatch", armed.SubscriptionId),
                    token).ConfigureAwait(false);
                ValidateMeasurement(baseline, lease, armed, selector, vault, scope, input.RoleDefinitionId,
                    RoleAdministrationCollector.Phase.Baseline);
                ValidateTargetMeasurement(baseline, scope);
                ValidateBaseline(operation, scope, input.IntendedPrincipalId, input.RoleDefinitionId, baseline.Assignments);
                ValidateReads(baseline, lease.BaselineRuntimeStatus, lease.RuntimeSecretSha256);
            }
            Task boundary = clients.Boundary.ResponseReceived;
            Result? result = null;
            bool canceled = false;
            try
            {
                result = await InvokeAsync(clients.Selected, operation, vault, scope, role, input.IntendedPrincipalId,
                    receipt, new(input.MaximumPages, input.MaximumItems, input.Timeout),
                    clients.Cancellation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (clients.Cancellation.IsCancellationRequested && !token.IsCancellationRequested)
            {
                canceled = true;
            }
            Measurement observed = await service.PostAsync<ObserveLease, Measurement>("role/observe",
                new(lease.Facts.LeaseId, selector.Nonce, "assignment-and-effective-permission", armed.SubscriptionId), token).ConfigureAwait(false);
            ValidateMeasurement(observed, lease, armed, selector, vault, scope, input.RoleDefinitionId,
                RoleAdministrationCollector.Phase.After, baseline?.Sequence ?? 0);
            if (baseline is not null)
                ManagementAdmission.Require(observed.ObservedAt >= baseline.ObservedAt, NativeFailure.ObserverUnavailable);
            if (definition.Key.Case == "cancellation-boundary")
                ManagementAdmission.Require(canceled && boundary.IsCompletedSuccessfully, NativeFailure.ContractMismatch);
            else if (definition.Key.Case == "lost-response-no-replay")
                ManagementAdmission.Require(result?.Status == SecretStatus.Unknown && boundary.IsCompletedSuccessfully, NativeFailure.ContractMismatch);
            else if (definition.Key.Case == "denied-authority")
                ManagementAdmission.Require(result?.Status == SecretStatus.Denied, NativeFailure.ContractMismatch);
            else
            {
                ManagementAdmission.Require(result?.Status == SecretStatus.Success, NativeFailure.ContractMismatch);
                if (result!.Assignment is { } assignment) MatchAssignment(assignment, observed.Assignments);
                if (result.Definition is { } roleDefinition) MatchDefinition(roleDefinition, observed.Definitions);
                ValidateInventory(result, observed, input.MaximumItems);
                if (result.Assignments is { } assignments)
                {
                    ManagementAdmission.Require(assignments.Items.Any(a => a.Scope.AssignmentId == selectedAssignment &&
                        ParentId(a.Scope.Parent) == ParentId(parent)), NativeFailure.ContractMismatch);
                }
            }
            if (receipt is not null) ManagementAdmission.Receipt(receipt, definition.Key.Case);
            bool denied = definition.Key.Case == "denied-authority";
            bool deletion = operation == "DeleteRoleAssignmentAsync" && !denied;
            bool creation = operation == "CreateRoleAssignmentAsync" && !denied;
            if (receipt is not null)
            {
                ValidateTargetMeasurement(observed, scope);
                ValidateMutation(operation, denied, scope, input.IntendedPrincipalId, input.RoleDefinitionId,
                    baseline?.Assignments, observed.Assignments);
            }
            SecretStatus expectedRead = denied ? lease.BaselineRuntimeStatus :
                deletion ? SecretStatus.Denied : SecretStatus.Success;
            ValidateReads(observed, expectedRead, lease.RuntimeSecretSha256);
            // These are independent data-plane SDK reads, not ARM metadata permission claims.
            var uri = new Uri("https://" + lease.VaultName + ".vault.azure.net");
            var runtime = new AzureKeyVaultClient(uri, env.Credential(NativeIdentityRole.Runtime), runtimeTransport);
            var deniedRuntime = new AzureKeyVaultClient(uri, env.Credential(NativeIdentityRole.Denied), runtimeTransport);
            var separateReader = new AzureKeyVaultClient(uri, env.Credential(NativeIdentityRole.Observer), runtimeTransport);
            await CheckReadAsync(runtime, lease.RuntimeSecretName, lease.RuntimeSecretSha256, expectedRead, token,
                lease.RuntimeSecretVersion).ConfigureAwait(false);
            await CheckReadAsync(deniedRuntime, lease.RuntimeSecretName, lease.RuntimeSecretSha256, SecretStatus.Denied, token,
                lease.RuntimeSecretVersion).ConfigureAwait(false);
            await CheckReadAsync(separateReader, lease.RuntimeSecretName, lease.RuntimeSecretSha256, SecretStatus.Success, token,
                lease.RuntimeSecretVersion).ConfigureAwait(false);
            probe.Contract(true, NativeFailure.ContractMismatch);
            probe.Effect(NativeObservation.Matched);
            ManagementAdmission.ConfirmInfrastructure(env, definition, lease.Facts);
            ManagementAdmission.Confirm(env, definition, "selected-runtime-identity", "intended-principal-permission-observer");
            if (result?.Status == SecretStatus.Success && !denied)
                ManagementAdmission.Confirm(env, definition, "selected-administrative-identity",
                    "scoped-administrative-rights", "azure-arm-public-cloud-rights");
            if (creation || deletion)
                ManagementAdmission.Confirm(env, definition, "azure-role-assignment-rights");
        }
        finally
        {
            await RoleFixtureRelease.ReleaseAsync(service, selector, known, probe, env, definition).ConfigureAwait(false);
        }
    }

    internal static Measurement ProjectMeasurement(RoleAdministrationCollector.Measurement measured, string observerIdentity)
    {
        ManagementAdmission.Require(measured.Complete, NativeFailure.ObserverUnavailable);
        var binding = measured.Binding;
        return new(binding.LeaseId, binding.Selector.Nonce, binding.Selector, observerIdentity, measured.StartedAt, measured.FinishedAt,
            measured.WindowId, measured.Sequence, measured.Phase,
            new(binding.Vault.ExportResourceId(), ParentId(binding.Target.Parent), binding.Target.AssignmentId,
                binding.DefinitionId, binding.SecretName, binding.SecretVersion),
            measured.Assignments.ToArray(), measured.Definitions.ToArray(),
            Project(measured.Intended), Project(measured.Denied), Project(measured.Observer),
            measured.TargetPresent, measured.AssignmentsComplete, measured.DefinitionsComplete);
        static ReadObservation Project(RoleAdministrationCollector.ReadEvidence read) =>
            new(read.Status, read.Sha256, read.NativeRequestId ?? "", read.Complete);
    }

    internal static void ValidateMeasurement(Measurement measured, Lease lease, ObservationSubscription armed,
        FixtureSelector selector, VaultScope vault, RoleAssignmentScope target, Guid definitionId, RoleAdministrationCollector.Phase phase,
        long previousSequence = 0)
    {
        ManagementAdmission.Require(measured.LeaseId == lease.Facts.LeaseId && measured.Nonce == lease.Facts.Nonce &&
            measured.Selector == selector && measured.Nonce == selector.Nonce &&
            measured.ObserverIdentity == lease.Facts.ObserverIdentity && measured.SubscriptionId == armed.SubscriptionId &&
            measured.Sequence > previousSequence && measured.Phase == phase &&
            measured.AssignmentsComplete == true && measured.DefinitionsComplete == true &&
            measured.StartedAt >= armed.ArmedAt && measured.ObservedAt >= measured.StartedAt &&
            measured.Coordinates == new Coordinates(vault.ExportResourceId(), ParentId(target.Parent),
                target.AssignmentId, definitionId, lease.RuntimeSecretName, lease.RuntimeSecretVersion),
            NativeFailure.ObserverUnavailable);
        foreach (ReadObservation? read in new[] { measured.Intended, measured.Denied, measured.Observer })
            ManagementAdmission.Require(read is not null && read.Complete && Enum.IsDefined(read.Status) &&
                !string.IsNullOrWhiteSpace(read.NativeRequestId) && read.NativeRequestId.Length <= 256 &&
                read.NativeRequestId.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.') &&
                (read.Status == SecretStatus.Success ? read.Sha256 is { Length: 64 } &&
                    read.Sha256.All(char.IsAsciiHexDigit) : read.Sha256 is null), NativeFailure.ObserverUnavailable);
    }

    internal static void ValidateReads(Measurement measured, SecretStatus intendedStatus, string sha256)
    {
        foreach (var (read, expected) in new[] { (measured.Intended, intendedStatus),
            (measured.Denied, SecretStatus.Denied), (measured.Observer, SecretStatus.Success) })
            ManagementAdmission.Require(read is not null && read.Complete && read.Status == expected &&
                (expected == SecretStatus.Success ? string.Equals(read.Sha256, sha256, StringComparison.OrdinalIgnoreCase) :
                    read.Sha256 is null), NativeFailure.EffectMismatch);
    }

    internal static async ValueTask CheckReadAsync(AzureKeyVaultClient client, string name, string sha256,
        SecretStatus status, CancellationToken token, string? version = null)
    {
        var outcome = await client.ReadAsync(new(client.Authority, new AzureSecretAddress(name, version)), token).ConfigureAwait(false);
        CheckReadOutcome(outcome, sha256, status);
    }

    internal static void CheckReadOutcome(SecretOutcome<SecretRead> outcome, string sha256, SecretStatus status)
    {
        using SecretRead? read = outcome.IsSuccess ? outcome.Value : null;
        ManagementAdmission.Require(outcome.Status == status, NativeFailure.EffectMismatch);
        if (read is not null)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(read.Material.Reveal());
            try
            {
                ManagementAdmission.Require(Convert.ToHexString(SHA256.HashData(bytes)).Equals(sha256, StringComparison.OrdinalIgnoreCase),
                    NativeFailure.EffectMismatch);
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }

    private static async ValueTask<Result> InvokeAsync(VaultAdministration client, string operation, VaultScope vault,
        RoleAssignmentScope assignment, RoleDefinitionScope definition, Guid principalId, ManagementReceipt? receipt,
        CollectionLimits limits, CancellationToken token)
    {
        switch (operation)
        {
            case "CreateRoleAssignmentAsync":
                {
                    var o = await client.CreateRoleAssignmentAsync(assignment, definition, principalId, receipt!, token).ConfigureAwait(false);
                    return new(o.Status, Assignment: o.IsSuccess ? o.Value : null);
                }
            case "DeleteRoleAssignmentAsync":
                {
                    var o = await client.DeleteRoleAssignmentAsync(assignment, receipt!, token).ConfigureAwait(false);
                    return new(o.Status, o.IsSuccess ? o.Value : null);
                }
            case "GetRoleAssignmentAsync":
                {
                    var o = await client.GetRoleAssignmentAsync(assignment, token).ConfigureAwait(false);
                    return new(o.Status, Assignment: o.IsSuccess ? o.Value : null);
                }
            case "GetRoleDefinitionAsync":
                {
                    var o = await client.GetRoleDefinitionAsync(definition, token).ConfigureAwait(false);
                    return new(o.Status, Definition: o.IsSuccess ? o.Value : null);
                }
            case "ListRoleAssignmentsAsync":
                {
                    var o = await client.ListRoleAssignmentsAsync(vault, limits, token).ConfigureAwait(false);
                    return new(o.Status, Assignments: o);
                }
            case "ListRoleDefinitionsAsync":
                {
                    var o = await client.ListRoleDefinitionsAsync(vault.ResourceGroup.Subscription, limits, token).ConfigureAwait(false);
                    return new(o.Status, Definitions: o);
                }
            default: throw new NativeCaseFailureException("contract-mismatch");
        }
    }

    internal static string ParentId(ManagementScope scope) => scope switch
    {
        VaultScope v => v.ExportResourceId(),
        ResourceGroupScope g => $"/subscriptions/{g.Subscription.SubscriptionId:D}/resourceGroups/{g.ResourceGroup}",
        SubscriptionScope s => $"/subscriptions/{s.SubscriptionId:D}",
        _ => throw new NativeCaseFailureException("contract-mismatch")
    };

    internal static void MatchAssignment(RoleAssignmentObservation value, Assignment[] observed)
    {
        ValidateAssignments(observed);
        ManagementAdmission.Require(observed.Any(a => a.Id == value.Scope.AssignmentId &&
            a.ParentResourceId.Equals(ParentId(value.Scope.Parent), StringComparison.OrdinalIgnoreCase) &&
            a.DefinitionId == value.Definition.DefinitionId && a.PrincipalId == value.PrincipalId &&
            a.PrincipalType == value.PrincipalType && a.Description == value.Description &&
            a.Condition == value.Condition && a.ConditionVersion == value.ConditionVersion), NativeFailure.EffectMismatch);
    }

    private static void ValidateAssignments(Assignment[]? assignments) =>
        ManagementAdmission.Require(assignments is not null &&
            assignments.All(a => a is not null && a.Id != Guid.Empty && a.PrincipalId != Guid.Empty &&
                a.DefinitionId != Guid.Empty && !string.IsNullOrWhiteSpace(a.ParentResourceId)) &&
            assignments.Select(a => (a.Id, a.ParentResourceId.ToUpperInvariant())).Distinct().Count() == assignments.Length,
            NativeFailure.EffectMismatch);

    private static bool SameAssignment(Assignment a, Assignment b) =>
        a.Id == b.Id && a.ParentResourceId.Equals(b.ParentResourceId, StringComparison.OrdinalIgnoreCase) &&
        a.DefinitionId == b.DefinitionId && a.PrincipalId == b.PrincipalId && a.PrincipalType == b.PrincipalType &&
        a.Description == b.Description && a.Condition == b.Condition && a.ConditionVersion == b.ConditionVersion;

    private static void ValidateDefinitions(Definition[]? definitions) =>
        ManagementAdmission.Require(definitions is not null &&
            definitions.All(d => d is not null && d.Id != Guid.Empty && d.AssignableScopes is not null &&
                d.Permissions is not null && d.Permissions.All(p => p is not null && p.Actions is not null &&
                    p.NotActions is not null && p.DataActions is not null && p.NotDataActions is not null)) &&
            definitions.Select(d => d.Id).Distinct().Count() == definitions.Length, NativeFailure.EffectMismatch);

    private static void MatchDefinition(RoleDefinitionObservation value, Definition[] observed)
    {
        ValidateDefinitions(observed);
        Definition? match = observed.SingleOrDefault(d => d.Id == value.Scope.DefinitionId);
        ManagementAdmission.Require(match is not null && match.Name == value.Name && match.Description == value.Description &&
            match.RoleType == value.RoleType && match.AssignableScopes.Order().SequenceEqual(value.AssignableScopes.Order()) &&
            match.Permissions.Length == value.Permissions.Count,
                NativeFailure.EffectMismatch);
        var remaining = match!.Permissions.ToList();
        foreach (var permission in value.Permissions)
        {
            int index = remaining.FindIndex(p => p.Actions.Order().SequenceEqual(permission.Actions.Order()) &&
                p.NotActions.Order().SequenceEqual(permission.NotActions.Order()) &&
                p.DataActions.Order().SequenceEqual(permission.DataActions.Order()) &&
                p.NotDataActions.Order().SequenceEqual(permission.NotDataActions.Order()));
            ManagementAdmission.Require(index >= 0, NativeFailure.EffectMismatch);
            remaining.RemoveAt(index);
        }
    }
}
