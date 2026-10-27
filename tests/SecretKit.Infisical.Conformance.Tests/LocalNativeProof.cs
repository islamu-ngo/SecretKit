using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;

namespace SecretKit.Infisical.Conformance.Tests;

// The host and selected setup operator are explicit trust roots. There is no
// arbitrary-token identity lookup, JWT decoding, public token hash or attestation.
internal sealed class LocalNativeProof : IAsyncDisposable
{
    private readonly OwnedSandbox sandbox;
    private readonly ManagementTransport transport;
    private readonly ManagementClient management;
    private readonly LocalNativeTokens setup;
    private readonly LocalNativeBinding binding;
    private readonly LocalNativeSettings selection;
    private readonly Dictionary<string, Func<CancellationToken, Task<bool>>> removals = [];
    private readonly Dictionary<string, SecretMaterial> credentials = [];
    private readonly Dictionary<string, TrialActor> trials = [];
    private readonly Dictionary<string, int> renewals = [];
    private readonly TimeProvider time;
    private LocalNativeSettings? produced;
    private byte[]? envelope;
    private bool challengesObserved;
    private int childCreate = -1, childUpdate = -1, childApproval = -1;
    private bool childObserved;
    internal LocalProducerLedger Ledger { get; }
    internal string RunId { get; } = Guid.NewGuid().ToString("N");

    internal LocalNativeProof(OwnedSandbox sandbox, LocalNativeSettings selection, LocalNativeBinding binding,
        string? ledgerPath = null, TimeProvider? timeProvider = null)
    {
        NativeWorkflow.Require(sandbox.Verified && sandbox.Origin.AbsoluteUri == new Uri(selection.Origin).AbsoluteUri &&
            sandbox.Owner == selection.Owner && sandbox.OrganizationId == selection.OrganizationId &&
            selection.Issuance is null);
        this.sandbox = sandbox;
        this.selection = selection;
        this.binding = binding;
        time = timeProvider ?? TimeProvider.System;
        using var material = sandbox.CopySetupToken();
        setup = new(material.Reveal());
        transport = new(sandbox.Origin, new() { AllowLoopbackDevelopmentHttp = true });
        management = new(transport, time);
        Ledger = new(selection.Owner, RunId, ledgerPath);
    }

    internal async Task<byte[]> ProduceAsync(CancellationToken token)
    {
        NativeWorkflow.Require(produced is null && !Ledger.CleanupStarted);
        string prefix = "SDK_" + selection.Owner[14..].ToUpperInvariant() + "_" + RunId.ToUpperInvariant();
        string readKey = prefix + "_READ";
        string writeKey = prefix + "_WRITE";
        string slug = "sdk-proof-" + RunId;
        using var projectRequest = ProjectOperations.CreateProject(selection.OrganizationId, "Owned proof isolation", slug);
        ProjectSummary foreign = await Apply(projectRequest,
            ProjectOperations.ProjectCreateTarget(selection.OrganizationId, "Owned proof isolation", slug),
            "project", 10, null, p => p.Id, id => ProjectOperations.DeleteProject(selection.OrganizationId, id), token);
        string foreignKey = prefix + "_FOREIGN";
        string expected = RandomValue();
        string foreignValue = RandomValue();
        await CreateFixture(selection.ProjectId, selection.Environment, selection.Folder, readKey, expected, null, token);
        await CreateFixture(foreign.Id, "dev", "/", foreignKey, foreignValue, "project:" + foreign.Id, token);
        var runtime = await Actor("runtime", "viewer", selection.ProjectId, null, 3600, 7200, 0, 0, 0, token);
        var denied = await Actor("denied", null, null, null, 3600, 7200, 0, 0, 0, token);
        var writer = await Actor("writer", "member", selection.ProjectId, null, 3600, 7200, 0, 0, 0, token);
        var observer = await Actor("observer", "viewer", selection.ProjectId, foreign.Id, 3600, 7200, 0, 0, 0, token);
        produced = selection with
        {
            ReadKey = readKey,
            WriteKey = writeKey,
            SelectedVersion = 1,
            Authentication = null,
            Runtime = new(runtime.Identity, runtime.Issued.Token),
            Denied = new(denied.Identity, denied.Issued.Token),
            Writer = new(writer.Identity, writer.Issued.Token),
            Observer = new(observer.Identity, observer.Issued.Token),
            Issuance = new("owned-causal-issuance-v1", RunId, binding.RecordSha256, selection.Owner, selection.ProjectId,
                selection.Environment, selection.Folder, foreign.Id, "dev", "/", foreignKey, expected, foreignValue,
                [.. NativeLifetimeTrials.Ids])
        };
        challengesObserved = await ChallengeAsync(produced, token);
        // The setup token is never handed to the installed child. This slot remains
        // structurally distinct but unusable; setup operations stay in this host.
        produced = produced with { Setup = new(selection.Setup.Id, "host-only-" + RunId) };
        envelope = JsonSerializer.SerializeToUtf8Bytes(new LocalNativeWire(1, "local-native-run", "infisical-runtime",
            "owned-local-native-execution", binding, JsonSerializer.SerializeToElement(produced, NativeWorkflow.JsonOptions)),
            NativeWorkflow.JsonOptions);
        AdmitProduced(envelope);
        return envelope.ToArray();
    }

    internal LocalNativeInput AdmitProduced(byte[] bytes)
    {
        NativeWorkflow.Require(envelope is not null && bytes.AsSpan().SequenceEqual(envelope));
        LocalNativeInput input = NativeWorkflow.Parse(bytes);
        NativeWorkflow.Require(input.Settings.Issuance?.RunId == RunId &&
            LocalProfileConformance.SameBinding(input.Binding, binding));
        return input;
    }

    internal void ValidateReport(LocalNativeReport report)
    {
        NativeWorkflow.Require(produced is not null && report.ProofRun == RunId &&
            LocalProfileConformance.SameBinding(report.Binding, binding));
        if (report.Cases.Any(c => c.Id is "actor-binding" or "policy-binding" && c.Status == "passed"))
            NativeWorkflow.Require(challengesObserved &&
                report.Cases.Single(c => c.Id == "read-native").Status == "passed" &&
                report.Cases.Single(c => c.Id == "read").Status == "passed");
        if (report.Cases.Single(c => c.Id == "policy-binding").Status == "passed")
            NativeWorkflow.Require(report.Cases.Single(c => c.Id == "actor-binding").Status == "passed" &&
                report.Cases.Single(c => c.Id == "runtime-write-denied").Status == "passed" &&
                report.Cases.Single(c => c.Id == "denied-read").Status == "passed");
        foreach (var observed in report.SupplementalCases.Where(c => c.Status == "passed"))
        {
            NativeWorkflow.Require(observed.Reason == "observed" && trials.TryGetValue(observed.Id, out _));
            var actor = trials[observed.Id];
            NativeLifetimeTrials.Validate(actor.Issued);
            NativeWorkflow.Require(observed.Id switch
            {
                "Q01" or "Q02" => actor.Renewals == 2,
                "Q03" or "Q05" => actor.Renewals == 0 && !actor.Exchanged,
                "Q04" => actor.SecondBootstrapRejected && actor.Renewals == 0,
                "Q06" => actor.RecoveryIssued && actor.Renewals == 1,
                _ => false
            });
        }
    }

    private async Task<bool> ChallengeAsync(LocalNativeSettings settings, CancellationToken token)
    {
        var issued = settings.Issuance!;
        using var runtime = new LocalNativeTokens(settings.Runtime.Token);
        using var observer = new LocalNativeTokens(settings.Observer.Token);
        var network = new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true };
        await using var reader = new InfisicalClient(sandbox.Origin, runtime, network, time);
        await using var witness = new InfisicalClient(sandbox.Origin, observer, network, time);
        var allowed = await reader.ReadNativeAsync(new(reader.Authority,
            new InfisicalSecretAddress(settings.ProjectId, settings.Environment, settings.Folder, settings.ReadKey)), token);
        bool readable = false;
        if (allowed.IsSuccess)
        {
            using var value = allowed.Value;
            readable = value.Material.Reveal() == issued.ExpectedReadValue;
        }
        var populated = await witness.ReadNativeAsync(new(witness.Authority, new InfisicalSecretAddress(
            issued.ForeignProjectId, issued.ForeignEnvironment, issued.ForeignFolder, issued.ForeignKey)), token);
        bool exists = false;
        if (populated.IsSuccess)
        {
            using var value = populated.Value;
            exists = value.Material.Reveal() == issued.ForeignValue;
        }
        var foreign = await reader.ReadNativeAsync(new(reader.Authority, new InfisicalSecretAddress(
            issued.ForeignProjectId, issued.ForeignEnvironment, issued.ForeignFolder, issued.ForeignKey)), token);
        if (foreign.IsSuccess) foreign.Value.Dispose();
        return readable && exists && foreign.Status == SecretStatus.Denied;
    }

    internal async Task<LocalTrialExchange> ExchangeAsync(string id, string operation, CancellationToken token)
    {
        NativeWorkflow.Require(produced is not null && !Ledger.CleanupStarted &&
            NativeLifetimeTrials.Ids.Contains(id, StringComparer.Ordinal));
        if (operation == "start")
        {
            NativeWorkflow.Require(!trials.ContainsKey(id));
            NativeWorkflow.Require(trials.Count < NativeLifetimeTrials.Ids.Length &&
                NativeLifetimeTrials.Ids[trials.Count] == id);
            var actor = await Actor(id, "viewer", produced.ProjectId, null, 10, 20, id == "Q02" ? 60 : 0,
                id == "Q05" ? 1 : 0, id is "Q04" or "Q06" ? 1 : 0, token);
            trials.Add(id, actor);
            return new(SecretStatus.Success, DispatchEvidence.Applied, actor.Issued);
        }
        NativeWorkflow.Require(trials.TryGetValue(id, out TrialActor? selected) && selected is not null);
        if (id == "Q04" && operation == "second-bootstrap")
        {
            NativeWorkflow.Require(!selected!.Exchanged);
            selected.Exchanged = true;
            var result = await Login(selected, token);
            selected.SecondBootstrapRejected = result.Status == SecretStatus.Denied &&
                result.Effect == DispatchEvidence.Rejected && result.Issued is null;
            return result;
        }
        NativeWorkflow.Require(id == "Q06" && operation == "explicit-recovery" && !selected!.Exchanged);
        selected.Exchanged = true;
        string previous = selected.SecretId;
        await Bootstrap(selected, 1, token);
        NativeWorkflow.Require(selected.SecretId != previous);
        var recovery = await Login(selected, token);
        selected.RecoveryIssued = recovery.Status == SecretStatus.Success && recovery.Effect == DispatchEvidence.Applied &&
            recovery.Issued?.ActorId == selected.Identity && recovery.Issued.Token != selected.Issued.Token;
        return recovery;
    }

    internal Task AcknowledgeRenewalAsync(string id, string? value, DispatchEvidence effect, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        NativeWorkflow.Require(!Ledger.CleanupStarted && trials.ContainsKey(id) && id is "Q01" or "Q02" or "Q06");
        NativeWorkflow.Require(effect is DispatchEvidence.PossiblyDispatched or DispatchEvidence.Applied or DispatchEvidence.Rejected);
        if (effect == DispatchEvidence.PossiblyDispatched && !renewals.ContainsKey(id))
        {
            int operation = Ledger.Begin("renewal", "configuration:" + trials[id].Identity);
            renewals.Add(id, operation);
            Ledger.Effect(operation, effect);
            return Task.CompletedTask;
        }
        NativeWorkflow.Require(renewals.TryGetValue(id, out int pending));
        if (effect == DispatchEvidence.Applied)
        {
            NativeWorkflow.Require(value is { Length: > 0 and <= 16384 } && value.All(c => c > ' ' && c < 127));
            RetainToken(value!, "configuration:" + trials[id].Identity);
            Ledger.Effect(pending, effect, acknowledged: true);
            trials[id].Renewals++;
        }
        else Ledger.Effect(pending, effect);
        renewals.Remove(id);
        return Task.CompletedTask;
    }

    internal async Task RecreateAsync(LocalNativeSettings settings, CancellationToken token)
    {
        NativeWorkflow.Require(produced is not null && settings.ReadKey == produced.ReadKey);
        NativeWorkflow.Require(await RemoveSecretAsync(settings.ProjectId, settings.Environment,
            settings.Folder, settings.ReadKey, token));
        await using var client = new InfisicalClient(sandbox.Origin, setup,
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
        var reference = new SecretReference(client.Authority, new InfisicalSecretAddress(settings.ProjectId,
            settings.Environment, settings.Folder, settings.ReadKey));
        var receipt = new MutationReceipt(reference);
        int operation = Ledger.Begin("recreate", "fixture:" + settings.ProjectId + ":" + settings.ReadKey);
        Ledger.Effect(operation, DispatchEvidence.PossiblyDispatched);
        try
        {
            using var material = SecretMaterial.FromText(produced.Issuance!.ExpectedReadValue);
            var created = await client.CreateAsync(reference, material, receipt, token);
            NativeWorkflow.Require(created.IsSuccess && created.Value.Disposition == InfisicalChangeDisposition.Applied &&
                receipt.Evidence == DispatchEvidence.Applied);
            Ledger.Acknowledged(operation);
        }
        finally { Ledger.Effect(operation, receipt.Evidence); }
    }

    private async Task<TrialActor> Actor(string purpose, string? role, string? project, string? otherProject,
        int ttl, int maximum, int period, long uses, long bootstrapUses, CancellationToken token)
    {
        string org = selection.OrganizationId;
        string name = "sdk-" + purpose + "-" + RunId;
        using var request = IdentityOperations.CreateOrganizationIdentity(org, name, "no-access");
        IdentitySummary identity = await Apply(request,
            IdentityOperations.OrganizationIdentityCreateTarget(org, name, "no-access"), "identity", 20, null,
            result => result.Id, id => IdentityOperations.DeleteOrganizationIdentity(org, id), token);
        using var getIdentity = IdentityOperations.GetOrganizationIdentity(org, identity.Id);
        IdentitySummary observed = await Read(getIdentity, token);
        NativeWorkflow.Require(observed.Membership.IsPresent && observed.Membership.Value.Role.Value == "no-access");
        foreach (string target in new[] { project, otherProject }.OfType<string>())
        {
            using var membership = MembershipOperations.AddProjectIdentity(org, target, identity.Id, [new MembershipRole(role!)]);
            var added = await Apply(membership, MembershipOperations.RoleChangeTarget(org, target, identity.Id,
                [new MembershipRole(role!)]), "membership", 30, "identity:" + identity.Id, r => r.Id,
                _ => MembershipOperations.RemoveProjectIdentity(org, target, identity.Id), token,
                additionalParent: "project:" + target);
            Ledger.Depend("membership:" + added.Id, "project:" + target);
            using var inspect = MembershipOperations.GetProjectIdentityMembership(org, target, identity.Id);
            var membershipObserved = await Read(inspect, token);
            NativeWorkflow.Require(membershipObserved.Roles.Count == 1 &&
                membershipObserved.Roles[0].Role == role && membershipObserved.Roles[0].IsTemporary == false &&
                membershipObserved.Roles[0].CustomRoleId is null);
            using var privileges = IdentityPrivilegeOperations.ListProjectPrivileges(org, target, identity.Id);
            var additional = await Read(privileges, token);
            NativeWorkflow.Require(additional.IsComplete && additional.Items.Count == 0);
        }
        var policy = new UniversalAuthConfigurationInput(ttl, maximum, uses, period);
        using var attach = IdentityAuthenticationOperations.AttachUniversalAuth(org, identity.Id, policy);
        var configuration = await Apply(attach,
            IdentityAuthenticationOperations.UniversalAuthConfigurationTarget(org, identity.Id, policy),
            "configuration", 40, "identity:" + identity.Id, _ => identity.Id,
            id => IdentityAuthenticationOperations.DeleteUniversalAuth(org, id), token);
        using var inspectConfiguration = IdentityAuthenticationOperations.GetUniversalAuth(org, identity.Id);
        var observedConfiguration = await Read(inspectConfiguration, token);
        NativeWorkflow.Require(configuration.Id == observedConfiguration.Id &&
            configuration.ClientId == observedConfiguration.ClientId &&
            observedConfiguration.AccessTokenTTL == ttl && observedConfiguration.AccessTokenMaxTTL == maximum &&
            observedConfiguration.AccessTokenPeriod == period && observedConfiguration.AccessTokenNumUsesLimit == uses);
        var actor = new TrialActor(identity.Id, observedConfiguration.Id, observedConfiguration.ClientId!, purpose,
            ttl, maximum, period, uses, bootstrapUses);
        await Bootstrap(actor, bootstrapUses, token);
        var login = await Login(actor, token);
        NativeWorkflow.Require(login.Status == SecretStatus.Success && login.Effect == DispatchEvidence.Applied);
        actor.Issued = login.Issued!;
        NativeWorkflow.Require(actor.Issued.ExpiresIn == (period > 0 ? period : ttl) &&
            actor.Issued.MaximumTtl == (period > 0 ? 0 : maximum));
        return actor;
    }

    private async Task Bootstrap(TrialActor actor, long uses, CancellationToken token)
    {
        string org = selection.OrganizationId;
        using var create = IdentityAuthenticationOperations.CreateUniversalClientSecret(org, actor.Identity, ttl: 600, numUsesLimit: uses);
        using var secret = await Apply(create,
            IdentityAuthenticationOperations.ClientSecretCreateTarget(org, actor.Identity, ttl: 600, numUsesLimit: uses),
            "bootstrap", 50, "configuration:" + actor.Identity, s => s.Metadata.Id,
            id => IdentityAuthenticationOperations.RevokeUniversalClientSecret(org, actor.Identity, id), token);
        actor.SecretId = secret.Metadata.Id;
        credentials.Add("bootstrap:" + actor.SecretId, secret.ClientSecret.Copy());
        using var inspect = IdentityAuthenticationOperations.GetUniversalClientSecret(org, actor.Identity, actor.SecretId);
        var observed = await Read(inspect, token);
        NativeWorkflow.Require(secret.Metadata.IdentityUAId == actor.ConfigurationId &&
            observed.IdentityUAId == actor.ConfigurationId && observed.ClientSecretNumUsesLimit == uses &&
            observed.ClientSecretNumUses == 0 && observed.ClientSecretTTL == 600 && observed.IsClientSecretRevoked == false);
    }

    private async Task<LocalTrialExchange> Login(TrialActor actor, CancellationToken token)
    {
        using var authentication = new InfisicalUniversalAuthentication(sandbox.Origin,
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true }, time);
        var receipt = authentication.CreateReceipt();
        int operation = Ledger.Begin("login", "bootstrap:" + actor.SecretId);
        Ledger.Effect(operation, DispatchEvidence.PossiblyDispatched);
        try
        {
            var result = await authentication.LoginAsync(actor.ClientId, credentials["bootstrap:" + actor.SecretId],
                receipt, cancellationToken: token);
            if (!result.IsSuccess) return new(result.Status, receipt.Evidence, null);
            using var issued = result.Value;
            RetainToken(issued.Token.Material.Reveal(), "bootstrap:" + actor.SecretId);
            Ledger.Acknowledged(operation);
            var trial = new LocalNativeTrial(actor.Purpose, actor.Identity, actor.ClientId, issued.Token.Material.Reveal(),
                issued.RequestStartedAt, time.GetUtcNow(), issued.ExpiresIn, issued.AccessTokenMaxTTL,
                actor.Ttl, actor.Maximum, actor.Period, actor.Uses, actor.BootstrapUses,
                new(RunId, binding.RecordSha256, selection.ProjectId, selection.Environment, selection.Folder));
            return new(SecretStatus.Success, receipt.Evidence, trial);
        }
        finally { Ledger.Effect(operation, receipt.Evidence); }
    }

    private void RetainToken(string value, string parent)
    {
        // Protected material store is separate from the acknowledged-handle ledger.
        if (credentials.Where(p => p.Key.StartsWith("token:", StringComparison.Ordinal)).Any(p => p.Value.Reveal() == value)) return;
        string key = "token:" + Guid.NewGuid().ToString("N");
        credentials.Add(key, SecretMaterial.FromText(value));
        Ledger.Add(key, 60, parent);
        removals.Add(key, async token =>
        {
            using var proof = new InfisicalProofAuthentication(sandbox.Origin,
                new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
            var receipt = proof.CreateRevocationReceipt();
            int operation = Ledger.Begin("revoke-token", key);
            Ledger.Effect(operation, DispatchEvidence.PossiblyDispatched);
            try
            {
                return await proof.RevokeTokenAsync(credentials[key], receipt, token) == SecretStatus.Success &&
                    receipt.Evidence == DispatchEvidence.Applied;
            }
            finally { Ledger.Effect(operation, receipt.Evidence, acknowledged: true); }
        });
    }

    private async Task<T> Apply<T, TRemoved>(ManagementRequest<T> request, ManagementTarget target, string kind, int order,
        string? parent, Func<T, string> handle, Func<string, ManagementRequest<TRemoved>> remove, CancellationToken token,
        string? additionalParent = null)
        where T : notnull where TRemoved : notnull
    {
        var authority = new ManagementAuthority(management.Authority, setup, selection.OrganizationId, target.ProjectId);
        var receipt = management.CreateReceipt(request);
        int operation = Ledger.Begin(kind, parent,
            [request.OperationId, target.OrganizationId, target.ProjectId, target.ResourceId, target.SecondaryId],
            additionalParent);
        Ledger.Effect(operation, DispatchEvidence.PossiblyDispatched);
        try
        {
            var result = await management.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt, token);
            if (!result.IsSuccess || receipt.Evidence != DispatchEvidence.Applied)
                throw new InvalidOperationException("local-proof-mutation-" + kind + "-" + result.Status);
            string id = handle(result.Value);
            string key = kind + ":" + id;
            using var cleanupSelection = remove(id);
            var cleanupTarget = cleanupSelection.Target;
            Ledger.Add(key, order, parent, coordinates: [cleanupSelection.OperationId, cleanupTarget.OrganizationId,
                cleanupTarget.ProjectId, cleanupTarget.ResourceId, cleanupTarget.SecondaryId]);
            Ledger.Acknowledged(operation);
            removals.Add(key, async ct =>
            {
                using var deletion = remove(id);
                var removalAuthority = new ManagementAuthority(management.Authority, setup,
                    selection.OrganizationId, deletion.Target.ProjectId);
                var removalReceipt = management.CreateReceipt(deletion);
                int removalOperation = Ledger.Begin("remove-" + kind, key);
                Ledger.Effect(removalOperation, DispatchEvidence.PossiblyDispatched);
                try
                {
                    var removed = await management.ExecuteAsync(deletion, removalAuthority,
                        removalAuthority.IssueGrant(deletion.OperationId, deletion.Target), removalReceipt, ct);
                    return removed.IsSuccess && removalReceipt.Evidence == DispatchEvidence.Applied;
                }
                finally { Ledger.Effect(removalOperation, removalReceipt.Evidence, acknowledged: true); }
            });
            return result.Value;
        }
        finally { Ledger.Effect(operation, receipt.Evidence); }
    }

    private async Task<T> Read<T>(ManagementRequest<T> request, CancellationToken token) where T : notnull
    {
        var authority = new ManagementAuthority(management.Authority, setup, selection.OrganizationId, request.Target.ProjectId);
        var result = await management.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, request.Target), cancellationToken: token);
        if (!result.IsSuccess) throw new InvalidOperationException("local-proof-observation-" + request.OperationId + "-" + result.Status);
        return result.Value;
    }

    private async Task CreateFixture(string project, string environment, string folder, string key,
        string value, string? parent, CancellationToken token)
    {
        await using var client = new InfisicalClient(sandbox.Origin, setup,
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
        var reference = new SecretReference(client.Authority, new InfisicalSecretAddress(project, environment, folder, key));
        var absent = await client.ReadNativeAsync(reference, token);
        if (absent.IsSuccess) absent.Value.Dispose();
        NativeWorkflow.Require(absent.Status == SecretStatus.Absent);
        var receipt = new MutationReceipt(reference);
        int operation = Ledger.Begin("fixture", parent, [selection.OrganizationId, project, environment, folder, key]);
        Ledger.Effect(operation, DispatchEvidence.PossiblyDispatched);
        try
        {
            using var material = SecretMaterial.FromText(value);
            var result = await client.CreateAsync(reference, material, receipt, token);
            NativeWorkflow.Require(result.IsSuccess && result.Value.Disposition == InfisicalChangeDisposition.Applied &&
                receipt.Evidence == DispatchEvidence.Applied);
            string handle = "fixture:" + project + ":" + key;
            Ledger.Add(handle, 35, parent, coordinates: [selection.OrganizationId, project, environment, folder, key]);
            Ledger.Acknowledged(operation);
            removals.Add(handle, ct => RemoveSecretAsync(project, environment, folder, key, ct));
        }
        finally { Ledger.Effect(operation, receipt.Evidence); }
    }

    internal async Task<bool> RemoveSecretAsync(string project, string environment, string folder, string key,
        CancellationToken token)
    {
        await using var client = new InfisicalClient(sandbox.Origin, setup,
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
        var reference = new SecretReference(client.Authority, new InfisicalBulkAddress(project, environment, folder));
        var authority = new InfisicalNativeAuthority(client.Authority, setup, project, environment, folder);
        InfisicalBulkSecret[] items = [new InfisicalBulkSecret(key)];
        var receipt = new InfisicalBulkReceipt(client, reference, items, InfisicalBulkOperation.Delete);
        int operation = Ledger.Begin("remove-fixture", "fixture:" + project + ":" + key);
        Ledger.Effect(operation, DispatchEvidence.PossiblyDispatched);
        bool removed = false;
        try
        {
            var result = await client.DeleteSecretsAsync(reference, items, authority, receipt, token);
            removed = result.IsSuccess && result.Value.AllApplied && receipt.Evidence == DispatchEvidence.Applied;
            return removed;
        }
        finally
        {
            Ledger.Effect(operation, receipt.Evidence, acknowledged: true);
            Ledger.ExternalCleanup("fixture:" + project + ":" + key, removed);
        }
    }

    internal void BeginChild()
    {
        NativeWorkflow.Require(produced is not null && childCreate < 0 && !Ledger.CleanupStarted);
        string target = "fixture:" + produced.ProjectId + ":" + produced.WriteKey;
        string?[] coordinates = [selection.OrganizationId, produced.ProjectId, produced.Environment, produced.Folder, produced.WriteKey];
        childCreate = Ledger.Begin("child-create", target, coordinates);
        childUpdate = Ledger.Begin("child-update", target, coordinates);
        if (produced.ApprovalKey is not null) childApproval = Ledger.Begin("child-approval");
        Ledger.Effect(childCreate, DispatchEvidence.PossiblyDispatched);
        Ledger.Effect(childUpdate, DispatchEvidence.PossiblyDispatched);
        if (childApproval >= 0) Ledger.Effect(childApproval, DispatchEvidence.PossiblyDispatched);
    }

    internal void ObserveChildReport(LocalNativeReport report)
    {
        NativeWorkflow.Require(produced is not null && childCreate >= 0 && !childObserved);
        LocalProfileConformance.ValidateReport(report, binding, this);
        childObserved = true;
        if (report.CreateEffect != DispatchEvidence.NotDispatched || report.ExecutionCompleted)
            Ledger.Effect(childCreate, report.CreateEffect, acknowledged: true);
        if (report.CreateEffect == DispatchEvidence.Applied)
            Ledger.Add("fixture:" + produced.ProjectId + ":" + produced.WriteKey, 35, null, external: true,
                coordinates: [selection.OrganizationId, produced.ProjectId, produced.Environment, produced.Folder, produced.WriteKey]);
        if (report.UpdateEffect != DispatchEvidence.NotDispatched || report.ExecutionCompleted)
            Ledger.Effect(childUpdate, report.UpdateEffect, acknowledged: true);
        if (childApproval >= 0 && (report.ApprovalEffect != DispatchEvidence.NotDispatched || report.ExecutionCompleted))
            Ledger.Effect(childApproval, report.ApprovalEffect, acknowledged: true);
    }

    internal Task<LocalProducerCleanup> CleanupAsync(CancellationToken token) =>
        Ledger.CleanupAsync((key, ct) => removals[key](ct), token);

    public async ValueTask DisposeAsync()
    {
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await CleanupAsync(deadline.Token);
        }
        foreach (var material in credentials.Values) material.Dispose();
        if (envelope is not null) Array.Clear(envelope);
        setup.Dispose();
        transport.Dispose();
        Ledger.Dispose();
    }
    private static string RandomValue() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    public override string ToString() => "[LocalNativeProof]";

    private sealed class TrialActor(string identity, string configurationId, string clientId, string purpose,
        int ttl, int maximum, int period, long uses, long bootstrapUses)
    {
        internal string Identity { get; } = identity;
        internal string ConfigurationId { get; } = configurationId;
        internal string ClientId { get; } = clientId;
        internal string Purpose { get; } = purpose;
        internal int Ttl { get; } = ttl;
        internal int Maximum { get; } = maximum;
        internal int Period { get; } = period;
        internal long Uses { get; } = uses;
        internal long BootstrapUses { get; } = bootstrapUses;
        internal string SecretId { get; set; } = "";
        internal LocalNativeTrial Issued { get; set; } = null!;
        internal bool Exchanged { get; set; }
        internal bool SecondBootstrapRejected { get; set; }
        internal bool RecoveryIssued { get; set; }
        internal int Renewals { get; set; }
    }
}

internal sealed class LocalProducerLedger : IDisposable
{
    private readonly List<Resource> resources = [];
    private readonly List<Operation> operations = [];
    private readonly FileStream? stream;
    private readonly string owner;
    private readonly string run;
    private Task<LocalProducerCleanup>? cleanup;
    private bool closing;
    internal bool CleanupStarted => closing;
    internal LocalProducerLedger(string owner, string run, string? path = null)
    {
        this.owner = owner;
        this.run = run;
        if (path is not null)
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.Read };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            stream = new(path, options);
        }
    }
    internal int Begin(string kind, string? parent = null, string?[]? coordinates = null, string? additionalParent = null)
    {
        operations.Add(new(kind, parent, additionalParent, coordinates ?? []));
        Persist();
        return operations.Count - 1;
    }
    internal void Acknowledged(int operation) => operations[operation].Acknowledged = true;
    internal void Effect(int operation, DispatchEvidence effect, bool acknowledged = false)
    {
        operations[operation].Effect = effect;
        operations[operation].Acknowledged |= acknowledged;
        Persist();
    }
    internal void Add(string handle, int order, string? parent, bool external = false, string?[]? coordinates = null)
    {
        NativeWorkflow.Require(!closing && resources.All(r => r.Handle != handle));
        resources.Add(new(handle, order, parent, external, coordinates ?? []));
        Persist();
    }
    internal void ExternalCleanup(string handle, bool removed)
    {
        var resource = resources.SingleOrDefault(r => r.Handle == handle && r.External);
        if (resource is not null) resource.Removed = removed;
        Persist();
    }
    internal void Depend(string handle, string parent)
    {
        NativeWorkflow.Require(!closing);
        resources.Single(r => r.Handle == handle).Parents.Add(parent);
        Persist();
    }
    internal Task<LocalProducerCleanup> CleanupAsync(Func<string, CancellationToken, Task<bool>> remove, CancellationToken token)
    {
        closing = true;
        return cleanup ??= CleanupCoreAsync(remove, token);
    }
    private async Task<LocalProducerCleanup> CleanupCoreAsync(Func<string, CancellationToken, Task<bool>> remove, CancellationToken token)
    {
        var blocked = new HashSet<string>(StringComparer.Ordinal);
        foreach (var operation in operations.Where(Uncertain))
            Block(operation.Parents);
        foreach (var resource in resources.OrderByDescending(r => r.Order).ThenByDescending(r => resources.IndexOf(r)))
        {
            try
            {
                if (!resource.External && !blocked.Contains(resource.Handle) && !token.IsCancellationRequested)
                    resource.Removed = await remove(resource.Handle, token);
            }
            catch { resource.Removed = false; }
            if (!resource.Removed)
            {
                Block(resource.Parents);
            }
            Persist();
        }
        int known = resources.Count(r => !r.Removed);
        int uncertain = operations.Count(Uncertain);
        return new(known == 0 && uncertain == 0 ? "complete" : "incomplete", known, uncertain);

        void Block(IEnumerable<string> handles)
        {
            var parents = new Stack<string>(handles);
            while (parents.TryPop(out string? parent))
                if (blocked.Add(parent))
                    foreach (string ancestor in resources.SingleOrDefault(r => r.Handle == parent)?.Parents ?? [])
                        parents.Push(ancestor);
        }
    }
    private static bool Uncertain(Operation operation) =>
        operation.Effect is DispatchEvidence.PossiblyDispatched or DispatchEvidence.Pending ||
        operation.Effect == DispatchEvidence.Applied && !operation.Acknowledged;
    private void Persist()
    {
        if (stream is null) return;
        byte[] row = JsonSerializer.SerializeToUtf8Bytes(new
        {
            owner,
            run,
            resources = resources.Select(r => new { r.Handle, r.Order, r.Parents, r.Removed, r.External, r.Coordinates }),
            operations = operations.Select(o => new { o.Kind, o.Parents, o.Effect, o.Acknowledged, o.Coordinates })
        }, NativeWorkflow.JsonOptions);
        try { stream.Write(row); stream.WriteByte((byte)'\n'); stream.Flush(flushToDisk: true); }
        finally { Array.Clear(row); }
    }
    public void Dispose() => stream?.Dispose();
    public override string ToString() => "[LocalProducerLedger]";
    private sealed class Resource(string handle, int order, string? parent, bool external, string?[] coordinates)
    {
        internal string Handle { get; } = handle;
        internal int Order { get; } = order;
        internal List<string> Parents { get; } = parent is null ? [] : [parent];
        internal bool Removed { get; set; }
        internal bool External { get; } = external;
        internal string?[] Coordinates { get; } = [.. coordinates];
    }
    private sealed class Operation(string kind, string? parent, string? additionalParent, string?[] coordinates)
    {
        internal string Kind { get; } = kind;
        internal string[] Parents { get; } = new[] { parent, additionalParent }.OfType<string>().ToArray();
        internal string?[] Coordinates { get; } = [.. coordinates];
        internal DispatchEvidence Effect { get; set; }
        internal bool Acknowledged { get; set; }
    }
}
