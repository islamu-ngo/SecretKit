using System.Security.Cryptography;
using System.Text;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalTemplatePrincipalCalibrationTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary, int Shape)> Cases() =>
        from c in TemplatePrincipalContract.CasesInventory()
        from shape in c.Variant.EndsWith(".value", StringComparison.Ordinal) ? new[] { 0, 1 } : new[] { 0 }
        select (c.Operation, c.Variant, c.Boundary, shape);
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary), InfisicalProjectFamilies.Bindings[operation].Member);

    [Test]
    public async Task RetainedPrincipalInventoryIsExactAndOtherGatesStayClosed()
    {
        var cases = TemplatePrincipalContract.CasesInventory().ToArray();
        await Assert.That(cases.Length).IsEqualTo(75);
        await Assert.That(cases.Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(15);
        await Assert.That(Cases().Count()).IsEqualTo(105);
        foreach (var c in cases)
            await Assert.That(TemplatePrincipalContract.Owns(Definition(c.Operation, c.Variant, c.Boundary))).IsTrue();
        foreach (var variant in new[] { "configuration.omitted", "permissions.metadata.elemMatch",
            "permission.Identity.create-token", "type.CertificateManager", "response.conditions-unprojected", "roles.empty" })
            await Assert.That(TemplatePrincipalContract.Owns(Definition(TemplatePrincipalContract.Create,
                variant, "independent-effect"))).IsFalse();
        await Assert.That(ProjectTemplatesEffects.UnavailableReason(Definition(TemplatePrincipalContract.Create,
            "configuration.omitted", "independent-effect"))).IsEqualTo("default-template-permission-policy-unestablished");
        foreach (string field in TemplatePrincipalContract.Fields)
        {
            await Assert.That(ProjectTemplatesEffects.UnavailableReason(Definition(TemplatePrincipalContract.Create,
                "ProjectTemplateConfiguration." + field + ".value", "independent-effect")))
                .IsEqualTo("template-principal-credential-observer-unavailable");
        }
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task DirectPublicSdkCalibratesMembershipCredentialCopyAndFreshAccess(string operation,
        string variant, string boundary, int shape)
    {
        await using var fixture = new InfisicalTemplatePrincipalFixture();
        var trial = await DirectAsync(fixture, operation, variant, boundary, (TemplatePrincipalShape)shape);
        await Assert.That(trial.Credentials.All(c => c.Bytes.All(b => b == 0))).IsTrue();
        await Assert.That(trial.Issued.Value.All(b => b == 0)).IsTrue();
        await CleanAsync(fixture);
        await Assert.That(fixture.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
    }
    [Test]
    [Arguments("lost-nonapplied", 0)]
    [Arguments("lost-partial", 2)]
    public async Task LostOriginalUsesCommitJournalAndRetainsPossiblyDispatched(string fault, int outcome)
    {
        await using var fixture = new InfisicalTemplatePrincipalFixture(fault);
        var result = await DirectAsync(fixture, TemplatePrincipalContract.Update,
            "ProjectTemplateConfiguration.users.value", "lost-response-no-replay");
        await Assert.That((int)result.Outcome).IsEqualTo(outcome);
        await Assert.That(result.Original?.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(result.Original?.Cancelled).IsTrue();
        await Assert.That(result.Credentials.All(c => c.Bytes.All(b => b == 0))).IsTrue();
        await Assert.That(fixture.Originals).IsEqualTo(1);
        await CleanAsync(fixture);
    }
    internal static async Task<TemplatePrincipalTrial> DirectAsync(InfisicalTemplatePrincipalFixture fixture,
        string operation, string variant, string boundary, TemplatePrincipalShape shape = TemplatePrincipalShape.Values)
    {
        using var env = fixture.Environment(shape);
        var root = fixture.Root(operation, variant, boundary, shape);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var capability = SecretMaterial.FromText("private-user-capability");
        TemplatePrincipalTrial? retained = null;
        try
        {
            var trial = await TemplatePrincipalTrial.OpenAsync(fixture.Source.CreateClient(), root, capability,
                20, t => retained = t, timeout.Token);
            var i = trial.Issued;
            await Send(() => ScopedAccessOperations.CreateGroup(root.Organization, i.GroupSlug, i.GroupSlug, "member"));
            await Send(() => ScopedAccessOperations.AddGroupUser(root.Organization, i.GroupId, i.Users[1].Username));
            await Send(() => ProjectTemplateOperations.CreateProjectTemplate(root.Organization,
                operation == TemplatePrincipalContract.Create ? i.SeedName : i.TemplateName, configuration: Config(true)));
            await Copy(false);
            await Witness(false);
            using var request = operation == TemplatePrincipalContract.Create ?
                ProjectTemplateOperations.CreateProjectTemplate(root.Organization, i.TemplateName, configuration: Config(false)) :
                ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, i.TemplateId, configuration: Config(false));
            await trial.ArmAsync(request.Target.SecondaryId!, timeout.Token);
            var client = env.CreateManagementClient();
            var receipt = client.CreateReceipt(request);
            var role = boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
            var barrier = boundary == "cancellation-boundary" ? new ProjectTokenBarrier(env.Tokens(role)) : null;
            using var cancel = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
            using var loss = boundary == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancel) : null;
            using var enteredLoss = loss?.Enter();
            var authority = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(role), root.Organization);
            Task? entered = barrier?.Entered;
            var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                receipt, cancel.Token).AsTask();
            SecretOutcome<ProjectTemplateSummary>? outcome = null;
            bool cancelled = false;
            try
            {
                if (entered is not null) { await entered.WaitAsync(timeout.Token); cancel.Cancel(); barrier!.Release(); }
                try { outcome = await execution; }
                catch (OperationCanceledException) when (!timeout.IsCancellationRequested && cancel.IsCancellationRequested)
                { cancelled = true; }
                await Assert.That(loss is null || loss.Reached).IsTrue();
            }
            finally
            {
                cancel.Cancel(); barrier?.Release();
                try { outcome ??= await execution; } catch (OperationCanceledException) { }
            }
            if (outcome is { IsSuccess: true } success)
            {
                await Assert.That(success.Value.Name).IsEqualTo(i.TemplateName);
                await Assert.That(success.Value.Id).IsEqualTo(i.TemplateId);
                await Assert.That(success.Value.IncludesPermissionConditionValues).IsFalse();
            }
            await trial.SettleAsync(new(receipt.Evidence, outcome?.Status, cancelled, request.Target.SecondaryId!), timeout.Token);
            if (trial.Outcome != TemplatePrincipalOutcome.Partial) { await Copy(true); await Witness(true); }
            return trial;

            ProjectTemplateConfiguration Config(bool baseline)
            {
                // Independently constructed typed factories, never effect Configuration/Original.
                string environment = baseline ? "baseline" : "witness";
                ProjectTemplateCollection<T>? Select<T>(string field, T value) where T : class
                {
                    if (baseline || !variant.Contains(field + ".", StringComparison.Ordinal))
                        return ProjectTemplateCollection<T>.FromValues([value]);
                    if (variant.EndsWith(".omitted", StringComparison.Ordinal)) return null;
                    if (variant.EndsWith(".null", StringComparison.Ordinal)) return ProjectTemplateCollection<T>.Null();
                    return ProjectTemplateCollection<T>.FromValues(shape == TemplatePrincipalShape.Empty ? [] : [value]);
                }
                string[] roles = baseline ? [i.ReaderRole] : [i.ReaderRole, i.MarkerRole];
                return new([new(i.ReaderRole, i.ReaderRole,
                    [new(ProjectRoleSubject.Secrets, ProjectRoleAction.Read,
                        conditions: [new(RoleConditionField.Environment, ProjectTemplateStringClause.Literal(environment)),
                            new(RoleConditionField.SecretPath, ProjectTemplateStringClause.Literal("/"))])]),
                    new(i.MarkerRole, i.MarkerRole, [])],
                    ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues(
                        [new("Baseline", "baseline", 1), new("Witness", "witness", 2), new("Outside", "outside", 3)]),
                    Select("users", new ProjectTemplateUser(i.Users[0].Username, roles)),
                    Select("groups", new ProjectTemplateGroup(i.GroupSlug, roles)),
                    projectManagedIdentities: Select("projectManagedIdentities", new ProjectTemplateManagedIdentity(i.ManagedName, roles)));
            }
            async ValueTask<T> Send<T>(Func<ManagementRequest<T>> factory) where T : notnull
            {
                using var request = factory();
                var client = env.CreateManagementClient();
                var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Setup, root.Organization, request.Target.ProjectId);
                var receipt = client.CreateReceipt(request);
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                    receipt, timeout.Token);
                await Assert.That(result.IsSuccess).IsTrue().Because(request.OperationId + ":" +
                    result.Status + ":" + fixture.HttpJournal.LastOrDefault().Status);
                await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
                return result.Value;
            }
            async ValueTask Copy(bool after)
            {
                string project = after ? i.AfterProject : i.BeforeProject, slug = after ? i.AfterSlug : i.BeforeSlug;
                string templateName = operation == TemplatePrincipalContract.Create &&
                    (!after || trial.Outcome == TemplatePrincipalOutcome.NonApplied) ? i.SeedName : i.TemplateName;
                var projectResult = await Send(() => ProjectOperations.CreateProject(root.Organization, slug, slug,
                    createDefaultEnvironments: false, template: templateName));
                await Assert.That(projectResult.Id).IsEqualTo(project);
                bool expectedManaged = !after || trial.Outcome == TemplatePrincipalOutcome.NonApplied ||
                    variant != "projectManagedIdentities.null" &&
                    !(variant.Contains("projectManagedIdentities.value", StringComparison.Ordinal) && shape == TemplatePrincipalShape.Empty) &&
                    !(operation == TemplatePrincipalContract.Create && variant == "ProjectTemplateConfiguration.projectManagedIdentities.omitted");
                if (expectedManaged)
                {
                    string identity = after ? i.AfterManaged : i.BeforeManaged;
                    await Send(() => IdentityAuthenticationOperations.AttachTokenAuth(root.Organization, identity,
                        new(accessTokenTTL: 600, accessTokenMaxTTL: 600)));
                    using var credential = await Send(() => IdentityAuthenticationOperations.CreateToken(root.Organization, identity, "witness"));
                    trial.AddCredential(identity, project, credential.Metadata.Id, credential.AccessToken);
                }
                await using var setup = env.CreateClient(NativeIdentityRole.Setup);
                using var value = TemplatePrincipalContract.Material(i.Value);
                foreach (string environment in new[] { "baseline", "witness", "outside" })
                {
                    var reference = new SecretReference(setup.Authority, new InfisicalSecretAddress(project, environment, "/", i.Key));
                    var receipt = new MutationReceipt(reference);
                    var result = await setup.CreateAsync(reference, value, receipt, timeout.Token);
                    await Assert.That(result.IsSuccess).IsTrue().Because(result.Status.ToString());
                    await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
                }
            }
            async ValueTask Witness(bool after)
            {
                await trial.BeginAsync(after, timeout.Token);
                var attempts = new List<TemplatePrincipalAttempt>();
                string project = after ? i.AfterProject : i.BeforeProject;
                string environment = after && trial.Outcome != TemplatePrincipalOutcome.NonApplied ? "witness" : "baseline";
                foreach (var credential in trial.Credentials.Where(c => c.Kind == "user" && c.Principal != i.Users[2].Principal ||
                    c.Kind == "managed" && c.Project == project))
                {
                    string field = credential.Kind == "managed" ? "projectManagedIdentities" :
                        credential.Principal == i.Users[0].Principal ? "users" : "groups";
                    bool expected = !after || trial.Outcome == TemplatePrincipalOutcome.NonApplied ||
                        !variant.Contains(field + ".", StringComparison.Ordinal) ||
                        variant.EndsWith(".omitted", StringComparison.Ordinal) && operation == TemplatePrincipalContract.Update ||
                        variant.EndsWith(".value", StringComparison.Ordinal) && shape == TemplatePrincipalShape.Values;
                    await User(credential, environment, expected);
                    await User(i.Users[2], environment, false);
                    await Host(NativeIdentityRole.Denied, environment, false);
                    await User(credential, environment, expected);
                    await User(credential, "outside", false);
                }
                await Host(NativeIdentityRole.Runtime, environment, false);
                await Host(NativeIdentityRole.Observer, environment, true);
                await trial.ObserveAsync(after, attempts.ToArray(), timeout.Token);
                async ValueTask User(TemplatePrincipalCredential c, string selectedEnvironment, bool expected)
                {
                    using var material = TemplatePrincipalContract.Material(c.Bytes);
                    await Read(new Tokens(material), c.Principal, c.CredentialId, c.Hash, selectedEnvironment, expected);
                }
                async ValueTask Host(NativeIdentityRole role, string selectedEnvironment, bool expected)
                {
                    var result = await env.Tokens(role).GetTokenAsync(timeout.Token);
                    using var credential = result.Value;
                    char[] chars = credential.Material.ExportCharacters();
                    byte[] bytes = Encoding.UTF8.GetBytes(chars);
                    string hash;
                    try { hash = TemplatePrincipalContract.HashBytes(bytes); }
                    finally { Array.Clear(chars); CryptographicOperations.ZeroMemory(bytes); }
                    await Assert.That(trial.Credentials.All(c => c.Hash != hash)).IsTrue();
                    await Read(env.Tokens(role), role == NativeIdentityRole.Runtime ? root.Authorities.Runtime :
                        role == NativeIdentityRole.Denied ? root.Authorities.Denied : root.Authorities.Observer,
                        "host", hash, selectedEnvironment, expected);
                }
                async ValueTask Read(IInfisicalTokenSource tokens, string actor, string credential, string hash,
                    string selectedEnvironment, bool expected)
                {
                    await using var client = new InfisicalClient(env.Origin, tokens, new() { AllowLoopbackDevelopmentHttp = true });
                    var result = await client.ReadAsync(new(client.Authority,
                        new InfisicalSecretAddress(project, selectedEnvironment, "/", i.Key)), timeout.Token);
                    string? valueHash = null;
                    if (result.IsSuccess)
                    {
                        using var read = result.Value;
                        char[] chars = read.Material.ExportCharacters();
                        byte[] bytes = Encoding.UTF8.GetBytes(chars);
                        try { valueHash = TemplatePrincipalContract.HashBytes(bytes); }
                        finally { Array.Clear(chars); CryptographicOperations.ZeroMemory(bytes); }
                    }
                    await Assert.That(expected ? result.IsSuccess && valueHash == i.ValueHash : result.Status == SecretStatus.Denied).IsTrue();
                    attempts.Add(new(actor, credential, hash, project, selectedEnvironment, expected, valueHash));
                }
            }
        }
        finally
        {
            if (retained is not null) await retained.DisposeAsync();
        }
    }
    internal static async Task CleanAsync(InfisicalTemplatePrincipalFixture fixture)
    {
        await Assert.That(fixture.Closes).IsEqualTo(1);
        await Assert.That(fixture.Remaining).IsEqualTo(0);
        await Assert.That(fixture.Registrations).IsEqualTo(0);
        await Assert.That(fixture.BorrowedPreserved).IsTrue();
        // This covers our tracked private/transport byte arrays, not managed
        // strings returned by JSON/GetString, headers, BCL/TLS or socket copies.
        await Assert.That(fixture.Copies.All(b => b.All(x => x == 0))).IsTrue();
    }
    private sealed class Tokens(SecretMaterial material) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(material.Copy())));
        }
    }
}
