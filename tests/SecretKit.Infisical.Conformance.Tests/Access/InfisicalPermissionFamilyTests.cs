using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalPermissionFamilyTests
{
    private const string Org = "00000000-0000-0000-0000-000000000001";
    private const string Admin = "00000000-0000-0000-0000-000000000002";
    private const string Observer = "00000000-0000-0000-0000-000000000003";
    private const string Runtime = "00000000-0000-0000-0000-000000000004";
    private const string Denied = "00000000-0000-0000-0000-000000000005";
    private const string Setup = "00000000-0000-0000-0000-000000000006";
    private const string Date = "2026-10-12T00:00:00.000Z";
    private const string ScopedUser = "00000000-0000-0000-0000-000000000007";
    private const string UnassignedUser = "00000000-0000-0000-0000-000000000008";

    [Test]
    public async Task OrganizationEligibilityUsesNativeMembershipShapes()
    {
        await using var backend = new Backend();
        using NativeEnvironment environment = Environment(backend.Origin);
        var context = new ProjectFamilyContext(environment, "ScopedAccess",
            Definition("ScopedAccessOperations.AddGroupUser", "input.organizationId-groupId-username"), new());
        var result = await context.ExecuteAsync(() => OrganizationMembershipOperations.ListOrganizationMemberships(Org),
            NativeIdentityRole.Observer, CancellationToken.None);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Items.Count).IsEqualTo(3);
        await Assert.That(result.Value.Items.Count(m => m.User?.Id == Runtime &&
            m.User.Username == "fixture-runtime" && m.IsActive == true && m.Status == "accepted")).IsEqualTo(1);
    }

    [Test]
    [Arguments("RoleChangeOperations.UpdateOrganizationRole")]
    [Arguments("RoleChangeOperations.UpdateProjectRole")]
    [Arguments("IdentityPrivilegeChangeOperations.UpdateLegacyPrivilege")]
    [Arguments("IdentityPrivilegeChangeOperations.UpdateProjectPrivilege")]
    public async Task EmptyPermissionUpdatesMustRevokeEstablishedAccess(string operation)
    {
        foreach (string caseName in new[] { "independent-effect", "lost-response-no-replay" })
        {
            await using var backend = new Backend("ignore-update");
            using NativeEnvironment environment = Environment(backend.Origin);
            var result = await RunAsync(environment, Definition(operation, "permissions.empty", caseName));
            await Assert.That(result.ReasonCode).IsEqualTo(caseName == "lost-response-no-replay" ?
                "effect-mismatch" : "contract-mismatch").Because(result.ReasonCode);
            await Assert.That(backend.OwnedCount).IsEqualTo(0);
        }
    }

    [Test]
    [Arguments("RoleChangeOperations.CreateProjectRole", "extra-action")]
    [Arguments("RoleChangeOperations.CreateProjectRole", "extra-subject")]
    [Arguments("IdentityPrivilegeChangeOperations.CreateProjectPrivilege", "extra-action")]
    [Arguments("IdentityPrivilegeChangeOperations.CreateProjectPrivilege", "extra-subject")]
    public async Task AdditionalPermissionSelectionsCannotPass(string operation, string mode)
    {
        await using var backend = new Backend(mode);
        using NativeEnvironment environment = Environment(backend.Origin);
        var result = await RunAsync(environment, Definition(operation,
            operation.StartsWith("RoleChangeOperations.", StringComparison.Ordinal) ? "permissions.action.array" : "permissions.array"));
        await Assert.That(result.ReasonCode).IsEqualTo("contract-mismatch").Because(result.ReasonCode);
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("duplicate-privileges")]
    [Arguments("omit-peer-privilege")]
    public async Task PrivilegeListsRequireUniqueKnownRows(string mode)
    {
        await using var backend = new Backend(mode);
        using NativeEnvironment environment = Environment(backend.Origin);
        var result = await RunAsync(environment, Definition("IdentityPrivilegeOperations.ListProjectPrivileges", "collection.bounded"));
        await Assert.That(result.ReasonCode).IsEqualTo("contract-mismatch").Because(result.ReasonCode);
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    private static async Task<NativeCaseDefinition[]> DefinitionsAsync()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        using JsonDocument inventory = JsonDocument.Parse(await File.ReadAllTextAsync(
            Path.Combine(root, "docs/internal/releases/admission/infisical.json")));
        return inventory.RootElement.GetProperty("operations").EnumerateArray()
            .Where(o => InfisicalPermissionFamilies.Owns(o.GetProperty("id").GetString()!))
            .SelectMany(o => o.GetProperty("variants").EnumerateArray().SelectMany(v =>
                o.GetProperty("requiredCases").EnumerateArray().Select(c => new NativeCaseDefinition(
                    new("Infisical", o.GetProperty("id").GetString()!, v.GetString()!, "local", c.GetString()!),
                    o.GetProperty("member").GetString()!)))).ToArray();
    }

    [Test]
    public async Task CompilerDenominatorIsExactAndUnavailableCasesCannotPass()
    {
        NativeCaseDefinition[] expected = await DefinitionsAsync();
        await Assert.That(expected.Length).IsEqualTo(7444);
        await Assert.That(expected.Select(d => d.Key.Operation).Distinct().Count()).IsEqualTo(35);
        await Assert.That(expected.Select(d => (d.Key.Operation, d.Key.Variant)).Distinct().Count()).IsEqualTo(1499);
        await Assert.That(expected.All(InfisicalPermissionFamilies.Valid)).IsTrue();
        await Assert.That(expected.Count(d => InfisicalPermissionFamilies.UnavailableReason(d) is null)).IsEqualTo(727);
        await Assert.That(expected.Where(d => InfisicalPermissionFamilies.UnavailableReason(d) is null)
            .Select(d => (d.Key.Operation, d.Key.Variant)).Distinct().Count()).IsEqualTo(154);
        using NativeEnvironment environment = Environment(new Uri("http://127.0.0.1:1/"), inputs: false);
        var registry = new NativeCaseRegistry();
        InfisicalPermissionFamilies.Register(registry, environment, expected);
        IReadOnlyList<NativeCaseResult> results = await NativeCaseRunner.RunAsync(registry, expected, CancellationToken.None);
        await Assert.That(results.All(r => !r.Passed && r.ReasonCode is "missing-input" or "observer-unavailable")).IsTrue();
        await Assert.That(results.Count(r => r.ReasonCode == "observer-unavailable")).IsEqualTo(6717);
    }

    [Test]
    [Arguments("member")]
    [Arguments("variant")]
    [Arguments("case")]
    [Arguments("provider")]
    [Arguments("scope")]
    [Arguments("identities")]
    public async Task InvalidSelectionFailsBeforeAnyTransport(string defect)
    {
        NativeCaseDefinition d = Definition("RoleChangeOperations.CreateProjectRole", "condition.literal");
        d = defect switch
        {
            "member" => d with { Member = d.Member + ".wrong" },
            "variant" => d with { Key = d.Key with { Variant = "unadmitted" } },
            "case" => d with { Key = d.Key with { Case = "unadmitted" } },
            "provider" => d with { Key = d.Key with { Provider = "AzureKeyVault" } },
            "scope" => d with { Key = d.Key with { Scope = "unselected" } },
            _ => d
        };
        using NativeEnvironment environment = Environment(new Uri("http://127.0.0.1:1/"), duplicate: defect == "identities");
        NativeCaseResult result = await RunAsync(environment, d);
        await Assert.That(result.ReasonCode).IsEqualTo(defect is "scope" or "identities" ? "missing-input" : "contract-mismatch");
    }

    [Test]
    public async Task EveryExecutableVariantAndBoundaryUsesActualAdaptersAndOwnedState()
    {
        var failures = new List<string>();
        foreach (NativeCaseDefinition d in (await DefinitionsAsync())
            .Where(d => InfisicalPermissionFamilies.UnavailableReason(d) is null && !TemporalPrivilegeEffects.Owns(d)))
        {
            await using var backend = new Backend();
            using NativeEnvironment environment = Environment(backend.Origin);
            NativeCaseResult result = await RunAsync(environment, d);
            int mutations = InfisicalPermissionFamilies.Bindings[d.Key.Operation].Mutation &&
                d.Key.Case is "selected-contract" or "independent-effect" or "lost-response-no-replay" ? 1 : 0;
            if (!result.Passed || backend.AdministrativeMutations != mutations || backend.OwnedCount != 0)
                failures.Add(d.Key.Operation + "|" + d.Key.Variant + "|" + d.Key.Case + "|" + result.ReasonCode +
                    "|mutations=" + backend.AdministrativeMutations + "|owned=" + backend.OwnedCount + "|" + backend.Trace);
        }
        await Assert.That(failures.Count).IsEqualTo(0).Because(string.Join("\n", failures.Take(15)));
    }

    [Test]
    [Arguments("access-denied", "effect-mismatch")]
    [Arguments("outside-allowed", "effect-mismatch")]
    [Arguments("drift", "effect-mismatch")]
    [Arguments("cleanup", "cleanup-incomplete")]
    [Arguments("wrong-coordinate", "contract-mismatch")]
    public async Task RoleAcknowledgementCannotReplacePermissionOrReadback(string mode, string reason)
    {
        await using var backend = new Backend(mode);
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment,
            Definition("RoleChangeOperations.CreateProjectRole", "condition.literal"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(reason).Because(backend.Trace);
    }

    [Test]
    public async Task NegativePolicyAndReadbacksNeverConfirmUnknownPrimaryShapes()
    {
        await using var backend = new Backend();
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment,
            Definition("IdentityPrivilegeChangeOperations.CreateProjectPrivilege", "permission.scalar-crud"));
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode + "|" + backend.Trace);
        string[] measured = ["selected-runtime-identity",
            "selected-administrative-identity", "scoped-administrative-rights", "permission-policy-entitlement",
            "intended-principal-permission-observer", "approved-sandbox-cleanup"];
        await Assert.That(environment.PrerequisiteResults(measured.Select(p =>
            new NativePrerequisiteKey("Infisical", "local", p)).ToArray()).All(p => p.Confirmed)).IsTrue();
        await Assert.That(environment.PrerequisiteResults([
            new("Infisical", "local", "separate-observer-identity"),
            new("Infisical", "local", "primary-permission-response-shapes"),
            new("Infisical", "local", "owned-origin-api-revision")]).All(p => !p.Confirmed)).IsTrue();
    }

    public static IEnumerable<(string Operation, string Variant, string Case, string Duration)> TemporalPrivilegeCases()
    {
        string[] cases = ["selected-contract", "independent-effect", "denied-authority",
            "cancellation-boundary", "lost-response-no-replay"];
        foreach (string operation in new[] { "CreateTemporaryLegacyPrivilege", "UpdateLegacyPrivilege",
            "CreateProjectPrivilege", "UpdateProjectPrivilege" })
            foreach ((string label, string duration) in new[] { ("minute", "1m"), ("hour", "1h"), ("day", "1d") })
                foreach (string caseName in cases)
                    yield return (operation, "lifetime.relative-" + label, caseName, duration);
        foreach (string variant in new[] { "permission.scalar-crud", "permissions.array", "permissions.empty" })
            foreach (string caseName in cases)
                yield return ("CreateTemporaryLegacyPrivilege", variant, caseName, "1m");
        foreach (string caseName in cases.Where(c => c != "lost-response-no-replay"))
            foreach (string duration in new[] { "1m", "1h", "1d" })
                yield return ("GetProjectPrivilegeBySlug", "response.relative", caseName, duration);
    }

    [Test]
    [MethodDataSource(nameof(TemporalPrivilegeCases))]
    public async Task TemporalPrivilegeRequiresNativeRowsAndIndependentExpiry(
        string operation, string variant, string caseName, string duration)
    {
        await using var backend = new Backend();
        var expiry = new ControlledPrivilegeExpiryObserver(backend);
        using NativeEnvironment environment = Environment(backend.Origin, temporalDuration: duration);
        NativeCaseDefinition definition = Definition("IdentityPrivilegeChangeOperations." + operation, variant, caseName);
        NativeCaseResult result = await RunAsync(environment, definition, expiry);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode + "|" + backend.Trace);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(expiry.Samples.SequenceEqual(Enum.GetValues<PrivilegeExpiryPhase>())).IsTrue();
        await Assert.That(expiry.CloseCalls).IsEqualTo(1);
        await Assert.That(expiry.Registrations).IsEqualTo(0);
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
        PrivilegeExpiryArm arm = expiry.Arm!;
        PrivilegeExpiryAttempt attempt = arm.Intent.Attempt;
        await Assert.That(attempt.Operation).IsEqualTo(definition.Key.Operation);
        await Assert.That(attempt.CaseIdentity).IsEqualTo(definition.Key.Identity);
        await Assert.That(attempt.Source).IsEqualTo(PrivilegeExpirySource.ControlledFixture);
        await Assert.That(attempt.Version).IsEqualTo(operation.Contains("Legacy", StringComparison.Ordinal) ?
            PrivilegeExpiryVersion.LegacyV1 : PrivilegeExpiryVersion.ProjectV2);
        await Assert.That(attempt.OrganizationId).IsEqualTo(Org);
        await Assert.That(attempt.IdentityId).IsEqualTo(Runtime);
        await Assert.That(attempt.ProjectId == attempt.ProjectSlug).IsFalse();
        await Assert.That(attempt.PrivilegeSlug.Length).IsGreaterThan(0);
        await Assert.That(attempt.MembershipId.Length).IsGreaterThan(0);
        await Assert.That(attempt.ExistingPrivilegeId is not null).IsEqualTo(operation.StartsWith("Update", StringComparison.Ordinal));
        await Assert.That(arm.SourceIdentity).IsEqualTo("fixture-expiry-source");
        await Assert.That(arm.Intent.RelativeDuration).IsEqualTo(duration);
        await Assert.That(arm.StartsAt - arm.ArmedAt).IsEqualTo(TimeSpan.FromSeconds(5));
        await Assert.That(arm.EndsAt - arm.StartsAt).IsEqualTo(Duration(duration));
        bool read = operation == "GetProjectPrivilegeBySlug";
        bool applied = read || caseName is not ("denied-authority" or "cancellation-boundary");
        await Assert.That(expiry.CompleteCalls).IsEqualTo(caseName == "cancellation-boundary" && !read ? 0 : 1);
        await Assert.That(expiry.AppliedMutations).IsEqualTo(applied ? 1 : 0);
        await Assert.That(expiry.CapturedBaseline!["roles"]!.AsArray().All(r =>
            r!["role"]!.GetValue<string>() == "no-access" && !r["isTemporary"]!.GetValue<bool>())).IsTrue();
        await Assert.That(expiry.CapturedBaseline["roles"]!.AsArray().Count).IsEqualTo(1);
        if (applied)
        {
            JsonObject row = expiry.CapturedPrivilege!;
            await Assert.That(row["isTemporary"]!.GetValue<bool>()).IsTrue();
            await Assert.That(row["temporaryMode"]!.GetValue<string>()).IsEqualTo("relative");
            await Assert.That(row["temporaryRange"]!.GetValue<string>()).IsEqualTo(duration);
            await Assert.That(DateTimeOffset.Parse(row["temporaryAccessStartTime"]!.GetValue<string>())).IsEqualTo(arm.StartsAt);
            await Assert.That(DateTimeOffset.Parse(row["temporaryAccessEndTime"]!.GetValue<string>())).IsEqualTo(arm.EndsAt);
            await Assert.That(row["projectMembershipId"]!.GetValue<string>()).IsEqualTo(attempt.MembershipId);
            await Assert.That(row["identityId"]!.GetValue<string>()).IsEqualTo(Runtime);
            await Assert.That(row["slug"]!.GetValue<string>()).IsEqualTo(attempt.PrivilegeSlug);
            await Assert.That(expiry.Completions.Single().PrivilegeId).IsEqualTo(row["id"]!.GetValue<string>());
            await Assert.That(backend.PrivilegeReadbacks.Any(r => r["id"]!.GetValue<string>() ==
                row["id"]!.GetValue<string>() && r["temporaryRange"]?.GetValue<string>() == duration)).IsTrue();
        }
        foreach (PrivilegeExpiryPhase phase in Enum.GetValues<PrivilegeExpiryPhase>())
        {
            DateTimeOffset time = PhaseTime(arm, phase);
            int expected = phase == PrivilegeExpiryPhase.Active && applied && variant != "permissions.empty" ? 200 : 403;
            await Assert.That(backend.Accesses.Any(a => a.Project == attempt.ProjectId &&
                a.Environment == "witness" && a.Credential == "runtime" && a.Time == time && a.Status == expected)).IsTrue();
            await Assert.That(backend.Accesses.Any(a => a.Project == attempt.ProjectId &&
                a.Environment == "outside" && a.Credential == "runtime" && a.Time == time && a.Status == 403)).IsTrue();
            await Assert.That(backend.Accesses.Any(a => a.Project != attempt.ProjectId &&
                a.Credential == "runtime" && a.Time == time && a.Status == 200)).IsTrue();
            await Assert.That(backend.Accesses.Any(a => a.Project == attempt.ProjectId &&
                a.Credential == "denied" && a.Time == time && a.Status == 403)).IsTrue();
        }
    }

    [Test]
    [Arguments("permission.Secrets.read")]
    [Arguments("permission.Secrets.readValue")]
    [Arguments("permission.Secrets.describeSecret")]
    public async Task TemporalPrivilegeSupportedSecretsReadsRetainTheirExactAction(string variant)
    {
        await using var backend = new Backend();
        using NativeEnvironment environment = Environment(backend.Origin);
        NativeCaseResult result = await RunAsync(environment,
            Definition("IdentityPrivilegeChangeOperations.CreateProjectPrivilege", variant));
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(backend.Accesses.Any(a => a.Credential == "runtime" && a.Status == 200)).IsTrue();
        await Assert.That(backend.Accesses.Any(a => a.Credential == "runtime" &&
            a.Environment == "outside" && a.Status == 403)).IsTrue();
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    private static TimeSpan Duration(string range) => range switch
    {
        "1m" => TimeSpan.FromMinutes(1),
        "1h" => TimeSpan.FromHours(1),
        "1d" => TimeSpan.FromDays(1),
        _ => throw new InvalidOperationException("fixture-duration")
    };

    public static IEnumerable<(string Operation, string Fault, string Case)> TemporalPrivilegeFaults()
    {
        foreach (string operation in new[] { "CreateTemporaryLegacyPrivilege", "UpdateLegacyPrivilege",
            "CreateProjectPrivilege", "UpdateProjectPrivilege" })
            foreach (string fault in new[] { "early-activation", "delayed-activation", "expiry-ignored",
                "token-expired-control", "wrong-row", "wrong-member", "wrong-identity", "wrong-slug",
                "wrong-temporal-metadata", "extra-action", "extra-subject", "outside-allowed",
                "access-denied", "wrong-schedule", "wrong-source", "wrong-epoch", "wrong-attempt",
                "wrong-window-epoch", "wrong-phase", "wrong-window-time", "wrong-fence-sequence",
                "wrong-window-sequence", "wrong-fence-slug", "unarmed", "missing-event",
                "missing-terminal-fence", "missing-permanent-baseline", "cleanup-residue",
                "cleanup-pending", "cleanup-inventory", "lost-arm", "false-denied-commit" })
                yield return (operation, fault, fault == "false-denied-commit" ? "denied-authority" : "independent-effect");
        foreach (string operation in new[] { "CreateTemporaryLegacyPrivilege", "CreateProjectPrivilege" })
            yield return (operation, "expiry-ignored", "lost-response-no-replay");
    }

    [Test]
    [MethodDataSource(nameof(TemporalPrivilegeFaults))]
    public async Task TemporalPrivilegeRejectsIndependentCounterexamples(string operation, string fault, string caseName)
    {
        await using var backend = new Backend(fault);
        var expiry = new ControlledPrivilegeExpiryObserver(backend, fault);
        using NativeEnvironment environment = Environment(backend.Origin, temporalDuration: "1m");
        NativeCaseResult result = await RunAsync(environment,
            Definition("IdentityPrivilegeChangeOperations." + operation, "lifetime.relative-minute", caseName), expiry);
        await Assert.That(result.Passed).IsFalse();
        // An unavailable return has not dispatched or sampled this counterexample.
        await Assert.That(result.ReasonCode == "observer-unavailable").IsFalse().Because(fault);
        await Assert.That(expiry.LastAttempt is not null).IsTrue();
        await Assert.That(expiry.CloseCalls).IsEqualTo(1);
        await Assert.That(expiry.Registrations).IsEqualTo(fault == "cleanup-residue" ? 1 : 0);
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
        if (fault == "lost-arm") await Assert.That(expiry.CompleteCalls).IsEqualTo(0);
        if (fault == "false-denied-commit")
        {
            await Assert.That(expiry.AppliedMutations).IsEqualTo(1);
            await Assert.That(expiry.Completions.Single().Disposition).IsEqualTo(PrivilegeExpiryDisposition.Applied);
        }
        if (fault is "cleanup-residue" or "cleanup-pending" or "cleanup-inventory")
            await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
    }

    [Test]
    [Arguments("missing-temporal")]
    [Arguments("missing-duration")]
    [Arguments("missing-lead")]
    [Arguments("missing-source")]
    [Arguments("wrong-duration")]
    [Arguments("zero-lead")]
    [Arguments("excess-lead")]
    [Arguments("bad-source")]
    [Arguments("excess-budget")]
    [Arguments("native-budget")]
    public async Task TemporalPrivilegeRejectsInvalidInputsBeforeArming(string fault)
    {
        await using var backend = new Backend();
        var expiry = new ControlledPrivilegeExpiryObserver(backend);
        using NativeEnvironment environment = Environment(backend.Origin, temporalDuration: "1m", temporalFault: fault);
        NativeCaseResult result = await RunAsync(environment, Definition(
            "IdentityPrivilegeChangeOperations.CreateProjectPrivilege",
            fault == "native-budget" ? "lifetime.relative-day" : "lifetime.relative-minute"), expiry);
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(expiry.LastAttempt is null).IsTrue();
        await Assert.That(backend.AdministrativeMutations).IsEqualTo(0);
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    [Test]
    public async Task TemporalPrivilegeControlledSourceRequiresExplicitInjection()
    {
        await using var backend = new Backend();
        using NativeEnvironment environment = Environment(backend.Origin, temporalDuration: "1m");
        NativeCaseResult result = await RunAsync(environment, Definition(
            "IdentityPrivilegeChangeOperations.CreateProjectPrivilege", "lifetime.relative-minute"));
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    [Test]
    [Arguments(true, "1m", "good")]
    [Arguments(true, "1h", "good")]
    [Arguments(true, "1d", "good")]
    [Arguments(false, "1m", "good")]
    [Arguments(false, "1h", "good")]
    [Arguments(false, "1d", "good")]
    [Arguments(true, "1m", "early-activation")]
    [Arguments(false, "1m", "early-activation")]
    [Arguments(true, "1m", "delayed-activation")]
    [Arguments(false, "1m", "delayed-activation")]
    [Arguments(true, "1m", "expiry-ignored")]
    [Arguments(false, "1m", "expiry-ignored")]
    [Arguments(true, "1m", "token-expired-control")]
    [Arguments(false, "1m", "token-expired-control")]
    public async Task TemporalPrivilegeFixtureClockDrivesActualSdkAccessAndMetadata(bool legacy, string duration, string fault)
    {
        await using var backend = new Backend(fault);
        var expiry = new ControlledPrivilegeExpiryObserver(backend, fault);
        using NativeEnvironment environment = Environment(backend.Origin, temporalDuration: duration);
        NativeCaseDefinition definition = Definition("IdentityPrivilegeChangeOperations." +
            (legacy ? "CreateTemporaryLegacyPrivilege" : "CreateProjectPrivilege"), "lifetime.relative-minute");
        var context = new ProjectFamilyContext(environment, "IdentityPrivilegeChanges", definition, new());
        var control = new ProjectFamilyContext(environment, "IdentityPrivilegeChanges", definition, new());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        CancellationToken token = deadline.Token;
        PrivilegeExpiryAttempt? attempt = null;
        LegacyPrivilegeSelection? selection = null;
        string? privilegeId = null;
        try
        {
            await context.EnsureProjectAsync(token);
            MembershipSummary member = await context.NeedAsync(() => MembershipOperations.AddProjectIdentity(
                Org, context.ProjectId, Runtime, new MembershipRoleSelection(roles: [new("no-access")])),
                NativeIdentityRole.Setup, token);
            await control.EnsureProjectAsync(token, runtimeMember: true);
            PermissionWitness witness = await PermissionWitness.CreateAsync(context, token);
            ProjectCanary controlCanary = await ProjectCanary.CreateAsync(control, control.ProjectId, "witness", token);
            await Assert.That(await witness.ObserveAsync(false, token)).IsTrue();
            await Assert.That(await controlCanary.ReadAsync(NativeIdentityRole.Runtime, true, token)).IsTrue();
            string slug = ProjectFamilyContext.FreshName();
            attempt = new(Guid.NewGuid().ToString(), "fixture-sdk-clock", definition.Key.Operation,
                legacy ? PrivilegeExpiryVersion.LegacyV1 : PrivilegeExpiryVersion.ProjectV2,
                Org, context.ProjectId, context.ProjectSlug, Runtime, member.Id, slug, null,
                PrivilegeExpirySource.ControlledFixture);
            selection = new(Org, context.ProjectId, context.ProjectSlug, Runtime, member.Id);
            PrivilegeExpiryArm arm = await expiry.ArmAsync(new(attempt, duration, 5), token);
            IdentityPrivilegeSummary created = await context.NeedAsync(() => legacy ?
                IdentityPrivilegeChangeOperations.CreateTemporaryLegacyPrivilege(selection,
                    new(slug, permissions: [new(ProjectRoleSubject.Secrets, LegacyPrivilegeAction.Read, new("witness", "/"))]),
                    PrivilegeLifetime.Temporary(duration, arm.StartsAt)) :
                IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection,
                    new(PermissionWitness.Policy("permission.scalar-crud"),
                        PrivilegeLifetime.Temporary(duration, arm.StartsAt), slug)),
                NativeIdentityRole.Administrative, token);
            privilegeId = created.Id;
            PrivilegeExpiryFence fence = await expiry.CompleteAsync(arm, token);
            await Assert.That(fence.Disposition).IsEqualTo(PrivilegeExpiryDisposition.Applied);
            await Assert.That(fence.PrivilegeId).IsEqualTo(created.Id);
            IdentityPrivilegeSummary readback = await context.NeedAsync(() => legacy ?
                LegacyIdentityPrivilegeOperations.GetPrivilege(selection, slug) :
                IdentityPrivilegeChangeOperations.GetProjectPrivilegeBySlug(selection, slug),
                NativeIdentityRole.Observer, token);
            await Assert.That(readback.Id).IsEqualTo(created.Id);
            await Assert.That(readback.IsTemporary).IsTrue();
            await Assert.That(readback.Mode).IsEqualTo("relative");
            await Assert.That(readback.Range).IsEqualTo(duration);
            await Assert.That(DateTimeOffset.Parse(readback.StartsAt!)).IsEqualTo(arm.StartsAt);
            await Assert.That(DateTimeOffset.Parse(readback.EndsAt!) - DateTimeOffset.Parse(readback.StartsAt!))
                .IsEqualTo(Duration(duration));
            await Assert.That(PermissionPrivilegeScenario.PermissionMetadata(readback.Permissions, "permission.scalar-crud")).IsTrue();
            foreach (PrivilegeExpiryPhase phase in Enum.GetValues<PrivilegeExpiryPhase>())
            {
                PrivilegeExpiryObservation<bool> observation = await expiry.ObserveAsync(fence, phase, async ct =>
                    await witness.ObserveAsync(phase == PrivilegeExpiryPhase.Active, ct) &&
                    await controlCanary.ReadAsync(NativeIdentityRole.Runtime, true, ct), token);
                bool counterexample = fault == "early-activation" && phase == PrivilegeExpiryPhase.BeforeActivation ||
                    fault == "delayed-activation" && phase == PrivilegeExpiryPhase.Active ||
                    fault is "expiry-ignored" or "token-expired-control" && phase == PrivilegeExpiryPhase.Expired;
                await Assert.That(observation.Sample).IsEqualTo(!counterexample);
                await Assert.That(observation.Window.OpenedAt).IsEqualTo(PhaseTime(arm, phase));
            }
            await Assert.That(expiry.AppliedMutations).IsEqualTo(1);
            await Assert.That(backend.AdministrativeMutations).IsEqualTo(1);
        }
        finally
        {
            if (attempt is not null) await expiry.CloseAsync(attempt, CancellationToken.None);
            if (selection is not null && privilegeId is not null)
                await context.NeedAsync(() => legacy ?
                    LegacyIdentityPrivilegeOperations.DeletePrivilege(selection, attempt!.PrivilegeSlug) :
                    IdentityPrivilegeOperations.DeleteProjectPrivilege(Org, selection.ProjectId, Runtime, privilegeId),
                    NativeIdentityRole.Setup, CancellationToken.None);
            await control.CleanupAsync();
            await context.CleanupAsync();
        }
        await Assert.That(expiry.Registrations).IsEqualTo(0);
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("minimum-lead", 1)]
    [Arguments("maximum-lead", 300)]
    public async Task TemporalPrivilegeControlledDayDoesNotRequireFullIntervalCaseBudget(string setting, int lead)
    {
        await using var backend = new Backend();
        var expiry = new ControlledPrivilegeExpiryObserver(backend);
        using NativeEnvironment environment = Environment(backend.Origin, temporalDuration: "1d", temporalFault: setting);
        NativeCaseResult result = await RunAsync(environment, Definition(
            "IdentityPrivilegeChangeOperations.CreateProjectPrivilege", "lifetime.relative-day"), expiry);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(expiry.Arm!.StartsAt - expiry.Arm.ArmedAt).IsEqualTo(TimeSpan.FromSeconds(lead));
        await Assert.That(expiry.Arm.EndsAt - expiry.Arm.StartsAt).IsEqualTo(TimeSpan.FromDays(1));
        await Assert.That(expiry.CloseCalls).IsEqualTo(1);
        await Assert.That(backend.OwnedCount).IsEqualTo(0);
    }

    private static DateTimeOffset PhaseTime(PrivilegeExpiryArm arm, PrivilegeExpiryPhase phase) => phase switch
    {
        PrivilegeExpiryPhase.BeforeActivation => arm.ArmedAt,
        PrivilegeExpiryPhase.Active => arm.StartsAt,
        _ => arm.EndsAt
    };

    private static NativeCaseDefinition Definition(string operation, string variant, string caseName = "independent-effect")
    {
        string id = "i.management." + operation;
        return new(new("Infisical", id, variant, "local", caseName), InfisicalPermissionFamilies.Bindings[id].Member);
    }

    private static async Task<NativeCaseResult> RunAsync(NativeEnvironment environment, NativeCaseDefinition d,
        IPrivilegeExpiryObserver? observer = null)
    {
        var registry = new NativeCaseRegistry();
        InfisicalPermissionFamilies.Register(registry, environment, [d], observer);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        return (await NativeCaseRunner.RunAsync(registry, [d], deadline.Token)).Single();
    }

    private static NativeEnvironment Environment(Uri origin, bool inputs = true, bool duplicate = false,
        string? temporalDuration = null, string temporalFault = "good")
    {
        var families = new Dictionary<string, object>();
        if (inputs)
            foreach (string family in new[] { "IdentityPrivilegeChanges", "IdentityPrivileges", "LegacyIdentityPrivileges",
                "RoleChanges", "ScopedAccess" })
                families.Add("C08-IM-" + family, new
                {
                    scopes = new Dictionary<string, object>
                    {
                        ["local"] = new
                        {
                            organizationId = Org,
                            setupIdentityId = Setup,
                            runtimeIdentityId = Runtime,
                            deniedIdentityId = duplicate ? Runtime : Denied,
                            administrativeIdentityId = Admin,
                            observerIdentityId = Observer,
                            runtimeUserId = Runtime,
                            runtimeUsername = "fixture-runtime",
                            scopedAccessUserId = ScopedUser,
                            scopedAccessUsername = "z-other-user",
                            scopedAccessUnassignedUserId = UnassignedUser,
                            scopedAccessUnassignedUsername = "eligible-user"
                        }
                    }
                });
        JsonObject settings = JsonSerializer.SerializeToNode(new
        {
            origin = origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families
        })!.AsObject();
        if (temporalDuration is not null)
        {
            JsonObject scope = settings["families"]!["C08-IM-IdentityPrivilegeChanges"]!["scopes"]!["local"]!.AsObject();
            scope["caseTimeoutSeconds"] = 120;
            scope["temporal"] = new JsonObject
            {
                ["nativeDuration"] = temporalDuration,
                ["activationLeadSeconds"] = 5,
                ["sourceProfile"] = "ControlledFixture"
            };
            JsonObject temporal = scope["temporal"]!.AsObject();
            switch (temporalFault)
            {
                case "missing-temporal": scope.Remove("temporal"); break;
                case "missing-duration": temporal.Remove("nativeDuration"); break;
                case "missing-lead": temporal.Remove("activationLeadSeconds"); break;
                case "missing-source": temporal.Remove("sourceProfile"); break;
                case "wrong-duration": temporal["nativeDuration"] = "1h"; break;
                case "zero-lead": temporal["activationLeadSeconds"] = 0; break;
                case "excess-lead": temporal["activationLeadSeconds"] = 301; break;
                case "bad-source": temporal["sourceProfile"] = "local-clock"; break;
                case "excess-budget": scope["caseTimeoutSeconds"] = 901; break;
                case "minimum-lead": temporal["activationLeadSeconds"] = 1; break;
                case "maximum-lead": temporal["activationLeadSeconds"] = 300; scope["caseTimeoutSeconds"] = 900; break;
                case "native-budget": temporal["sourceProfile"] = "NativeProvider"; temporal["nativeDuration"] = "1d"; break;
            }
        }
        return NativeEnvironment.Create(JsonSerializer.SerializeToElement(settings));
    }

    private sealed class PrivilegeClock : TimeProvider
    {
        private DateTimeOffset now = new(2026, 10, 13, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => now;
        internal event Action? Changed;
        internal void AdvanceTo(DateTimeOffset value)
        {
            if (value < now) throw new InvalidOperationException("fixture-clock-regression");
            now = value;
            Changed?.Invoke();
        }
    }

    private sealed class ControlledPrivilegeExpiryObserver : IPrivilegeExpiryObserver
    {
        private readonly Backend backend;
        private readonly string fault;
        private readonly Dictionary<string, PrivilegeExpiryArm> registrations = [];
        private readonly Dictionary<string, TaskCompletionSource<PrivilegeExpiryFence>> terminals = [];
        private readonly Dictionary<string, PrivilegeExpiryAttempt> closed = [];
        private long sequence;
        internal PrivilegeExpiryArm? Arm { get; private set; }
        internal PrivilegeExpiryAttempt? LastAttempt { get; private set; }
        internal JsonObject? CapturedPrivilege { get; private set; }
        internal JsonObject? CapturedBaseline { get; private set; }
        internal int CompleteCalls { get; private set; }
        internal int AppliedMutations { get; private set; }
        internal int CloseCalls { get; private set; }
        internal int Registrations => registrations.Count;
        internal List<PrivilegeExpiryPhase> Samples { get; } = [];
        internal List<PrivilegeExpiryFence> Completions { get; } = [];

        internal ControlledPrivilegeExpiryObserver(Backend backend, string fault = "good")
        {
            this.backend = backend;
            this.fault = fault;
            backend.ExpiryObserver = this;
        }

        public ValueTask<PrivilegeExpiryArm> ArmAsync(PrivilegeExpiryIntent intent, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            LastAttempt = intent.Attempt;
            DateTimeOffset time = backend.Clock.GetUtcNow();
            var arm = new PrivilegeExpiryArm(intent, Guid.NewGuid().ToString(), "fixture-expiry-source",
                "fixture-privilege-clock", "fixture-privilege-epoch", time,
                time.AddSeconds(intent.ActivationLeadSeconds),
                time.AddSeconds(intent.ActivationLeadSeconds).Add(Duration(intent.RelativeDuration)), ++sequence, true);
            Arm = arm;
            // Both callbacks are armed before returning any schedule to the SDK caller.
            registrations.Add(intent.Attempt.Id, arm);
            terminals.Add(intent.Attempt.Id, new(TaskCreationOptions.RunContinuationsAsynchronously));
            CapturedBaseline = backend.MembershipSnapshot(intent.Attempt.ProjectId, intent.Attempt.IdentityId);
            if (fault == "lost-arm") throw new IOException("fixture-lost-arm");
            return ValueTask.FromResult(fault switch
            {
                "wrong-source" => arm with { SourceIdentity = "observer" },
                "wrong-epoch" => arm with { ClockEpoch = "" },
                "wrong-schedule" => arm with { EndsAt = arm.StartsAt.AddSeconds(1) },
                "unarmed" => arm with { CaptureArmed = false },
                "wrong-attempt" => arm with { Intent = intent with { Attempt = intent.Attempt with { Id = "foreign-attempt" } } },
                _ => arm
            });
        }

        internal bool IsClosedMutation(Uri uri, JsonObject body) =>
            IsTemporalMutation(uri, body) && closed.Values.Any(a => MatchesAttempt(a, uri, body));

        private static bool IsTemporalMutation(Uri uri, JsonObject body) =>
            (uri.AbsolutePath.Contains("/additional-privilege/", StringComparison.Ordinal) ||
                uri.AbsolutePath.Contains("/identity-project-additional-privilege", StringComparison.Ordinal)) &&
            (uri.AbsolutePath.EndsWith("/temporary", StringComparison.Ordinal) ||
                (body["privilegeDetails"] ?? body["type"] ?? body)["isTemporary"]?.GetValue<bool>() == true);

        private static bool MatchesAttempt(PrivilegeExpiryAttempt attempt, Uri uri, JsonObject body)
        {
            JsonNode fields = body["privilegeDetails"] ?? body;
            bool legacy = uri.AbsolutePath.Contains("/api/v1/", StringComparison.Ordinal);
            return legacy == (attempt.Version == PrivilegeExpiryVersion.LegacyV1) &&
                fields["slug"]?.GetValue<string>() == attempt.PrivilegeSlug &&
                (body["identityId"] is null || body["identityId"]!.GetValue<string>() == attempt.IdentityId) &&
                (body["projectId"] is null || body["projectId"]!.GetValue<string>() == attempt.ProjectId) &&
                (body["projectSlug"] is null || body["projectSlug"]!.GetValue<string>() == attempt.ProjectSlug) &&
                (attempt.ExistingPrivilegeId is null || legacy ||
                    uri.AbsolutePath.EndsWith("/" + attempt.ExistingPrivilegeId, StringComparison.Ordinal));
        }

        internal void Capture(string method, Uri uri, JsonObject body, int status)
        {
            if (method is not ("POST" or "PATCH") || !IsTemporalMutation(uri, body)) return;
            foreach (PrivilegeExpiryArm arm in registrations.Values)
            {
                PrivilegeExpiryAttempt attempt = arm.Intent.Attempt;
                if (!MatchesAttempt(attempt, uri, body)) continue;
                JsonObject? committed = backend.PrivilegeSnapshot(attempt.ProjectId, attempt.PrivilegeSlug);
                bool applied = committed?["isTemporary"]?.GetValue<bool>() == true;
                if (applied)
                {
                    AppliedMutations++;
                    CapturedPrivilege = committed;
                }
                // A native row commit, not an acknowledgement or supplied access flag,
                // determines Applied even if the service reports a false denial.
                var fence = new PrivilegeExpiryFence(arm, Guid.NewGuid().ToString(),
                    applied ? PrivilegeExpiryDisposition.Applied : PrivilegeExpiryDisposition.Rejected,
                    applied ? committed!["id"]!.GetValue<string>() : attempt.ExistingPrivilegeId,
                    attempt.PrivilegeSlug, ++sequence, true);
                if (!terminals[attempt.Id].TrySetResult(fence))
                    throw new InvalidOperationException("fixture-temporal-mutation-replayed");
                if (!applied && status != 403) throw new InvalidOperationException("fixture-unsettled-mutation");
            }
        }

        public async ValueTask<PrivilegeExpiryFence> CompleteAsync(PrivilegeExpiryArm arm, CancellationToken token)
        {
            CompleteCalls++;
            PrivilegeExpiryFence fence = await terminals[arm.Intent.Attempt.Id].Task.WaitAsync(token);
            Completions.Add(fence);
            return fault switch
            {
                "missing-terminal-fence" => fence with { ExcludesLateCommit = false },
                "wrong-row" => fence with { PrivilegeId = Guid.NewGuid().ToString() },
                "wrong-fence-slug" => fence with { PrivilegeSlug = "other-slug" },
                "wrong-fence-sequence" => fence with { Sequence = arm.Cursor },
                _ => fence
            };
        }

        public async ValueTask<PrivilegeExpiryObservation<T>> ObserveAsync<T>(PrivilegeExpiryFence binding,
            PrivilegeExpiryPhase phase, Func<CancellationToken, ValueTask<T>> sample, CancellationToken token)
        {
            PrivilegeExpiryAttempt attempt = binding.Arm.Intent.Attempt;
            if (binding.Disposition == PrivilegeExpiryDisposition.NotDispatched)
            {
                // A local cancellation fence is accepted only on an open capture with
                // no service terminal. It must not be converted into Complete.
                if (!registrations.ContainsKey(attempt.Id) || terminals[attempt.Id].Task.IsCompleted ||
                    binding.ProviderRequestId is not null || !binding.ExcludesLateCommit)
                    throw new InvalidOperationException("fixture-invalid-local-fence");
            }
            else if (!terminals[attempt.Id].Task.IsCompleted)
                throw new InvalidOperationException("fixture-missing-service-terminal");
            sequence = Math.Max(sequence, binding.Sequence);
            var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            void Changed() => reached.TrySetResult();
            backend.Clock.Changed += Changed;
            try
            {
                backend.Clock.AdvanceTo(PhaseTime(binding.Arm, phase));
                await reached.Task.WaitAsync(token);
            }
            finally { backend.Clock.Changed -= Changed; }
            backend.CorruptPrivilege(attempt, phase, fault);
            Samples.Add(phase);
            var window = new PrivilegeExpiryWindow(binding, phase, Guid.NewGuid().ToString(),
                Guid.NewGuid().ToString(), ++sequence, backend.Clock.GetUtcNow(), backend.Clock.GetUtcNow(), true, true);
            T result = await sample(token);
            window = fault switch
            {
                "wrong-window-epoch" => window with { Binding = binding with { Arm = binding.Arm with { ClockEpoch = "foreign" } } },
                "wrong-phase" => window with { Phase = phase == PrivilegeExpiryPhase.Active ? PrivilegeExpiryPhase.Expired : PrivilegeExpiryPhase.Active },
                "wrong-window-time" => window with { OpenedAt = binding.Arm.EndsAt.AddSeconds(1) },
                "wrong-window-sequence" => window with { Sequence = binding.Sequence },
                "missing-event" => window with { EventObserved = false },
                _ => window
            };
            return new(window, result);
        }

        public ValueTask<PrivilegeExpiryCleanup> CloseAsync(PrivilegeExpiryAttempt attempt, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            CloseCalls++;
            closed.Add(attempt.Id, attempt);
            if (fault != "cleanup-residue") registrations.Remove(attempt.Id);
            bool settled = !terminals.TryGetValue(attempt.Id, out var terminal) || terminal.Task.IsCompleted ||
                AppliedMutations == 0;
            terminals.Remove(attempt.Id);
            return ValueTask.FromResult(new PrivilegeExpiryCleanup(attempt, true, true, settled,
                fault != "cleanup-inventory", registrations.Count,
                fault == "cleanup-pending" ? 1 : 0));
        }
    }

    // Offline stateful provider characterization, never a native evidence producer.
    // Policies are enforced by this server, not reported as a pass by fixture input.
    private sealed class Backend : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly ConcurrentBag<Task> connections = [];
        private readonly Dictionary<string, JsonObject> projects = [];
        private readonly Dictionary<string, JsonObject> roles = [];
        private readonly Dictionary<string, JsonObject> privileges = [];
        private readonly Dictionary<string, JsonObject> groups = [];
        private readonly Dictionary<string, JsonObject> identities = [];
        private readonly Dictionary<(string Project, string Principal), JsonObject> members = [];
        private readonly Dictionary<string, JsonObject> organizationGroups = [];
        private readonly HashSet<(string Group, string Principal)> groupMembers = [];
        private readonly HashSet<(string Group, string Principal)> userGroups = [];
        private readonly Dictionary<string, string> users = new()
        { [Runtime] = "fixture-runtime", [ScopedUser] = "z-other-user", [UnassignedUser] = "eligible-user" };
        private readonly Dictionary<(string Project, string Environment, string Key), string> secrets = [];
        private readonly Dictionary<(string Project, string Environment, string Key), string[]> secretTags = [];
        private readonly Dictionary<string, string> tags = [];
        private readonly Task accept;
        private readonly string mode;
        private readonly List<string> trace = [];
        internal PrivilegeClock Clock { get; } = new();
        internal ControlledPrivilegeExpiryObserver? ExpiryObserver { get; set; }
        internal bool RuntimeExpired { get; private set; }
        internal List<(string Project, string Environment, string Credential, DateTimeOffset Time, int Status)> Accesses { get; } = [];
        internal List<JsonObject> PrivilegeReadbacks { get; } = [];
        internal string Trace => string.Join(",", trace);
        internal Uri Origin { get; }
        internal int AdministrativeMutations { get; private set; }
        internal int OwnedCount => projects.Count + roles.Count + privileges.Count + groups.Count + identities.Count;

        internal Backend(string mode = "good")
        {
            this.mode = mode;
            listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
            accept = AcceptAsync();
        }

        private async Task AcceptAsync()
        {
            try
            {
                while (!shutdown.IsCancellationRequested)
                    connections.Add(ServeAsync(await listener.AcceptTcpClientAsync(shutdown.Token)));
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        }

        private async Task ServeAsync(TcpClient socket)
        {
            using (socket)
            {
                NetworkStream stream = socket.GetStream();
                var header = new List<byte>();
                byte[] one = new byte[1];
                while (header.Count < 32768)
                {
                    if (await stream.ReadAsync(one, shutdown.Token) == 0) return;
                    header.Add(one[0]);
                    if (header.Count >= 4 && header.TakeLast(4).SequenceEqual(new byte[] { 13, 10, 13, 10 })) break;
                }
                string[] lines = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n");
                string[] request = lines[0].Split(' ');
                string credential = lines.Single(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))
                    .Split(' ').Last();
                string? length = lines.SingleOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
                byte[] bodyBytes = new byte[length is null ? 0 : int.Parse(length.Split(':')[1])];
                await stream.ReadExactlyAsync(bodyBytes, shutdown.Token);
                JsonObject body = bodyBytes.Length == 0 ? new() : JsonNode.Parse(bodyBytes)!.AsObject();
                int status;
                JsonNode response;
                lock (projects)
                {
                    Uri uri = new(Origin, request[1]);
                    (status, response) = ExpiryObserver?.IsClosedMutation(uri, body) == true ?
                        (409, new JsonObject()) : Respond(request[0], uri, credential, body);
                    ExpiryObserver?.Capture(request[0], uri, body, status);
                    string[] route = new Uri(Origin, request[1]).AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
                    trace.Add(request[0] + ":" + route[2] + ":" + route.Length + ":" + credential + ":" + status);
                }
                byte[] content = Encoding.UTF8.GetBytes(response.ToJsonString());
                byte[] headers = Encoding.ASCII.GetBytes($"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {content.Length}\r\nConnection: close\r\n\r\n");
                try
                {
                    await stream.WriteAsync(headers, shutdown.Token);
                    await stream.WriteAsync(content, shutdown.Token);
                }
                catch (IOException) { /* The selected cancellation boundary may close its socket. */ }
                catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
                {
                    // Disposal can cancel a writer after the SDK's exact headers boundary.
                }
            }
        }

        private (int, JsonNode) Respond(string method, Uri uri, string credential, JsonObject body)
        {
            string[] p = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries).Select(Uri.UnescapeDataString).ToArray();
            var selectors = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Split('=', 2)).ToLookup(s => s[0], s => Uri.UnescapeDataString(s[1]));
            var q = selectors.ToDictionary(s => s.Key, s => s.Last());
            if (p[2] == "secrets") return Secret(method, p, q, body, credential);
            if (credential == "denied")
            {
                if (mode == "false-denied-commit" && method is "POST" or "PATCH" &&
                    p[2] is "additional-privilege" or "identity-project-additional-privilege")
                    Privilege(method, p, q, body, credential);
                return (403, new JsonObject());
            }
            if (credential == "administrative" && method != "GET") AdministrativeMutations++;
            if (mode == "cleanup" && credential == "setup" && method == "DELETE") return (403, new JsonObject());
            if (p[2] == "organizations" && p.Length == 5 && p[4] == "memberships")
                return (200, new JsonObject
                {
                    ["users"] = new JsonArray(users.Select(u => (JsonNode)new JsonObject
                    {
                        ["id"] = u.Key,
                        ["orgId"] = Org,
                        ["userId"] = u.Key,
                        ["role"] = "member",
                        ["status"] = "accepted",
                        ["isActive"] = true,
                        ["user"] = new JsonObject { ["id"] = u.Key, ["username"] = u.Value }
                    }).ToArray())
                });
            if (p[2] is "identity-project-additional-privilege" or "additional-privilege")
                return Privilege(method, p, q, body, credential);
            if (p[2] == "identities")
            {
                if (method == "POST")
                {
                    JsonObject identity = Without(Identity(Guid.NewGuid().ToString(), Text(body, "name")), "activeLockoutAuthMethods");
                    identities.Add(Text(identity, "id"), identity);
                    return (200, Wrap("identity", identity));
                }
                string? id = p.Length > 3 ? p[3] : null;
                if (id is null) return (200, new JsonObject
                {
                    ["identities"] = new JsonArray(identities.Values.Select(i => IdentityMembership(i, false)).ToArray()),
                    ["totalCount"] = identities.Count
                });
                if (id == Runtime) return (200, Wrap("identity", IdentityMembership(Identity(Runtime, "fixture-runtime"))));
                if (!identities.TryGetValue(id, out JsonObject? selected)) return (404, new JsonObject());
                if (method == "DELETE") identities.Remove(id);
                return (200, Wrap("identity", method == "GET" ? IdentityMembership(selected) :
                    Fields(selected, "id", "name", "orgId", "projectId", "createdAt", "updatedAt")));
            }
            if (p[2] == "organization" && p[3].StartsWith("available-", StringComparison.Ordinal))
            {
                bool group = p[3] == "available-groups";
                IEnumerable<JsonObject> items = group ? groups.Values : identities.Values;
                if (q.TryGetValue("identityName", out string? search)) items = items.Where(i => Text(i, "name").Contains(search, StringComparison.Ordinal));
                return (200, new JsonObject
                {
                    [group ? "groups" : "identities"] = new JsonArray(items.Select(i => group ?
                        Fields(i, "id", "name", "slug") : Fields(i, "id", "name")).ToArray())
                });
            }
            if (p[2] == "organization" && p[3] == "roles") return Role(method, p, body, credential, null);
            if (p[2] == "organizations" && p[3] == "memberships")
            {
                string group = p[5];
                if (method == "POST") organizationGroups[group] = NewMember(body["roles"]!.AsArray());
                if (!organizationGroups.TryGetValue(group, out JsonObject? member)) return (404, new JsonObject());
                if (method == "PATCH") member["roles"] = NewMember(body["roles"]!.AsArray())["roles"]!.DeepClone();
                return (200, Wrap("groupMembership", GroupMembership(group, member, null)));
            }
            if (p[2] == "groups") return Group(method, p, selectors, body, credential);
            if (p[2] != "projects") return (404, new JsonObject());
            // Exact-role inspection is the SDK's /projects/roles/{roleId}
            // endpoint, not the project-nested role authoring endpoint.
            if (method == "GET" && p.Length == 5 && p[3] == "roles")
                return roles.TryGetValue(p[4], out JsonObject? exactRole) ?
                    (200, Wrap("role", exactRole)) : (404, new JsonObject());
            if (p.Length == 3)
            {
                string id = Guid.NewGuid().ToString();
                var project = new JsonObject
                {
                    ["id"] = id,
                    ["_id"] = id,
                    ["orgId"] = Org,
                    ["name"] = body["projectName"]!.DeepClone(),
                    ["slug"] = body["slug"]!.DeepClone(),
                    ["type"] = "secret-manager",
                    ["hasDeleteProtection"] = false,
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date,
                    ["environments"] = new JsonArray(),
                    ["deletedEnvironments"] = new JsonArray()
                };
                projects.Add(id, project);
                return (200, Wrap("project", project));
            }
            string? projectId = p[3] == "slug" ? projects.Keys.SingleOrDefault(id => Text(projects[id], "slug") == p[4]) : p[3];
            if (projectId is null || !projects.TryGetValue(projectId, out JsonObject? owner)) return (404, new JsonObject());
            if (p[3] == "slug") return (200, owner.DeepClone());
            if (p.Length == 4)
            {
                if (method == "DELETE") projects.Remove(projectId);
                return (200, Wrap("project", method == "DELETE" ?
                    Without(owner, "_id", "environments", "deletedEnvironments") : owner));
            }
            if (p[4] == "roles") return Role(method, p, body, credential, projectId);
            if (p[4] == "memberships")
            {
                string principal = p[^1];
                bool group = p[5] == "groups";
                if (method == "POST") members[(projectId, principal)] = NewMember(body["roles"]!.AsArray());
                if (!members.TryGetValue((projectId, principal), out JsonObject? m)) return (404, new JsonObject());
                if (method == "PATCH")
                {
                    m["roles"] = NewMember(body["roles"]!.AsArray())["roles"]!.DeepClone();
                }
                if (group) return (200, Wrap("groupMembership", GroupMembership(principal, m, projectId)));
                if (method == "GET")
                    return (200, Wrap("identityMembership", Stamp(new JsonObject
                    {
                        ["id"] = m["id"]!.DeepClone(),
                        ["roles"] = m["roles"]!.DeepClone(),
                        ["identity"] = Fields(Identity(principal, "fixture-runtime"), "id", "name", "orgId",
                            "projectId", "authMethods", "metadata")
                    })));
                return (200, Wrap("identityMembership", new JsonObject
                {
                    ["id"] = m["id"]!.DeepClone(),
                    ["identityId"] = principal,
                    ["projectId"] = projectId,
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date
                }));
            }
            if (p[4] == "environments")
                return (200, new JsonObject
                {
                    ["projectId"] = projectId,
                    ["environment"] = new JsonObject
                    {
                        ["id"] = Guid.NewGuid().ToString(),
                        ["projectId"] = projectId,
                        ["name"] = body["name"]!.DeepClone(),
                        ["slug"] = body["slug"]!.DeepClone(),
                        ["position"] = 1,
                        ["createdAt"] = Date,
                        ["updatedAt"] = Date
                    }
                });
            if (p[4] == "tags")
            {
                string id = Guid.NewGuid().ToString();
                tags.Add(id, Text(body, "slug"));
                return (200, Wrap("tag", new JsonObject
                {
                    ["id"] = id,
                    ["projectId"] = projectId,
                    ["slug"] = body["slug"]!.DeepClone(),
                    ["color"] = body["color"]!.DeepClone(),
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date
                }));
            }
            return (404, new JsonObject());
        }

        private (int, JsonNode) Role(string method, string[] p, JsonObject body, string credential, string? project)
        {
            int index = project is null ? 4 : 5;
            if (method == "GET" && p.Length == index)
                return (200, new JsonObject
                {
                    ["roles"] = new JsonArray(roles.Values.Select(r => Without(r, "permissions")).ToArray())
                });
            string? id = p.Length <= index ? null : p[index] == "slug" ?
                roles.Keys.SingleOrDefault(k => Text(roles[k], "slug") == p[index + 1]) : p[index];
            JsonObject value;
            if (method == "POST")
            {
                id = Guid.NewGuid().ToString();
                value = Stamp(new JsonObject { ["id"] = id, [project is null ? "orgId" : "projectId"] = project ?? Org });
                Merge(value, body);
                CorruptPermissions(value, credential);
                if (mode != "drift" || credential != "administrative") roles.Add(id, (JsonObject)value.DeepClone());
            }
            else
            {
                if (id is null || !roles.TryGetValue(id, out JsonObject? current)) return (404, new JsonObject());
                value = (JsonObject)current.DeepClone();
                if (method == "PATCH")
                {
                    if (mode != "ignore-update" || credential != "administrative") Merge(value, body);
                    CorruptPermissions(value, credential);
                    if (mode != "drift" || credential != "administrative") roles[id] = (JsonObject)value.DeepClone();
                }
                if (method == "DELETE") roles.Remove(id);
            }
            if (credential == "administrative" && mode == "wrong-coordinate") value["projectId"] = Runtime;
            return (200, Wrap("role", value));
        }

        private (int, JsonNode) Privilege(string method, string[] p, Dictionary<string, string> q,
            JsonObject body, string credential)
        {
            bool legacy = p[2] == "additional-privilege";
            bool create = method == "POST";
            string? id = create ? null : legacy ? privileges.Keys.SingleOrDefault(k =>
                Text(privileges[k], "slug") == (method == "GET" ? p.Length > 4 ? p[4] : "" : Text(body, "privilegeSlug"))) :
                p.Length > 3 ? p[3] == "slug" ?
                    privileges.Keys.SingleOrDefault(k => Text(privileges[k], "slug") == p[4]) : p[3] : null;
            if (method == "GET" && (legacy ? p.Length == 4 : p.Length == 3))
            {
                string project = legacy ? projects.Keys.Single(k => Text(projects[k], "slug") == q["projectSlug"]) : q["projectId"];
                JsonNode[] rows = privileges.Values.Where(v => Text(v, "projectId") == project)
                    .Select(v => legacy ? Without(v, "projectId", "identityId") :
                        Without(v, "projectId", "identityId", "projectMembershipId", "permissions")).ToArray();
                if (!legacy && credential == "administrative" && rows.Length != 0)
                {
                    if (mode == "duplicate-privileges") rows = [.. rows, rows[0].DeepClone()];
                    if (mode == "omit-peer-privilege") rows = rows[..1];
                }
                return (200, new JsonObject
                {
                    ["privileges"] = new JsonArray(rows)
                });
            }
            JsonObject fields = legacy && method == "PATCH" ? body["privilegeDetails"]!.AsObject() : body;
            JsonObject value;
            if (create)
            {
                id = Guid.NewGuid().ToString();
                string project = legacy ? projects.Keys.Single(k => Text(projects[k], "slug") == Text(body, "projectSlug")) : Text(body, "projectId");
                string identity = Text(body, "identityId");
                value = Stamp(new JsonObject
                {
                    ["id"] = id,
                    ["projectId"] = project,
                    ["identityId"] = identity,
                    ["projectMembershipId"] = members[(project, identity)]["id"]!.DeepClone(),
                    ["isTemporary"] = false
                });
            }
            else
            {
                if (id is null || !privileges.TryGetValue(id, out JsonObject? found)) return (404, new JsonObject());
                value = (JsonObject)found.DeepClone();
            }
            if ((create || method == "PATCH") && !(method == "PATCH" && credential == "administrative" && mode == "ignore-update"))
            {
                value["slug"] = fields["slug"]!.DeepClone();
                if (fields["privilegePermission"] is JsonObject alternative)
                    value["permissions"] = new JsonArray(new JsonObject
                    {
                        ["subject"] = "secrets",
                        ["action"] = alternative["actions"]!.DeepClone(),
                        ["conditions"] = alternative["conditions"]!.DeepClone()
                    });
                else value["permissions"] = fields["permissions"]!.DeepClone();
                JsonObject lifetime = fields["type"]?.AsObject() ?? fields;
                bool temporary = lifetime["isTemporary"]?.GetValue<bool>() ??
                    p[^1] == "temporary";
                if (lifetime["temporaryRange"] is not null || lifetime["isTemporary"] is not null ||
                    p[^1] is "temporary" or "permanent")
                {
                    value["isTemporary"] = temporary;
                    foreach (string field in new[] { "temporaryMode", "temporaryRange", "temporaryAccessStartTime" })
                        value[field] = temporary ? lifetime[field]?.DeepClone() : null;
                    value["temporaryAccessEndTime"] = temporary ?
                        JsonValue.Create(DateTimeOffset.Parse(Text(lifetime, "temporaryAccessStartTime"))
                            .Add(Duration(Text(lifetime, "temporaryRange"))).ToString("O")) : null;
                }
                CorruptPermissions(value, credential);
                if (credential != "administrative" || mode != "drift") privileges[id!] = (JsonObject)value.DeepClone();
            }
            if (method == "DELETE") privileges.Remove(id!);
            if (method == "GET" && credential == "observer") PrivilegeReadbacks.Add((JsonObject)value.DeepClone());
            return (200, Wrap("privilege", legacy ? Without(value, "projectId", "identityId") :
                Without(value, "projectId", "identityId", "projectMembershipId")));
        }

        private (int, JsonNode) Group(string method, string[] p, ILookup<string, string> selectors, JsonObject body, string credential)
        {
            var q = selectors.ToDictionary(s => s.Key, s => s.Last());
            if (credential == "runtime" && !CanGroup()) return (403, new JsonObject());
            if (p.Length == 3)
            {
                if (method == "GET") return (200, new JsonArray(groups.Values.Select(g => Without(g, "customRoleSlug")).ToArray()));
                string id = Guid.NewGuid().ToString(), role = body["role"]?.GetValue<string>() ?? "no-access";
                var g = Stamp(new JsonObject
                {
                    ["id"] = id,
                    ["orgId"] = Org,
                    ["name"] = body["name"]!.DeepClone(),
                    ["slug"] = body["slug"]?.DeepClone() ?? JsonValue.Create(Text(body, "name")),
                    ["role"] = role,
                    ["customRoleSlug"] = roles.Values.Any(r => Text(r, "slug") == role) ? role : null
                });
                groups.Add(id, g);
                organizationGroups[id] = NewMember(new JsonArray(new JsonObject { ["role"] = role }));
                return (200, Without(g, "role", "customRoleSlug"));
            }
            string group = p[3];
            if (!groups.TryGetValue(group, out JsonObject? selected)) return (404, new JsonObject());
            if (p.Length == 4)
            {
                if (method == "PATCH")
                {
                    Merge(selected, body);
                    if (body["role"] is not null)
                    {
                        selected["customRoleSlug"] = body["role"]!.DeepClone();
                        organizationGroups[group] = NewMember(new JsonArray(new JsonObject { ["role"] = body["role"]!.DeepClone() }));
                    }
                }
                if (method == "DELETE")
                {
                    groups.Remove(group);
                    organizationGroups.Remove(group);
                    groupMembers.RemoveWhere(m => m.Group == group);
                    userGroups.RemoveWhere(m => m.Group == group);
                }
                return (200, method == "GET" ? selected.DeepClone() : Without(selected, "role", "customRoleSlug"));
            }
            if (p.Length > 5)
            {
                bool user = p[4] == "users";
                string principal = user ? users.Single(u => u.Value == p[5]).Key : p[5];
                if (method == "POST")
                {
                    groupMembers.Add((group, principal));
                    if (user) userGroups.Add((group, principal));
                }
                if (method == "DELETE") { groupMembers.Remove((group, principal)); userGroups.Remove((group, principal)); }
                return (200, user ? new JsonObject { ["id"] = principal, ["username"] = users[principal] } :
                    new JsonObject { ["id"] = Guid.NewGuid().ToString() });
            }
            JsonArray items = [];
            string field;
            if (p[4] == "projects")
            {
                field = "projects";
                foreach (var (id, project) in projects)
                {
                    bool assigned = members.ContainsKey((id, group));
                    if (q.GetValueOrDefault("filter") == "assignedProjects" && !assigned ||
                        q.GetValueOrDefault("filter") == "unassignedProjects" && assigned ||
                        q.TryGetValue("search", out string? s) && !Text(project, "name").Contains(s, StringComparison.Ordinal)) continue;
                    var item = Fields(project, "id", "name", "slug", "type", "description");
                    item["joinedGroupAt"] = assigned ? Date : null;
                    items.Add(item);
                }
            }
            else if (p[4] == "members")
            {
                field = "members";
                foreach (var m in groupMembers.Where(m => m.Group == group))
                {
                    bool user = userGroups.Contains(m);
                    string[] types = selectors["memberTypeFilter"].ToArray();
                    if (types.Length != 0 && !types.Contains(user ? "users" : "machineIdentities")) continue;
                    items.Add(new JsonObject
                    {
                        ["id"] = m.Principal,
                        ["type"] = user ? "user" : "machineIdentity",
                        ["joinedGroupAt"] = Date,
                        [user ? "user" : "machineIdentity"] = user ?
                            new JsonObject { ["id"] = m.Principal, ["username"] = users[m.Principal] } :
                            new JsonObject
                            {
                                ["id"] = m.Principal,
                                ["name"] = m.Principal == Runtime ?
                                    "fixture-runtime" : Text(identities[m.Principal], "name")
                            }
                    });
                }
            }
            else
            {
                bool user = p[4] == "users";
                field = user ? "users" : "machineIdentities";
                var candidates = user ? users : identities.ToDictionary(i => i.Key, i => Text(i.Value, "name"));
                if (!user) candidates[Runtime] = "fixture-runtime";
                foreach (var (principal, name) in candidates)
                {
                    bool member = groupMembers.Contains((group, principal)) && userGroups.Contains((group, principal)) == user;
                    string? filter = q.GetValueOrDefault("filter");
                    if (filter is "nonMembers" or "nonAssignedMachineIdentities" && member ||
                        filter is "existingMembers" or "assignedMachineIdentities" && !member) continue;
                    items.Add(new JsonObject
                    {
                        ["id"] = principal,
                        [user ? "username" : "name"] = name,
                        ["isPartOfGroup"] = member,
                        ["joinedGroupAt"] = member ? Date : null
                    });
                }
            }
            string Name(JsonNode row) => field == "members" ?
                row["user"]?["username"]?.GetValue<string>() ?? row["machineIdentity"]!["name"]!.GetValue<string>() :
                row["username"]?.GetValue<string>() ?? row["name"]!.GetValue<string>();
            var selectedItems = items.Where(row =>
                (!q.TryGetValue("search", out string? search) || Name(row!).Contains(search, StringComparison.OrdinalIgnoreCase)) &&
                (!q.TryGetValue("username", out string? username) || Name(row!) == username));
            var ordered = q.GetValueOrDefault("orderDirection") == "desc" ?
                selectedItems.OrderByDescending(row => Name(row!), StringComparer.Ordinal) :
                selectedItems.OrderBy(row => Name(row!), StringComparer.Ordinal);
            items = new JsonArray(ordered.Select(row => row!.DeepClone()).ToArray());
            return (200, new JsonObject { [field] = items, ["totalCount"] = items.Count });
        }

        private bool CanGroup() => groupMembers.Any(m => m.Principal == Runtime &&
            organizationGroups.TryGetValue(m.Group, out JsonObject? membership) &&
            membership["roles"]!.AsArray().Any(r => roles.Values.Any(role =>
                Text(role, "slug") == Text(r!.AsObject(), "role") && role["permissions"]!.AsArray().Any(rule =>
                    Text(rule!.AsObject(), "subject") == "groups" && Actions(rule.AsObject()).Contains("read")))));

        private (int, JsonNode) Secret(string method, string[] p, Dictionary<string, string> q, JsonObject body, string credential)
        {
            string project = method == "GET" ? q["projectId"] : Text(body, "projectId");
            string environment = method == "GET" ? q["environment"] : Text(body, "environment");
            if (credential == "denied")
            {
                Accesses.Add((project, environment, credential, Clock.GetUtcNow(), 403));
                return (403, new JsonObject());
            }
            if (p.Length > 3 && p[3] == "batch")
            {
                JsonArray items = [];
                foreach (JsonNode? s in body["secrets"]!.AsArray())
                {
                    string key = Text(s!.AsObject(), "secretKey");
                    secrets[(project, environment, key)] = Text(s.AsObject(), "secretValue");
                    secretTags[(project, environment, key)] = (s["tagIds"]?.AsArray() ?? []).Select(t => tags[t!.GetValue<string>()]).ToArray();
                    items.Add(new JsonObject { ["secretKey"] = key, ["workspace"] = project, ["environment"] = environment, ["type"] = "shared", ["version"] = 1 });
                }
                return (200, new JsonObject { ["secrets"] = items });
            }
            string selectedKey = p.Length > 3 ? p[3] : secrets.Keys.First(k => k.Project == project && k.Environment == environment).Key;
            if (credential == "runtime")
            {
                bool allowed = !RuntimeExpired &&
                    CanSecret(project, environment, selectedKey, p.Length == 3 ? "describeSecret" : "readValue");
                Accesses.Add((project, environment, credential, Clock.GetUtcNow(), allowed ? 200 : 403));
                if (!allowed) return (403, new JsonObject());
            }
            if (p.Length == 3)
                return (200, new JsonObject
                {
                    ["secrets"] = new JsonArray(secrets.Keys.Where(k => k.Project == project && k.Environment == environment)
                        .Select(k => new JsonObject { ["secretKey"] = k.Key, ["version"] = 1 }).ToArray())
                });
            if (method == "POST") secrets.Add((project, environment, selectedKey), Text(body, "secretValue"));
            if (!secrets.TryGetValue((project, environment, selectedKey), out string? value)) return (404, new JsonObject());
            return (200, Wrap("secret", new JsonObject
            {
                ["id"] = Guid.NewGuid().ToString(),
                ["secretKey"] = selectedKey,
                ["secretValue"] = value,
                ["workspace"] = project,
                ["environment"] = environment,
                ["version"] = 1,
                ["secretValueHidden"] = false
            }));
        }

        private bool CanSecret(string project, string environment, string key, string action)
        {
            var rules = new List<JsonObject>();
            foreach (string principal in new[] { Runtime }.Concat(groupMembers.Where(m => m.Principal == Runtime).Select(m => m.Group)))
            {
                if (!members.TryGetValue((project, principal), out JsonObject? member)) continue;
                foreach (JsonNode? assignment in member["roles"]!.AsArray())
                {
                    string slug = Text(assignment!.AsObject(), "role");
                    if (slug == "viewer") return true;
                    foreach (JsonObject role in roles.Values.Where(r => Text(r, "slug") == slug))
                        rules.AddRange(role["permissions"]!.AsArray().Select(p => p!.AsObject()));
                }
            }
            foreach (JsonObject privilege in privileges.Values.Where(p => Text(p, "projectId") == project && Text(p, "identityId") == Runtime))
            {
                if (!members.TryGetValue((project, Runtime), out var membership) ||
                    Text(privilege, "projectMembershipId") != Text(membership, "id")) continue;
                if (privilege["isTemporary"]?.GetValue<bool>() == true)
                {
                    DateTimeOffset starts = DateTimeOffset.Parse(Text(privilege, "temporaryAccessStartTime"));
                    DateTimeOffset ends = DateTimeOffset.Parse(Text(privilege, "temporaryAccessEndTime"));
                    if (mode == "early-activation") starts = starts.AddSeconds(-5);
                    if (mode == "delayed-activation") starts = starts.AddSeconds(1);
                    if (Clock.GetUtcNow() < starts || mode != "expiry-ignored" && Clock.GetUtcNow() >= ends) continue;
                }
                rules.AddRange(privilege["permissions"]!.AsArray().Select(p => p!.AsObject()));
            }
            bool allowed = false;
            foreach (JsonObject rule in rules)
            {
                bool secrets = rule["subject"] is JsonArray subjects
                    ? subjects.Any(s => s!.GetValue<string>() == "secrets") : Text(rule, "subject") == "secrets";
                if (!secrets || !Actions(rule).Any(a => a == action || a == "read")) continue;
                if (!Matches(rule["conditions"]?["environment"], environment)) continue;
                if (rule["conditions"]?["secretTags"] is JsonObject tagRule)
                {
                    string[] actual = secretTags.GetValueOrDefault((project, environment, key)) ?? [];
                    if (tagRule["$in"] is JsonArray included && !included.Any(t => actual.Contains(t!.GetValue<string>()))) continue;
                    if (tagRule["$all"] is JsonArray all && !all.All(t => actual.Contains(t!.GetValue<string>()))) continue;
                }
                if (rule["inverted"]?.GetValue<bool>() == true) return false;
                allowed = true;
            }
            return mode != "access-denied" && (allowed || mode == "outside-allowed" && rules.Count > 0);
        }

        private static bool Matches(JsonNode? clause, string value) => clause switch
        {
            null => true,
            JsonValue literal => literal.GetValue<string>() == value,
            JsonObject c when c["$eq"] is not null => Text(c, "$eq") == value,
            JsonObject c when c["$ne"] is not null => Text(c, "$ne") != value,
            JsonObject c when c["$in"] is JsonArray included => included.Any(v => v!.GetValue<string>() == value),
            JsonObject c when c["$glob"] is not null => value.StartsWith(Text(c, "$glob").TrimEnd('*'), StringComparison.Ordinal),
            _ => false
        };
        private static string[] Actions(JsonObject p) => p["action"] is JsonArray array ?
            array.Select(a => a!.GetValue<string>()).ToArray() : [Text(p, "action")];
        private void CorruptPermissions(JsonObject value, string credential)
        {
            if (credential != "administrative" || value["permissions"] is not JsonArray { Count: > 0 } permissions) return;
            if (mode == "extra-action") permissions[0]!["action"] = new JsonArray("read", "edit");
            if (mode == "extra-subject") permissions[0]!["subject"] = new JsonArray("secrets", "groups");
        }
        internal JsonObject? MembershipSnapshot(string project, string identity)
        {
            lock (projects)
                return members.TryGetValue((project, identity), out JsonObject? row) ? (JsonObject)row.DeepClone() : null;
        }
        internal JsonObject? PrivilegeSnapshot(string project, string slug)
        {
            lock (projects)
                return privileges.Values.SingleOrDefault(p => Text(p, "projectId") == project &&
                    Text(p, "slug") == slug)?.DeepClone().AsObject();
        }
        internal void CorruptPrivilege(PrivilegeExpiryAttempt attempt, PrivilegeExpiryPhase phase, string fault)
        {
            lock (projects)
            {
                if (fault == "token-expired-control" && phase == PrivilegeExpiryPhase.Expired) RuntimeExpired = true;
                JsonObject? row = privileges.Values.SingleOrDefault(p => Text(p, "projectId") == attempt.ProjectId &&
                    Text(p, "slug") == attempt.PrivilegeSlug);
                if (row is null) return;
                if (fault == "wrong-member") row["projectMembershipId"] = Guid.NewGuid().ToString();
                if (fault == "wrong-identity") row["identityId"] = Denied;
                if (fault == "wrong-slug") row["slug"] = "foreign-slug";
                if (fault == "wrong-temporal-metadata") row["temporaryRange"] = "2m";
                if (fault == "missing-permanent-baseline") members[(attempt.ProjectId, attempt.IdentityId)]["roles"] = new JsonArray();
            }
        }
        private static JsonObject Identity(string id, string name) => Stamp(new JsonObject
        {
            ["id"] = id,
            ["name"] = name,
            ["orgId"] = Org,
            ["projectId"] = null,
            ["authMethods"] = new JsonArray(),
            ["activeLockoutAuthMethods"] = new JsonArray(),
            ["metadata"] = new JsonArray()
        });
        private static JsonObject IdentityMembership(JsonObject identity, bool details = true)
        {
            JsonObject nested = details ? Fields(identity, "id", "name", "orgId", "authMethods") :
                Fields(identity, "id", "name", "authMethods");
            if (details) nested["activeLockoutAuthMethods"] = new JsonArray();
            var result = Stamp(new JsonObject
            {
                ["id"] = Guid.NewGuid().ToString(),
                ["identityId"] = identity["id"]!.DeepClone(),
                ["orgId"] = Org,
                ["identity"] = nested,
                ["role"] = "no-access"
            });
            if (details) result["metadata"] = new JsonArray();
            return result;
        }
        private JsonObject GroupMembership(string group, JsonObject member, string? project)
        {
            var result = Stamp(new JsonObject
            {
                ["id"] = member["id"]!.DeepClone(),
                ["groupId"] = group,
                ["roles"] = member["roles"]!.DeepClone(),
                ["group"] = Fields(groups[group], "id", "name", "slug", "orgId")
            });
            if (project is not null) result["projectId"] = project;
            return result;
        }
        private static JsonObject NewMember(JsonArray roles)
        {
            JsonArray copied = (JsonArray)roles.DeepClone();
            foreach (JsonNode? r in copied) { r!["id"] = Guid.NewGuid().ToString(); r["isTemporary"] = false; }
            return new() { ["id"] = Guid.NewGuid().ToString(), ["roles"] = copied };
        }
        private static JsonObject Stamp(JsonObject value) { value["createdAt"] = Date; value["updatedAt"] = Date; return value; }
        private static void Merge(JsonObject target, JsonObject source)
        {
            foreach (var (key, value) in source) target[key] = value?.DeepClone();
        }
        private static JsonArray Array(IEnumerable<JsonObject> values) => new(values.Select(v => v.DeepClone()).ToArray());
        private static JsonObject Fields(JsonObject value, params string[] fields)
        {
            var result = new JsonObject();
            foreach (string field in fields)
                if (value.ContainsKey(field)) result[field] = value[field]?.DeepClone();
            return result;
        }
        private static JsonObject Without(JsonObject value, params string[] fields)
        {
            var result = (JsonObject)value.DeepClone();
            foreach (string field in fields) result.Remove(field);
            return result;
        }
        private static JsonObject Wrap(string field, JsonNode value) => new() { [field] = value.DeepClone() };
        private static string Text(JsonObject value, string field) => value[field]!.GetValue<string>();

        public async ValueTask DisposeAsync()
        {
            shutdown.Cancel();
            // Let token cancellation finish the subscribed accept before closing
            // the socket; Stop racing cancellation can surface a SocketException.
            try { await accept; }
            finally { listener.Stop(); }
            await Task.WhenAll(connections);
            shutdown.Dispose();
        }
    }
}
