using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalProxyPatchEffectTests
{
    internal static readonly JsonSerializerOptions Options = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    internal const string Operation = "i.management.ProxiedServiceAdministrationOperations.Update";
    private static readonly string[] Boundaries =
    [
        "selected-contract", "independent-effect", "denied-authority",
        "cancellation-boundary", "lost-response-no-replay"
    ];

    public static IEnumerable<(string Variant, string Boundary)> Cases() =>
        InfisicalGovernanceFamilies.Bindings[Operation].Variants.SelectMany(v => Boundaries.Select(b => (v, b)));

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task IndependentCalibrationUsesTypedRequestsReceiptsStorageAndDelivery(string variant, string boundary)
    {
        await using var fixture = new InfisicalProxyPatchEffectFixture();
        await CalibrateAsync(fixture, variant, boundary);
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
        await Assert.That(fixture.Source.Registrations).IsEqualTo(0);
        await Assert.That(fixture.Source.Observations).IsEqualTo(2);
        await Assert.That(fixture.Source.PrivateCopiesDestroyed).IsTrue();
        await Assert.That(fixture.BorrowedStatePreserved).IsTrue();
        await Assert.That(fixture.Source.Fences.Count).IsEqualTo(2);
        var original = fixture.Source.Fences[^1];
        await Assert.That(original.OriginalAttemptSettled && original.ExcludesLateCommit && original.NoReplay).IsTrue();
        await Assert.That(original.MatchedRequests).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await Assert.That(original.MatchedCommits).IsEqualTo(boundary is "denied-authority" or "cancellation-boundary" ? 0 : 1);
        await Assert.That(fixture.Validations.All(v => v.Privilege != "Describe")).IsTrue();
    }

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalProxyUpdateMustOpenIndependentSourceAndObserveEffect(string variant, string boundary)
    {
        await using var fixture = new InfisicalProxyPatchEffectFixture();
        using var environment = fixture.Environment();
        var definition = Definition(variant, boundary);
        var registry = new NativeCaseRegistry();
        InfisicalGovernanceFamilies.Register(registry, environment, [definition], fixture.Observers);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None))[0];
        // The intentional Red is source-not-opened while the old central gate
        // remains. Unavailable is never an accepted positive witness.
        await Assert.That(fixture.Source.Opens).IsEqualTo(1).Because("source-not-opened:" + result.ReasonCode);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
        await Assert.That(fixture.Source.Registrations).IsEqualTo(0);
        await Assert.That(fixture.Source.PrivateCopiesDestroyed).IsTrue();
    }

    [Test]
    [Arguments("ignored-selected-row")]
    [Arguments("retained-removed-row")]
    [Arguments("optional-retained-ignored")]
    [Arguments("new-refs-not-validated")]
    [Arguments("wrong-actual-substitution")]
    [Arguments("denied-delivered")]
    [Arguments("noncommitted")]
    [Arguments("late")]
    [Arguments("replay")]
    [Arguments("source-foreign")]
    [Arguments("borrowed-damage")]
    [Arguments("cleanup-pending")]
    public async Task IndependentCalibrationRejectsConcreteSourceAndServiceFaults(string fault)
    {
        await using var fixture = new InfisicalProxyPatchEffectFixture(fault);
        string? code = null;
        try { await CalibrateAsync(fixture, "ProxiedServiceCredentialInput.headerPrefix.omitted", "independent-effect"); }
        catch (NativeCaseFailureException error) { code = error.Message; }
        await Assert.That(code is "effect-mismatch" or "observer-unavailable" or "cleanup-incomplete").IsTrue();
        await Assert.That(fixture.Source.Opens).IsEqualTo(1);
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
        await Assert.That(fixture.Source.Registrations).IsEqualTo(0);
        await Assert.That(fixture.PrivateCopiesDestroyed).IsTrue();
    }

    [Test]
    public async Task ActualEmptyPatchRevalidatesRetainedReferencesWithEditAuthority()
    {
        await using var fixture = new InfisicalProxyPatchEffectFixture();
        await CalibrateAsync(fixture, "patch.empty", "selected-contract", revoke: true);
        var original = fixture.Source.Fences[^1];
        await Assert.That(original.Applied).IsFalse();
        await Assert.That(original.Disposition).IsEqualTo(DispatchEvidence.Rejected);
        await Assert.That(fixture.Validations.Count(v => v.Action == "Edit" && !v.Accepted)).IsEqualTo(3);
        await Assert.That(original.MatchedCommits).IsEqualTo(0);
    }

    [Test]
    public async Task InvalidEmptyCredentialArrayIsRejectedBeforeAnyNativeRequest()
    {
        await using var fixture = new InfisicalProxyPatchEffectFixture();
        await Assert.That(() => new ProxiedServiceUpdate(credentials: [])).Throws<ArgumentException>();
        await Assert.That(fixture.Patches.Count).IsEqualTo(0);
    }

    internal static NativeCaseDefinition Definition(string variant, string boundary) => new(
        new("Infisical", Operation, variant, "local", boundary),
        InfisicalGovernanceFamilies.Bindings[Operation].Member);

    private static async Task CalibrateAsync(InfisicalProxyPatchEffectFixture fixture, string variant,
        string boundary, bool revoke = false)
    {
        using var environment = fixture.Environment();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var token = deadline.Token;
        var client = environment.CreateManagementClient();
        var setup = environment.Tokens(NativeIdentityRole.Setup);
        string name = "sk" + Guid.NewGuid().ToString("N");
        var root = new ProxyPatchRootAttempt(Guid.NewGuid().ToString("N"), variant + "/" + boundary,
            "v0.166.3", "controlled-proxy", "controlled-fixture", Guid.NewGuid().ToString("N"),
            InfisicalProxyPatchEffectFixture.OrganizationId, InfisicalProxyPatchEffectFixture.ProjectId,
            "witness", name, name + "-renamed", ProxyPatchSource.ControlledFixture);
        var observer = fixture.Source.CreateObserver();
        ProxyCredentialFixture? first = null, second = null, selected = null;
        string? serviceId = null;
        Exception? failure = null;
        try
        {
            var binding = await observer.OpenAsync(root, token);
            first = await fixture.PrepareAsync(root.OrganizationId, root.ProjectId, root.Environment, name + "-first", setup, token);
            second = await fixture.PrepareAsync(root.OrganizationId, root.ProjectId, root.Environment, name + "-second", setup, token);
            selected = await fixture.PrepareAsync(root.OrganizationId, root.ProjectId, root.Environment, name + "-selected", setup, token);
            using var baselinePlaceholder = SecretMaterial.FromText("BASELINE");
            using var one = new ProxiedServiceCredentialInput(ProxiedServiceCredentialRole.HeaderRewrite,
                first.DynamicSecretField, first.DynamicSecretName,
                headerName: "X-First", headerPrefix: "First ", headerPurpose: ProxiedServiceHeaderPurpose.Password,
                placeholderKey: "SK_FIRST", placeholderValue: baselinePlaceholder, secretKey: first.SecretKey,
                substitutionSurfaces: [ProxiedServiceSubstitutionSurface.Header]);
            using var two = new ProxiedServiceCredentialInput(ProxiedServiceCredentialRole.CredentialSubstitution,
                placeholderKey: "SK_SECOND", secretKey: second.SecretKey,
                substitutionSurfaces: [ProxiedServiceSubstitutionSurface.Query]);
            using var creation = new ProxiedServiceCreation(root.ProjectId, root.Environment, name,
                first.HostPattern, [one, two], isEnabled: true);
            var createArm = await observer.ArmAsync(binding, Guid.NewGuid().ToString("N"), "Create",
                "calibration-seed", "baseline", null, token);
            using var createRequest = ProxiedServiceAdministrationOperations.Create(root.OrganizationId, creation);
            var createReceipt = client.CreateReceipt(createRequest);
            var created = await Execute(createRequest, NativeIdentityRole.Setup, createReceipt, token);
            if (!created.IsSuccess) throw new NativeCaseFailureException("effect-mismatch");
            using (created.Value) serviceId = created.Value.Id;
            var createFence = await observer.CompleteAsync(createArm, createReceipt.Evidence, token);
            await Deliver(serviceId);
            await observer.ObserveAsync(binding, createFence, token);

            using var placeholder = SecretMaterial.FromText("SK_SELECTED");
            var choice = Select(variant, selected, placeholder);
            using var credential = choice.Credential;
            using var update = new ProxiedServiceUpdate(choice.Name ? root.Renamed : null,
                choice.Host ? selected.HostPattern : null, choice.Enabled, choice.Array ? [credential] : null);
            var arm = await observer.ArmAsync(binding, Guid.NewGuid().ToString("N"), "Update",
                variant, boundary, serviceId, token);
            if (revoke) fixture.RevokeReferences();
            using var request = ProxiedServiceAdministrationOperations.Update(root.OrganizationId, root.ProjectId, serviceId, update);
            var receipt = client.CreateReceipt(request);
            if (boundary == "cancellation-boundary")
            {
                using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
                var barrier = new ProjectTokenBarrier(environment.Tokens(NativeIdentityRole.Administrative));
                var authority = new ManagementAuthority(client.Authority, barrier, root.OrganizationId, root.ProjectId);
                Task entered = barrier.Entered;
                var action = client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, request.Target), receipt, cancellation.Token).AsTask();
                await entered.WaitAsync(token);
                cancellation.Cancel(); barrier.Release();
                try { var unexpected = await action; if (unexpected.IsSuccess) unexpected.Value.Dispose(); }
                catch (OperationCanceledException) { }
                if (receipt.Evidence != DispatchEvidence.NotDispatched) throw new NativeCaseFailureException("effect-mismatch");
            }
            else if (boundary == "lost-response-no-replay")
            {
                using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
                using var response = new ProjectResponseBoundary(environment.Origin, cancellation);
                using (response.Enter())
                {
                    try
                    {
                        var unexpected = await Execute(request, NativeIdentityRole.Administrative, receipt, cancellation.Token);
                        if (unexpected.IsSuccess) unexpected.Value.Dispose();
                    }
                    catch (OperationCanceledException) when (!token.IsCancellationRequested) { }
                }
                if (!response.Reached || receipt.Evidence != DispatchEvidence.PossiblyDispatched)
                    throw new NativeCaseFailureException("effect-mismatch");
            }
            else
            {
                var result = await Execute(request, boundary == "denied-authority" ? NativeIdentityRole.Denied :
                    NativeIdentityRole.Administrative, receipt, token);
                if (result.IsSuccess) result.Value.Dispose();
                if (revoke && result.Status != SecretStatus.Denied) throw new NativeCaseFailureException("effect-mismatch");
            }
            var fence = await observer.CompleteAsync(arm, receipt.Evidence, token);
            await Deliver(serviceId);
            await observer.ObserveAsync(binding, fence, token);
        }
        catch (Exception error) { failure = error; }
        finally
        {
            if (serviceId is not null)
            {
                using var remove = ProxiedServiceAdministrationOperations.Delete(root.OrganizationId, root.ProjectId, serviceId);
                var removed = await Execute(remove, NativeIdentityRole.Setup, client.CreateReceipt(remove), token);
                if (removed.IsSuccess) removed.Value.Dispose();
            }
            foreach (string suffix in new[] { "-first", "-second", "-selected" })
                await fixture.RemoveFixtureAsync(root.ProjectId, name + suffix, setup, token);
            first?.Dispose(); second?.Dispose(); selected?.Dispose();
            try { await observer.CloseAsync(root, token); }
            catch (NativeCaseFailureException error) { failure ??= error; }
        }
        if (failure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();

        async ValueTask<SecretOutcome<ProxiedServiceSummary>> Execute(ManagementRequest<ProxiedServiceSummary> request,
            NativeIdentityRole role, ManagementReceipt receipt, CancellationToken ct)
        {
            var authority = environment.CreateManagementAuthority(client, role, request.Target.OrganizationId, request.Target.ProjectId);
            return await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, ct);
        }
        async Task Deliver(string id)
        {
            var row = fixture.Storage(id)!["credentials"]![0]!.AsObject();
            var role = row["role"]!.GetValue<string>() == "header-rewrite" ?
                ProxiedServiceCredentialRole.HeaderRewrite : ProxiedServiceCredentialRole.CredentialSubstitution;
            var surface = Enum.Parse<ProxiedServiceSubstitutionSurface>(
                row["substitutionSurfaces"]?[0]?.GetValue<string>() ?? "header", true);
            string challenge = Guid.NewGuid().ToString("N");
            using var allowed = await fixture.SendThroughAsync(id, challenge, role, surface,
                environment.Tokens(NativeIdentityRole.Runtime), token);
            using var denied = await fixture.SendThroughAsync(id, challenge, role, surface,
                environment.Tokens(NativeIdentityRole.Denied), token);
        }
    }

    private static (ProxiedServiceCredentialInput Credential, bool Array, bool Name,
        bool Host, bool? Enabled) Select(string v, ProxyCredentialFixture selected, SecretMaterial placeholder)
    {
        bool Omitted(string field) => v == "ProxiedServiceCredentialInput." + field + ".omitted";
        bool dynamic = v == "credential.dynamic-secret" || v.Contains("dynamicSecret", StringComparison.Ordinal);
        bool substitution = v.Contains("placeholder", StringComparison.Ordinal) ||
            v.Contains("substitutionSurfaces", StringComparison.Ordinal) ||
            v == "credential.role.CredentialSubstitution" || v.StartsWith("credential.surface.", StringComparison.Ordinal);
        var role = substitution ? ProxiedServiceCredentialRole.CredentialSubstitution : ProxiedServiceCredentialRole.HeaderRewrite;
        var surface = v.StartsWith("credential.surface.", StringComparison.Ordinal) ?
            Enum.Parse<ProxiedServiceSubstitutionSurface>(v.Split('.')[2]) : ProxiedServiceSubstitutionSurface.Header;
        string? key = dynamic || Omitted("secretKey") ? null : selected.SecretKey;
        string? dynamicName = dynamic && !Omitted("dynamicSecretName") ? selected.DynamicSecretName : null;
        string? field = !dynamic || Omitted("dynamicSecretField") ? null : selected.DynamicSecretField;
        string? header = Omitted("headerName") ? null : "X-Selected";
        string? prefix = v == "ProxiedServiceCredentialInput.headerPrefix.value" ? "Selected " : null;
        ProxiedServiceHeaderPurpose? purpose = Omitted("headerPurpose") ? null :
            v.EndsWith(".Username", StringComparison.Ordinal) ? ProxiedServiceHeaderPurpose.Username : ProxiedServiceHeaderPurpose.Password;
        string? placeholderKey = !substitution || Omitted("placeholderKey") ? null : "SK_SELECTED";
        SecretMaterial? value = v == "ProxiedServiceCredentialInput.placeholderValue.value" ? placeholder : null;
        ProxiedServiceSubstitutionSurface[]? surfaces = !substitution || Omitted("substitutionSurfaces") ? null : [surface];
        var credential = new ProxiedServiceCredentialInput(role, field, dynamicName, header, prefix,
            purpose, placeholderKey, value, key, surfaces);
        bool empty = v == "patch.empty";
        bool array = !empty && v is not ("credentials.omitted" or "ProxiedServiceUpdate.credentials.omitted");
        return (credential, array, v == "ProxiedServiceUpdate.name.value",
            v == "ProxiedServiceUpdate.hostPattern.value",
            v == "ProxiedServiceUpdate.isEnabled.false" ? false :
            v == "ProxiedServiceUpdate.isEnabled.true" ? true : null);
    }

}
