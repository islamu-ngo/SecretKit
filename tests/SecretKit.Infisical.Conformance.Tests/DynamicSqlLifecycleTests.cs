using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class DynamicSqlLifecycleTests
{
    [Test]
    public async Task AcquiredSqlCredentialsHaveObservedBackendRenewalAndRevocationEffects() =>
        await IdentitySetupTests.RunAsync(OwnedConformanceScenario.SqlLifecycle);

    internal static async Task VerifyAsync(Uri origin, IInfisicalTokenSource administrator,
        string project, string projectSlug, Action<string, string> record, CancellationToken cancellationToken)
    {
        using var backend = new OwnedSqlBackend(Environment.GetEnvironmentVariable("SECRETKIT_LIVE_OWNER")!);
        await backend.StartAsync(record, cancellationToken);
        var network = new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true };
        await using var native = new InfisicalClient(origin, administrator, network);
        var environment = await native.GetEnvironmentAsync(new SecretReference(native.Authority,
            new InfisicalEnvironmentAddress(project, "dev", InfisicalOrganizationSelector.Slug)), cancellationToken);
        Require(environment.Status, "environment", DispatchEvidence.NotDispatched);
        const string folderName = "sdk-sql-effects";
        var folderTarget = new SecretReference(native.Authority,
            new InfisicalFolderAddress(project, "dev", environment.Value.Id, "/", name: folderName));
        var folderReceipt = new MutationReceipt(folderTarget);
        var folder = await native.CreateFolderAsync(folderTarget,
            new InfisicalNativeAuthority(native.Authority, administrator, project), folderReceipt,
            cancellationToken: cancellationToken);
        Require(folder.Status, "folder", folderReceipt.Evidence);
        record("folder", folder.Value.Id);
        await using var lifecycle = new InfisicalDynamicClient(origin, administrator,
            new InfisicalDynamicScope(projectSlug, "dev", "/" + folderName, Guid.Parse(folder.Value.Id)), network);
        using var profile = new NativeSqlDefinitionProfile(NativeSqlEngine.Postgres, backend.Host,
            backend.Port, "postgres", backend.Password, OwnedSqlBackend.Database,
            "CREATE ROLE \"{{username}}\" LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; " +
                "GRANT SELECT ON sdk_probe TO \"{{username}}\";",
            "REVOKE SELECT ON sdk_probe FROM \"{{username}}\"; DROP ROLE \"{{username}}\";",
            "ALTER ROLE \"{{username}}\" VALID UNTIL '{{expiration}}';", sslEnabled: false);
        var target = lifecycle.Definition("sdk-sql");
        var createReceipt = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.CreateDefinition);
        var created = await lifecycle.CreateDefinitionAsync(target, profile,
            new(TimeSpan.FromSeconds(60)), new(TimeSpan.FromSeconds(300)), createReceipt, cancellationToken);
        Require(created.Status, "definition-create", createReceipt.Evidence);
        record("dynamic-definition", created.Value.Id.ToString("D"));
        var inspection = await lifecycle.InspectDefinitionAsync(target, cancellationToken);
        Require(inspection.Status, "definition-inspection", DispatchEvidence.NotDispatched);
        var before = await lifecycle.ListLeasesAsync(created.Value, cancellationToken);
        Require(before.Status, "empty-lease-list", DispatchEvidence.NotDispatched);
        await Assert.That(before.Value.Items.Count).IsEqualTo(0);
        var acquireReceipt = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.Acquire);
        var acquired = await lifecycle.AcquireDatabaseAsync(created.Value, acquireReceipt,
            cancellationToken: cancellationToken);
        Require(acquired.Status, "acquire", acquireReceipt.Evidence);
        await Assert.That(acquireReceipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        using var lease = acquired.Value;
        record("dynamic-lease", lease.Reference.Id.ToString("D"));
        using var credentials = lease.CopyCredentials().Value;
        string username = credentials.RevealUsername();
        string password = credentials.RevealPassword();
        var use = await backend.QueryAsync(username, password, "SELECT value FROM sdk_probe;", cancellationToken);
        await Assert.That(use.ExitCode).IsEqualTo(0);
        await Assert.That(use.Output.Trim()).IsEqualTo("731");
        var write = await backend.QueryAsync(username, password, "INSERT INTO sdk_probe VALUES (732);", cancellationToken);
        await Assert.That(write.ExitCode != 0).IsTrue();
        DateTimeOffset previous = lease.Observation.ExpiresAt;
        var renewReceipt = new InfisicalDynamicMutationReceipt(lease.Reference, InfisicalDynamicOperation.Renew);
        var renewed = await lifecycle.RenewAsync(lease, renewReceipt, new(TimeSpan.FromSeconds(120)), cancellationToken);
        Require(renewed.Status, "renew", renewReceipt.Evidence);
        await Assert.That(renewReceipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(renewed.Value.ExpiresAt > previous).IsTrue();
        var roleExpiry = await backend.QueryAsync(username, password,
            "SELECT rolvaliduntil FROM pg_roles WHERE rolname = current_user;", cancellationToken);
        await Assert.That(roleExpiry.ExitCode).IsEqualTo(0);
        await Assert.That(DateTimeOffset.TryParse(roleExpiry.Output.Trim(),
            System.Globalization.CultureInfo.InvariantCulture, out var nativeExpiry)).IsTrue();
        await Assert.That(Math.Abs((nativeExpiry - renewed.Value.ExpiresAt).TotalSeconds) < 1).IsTrue();
        var revokeReceipt = new InfisicalDynamicMutationReceipt(lease.Reference, InfisicalDynamicOperation.Revoke);
        var revoked = await lifecycle.RevokeAsync(lease, revokeReceipt, cancellationToken: cancellationToken);
        Require(revoked.Status, "revoke", revokeReceipt.Evidence);
        await Assert.That(revokeReceipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        // Ordinary strings are deliberate test-only exports retained solely for
        // a fresh backend denial after the local lease handle becomes unusable.
        var denied = await backend.QueryAsync(username, password, "SELECT value FROM sdk_probe;", cancellationToken);
        await Assert.That(denied.ExitCode != 0).IsTrue();
        var after = await lifecycle.ListLeasesAsync(created.Value, cancellationToken);
        Require(after.Status, "post-revoke-lease-list", DispatchEvidence.NotDispatched);
        await Assert.That(after.Value.Items.Count).IsEqualTo(0);
        foreach (bool cancelAfterCommit in new[] { false, true })
        {
            using var fault = new AcquireFaultTransport(cancelAfterCommit);
            await using var uncertain = new InfisicalDynamicClient(origin, administrator, lifecycle.Scope,
                network, transport: fault);
            var faultTarget = uncertain.Definition("sdk-sql");
            var observedDefinition = await uncertain.InspectDefinitionAsync(faultTarget, cancellationToken);
            Require(observedDefinition.Status, "fault-definition-inspection", DispatchEvidence.NotDispatched);
            var receipt = new InfisicalDynamicMutationReceipt(faultTarget, InfisicalDynamicOperation.Acquire);
            using var preCancelled = new CancellationTokenSource();
            preCancelled.Cancel();
            await Assert.That(async () => await uncertain.AcquireDatabaseAsync(observedDefinition.Value,
                receipt, cancellationToken: preCancelled.Token)).Throws<OperationCanceledException>();
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
            // Subscribe before issuance. The fault waits for a real upstream
            // success before cancellation or loss; it never repeats the request.
            Task committed = fault.Committed.Task;
            using var cancel = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var pending = uncertain.AcquireDatabaseAsync(observedDefinition.Value, receipt,
                cancellationToken: cancel.Token).AsTask();
            await committed.WaitAsync(TimeSpan.FromSeconds(15), cancellationToken);
            if (cancelAfterCommit)
            {
                cancel.Cancel();
                await Assert.That(async () => await pending).Throws<OperationCanceledException>();
            }
            else await Assert.That((await pending).Status).IsEqualTo(SecretStatus.Unknown);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            await Assert.That((await uncertain.AcquireDatabaseAsync(observedDefinition.Value, receipt,
                cancellationToken: cancellationToken)).Status).IsEqualTo(SecretStatus.Invalid);
            var actual = await lifecycle.ListLeasesAsync(created.Value, cancellationToken);
            Require(actual.Status, "uncertain-fresh-lease-inspection", DispatchEvidence.NotDispatched);
            await Assert.That(actual.Value.Items.Count).IsEqualTo(1);
            var orphan = actual.Value.Items.Single();
            record("uncertain-dynamic-lease", orphan.Reference.Id.ToString("D"));
            // This independently selected reference authorizes explicit cleanup;
            // it does not reconcile the original uncertain issuance receipt.
            var cleanupReceipt = new InfisicalDynamicMutationReceipt(orphan.Reference, InfisicalDynamicOperation.Revoke);
            var cleanup = await lifecycle.RevokeLeaseAsync(orphan.Reference, cleanupReceipt,
                cancellationToken: cancellationToken);
            Require(cleanup.Status, "observed-orphan-cleanup", cleanupReceipt.Evidence);
            await Assert.That(cleanupReceipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        }
        Console.WriteLine("OWNED_SQL_ACQUIRE_USE_RENEW_REVOKE_EFFECTS_PASSED");
    }

    private static void Require(SecretStatus status, string step, DispatchEvidence evidence)
    {
        if (status != SecretStatus.Success)
            throw new InvalidOperationException($"Owned SQL {step}: {status}; evidence: {evidence}.");
    }

    private sealed class AcquireFaultTransport(bool holdForCancellation) : HttpMessageHandler
    {
        private readonly HttpMessageInvoker _upstream = new(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            ActivityHeadersPropagator = null
        });
        internal TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var response = await _upstream.SendAsync(request, cancellationToken);
            if (request.Method != HttpMethod.Post || request.RequestUri!.AbsolutePath != "/api/v1/dynamic-secrets/leases")
                return response;
            using (response)
            {
                if (!response.IsSuccessStatusCode)
                    throw new InvalidOperationException("Owned uncertain acquisition did not succeed upstream.");
                if (!Committed.TrySetResult())
                    throw new InvalidOperationException("Owned uncertain acquisition was duplicated.");
                if (holdForCancellation)
                    await new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)
                        .Task.WaitAsync(cancellationToken);
                throw new HttpRequestException("Owned acquisition response intentionally withheld.");
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _upstream.Dispose();
            base.Dispose(disposing);
        }
    }
}
