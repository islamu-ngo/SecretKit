using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Reflection;
using System.Text;
using SecretKit.Core;
using SecretKit.Infisical.Dynamic;

namespace SecretKit.Infisical.Tests;

[NotInParallel]
public sealed class ClientDisposalBoundaryTests
{
    [Test]
    public async Task DisposedEntrypointsThrowObjectDisposedBeforeRunAsyncWithoutTelemetry()
    {
        var wire = new CountingWire();
        var tokens = new CountingTokens();
        var options = new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) };
        var client = new InfisicalClient(new("https://infisical.test"), tokens, options);
        var admin = new InfisicalNativeAuthority(client.Authority, tokens, "project");
        using var secretMaterial = SecretMaterial.FromText("secret-canary");
        SecretReference secretTarget = new(client.Authority, new InfisicalSecretAddress("project", "dev", "/", "KEY"));
        SecretReference bulkTarget = new(client.Authority, new InfisicalBulkAddress("project", "dev", "/"));
        SecretReference importTarget = new(client.Authority,
            new InfisicalImportAddress("project", "dev", "/", Phase5TestSupport.Id, Phase5TestSupport.Id));
        SecretReference environmentTarget = new(client.Authority,
            new InfisicalEnvironmentAddress("project", Phase5TestSupport.EnvironmentId));
        SecretReference tagTarget = new(client.Authority, new InfisicalTagAddress("project", Phase5TestSupport.Id));
        SecretReference folderTarget = new(client.Authority,
            new InfisicalFolderAddress("project", "dev", Phase5TestSupport.EnvironmentId, "/", Phase5TestSupport.Id, "child"));
        SecretReference folderScope = new(client.Authority,
            new InfisicalFolderAddress("project", "dev", Phase5TestSupport.EnvironmentId, "/"));
        SecretReference validationTarget = new(client.Authority,
            new InfisicalValidationAddress("project", InfisicalValidationKind.StaticSecrets, Phase5TestSupport.Id, "dev", "/"));
        SecretReference validationScope = new(client.Authority,
            new InfisicalValidationAddress("project", InfisicalValidationKind.StaticSecrets, environment: "dev", secretPath: "/"));

        MutationReceipt staticCreateReceipt = client.CreateReceipt(secretTarget);
        MutationReceipt staticUpdateReceipt = client.CreateReceipt(secretTarget);
        var bulkInputs = new[] { new InfisicalBulkSecret("KEY", secretMaterial) };
        var bulkCreateReceipt = new InfisicalBulkReceipt(client, bulkTarget, bulkInputs, InfisicalBulkOperation.Create);
        var bulkUpdateReceipt = new InfisicalBulkReceipt(client, bulkTarget, bulkInputs, InfisicalBulkOperation.Update);
        var bulkDeleteReceipt = new InfisicalBulkReceipt(client, bulkTarget, bulkInputs, InfisicalBulkOperation.Delete);
        MutationReceipt importReceipt = client.CreateReceipt(importTarget);
        MutationReceipt environmentReceipt = client.CreateReceipt(environmentTarget);
        MutationReceipt tagReceipt = client.CreateReceipt(tagTarget);
        MutationReceipt folderReceipt = client.CreateReceipt(folderTarget);
        MutationReceipt folderMoveReceipt = client.CreateReceipt(folderTarget);
        MutationReceipt validationReceipt = client.CreateReceipt(validationTarget);

        var dynamicClient = new InfisicalDynamicClient(new("https://infisical.test"), tokens,
            new("project", "dev", "/", Guid.Parse(Phase5TestSupport.EnvironmentId)), options);
        InfisicalDynamicTarget definitionTarget = dynamicClient.Definition("db");
        var createDefinitionReceipt = new InfisicalDynamicMutationReceipt(definitionTarget, InfisicalDynamicOperation.CreateDefinition);

        var rotationAuthority = new SecretAuthority();
        var rotationClient = new InfisicalRotationClient(new("https://infisical.test"), rotationAuthority,
            new(rotationAuthority, tokens, "project"), options);
        SecretReference rotationScope = new(rotationAuthority, new InfisicalRotationScope("project"));
        SecretReference rotationTarget = new(rotationAuthority,
            new InfisicalRotationAddress("project", "dev", "/", InfisicalRotationProfile.Auth0ClientSecret, Phase5TestSupport.Id));
        var rotationReceipt = new InfisicalRotationReceipt(rotationTarget, InfisicalRotationAction.RotateSecrets);
        using var dynamicProfile = new NativeSqlDefinitionProfile(
            NativeSqlEngine.Postgres, "db.test", 5432, "user-canary", "password-canary", "app",
            "CREATE ROLE x;", "DROP ROLE x;");

        var universalAuth = new InfisicalUniversalAuthentication(new("https://auth.test"), wire);
        InfisicalUniversalLoginReceipt universalReceipt = universalAuth.CreateReceipt();
        var proofAuth = new InfisicalProofAuthentication(new("https://auth.test"), wire);
        InfisicalProofLoginReceipt proofLoginReceipt = proofAuth.CreateReceipt();
        InfisicalTokenRevocationReceipt revocationReceipt = proofAuth.CreateRevocationReceipt();
        using var proof = InfisicalLoginProof.Oidc("identity-canary", secretMaterial);

        await client.DisposeAsync();
        await dynamicClient.DisposeAsync();
        await rotationClient.DisposeAsync();
        universalAuth.Dispose();
        proofAuth.Dispose();

        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        using var telemetry = new TelemetryCapture();

        await Assert.That(async () => await client.ReadAsync(secretTarget)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.ReadNativeAsync(secretTarget)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.InspectAsync(
            new InfisicalInventoryScope(client.Authority, "project", "dev", "/"))).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.CreateAsync(secretTarget, secretMaterial, staticCreateReceipt)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.UpdateValueAsync(secretTarget, secretMaterial, staticUpdateReceipt)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.CreateSecretsAsync(bulkTarget, bulkInputs, admin, bulkCreateReceipt)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.UpdateSecretsAsync(bulkTarget, bulkInputs, admin, bulkUpdateReceipt)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.DeleteSecretsAsync(bulkTarget, bulkInputs, admin, bulkDeleteReceipt)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.GetImportAsync(importTarget)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.ListImportsAsync(folderScope)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.ReadImportedSecretsAsync(folderScope)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.ObserveImportEffectsAsync(importTarget, client, secretTarget)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.CreateImportAsync(folderScope, new("dev", "/src"), false, admin, importReceipt)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.GetEnvironmentAsync(environmentTarget)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.RestoreEnvironmentAsync(environmentTarget, admin, environmentReceipt)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.GetTagAsync(tagTarget)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.ListTagsAsync(tagTarget)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.DeleteTagAsync(tagTarget, admin, tagReceipt)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.GetFolderAsync(folderTarget)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.ListFoldersAsync(folderScope)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.UpdateFoldersAsync(folderScope, [], admin, folderReceipt)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.MoveFolderAsync(folderTarget,
            new InfisicalFolderAddress("project", "prod", Phase5TestSupport.OtherEnvironmentId, "/"), admin, folderMoveReceipt)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.GetValidationRuleAsync(validationTarget)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.DeleteValidationRuleAsync(validationTarget, admin, validationReceipt)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await client.ListValidationRulesAsync(validationScope)).Throws<ObjectDisposedException>();

        await Assert.That(async () => await dynamicClient.ListDefinitionsAsync()).Throws<ObjectDisposedException>();
        await Assert.That(async () => await dynamicClient.InspectDefinitionAsync(definitionTarget)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await dynamicClient.CreateDefinitionAsync(definitionTarget,
            dynamicProfile, new(TimeSpan.FromMinutes(5)), null, createDefinitionReceipt)).Throws<ObjectDisposedException>();

        await Assert.That(async () => await rotationClient.ListAsync(rotationScope)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await rotationClient.GetAsync(rotationTarget)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await rotationClient.RotateSecretsAsync(rotationTarget, rotationReceipt)).Throws<ObjectDisposedException>();

        await Assert.That(() => universalAuth.CreateReceipt()).Throws<ObjectDisposedException>();
        await Assert.That(async () => await universalAuth.LoginAsync("client-id", secretMaterial, universalReceipt)).Throws<ObjectDisposedException>();

        await Assert.That(() => proofAuth.CreateReceipt()).Throws<ObjectDisposedException>();
        await Assert.That(() => proofAuth.CreateRevocationReceipt()).Throws<ObjectDisposedException>();
        await Assert.That(async () => await proofAuth.LoginAsync(proof, proofLoginReceipt)).Throws<ObjectDisposedException>();
        await Assert.That(async () => await proofAuth.RevokeTokenAsync(secretMaterial, revocationReceipt)).Throws<ObjectDisposedException>();

        // Pre-canceled callers retain cancellation precedence without emitting telemetry.
        await Assert.That(async () => await client.InspectAsync(
            new InfisicalInventoryScope(client.Authority, "project", "dev", "/"), canceled.Token)).Throws<OperationCanceledException>();
        await Assert.That(async () => await universalAuth.LoginAsync(
            "client-id", secretMaterial, universalReceipt, cancellationToken: canceled.Token)).Throws<OperationCanceledException>();
        await Assert.That(async () => await proofAuth.LoginAsync(
            proof, proofLoginReceipt, canceled.Token)).Throws<OperationCanceledException>();
        await Assert.That(async () => await proofAuth.RevokeTokenAsync(
            secretMaterial, revocationReceipt, canceled.Token)).Throws<OperationCanceledException>();

        await Assert.That(telemetry.Spans).IsEmpty();
        await Assert.That(telemetry.MeasurementCount).IsEqualTo(0);
        await Assert.That(tokens.Calls).IsEqualTo(0);
        await Assert.That(wire.Calls).IsEqualTo(0);
    }

    [Test]
    public async Task ConcurrentDisposeKeepsInFlightAuthTransportAliveUntilCompletion()
    {
        var universalWire = new HeldJsonWire("""{"accessToken":"u-token","tokenType":"Bearer","expiresIn":120,"accessTokenMaxTTL":0}""");
        using var universal = new InfisicalUniversalAuthentication(new("https://auth.test"), universalWire);
        using var secret = SecretMaterial.FromText("client-secret-canary");
        Task<SecretOutcome<InfisicalUniversalLogin>> universalTask = universal
            .LoginAsync("client-id", secret, universal.CreateReceipt()).AsTask();
        await universalWire.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        universal.Dispose();
        universalWire.Release.SetResult();
        SecretOutcome<InfisicalUniversalLogin> universalOutcome = await universalTask.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.That(universalOutcome.Status).IsEqualTo(SecretStatus.Success);
        universalOutcome.Value.Dispose();
        await Assert.That(() => universal.CreateReceipt()).Throws<ObjectDisposedException>();

        var proofWire = new HeldJsonWire("""{"accessToken":"p-token","tokenType":"Bearer","expiresIn":120,"accessTokenMaxTTL":0}""");
        using var proofClient = new InfisicalProofAuthentication(new("https://auth.test"), proofWire);
        using var proof = InfisicalLoginProof.Oidc("identity", secret);
        Task<SecretOutcome<InfisicalProofLogin>> proofTask = proofClient
            .LoginAsync(proof, proofClient.CreateReceipt()).AsTask();
        await proofWire.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        proofClient.Dispose();
        proofWire.Release.SetResult();
        SecretOutcome<InfisicalProofLogin> proofOutcome = await proofTask.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.That(proofOutcome.Status).IsEqualTo(SecretStatus.Success);
        proofOutcome.Value.Dispose();

        var revokeWire = new HeldJsonWire("""{"message":"Successfully revoked token"}""");
        using var revokeClient = new InfisicalProofAuthentication(new("https://auth.test"), revokeWire);
        Task<SecretOutcome<InfisicalTokenRevocationReceipt>> revokeTask = revokeClient
            .RevokeTokenAsync(secret, revokeClient.CreateRevocationReceipt()).AsTask();
        await revokeWire.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        revokeClient.Dispose();
        revokeWire.Release.SetResult();
        SecretOutcome<InfisicalTokenRevocationReceipt> revokeOutcome = await revokeTask.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.That(revokeOutcome.Status).IsEqualTo(SecretStatus.Success);
    }

    [Test]
    public async Task InfisicalLockFieldsUseSystemThreadingLock()
    {
        FieldInfo[] legacyGates = typeof(InfisicalClient).Assembly.GetTypes()
            .SelectMany(type => type.GetFields(BindingFlags.Instance | BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public))
            .Where(field => field.Name is "_gate" or "Gate" && field.FieldType == typeof(object))
            .ToArray();
        await Assert.That(legacyGates).IsEmpty();
    }

    private sealed class CountingTokens : IInfisicalTokenSource
    {
        private int _calls;
        internal int Calls => Volatile.Read(ref _calls);
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText("unused-token"), null)));
        }
    }

    private sealed class CountingWire : HttpMessageHandler
    {
        private int _calls;
        internal int Calls => Volatile.Read(ref _calls);
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError));
        }
    }

    private sealed class HeldJsonWire(string body) : HttpMessageHandler
    {
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Entered.TrySetResult();
            await Release.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(Encoding.UTF8.GetBytes(body))
            };
        }
    }

    private sealed class TelemetryCapture : IDisposable
    {
        private readonly ActivityListener _activityListener;
        private readonly MeterListener _meterListener = new();
        private int _measurements;
        internal ConcurrentQueue<string> Spans { get; } = new();
        internal int MeasurementCount => Volatile.Read(ref _measurements);

        internal TelemetryCapture()
        {
            _activityListener = new ActivityListener
            {
                ShouldListenTo = source => source.Name == "SecretKit.Infisical",
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStarted = activity => Spans.Enqueue(activity.OperationName)
            };
            ActivitySource.AddActivityListener(_activityListener);
            _meterListener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == "SecretKit.Infisical")
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };
            _meterListener.SetMeasurementEventCallback<long>((_, _, _, _) => Interlocked.Increment(ref _measurements));
            _meterListener.SetMeasurementEventCallback<double>((_, _, _, _) => Interlocked.Increment(ref _measurements));
            _meterListener.Start();
        }

        public void Dispose()
        {
            _activityListener.Dispose();
            _meterListener.Dispose();
        }
    }
}
