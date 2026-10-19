using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    public async Task StatusVaultRecoverCancellationCaptureRetainsActualTasksAndDistinctNativeReadKinds()
    {
        using var f = new Fixture("RecoverVault", boundary: "cancellation-boundary");
        ConfigureCancellationRecover(f);
        Task? start = null, canceled = null, later = null;
        await Assert.That(await f.Start(retained: t => start = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token, t => canceled = t)).Throws<OperationCanceledException>();
        await Assert.That(canceled!.IsCanceled).IsTrue();
        await Assert.That(f.Window.Status).IsNull();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Source.OwnsRecoverCanceledStatusAttempt(f.Window, f.Binding, f.Client, (VaultScope)f.Scope,
            f.Receipt, start!, f.Handle!, canceled)).IsTrue();
        var scope = (VaultScope)f.Scope;
        await Assert.That(f.Source.OwnsRecoverCanceledStatusAttempt(f.Window, f.Binding, f.Client,
            new(scope.ResourceGroup, scope.VaultName), f.Receipt, start!, f.Handle!, canceled)).IsFalse();
        await Assert.That(f.Source.OwnsRecoverCanceledStatusAttempt(f.Window, f.Binding with { }, f.Client, scope,
            f.Receipt, start!, f.Handle!, canceled)).IsFalse();
        await Assert.That(f.Source.OwnsRecoverCanceledStatusAttempt(f.Window, f.Binding, f.Client, scope,
            f.Receipt, start!, f.Handle!, Task.FromCanceled<SecretStatus>(stop.Token))).IsFalse();
        await Assert.That(await f.Check(retained: t => later = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.OwnsStatusVaultRecoverCancellationCompletion(f.Window, f.Binding, f.Client,
            scope, f.Receipt, start!, f.Handle!, canceled, later!)).IsTrue();
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsTrue();
        await Assert.That(f.Window.Status!.Attempts.Count).IsEqualTo(2);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(3);
        await Assert.That(f.Backend.Requests[1].Path).IsEqualTo(f.Backend.StatusPath);
        await Assert.That(f.Backend.Requests[2].Path).IsEqualTo(Vault);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("uncanceled")]
    [Arguments("foreign-handle")]
    [Arguments("retention")]
    public async Task StatusVaultRecoverCancellationCaptureRejectsUnqualifiedFirstCheck(string fault)
    {
        using var f = new Fixture("RecoverVault", boundary: "cancellation-boundary");
        using var other = new Fixture("RecoverVault");
        ConfigureCancellationRecover(f);
        ConfigureCancellationRecover(other);
        Task? start = null, canceled = null;
        await f.Start(retained: t => start = t);
        await other.Start();
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        Task<SecretStatus> Invoke() => f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            fault == "foreign-handle" ? other.Handle! : f.Handle!, fault == "uncanceled" ? default : stop.Token, t =>
            {
                canceled = t;
                if (fault == "retention") throw new InvalidOperationException("controlled-retention-failure");
            });
        if (fault == "retention")
        {
            await Assert.That(async () => await Invoke()).Throws<OperationCanceledException>();
            await Assert.That(canceled!.IsCanceled).IsTrue();
            await Assert.That(f.Source.OwnsRecoverCanceledStatusAttempt(f.Window, f.Binding, f.Client, (VaultScope)f.Scope,
                f.Receipt, start!, f.Handle!, canceled)).IsFalse();
        }
        else
        {
            await Assert.That(async () => await Invoke()).Throws<InvalidOperationException>();
            await Assert.That(canceled is null).IsTrue();
        }
        await Assert.That(f.Window.Status).IsNull();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    public async Task StatusVaultRecoverCancellationCaptureMissingAndRepeatedCancellationCannotConsumeStatusSlot()
    {
        using var f = new Fixture("RecoverVault", boundary: "cancellation-boundary");
        ConfigureCancellationRecover(f);
        await f.Start();
        await Assert.That(async () => await f.Check()).Throws<InvalidOperationException>();
        await Assert.That(f.Window.Status).IsNull();
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token)).Throws<OperationCanceledException>();
        await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
            f.Handle!, stop.Token)).Throws<InvalidOperationException>();
        await Assert.That(f.Window.Status).IsNull();
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(3);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments(1, false)]
    [Arguments(1, true)]
    [Arguments(2, false)]
    [Arguments(2, true)]
    [Arguments(3, false)]
    [Arguments(3, true)]
    public async Task StatusVaultRecoverCancellationCaptureRejectsResponseAndStreamSubstitutions(int stage, bool streamOnly)
    {
        PurgeCancellationSubstitution? substitution = null;
        using var f = new Fixture("RecoverVault", boundary: "cancellation-boundary",
            decorate: inner => substitution = new(inner, stage, streamOnly));
        ConfigureCancellationRecover(f);
        Task? start = null, canceled = null, later = null;
        await f.Start(retained: t => start = t);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        if (stage == 1)
            await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
                f.Handle!, stop.Token)).Throws<InvalidOperationException>();
        else
        {
            await Assert.That(async () => await f.Source.CheckCanceledStatusAsync(f.Window, f.Binding.Selector,
                f.Handle!, stop.Token, t => canceled = t)).Throws<OperationCanceledException>();
            await f.Check(retained: t => later = t);
            await Assert.That(f.Source.OwnsStatusVaultRecoverCancellationCompletion(f.Window, f.Binding, f.Client,
                (VaultScope)f.Scope, f.Receipt, start!, f.Handle!, canceled!, later!)).IsFalse();
        }
        await Assert.That(substitution!.Replacements).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    private static void ConfigureCancellationRecover(Fixture f)
    {
        f.AsyncStart();
        var final = JsonNode.Parse(f.Backend.FinalBody!)!;
        var p = final["properties"]!;
        p["enableRbacAuthorization"] = true;
        p["enablePurgeProtection"] = false;
        p["enableSoftDelete"] = true;
        p["softDeleteRetentionInDays"] = 7;
        p["publicNetworkAccess"] = "Enabled";
        p["accessPolicies"] = new JsonArray();
        p["privateEndpointConnections"] = new JsonArray();
        p["createMode"] = "recover";
        final["tags"] = new JsonObject { ["secretkit-fixture"] = f.Binding.Selector.Nonce.ToString("N") };
        f.Backend.FinalBody = final.ToJsonString();
        p["provisioningState"] = "Updating";
        f.Backend.StartStatus = 201;
        f.Backend.StartBody = final.ToJsonString();
        f.Backend.StatusBody = """{"status":"Succeeded"}""";
        f.Backend.ExtraHeaders.Add(("x-ms-request-id", "native-recover-capture"));
    }
}
