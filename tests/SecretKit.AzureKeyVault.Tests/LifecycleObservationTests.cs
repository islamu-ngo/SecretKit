using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Tests;

public sealed class LifecycleObservationTests
{
    [Test]
    [Arguments(true, "visible")]
    [Arguments(false, "visible")]
    [Arguments(true, "absent")]
    [Arguments(false, "absent")]
    [Arguments(true, "empty")]
    [Arguments(false, "unrelated")]
    [Arguments(true, "denied")]
    [Arguments(false, "denied")]
    [Arguments(true, "invalid-row")]
    [Arguments(false, "invalid-row")]
    [Arguments(true, "invalid-next")]
    [Arguments(false, "invalid-next")]
    [Arguments(true, "limit")]
    [Arguments(false, "limit")]
    public async Task StatusUsesOnlyCompleteValidatedMetadata(bool recover, string scenario)
    {
        var vault = new Uri($"https://l{Guid.NewGuid():N}"[..22] + ".vault.azure.net");
        var version = new string('a', 32);
        var newer = new string('b', 32);
        var reads = 0;
        var invalidRoute = 0;
        var mutations = 0;
        var collection = recover ? "/secrets/target/versions" : "/deletedsecrets";
        object Row(string name, string ver, int created, bool wrong = false) => new
        {
            id = $"{(wrong ? "https://other.vault.azure.net/" : vault.AbsoluteUri)}secrets/{name}/{ver}",
            recoveryId = $"{vault}deletedsecrets/{name}",
            attributes = new { enabled = false, created }
        };
        var wire = new WireTransport((request, _) =>
        {
            if (request.Headers.Authorization is null) return Task.FromResult(WireTransport.Challenge());
            var path = request.RequestUri!.AbsolutePath.TrimEnd('/');
            if (request.Method != HttpMethod.Get)
            {
                mutations++;
                return Task.FromResult(WireTransport.Json(200, JsonSerializer.Serialize(Row("target", version, 10))));
            }
            if (path != collection)
            {
                invalidRoute++;
                return Task.FromResult(WireTransport.Json(403, "{}"));
            }
            reads++;
            if (scenario is "absent" or "denied") return Task.FromResult(WireTransport.Json(scenario == "absent" ? 404 : 403, "{}"));
            object[] rows = scenario switch
            {
                "empty" => [],
                "unrelated" => [Row("other", version, 10)],
                "invalid-row" => [Row("target", version, 10), Row("target", newer, 20, wrong: true)],
                _ => [Row(!recover && reads == 1 ? "other" : "target", reads == 1 ? version : newer, reads == 1 ? 10 : 20)]
            };
            string? next = scenario switch
            {
                "invalid-next" => new UriBuilder(request.RequestUri!) { Path = "/secrets/target" }.Uri.AbsoluteUri,
                "limit" => $"{request.RequestUri.AbsoluteUri}&page={reads + 1}",
                "visible" when reads == 1 => $"{request.RequestUri.AbsoluteUri}&page=2",
                _ => null
            };
            return Task.FromResult(WireTransport.Json(200, JsonSerializer.Serialize(new { value = rows, nextLink = next })));
        });
        var client = new AzureKeyVaultClient(vault, new TestCredential(), wire);
        var target = new SecretReference(client.Authority, new AzureSecretAddress("target"));
        var receipt = client.CreateReceipt(target);
        var start = recover ? await client.StartRecoverDeletedSecretAsync(target, receipt) : await client.StartDeleteSecretAsync(target, receipt);
        var result = await client.CheckLifecycleStatusAsync(start.Value.Operation);
        await Assert.That((invalidRoute, mutations, receipt.Evidence)).IsEqualTo((0, 1, DispatchEvidence.Pending));
        await Assert.That(reads).IsEqualTo(scenario switch { "visible" => 2, "limit" => 10, _ => 1 });
        await Assert.That(result.Status).IsEqualTo(scenario switch
        {
            "denied" => SecretStatus.Denied,
            "limit" => SecretStatus.Unknown,
            "invalid-row" or "invalid-next" => SecretStatus.Invalid,
            _ => SecretStatus.Success
        });
        if (scenario == "visible")
        {
            await Assert.That(result.Value.State).IsEqualTo(AzureLifecycleState.Applied);
            var metadata = result.Value.Metadata!;
            await Assert.That(((AzureSecretAddress)metadata.Reference.Address).Version).IsEqualTo(newer);
            await Assert.That(metadata.Enabled).IsFalse();
        }
        else if (result.IsSuccess)
        {
            await Assert.That(result.Value.State).IsEqualTo(AzureLifecycleState.Pending);
            await Assert.That(result.Value.Metadata).IsNull();
        }
    }

    [Test]
    [Arguments(false, 401, SecretStatus.Denied, DispatchEvidence.NotDispatched)]
    [Arguments(false, 429, SecretStatus.Throttled, DispatchEvidence.NotDispatched)]
    [Arguments(true, 400, SecretStatus.Invalid, DispatchEvidence.Rejected)]
    [Arguments(true, 403, SecretStatus.Denied, DispatchEvidence.Rejected)]
    [Arguments(true, 404, SecretStatus.Absent, DispatchEvidence.Rejected)]
    [Arguments(true, 409, SecretStatus.Conflict, DispatchEvidence.Conflict)]
    public async Task BodylessMutationSeparatesChallengeFailureFromServiceRejection(bool dispatch, int status, SecretStatus expected, DispatchEvidence evidence)
    {
        var vault = new Uri($"https://f{Guid.NewGuid():N}"[..22] + ".vault.azure.net");
        var wire = new WireTransport((request, _) => Task.FromResult(dispatch && request.Headers.Authorization is null
            ? WireTransport.Challenge() : WireTransport.Json(status, "{}")));
        var client = new AzureKeyVaultClient(vault, new TestCredential(), wire);
        var target = new SecretReference(client.Authority, new AzureSecretAddress("target"));
        var receipt = client.CreateReceipt(target);
        var result = await client.StartDeleteSecretAsync(target, receipt);
        await Assert.That((result.Status, receipt.Evidence, wire.Authorized.Count(a => a))).IsEqualTo((expected, evidence, dispatch ? 1 : 0));
    }
}
