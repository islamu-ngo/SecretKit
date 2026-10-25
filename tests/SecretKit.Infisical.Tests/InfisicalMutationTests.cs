using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class InfisicalMutationTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SelectedCreateAndUpdatePreserveBytesAndReturnObservedVersion(bool update)
    {
        string value = Material() + "\n\n";
        var backend = new Backend();
        await using InfisicalClient client = Client(backend);
        SecretReference target = Target(client);
        var receipt = new MutationReceipt(target);
        using SecretMaterial material = SecretMaterial.FromText(value);

        SecretOutcome<InfisicalStaticChange> result = update
            ? await client.UpdateValueAsync(target, material, receipt)
            : await client.CreateAsync(target, material, receipt);

        await Assert.That(result.Value.Disposition).IsEqualTo(InfisicalChangeDisposition.Applied);
        await Assert.That(result.Value.Version).IsEqualTo("1");
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        using SecretRead observed = (await client.ReadAsync(target)).Value;
        await Assert.That(observed.Material.Reveal()).IsEqualTo(value);
        await Assert.That(material.Reveal()).IsEqualTo(value);
        await Assert.That(JsonSerializer.Serialize(result).Contains(value, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task CommittedLostResponseRemainsUnknownWithoutReplay()
    {
        var backend = new Backend { DropResponse = true };
        await using InfisicalClient client = Client(backend);
        SecretReference target = Target(client);
        var receipt = new MutationReceipt(target);
        string value = Material();
        using SecretMaterial material = SecretMaterial.FromText(value);

        SecretOutcome<InfisicalStaticChange> result = await client.CreateAsync(target, material, receipt);

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        using SecretRead observed = (await client.ReadAsync(target)).Value;
        await Assert.That(observed.Material.Reveal()).IsEqualTo(value);
        await Assert.That(observed.Observation.Version).IsEqualTo("1");
        SecretOutcome<InfisicalStaticChange> replay = await client.CreateAsync(target, material, receipt);
        await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        using SecretRead unchanged = (await client.ReadAsync(target)).Value;
        await Assert.That(unchanged.Observation.Version).IsEqualTo("1");
    }

    [Test]
    public async Task DuplicateMutationResponseRetainsUncertaintyWithoutReplay()
    {
        var backend = new Backend { AmbiguousResponse = true };
        await using InfisicalClient client = Client(backend);
        SecretReference target = Target(client);
        var receipt = new MutationReceipt(target);
        using SecretMaterial material = SecretMaterial.FromText(Material());

        SecretOutcome<InfisicalStaticChange> result = await client.CreateAsync(target, material, receipt);

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(() => result.Value).Throws<InvalidOperationException>();
        using SecretRead observed = (await client.ReadAsync(target)).Value;
        await Assert.That(observed.Material.Reveal()).IsEqualTo(material.Reveal());
        await Assert.That(observed.Observation.Version).IsEqualTo("1");

        SecretOutcome<InfisicalStaticChange> replay = await client.CreateAsync(target, material, receipt);

        await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        using SecretRead unchanged = (await client.ReadAsync(target)).Value;
        await Assert.That(unchanged.Observation.Version).IsEqualTo("1");
    }

    [Test]
    public async Task SubmittedApprovalIsNotAppliedMaterial()
    {
        var backend = new Backend { Approval = true };
        await using InfisicalClient client = Client(backend);
        SecretReference target = Target(client);
        var receipt = new MutationReceipt(target);
        using SecretMaterial material = SecretMaterial.FromText(Material());

        SecretOutcome<InfisicalStaticChange> result = await client.UpdateValueAsync(target, material, receipt);

        await Assert.That(result.Value.Disposition).IsEqualTo(InfisicalChangeDisposition.SubmittedForApproval);
        await Assert.That(result.Value.Version is null).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That((await client.ReadAsync(target)).Status).IsEqualTo(SecretStatus.Absent);
        await Assert.That(JsonSerializer.Serialize(result.Value).Contains(result.Value.ApprovalId!, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DefiniteRejectionIsNotAnUnknownWriteAndCannotReuseItsReceipt(bool update)
    {
        var backend = new Backend { Reject = true };
        await using InfisicalClient client = Client(backend);
        SecretReference target = Target(client);
        var receipt = new MutationReceipt(target);
        using SecretMaterial material = SecretMaterial.FromText(Material());

        SecretOutcome<InfisicalStaticChange> result = update
            ? await client.UpdateValueAsync(target, material, receipt)
            : await client.CreateAsync(target, material, receipt);

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Rejected);
        await Assert.That(() => result.Value).Throws<InvalidOperationException>();
        await Assert.That((await client.ReadAsync(target)).Status).IsEqualTo(SecretStatus.Absent);
        SecretOutcome<InfisicalStaticChange> replay = await client.CreateAsync(target, material, receipt);
        await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Rejected);
    }

    [Test]
    public async Task CancelBeforeDispatchDoesNotAcquireCredentialsOrChangeState()
    {
        var backend = new Backend();
        await using InfisicalClient client = Client(backend);
        SecretReference target = Target(client);
        var receipt = new MutationReceipt(target);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        using SecretMaterial material = SecretMaterial.FromText(Material());

        await Assert.That(async () => await client.CreateAsync(target, material, receipt, cancellation.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That((await client.ReadAsync(target)).Status).IsEqualTo(SecretStatus.Absent);
    }

    [Test]
    public async Task CancelAfterCommitPropagatesAndRetainsUncertainEffect()
    {
        var backend = new Backend { HoldResponse = true };
        await using InfisicalClient client = Client(backend);
        SecretReference target = Target(client);
        var receipt = new MutationReceipt(target);
        using var cancellation = new CancellationTokenSource();
        using SecretMaterial material = SecretMaterial.FromText(Material());
        Task<SecretOutcome<InfisicalStaticChange>> pending = client.CreateAsync(target, material, receipt, cancellation.Token).AsTask();
        await backend.Committed.Task.WaitAsync(TimeSpan.FromSeconds(5));

        cancellation.Cancel();

        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        using SecretRead observed = (await client.ReadAsync(target)).Value;
        await Assert.That(observed.Observation.Version).IsEqualTo("1");
        await Assert.That(observed.Material.Reveal()).IsEqualTo(material.Reveal());
        SecretOutcome<InfisicalStaticChange> replay = await client.CreateAsync(target, material, receipt);
        await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        using SecretRead unchanged = (await client.ReadAsync(target)).Value;
        await Assert.That(unchanged.Observation.Version).IsEqualTo("1");
    }

    [Test]
    public async Task VersionSelectorCannotPretendToBeAWritePrecondition()
    {
        var backend = new Backend();
        await using InfisicalClient client = Client(backend);
        var target = new SecretReference(client.Authority, new InfisicalSecretAddress("project", "env", "/", "key", 7));
        var receipt = new MutationReceipt(target);
        using SecretMaterial material = SecretMaterial.FromText(Material());

        SecretOutcome<InfisicalStaticChange> result = await client.UpdateValueAsync(target, material, receipt);

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unsupported);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That((await client.ReadAsync(Target(client))).Status).IsEqualTo(SecretStatus.Absent);
    }

    private static string Material() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    private static SecretReference Target(InfisicalClient client) =>
        new(client.Authority, new InfisicalSecretAddress("project", "env", "/", "key"));
    private static InfisicalClient Client(Backend backend) =>
        new(new Uri("https://infisical.test"), new Tokens(), new InfisicalNetworkOptions(), null, backend);

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText(Material()))));
        }
    }

    private sealed class Backend : HttpMessageHandler
    {
        private string? _value;
        private int _version;
        public bool DropResponse { get; init; }
        public bool Approval { get; init; }
        public bool HoldResponse { get; init; }
        public bool AmbiguousResponse { get; init; }
        public bool Reject { get; init; }
        public TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _never = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (request.Method == HttpMethod.Get)
            {
                return _value is null ? Json(404, new { }) : Json(200, new
                {
                    secret = new { secretKey = "key", secretValue = _value, secretValueHidden = false, version = _version }
                });
            }

            using JsonDocument body = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(token));
            if (body.RootElement.GetProperty("projectId").GetString() != "project" ||
                body.RootElement.GetProperty("environment").GetString() != "env" ||
                body.RootElement.GetProperty("secretPath").GetString() != "/" ||
                !body.RootElement.GetProperty("skipMultilineEncoding").GetBoolean())
            {
                return Json(400, new { });
            }

            if (Reject)
            {
                return Json(403, new { });
            }

            if (Approval)
            {
                return Json(200, new { approval = new { id = Guid.NewGuid(), hasMerged = false } });
            }

            _value = body.RootElement.GetProperty("secretValue").GetString();
            _version++;
            Committed.TrySetResult();
            if (HoldResponse)
            {
                await _never.Task.WaitAsync(token);
            }

            if (DropResponse)
            {
                throw new HttpRequestException("Fixture response lost after commit.");
            }

            if (AmbiguousResponse)
            {
                return new(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        """{"secret":{"secretKey":"other-key","secretKey":"key","workspace":"project","environment":"env","version":1}}""",
                        Encoding.UTF8, "application/json")
                };
            }

            return Json(200, new
            {
                secret = new { secretKey = "key", workspace = "project", environment = "env", version = _version }
            });
        }

        private static HttpResponseMessage Json<T>(int status, T body) => new((HttpStatusCode)status)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
        };
    }
}
