using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalSettingsPermissionFixtureSource(InfisicalSettingsPermissionFixture provider) : HttpMessageHandler
{
    private readonly ECDsa coordinator = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    internal InfisicalSettingsPermissionSource CreateClient() => new(new(provider.Input(SettingsPermissionContract.Operations[0], SettingsPermissionAction.Edit).Observer,
        this, length => { var bytes = new byte[length]; provider.Copies.Add(bytes); return bytes; }), "settings-coordinator", MemberPermissionSourceKind.ControlledFixture);
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (request.Headers.Authorization?.Parameter != "coordinator-token") return new(HttpStatusCode.Forbidden);
        byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token); provider.Copies.Add(bytes);
        try
        {
            using var document = JsonDocument.Parse(bytes); var body = document.RootElement;
            NativeRunProtocol.RejectDuplicates(body);
            if (request.RequestUri!.AbsolutePath != "/settings-permission/step") return new(HttpStatusCode.NotFound);
            var root = body.GetProperty("root").Deserialize<SettingsPermissionRoot>(SettingsPermissionContract.Options)!;
            var step = (SettingsPermissionStep)body.GetProperty("step").GetInt32();
            if (step == SettingsPermissionStep.Close) await provider.SealAndDrainAsync();
            var packet = provider.Step(root, step, body.TryGetProperty("capability", out var cap) ? cap.GetString() : null);
            if (provider.Fault == "interrupted-open" && step == SettingsPermissionStep.Open)
            {
                provider.OpenEntered.TrySetResult(); await provider.OpenRelease.Task.WaitAsync(token);
            }
            if (step is SettingsPermissionStep.Open or SettingsPermissionStep.ObserveAfter)
                packet = Tamper(packet, provider.Fault);
            byte[] response = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                nonce = body.GetProperty("nonce").GetString(),
                observerIdentity = "settings-coordinator",
                observedAt = DateTimeOffset.UtcNow,
                facts = packet
            }, SettingsPermissionContract.Options);
            provider.Copies.Add(response);
            return new(HttpStatusCode.OK) { Content = new ClearingContent(response) };
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal SettingsPermissionPacket Tamper(SettingsPermissionPacket packet, string fault)
    {
        var journals = packet.Journals.ToArray();
        foreach (var journal in Enum.GetValues<SettingsPermissionJournal>())
        {
            int index = Array.FindIndex(journals, j => j.Content.Journal == journal);
            var signed = journals[index]; var p = signed.Content;
            if (fault == "forge-" + journal)
            {
                byte[] bytes = SettingsPermissionContract.Bytes(p);
                try { signed = signed with { Signature = Convert.ToBase64String(coordinator.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) }; }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
            if (fault == "omit-" + journal && p.Events.Length > 1) signed = signed with { Content = p with { Events = p.Events.Where((_, i) => i != 1).ToArray() } };
            if (fault == "duplicate-" + journal) signed = signed with { Content = p with { Events = [.. p.Events, p.Events[0]] } };
            if (fault == "reorder-" + journal) signed = signed with { Content = p with { Events = p.Events.Reverse().ToArray() } };
            if (fault == "substitute-" + journal) signed = signed with { Content = p with { Head = "substituted" } };
            if (fault == "nonterminal-" + journal) signed = signed with { Content = p with { Terminal = false } };
            journals[index] = signed;
        }
        return packet with { Journals = fault == "missing-journal" ? journals.Skip(1).ToArray() : journals };
    }
    protected override void Dispose(bool disposing) { if (disposing) coordinator.Dispose(); base.Dispose(disposing); }
    private sealed class ClearingContent : ByteArrayContent
    {
        private readonly byte[] bytes;
        internal ClearingContent(byte[] bytes) : base(bytes) => this.bytes = bytes;
        protected override void Dispose(bool disposing) { base.Dispose(disposing); if (disposing) CryptographicOperations.ZeroMemory(bytes); }
    }
}
