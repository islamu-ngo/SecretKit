using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalTemplatePrincipalSource(InfisicalLifecycleObservers channel, string identity,
    TemplatePrincipalKind kind = TemplatePrincipalKind.NativeProvider) : ITemplatePrincipalSource
{
    private readonly object gate = new();
    private readonly Dictionary<string, Session> sessions = [];
    public string Identity => identity;
    public TemplatePrincipalKind Kind => kind;
    private sealed class Session(TemplatePrincipalRoot root)
    {
        internal string RootHash { get; } = TemplatePrincipalContract.Hash(root);
        internal string Nonce { get; } = root.Nonce;
        internal int Stage;
        internal bool Busy, Failed, Closed;
    }
    public async ValueTask<TemplatePrincipalPacket> StepAsync(TemplatePrincipalRoot root, TemplatePrincipalStep step,
        SecretMaterial? capability, TemplatePrincipalReceipt? receipt, CancellationToken token)
    {
        Session session;
        lock (gate)
        {
            if (step == TemplatePrincipalStep.Reserve)
            {
                TemplatePrincipalContract.Require(root.Source == Identity && root.Kind == Kind &&
                    sessions.Values.All(s => s.Nonce != root.Nonce) && sessions.TryAdd(root.Id, new(root)), "missing-input");
            }
            TemplatePrincipalContract.Require(sessions.TryGetValue(root.Id, out var found) &&
                found.RootHash == TemplatePrincipalContract.Hash(root) && !found.Closed &&
                (step == TemplatePrincipalStep.Close || !found.Busy && !found.Failed && found.Stage == (int)step));
            session = found!;
            if (step == TemplatePrincipalStep.Close) session.Closed = true;
            else { session.Busy = session.Failed = true; session.Stage++; }
        }
        TemplatePrincipalPacket? packet = null;
        try
        {
            packet = await channel.PostAsync<TemplatePrincipalPacket>("template-principal/step", w =>
            {
                w.WritePropertyName("root"); JsonSerializer.Serialize(w, root, TemplatePrincipalContract.Options);
                w.WriteNumber("step", (int)step);
                if (capability is not null)
                {
                    char[] chars = capability.ExportCharacters();
                    try { w.WriteString("capability", chars); } finally { Array.Clear(chars); }
                }
                if (receipt is not null)
                {
                    w.WritePropertyName("receipt"); JsonSerializer.Serialize(w, receipt, TemplatePrincipalContract.Options);
                }
            }, token);
            lock (gate)
            {
                TemplatePrincipalContract.Require(step == TemplatePrincipalStep.Close || !session.Closed);
                session.Failed = false;
            }
            return packet;
        }
        catch { packet?.Owner.Payload.Content.Issued?.Erase(); throw; }
        finally { lock (gate) session.Busy = false; }
    }
    public override string ToString() => "[InfisicalTemplatePrincipalSource]";
}
