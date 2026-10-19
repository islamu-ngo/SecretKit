using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalGroupPermissionSource(InfisicalLifecycleObservers channel, string identity,
    MemberPermissionSourceKind kind = MemberPermissionSourceKind.NativeProvider) : IGroupPermissionSource
{
    public string Identity => identity;
    public MemberPermissionSourceKind Kind => kind;
    private readonly object gate = new();
    private readonly Dictionary<string, Session> sessions = [];
    private sealed class Session(string hash)
    {
        internal string Hash { get; } = hash;
        internal int Stage;
        internal bool Busy, Failed, Closed;
    }
    public async ValueTask<GroupPermissionPacket> StepAsync(GroupPermissionRoot root, GroupPermissionStep step,
        SecretMaterial? capability, CancellationToken token)
    {
        Session session;
        lock (gate)
        {
            string hash = GroupPermissionContract.Hash(root);
            if (step == GroupPermissionStep.Reserve)
                GroupPermissionContract.Require(root.Source == Identity && root.Kind == Kind &&
                    sessions.TryAdd(root.Id, new(hash)), "missing-input");
            GroupPermissionContract.Require(sessions.TryGetValue(root.Id, out var candidate) &&
                candidate.Hash == hash && !candidate.Busy && !candidate.Closed &&
                (step == GroupPermissionStep.Close || !candidate.Failed && candidate.Stage == (int)step));
            session = candidate!;
            session.Busy = session.Failed = true;
            if (step == GroupPermissionStep.Close) session.Closed = true; else session.Stage++;
        }
        try
        {
            var json = await channel.PostAsync<JsonElement>("group-permission/step", writer =>
            {
                writer.WritePropertyName("root"); JsonSerializer.Serialize(writer, root, GroupPermissionContract.Options);
                writer.WriteNumber("step", (int)step);
                if (capability is not null)
                {
                    char[] chars = capability.ExportCharacters();
                    try { writer.WriteString("capability", chars); } finally { Array.Clear(chars); }
                }
            }, token);
            var result = json.Deserialize<GroupPermissionPacket>(GroupPermissionContract.Options);
            GroupPermissionContract.Require(result is not null);
            lock (gate) session.Failed = false;
            return result!;
        }
        finally { lock (gate) session.Busy = false; }
    }
}
