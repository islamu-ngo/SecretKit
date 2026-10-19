using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalEnvironmentPermissionSource(InfisicalLifecycleObservers channel, string identity,
    MemberPermissionSourceKind kind = MemberPermissionSourceKind.NativeProvider) : IEnvironmentPermissionSource
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
    public async ValueTask<EnvironmentPermissionPacket> StepAsync(EnvironmentPermissionRoot root, EnvironmentPermissionStep step,
        SecretMaterial? capability, CancellationToken token)
    {
        Session session;
        lock (gate)
        {
            string hash = EnvironmentPermissionContract.Hash(root);
            if (step == EnvironmentPermissionStep.Reserve)
                EnvironmentPermissionContract.Require(root.Source == Identity && root.Kind == Kind &&
                    sessions.TryAdd(root.Id, new(hash)), "missing-input");
            EnvironmentPermissionContract.Require(sessions.TryGetValue(root.Id, out var candidate) &&
                candidate.Hash == hash && !candidate.Busy && !candidate.Closed &&
                (step == EnvironmentPermissionStep.Close || !candidate.Failed && candidate.Stage == (int)step));
            session = candidate!;
            session.Busy = session.Failed = true;
            if (step == EnvironmentPermissionStep.Close) session.Closed = true; else session.Stage++;
        }
        try
        {
            var json = await channel.PostAsync<JsonElement>("environment-permission/step", writer =>
            {
                writer.WritePropertyName("root"); JsonSerializer.Serialize(writer, root, EnvironmentPermissionContract.Options);
                writer.WriteNumber("step", (int)step);
                if (capability is not null)
                {
                    char[] chars = capability.ExportCharacters();
                    try { writer.WriteString("capability", chars); } finally { Array.Clear(chars); }
                }
            }, token);
            var result = json.Deserialize<EnvironmentPermissionPacket>(EnvironmentPermissionContract.Options);
            EnvironmentPermissionContract.Require(result is not null);
            lock (gate) session.Failed = false;
            return result!;
        }
        finally { lock (gate) session.Busy = false; }
    }
}
