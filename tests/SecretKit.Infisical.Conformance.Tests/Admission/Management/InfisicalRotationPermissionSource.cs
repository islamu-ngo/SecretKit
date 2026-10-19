using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalRotationPermissionSource(InfisicalLifecycleObservers channel, string identity,
    RotationPermissionSourceKind kind = RotationPermissionSourceKind.NativeProvider) : IRotationPermissionSource
{
    public string Identity => identity;
    public RotationPermissionSourceKind Kind => kind;
    private readonly Dictionary<string, (string Hash, int Stage, bool Failed, bool Closed)> sessions = [];
    private readonly HashSet<string> busy = [];
    public async ValueTask<RotationPermissionPacket> StepAsync(RotationPermissionRoot root, RotationPermissionStep step,
        SecretMaterial? capability, CancellationToken token)
    {
        lock (sessions)
        {
            string hash = RotationPermissionContract.Hash(root);
            if (step == RotationPermissionStep.Reserve)
                RotationPermissionContract.Require(root.Source == Identity && root.Kind == Kind &&
                    sessions.TryAdd(root.Id, (hash, 0, false, false)), "missing-input");
            RotationPermissionContract.Require(sessions.TryGetValue(root.Id, out var s) && s.Hash == hash &&
                !s.Closed && !busy.Contains(root.Id) && (step == RotationPermissionStep.Close || !s.Failed && s.Stage == (int)step));
            busy.Add(root.Id);
            sessions[root.Id] = (hash, (int)step + 1, true, step == RotationPermissionStep.Close);
        }
        try
        {
            var json = await channel.PostAsync<JsonElement>("rotation-permission/step", writer =>
            {
                writer.WritePropertyName("root"); JsonSerializer.Serialize(writer, root, RotationPermissionContract.Options);
                writer.WriteNumber("step", (int)step);
                if (capability is not null)
                {
                    char[] chars = capability.ExportCharacters();
                    try { writer.WriteString("capability", chars); }
                    finally { Array.Clear(chars); }
                }
            }, token);
            var result = json.Deserialize<RotationPermissionPacket>(RotationPermissionContract.Options);
            RotationPermissionContract.Require(result is not null);
            lock (sessions) { var s = sessions[root.Id]; sessions[root.Id] = (s.Hash, s.Stage, false, s.Closed); }
            return result!;
        }
        finally { lock (sessions) busy.Remove(root.Id); }
    }
}
