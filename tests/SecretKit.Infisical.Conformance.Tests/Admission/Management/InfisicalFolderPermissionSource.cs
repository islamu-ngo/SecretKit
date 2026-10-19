using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalFolderPermissionSource(InfisicalLifecycleObservers channel, string identity,
    FolderPermissionSourceKind kind = FolderPermissionSourceKind.NativeProvider) : IFolderPermissionSource
{
    public string Identity => identity;
    public FolderPermissionSourceKind Kind => kind;
    private readonly object gate = new();
    private readonly Dictionary<string, Session> sessions = [];
    private sealed class Session(string hash)
    {
        internal string Hash { get; } = hash;
        internal int Stage;
        internal bool Busy, Failed, Closed;
    }
    public async ValueTask<FolderPermissionPacket> StepAsync(FolderPermissionRoot root, FolderPermissionStep step,
        SecretMaterial? capability, CancellationToken token)
    {
        Session session;
        lock (gate)
        {
            string hash = FolderPermissionContract.Hash(root);
            if (step == FolderPermissionStep.Reserve)
                FolderPermissionContract.Require(root.Source == Identity && root.Kind == Kind &&
                    sessions.TryAdd(root.Id, new(hash)), "missing-input");
            FolderPermissionContract.Require(sessions.TryGetValue(root.Id, out var candidate) &&
                candidate.Hash == hash && !candidate.Closed && !candidate.Busy &&
                (step == FolderPermissionStep.Close || !candidate.Failed && candidate.Stage == (int)step));
            session = candidate!;
            session.Busy = session.Failed = true;
            if (step == FolderPermissionStep.Close) session.Closed = true;
            else session.Stage++;
        }
        try
        {
            var json = await channel.PostAsync<JsonElement>("folder-permission/step", writer =>
            {
                writer.WritePropertyName("root"); JsonSerializer.Serialize(writer, root, FolderPermissionContract.Options);
                writer.WriteNumber("step", (int)step);
                if (capability is not null)
                {
                    char[] chars = capability.ExportCharacters();
                    try { writer.WriteString("capability", chars); }
                    finally { Array.Clear(chars); }
                }
            }, token);
            var result = json.Deserialize<FolderPermissionPacket>(FolderPermissionContract.Options);
            FolderPermissionContract.Require(result is not null);
            lock (gate) session.Failed = false;
            return result!;
        }
        finally { lock (gate) session.Busy = false; }
    }
}
