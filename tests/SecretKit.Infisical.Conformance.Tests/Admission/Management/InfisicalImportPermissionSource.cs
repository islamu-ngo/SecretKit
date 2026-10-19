using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalImportPermissionSource(InfisicalLifecycleObservers channel, string identity,
    ImportPermissionSourceKind kind = ImportPermissionSourceKind.NativeProvider) : IImportPermissionSource
{
    public string Identity => identity;
    public ImportPermissionSourceKind Kind => kind;
    private readonly object gate = new();
    private readonly Dictionary<string, Session> sessions = [];
    private sealed class Session(string hash)
    {
        internal string Hash { get; } = hash;
        internal int Stage;
        internal bool Busy, Failed, Closed;
    }
    public async ValueTask<ImportPermissionPacket> StepAsync(ImportPermissionRoot root, ImportPermissionStep step,
        SecretMaterial? capability, CancellationToken token)
    {
        Session session;
        lock (gate)
        {
            string hash = ImportPermissionContract.Hash(root);
            if (step == ImportPermissionStep.Reserve)
                ImportPermissionContract.Require(root.Source == Identity && root.Kind == Kind &&
                    sessions.TryAdd(root.Id, new(hash)), "missing-input");
            ImportPermissionContract.Require(sessions.TryGetValue(root.Id, out var candidate) &&
                candidate.Hash == hash && !candidate.Closed && !candidate.Busy &&
                (step == ImportPermissionStep.Close || !candidate.Failed && candidate.Stage == (int)step));
            session = candidate!;
            session.Busy = session.Failed = true;
            if (step == ImportPermissionStep.Close) session.Closed = true;
            else session.Stage++;
        }
        try
        {
            var json = await channel.PostAsync<JsonElement>("import-permission/step", writer =>
            {
                writer.WritePropertyName("root"); JsonSerializer.Serialize(writer, root, ImportPermissionContract.Options);
                writer.WriteNumber("step", (int)step);
                if (capability is not null)
                {
                    char[] chars = capability.ExportCharacters();
                    try { writer.WriteString("capability", chars); }
                    finally { Array.Clear(chars); }
                }
            }, token);
            var result = json.Deserialize<ImportPermissionPacket>(ImportPermissionContract.Options);
            ImportPermissionContract.Require(result is not null);
            lock (gate) session.Failed = false;
            return result!;
        }
        finally { lock (gate) session.Busy = false; }
    }
}
