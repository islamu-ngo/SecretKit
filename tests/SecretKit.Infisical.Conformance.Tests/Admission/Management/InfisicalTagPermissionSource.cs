using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalTagPermissionSource(InfisicalLifecycleObservers channel, string identity,
    TagPermissionSourceKind kind = TagPermissionSourceKind.NativeProvider) : ITagPermissionSource
{
    public string Identity => identity;
    public TagPermissionSourceKind Kind => kind;
    private readonly object gate = new();
    private readonly Dictionary<string, Session> sessions = [];
    private sealed class Session(string hash)
    {
        internal string Hash { get; } = hash;
        internal int Stage;
        internal bool Busy, Failed, Closed;
    }
    public async ValueTask<TagPermissionPacket> StepAsync(TagPermissionRoot root, TagPermissionStep step,
        SecretMaterial? capability, CancellationToken token)
    {
        Session session;
        lock (gate)
        {
            string hash = TagPermissionContract.Hash(root);
            if (step == TagPermissionStep.Reserve)
                TagPermissionContract.Require(root.Source == Identity && root.Kind == Kind &&
                    sessions.TryAdd(root.Id, new(hash)), "missing-input");
            TagPermissionContract.Require(sessions.TryGetValue(root.Id, out var candidate) &&
                candidate.Hash == hash && !candidate.Closed && !candidate.Busy &&
                (step == TagPermissionStep.Close || !candidate.Failed && candidate.Stage == (int)step));
            session = candidate!;
            session.Busy = session.Failed = true;
            if (step == TagPermissionStep.Close) session.Closed = true;
            else session.Stage++;
        }
        try
        {
            var json = await channel.PostAsync<JsonElement>("tag-permission/step", writer =>
            {
                writer.WritePropertyName("root"); JsonSerializer.Serialize(writer, root, TagPermissionContract.Options);
                writer.WriteNumber("step", (int)step);
                if (capability is not null)
                {
                    char[] chars = capability.ExportCharacters();
                    try { writer.WriteString("capability", chars); }
                    finally { Array.Clear(chars); }
                }
            }, token);
            var result = json.Deserialize<TagPermissionPacket>(TagPermissionContract.Options);
            TagPermissionContract.Require(result is not null);
            lock (gate) session.Failed = false;
            return result!;
        }
        finally { lock (gate) session.Busy = false; }
    }
}
