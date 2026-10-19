using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// Transport authenticates only the coordinator. The trial independently verifies
// every journal using the HOST's pins; this adapter never trusts remote keys.
internal sealed class InfisicalMetadataPermissionSource(InfisicalLifecycleObservers channel, string identity,
    MetadataPermissionSourceKind kind = MetadataPermissionSourceKind.NativeProvider) : IMetadataPermissionSource
{
    public string Identity => identity;
    public MetadataPermissionSourceKind Kind => kind;
    private readonly object gate = new();
    private readonly Dictionary<string, Session> sessions = [];
    private sealed class Session(string hash)
    {
        internal string Hash { get; } = hash;
        internal int Stage;
        internal bool Busy, Failed, Closed;
    }
    public async ValueTask<MetadataPermissionPacket> StepAsync(MetadataPermissionRoot root,
        MetadataPermissionStep step, SecretMaterial? capability, CancellationToken token)
    {
        Session session;
        lock (gate)
        {
            string hash = MetadataPermissionContract.Hash(root);
            if (step == MetadataPermissionStep.Reserve)
            {
                MetadataPermissionContract.Require(root.Source == Identity && root.Kind == Kind &&
                    sessions.TryAdd(root.Id, new(hash)), "missing-input");
            }
            MetadataPermissionContract.Require(sessions.TryGetValue(root.Id, out var candidate) &&
                candidate.Hash == hash && !candidate.Closed && !candidate.Busy &&
                (step == MetadataPermissionStep.Close || !candidate.Failed && candidate.Stage == (int)step));
            session = candidate!;
            session.Busy = session.Failed = true;
            if (step == MetadataPermissionStep.Close) session.Closed = true;
            else session.Stage++;
        }
        try
        {
            var json = await channel.PostAsync<JsonElement>("metadata-permission/step", w =>
            {
                w.WritePropertyName("root"); JsonSerializer.Serialize(w, root, MetadataPermissionContract.Options);
                w.WriteNumber("step", (int)step);
                if (capability is not null)
                {
                    char[] chars = capability.ExportCharacters();
                    try { w.WriteString("capability", chars); }
                    finally { Array.Clear(chars); }
                }
            }, token);
            var result = json.Deserialize<MetadataPermissionPacket>(MetadataPermissionContract.Options);
            MetadataPermissionContract.Require(result is not null);
            lock (gate) session.Failed = false;
            return result!;
        }
        finally { lock (gate) session.Busy = false; }
    }
    public async ValueTask<MetadataPermissionSigned<MetadataPermissionBackend>> MeasureAsync(
        MetadataPermissionRoot root, Guid lease, SecretMaterial username, SecretMaterial password,
        MetadataPermissionAction action, CancellationToken token)
    {
        Session session;
        lock (gate)
        {
            MetadataPermissionContract.Require(sessions.TryGetValue(root.Id, out var candidate) &&
                candidate.Hash == MetadataPermissionContract.Hash(root) && !candidate.Closed &&
                !candidate.Busy && !candidate.Failed && candidate.Stage is 3 or 7 && Enum.IsDefined(action));
            session = candidate!;
            session.Busy = session.Failed = true;
        }
        try
        {
            var json = await channel.PostAsync<JsonElement>("metadata-permission/measure", w =>
            {
                w.WritePropertyName("root"); JsonSerializer.Serialize(w, root, MetadataPermissionContract.Options);
                w.WriteString("lease", lease); w.WriteNumber("action", (int)action);
                char[] user = username.ExportCharacters(), secret = password.ExportCharacters();
                try { w.WriteString("username", user); w.WriteString("password", secret); }
                finally { Array.Clear(user); Array.Clear(secret); }
            }, token);
            var result = json.Deserialize<MetadataPermissionSigned<MetadataPermissionBackend>>(MetadataPermissionContract.Options);
            MetadataPermissionContract.Require(result is not null);
            lock (gate) session.Failed = false;
            return result!;
        }
        finally { lock (gate) session.Busy = false; }
    }
}
