using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalDynamicPermissionSource(InfisicalLifecycleObservers channel, string identity,
    DynamicPermissionSourceKind kind = DynamicPermissionSourceKind.NativeProvider) : IDynamicPermissionSource
{
    public string Identity => identity;
    public DynamicPermissionSourceKind Kind => kind;
    private readonly object gate = new();
    private readonly Dictionary<string, Session> sessions = [];
    private sealed class Session(string hash)
    {
        internal string Hash { get; } = hash;
        internal int Stage;
        internal bool Busy, Failed, Closed;
    }
    public async ValueTask<DynamicPermissionPacket> StepAsync(DynamicPermissionRoot root, DynamicPermissionStep step,
        SecretMaterial? capability, CancellationToken token)
    {
        Session session;
        lock (gate)
        {
            string hash = DynamicPermissionContract.Hash(root);
            if (step == DynamicPermissionStep.Reserve)
                DynamicPermissionContract.Require(root.Source == Identity && root.Kind == Kind &&
                    sessions.TryAdd(root.Id, new(hash)), "missing-input");
            DynamicPermissionContract.Require(sessions.TryGetValue(root.Id, out var candidate) &&
                candidate.Hash == hash && !candidate.Closed && !candidate.Busy &&
                (step == DynamicPermissionStep.Close || !candidate.Failed && candidate.Stage == (int)step));
            session = candidate!;
            session.Busy = session.Failed = true;
            if (step == DynamicPermissionStep.Close) session.Closed = true;
            else session.Stage++;
        }
        try
        {
            var json = await channel.PostAsync<JsonElement>("dynamic-permission/step", writer =>
            {
                writer.WritePropertyName("root"); JsonSerializer.Serialize(writer, root, DynamicPermissionContract.Options);
                writer.WriteNumber("step", (int)step);
                if (capability is not null)
                {
                    char[] chars = capability.ExportCharacters();
                    try { writer.WriteString("capability", chars); }
                    finally { Array.Clear(chars); }
                }
            }, token);
            var result = json.Deserialize<DynamicPermissionPacket>(DynamicPermissionContract.Options);
            DynamicPermissionContract.Require(result is not null);
            lock (gate) session.Failed = false;
            return result!;
        }
        finally { lock (gate) session.Busy = false; }
    }
    public async ValueTask<DynamicPermissionSigned<DynamicPermissionSql>> MeasureAsync(DynamicPermissionRoot root,
        Guid lease, SecretMaterial username, SecretMaterial password, DynamicPermissionSqlAction action, CancellationToken token)
    {
        Session session;
        lock (gate)
        {
            DynamicPermissionContract.Require(sessions.TryGetValue(root.Id, out var candidate) &&
                candidate.Hash == DynamicPermissionContract.Hash(root) && !candidate.Closed &&
                !candidate.Busy && !candidate.Failed && candidate.Stage is 3 or 7 && Enum.IsDefined(action));
            session = candidate!; session.Busy = session.Failed = true;
        }
        try
        {
            var json = await channel.PostAsync<JsonElement>("dynamic-permission/measure", writer =>
            {
                writer.WritePropertyName("root"); JsonSerializer.Serialize(writer, root, DynamicPermissionContract.Options);
                writer.WriteString("lease", lease); writer.WriteNumber("action", (int)action);
                char[] user = username.ExportCharacters(), secret = password.ExportCharacters();
                try { writer.WriteString("username", user); writer.WriteString("password", secret); }
                finally { Array.Clear(user); Array.Clear(secret); }
            }, token);
            var result = json.Deserialize<DynamicPermissionSigned<DynamicPermissionSql>>(DynamicPermissionContract.Options);
            DynamicPermissionContract.Require(result is not null);
            lock (gate) session.Failed = false;
            return result!;
        }
        finally { lock (gate) session.Busy = false; }
    }
}
