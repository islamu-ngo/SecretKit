using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalIdentityPermissionSource(InfisicalLifecycleObservers channel, string identity,
    MemberPermissionSourceKind kind = MemberPermissionSourceKind.NativeProvider) : IIdentityPermissionSource
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
        internal readonly HashSet<string> Captured = [];
        internal readonly List<Task> Captures = [];
    }
    public async ValueTask<IdentityPermissionPacket> StepAsync(IdentityPermissionRoot root, IdentityPermissionStep step,
        SecretMaterial? capability, CancellationToken token)
    {
        Session session;
        lock (gate)
        {
            string hash = IdentityPermissionContract.Hash(root);
            if (step == IdentityPermissionStep.Reserve)
                IdentityPermissionContract.Require(root.Source == Identity && root.Kind == Kind &&
                    sessions.TryAdd(root.Id, new(hash)), "missing-input");
            IdentityPermissionContract.Require(sessions.TryGetValue(root.Id, out var candidate) &&
                candidate.Hash == hash && !candidate.Busy && !candidate.Closed &&
                (step == IdentityPermissionStep.Close || !candidate.Failed && candidate.Stage == (int)step));
            session = candidate!;
            session.Busy = session.Failed = true;
            if (step == IdentityPermissionStep.Close) session.Closed = true; else session.Stage++;
        }
        try
        {
            if (step == IdentityPermissionStep.Close) await Task.WhenAll(session.Captures).WaitAsync(token);
            var json = await channel.PostAsync<JsonElement>("identity-permission/step", writer =>
            {
                writer.WritePropertyName("root"); JsonSerializer.Serialize(writer, root, IdentityPermissionContract.Options);
                writer.WriteNumber("step", (int)step);
                if (capability is not null)
                {
                    char[] chars = capability.ExportCharacters();
                    try { writer.WriteString("capability", chars); } finally { Array.Clear(chars); }
                }
            }, token);
            var result = json.Deserialize<IdentityPermissionPacket>(IdentityPermissionContract.Options);
            IdentityPermissionContract.Require(result is not null);
            lock (gate) session.Failed = false;
            return result!;
        }
        finally { lock (gate) session.Busy = false; }
    }
    public async ValueTask CaptureAsync(IdentityPermissionRoot root, string row, string tokenId, SecretMaterial material, CancellationToken token)
    {
        var completed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Session session;
        lock (gate)
        {
            IdentityPermissionContract.Require(sessions.TryGetValue(root.Id, out var selected) && selected.Hash == IdentityPermissionContract.Hash(root) &&
                !selected.Busy && !selected.Failed && !selected.Closed && selected.Stage is 3 or 7 && selected.Captured.Add(row));
            session = selected!; session.Captures.Add(completed.Task);
        }
        try
        {
            _ = await channel.PostAsync<JsonElement>("identity-permission/capture", writer =>
            {
                writer.WritePropertyName("root"); JsonSerializer.Serialize(writer, root, IdentityPermissionContract.Options);
                writer.WriteString("row", row); writer.WriteString("tokenId", tokenId);
                char[] characters = material.ExportCharacters();
                try { writer.WriteString("material", characters); } finally { Array.Clear(characters); }
            }, token);
        }
        catch { lock (gate) session.Failed = true; throw; }
        finally { completed.TrySetResult(); }
    }

}
