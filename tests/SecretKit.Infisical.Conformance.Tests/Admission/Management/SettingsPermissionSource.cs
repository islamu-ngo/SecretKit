using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalSettingsPermissionSource(InfisicalLifecycleObservers channel, string identity,
    MemberPermissionSourceKind kind = MemberPermissionSourceKind.NativeProvider) : ISettingsPermissionSource
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
    public async ValueTask<SettingsPermissionPacket> StepAsync(SettingsPermissionRoot root, SettingsPermissionStep step,
        SecretMaterial? capability, CancellationToken token)
    {
        Session session;
        lock (gate)
        {
            string hash = SettingsPermissionContract.Hash(root);
            if (step == SettingsPermissionStep.Reserve)
                SettingsPermissionContract.Require(root.Source == Identity && root.Kind == Kind && sessions.TryAdd(root.Id, new(hash)), "missing-input");
            SettingsPermissionContract.Require(sessions.TryGetValue(root.Id, out var found) && found.Hash == hash &&
                !found.Closed && !found.Busy && (step == SettingsPermissionStep.Close || !found.Failed && found.Stage == (int)step));
            session = found!; session.Busy = session.Failed = true;
            if (step == SettingsPermissionStep.Close) session.Closed = true; else session.Stage++;
        }
        try
        {
            var json = await channel.PostAsync<JsonElement>("settings-permission/step", writer =>
            {
                writer.WritePropertyName("root"); JsonSerializer.Serialize(writer, root, SettingsPermissionContract.Options);
                writer.WriteNumber("step", (int)step);
                if (capability is not null)
                {
                    char[] chars = capability.ExportCharacters();
                    try { writer.WriteString("capability", chars); } finally { Array.Clear(chars); }
                }
            }, token);
            // The existing channel's 1 MiB budget remains unchanged. This bounded
            // profile rejects overflow rather than dropping any journal history.
            var actors = new List<SettingsPermissionActor>();
            bool returned = false;
            try
            {
                SettingsPermissionContract.Require(json.EnumerateObject().Select(p => p.Name).Order().SequenceEqual(new[] { "actors", "journals" }));
                var journals = json.GetProperty("journals").Deserialize<SettingsPermissionSigned[]>(SettingsPermissionContract.Options);
                foreach (var actor in json.GetProperty("actors").EnumerateArray())
                {
                    SettingsPermissionContract.Require(step == SettingsPermissionStep.Open &&
                        actor.EnumerateObject().Select(p => p.Name).Order().SequenceEqual(new[] { "credential", "identity" }));
                    var credential = actor.GetProperty("identity").Deserialize<SettingsPermissionCredential>(SettingsPermissionContract.Options);
                    SettingsPermissionContract.Require(credential is not null);
                    actors.Add(new(credential!, actor.GetProperty("credential").GetBytesFromBase64()));
                }
                SettingsPermissionContract.Require(journals is not null);
                lock (gate) session.Failed = false;
                returned = true; return new(journals!, actors.ToArray());
            }
            finally { if (!returned) foreach (var actor in actors) actor.Erase(); }
        }
        finally { lock (gate) session.Busy = false; }
    }
}
