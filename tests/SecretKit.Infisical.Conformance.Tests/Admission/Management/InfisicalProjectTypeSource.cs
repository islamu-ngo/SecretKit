using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalProjectTypeSource(InfisicalLifecycleObservers channel, string identity,
    ProjectTypeSourceKind kind = ProjectTypeSourceKind.NativeProvider) : IProjectTypeSource
{
    private readonly object gate = new();
    private readonly Dictionary<string, Session> sessions = [];
    public ProjectTypeSourceKind Kind => kind;
    public string Identity => identity;
    private sealed class Session(ProjectTypeRoot root)
    {
        internal ProjectTypeRoot Root { get; } = root;
        internal int Stage { get; set; }
        internal bool Busy { get; set; }
        internal bool Failed { get; set; }
        internal bool Closed { get; set; }
    }
    public ValueTask<ProjectTypeReservation> ReserveAsync(ProjectTypeRoot root,
        SecretMaterial capability, CancellationToken token)
    {
        lock (gate)
        {
            ProjectTypeContract.Require(root.Source == Kind && root.SourceIdentity == Identity &&
                ProjectTypeContract.Owns(root.Operation) && ProjectTypeContract.Cases.Contains(root.Case) &&
                sessions.Values.All(s => s.Root.Nonce != root.Nonce) && sessions.TryAdd(root.Id, new(root)), "missing-input");
        }
        return Post<ProjectTypeReservation>(root, 0, "reserve", w =>
        {
            char[] chars = capability.ExportCharacters();
            try { w.WriteString("capability", chars); }
            finally { Array.Clear(chars); }
        }, token);
    }
    public ValueTask<ProjectTypeIssuance> OpenAsync(ProjectTypeRoot root, CancellationToken token) =>
        Post<ProjectTypeIssuance>(root, 1, "open", null, token);
    public ValueTask<ProjectTypeWindow> BeginAsync(ProjectTypeRoot root, string phase, CancellationToken token) =>
        Post<ProjectTypeWindow>(root, Phase(phase, 2, 6), "begin", w => w.WriteString("phase", phase), token);
    public ValueTask<ProjectTypeObservation> ObserveAsync(ProjectTypeRoot root, string phase, CancellationToken token) =>
        Post<ProjectTypeObservation>(root, Phase(phase, 3, 7), "observe", w => w.WriteString("phase", phase), token);
    public ValueTask<ProjectTypeArm> ArmAsync(ProjectTypeRoot root, CancellationToken token) =>
        Post<ProjectTypeArm>(root, 4, "arm", null, token);
    public ValueTask<ProjectTypeFence> SettleAsync(ProjectTypeRoot root, CancellationToken token) =>
        Post<ProjectTypeFence>(root, 5, "settle", null, token);
    public ValueTask<ProjectTypeCleanup> CloseAsync(ProjectTypeRoot root, CancellationToken token) =>
        Post<ProjectTypeCleanup>(root, -1, "close", null, token);
    private async ValueTask<T> Post<T>(ProjectTypeRoot root, int stage, string route,
        Action<Utf8JsonWriter>? fields, CancellationToken token) where T : notnull
    {
        Session session;
        lock (gate)
        {
            ProjectTypeContract.Require(sessions.TryGetValue(root.Id, out var selected) &&
                selected.Root == root && !selected.Closed &&
                (stage == -1 || !selected.Busy && !selected.Failed && selected.Stage == stage));
            session = selected!;
            if (stage == -1) session.Closed = true;
            else { session.Busy = session.Failed = true; session.Stage++; }
        }
        try
        {
            T value = await channel.PostAsync<T>("project-type/" + route, w =>
            {
                w.WritePropertyName("root"); JsonSerializer.Serialize(w, root, ProjectTypeContract.Options);
                fields?.Invoke(w);
            }, token);
            lock (gate)
            {
                ProjectTypeContract.Require(stage == -1 || !session.Closed);
                session.Failed = false;
            }
            return value;
        }
        finally { lock (gate) session.Busy = false; }
    }
    private static int Phase(string phase, int before, int after) => phase switch
    {
        "before" => before,
        "after" => after,
        _ => throw new SecretKit.TestFixtures.NativeCaseFailureException("observer-unavailable")
    };
    public override string ToString() => "[InfisicalProjectTypeSource]";
}
