using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalWorkloadTransitionSource(InfisicalLifecycleObservers channel, string identity,
    WorkloadTransitionSourceKind kind = WorkloadTransitionSourceKind.NativeProvider) : IWorkloadTransitionSource
{
    public string Identity => identity;
    public WorkloadTransitionSourceKind Kind => kind;
    private readonly object gate = new();
    private readonly Dictionary<string, Session> sessions = [];
    private sealed class Session(WorkloadTransitionRoot root)
    {
        internal WorkloadTransitionRoot Root { get; } = root;
        internal int Stage;
        internal bool Busy, Failed, Closed;
    }
    public ValueTask<WorkloadTransitionReservation> ReserveAsync(WorkloadTransitionRoot root,
        SecretMaterial capability, CancellationToken token)
    {
        lock (gate)
        {
            WorkloadTransitionContract.Require(root.Source == Identity && root.Kind == Kind &&
                sessions.Values.All(s => s.Root.Nonce != root.Nonce) && sessions.TryAdd(root.Id, new(root)), "missing-input");
        }
        return Post<WorkloadTransitionReservation>(root, 0, "reserve", writer =>
        {
            char[] chars = capability.ExportCharacters();
            try { writer.WriteString("capability", chars); }
            finally { Array.Clear(chars); }
        }, token);
    }
    public ValueTask<WorkloadTransitionIssuance> OpenAsync(WorkloadTransitionRoot root, CancellationToken token) =>
        Post<WorkloadTransitionIssuance>(root, 1, "open", null, token);
    public ValueTask<WorkloadTransitionWindow> BeginAsync(WorkloadTransitionRoot root, string phase, CancellationToken token) =>
        Post<WorkloadTransitionWindow>(root, Phase(phase, 2, 6), "begin", w => w.WriteString("phase", phase), token);
    public ValueTask<WorkloadTransitionObservation> ObserveAsync(WorkloadTransitionRoot root, string phase, CancellationToken token) =>
        Post<WorkloadTransitionObservation>(root, Phase(phase, 3, 7), "observe", w => w.WriteString("phase", phase), token);
    public ValueTask<WorkloadTransitionArm> ArmAsync(WorkloadTransitionRoot root, CancellationToken token) =>
        Post<WorkloadTransitionArm>(root, 4, "arm", null, token);
    public ValueTask<WorkloadTransitionFence> SettleAsync(WorkloadTransitionRoot root, CancellationToken token) =>
        Post<WorkloadTransitionFence>(root, 5, "settle", null, token);
    public ValueTask<WorkloadTransitionCleanup> CloseAsync(WorkloadTransitionRoot root, CancellationToken token) =>
        Post<WorkloadTransitionCleanup>(root, -1, "close", null, token);
    private async ValueTask<T> Post<T>(WorkloadTransitionRoot root, int stage, string route,
        Action<Utf8JsonWriter>? fields, CancellationToken token) where T : notnull
    {
        Session session;
        lock (gate)
        {
            WorkloadTransitionContract.Require(sessions.TryGetValue(root.Id, out var candidate) &&
                WorkloadTransitionContract.SameRoot(candidate.Root, root) && !candidate.Closed &&
                (stage == -1 || !candidate.Busy && !candidate.Failed && candidate.Stage == stage));
            session = candidate!;
            if (stage == -1) session.Closed = true;
            else { session.Busy = session.Failed = true; session.Stage++; }
        }
        try
        {
            var result = await channel.PostAsync<T>("workload-transition/" + route, w =>
            {
                w.WritePropertyName("root"); JsonSerializer.Serialize(w, root, WorkloadTransitionContract.Options);
                fields?.Invoke(w);
            }, token);
            lock (gate)
            {
                WorkloadTransitionContract.Require(stage == -1 || !session.Closed);
                session.Failed = false;
            }
            return result;
        }
        finally { lock (gate) session.Busy = false; }
    }
    private static int Phase(string phase, int before, int after) => phase switch
    {
        "before" => before,
        "after" => after,
        _ => throw new SecretKit.TestFixtures.NativeCaseFailureException("observer-unavailable")
    };
    public override string ToString() => "[InfisicalWorkloadTransitionSource]";
}
