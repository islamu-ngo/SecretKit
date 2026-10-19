using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// The source service has its own credentials and authority. This client never
// treats the service's echo of a root or caller receipt as provider evidence.
// Every operation is single-use, including a failed/lost call. Only Close may
// follow a failed call; the original root remains available for compensation.
internal sealed class InfisicalOrganizationUserSource(InfisicalLifecycleObservers channel,
    string identity, OrganizationUserSourceKind kind = OrganizationUserSourceKind.NativeProvider)
    : IOrganizationUserSource
{
    private readonly object gate = new();
    private readonly Dictionary<string, Session> sessions = [];
    public OrganizationUserSourceKind Kind => kind;
    public string Identity => identity;

    private sealed class Session(OrganizationUserRoot root)
    {
        internal OrganizationUserRoot Root { get; } = root;
        internal int Stage { get; set; }
        internal bool Busy { get; set; }
        internal bool Failed { get; set; }
        internal bool Closed { get; set; }
    }

    public ValueTask<OrganizationUserReservation> ReserveAsync(OrganizationUserRoot root,
        SecretMaterial capability, CancellationToken token)
    {
        lock (gate)
        {
            OrganizationUserContract.Require(root.Source == Kind && root.SourceIdentity == Identity &&
                OrganizationUserContract.Owns(root.Operation) && !OrganizationUserContract.Gated(root.Variant) &&
                sessions.Values.All(s => s.Root.Nonce != root.Nonce) &&
                sessions.TryAdd(root.Id, new(root)), "missing-input");
        }
        return Post<OrganizationUserReservation>(root, 0, "reserve", writer =>
        {
            char[] chars = capability.ExportCharacters();
            try { writer.WriteString("capability", chars); }
            finally { Array.Clear(chars); }
        }, token);
    }
    public ValueTask<OrganizationUserIssuance> OpenAsync(OrganizationUserRoot root, CancellationToken token) =>
        Post<OrganizationUserIssuance>(root, 1, "open", null, token);
    public ValueTask<OrganizationUserWindow> BeginAsync(OrganizationUserRoot root, string phase, CancellationToken token) =>
        Post<OrganizationUserWindow>(root, Phase(phase, 2, 6), "begin",
            w => w.WriteString("phase", phase), token);
    public ValueTask<OrganizationUserObservation> ObserveAsync(OrganizationUserRoot root, string phase, CancellationToken token) =>
        Post<OrganizationUserObservation>(root, Phase(phase, 3, 7), "observe",
            w => w.WriteString("phase", phase), token);
    public ValueTask<OrganizationUserArm> ArmAsync(OrganizationUserRoot root, OrganizationUserIntent intent,
        CancellationToken token) => Post<OrganizationUserArm>(root, 4, "arm", w =>
        {
            w.WritePropertyName("intent");
            JsonSerializer.Serialize(w, intent, OrganizationUserContract.Options);
        }, token);
    public ValueTask<OrganizationUserFence> SettleAsync(OrganizationUserRoot root, OrganizationUserReceipt receipt,
        CancellationToken token) => Post<OrganizationUserFence>(root, 5, "settle", w =>
        {
            w.WritePropertyName("receipt");
            JsonSerializer.Serialize(w, receipt, OrganizationUserContract.Options);
        }, token);
    public ValueTask<OrganizationUserCleanup> CloseAsync(OrganizationUserRoot root, CancellationToken token) =>
        Post<OrganizationUserCleanup>(root, -1, "close", null, token);

    private async ValueTask<T> Post<T>(OrganizationUserRoot root, int stage, string route,
        Action<Utf8JsonWriter>? fields, CancellationToken token) where T : notnull
    {
        Session session;
        lock (gate)
        {
            OrganizationUserContract.Require(sessions.TryGetValue(root.Id, out var selected) &&
                selected.Root == root && !selected.Closed &&
                (stage == -1 || !selected.Busy && !selected.Failed && selected.Stage == stage));
            session = selected!;
            if (stage == -1) session.Closed = true;
            else { session.Busy = true; session.Failed = true; session.Stage++; }
        }
        try
        {
            T result = await channel.PostAsync<T>("organization-user/" + route, writer =>
            {
                writer.WritePropertyName("root");
                JsonSerializer.Serialize(writer, root, OrganizationUserContract.Options);
                fields?.Invoke(writer);
            }, token);
            lock (gate)
            {
                // Close may race an interrupted Open. A late reply cannot reopen
                // the local stage or transfer its credential bytes to a caller.
                if (stage != -1 && session.Closed)
                {
                    if (result is OrganizationUserIssuance issuance) issuance.Erase();
                    throw new SecretKit.TestFixtures.NativeCaseFailureException("observer-unavailable");
                }
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
    public override string ToString() => "[InfisicalOrganizationUserSource]";
}
