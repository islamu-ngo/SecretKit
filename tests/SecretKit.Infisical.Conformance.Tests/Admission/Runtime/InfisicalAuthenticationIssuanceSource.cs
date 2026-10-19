using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// Coordinator transport alone is not evidence authentication. The trial checks
// host-pinned signatures. Protected capture is available ONLY through this private
// channel, never list-token inference or a retry of the original login.
internal sealed class InfisicalAuthenticationIssuanceSource(InfisicalLifecycleObservers channel,
    string identity, AuthenticationIssuanceKind kind = AuthenticationIssuanceKind.NativeProvider) : IAuthenticationIssuanceSource
{
    public string Identity => identity;
    public AuthenticationIssuanceKind Kind => kind;
    private readonly object gate = new();
    private readonly Dictionary<string, Session> sessions = [];
    private sealed class Session(string hash)
    {
        internal string Hash { get; } = hash;
        internal int Stage;
        internal bool Busy, Failed, Closed, Captured;
    }
    public async ValueTask<AuthenticationIssuancePacket> StepAsync(AuthenticationIssuanceRoot root,
        AuthenticationIssuanceStep step, SecretMaterial? capability, ReadOnlyMemory<byte> correlationKey,
        CancellationToken token)
    {
        Session session;
        lock (gate)
        {
            string hash = AuthenticationIssuanceContract.Hash(root);
            if (step == AuthenticationIssuanceStep.Reserve)
                AuthenticationIssuanceContract.Require(root.Source == Identity && root.Kind == Kind &&
                    sessions.TryAdd(root.Id, new(hash)), "missing-input");
            AuthenticationIssuanceContract.Require(sessions.TryGetValue(root.Id, out var candidate) &&
                candidate.Hash == hash && !candidate.Busy && !candidate.Closed &&
                (step == AuthenticationIssuanceStep.Close || !candidate.Failed && candidate.Stage == (int)step) &&
                (step == AuthenticationIssuanceStep.Arm ? correlationKey.Length == 32 : correlationKey.IsEmpty));
            session = candidate!; session.Busy = session.Failed = true;
            if (step == AuthenticationIssuanceStep.Close) session.Closed = true;
            else session.Stage++;
        }
        try
        {
            var packet = await channel.PostAsync<AuthenticationIssuancePacket>("authentication-issuance/step", w =>
            {
                w.WritePropertyName("root"); JsonSerializer.Serialize(w, root, AuthenticationIssuanceContract.Options);
                w.WriteNumber("step", (int)step);
                if (!correlationKey.IsEmpty) w.WriteBase64String("correlationKey", correlationKey.Span);
                if (capability is not null)
                {
                    char[] chars = capability.ExportCharacters();
                    try { w.WriteString("capability", chars); }
                    finally { Array.Clear(chars); }
                }
            }, token);
            lock (gate) session.Failed = false;
            return packet;
        }
        finally { lock (gate) session.Busy = false; }
    }
    public async ValueTask<AuthenticationIssuanceCaptured> TakeCaptureAsync(AuthenticationIssuanceRoot root,
        string captureEvent, CancellationToken token)
    {
        Session session;
        lock (gate)
        {
            AuthenticationIssuanceContract.Require(sessions.TryGetValue(root.Id, out var candidate) &&
                candidate.Hash == AuthenticationIssuanceContract.Hash(root) && !candidate.Busy &&
                !candidate.Closed && !candidate.Failed && !candidate.Captured && candidate.Stage == 4);
            session = candidate!; session.Busy = session.Failed = session.Captured = true;
        }
        try
        {
            var result = await channel.PostAsync<CaptureReply>("authentication-issuance/capture", w =>
            {
                w.WritePropertyName("root"); JsonSerializer.Serialize(w, root, AuthenticationIssuanceContract.Options);
                w.WriteString("captureEvent", captureEvent);
            }, token);
            char[]? chars = null;
            try
            {
                AuthenticationIssuanceContract.Require(result.CaptureEvent == captureEvent &&
                    result.Material.Length is > 0 and <= 16384 &&
                    result.Material.All(b => b > 32 && b < 127));
                chars = Encoding.UTF8.GetChars(result.Material);
                token.ThrowIfCancellationRequested();
                var captured = new AuthenticationIssuanceCaptured(result.CaptureEvent, SecretMaterial.FromText(chars));
                lock (gate) session.Failed = false;
                return captured;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(result.Material);
                if (chars is not null) Array.Clear(chars);
            }
        }
        finally { lock (gate) session.Busy = false; }
    }
    private sealed record CaptureReply(string CaptureEvent, byte[] Material)
    {
        public override string ToString() => "[AuthenticationIssuanceCaptureReply]";
    }
}
