using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalValidationPermissionSource(InfisicalLifecycleObservers channel, string identity,
    MemberPermissionSourceKind kind = MemberPermissionSourceKind.NativeProvider) : IValidationPermissionSource
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
    public async ValueTask<ValidationPermissionPacket> StepAsync(ValidationPermissionRoot root, ValidationPermissionStep step,
        SecretMaterial? capability, CancellationToken token)
    {
        Session session;
        lock (gate)
        {
            string hash = ValidationPermissionContract.Hash(root);
            if (step == ValidationPermissionStep.Reserve)
                ValidationPermissionContract.Require(root.Source == Identity && root.Kind == Kind &&
                    sessions.TryAdd(root.Id, new(hash)), "missing-input");
            ValidationPermissionContract.Require(sessions.TryGetValue(root.Id, out var candidate) &&
                candidate.Hash == hash && !candidate.Busy && !candidate.Closed &&
                (step == ValidationPermissionStep.Close || !candidate.Failed && candidate.Stage == (int)step));
            session = candidate!;
            session.Busy = session.Failed = true;
            if (step == ValidationPermissionStep.Close) session.Closed = true; else session.Stage++;
        }
        try
        {
            var json = await channel.PostAsync<JsonElement>("validation-permission/step", writer =>
            {
                writer.WritePropertyName("root"); JsonSerializer.Serialize(writer, root, ValidationPermissionContract.Options);
                writer.WriteNumber("step", (int)step);
                if (capability is not null)
                {
                    char[] chars = capability.ExportCharacters();
                    try { writer.WriteString("capability", chars); } finally { Array.Clear(chars); }
                }
            }, token);
            ValidationPermissionContract.Require(json.GetProperty("encoding").GetString() == "brotli-base64-v1");
            byte[] compressed = json.GetProperty("content").GetBytesFromBase64();
            using var packed = new MemoryStream(compressed, writable: false);
            using var decoder = new BrotliStream(packed, CompressionMode.Decompress);
            using var decoded = new MemoryStream();
            byte[] buffer = new byte[8192];
            ValidationPermissionPacket? result;
            try
            {
                int count;
                while ((count = await decoder.ReadAsync(buffer, token)) != 0)
                {
                    ValidationPermissionContract.Require(decoded.Length + count <= 8 * 1024 * 1024);
                    decoded.Write(buffer, 0, count);
                }
                result = JsonSerializer.Deserialize<ValidationPermissionPacket>(decoded.GetBuffer().AsSpan(0, checked((int)decoded.Length)), ValidationPermissionContract.Options);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(compressed); CryptographicOperations.ZeroMemory(buffer);
                CryptographicOperations.ZeroMemory(decoded.GetBuffer());
            }
            ValidationPermissionContract.Require(result is not null);
            lock (gate) session.Failed = false;
            return result!;
        }
        finally { lock (gate) session.Busy = false; }
    }
}
