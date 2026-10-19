using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// Closed private capability client. Service/infrastructure qualification remains
// external; this adapter neither executes vendor JSON nor adds management APIs.
internal sealed class InfisicalRotationMutationSource(InfisicalLifecycleObservers channel,
    string identity, RotationMaterialSource source = RotationMaterialSource.NativeProvider)
    : IInfisicalRotationMutationSource
{
    private readonly Dictionary<string, RotationMutationRoot> roots = new(StringComparer.Ordinal);
    private readonly HashSet<string> calls = new(StringComparer.Ordinal);
    private readonly HashSet<string> closed = new(StringComparer.Ordinal);

    public ValueTask<RotationMutationBinding> OpenAsync(RotationMutationRoot root,
        RotationMaterialPacket baseline, SecretMaterial setupCapability, CancellationToken token)
    {
        lock (roots)
        {
            RotationMaterialTrial.Require(root.Material.SourceIdentity == identity && root.Material.Source == source &&
                root.Material.ProviderVersion == "v0.166.3" &&
                RotationMaterialTrial.Text(root.AttemptId) &&
                !roots.ContainsKey(root.Material.Id) &&
                roots.Values.All(r => r.AttemptId != root.AttemptId && r.Material.Nonce != root.Material.Nonce) &&
                root.Material.Profile == baseline.Profile && root.Material.Kind == baseline.Kind &&
                root.Material.Generation == baseline.Generation, "missing-input");
            roots.Add(root.Material.Id, root);
        }
        return Post<RotationMutationBinding>(root, "open", writer =>
        {
            Write(writer, "root", root);
            baseline.Write(writer, "baseline");
            char[] capability = setupCapability.ExportCharacters();
            try { writer.WriteString("setupCapability", capability); }
            finally { Array.Clear(capability); }
        }, token);
    }

    public ValueTask<RotationMutationArm> ArmAsync(RotationMutationBinding binding, CancellationToken token) =>
        Post<RotationMutationArm>(binding.Stamp.Root, "arm", w => Write(w, "binding", binding), token);

    public ValueTask<RotationMutationSettlement> SettleAsync(RotationMutationArm arm,
        RotationMutationReceipt receipt, CancellationToken token) =>
        Post<RotationMutationSettlement>(arm.Stamp.Root, "settle", w =>
        {
            Write(w, "arm", arm);
            Write(w, "receipt", receipt);
        }, token);

    public ValueTask<RotationMutationAuthentication> AuthenticateAsync(RotationMutationArm arm,
        RotationMaterialPacket actual, RotationMaterialPacket wrong, CancellationToken token) =>
        Post<RotationMutationAuthentication>(arm.Stamp.Root, "authenticate", w =>
        {
            Write(w, "arm", arm);
            actual.Write(w, "actual");
            wrong.Write(w, "wrong");
        }, token);

    public ValueTask<RotationMutationCleanup> CloseAsync(RotationMutationRoot root, CancellationToken token) =>
        Post<RotationMutationCleanup>(root, "close", w => Write(w, "root", root), token);

    private ValueTask<T> Post<T>(RotationMutationRoot root, string method, Action<Utf8JsonWriter> fields,
        CancellationToken token) where T : notnull
    {
        lock (roots)
        {
            RotationMaterialTrial.Require(roots.TryGetValue(root.Material.Id, out var original) && original == root &&
                !closed.Contains(root.Material.Id) && calls.Add(root.Material.Id + "/" + method));
            if (method == "close") closed.Add(root.Material.Id);
        }
        return channel.PostAsync<T>("rotation-mutation/" + method, fields, token);
    }

    private static void Write<T>(Utf8JsonWriter writer, string name, T value)
    {
        writer.WritePropertyName(name);
        JsonSerializer.Serialize(writer, value, InfisicalLifecycleFamilies.Options);
    }
    public override string ToString() => "[InfisicalRotationMutationSource]";
}
