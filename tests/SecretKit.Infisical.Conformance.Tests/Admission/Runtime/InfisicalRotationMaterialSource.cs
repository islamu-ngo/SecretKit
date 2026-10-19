using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Concrete client for the separately selected private source capability. It
// executes no vendor payload and exposes no new management surface. Native
// provisioning/observation still require an independently qualified service.
internal sealed class InfisicalRotationMaterialSource(InfisicalLifecycleObservers channel,
    string identity, RotationMaterialSource source = RotationMaterialSource.NativeProvider) : IInfisicalRotationMaterialSource
{
    private readonly Dictionary<string, RotationMaterialRoot> roots = new(StringComparer.Ordinal);
    private readonly HashSet<string> calls = new(StringComparer.Ordinal);
    private readonly HashSet<string> closed = new(StringComparer.Ordinal);

    public async ValueTask<RotationMaterialBinding> OpenAsync(RotationMaterialRoot root,
        RotationMaterialPacket packet, SecretMaterial setupCapability, CancellationToken token)
    {
        lock (roots)
        {
            RotationMaterialTrial.Require(root.SourceIdentity == identity && root.Source == source &&
                root.ProviderVersion == "v0.166.3" && !roots.ContainsKey(root.Id) &&
                roots.Values.All(r => r.Nonce != root.Nonce) && root.Profile == packet.Profile &&
                root.Kind == packet.Kind && root.Generation == packet.Generation, "missing-input");
            roots.Add(root.Id, root); // Recovery survives a lost Open reply.
        }
        var result = await Post<RotationMaterialBinding>(root, "open", writer =>
        {
            Write(writer, "root", root);
            packet.Write(writer, "material");
            char[] capability = setupCapability.ExportCharacters();
            try { writer.WriteString("setupCapability", capability); }
            finally { Array.Clear(capability); }
        }, token);
        RotationMaterialTrial.Require(result.Stamp.Root == root);
        return result;
    }

    public ValueTask<RotationMaterialArm> ArmAsync(RotationMaterialBinding binding, CancellationToken token) =>
        Post<RotationMaterialArm>(binding.Stamp.Root, "arm", writer => Write(writer, "binding", binding), token);

    public ValueTask<RotationMaterialAuthentication> AuthenticateAsync(RotationMaterialArm arm,
        RotationMaterialPacket actual, RotationMaterialPacket wrong, CancellationToken token) =>
        Post<RotationMaterialAuthentication>(arm.Stamp.Root, "authenticate", writer =>
        {
            Write(writer, "arm", arm);
            actual.Write(writer, "actual");
            wrong.Write(writer, "wrong");
        }, token);

    public ValueTask<RotationMaterialWindow> CompleteAsync(RotationMaterialArm arm, SecretStatus status,
        CancellationToken token) => Post<RotationMaterialWindow>(arm.Stamp.Root, "complete", writer =>
        {
            Write(writer, "arm", arm);
            Write(writer, "status", status);
        }, token);

    public ValueTask<RotationMaterialCleanup> CloseAsync(RotationMaterialRoot root, CancellationToken token) =>
        Post<RotationMaterialCleanup>(root, "close", writer => Write(writer, "root", root), token);

    private ValueTask<T> Post<T>(RotationMaterialRoot root, string method, Action<Utf8JsonWriter> fields,
        CancellationToken token) where T : notnull
    {
        lock (roots)
        {
            RotationMaterialTrial.Require(roots.TryGetValue(root.Id, out var original) && original == root &&
                !closed.Contains(root.Id) && calls.Add(root.Id + "/" + method));
            if (method == "close") closed.Add(root.Id);
        }
        return channel.PostAsync<T>("rotation-material/" + method, fields, token);
    }

    private static void Write<T>(Utf8JsonWriter writer, string name, T value)
    {
        writer.WritePropertyName(name);
        JsonSerializer.Serialize(writer, value, InfisicalLifecycleFamilies.Options);
    }
    public override string ToString() => "[InfisicalRotationMaterialSource]";
}
