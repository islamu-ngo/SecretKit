using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// Closed capability client only. A native source service and independent
// qualification of its all-ingress fence are external prerequisites.
internal sealed class InfisicalPeriodicRenewalSource(InfisicalLifecycleObservers channel,
    string identity, PeriodicRenewalSourceKind kind = PeriodicRenewalSourceKind.NativeProvider)
    : IInfisicalPeriodicRenewalSource
{
    private readonly Dictionary<string, PeriodicRenewalRoot> roots = new(StringComparer.Ordinal);
    private readonly HashSet<string> calls = new(StringComparer.Ordinal);
    private readonly HashSet<string> closed = new(StringComparer.Ordinal);

    public ValueTask<PeriodicRenewalBinding> OpenAsync(PeriodicRenewalRoot root, SecretMaterial borrowed,
        SecretMaterial capability, CancellationToken token)
    {
        lock (roots)
        {
            PeriodicRenewalTrial.Require(root.SourceIdentity == identity && root.Source == kind &&
                root.ProviderVersion == "v0.166.3" && !roots.ContainsKey(root.Id) &&
                roots.Values.All(r => r.Nonce != root.Nonce), "missing-input");
            roots.Add(root.Id, root); // retained even if the Open reply is lost
        }
        return Post<PeriodicRenewalBinding>(root, "open", w =>
        {
            Write(w, "root", root);
            Material(w, "borrowed", borrowed);
            Material(w, "capability", capability);
        }, token);
    }

    public ValueTask<PeriodicRenewalExpiry> ExpireAsync(PeriodicRenewalBinding binding, CancellationToken token) =>
        Post<PeriodicRenewalExpiry>(binding.Stamp.Root, "expire", w => Write(w, "binding", binding), token);
    public ValueTask<PeriodicRenewalArm> ArmAsync(PeriodicRenewalBinding binding, CancellationToken token) =>
        Post<PeriodicRenewalArm>(binding.Stamp.Root, "arm", w => Write(w, "binding", binding), token);
    public ValueTask<PeriodicRenewalArrival> AwaitBoundaryAsync(PeriodicRenewalArm arm, CancellationToken token) =>
        Post<PeriodicRenewalArrival>(arm.Stamp.Root, "boundary", w => Write(w, "arm", arm), token);
    public ValueTask<PeriodicRenewalSettlement> SettleAsync(PeriodicRenewalArm arm,
        PeriodicRenewalReceipt receipt, CancellationToken token) =>
        Post<PeriodicRenewalSettlement>(arm.Stamp.Root, "settle", w =>
        {
            Write(w, "arm", arm);
            Write(w, "receipt", receipt);
        }, token);
    public ValueTask<PeriodicRenewalDelivery> InspectDeliveryAsync(PeriodicRenewalArm arm,
        SecretMaterial actualSdkMaterial, CancellationToken token) =>
        Post<PeriodicRenewalDelivery>(arm.Stamp.Root, "delivery", w =>
        {
            Write(w, "arm", arm);
            Material(w, "actual", actualSdkMaterial);
        }, token);
    public ValueTask<PeriodicRenewalCleanup> CloseAsync(PeriodicRenewalRoot root, CancellationToken token) =>
        Post<PeriodicRenewalCleanup>(root, "close", w => Write(w, "root", root), token);

    private ValueTask<T> Post<T>(PeriodicRenewalRoot root, string method,
        Action<Utf8JsonWriter> fields, CancellationToken token) where T : notnull
    {
        lock (roots)
        {
            PeriodicRenewalTrial.Require(roots.TryGetValue(root.Id, out var registered) && registered == root &&
                !closed.Contains(root.Id) && calls.Add(root.Id + "/" + method));
            if (method == "close") closed.Add(root.Id);
        }
        return channel.PostAsync<T>("periodic-renewal/" + method, fields, token);
    }

    private static void Material(Utf8JsonWriter writer, string name, SecretMaterial material)
    {
        char[] copy = material.ExportCharacters();
        try { writer.WriteString(name, copy); }
        finally { Array.Clear(copy); }
    }
    private static void Write<T>(Utf8JsonWriter writer, string name, T value)
    {
        writer.WritePropertyName(name);
        JsonSerializer.Serialize(writer, value, InfisicalLifecycleFamilies.Options);
    }
    public override string ToString() => "[InfisicalPeriodicRenewalSource]";
}
