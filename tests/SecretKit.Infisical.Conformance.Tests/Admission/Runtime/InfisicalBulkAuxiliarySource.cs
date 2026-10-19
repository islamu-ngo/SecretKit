using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Host-owned authenticated sidecar. The source implements only this closed
// fixture capability, never arbitrary URLs, vendor JSON, or additional writes.
internal sealed class InfisicalBulkAuxiliarySource(InfisicalLifecycleObservers channel,
    string identity, BulkAuxiliarySourceKind kind = BulkAuxiliarySourceKind.NativeProvider) : IBulkAuxiliarySource
{
    public BulkAuxiliarySourceKind Kind => kind;
    public string Identity => identity;
    private readonly Dictionary<string, BulkAuxiliaryRoot> roots = [];
    private readonly Dictionary<string, int> stages = [];
    private readonly HashSet<string> nonces = [];
    internal static InfisicalBulkAuxiliarySource? FromInputs(NativeEnvironment env)
    {
        if (!env.RequireFamilyInput("C08-IR-NativeBulk").TryGetProperty("bulkAuxiliaryObserver", out var input))
            return null;
        try
        {
            var settings = input.Deserialize<InfisicalLifecycleObservers.Settings>(InfisicalStaticFamilies.Options)
                ?? throw new NativeCaseFailureException("missing-input");
            return new(new(settings), settings.Identity);
        }
        catch (JsonException) { throw new NativeCaseFailureException("missing-input"); }
    }
    public async ValueTask<BulkAuxiliaryBinding> OpenAsync(BulkAuxiliaryRoot root,
        BulkAuxiliaryRow[] baseline, CancellationToken token)
    {
        lock (roots)
        {
            BulkAuxiliaryContract.Require(!roots.ContainsKey(root.Id) && nonces.Add(root.Nonce));
            roots.Add(root.Id, root); // Lost Open still retains the original root.
            stages.Add(root.Id, -1);
        }
        var facts = await channel.PostAsync<BulkAuxiliaryBinding>("bulk-auxiliary/open", w =>
        { Write(w, "root", root); Write(w, "baseline", baseline); }, token);
        Accepted(root, 0);
        return facts;
    }
    public async ValueTask<BulkAuxiliaryFence> CompleteAsync(BulkAuxiliaryRoot root,
        DispatchEvidence receipt, CancellationToken token)
    {
        Advance(root, 0);
        var facts = await channel.PostAsync<BulkAuxiliaryFence>("bulk-auxiliary/complete", w =>
        { Write(w, "root", root); Write(w, "receipt", receipt); }, token);
        Accepted(root, 1);
        return facts;
    }
    public async ValueTask<BulkAuxiliarySnapshot> ObserveAsync(BulkAuxiliaryRoot root, CancellationToken token)
    {
        Advance(root, 1);
        var facts = await channel.PostAsync<BulkAuxiliarySnapshot>("bulk-auxiliary/observe",
            w => Write(w, "root", root), token);
        Accepted(root, 2);
        return facts;
    }
    public async ValueTask<BulkAuxiliaryCleanup> CloseAsync(BulkAuxiliaryRoot root, CancellationToken token)
    {
        lock (roots)
        {
            Original(root);
            BulkAuxiliaryContract.Require(stages[root.Id] != -2);
            stages[root.Id] = -2;
        }
        try
        {
            return await channel.PostAsync<BulkAuxiliaryCleanup>("bulk-auxiliary/close",
                w => Write(w, "root", root), token);
        }
        finally { lock (roots) { roots.Remove(root.Id); stages.Remove(root.Id); } }
    }
    private void Original(BulkAuxiliaryRoot root)
    {
        lock (roots)
            BulkAuxiliaryContract.Require(roots.TryGetValue(root.Id, out var original) && ReferenceEquals(root, original));
    }
    private void Advance(BulkAuxiliaryRoot root, int expected)
    {
        lock (roots)
        {
            Original(root);
            BulkAuxiliaryContract.Require(stages[root.Id] == expected);
            // Consume before send. Unknown source loss never permits a retry.
            stages[root.Id] = -1;
        }
    }
    private void Accepted(BulkAuxiliaryRoot root, int next)
    {
        lock (roots)
        {
            Original(root);
            BulkAuxiliaryContract.Require(stages[root.Id] == -1);
            stages[root.Id] = next;
        }
    }
    private static void Write<T>(Utf8JsonWriter writer, string name, T value)
    {
        writer.WritePropertyName(name);
        JsonSerializer.Serialize(writer, value, InfisicalStaticFamilies.Options);
    }
}
