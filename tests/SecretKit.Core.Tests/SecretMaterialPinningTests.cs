using System.Reflection;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using SecretKit.Core;

namespace SecretKit.Core.Tests;

[NotInParallel]
public sealed class SecretMaterialPinningTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OwnedUtf8StorageDoesNotMoveAndIsClearedOnDisposal(bool copy)
    {
        using var original = SecretMaterial.FromText("owned-material-canary-\u00e9");
        using var material = copy ? original.Copy() : original;
        // The backing array is inspected only to verify the memory-custody
        // invariant; pinning it with a GCHandle would make this test vacuous.
        object? storage = typeof(SecretMaterial).GetFields(BindingFlags.Instance | BindingFlags.NonPublic)
            .Single(field => field.FieldType.IsArray).GetValue(material);
        await Assert.That(storage is byte[]).IsTrue();
        byte[] bytes = (byte[])storage!;
        nint before = Address(bytes);

        GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);

        await Assert.That(Address(bytes)).IsEqualTo(before);
        material.Dispose();
        await Assert.That(bytes.All(value => value == 0)).IsTrue();
        GC.KeepAlive(bytes);
    }

    private static unsafe nint Address(byte[] bytes) =>
        (nint)Unsafe.AsPointer(ref MemoryMarshal.GetArrayDataReference(bytes));

    [Test]
    [Arguments(256, false)]
    [Arguments(257, false)]
    [Arguments(256, true)]
    [Arguments(257, true)]
    public async Task CallbackSnapshotRemainsStableDuringCompaction(int length, bool utf8)
    {
        string text = utf8
            ? new string('\u00e9', length / 2) + (length % 2 == 0 ? "" : "a")
            : new string('\u00e9', length);
        using var material = SecretMaterial.FromText(text);
        bool stable = utf8
            ? material.UseUtf8(span =>
            {
                nint before = Address(span);
                material.Dispose();
                GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
                return Address(span) == before && System.Text.Encoding.UTF8.GetString(span) == text;
            })
            : material.Use(span =>
            {
                nint before = Address(MemoryMarshal.AsBytes(span));
                material.Dispose();
                GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
                return Address(MemoryMarshal.AsBytes(span)) == before && span.SequenceEqual(text);
            });
        await Assert.That(stable).IsTrue();
    }

    [Test]
    [Arguments(false, false)]
    [Arguments(false, true)]
    [Arguments(true, false)]
    [Arguments(true, true)]
    public async Task LargeSnapshotIsClearedAfterNormalOrExceptionalExit(bool utf8, bool throws)
    {
        await Assert.That(ObserveClearedHeapSnapshot(utf8, throws)).IsTrue();
    }

    private static unsafe bool ObserveClearedHeapSnapshot(bool utf8, bool throws)
    {
        using var material = SecretMaterial.FromText(new string('s', 1024));
        var failure = new InvalidOperationException("callback failure");
        nint address = 0;
        // Only heap snapshots are inspected after their borrow ends. A no-GC
        // region keeps their allocation alive without pinning it or retaining
        // an escaped stack pointer. No await or test-framework work occurs here.
        if (!GC.TryStartNoGCRegion(32 * 1024 * 1024))
            throw new InvalidOperationException("Could not establish snapshot observation region.");
        try
        {
            try
            {
                if (utf8)
                    material.UseUtf8(span =>
                    {
                        address = Address(span);
                        material.Dispose();
                        if (throws) throw failure;
                    });
                else
                    material.Use(span =>
                    {
                        address = Address(MemoryMarshal.AsBytes(span));
                        material.Dispose();
                        if (throws) throw failure;
                    });
            }
            catch (InvalidOperationException error) when (ReferenceEquals(error, failure)) { }
            if (GCSettings.LatencyMode != GCLatencyMode.NoGCRegion)
                throw new InvalidOperationException("Snapshot observation region ended prematurely.");
            return new ReadOnlySpan<byte>((void*)address, utf8 ? 1024 : 2048).IndexOfAnyExcept((byte)0) < 0;
        }
        finally
        {
            if (GCSettings.LatencyMode == GCLatencyMode.NoGCRegion) GC.EndNoGCRegion();
        }
    }

    private static unsafe nint Address(ReadOnlySpan<byte> bytes) =>
        (nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(bytes));
}
