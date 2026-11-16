using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Core.Tests;

public sealed class SecretMaterialOwnershipTests
{
    [Test]
    public async Task CopiesRemainIndependentAfterOriginalDisposal()
    {
        string value = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        using SecretMaterial original = SecretMaterial.FromText(value);
        using SecretMaterial copy = original.Copy();

        original.Dispose();

        await Assert.That(copy.Reveal()).IsEqualTo(value);
        await Assert.That(() => original.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task FormattingAndSerializationDoNotExposeMaterial()
    {
        string value = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        using SecretMaterial material = SecretMaterial.FromText(value);

        string formatted = $"{material}";
        string json = JsonSerializer.Serialize(material);

        await Assert.That(formatted.Contains(value, StringComparison.Ordinal)).IsFalse();
        await Assert.That(json.Contains(value, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task ExportedArrayCannotModifyOwnedMaterial()
    {
        string value = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        using SecretMaterial material = SecretMaterial.FromText(value);
        char[] exported = material.ExportCharacters();

        Array.Clear(exported);

        await Assert.That(material.Reveal()).IsEqualTo(value);
    }

    [Test]
    public async Task ConcurrentCopyAndDisposalSmokePreservesAnyReturnedCopy()
    {
        string value = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        using SecretMaterial material = SecretMaterial.FromText(value);
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task copy = Task.Run(async () =>
        {
            await start.Task;
            SecretMaterial owned;
            try
            {
                owned = material.Copy();
            }
            catch (ObjectDisposedException)
            {
                // Disposal won the synchronization boundary.
                return;
            }
            using (owned)
                await Assert.That(owned.Reveal()).IsEqualTo(value);
        });
        Task dispose = Task.Run(async () =>
        {
            await start.Task;
            material.Dispose();
        });

        start.SetResult();

        await Task.WhenAll(copy, dispose).WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Test]
    public async Task ConcurrentUseAndDisposalNeverObservesZeroedBytes()
    {
        const string expected = "concurrent-use-material-canary-value";
        for (int iteration = 0; iteration < 64; iteration++)
        {
            using SecretMaterial material = SecretMaterial.FromText(expected);
            using var barrier = new Barrier(2);
            Task useTask = Task.Run(() =>
            {
                barrier.SignalAndWait();
                try
                {
                    material.Use(span =>
                    {
                        if (!span.SequenceEqual(expected.AsSpan()))
                        {
                            throw new InvalidOperationException("Observed corrupted or zeroed char span.");
                        }
                    });
                    material.UseUtf8(utf8 =>
                    {
                        if (!utf8.SequenceEqual(System.Text.Encoding.UTF8.GetBytes(expected)))
                        {
                            throw new InvalidOperationException("Observed corrupted or zeroed UTF-8 span.");
                        }
                    });
                }
                catch (ObjectDisposedException)
                {
                    // Disposal won the lock boundary.
                }
            });
            Task disposeTask = Task.Run(() =>
            {
                barrier.SignalAndWait();
                material.Dispose();
            });

            await Task.WhenAll(useTask, disposeTask).WaitAsync(TimeSpan.FromSeconds(5));
            bool invokedAfterDispose = false;
            await Assert.That(() => material.Use(_ => invokedAfterDispose = true)).Throws<ObjectDisposedException>();
            await Assert.That(() => material.UseUtf8(_ => invokedAfterDispose = true)).Throws<ObjectDisposedException>();
            await Assert.That(invokedAfterDispose).IsFalse();
        }
    }

    [Test]
    public async Task CoreAssemblyUsesSystemThreadingLockAndIsMarkedTrimmable()
    {
        Assembly assembly = typeof(SecretMaterial).Assembly;
        bool isTrimmable = assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .Any(attribute => attribute.Key == "IsTrimmable" &&
                string.Equals(attribute.Value, "True", StringComparison.OrdinalIgnoreCase));
        await Assert.That(isTrimmable).IsTrue();

        FieldInfo? materialGate = typeof(SecretMaterial).GetField("_gate", BindingFlags.Instance | BindingFlags.NonPublic);
        FieldInfo? receiptGate = typeof(MutationReceipt).GetField("_gate", BindingFlags.Instance | BindingFlags.NonPublic);
        await Assert.That(materialGate?.FieldType).IsEqualTo(typeof(Lock));
        await Assert.That(receiptGate?.FieldType).IsEqualTo(typeof(Lock));
    }
}
