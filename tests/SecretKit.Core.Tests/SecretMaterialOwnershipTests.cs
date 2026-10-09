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
    public async Task ConcurrentCopyAndDisposalNeverReturnClearedMaterial()
    {
        string value = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        using SecretMaterial material = SecretMaterial.FromText(value);
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task copy = Task.Run(async () =>
        {
            await start.Task;
            try
            {
                using SecretMaterial owned = material.Copy();
                await Assert.That(owned.Reveal()).IsEqualTo(value);
            }
            catch (ObjectDisposedException)
            {
                // Disposal won the synchronization boundary.
            }
        });
        Task dispose = Task.Run(async () =>
        {
            await start.Task;
            material.Dispose();
        });

        start.SetResult();

        await Task.WhenAll(copy, dispose).WaitAsync(TimeSpan.FromSeconds(5));
    }
}
