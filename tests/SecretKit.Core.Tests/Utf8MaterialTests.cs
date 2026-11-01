using System.Text;
using SecretKit.Core;

namespace SecretKit.Core.Tests;

public sealed class Utf8MaterialTests
{
    [Test]
    [Arguments("")]
    [Arguments("vault-\u00e9-\u4e2d-\U0001f511")]
    public async Task ValidTextRoundTripsWithIndependentOwnership(string text)
    {
        byte[] input = Encoding.UTF8.GetBytes(text);
        byte[] expected = (byte[])input.Clone();
        using SecretMaterial material = SecretMaterial.FromUtf8(input);
        using SecretMaterial copy = material.Copy();
        Array.Clear(input);
        byte[] output = new byte[material.GetUtf8ByteCount()];
        bool copied = material.TryCopyUtf8To(output, out int written);
        material.Dispose();
        await Assert.That(copied).IsTrue();
        await Assert.That(written).IsEqualTo(expected.Length);
        await Assert.That(output.SequenceEqual(expected)).IsTrue();
        await Assert.That(copy.Reveal()).IsEqualTo(text);
        await Assert.That(input.All(b => b == 0)).IsTrue();
    }

    [Test]
    public async Task DisposalDoesNotClearBorrowedInputOrExport()
    {
        byte[] input = [65, 66, 67];
        byte[] output = new byte[3];
        using SecretMaterial material = SecretMaterial.FromUtf8(input);
        material.TryCopyUtf8To(output, out _);
        material.Dispose();
        await Assert.That(input.SequenceEqual(new byte[] { 65, 66, 67 })).IsTrue();
        await Assert.That(output.SequenceEqual(input)).IsTrue();
        await Assert.That(() => material.GetUtf8ByteCount()).Throws<ObjectDisposedException>();
        await Assert.That(() => material.TryCopyUtf8To(output, out _)).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task InsufficientCapacityDoesNotWritePartialMaterial()
    {
        using SecretMaterial material = SecretMaterial.FromText("credential-canary");
        byte[] destination = [17, 17, 17];
        bool copied = material.TryCopyUtf8To(destination, out int written);
        await Assert.That(copied).IsFalse();
        await Assert.That(written).IsEqualTo(0);
        await Assert.That(destination.All(b => b == 17)).IsTrue();
    }

    [Test]
    public async Task MalformedUtf8RejectsWithoutRetainingFallbackEvidence()
    {
        byte[][] inputs = [[0xff, 0xfe], [0xc0, 0xaf], [0xed, 0xa0, 0x80], [0xf0, 0x9f]];
        foreach (byte[] input in inputs)
        {
            byte[] credential = [.. Encoding.UTF8.GetBytes("decode-credential-canary"), .. input];
            Exception? error = null;
            try { using SecretMaterial material = SecretMaterial.FromUtf8(credential); }
            catch (Exception caught) { error = caught; }
            await Assert.That(error is ArgumentException && error is not DecoderFallbackException).IsTrue();
            await Assert.That(error?.InnerException is null).IsTrue();
            await Assert.That(error?.Data.Count).IsEqualTo(0);
            await Assert.That(ContainsCanary(error!, "decode-credential-canary")).IsFalse();
            await Assert.That(ContainsCanary(new ArgumentException("decode-credential-canary"),
                "decode-credential-canary")).IsTrue();
        }
    }

    [Test]
    public async Task InvalidUtf16DoesNotWriteOrExposeCredentialFragments()
    {
        const string canary = "credential-canary";
        using SecretMaterial material = SecretMaterial.FromText(canary + '\ud801');
        byte[] destination = Enumerable.Repeat((byte)17, 128).ToArray();
        Exception? error = null;
        try { material.TryCopyUtf8To(destination, out _); }
        catch (Exception caught) { error = caught; }
        await Assert.That(error is ArgumentException && error is not EncoderFallbackException).IsTrue();
        await Assert.That(error?.InnerException is null).IsTrue();
        await Assert.That(error?.Data.Count).IsEqualTo(0);
        await Assert.That(ContainsCanary(error!, canary)).IsFalse();
        await Assert.That(ContainsCanary(new ArgumentException(canary), canary)).IsTrue();
        await Assert.That(destination.All(b => b == 17)).IsTrue();
        await Assert.That(() => material.GetUtf8ByteCount()).Throws<ArgumentException>();
    }

    [Test]
    public async Task ExportRacingDisposalReturnsCompleteValueOrDisposed()
    {
        const string text = "credential-\u00e9-\U0001f511";
        using SecretMaterial material = SecretMaterial.FromText(text);
        byte[] expected = Encoding.UTF8.GetBytes(text);
        byte[] output = new byte[expected.Length];
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task export = Task.Run(async () =>
        {
            await start.Task;
            try
            {
                bool success = material.TryCopyUtf8To(output, out int count);
                await Assert.That(success).IsTrue();
                await Assert.That(count).IsEqualTo(expected.Length);
                await Assert.That(output.SequenceEqual(expected)).IsTrue();
            }
            catch (ObjectDisposedException)
            {
                await Assert.That(output.All(b => b == 0)).IsTrue();
            }
        });
        Task dispose = Task.Run(async () => { await start.Task; material.Dispose(); });
        start.SetResult();
        await Task.WhenAll(export, dispose).WaitAsync(TimeSpan.FromSeconds(5));
    }

    private static bool ContainsCanary(Exception error, string canary) =>
        error.ToString().Contains(canary, StringComparison.Ordinal) ||
        error.Data.Cast<System.Collections.DictionaryEntry>().Any(entry =>
            $"{entry.Key}{entry.Value}".Contains(canary, StringComparison.Ordinal)) ||
        (error.InnerException is not null && ContainsCanary(error.InnerException, canary));
}
