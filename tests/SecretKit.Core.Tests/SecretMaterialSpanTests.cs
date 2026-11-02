using System.Text;
using SecretKit.Core;

namespace SecretKit.Core.Tests;

public sealed class SecretMaterialSpanTests
{
    [Test]
    [Arguments("")]
    [Arguments("credential-é-中-🔑")]
    public async Task AllCallbackFormsReadTheCompleteSnapshot(string text)
    {
        using var material = SecretMaterial.FromText(text);
        await Assert.That(material.Use(static span => new string(span))).IsEqualTo(text);
        await Assert.That(material.Use(text, static (span, state) => span.SequenceEqual(state))).IsTrue();
        await Assert.That(material.UseUtf8(static span => Encoding.UTF8.GetString(span))).IsEqualTo(text);
        await Assert.That(material.UseUtf8(text, static (span, state) => Encoding.UTF8.GetString(span) == state)).IsTrue();
        string? characters = null;
        string? bytes = null;
        material.Use(span => { characters = new string(span); });
        material.UseUtf8(span => { bytes = Encoding.UTF8.GetString(span); });
        await Assert.That(characters).IsEqualTo(text);
        await Assert.That(bytes).IsEqualTo(text);
        var results = new List<string>();
        material.Use(results, static (span, state) => { state.Add(new string(span)); });
        material.UseUtf8(results, static (span, state) => { state.Add(Encoding.UTF8.GetString(span)); });
        await Assert.That(results.SequenceEqual(new[] { text, text })).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CallbackMayDisposeOwnerWithoutInvalidatingItsSnapshot(bool utf8)
    {
        const string text = "credential-é-中-🔑";
        using var material = SecretMaterial.FromText(text);
        string result = utf8
            ? material.UseUtf8(span => { material.Dispose(); return Encoding.UTF8.GetString(span); })
            : material.Use(span => { material.Dispose(); return new string(span); });
        await Assert.That(result).IsEqualTo(text);
        await Assert.That(() => material.Use(static span => span.Length)).Throws<ObjectDisposedException>();
        await Assert.That(() => material.UseUtf8(static span => span.Length)).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DisposalCompletesWhileCallbackIsBlockedAndSnapshotStaysIntact(bool utf8)
    {
        const string text = "credential-é-中-🔑";
        using var material = SecretMaterial.FromText(text);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<string> use = Task.Run(() => utf8
            ? material.UseUtf8(span => { entered.SetResult(); release.Task.GetAwaiter().GetResult(); return Encoding.UTF8.GetString(span); })
            : material.Use(span => { entered.SetResult(); release.Task.GetAwaiter().GetResult(); return new string(span); }));
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await Task.Run(material.Dispose).WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally { release.TrySetResult(); }
        await Assert.That(await use.WaitAsync(TimeSpan.FromSeconds(5))).IsEqualTo(text);
    }

    [Test]
    public async Task ConcurrentUseAndDisposalReturnOnlyIntactMaterialOrDisposed()
    {
        const string text = "credential-é-中-🔑";
        using var material = SecretMaterial.FromText(text);
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task[] uses = Enumerable.Range(0, 16).Select(index => Task.Run(async () =>
        {
            await start.Task;
            try
            {
                string result = index % 2 == 0 ? material.Use(static span => new string(span))
                    : material.UseUtf8(static span => Encoding.UTF8.GetString(span));
                await Assert.That(result).IsEqualTo(text);
            }
            catch (ObjectDisposedException) { }
        })).ToArray();
        Task dispose = Task.Run(async () => { await start.Task; material.Dispose(); });
        start.SetResult();
        await Task.WhenAll(uses.Append(dispose)).WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Test]
    public async Task ThrowingCallbacksDoNotDisposeTheOwnerAndInvalidEncodingIsSanitized()
    {
        using var material = SecretMaterial.FromText("material-canary");
        var failure = new InvalidOperationException("callback failed");
        await Assert.That(() => material.Use<int>(_ => throw failure)).Throws<InvalidOperationException>();
        await Assert.That(() => material.UseUtf8<int>(_ => throw failure)).Throws<InvalidOperationException>();
        await Assert.That(material.Use(static span => span.Length)).IsEqualTo(15);
        using var malformed = SecretMaterial.FromText("material-canary\ud801");
        Exception? error = null;
        try { malformed.UseUtf8(static span => span.Length); }
        catch (Exception caught) { error = caught; }
        await Assert.That(error is ArgumentException and not EncoderFallbackException).IsTrue();
        await Assert.That(error?.InnerException is null).IsTrue();
        await Assert.That(error!.ToString().Contains("material-canary", StringComparison.Ordinal)).IsFalse();
    }
}
