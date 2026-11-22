using System.Diagnostics;
using SecretKit.Telemetry.Internal;

namespace SecretKit.Core.Tests;

[NotInParallel]
public sealed class SharedTelemetryTests
{
    [Test]
    public async Task ThrowingAmbientChangeObserverCannotEscapeOrReplaceCallerContext()
    {
        using var parent = new Activity("caller").Start();
        var telemetry = new SecretKitTelemetry("SecretKit.Test", "test.operation", "test.operations", "test.duration");
        EventHandler<ActivityChangedEventArgs> observer = (_, change) =>
        {
            if (ReferenceEquals(change.Current, parent))
                throw new InvalidOperationException("observer-canary");
        };
        Exception? failure = null;
        Activity.CurrentChanged += observer;
        try
        {
            telemetry.Emit(new TagList { { "operation", "Read" } }, DateTime.UtcNow,
                TimeSpan.FromTicks(1), parent.Context);
        }
        catch (Exception error) { failure = error; }
        finally { Activity.CurrentChanged -= observer; }

        await Assert.That(failure).IsNull();
        await Assert.That(ReferenceEquals(Activity.Current, parent)).IsTrue();
    }
}
