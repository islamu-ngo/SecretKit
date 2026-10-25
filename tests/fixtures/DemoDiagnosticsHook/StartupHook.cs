using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Text.Json;

// The runtime requires this exact global type/method for a startup observer.
// This nonpackable test assembly is never referenced by a demo or SDK package.
public static class StartupHook
{
    private static readonly object Gate = new();
    private static readonly List<IDisposable> Observers = [];
    private static string? _destination;
    private static int _bytes;

    public static void Initialize()
    {
        _destination = Environment.GetEnvironmentVariable("SECRETKIT_DEMO_DIAGNOSTIC_CAPTURE") ??
            throw new InvalidOperationException("Select the test diagnostic capture.");
        var activities = new ActivityListener
        {
            ShouldListenTo = _ => true,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity =>
            {
                foreach (var tag in activity.TagObjects) Record("activity", tag.Value?.ToString());
                foreach (var item in activity.Baggage) Record("baggage", item.Value);
                foreach (var item in activity.Events)
                    foreach (var tag in item.Tags) Record("activity-event", tag.Value?.ToString());
            }
        };
        ActivitySource.AddActivityListener(activities);
        Observers.Add(activities);
        var metrics = new MeterListener
        {
            InstrumentPublished = (instrument, listener) => listener.EnableMeasurementEvents(instrument)
        };
        metrics.SetMeasurementEventCallback<int>((_, _, tags, _) =>
        {
            foreach (var tag in tags) Record("metric", tag.Value?.ToString());
        });
        metrics.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            foreach (var tag in tags) Record("metric", tag.Value?.ToString());
        });
        metrics.SetMeasurementEventCallback<double>((_, _, tags, _) =>
        {
            foreach (var tag in tags) Record("metric", tag.Value?.ToString());
        });
        metrics.Start();
        Observers.Add(metrics);
        var trace = new CaptureTrace();
        Trace.Listeners.Add(trace);
        Observers.Add(trace);
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            foreach (IDisposable observer in Observers) observer.Dispose();
        };
        using (var source = new ActivitySource("SecretKit.Demo.TestObserver"))
        using (Activity? activity = source.StartActivity("probe"))
            activity?.SetTag("probe", "activity-probe");
        using (var meter = new Meter("SecretKit.Demo.TestObserver"))
            meter.CreateCounter<int>("probe").Add(1, new KeyValuePair<string, object?>("probe", "metric-probe"));
        Trace.WriteLine("trace-probe");
        Record("ready", "observer-ready");
    }

    private static void Record(string surface, string? value)
    {
        string line = JsonSerializer.Serialize(new { surface, value }) + "\n";
        lock (Gate)
        {
            if (_bytes > 131072) return;
            _bytes += System.Text.Encoding.UTF8.GetByteCount(line);
            File.AppendAllText(_destination!, _bytes > 131072
                ? "{\"surface\":\"overflow\",\"value\":\"capture-overflow\"}\n" : line);
        }
    }

    private sealed class CaptureTrace : TraceListener
    {
        public override void Write(string? message) => Record("trace", message);
        public override void WriteLine(string? message) => Record("trace", message);
    }
}
