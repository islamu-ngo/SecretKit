using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Samples.Infisical;

internal static class DemoOutput
{
    internal static int Write(string outcome, int exitCode, DispatchEvidence? evidence = null,
        string? version = null)
    {
        Console.WriteLine(JsonSerializer.Serialize(new { outcome, evidence = evidence?.ToString(), version }));
        return exitCode;
    }
}
