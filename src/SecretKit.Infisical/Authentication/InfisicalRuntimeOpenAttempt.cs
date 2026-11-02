using System.Text.Json.Serialization;

namespace SecretKit.Infisical;

/// <summary>Caller-held, single-use open evidence; never an idempotency key or permission to retry login.</summary>
public sealed class InfisicalRuntimeOpenAttempt
{
    private int _started;
    private InfisicalUniversalLoginReceipt? _loginReceipt;

    /// <summary>The actual native receipt once created, retained after failure or cancellation; null before creation.</summary>
    [JsonIgnore]
    public InfisicalUniversalLoginReceipt? LoginReceipt => Volatile.Read(ref _loginReceipt);

    internal bool TryBegin() => Interlocked.CompareExchange(ref _started, 1, 0) == 0;

    internal void Record(InfisicalUniversalLoginReceipt receipt) => Volatile.Write(ref _loginReceipt, receipt);

    /// <summary>Returns a fixed label without bootstrap material, token or coordinates.</summary>
    public override string ToString() => "[InfisicalRuntimeOpenAttempt]";
}
