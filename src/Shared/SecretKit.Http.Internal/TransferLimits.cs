namespace SecretKit.Internal;

internal static class TransferLimits
{
    internal const int MinimumBytes = 1024;
    internal const int MaximumBytes = 16 << 20;
    internal const int DefaultBytes = 1 << 20;

    internal static bool IsValidByteBudget(int bytes) => bytes is >= MinimumBytes and <= MaximumBytes;
    internal static bool IsValidTimeout(TimeSpan timeout) =>
        timeout > TimeSpan.Zero && timeout <= TimeSpan.FromMinutes(1);
}
