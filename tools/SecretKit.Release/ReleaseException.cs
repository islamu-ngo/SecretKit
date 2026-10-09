namespace SecretKit.Release;

public sealed class ReleaseException(string code) : Exception(code);

public static class Guard
{
    public static void Require(bool condition, string code)
    {
        if (!condition)
        {
            throw new ReleaseException(code);
        }
    }
}
