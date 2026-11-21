namespace SecretKit.LiveProvisioner;

internal static class LocalSandboxReadiness
{
    internal static bool IsOwner(string owner) =>
        owner.Length == 22 && owner.StartsWith("secretkit-sdk-", StringComparison.Ordinal) &&
        owner[14..].All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    internal static async Task VerifyAsync(string root, string owner, Uri origin, CancellationToken ct)
    {
        if (!IsOwner(owner) || origin.Scheme != Uri.UriSchemeHttp || origin.Host != "127.0.0.1")
            throw new ProvisioningException("Expected an exact sandbox owner and its IPv4 loopback HTTP origin.");
        var ready = LiveProcess.Command(root, "bash",
        [
            "-c", """
                set -e
                status=$(bash eng/live-infisical/sandbox.sh status "$1")
                [[ $status == "owner=$1"$'\n'"origin=$2"$'\n'"health=ready" ]]
                """, "live-sandbox-status", owner, origin.AbsoluteUri.TrimEnd('/')
        ]);
        if (await LiveProcess.RunAsync(root, new(ready, new Dictionary<string, string>()), ct) != 0)
            throw new ProvisioningException("The configured local sandbox did not pass ownership and readiness checks.");
    }
}
