using System.Diagnostics;

namespace SecretKit.LiveProvisioner;

internal static class RepositoryEnvironment
{
    internal const UnixFileMode PrivateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    internal static string FindRoot(string directory)
    {
        string common = Git(directory, "rev-parse", "--path-format=absolute", "--git-common-dir").TrimEnd('\r', '\n');
        string root = Path.GetDirectoryName(common) ?? throw new ProvisioningException("Unsupported Git common directory.");
        if (!Path.IsPathFullyQualified(common) || Path.GetFileName(common) != ".git" ||
            !File.Exists(Path.Combine(root, "SecretKit.slnx")))
            throw new ProvisioningException("Expected a SecretKit clone with a conventional Git common directory.");
        NativeLiveInputs.RequireUnlinked(common);
        return root;
    }

    internal static string Guard(string root, string workingDirectory)
    {
        if (Git(root, "ls-files", "--", ".env").Length != 0 ||
            Git(workingDirectory, "ls-files", "--full-name", "--", ":/.env").Length != 0)
            throw new ProvisioningException("Refusing a Git-tracked .env.");
        string path = Path.Combine(root, ".env");
        if (new FileInfo(path).LinkTarget is not null)
            throw new ProvisioningException("Refusing a symbolic-link .env.");
        NativeLiveInputs.RequireUnlinked(root);
        return path;
    }

    private static string Git(string directory, params string[] arguments)
    {
        var start = new ProcessStartInfo("git")
        {
            WorkingDirectory = directory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (string key in start.Environment.Keys.Where(k => k.StartsWith("GIT_", StringComparison.Ordinal)).ToArray())
            start.Environment.Remove(key);
        start.Environment["GIT_OPTIONAL_LOCKS"] = "0";
        foreach (string argument in arguments)
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new ProvisioningException("Git discovery could not start.");
        var error = process.StandardError.ReadToEndAsync();
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        _ = error.GetAwaiter().GetResult();
        return process.ExitCode == 0 ? output : throw new ProvisioningException("Git environment safety check failed.");
    }
}
