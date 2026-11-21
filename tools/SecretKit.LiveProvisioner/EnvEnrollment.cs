namespace SecretKit.LiveProvisioner;

internal sealed class EnvEnrollment(string root, string workingDirectory, string expected)
{
    internal static IReadOnlyList<string> Slots { get; } =
    [
        "PROJECT_A_ID", "PROJECT_B_ID", "IMPORT_PROJECT_ID", "SETUP_IDENTITY_ID", "RUNTIME_IDENTITY_ID",
        "DENIED_IDENTITY_ID", "ADMINISTRATIVE_IDENTITY_ID", "OBSERVER_IDENTITY_ID"
    ];

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte> ActiveRoots = new(StringComparer.Ordinal);
    private string PathToEnv() => RepositoryEnvironment.Guard(root, workingDirectory);
    private string _expected = expected;

    internal static string Read(string path)
    {
        if (!File.Exists(path))
            throw new ProvisioningException("Missing clone-root .env; use the template or bootstrap-local.");
        if (OperatingSystem.IsWindows() || (File.GetUnixFileMode(path) & ~RepositoryEnvironment.PrivateMode) != 0)
            throw new ProvisioningException("The .env requires private Unix permissions (0600).");
        using var file = File.OpenRead(path);
        if (file.Length > 64 * 1024)
            throw new ProvisioningException("The .env exceeds its size limit.");
        using var reader = new StreamReader(file);
        return reader.ReadToEnd();
    }

    internal void Verify()
    {
        if (Read(PathToEnv()) != _expected)
            throw new ProvisioningException("The .env changed during this command; reload and verify fixture state.");
    }

    internal IDisposable BeginMutation()
    {
        if (!OperatingSystem.IsLinux())
            throw new ProvisioningException("Atomic fixture enrollment requires Linux.");
        if (!ActiveRoots.TryAdd(root, 0))
            throw new ProvisioningException("Another fixture mutation is already active in this clone.");
        FileStream? stream = null;
        try
        {
            string path = Path.Combine(LiveProcess.ArtifactDirectory(root), ".enrollment.lock");
            if (new FileInfo(path).LinkTarget is not null)
                throw new ProvisioningException("Refusing a symbolic-link enrollment lock.");
            stream = new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.OpenOrCreate,
                Access = FileAccess.ReadWrite,
                Share = FileShare.ReadWrite,
                UnixCreateMode = RepositoryEnvironment.PrivateMode
            });
            try { stream.Lock(0, 1); }
            catch (IOException) { throw new ProvisioningException("Another fixture mutation holds the enrollment lock."); }
            Verify();
            return new Lease(root, stream);
        }
        catch
        {
            stream?.Dispose();
            ActiveRoots.TryRemove(root, out _);
            throw;
        }
    }

    internal void Change(params (string Key, string Value)[] changes)
    {
        if (!OperatingSystem.IsLinux())
            throw new ProvisioningException("Atomic fixture enrollment requires Linux.");
        string path = PathToEnv();
        Verify();
        string revised = _expected;
        foreach (var (key, value) in changes)
        {
            string[] lines = revised.Split('\n');
            int index = Array.FindIndex(lines, line => line.TrimStart().StartsWith(key + "=", StringComparison.Ordinal));
            string replacement = key + "=" + value;
            if (index >= 0)
            {
                if (lines[index].EndsWith('\r'))
                    replacement += '\r';
                lines[index] = replacement;
                revised = string.Join('\n', lines);
            }
            else
                revised += (revised.EndsWith('\n') ? "" : "\n") + replacement + "\n";
        }
        string temporary = Path.Combine(root, ".env.enrollment-" + Guid.NewGuid().ToString("N") + ".local");
        bool created = false;
        try
        {
            using (var file = new FileStream(temporary, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                UnixCreateMode = RepositoryEnvironment.PrivateMode
            }))
            {
                created = true;
                using (var writer = new StreamWriter(file, leaveOpen: true))
                    writer.Write(revised);
                file.Flush(flushToDisk: true);
            }
            Verify();
            File.Move(temporary, path, overwrite: true);
            _expected = revised;
        }
        finally
        {
            if (created)
                File.Delete(temporary);
        }
    }

    private sealed class Lease(string root, FileStream stream) : IDisposable
    {
        public void Dispose()
        {
            try { stream.Dispose(); }
            finally { ActiveRoots.TryRemove(root, out _); }
        }
    }
}
