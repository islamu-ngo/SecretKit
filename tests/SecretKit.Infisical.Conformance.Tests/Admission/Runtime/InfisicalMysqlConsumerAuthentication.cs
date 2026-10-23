using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Accepted-session evidence only. CLI errors do not attest authenticated refusal.
internal sealed class InfisicalMysqlConsumerAuthentication
{
    internal delegate Task<int> AuthenticationProcess(IReadOnlyList<string> arguments,
        IReadOnlyDictionary<string, string> environment, Func<Stream, Stream, CancellationToken, Task> consume,
        CancellationToken token);

    // Local custody fault seams; never selected by the input profile.
    internal sealed class Custody
    {
        internal Func<int, byte[]> Allocate { get; init; } = static size => new byte[size];
        internal Func<string, FileStreamOptions, FileStream> Open { get; init; } = static (path, options) => new(path, options);
        internal Action<string> Delete { get; init; } = File.Delete;
        internal Action<char[]>? Exported { get; init; }
    }

    private readonly RotationBackendCoordinate binding;
    private readonly string username1, username2, accountHost1, accountHost2, rootCertificate;
    private readonly int timeoutSeconds;
    private readonly AuthenticationProcess run;
    private readonly Custody custody;

    internal InfisicalMysqlConsumerAuthentication(JsonElement input, AuthenticationProcess? process = null,
        Custody? custody = null)
    {
        try
        {
            string[] fields = ["host", "port", "database", "account", "username1", "username2",
                "accountHost1", "accountHost2", "rootCertificate", "timeoutSeconds"];
            if (input.ValueKind != JsonValueKind.Object || input.EnumerateObject().Count() != fields.Length ||
                !input.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal).SetEquals(fields))
                throw new NativeCaseFailureException("missing-input");
            string host = input.GetProperty("host").GetString()!;
            int port = input.GetProperty("port").GetInt32();
            string database = input.GetProperty("database").GetString()!;
            string account = input.GetProperty("account").GetString()!;
            username1 = input.GetProperty("username1").GetString()!;
            username2 = input.GetProperty("username2").GetString()!;
            accountHost1 = input.GetProperty("accountHost1").GetString()!;
            accountHost2 = input.GetProperty("accountHost2").GetString()!;
            rootCertificate = input.GetProperty("rootCertificate").GetString()!;
            timeoutSeconds = input.GetProperty("timeoutSeconds").GetInt32();
            bool ip = host is { Length: > 0 and <= 253 } && IPAddress.TryParse(host, out _) &&
                host.All(c => char.IsAsciiHexDigit(c) || c is '.' or ':');
            bool dns = host is { Length: > 0 and <= 253 } && Uri.CheckHostName(host) == UriHostNameType.Dns &&
                host.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.');
            if ((!ip && !dns) || port is < 1 or > 65535 || !Metadata(database, 64) || !Metadata(account, 128) ||
                !Metadata(username1, 32) || !Metadata(username2, 32) || username1 == username2 ||
                !Metadata(accountHost1, 255) || !Metadata(accountHost2, 255) ||
                rootCertificate is not { Length: > 0 and <= 4096 } || rootCertificate.Any(char.IsControl) ||
                !Path.IsPathFullyQualified(rootCertificate) || timeoutSeconds is < 1 or > 60)
                throw new NativeCaseFailureException("missing-input");
            binding = new(InfisicalRotationProfile.MysqlCredentials, host!, port, database, account);
        }
        catch (Exception error) when (error is InvalidOperationException or KeyNotFoundException or FormatException or ArgumentException)
        {
            throw new NativeCaseFailureException("missing-input");
        }
        this.custody = custody ?? new();
        run = process ?? (static (arguments, environment, consume, token) =>
            RunProcessAsync(new Process { StartInfo = new("/usr/bin/mysql") }, arguments, environment, consume, token));
    }

    public override string ToString() => "[InfisicalMysqlConsumerAuthentication]";

    internal async ValueTask<BackendAuthentication> AuthenticateAsync(RotationBackendCoordinate coordinate,
        SecretMaterial username, SecretMaterial password, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsLinux() || coordinate != binding) return BackendAuthentication.Unavailable;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
        char[]? user = null, secret = null;
        byte[]? options = null, output = null, scratch = null;
        DirectoryInfo? home = null;
        FileStream? file = null;
        string? path = null;
        bool clean = true, accepted = false, sealedCallbacks = false;
        int callbacks = 0;
        var gate = new object();
        var readers = new List<Task>();
        try
        {
            user = username.ExportCharacters();
            custody.Exported?.Invoke(user);
            secret = password.ExportCharacters();
            custody.Exported?.Invoke(secret);
            string? accountHost = user.AsSpan().SequenceEqual(username1) ? accountHost1 :
                user.AsSpan().SequenceEqual(username2) ? accountHost2 : null;
            if (accountHost is null || !Printable(user, 32) || !Printable(secret, 4096))
                throw new NativeCaseFailureException("observer-unavailable");
            options = Allocate(32 + 2 * (user.Length + secret.Length));
            output = Allocate(1024);
            scratch = Allocate(256);
            int length = EncodeOptions(options, user, secret);
            home = Directory.CreateTempSubdirectory("secretkit-mysql-auth-");
            string plugin = Path.Combine(home.FullName, "plugins");
            Directory.CreateDirectory(plugin, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            path = Path.Combine(home.FullName, "credentials");
            file = custody.Open(path, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.ReadWrite,
                Share = FileShare.Read,
                BufferSize = 1,
                Options = FileOptions.Asynchronous,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
            });
            await file.WriteAsync(options.AsMemory(0, length), linked.Token).ConfigureAwait(false);
            await file.FlushAsync(linked.Token).ConfigureAwait(false);
            string[] arguments = ["--defaults-file=" + path, "--no-login-paths", "--protocol=TCP",
                "--ssl-mode=VERIFY_IDENTITY", "--ssl-ca=" + rootCertificate, "--host=" + binding.Host,
                "--port=" + binding.Port.ToString(CultureInfo.InvariantCulture), "--database=" + binding.Database,
                "--plugin-dir=" + plugin, "--default-auth=caching_sha2_password", "--skip-reconnect",
                "--local-infile=0", "--batch", "--raw", "--skip-column-names", "--binary-mode",
                "--skip-auto-rehash", "--default-character-set=utf8mb4",
                "--connect-timeout=" + timeoutSeconds.ToString(CultureInfo.InvariantCulture),
                "--execute=SELECT HEX(CURRENT_USER()), HEX(DATABASE())"];
            var environment = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["HOME"] = home.FullName,
                ["APPDATA"] = home.FullName,
                ["MYSQL_TEST_LOGIN_FILE"] = Path.Combine(home.FullName, "unused-login-file")
            };
            linked.Token.ThrowIfCancellationRequested();
            int exit = await run(arguments, environment, (stdout, stderr, childToken) =>
            {
                lock (gate)
                {
                    callbacks++;
                    if (sealedCallbacks || callbacks != 1)
                        return Task.FromException(new NativeCaseFailureException("observer-unavailable"));
                    Task read = ConsumeAsync(stdout, stderr, output, scratch, user, accountHost, childToken);
                    readers.Add(read);
                    return read;
                }
            }, linked.Token).ConfigureAwait(false);
            lock (gate) sealedCallbacks = true;
            await Task.WhenAll(readers).ConfigureAwait(false);
            accepted = exit == 0 && callbacks == 1;
        }
        catch (Exception)
        {
            accepted = false;
        }
        finally
        {
            lock (gate) sealedCallbacks = true;
            // Even a noncooperative delegate's callback must relinquish storage.
            try { await linked.CancelAsync().ConfigureAwait(false); }
            catch (Exception) { accepted = false; }
            try { await Task.WhenAll(readers).ConfigureAwait(false); }
            catch (Exception) { accepted = false; }
            lock (gate) accepted &= callbacks == 1;
            if (file is not null)
            {
                try
                {
                    // Wipe through the retained handle, including any partial write.
                    if (options is not null)
                    {
                        CryptographicOperations.ZeroMemory(options);
                        file.Position = 0;
                        long remaining = file.Length;
                        while (remaining > 0)
                        {
                            int count = (int)Math.Min(remaining, options.Length);
                            await file.WriteAsync(options.AsMemory(0, count), CancellationToken.None).ConfigureAwait(false);
                            remaining -= count;
                        }
                        file.Flush(flushToDisk: true);
                    }
                }
                catch (Exception) { clean = false; }
                try { await file.DisposeAsync().ConfigureAwait(false); }
                catch (Exception) { clean = false; }
            }
            if (path is not null)
            {
                try { custody.Delete(path); }
                catch (Exception) { clean = false; }
            }
            if (home is not null)
            {
                try
                {
                    string plugin = Path.Combine(home.FullName, "plugins");
                    if (Directory.Exists(plugin)) Directory.Delete(plugin);
                }
                catch (Exception) { clean = false; }
                try { home.Delete(); }
                catch (Exception) { clean = false; }
            }
            if (user is not null) Array.Clear(user);
            if (secret is not null) Array.Clear(secret);
            if (options is not null) CryptographicOperations.ZeroMemory(options);
            if (output is not null) CryptographicOperations.ZeroMemory(output);
            if (scratch is not null) CryptographicOperations.ZeroMemory(scratch);
            if (!clean) throw new NativeCaseFailureException("cleanup-incomplete");
        }
        token.ThrowIfCancellationRequested();
        if (deadline.IsCancellationRequested) throw new NativeCaseFailureException("deadline-exceeded");
        return accepted ? BackendAuthentication.Accepted : BackendAuthentication.Unavailable;
    }

    private byte[] Allocate(int size)
    {
        byte[] buffer = custody.Allocate(size);
        if (buffer.Length >= size && buffer.Length <= 16384) return buffer;
        CryptographicOperations.ZeroMemory(buffer);
        throw new NativeCaseFailureException("observer-unavailable");
    }

    private static bool Metadata(string? value, int maximum) =>
        !string.IsNullOrWhiteSpace(value) && Printable(value.AsSpan(), maximum);

    private static bool Printable(ReadOnlySpan<char> value, int maximum)
    {
        if (value.Length > maximum) return false;
        foreach (char c in value)
            if (c is < ' ' or > '~') return false;
        return true;
    }

    private static int EncodeOptions(Span<byte> bytes, ReadOnlySpan<char> user, ReadOnlySpan<char> password)
    {
        int offset = 0;
        foreach (char c in "[client]\nuser=\"") bytes[offset++] = (byte)c;
        Encode(user, bytes, ref offset);
        foreach (char c in "\"\npassword=\"") bytes[offset++] = (byte)c;
        Encode(password, bytes, ref offset);
        bytes[offset++] = (byte)'"';
        bytes[offset++] = (byte)'\n';
        return offset;
    }

    private static void Encode(ReadOnlySpan<char> value, Span<byte> bytes, ref int offset)
    {
        foreach (char c in value)
        {
            if (c is '"' or '\\') bytes[offset++] = (byte)'\\';
            bytes[offset++] = (byte)c;
        }
    }

    private async Task ConsumeAsync(Stream stdout, Stream stderr, byte[] output, byte[] scratch,
        char[] user, string accountHost, CancellationToken token)
    {
        using var failed = CancellationTokenSource.CreateLinkedTokenSource(token);
        Task<int> read = ReadOutputAsync(stdout, output, failed.Token);
        Task<bool> diagnostics = DiscardErrorAsync(stderr, scratch, failed.Token);
        try
        {
            await await Task.WhenAny(read, diagnostics).ConfigureAwait(false);
            await Task.WhenAll(read, diagnostics).ConfigureAwait(false);
            if (await diagnostics.ConfigureAwait(false) ||
                !Bound(output.AsSpan(0, await read.ConfigureAwait(false)), user, accountHost, binding.Database))
                throw new NativeCaseFailureException("observer-unavailable");
        }
        finally
        {
            try { await failed.CancelAsync().ConfigureAwait(false); }
            finally
            {
                try { await Task.WhenAll(read, diagnostics).ConfigureAwait(false); }
                catch (Exception) { }
            }
        }
    }

    private static async Task<int> ReadOutputAsync(Stream stream, byte[] buffer, CancellationToken token)
    {
        int length = 0;
        while (true)
        {
            int count = await stream.ReadAsync(buffer.AsMemory(length, 1024 - length), token)
                .ConfigureAwait(false);
            if (count == 0) return length;
            length += count;
            if (length >= 1024) throw new NativeCaseFailureException("observer-unavailable");
        }
    }

    private static async Task<bool> DiscardErrorAsync(Stream stream, byte[] scratch, CancellationToken token)
    {
        int length = 0, count;
        while ((count = await stream.ReadAsync(scratch.AsMemory(0, 256), token).ConfigureAwait(false)) != 0)
        {
            length += count;
            CryptographicOperations.ZeroMemory(scratch);
            if (length > 4096) throw new NativeCaseFailureException("observer-unavailable");
        }
        return length != 0;
    }

    private static bool Bound(Span<byte> bytes, ReadOnlySpan<char> user, string accountHost, string database)
    {
        int principalLength = user.Length + 1 + accountHost.Length;
        int separator = principalLength * 2;
        if (bytes.Length != separator + 1 + database.Length * 2 + 1 ||
            bytes[separator] != '\t' || bytes[^1] != '\n') return false;
        Span<byte> principal = bytes[..separator];
        Span<byte> selected = bytes.Slice(separator + 1, database.Length * 2);
        if (!Decode(principal) || !Decode(selected)) return false;
        for (int i = 0; i < user.Length; i++)
            if (principal[i] != user[i]) return false;
        if (principal[user.Length] != '@') return false;
        for (int i = 0; i < accountHost.Length; i++)
            if (principal[user.Length + 1 + i] != accountHost[i]) return false;
        for (int i = 0; i < database.Length; i++)
            if (selected[i] != database[i]) return false;
        return true;
    }

    private static bool Decode(Span<byte> hex)
    {
        for (int i = 0; i < hex.Length; i += 2)
        {
            int high = Nibble(hex[i]), low = Nibble(hex[i + 1]);
            if (high < 0 || low < 0) return false;
            hex[i / 2] = (byte)(high * 16 + low);
        }
        return true;
    }

    private static int Nibble(byte value) => value is >= (byte)'0' and <= (byte)'9' ? value - '0' :
        value is >= (byte)'A' and <= (byte)'F' ? value - 'A' + 10 : -1;

    // An active Process is an internal local-child seam, not profile authority.
    // Production always supplies /usr/bin/mysql; this method owns and disposes it.
    internal static async Task<int> RunProcessAsync(Process process, IReadOnlyList<string> arguments,
        IReadOnlyDictionary<string, string> environment, Func<Stream, Stream, CancellationToken, Task> consume,
        CancellationToken token)
    {
        using (process)
        {
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardInput = true;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.Environment.Clear();
            foreach (var (name, value) in environment) process.StartInfo.Environment[name] = value;
            foreach (string argument in arguments) process.StartInfo.ArgumentList.Add(argument);
            token.ThrowIfCancellationRequested();
            process.Start();
            Task? reading = null, exited = null;
            try
            {
                process.StandardInput.Close();
                reading = consume(process.StandardOutput.BaseStream, process.StandardError.BaseStream, token);
                exited = process.WaitForExitAsync(token);
                await await Task.WhenAny(reading, exited).ConfigureAwait(false);
                await Task.WhenAll(reading, exited).ConfigureAwait(false);
                return process.ExitCode;
            }
            catch
            {
                try
                {
                    if (!process.HasExited) process.Kill(entireProcessTree: true);
                }
                finally
                {
                    await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
                    if (exited is not null)
                    {
                        try { await exited.ConfigureAwait(false); }
                        catch (Exception) { }
                    }
                    if (reading is not null)
                    {
                        try { await reading.ConfigureAwait(false); }
                        catch (Exception) { }
                    }
                }
                throw;
            }
        }
    }
}
