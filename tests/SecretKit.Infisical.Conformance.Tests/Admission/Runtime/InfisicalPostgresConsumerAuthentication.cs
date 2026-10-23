using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Accepted-session evidence only; native errors cannot attest authenticated refusal.
internal sealed class InfisicalPostgresConsumerAuthentication
{
    internal delegate Task<int> AuthenticationProcess(IReadOnlyList<string> arguments,
        IReadOnlyDictionary<string, string> environment, Func<Stream, Stream, CancellationToken, Task> consume,
        CancellationToken token);

    internal sealed class Custody
    {
        internal Func<int, byte[]> Allocate { get; init; } = static size => new byte[size];
        internal Func<string, FileStreamOptions, FileStream> Open { get; init; } = static (path, options) => new(path, options);
        internal Action<string> Delete { get; init; } = File.Delete;
        internal Action<char[]>? Exported { get; init; }
    }

    private readonly RotationBackendCoordinate binding;
    private readonly string username1, username2, rootCertificate;
    private readonly int timeoutSeconds;
    private readonly AuthenticationProcess run;
    private readonly Custody custody;

    internal InfisicalPostgresConsumerAuthentication(JsonElement input, AuthenticationProcess? process = null,
        Custody? custody = null)
    {
        try
        {
            string[] fields = ["host", "port", "database", "account", "username1", "username2",
                "rootCertificate", "timeoutSeconds"];
            if (input.ValueKind != JsonValueKind.Object || input.EnumerateObject().Count() != fields.Length ||
                !input.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal).SetEquals(fields))
                throw new NativeCaseFailureException("missing-input");
            string host = input.GetProperty("host").GetString()!;
            int port = input.GetProperty("port").GetInt32();
            string database = input.GetProperty("database").GetString()!;
            string account = input.GetProperty("account").GetString()!;
            username1 = input.GetProperty("username1").GetString()!;
            username2 = input.GetProperty("username2").GetString()!;
            rootCertificate = input.GetProperty("rootCertificate").GetString()!;
            timeoutSeconds = input.GetProperty("timeoutSeconds").GetInt32();
            bool ip = host is { Length: > 0 and <= 253 } && IPAddress.TryParse(host, out _) &&
                host.All(c => char.IsAsciiHexDigit(c) || c is '.' or ':');
            bool dns = host is { Length: > 0 and <= 253 } && Uri.CheckHostName(host) == UriHostNameType.Dns &&
                host.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.');
            if ((!ip && !dns) || port is < 1 or > 65535 || !Identifier(database) ||
                string.IsNullOrWhiteSpace(account) || !Printable(account.AsSpan(), 128) ||
                !Identifier(username1) || !Identifier(username2) || username1 == username2 ||
                rootCertificate is not { Length: > 0 and <= 4096 } || rootCertificate.Any(char.IsControl) ||
                !Path.IsPathFullyQualified(rootCertificate) || timeoutSeconds is < 1 or > 60)
                throw new NativeCaseFailureException("missing-input");
            binding = new(InfisicalRotationProfile.PostgresCredentials, host!, port, database, account);
        }
        catch (Exception error) when (error is InvalidOperationException or KeyNotFoundException or FormatException or ArgumentException)
        {
            throw new NativeCaseFailureException("missing-input");
        }
        this.custody = custody ?? new();
        run = process ?? (static (arguments, environment, consume, token) =>
            RunProcessAsync(new Process { StartInfo = new("/usr/bin/psql") }, arguments, environment, consume, token));
    }

    public override string ToString() => "[InfisicalPostgresConsumerAuthentication]";

    internal async ValueTask<BackendAuthentication> AuthenticateAsync(RotationBackendCoordinate coordinate,
        SecretMaterial username, SecretMaterial password, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsLinux() || coordinate != binding) return BackendAuthentication.Unavailable;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
        char[]? user = null, secret = null;
        byte[]? service = null, pass = null, output = null, scratch = null;
        DirectoryInfo? home = null;
        FileStream? serviceFile = null, passFile = null;
        string? servicePath = null, passPath = null;
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
            if ((!user.AsSpan().SequenceEqual(username1) && !user.AsSpan().SequenceEqual(username2)) ||
                !Printable(secret, 4096))
                throw new NativeCaseFailureException("observer-unavailable");
            service = Allocate(128);
            pass = Allocate(16 + 2 * (binding.Host.Length + binding.Database.Length + user.Length + secret.Length));
            output = Allocate(1024);
            scratch = Allocate(256);
            int serviceLength = 0, passLength = 0;
            Append("[secretkit]\nuser=", service, ref serviceLength);
            Append(user, service, ref serviceLength);
            Append("\n", service, ref serviceLength);
            AppendPass(binding.Host, pass, ref passLength);
            Append(":", pass, ref passLength);
            Append(binding.Port.ToString(CultureInfo.InvariantCulture), pass, ref passLength);
            Append(":", pass, ref passLength);
            AppendPass(binding.Database, pass, ref passLength);
            Append(":", pass, ref passLength);
            AppendPass(user, pass, ref passLength);
            Append(":", pass, ref passLength);
            AppendPass(secret, pass, ref passLength);
            Append("\n", pass, ref passLength);
            home = Directory.CreateTempSubdirectory("secretkit-postgres-auth-");
            servicePath = Path.Combine(home.FullName, "service");
            passPath = Path.Combine(home.FullName, "password");
            serviceFile = Open(servicePath);
            passFile = Open(passPath);
            await serviceFile.WriteAsync(service.AsMemory(0, serviceLength), linked.Token).ConfigureAwait(false);
            await serviceFile.FlushAsync(linked.Token).ConfigureAwait(false);
            await passFile.WriteAsync(pass.AsMemory(0, passLength), linked.Token).ConfigureAwait(false);
            await passFile.FlushAsync(linked.Token).ConfigureAwait(false);
            string[] arguments = ["-X", "--no-password", "--quiet", "--tuples-only", "--no-align",
                "--field-separator=\t", "--record-separator=\n", "--set=ON_ERROR_STOP=on",
                "--dbname=service=secretkit sslmode=verify-full require_auth=scram-sha-256 channel_binding=require " +
                    "gssencmode=disable sslcertmode=disable client_encoding=UTF8",
                "--command=SELECT pg_catalog.encode(pg_catalog.convert_to(session_user::text, 'UTF8'), 'hex'), " +
                    "pg_catalog.encode(pg_catalog.convert_to(current_user::text, 'UTF8'), 'hex'), " +
                    "pg_catalog.encode(pg_catalog.convert_to(pg_catalog.current_database()::text, 'UTF8'), 'hex')"];
            var environment = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["HOME"] = home.FullName,
                ["APPDATA"] = home.FullName,
                ["PGSYSCONFDIR"] = home.FullName,
                ["PGSERVICEFILE"] = servicePath,
                ["PGPASSFILE"] = passPath,
                ["PGHOST"] = binding.Host,
                ["PGPORT"] = binding.Port.ToString(CultureInfo.InvariantCulture),
                ["PGDATABASE"] = binding.Database,
                ["PGSSLROOTCERT"] = rootCertificate,
                ["PGSSLCERT"] = Path.Combine(home.FullName, "unused-client-cert"),
                ["PGSSLKEY"] = Path.Combine(home.FullName, "unused-client-key"),
                ["PGSSLCRL"] = Path.Combine(home.FullName, "unused-crl"),
                ["PGSSLCRLDIR"] = home.FullName,
                ["PGCONNECT_TIMEOUT"] = timeoutSeconds.ToString(CultureInfo.InvariantCulture),
                ["PGOPTIONS"] = "-c search_path=pg_catalog -c default_transaction_read_only=on -c statement_timeout=" +
                    (timeoutSeconds * 1000).ToString(CultureInfo.InvariantCulture),
                ["OPENSSL_CONF"] = "/dev/null",
                ["OPENSSL_MODULES"] = home.FullName
            };
            linked.Token.ThrowIfCancellationRequested();
            int exit = await run(arguments, environment, (stdout, stderr, childToken) =>
            {
                lock (gate)
                {
                    callbacks++;
                    if (sealedCallbacks || callbacks != 1)
                        return Task.FromException(new NativeCaseFailureException("observer-unavailable"));
                    Task read = ConsumeAsync(stdout, stderr, output, scratch, user, childToken);
                    readers.Add(read);
                    return read;
                }
            }, linked.Token).ConfigureAwait(false);
            lock (gate) sealedCallbacks = true;
            await Task.WhenAll(readers).ConfigureAwait(false);
            accepted = exit == 0;
        }
        catch (Exception) { accepted = false; }
        finally
        {
            lock (gate) sealedCallbacks = true;
            try { await linked.CancelAsync().ConfigureAwait(false); }
            catch (Exception) { accepted = false; }
            try { await Task.WhenAll(readers).ConfigureAwait(false); }
            catch (Exception) { accepted = false; }
            clean &= await EraseAsync(serviceFile, service).ConfigureAwait(false);
            clean &= await EraseAsync(passFile, pass).ConfigureAwait(false);
            foreach (string? path in new[] { servicePath, passPath })
            {
                if (path is null) continue;
                try { custody.Delete(path); }
                catch (Exception) { clean = false; }
            }
            if (home is not null)
            {
                try { home.Delete(); }
                catch (Exception) { clean = false; }
            }
            if (user is not null) Array.Clear(user);
            if (secret is not null) Array.Clear(secret);
            if (service is not null) CryptographicOperations.ZeroMemory(service);
            if (pass is not null) CryptographicOperations.ZeroMemory(pass);
            if (output is not null) CryptographicOperations.ZeroMemory(output);
            if (scratch is not null) CryptographicOperations.ZeroMemory(scratch);
            lock (gate) accepted &= callbacks == 1;
            if (!clean) throw new NativeCaseFailureException("cleanup-incomplete");
        }
        token.ThrowIfCancellationRequested();
        if (deadline.IsCancellationRequested) throw new NativeCaseFailureException("deadline-exceeded");
        return accepted ? BackendAuthentication.Accepted : BackendAuthentication.Unavailable;
    }

    private FileStream Open(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        return custody.Open(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.ReadWrite,
            Share = FileShare.Read,
            BufferSize = 1,
            Options = FileOptions.Asynchronous,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
        });
    }

    private static async Task<bool> EraseAsync(FileStream? file, byte[]? buffer)
    {
        if (file is null) return true;
        bool clean = true;
        try
        {
            if (buffer is not null)
            {
                CryptographicOperations.ZeroMemory(buffer);
                file.Position = 0;
                long remaining = file.Length;
                while (remaining > 0)
                {
                    int count = (int)Math.Min(remaining, buffer.Length);
                    await file.WriteAsync(buffer.AsMemory(0, count), CancellationToken.None).ConfigureAwait(false);
                    remaining -= count;
                }
                file.Flush(flushToDisk: true);
            }
        }
        catch (Exception) { clean = false; }
        try { await file.DisposeAsync().ConfigureAwait(false); }
        catch (Exception) { clean = false; }
        return clean;
    }

    private byte[] Allocate(int size)
    {
        byte[] buffer = custody.Allocate(size);
        if (buffer.Length >= size && buffer.Length <= 16384) return buffer;
        CryptographicOperations.ZeroMemory(buffer);
        throw new NativeCaseFailureException("observer-unavailable");
    }

    private static bool Identifier(string? value) => value is { Length: > 0 and <= 63 } &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '.' or '$' or '-');

    private static bool Printable(ReadOnlySpan<char> value, int maximum)
    {
        if (value.Length > maximum) return false;
        foreach (char c in value)
            if (c is < ' ' or > '~') return false;
        return true;
    }

    private static void Append(ReadOnlySpan<char> value, Span<byte> bytes, ref int offset)
    {
        foreach (char c in value) bytes[offset++] = (byte)c;
    }

    private static void AppendPass(ReadOnlySpan<char> value, Span<byte> bytes, ref int offset)
    {
        foreach (char c in value)
        {
            if (c is ':' or '\\') bytes[offset++] = (byte)'\\';
            bytes[offset++] = (byte)c;
        }
    }

    private async Task ConsumeAsync(Stream stdout, Stream stderr, byte[] output, byte[] scratch,
        char[] user, CancellationToken token)
    {
        using var failed = CancellationTokenSource.CreateLinkedTokenSource(token);
        Task<int> read = ReadOutputAsync(stdout, output, failed.Token);
        Task<bool> diagnostics = DiscardErrorAsync(stderr, scratch, failed.Token);
        try
        {
            await await Task.WhenAny(read, diagnostics).ConfigureAwait(false);
            await Task.WhenAll(read, diagnostics).ConfigureAwait(false);
            if (await diagnostics.ConfigureAwait(false) ||
                !Bound(output.AsSpan(0, await read.ConfigureAwait(false)), user, binding.Database))
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
            int count = await stream.ReadAsync(buffer.AsMemory(length, 1024 - length), token).ConfigureAwait(false);
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

    private static bool Bound(ReadOnlySpan<byte> bytes, ReadOnlySpan<char> user, string database)
    {
        int principal = user.Length * 2;
        if (bytes.Length != principal * 2 + database.Length * 2 + 3 ||
            bytes[principal] != '\t' || bytes[principal * 2 + 1] != '\t' || bytes[^1] != '\n')
            return false;
        return HexEquals(bytes[..principal], user) &&
            HexEquals(bytes.Slice(principal + 1, principal), user) &&
            HexEquals(bytes.Slice(principal * 2 + 2, database.Length * 2), database);
    }

    private static bool HexEquals(ReadOnlySpan<byte> hex, ReadOnlySpan<char> value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            int high = Nibble(hex[i * 2]), low = Nibble(hex[i * 2 + 1]);
            if (high < 0 || low < 0 || high * 16 + low != value[i]) return false;
        }
        return true;
    }

    private static int Nibble(byte value) => value is >= (byte)'0' and <= (byte)'9' ? value - '0' :
        value is >= (byte)'a' and <= (byte)'f' ? value - 'a' + 10 :
        value is >= (byte)'A' and <= (byte)'F' ? value - 'A' + 10 : -1;

    // The supplied Process is a local test seam. Production always uses /usr/bin/psql.
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
