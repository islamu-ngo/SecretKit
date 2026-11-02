using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalMysqlConsumerAuthenticationTests
{
    private static readonly RotationBackendCoordinate Coordinate =
        new(InfisicalRotationProfile.MysqlCredentials, "database.invalid", 3306, "owned", "anchor");
    private const string User1 = " first\"\\user ";
    private const string User2 = "second-user";
    private const string Password = " secret\"\\ #;= value ";
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);

    private static JsonObject Profile() => new()
    {
        ["host"] = Coordinate.Host,
        ["port"] = Coordinate.Port,
        ["database"] = Coordinate.Database,
        ["account"] = Coordinate.Account,
        ["username1"] = User1,
        ["username2"] = User2,
        ["accountHost1"] = "%",
        ["accountHost2"] = "localhost",
        ["rootCertificate"] = "/owned/ca.pem",
        ["timeoutSeconds"] = 10
    };

    private static InfisicalMysqlConsumerAuthentication Source(
        InfisicalMysqlConsumerAuthentication.AuthenticationProcess process,
        InfisicalMysqlConsumerAuthentication.Custody? custody = null, JsonObject? profile = null) =>
        new(JsonSerializer.SerializeToElement(profile ?? Profile()), process, custody);

    private static byte[] Output(string username = User1, string host = "%", string database = "owned") =>
        Encoding.ASCII.GetBytes(Convert.ToHexString(Encoding.ASCII.GetBytes(username + "@" + host)) + "\t" +
            Convert.ToHexString(Encoding.ASCII.GetBytes(database)) + "\n");

    private static async Task Feed(Func<Stream, Stream, CancellationToken, Task> consume, byte[] output,
        CancellationToken token, string error = "")
    {
        using var stdout = new MemoryStream(output);
        using var stderr = new MemoryStream(Encoding.ASCII.GetBytes(error));
        await consume(stdout, stderr, token);
    }

    [Test]
    public async Task AlternatingAdmittedUsersUsePrivateBothCredentialFileAndFixedAuthority()
    {
        var buffers = new List<byte[]>();
        var characters = new List<char[]>();
        var paths = new List<string>();
        int invocation = 0;
        var source = Source(async (arguments, environment, consume, token) =>
        {
            if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
            string path = arguments[0]["--defaults-file=".Length..];
            string home = environment["HOME"];
            string plugin = arguments.Single(a => a.StartsWith("--plugin-dir=", StringComparison.Ordinal))["--plugin-dir=".Length..];
            paths.Add(home);
            await Assert.That(File.GetUnixFileMode(path)).IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
            await Assert.That(File.GetUnixFileMode(home)).IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            await Assert.That(File.GetUnixFileMode(plugin)).IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            await Assert.That(plugin != home && !Directory.EnumerateFileSystemEntries(plugin).Any()).IsTrue();
            string user = invocation++ == 0 ? User1 : User2;
            string text = await File.ReadAllTextAsync(path, token);
            string escapedUser = user.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal);
            string escapedPassword = Password.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal);
            await Assert.That(text).IsEqualTo("[client]\nuser=\"" + escapedUser + "\"\npassword=\"" + escapedPassword + "\"\n");
            await Assert.That(environment.Keys.Order().ToArray()).IsEquivalentTo(new[] { "HOME", "APPDATA", "MYSQL_TEST_LOGIN_FILE" });
            await Assert.That(environment["APPDATA"]).IsEqualTo(home);
            await Assert.That(arguments.Contains("--no-login-paths") && arguments.Contains("--protocol=TCP") &&
                arguments.Contains("--ssl-mode=VERIFY_IDENTITY") && arguments.Contains("--ssl-ca=/owned/ca.pem") &&
                arguments.Contains("--skip-reconnect") && arguments.Contains("--host=database.invalid") &&
                arguments.Contains("--database=owned") && arguments.Contains("--port=3306") &&
                arguments.Contains("--execute=SELECT HEX(CURRENT_USER()), HEX(DATABASE())")).IsTrue();
            await Assert.That(arguments.Any(a => a.Contains(user, StringComparison.Ordinal) || a.Contains(Password, StringComparison.Ordinal)) ||
                environment.Values.Any(a => a.Contains(user, StringComparison.Ordinal) || a.Contains(Password, StringComparison.Ordinal))).IsFalse();
            await Feed(consume, Output(user, user == User1 ? "%" : "localhost"), token);
            return 0;
        }, new()
        {
            Allocate = size => { byte[] value = Enumerable.Repeat((byte)0x7f, size + 19).ToArray(); buffers.Add(value); return value; },
            Exported = characters.Add,
            Open = (path, options) =>
            {
                if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
                var file = new FileStream(path, options);
                if (file.Length != 0 || options.Mode != FileMode.CreateNew || options.BufferSize != 1 ||
                    File.GetUnixFileMode(path) != (UnixFileMode.UserRead | UnixFileMode.UserWrite))
                    throw new InvalidOperationException("private creation contract");
                return file;
            }
        });
        foreach (string name in new[] { User1, User2 })
        {
            using var username = SecretMaterial.FromText(name);
            using var password = SecretMaterial.FromText(Password);
            await Assert.That(await source.AuthenticateAsync(Coordinate, username, password, default)).IsEqualTo(BackendAuthentication.Accepted);
            char[] retained = password.ExportCharacters();
            try { await Assert.That(retained.AsSpan().SequenceEqual(Password)).IsTrue(); }
            finally { Array.Clear(retained); }
            char[] retainedUser = username.ExportCharacters();
            try { await Assert.That(retainedUser.AsSpan().SequenceEqual(name)).IsTrue(); }
            finally { Array.Clear(retainedUser); }
        }
        await Assert.That(buffers.All(b => b.All(v => v == 0)) && characters.All(c => c.All(v => v == 0))).IsTrue();
        await Assert.That(paths.All(p => !Directory.Exists(p))).IsTrue();
        await Assert.That(source.ToString()).IsEqualTo("[InfisicalMysqlConsumerAuthentication]");
    }

    [Test]
    [Arguments("refusal")]
    [Arguments("pre-tls")]
    [Arguments("exit")]
    [Arguments("stderr")]
    [Arguments("stderr-overflow")]
    [Arguments("wrong-user")]
    [Arguments("anonymous")]
    [Arguments("wrong-host")]
    [Arguments("wrong-database")]
    [Arguments("extra-row")]
    [Arguments("truncated")]
    [Arguments("invalid-hex")]
    [Arguments("overflow")]
    [Arguments("repeat")]
    [Arguments("repeat-during-drain")]
    [Arguments("no-callback")]
    [Arguments("launch")]
    [Arguments("read")]
    public async Task EveryNativeFailureOrAmbiguousFrameRemainsUnavailable(string fault)
    {
        var allocations = new List<byte[]>();
        string? home = null;
        var source = Source(async (_, environment, consume, token) =>
        {
            home = environment["HOME"];
            if (fault == "launch") throw new IOException(Password);
            if (fault == "no-callback") return 0;
            if (fault == "read")
            {
                using var broken = new BrokenReadStream();
                await consume(broken, Stream.Null, token);
                return 0;
            }
            byte[] output = fault switch
            {
                "wrong-user" => Output("foreign"),
                "anonymous" => Output(""),
                "wrong-host" => Output(host: "localhost"),
                "wrong-database" => Output(database: "foreign"),
                "extra-row" => [.. Output(), .. Output()],
                "truncated" => Output()[..^1],
                "invalid-hex" => Encoding.ASCII.GetBytes(new string('Z', Output().Length - 1) + "\n"),
                "overflow" => new byte[1025],
                _ => Output()
            };
            await Feed(consume, output, token, fault switch
            {
                "refusal" => "ERROR 1045 (28000): " + Password,
                "pre-tls" => "ERROR 1045 (28000): Host blocked before handshake " + Password,
                "stderr" => Password,
                "stderr-overflow" => new string('x', 4097),
                _ => ""
            });
            if (fault == "repeat")
            {
                try { await Feed(consume, Output(), token); }
                catch (NativeCaseFailureException) { }
            }
            if (fault == "repeat-during-drain")
                token.Register(() =>
                {
                    try { consume(Stream.Null, Stream.Null, token).GetAwaiter().GetResult(); }
                    catch (NativeCaseFailureException) { }
                }, useSynchronizationContext: false);
            return fault is "refusal" or "pre-tls" or "exit" ? 1 : 0;
        }, new() { Allocate = size => { var bytes = new byte[size]; allocations.Add(bytes); return bytes; } });
        using var user = SecretMaterial.FromText(User1);
        using var password = SecretMaterial.FromText(Password);
        await Assert.That(await source.AuthenticateAsync(Coordinate, user, password, default)).IsEqualTo(BackendAuthentication.Unavailable);
        await Assert.That(home is null || !Directory.Exists(home)).IsTrue();
        await Assert.That(allocations.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    [Arguments("unicode")]
    [Arguments("newline")]
    [Arguments("too-long")]
    [Arguments("foreign-user")]
    [Arguments("coordinate")]
    [Arguments("disposed")]
    public async Task UnsupportedMaterialAndCoordinateNeverLaunch(string fault)
    {
        bool launched = false;
        var source = Source((_, _, _, _) => { launched = true; return Task.FromResult(0); });
        using var user = SecretMaterial.FromText(fault == "foreign-user" ? "foreign" : User1);
        using var password = SecretMaterial.FromText(fault switch
        {
            "unicode" => "\u00e9",
            "newline" => "line\nbreak",
            "too-long" => new string('x', 4097),
            _ => Password
        });
        if (fault == "disposed") password.Dispose();
        await Assert.That(await source.AuthenticateAsync(fault == "coordinate" ? Coordinate with { Account = "other" } : Coordinate,
            user, password, default)).IsEqualTo(BackendAuthentication.Unavailable);
        await Assert.That(launched).IsFalse();
    }

    [Test]
    [Arguments("unknown")]
    [Arguments("duplicate")]
    [Arguments("missing")]
    [Arguments("same-users")]
    [Arguments("blank-user")]
    [Arguments("uri-host")]
    [Arguments("relative-ca")]
    [Arguments("bad-timeout")]
    [Arguments("null-host")]
    [Arguments("wrong-type")]
    public async Task ProfileIsExactlyTenTypedBoundedFields(string fault)
    {
        JsonObject profile = Profile();
        switch (fault)
        {
            case "unknown": profile["executable"] = "/bin/sh"; break;
            case "missing": profile.Remove("account"); break;
            case "same-users": profile["username2"] = User1; break;
            case "blank-user": profile["username1"] = " "; break;
            case "uri-host": profile["host"] = "mysql://host"; break;
            case "relative-ca": profile["rootCertificate"] = "ca.pem"; break;
            case "bad-timeout": profile["timeoutSeconds"] = 61; break;
            case "null-host": profile["host"] = null; break;
            case "wrong-type": profile["port"] = "3306"; break;
        }
        string json = profile.ToJsonString();
        if (fault == "duplicate") json = "{\"host\":\"foreign\"," + json[1..];
        using var document = JsonDocument.Parse(json);
        await Assert.That(() => new InfisicalMysqlConsumerAuthentication(document.RootElement))
            .Throws<NativeCaseFailureException>().WithMessage("missing-input");
    }

    [Test]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task EveryPartialAllocationClearsAllAcquiredCapacity(int failure)
    {
        var buffers = new List<byte[]>();
        var characters = new List<char[]>();
        int allocations = 0;
        var source = Source((_, _, _, _) => throw new InvalidOperationException("must not launch"), new()
        {
            Allocate = size =>
            {
                if (++allocations == failure) throw new IOException(Password);
                var bytes = Enumerable.Repeat((byte)0x7f, size + 7).ToArray();
                buffers.Add(bytes);
                return bytes;
            },
            Exported = characters.Add
        });
        using var user = SecretMaterial.FromText(User1);
        using var password = SecretMaterial.FromText(Password);
        await Assert.That(await source.AuthenticateAsync(Coordinate, user, password, default)).IsEqualTo(BackendAuthentication.Unavailable);
        await Assert.That(buffers.All(b => b.All(v => v == 0)) && characters.All(c => c.All(v => v == 0))).IsTrue();
    }

    [Test]
    [Arguments("open")]
    [Arguments("flush")]
    [Arguments("short-allocation")]
    [Arguments("export")]
    public async Task PrelaunchFaultsClearOwnedStorageAndNeverExposeRawErrors(string fault)
    {
        var buffers = new List<byte[]>();
        var characters = new List<char[]>();
        string? home = null;
        var source = Source((_, _, _, _) => throw new InvalidOperationException("must not launch"), new()
        {
            Allocate = size =>
            {
                byte[] bytes = Enumerable.Repeat((byte)0x7f, fault == "short-allocation" ? size - 1 : size).ToArray();
                buffers.Add(bytes);
                return bytes;
            },
            Exported = chars =>
            {
                characters.Add(chars);
                if (fault == "export") throw new IOException(Password);
            },
            Open = (path, options) =>
            {
                home = Path.GetDirectoryName(path);
                if (fault == "open") throw new IOException(Password);
                return new FlushFailureFile(path, options);
            }
        });
        using var user = SecretMaterial.FromText(User1);
        using var password = SecretMaterial.FromText(Password);
        await Assert.That(await source.AuthenticateAsync(Coordinate, user, password, default)).IsEqualTo(BackendAuthentication.Unavailable);
        await Assert.That(buffers.All(b => b.All(v => v == 0)) && characters.All(c => c.All(v => v == 0))).IsTrue();
        await Assert.That(home is null || !Directory.Exists(home)).IsTrue();
    }

    [Test]
    public async Task EmptyPasswordAndOneByteStreamChunksPreserveTheAdmittedDomain()
    {
        var source = Source(async (arguments, _, consume, token) =>
        {
            string path = arguments[0]["--defaults-file=".Length..];
            await Assert.That((await File.ReadAllTextAsync(path, token)).EndsWith("password=\"\"\n", StringComparison.Ordinal)).IsTrue();
            using var stdout = new ChunkedStream(Output());
            await consume(stdout, Stream.Null, token);
            return 0;
        });
        using var user = SecretMaterial.FromText(User1);
        using var password = SecretMaterial.FromText("");
        await Assert.That(await source.AuthenticateAsync(Coordinate, user, password, default)).IsEqualTo(BackendAuthentication.Accepted);
    }

    [Test]
    public async Task PartialWriteIsOverwrittenThroughOwnedHandleBeforeDeletion()
    {
        byte[]? erased = null;
        string? home = null;
        var source = Source((_, _, _, _) => throw new InvalidOperationException("must not launch"), new()
        {
            Open = (path, options) => { home = Path.GetDirectoryName(path); return new PartialWriteFile(path, options); },
            Delete = path => { erased = File.ReadAllBytes(path); File.Delete(path); }
        });
        using var user = SecretMaterial.FromText(User1);
        using var password = SecretMaterial.FromText(Password);
        await Assert.That(await source.AuthenticateAsync(Coordinate, user, password, default)).IsEqualTo(BackendAuthentication.Unavailable);
        await Assert.That(erased is { Length: > 0 } && erased.All(b => b == 0)).IsTrue();
        await Assert.That(Directory.Exists(home)).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CleanupFailureWinsOverAcceptanceAndCallerCancellation(bool cancel)
    {
        string? path = null;
        using var cancellation = new CancellationTokenSource();
        var source = Source(async (_, _, consume, token) =>
        {
            await Feed(consume, Output(), token);
            if (cancel) cancellation.Cancel();
            return 0;
        }, new() { Delete = p => { path = p; throw new IOException(Password); } });
        using var user = SecretMaterial.FromText(User1);
        using var password = SecretMaterial.FromText(Password);
        try
        {
            await Assert.That(async () => await source.AuthenticateAsync(Coordinate, user, password, cancellation.Token))
                .Throws<NativeCaseFailureException>().WithMessage("cleanup-incomplete");
            await Assert.That(File.ReadAllBytes(path!).All(b => b == 0)).IsTrue();
        }
        finally
        {
            File.Delete(path!);
            Directory.Delete(Path.GetDirectoryName(path!)!);
        }
    }

    [Test]
    [Arguments("wipe")]
    [Arguments("flush")]
    [Arguments("close")]
    public async Task OwnedHandleCleanupFailuresCannotReturnPositiveOrRawErrors(string fault)
    {
        var buffers = new List<byte[]>();
        string? home = null;
        var source = Source(async (_, environment, consume, token) =>
        {
            home = environment["HOME"];
            await Feed(consume, Output(), token);
            return 0;
        }, new()
        {
            Allocate = size => { byte[] bytes = new byte[size]; buffers.Add(bytes); return bytes; },
            Open = (path, options) => new CleanupFailureFile(path, options, fault)
        });
        using var user = SecretMaterial.FromText(User1);
        using var password = SecretMaterial.FromText(Password);
        await Assert.That(async () => await source.AuthenticateAsync(Coordinate, user, password, default))
            .Throws<NativeCaseFailureException>().WithMessage("cleanup-incomplete");
        await Assert.That(buffers.All(b => b.All(v => v == 0)) && !Directory.Exists(home)).IsTrue();
    }

    [Test]
    public async Task ThrowingReaderCancellationStillDrainsItsSiblingBeforeWipe()
    {
        var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        string? path = null;
        var source = Source(async (arguments, _, consume, token) =>
        {
            path = arguments[0]["--defaults-file=".Length..];
            using var stdout = new BrokenReadStream();
            using var stderr = new CancellationFaultStream(cancelled, release);
            await consume(stdout, stderr, token);
            return 0;
        });
        using var user = SecretMaterial.FromText(User1);
        using var password = SecretMaterial.FromText(Password);
        Task<BackendAuthentication> pending = source.AuthenticateAsync(Coordinate, user, password, default).AsTask();
        try
        {
            await cancelled.Task.WaitAsync(Bound);
            await Assert.That(File.Exists(path) && File.ReadAllBytes(path!).Any(b => b != 0) && !pending.IsCompleted).IsTrue();
        }
        finally { release.TrySetResult(); }
        await Assert.That(await pending.WaitAsync(Bound)).IsEqualTo(BackendAuthentication.Unavailable);
        await Assert.That(Directory.Exists(Path.GetDirectoryName(path!))).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CancellationWaitsForNoncooperativeProcessAndActiveReaderBeforeDeletion(bool processReturnsEarly)
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseReader = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var processEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseProcess = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        string? path = null;
        Task? reading = null;
        using var cancellation = new CancellationTokenSource();
        var source = Source(async (arguments, _, consume, token) =>
        {
            path = arguments[0]["--defaults-file=".Length..];
            using var output = new BarrierStream(Output(), entered, releaseReader);
            reading = consume(output, Stream.Null, token);
            processEntered.SetResult();
            if (processReturnsEarly) return 0;
            await releaseProcess.Task;
            await reading;
            return 0;
        });
        using var user = SecretMaterial.FromText(User1);
        using var password = SecretMaterial.FromText(Password);
        Task<BackendAuthentication> pending = source.AuthenticateAsync(Coordinate, user, password, cancellation.Token).AsTask();
        try
        {
            await processEntered.Task.WaitAsync(Bound);
            await entered.Task.WaitAsync(Bound);
            cancellation.Cancel();
            await Assert.That(File.Exists(path) && File.ReadAllBytes(path!).Any(b => b != 0) && !pending.IsCompleted).IsTrue();
            releaseProcess.TrySetResult();
            await Assert.That(File.Exists(path) && File.ReadAllBytes(path!).Any(b => b != 0) && !pending.IsCompleted).IsTrue();
        }
        finally
        {
            releaseProcess.TrySetResult();
            releaseReader.TrySetResult();
        }
        await Assert.That(async () => await pending.WaitAsync(Bound)).Throws<OperationCanceledException>();
        await Assert.That(reading!.IsCompleted && !Directory.Exists(Path.GetDirectoryName(path!))).IsTrue();
    }

    [Test]
    public async Task DeadlineIsSanitizedAfterActualDelegateSettles()
    {
        JsonObject profile = Profile();
        profile["timeoutSeconds"] = 1;
        var source = Source(async (_, _, consume, token) =>
        {
            var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var registration = token.Register(() => cancelled.TrySetResult());
            await cancelled.Task;
            await Feed(consume, Output(), CancellationToken.None);
            return 0;
        }, profile: profile);
        using var user = SecretMaterial.FromText(User1);
        using var password = SecretMaterial.FromText(Password);
        await Assert.That(async () => await source.AuthenticateAsync(Coordinate, user, password, default))
            .Throws<NativeCaseFailureException>().WithMessage("deadline-exceeded");
    }

    [Test]
    [Arguments(0, false)]
    [Arguments(0, true)]
    [Arguments(17, false)]
    public async Task ActualAdapterClearsAmbientEnvironmentAndDrainsBothPipesOnExit(int exit, bool diagnostic)
    {
        string name = "SECRETKIT_MYSQL_AMBIENT_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(name, Password);
        var source = Source((_, environment, consume, token) =>
            InfisicalMysqlConsumerAuthentication.RunProcessAsync(new Process { StartInfo = new("/bin/sh") },
                ["-c", "test -z \"$" + name + "\" || exit 3; printf '" +
                    Encoding.ASCII.GetString(Output()).Replace("\n", "\\n", StringComparison.Ordinal) +
                    "'" + (diagnostic ? "; printf 'diagnostic' >&2" : "") + "; exit " + exit], environment, consume, token));
        using var user = SecretMaterial.FromText(User1);
        using var password = SecretMaterial.FromText(Password);
        try
        {
            await Assert.That(await source.AuthenticateAsync(Coordinate, user, password, default))
                .IsEqualTo(diagnostic || exit != 0 ? BackendAuthentication.Unavailable : BackendAuthentication.Accepted);
        }
        finally { Environment.SetEnvironmentVariable(name, null); }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ActualAdapterLaunchAndReaderFailuresAreSanitizedAndCleaned(bool readerFailure)
    {
        string? home = null;
        var source = Source((_, environment, _, token) =>
        {
            home = environment["HOME"];
            return InfisicalMysqlConsumerAuthentication.RunProcessAsync(new Process
            {
                StartInfo = new(readerFailure ? "/bin/sh" : "/secretkit-nonexistent/mysql")
            }, readerFailure ? ["-c", "printf 'READY\\n'; kill -STOP $$"] : [], environment,
                async (stdout, _, childToken) =>
                {
                    byte[] ready = new byte[6];
                    try { await stdout.ReadExactlyAsync(ready, childToken); }
                    finally { Array.Clear(ready); }
                    throw new IOException(Password);
                }, token);
        });
        using var user = SecretMaterial.FromText(User1);
        using var password = SecretMaterial.FromText(Password);
        await Assert.That(await source.AuthenticateAsync(Coordinate, user, password, default).AsTask().WaitAsync(Bound))
            .IsEqualTo(BackendAuthentication.Unavailable);
        await Assert.That(Directory.Exists(home)).IsFalse();
    }

    [Test]
    public async Task ActualAdapterKillsChildAndDrainsReaderBeforeCredentialDeletion()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Process? active = null;
        string? path = null;
        using var cancellation = new CancellationTokenSource();
        var source = Source((arguments, environment, consume, token) =>
        {
            path = arguments[0]["--defaults-file=".Length..];
            active = new Process { StartInfo = new("/bin/sh") };
            return InfisicalMysqlConsumerAuthentication.RunProcessAsync(active,
                ["-c", "printf 'READY\\n'; kill -STOP $$"], environment, async (stdout, stderr, childToken) =>
                {
                    byte[] ready = new byte[6];
                    try
                    {
                        await stdout.ReadExactlyAsync(ready, childToken);
                        entered.SetResult();
                        await release.Task;
                        await consume(stdout, stderr, childToken);
                    }
                    finally { Array.Clear(ready); }
                }, token);
        });
        using var user = SecretMaterial.FromText(User1);
        using var password = SecretMaterial.FromText(Password);
        Task<BackendAuthentication> pending = source.AuthenticateAsync(Coordinate, user, password, cancellation.Token).AsTask();
        try
        {
            await entered.Task.WaitAsync(Bound);
            var exited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            active!.Exited += (_, _) => exited.TrySetResult();
            active.EnableRaisingEvents = true;
            cancellation.Cancel();
            await exited.Task.WaitAsync(Bound);
            await Assert.That(active.HasExited && File.Exists(path) &&
                File.ReadAllBytes(path!).Any(b => b != 0) && !pending.IsCompleted).IsTrue();
        }
        finally { release.TrySetResult(); cancellation.Cancel(); }
        await Assert.That(async () => await pending.WaitAsync(Bound)).Throws<OperationCanceledException>();
        await Assert.That(Directory.Exists(Path.GetDirectoryName(path!))).IsFalse();
    }

    private sealed class BrokenReadStream : MemoryStream
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.FromException<int>(new IOException(Password));
    }

    private sealed class PartialWriteFile(string path, FileStreamOptions options) : FileStream(path, options)
    {
        private bool first = true;
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!first) { await base.WriteAsync(buffer, cancellationToken); return; }
            first = false;
            await base.WriteAsync(buffer[..Math.Min(17, buffer.Length)], cancellationToken);
            throw new IOException(Password);
        }
    }

    private sealed class FlushFailureFile(string path, FileStreamOptions options) : FileStream(path, options)
    {
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.FromException(new IOException(Password));
    }

    private sealed class CleanupFailureFile(string path, FileStreamOptions options, string fault) : FileStream(path, options)
    {
        private int writes;
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            ++writes > 1 && fault == "wipe" ? ValueTask.FromException(new IOException(Password)) :
                base.WriteAsync(buffer, cancellationToken);

        public override void Flush(bool flushToDisk)
        {
            if (fault == "flush" && flushToDisk) throw new IOException(Password);
            base.Flush(flushToDisk);
        }

        public override async ValueTask DisposeAsync()
        {
            await base.DisposeAsync();
            if (fault == "close") throw new IOException(Password);
        }
    }

    private sealed class CancellationFaultStream(TaskCompletionSource cancelled, TaskCompletionSource release) : MemoryStream
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            using var registration = cancellationToken.Register(() =>
            {
                cancelled.TrySetResult();
                throw new IOException(Password);
            });
            await release.Task;
            return 0;
        }
    }

    private sealed class ChunkedStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(1, buffer.Length)], cancellationToken);
    }

    private sealed class BarrierStream(byte[] bytes, TaskCompletionSource entered, TaskCompletionSource release) : MemoryStream(bytes)
    {
        private bool first = true;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (first)
            {
                first = false;
                entered.TrySetResult();
                await release.Task;
            }
            return await base.ReadAsync(buffer, CancellationToken.None);
        }
    }
}
