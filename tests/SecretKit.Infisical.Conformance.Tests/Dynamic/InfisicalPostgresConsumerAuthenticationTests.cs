using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalPostgresConsumerAuthenticationTests
{
    private static readonly RotationBackendCoordinate Coordinate =
        new(InfisicalRotationProfile.PostgresCredentials, "database.invalid", 5432, "owned", "anchor");
    private const string User1 = "First_user.$-1";
    private const string User2 = "second-user";
    private const string Password = " secret\"\\: #;= value ";
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);

    private static JsonObject Profile() => new()
    {
        ["host"] = Coordinate.Host,
        ["port"] = Coordinate.Port,
        ["database"] = Coordinate.Database,
        ["account"] = Coordinate.Account,
        ["username1"] = User1,
        ["username2"] = User2,
        ["rootCertificate"] = "/owned/ca.pem",
        ["timeoutSeconds"] = 10
    };

    private static InfisicalPostgresConsumerAuthentication Source(
        InfisicalPostgresConsumerAuthentication.AuthenticationProcess process,
        InfisicalPostgresConsumerAuthentication.Custody? custody = null, JsonObject? profile = null) =>
        new(JsonSerializer.SerializeToElement(profile ?? Profile()), process, custody);

    private static byte[] Output(string session = User1, string current = User1, string database = "owned") =>
        Encoding.ASCII.GetBytes(Convert.ToHexStringLower(Encoding.ASCII.GetBytes(session)) + "\t" +
            Convert.ToHexStringLower(Encoding.ASCII.GetBytes(current)) + "\t" +
            Convert.ToHexStringLower(Encoding.ASCII.GetBytes(database)) + "\n");

    private static async Task Feed(Func<Stream, Stream, CancellationToken, Task> consume, byte[] output,
        CancellationToken token, string error = "")
    {
        using var stdout = new MemoryStream(output);
        using var stderr = new MemoryStream(Encoding.ASCII.GetBytes(error));
        await consume(stdout, stderr, token);
    }

    [Test]
    public async Task BothBorrowedCredentialsUsePrivateExactFilesAndFixedAuthority()
    {
        var buffers = new List<byte[]>();
        var characters = new List<char[]>();
        var homes = new List<string>();
        var erased = new List<byte[]>();
        int invocation = 0;
        var source = Source(async (arguments, environment, consume, token) =>
        {
            if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
            string user = invocation++ == 0 ? User1 : User2;
            string home = environment["HOME"];
            homes.Add(home);
            await Assert.That(File.GetUnixFileMode(home)).IsEqualTo(
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            await Assert.That(await File.ReadAllTextAsync(environment["PGSERVICEFILE"], token))
                .IsEqualTo("[secretkit]\nuser=" + user + "\n");
            await Assert.That(await File.ReadAllTextAsync(environment["PGPASSFILE"], token))
                .IsEqualTo("database.invalid:5432:owned:" + user + ": secret\"\\\\\\: #;= value \n");
            await Assert.That(environment["PGSYSCONFDIR"] == home && environment["APPDATA"] == home &&
                environment["PGSSLROOTCERT"] == "/owned/ca.pem" && environment["PGHOST"] == Coordinate.Host &&
                environment["PGPORT"] == "5432" && environment["PGDATABASE"] == Coordinate.Database &&
                environment["PGCONNECT_TIMEOUT"] == "10" && environment["OPENSSL_CONF"] == "/dev/null" &&
                environment["OPENSSL_MODULES"] == home).IsTrue();
            await Assert.That(environment["PGSSLCERT"].StartsWith(home + "/", StringComparison.Ordinal) &&
                environment["PGSSLKEY"].StartsWith(home + "/", StringComparison.Ordinal) &&
                environment["PGSSLCRL"].StartsWith(home + "/", StringComparison.Ordinal) &&
                environment["PGSSLCRLDIR"] == home).IsTrue();
            await Assert.That(environment["PGOPTIONS"]).IsEqualTo(
                "-c search_path=pg_catalog -c default_transaction_read_only=on -c statement_timeout=10000");
            await Assert.That(arguments.Contains("-X") && arguments.Contains("--no-password") &&
                arguments.Contains("--no-align") && arguments.Contains("--tuples-only") &&
                arguments.Contains("--field-separator=\t") && arguments.Contains("--record-separator=\n") &&
                arguments.Contains("--set=ON_ERROR_STOP=on")).IsTrue();
            await Assert.That(arguments.Single(a => a.StartsWith("--dbname=", StringComparison.Ordinal))).IsEqualTo(
                "--dbname=service=secretkit sslmode=verify-full require_auth=scram-sha-256 channel_binding=require " +
                "gssencmode=disable sslcertmode=disable client_encoding=UTF8");
            await Assert.That(arguments.Any(a => a.Contains(user, StringComparison.Ordinal) || a.Contains(Password, StringComparison.Ordinal)) ||
                environment.Values.Any(a => a.Contains(user, StringComparison.Ordinal) || a.Contains(Password, StringComparison.Ordinal)) ||
                environment.ContainsKey("PGUSER") || environment.ContainsKey("PGPASSWORD")).IsFalse();
            await Feed(consume, Output(user, user), token);
            return 0;
        }, new()
        {
            Allocate = size => { byte[] bytes = Enumerable.Repeat((byte)0x7f, size + 19).ToArray(); buffers.Add(bytes); return bytes; },
            Exported = characters.Add,
            Open = (path, options) =>
            {
                if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
                var file = new FileStream(path, options);
                if (file.Length != 0 || options.Mode != FileMode.CreateNew || options.BufferSize != 1 ||
                    options.Access != FileAccess.ReadWrite || options.Share != FileShare.Read ||
                    File.GetUnixFileMode(path) != (UnixFileMode.UserRead | UnixFileMode.UserWrite))
                    throw new InvalidOperationException("private creation contract");
                return file;
            },
            Delete = path => { if (File.Exists(path)) erased.Add(File.ReadAllBytes(path)); File.Delete(path); }
        });
        foreach (string name in new[] { User1, User2 })
        {
            using var username = SecretMaterial.FromText(name);
            using var password = SecretMaterial.FromText(Password);
            await Assert.That(await source.AuthenticateAsync(Coordinate, username, password, default)).IsEqualTo(BackendAuthentication.Accepted);
            char[] retainedUser = username.ExportCharacters(), retainedPassword = password.ExportCharacters();
            try
            {
                await Assert.That(retainedUser.AsSpan().SequenceEqual(name) &&
                    retainedPassword.AsSpan().SequenceEqual(Password)).IsTrue();
            }
            finally { Array.Clear(retainedUser); Array.Clear(retainedPassword); }
        }
        await Assert.That(buffers.All(b => b.All(v => v == 0)) && characters.All(c => c.All(v => v == 0)) &&
            erased.Count == 4 && erased.All(b => b.Length > 0 && b.All(v => v == 0)) &&
            homes.All(h => !Directory.Exists(h))).IsTrue();
        await Assert.That(source.ToString()).IsEqualTo("[InfisicalPostgresConsumerAuthentication]");
    }

    [Test]
    [Arguments("refusal")]
    [Arguments("exit")]
    [Arguments("stderr")]
    [Arguments("stderr-overflow")]
    [Arguments("session")]
    [Arguments("current")]
    [Arguments("database")]
    [Arguments("empty-principal")]
    [Arguments("extra-row")]
    [Arguments("truncated")]
    [Arguments("crlf")]
    [Arguments("trailing-byte")]
    [Arguments("invalid-hex")]
    [Arguments("overflow")]
    [Arguments("repeat")]
    [Arguments("late")]
    [Arguments("no-callback")]
    [Arguments("launch")]
    [Arguments("read")]
    public async Task NativeFailuresAndAmbiguousCallbacksNeverAttestRefusal(string fault)
    {
        var buffers = new List<byte[]>();
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
            byte[] bytes = fault switch
            {
                "session" => Output(session: "foreign"),
                "current" => Output(current: "foreign"),
                "database" => Output(database: "foreign"),
                "empty-principal" => Output(session: ""),
                "extra-row" => [.. Output(), .. Output()],
                "truncated" => Output()[..^1],
                "crlf" => [.. Output()[..^1], (byte)'\r', (byte)'\n'],
                "trailing-byte" => [.. Output(), (byte)' '],
                "invalid-hex" => Encoding.ASCII.GetBytes(new string('z', Output().Length - 1) + "\n"),
                "overflow" => new byte[1025],
                _ => Output()
            };
            await Feed(consume, bytes, token, fault switch
            {
                "refusal" => "FATAL: password authentication failed " + Password,
                "stderr" => Password,
                "stderr-overflow" => new string('x', 4097),
                _ => ""
            });
            if (fault == "repeat")
            {
                try { await Feed(consume, Output(), token); }
                catch (NativeCaseFailureException) { }
            }
            if (fault == "late")
                token.Register(() =>
                {
                    try { consume(Stream.Null, Stream.Null, token).GetAwaiter().GetResult(); }
                    catch (NativeCaseFailureException) { }
                }, useSynchronizationContext: false);
            return fault is "refusal" or "exit" ? 2 : 0;
        }, new() { Allocate = size => { var bytes = new byte[size]; buffers.Add(bytes); return bytes; } });
        using var user = SecretMaterial.FromText(User1);
        using var password = SecretMaterial.FromText(Password);
        await Assert.That(await source.AuthenticateAsync(Coordinate, user, password, default)).IsEqualTo(BackendAuthentication.Unavailable);
        await Assert.That((home is null || !Directory.Exists(home)) && buffers.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    [Arguments("profile")]
    [Arguments("host")]
    [Arguments("port")]
    [Arguments("database")]
    [Arguments("account")]
    [Arguments("user")]
    [Arguments("normalized-user")]
    [Arguments("control")]
    [Arguments("unicode")]
    [Arguments("oversize")]
    public async Task UnsupportedInputsFailBeforeLaunchWithoutNormalizing(string fault)
    {
        bool launched = false;
        var source = Source((_, _, _, _) => { launched = true; return Task.FromResult(0); });
        RotationBackendCoordinate coordinate = fault switch
        {
            "profile" => Coordinate with { Profile = InfisicalRotationProfile.MysqlCredentials },
            "host" => Coordinate with { Host = "foreign.invalid" },
            "port" => Coordinate with { Port = 5433 },
            "database" => Coordinate with { Database = "foreign" },
            "account" => Coordinate with { Account = "foreign" },
            _ => Coordinate
        };
        using var user = SecretMaterial.FromText(fault switch
        {
            "user" => "foreign",
            "normalized-user" => " " + User1,
            _ => User1
        });
        using var password = SecretMaterial.FromText(fault switch
        {
            "control" => "secret\n",
            "unicode" => "secr\u00e9t",
            "oversize" => new string('x', 4097),
            _ => Password
        });
        await Assert.That(await source.AuthenticateAsync(coordinate, user, password, default)).IsEqualTo(BackendAuthentication.Unavailable);
        await Assert.That(launched).IsFalse();
    }

    [Test]
    [Arguments("unknown")]
    [Arguments("duplicate")]
    [Arguments("missing")]
    [Arguments("same-users")]
    [Arguments("blank-user")]
    [Arguments("long-user")]
    [Arguments("unsafe-user")]
    [Arguments("wildcard-user")]
    [Arguments("wildcard-host")]
    [Arguments("wildcard-database")]
    [Arguments("uri-host")]
    [Arguments("relative-ca")]
    [Arguments("bad-timeout")]
    [Arguments("null-host")]
    [Arguments("wrong-type")]
    public async Task ProfileRequiresExactlyEightTypedBoundedFields(string fault)
    {
        JsonObject profile = Profile();
        switch (fault)
        {
            case "unknown": profile["executable"] = "/bin/sh"; break;
            case "missing": profile.Remove("account"); break;
            case "same-users": profile["username2"] = User1; break;
            case "blank-user": profile["username1"] = " "; break;
            case "long-user": profile["username1"] = new string('a', 64); break;
            case "unsafe-user": profile["username1"] = "user=foreign"; break;
            case "wildcard-user": profile["username1"] = "*"; break;
            case "wildcard-host": profile["host"] = "*"; break;
            case "wildcard-database": profile["database"] = "*"; break;
            case "uri-host": profile["host"] = "postgres://host"; break;
            case "relative-ca": profile["rootCertificate"] = "ca.pem"; break;
            case "bad-timeout": profile["timeoutSeconds"] = 61; break;
            case "null-host": profile["host"] = null; break;
            case "wrong-type": profile["port"] = "5432"; break;
        }
        string json = profile.ToJsonString();
        if (fault == "duplicate") json = "{\"host\":\"foreign\"," + json[1..];
        using var document = JsonDocument.Parse(json);
        await Assert.That(() => new InfisicalPostgresConsumerAuthentication(document.RootElement))
            .Throws<NativeCaseFailureException>().WithMessage("missing-input");
    }

    [Test]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    public async Task PartialAllocationClearsFullAcquiredCapacityAndExports(int failure)
    {
        var buffers = new List<byte[]>();
        var characters = new List<char[]>();
        int allocations = 0;
        var source = Source((_, _, _, _) => throw new InvalidOperationException("must not launch"), new()
        {
            Allocate = size =>
            {
                if (++allocations == failure) throw new IOException(Password);
                byte[] bytes = Enumerable.Repeat((byte)0x7f, size + 7).ToArray();
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
    [Arguments("export")]
    [Arguments("short-allocation")]
    [Arguments("large-allocation")]
    [Arguments("first-open")]
    [Arguments("second-open")]
    [Arguments("first-write")]
    [Arguments("second-write")]
    [Arguments("first-flush")]
    [Arguments("second-flush")]
    public async Task PartialIoAndExportFailuresEraseBothFilesAndBuffers(string fault)
    {
        var buffers = new List<byte[]>();
        var characters = new List<char[]>();
        var erased = new List<byte[]>();
        string? home = null;
        int opens = 0;
        var source = Source((_, _, _, _) => throw new InvalidOperationException("must not launch"), new()
        {
            Exported = chars =>
            {
                characters.Add(chars);
                if (fault == "export") throw new IOException(Password);
            },
            Allocate = size =>
            {
                byte[] bytes = Enumerable.Repeat((byte)0x7f,
                    fault == "short-allocation" ? size - 1 : fault == "large-allocation" ? 16385 : size).ToArray();
                buffers.Add(bytes);
                return bytes;
            },
            Open = (path, options) =>
            {
                home = Path.GetDirectoryName(path);
                string which = ++opens == 1 ? "first" : "second";
                if (fault == which + "-open") throw new IOException(Password);
                return new FaultFile(path, options, fault == which + "-write" ? "partial" :
                    fault == which + "-flush" ? "initial-flush" : "");
            },
            Delete = path => { if (File.Exists(path)) erased.Add(File.ReadAllBytes(path)); File.Delete(path); }
        });
        using var user = SecretMaterial.FromText(User1);
        using var password = SecretMaterial.FromText(Password);
        await Assert.That(await source.AuthenticateAsync(Coordinate, user, password, default)).IsEqualTo(BackendAuthentication.Unavailable);
        await Assert.That(buffers.All(b => b.All(v => v == 0)) && characters.All(c => c.All(v => v == 0)) &&
            erased.All(b => b.All(v => v == 0)) && (home is null || !Directory.Exists(home))).IsTrue();
    }

    [Test]
    [Arguments("")]
    [Arguments(" ")]
    [Arguments("printable")]
    [Arguments("maximum")]
    public async Task PasswordDomainAndChunkedHexResultPreserveExactBytes(string kind)
    {
        string secret = kind switch
        {
            "printable" => new string(Enumerable.Range(32, 95).Select(c => (char)c).ToArray()),
            "maximum" => new string('\\', 4096),
            _ => kind
        };
        JsonObject profile = Profile();
        profile["host"] = "::1";
        profile["username1"] = new string('a', 63);
        string name = profile["username1"]!.GetValue<string>();
        var source = Source(async (_, environment, consume, token) =>
        {
            string row = await File.ReadAllTextAsync(environment["PGPASSFILE"], token);
            await Assert.That(row).IsEqualTo("\\:\\:1:5432:owned:" + name + ":" +
                secret.Replace("\\", "\\\\", StringComparison.Ordinal).Replace(":", "\\:", StringComparison.Ordinal) + "\n");
            using var stdout = new ChunkedStream(Output(name, name));
            await consume(stdout, Stream.Null, token);
            return 0;
        }, profile: profile);
        using var user = SecretMaterial.FromText(name);
        using var password = SecretMaterial.FromText(secret);
        await Assert.That(await source.AuthenticateAsync(Coordinate with { Host = "::1" }, user, password, default))
            .IsEqualTo(BackendAuthentication.Accepted);
    }

    [Test]
    [Arguments("wipe", false)]
    [Arguments("flush", false)]
    [Arguments("close", false)]
    [Arguments("delete", false)]
    [Arguments("delete", true)]
    public async Task CleanupFailureOverridesAcceptanceAndCancellation(string fault, bool cancel)
    {
        var paths = new List<string>();
        var buffers = new List<byte[]>();
        var characters = new List<char[]>();
        using var cancellation = new CancellationTokenSource();
        var source = Source(async (_, _, consume, token) =>
        {
            await Feed(consume, Output(), token);
            if (cancel) cancellation.Cancel();
            return 0;
        }, new()
        {
            Allocate = size => { var bytes = new byte[size]; buffers.Add(bytes); return bytes; },
            Exported = characters.Add,
            Open = (path, options) => { paths.Add(path); return new FaultFile(path, options, fault); },
            Delete = path => { if (fault == "delete") throw new IOException(Password); File.Delete(path); }
        });
        using var user = SecretMaterial.FromText(User1);
        using var password = SecretMaterial.FromText(Password);
        try
        {
            await Assert.That(async () => await source.AuthenticateAsync(Coordinate, user, password, cancellation.Token))
                .Throws<NativeCaseFailureException>().WithMessage("cleanup-incomplete");
            await Assert.That(buffers.All(b => b.All(v => v == 0)) && characters.All(c => c.All(v => v == 0))).IsTrue();
            if (fault == "delete")
                await Assert.That(paths.All(p => File.ReadAllBytes(p).All(b => b == 0))).IsTrue();
        }
        finally
        {
            foreach (string path in paths)
                if (File.Exists(path)) File.Delete(path);
            if (paths.Count > 0 && Directory.Exists(Path.GetDirectoryName(paths[0])))
                Directory.Delete(Path.GetDirectoryName(paths[0])!);
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CancellationDrainsActualDelegateAndNoncooperativeReaderBeforeErasure(bool earlyReturn)
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseReader = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var processEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseProcess = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        string? path = null;
        Task? reading = null;
        using var cancellation = new CancellationTokenSource();
        var source = Source(async (_, environment, consume, token) =>
        {
            path = environment["PGPASSFILE"];
            using var output = new BarrierStream(Output(), entered, releaseReader);
            reading = consume(output, Stream.Null, token);
            processEntered.SetResult();
            if (earlyReturn) return 0;
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
            await Assert.That(File.Exists(path) && !pending.IsCompleted).IsTrue();
        }
        finally { releaseProcess.TrySetResult(); releaseReader.TrySetResult(); }
        await Assert.That(async () => await pending.WaitAsync(Bound)).Throws<OperationCanceledException>();
        await Assert.That(reading!.IsCompleted && !Directory.Exists(Path.GetDirectoryName(path!))).IsTrue();
    }

    [Test]
    public async Task ReaderFaultAndThrowingCancellationDrainSiblingBeforeErasure()
    {
        var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        string? path = null;
        var source = Source(async (_, environment, consume, token) =>
        {
            path = environment["PGPASSFILE"];
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
    public async Task DeadlineWaitsForDelegateAndSanitizesItsOutcome()
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
        await Assert.That(async () => await source.AuthenticateAsync(Coordinate, user, password, default).AsTask().WaitAsync(Bound))
            .Throws<NativeCaseFailureException>().WithMessage("deadline-exceeded");
    }

    [Test]
    [Arguments(0, false)]
    [Arguments(0, true)]
    [Arguments(17, false)]
    public async Task ActualRunnerClearsAmbientAuthorityAndDrainsBothPipes(int exit, bool diagnostic)
    {
        string name = "SECRETKIT_POSTGRES_AMBIENT_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(name, Password);
        var source = Source((_, environment, consume, token) =>
            InfisicalPostgresConsumerAuthentication.RunProcessAsync(new Process { StartInfo = new("/bin/sh") },
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
    public async Task ActualRunnerLaunchAndReaderFailuresAreSanitized(bool readerFailure)
    {
        string? home = null;
        var source = Source((_, environment, _, token) =>
        {
            home = environment["HOME"];
            return InfisicalPostgresConsumerAuthentication.RunProcessAsync(new Process
            {
                StartInfo = new(readerFailure ? "/bin/sh" : "/secretkit-nonexistent/psql")
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
    public async Task ActualRunnerKillsChildAndDrainsReaderBeforeDeletingCredentials()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Process? active = null;
        string? path = null;
        using var cancellation = new CancellationTokenSource();
        var source = Source((_, environment, consume, token) =>
        {
            path = environment["PGPASSFILE"];
            active = new Process { StartInfo = new("/bin/sh") };
            return InfisicalPostgresConsumerAuthentication.RunProcessAsync(active,
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

    private sealed class FaultFile(string path, FileStreamOptions options, string fault) : FileStream(path, options)
    {
        private int writes;
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            writes++;
            if (fault == "partial" && writes == 1)
            {
                await base.WriteAsync(buffer[..Math.Min(7, buffer.Length)], cancellationToken);
                throw new IOException(Password);
            }
            if (fault == "wipe" && writes > 1) throw new IOException(Password);
            await base.WriteAsync(buffer, cancellationToken);
        }

        public override Task FlushAsync(CancellationToken cancellationToken) =>
            fault == "initial-flush" ? Task.FromException(new IOException(Password)) : base.FlushAsync(cancellationToken);

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
}
