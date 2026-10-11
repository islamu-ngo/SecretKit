using System.Diagnostics;
using System.Security.Cryptography;

namespace SecretKit.Infisical.Conformance.Tests;

/// <summary>One separate generated backend on the validated owner's private bridge, with no host ingress.</summary>
internal sealed class OwnedSqlBackend : IDisposable
{
    private const string Image = "docker.io/library/postgres@sha256:4ea9e5ed06591da7ea23eb65465e8d3187fe79f4d5ec3ae976d29a33b013e77a";
    private readonly Process _attached;
    private readonly string _network;
    private bool _started;
    internal string Container { get; }
    internal int Port => 5432;
    internal string Host => Container;
    internal string Password { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    internal const string Database = "sdk_effects";

    internal OwnedSqlBackend(string owner)
    {
        Container = owner + "-sql-" + Guid.NewGuid().ToString("N")[..8];
        _network = owner + "-network";
        _attached = new Process
        {
            StartInfo = new ProcessStartInfo("podman")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            },
            EnableRaisingEvents = true
        };
        _attached.StartInfo.ArgumentList.Add("start");
        _attached.StartInfo.ArgumentList.Add("--attach");
        _attached.StartInfo.ArgumentList.Add("--sig-proxy=false");
        _attached.StartInfo.ArgumentList.Add(Container);
    }

    internal async Task StartAsync(Action<string, string> record, CancellationToken cancellationToken)
    {
        var network = await OwnedProcess.RunAsync("podman",
            ["network", "inspect", _network, "--format", "{{index .Labels \"secretkit-sdk-owned\"}}"],
            AppContext.BaseDirectory, cancellationToken: cancellationToken);
        if (network.ExitCode != 0 || network.Output.Trim() != "true")
            throw new InvalidOperationException("The owned SQL private network was not established.");
        var created = await OwnedProcess.RunAsync("podman",
            ["create", "--network", _network, "--name", Container, "--label", "secretkit-sdk-owned=true",
                "-e", "POSTGRES_PASSWORD", "-e", "POSTGRES_DB=" + Database,
                "-e", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256", Image],
            AppContext.BaseDirectory, new Dictionary<string, string> { ["POSTGRES_PASSWORD"] = Password },
            cancellationToken);
        if (created.ExitCode != 0) throw new InvalidOperationException("Owned SQL creation failed.");
        record("sql-container", Container);
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        bool listening = false;
        _attached.ErrorDataReceived += (_, line) =>
        {
            // initdb's temporary server is Unix-socket-only. Require the final
            // TCP listener before accepting its readiness event.
            if (line.Data?.Contains("listening on IPv4 address \"0.0.0.0\"", StringComparison.Ordinal) == true)
                listening = true;
            if (listening && line.Data?.Contains("database system is ready to accept connections",
                StringComparison.Ordinal) == true) ready.TrySetResult();
        };
        _attached.OutputDataReceived += (_, _) => { };
        _attached.Exited += (_, _) => ready.TrySetException(
            new InvalidOperationException("Owned SQL exited before readiness."));
        _attached.Start();
        _started = true;
        _attached.BeginOutputReadLine();
        _attached.BeginErrorReadLine();
        await ready.Task.WaitAsync(TimeSpan.FromSeconds(30), cancellationToken);
        var initialized = await QueryAsync("postgres", Password,
            "CREATE TABLE sdk_probe (value integer NOT NULL); INSERT INTO sdk_probe VALUES (731);", cancellationToken);
        if (initialized.ExitCode != 0) throw new InvalidOperationException("Owned SQL fixture initialization failed.");
    }

    internal Task<(int ExitCode, string Output)> QueryAsync(string username, string password, string statement,
        CancellationToken cancellationToken) =>
        OwnedProcess.RunAsync("podman",
            ["exec", "--env", "PGUSER", "--env", "PGPASSWORD", "--env", "PGDATABASE", Container,
                "psql", "-X", "-h", "127.0.0.1", "-p", "5432",
                "-v", "ON_ERROR_STOP=1", "-At", "-c", statement],
            AppContext.BaseDirectory, new Dictionary<string, string>
            {
                ["PGUSER"] = username,
                ["PGPASSWORD"] = password,
                ["PGDATABASE"] = Database
            }, cancellationToken);

    public void Dispose()
    {
        // Detach the CLI only. The exact owned backend and recovery manifest
        // remain available; disposing the helper is not remote cleanup authority.
        if (_started && !_attached.HasExited) _attached.Kill(entireProcessTree: true);
        _attached.Dispose();
    }
}
