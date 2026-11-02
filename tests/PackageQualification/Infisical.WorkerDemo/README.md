# Infisical Generic Host worker

**In development, not ready for production.** This .NET 10 / C# 14 teaching
sample uses installed packages, outside the SDK solution graph. It does not
establish native, Windows or AOT qualification.

## Reading order

1. `Program.cs` delegates to `WorkerDemoApplication.RunAsync`.
2. `WorkerDemoApplication.cs` reads the selected input/session, awaits a required
   read, builds/starts the host, waits for completion, then stops/drains it.
3. `SecretWorker.cs` separates command intake, sequential work and native renewal.
4. Linked `WorkerInput.cs`, `DemoInput.cs`, `DemoInputReader.cs` and `DemoOutput.cs`
   own protected framing, selected material/lifetime evidence and fixed output.

## Install and run

Use the [local package guide](../../docs/public/local-packages.md) to select the
four original archives and a source-mapped NuGet configuration. From this
directory, set `SECRETKIT_FEED_CONFIG` to that configuration:

```sh
version=0.1.0-local.20261024.1
export NUGET_PACKAGES="$(mktemp -d)"
dotnet restore Infisical.WorkerDemo.csproj --locked-mode \
  --configfile "$SECRETKIT_FEED_CONFIG" -p:SecretKitCandidateVersion="$version"
dotnet build Infisical.WorkerDemo.csproj --configuration Release --no-restore \
  -p:SecretKitCandidateVersion="$version"
dotnet bin/Release/net10.0/Infisical.WorkerDemo.dll --help
dotnet bin/Release/net10.0/Infisical.WorkerDemo.dll run --maintain
```

The generated lock selects `0.1.0-local.20261024.1`; another candidate requires
deliberate lock regeneration/review. The app-only Generic Host is exactly
`10.0.12`. Default invocation and `--help` do no input, host or provider I/O.

Send the selected compact JSON frame over a protected stdin pipe, then
LF-terminated ASCII controls (at most 16 bytes each). The producer protects the
pipe; never put credentials in arguments or committed settings. See
[demos and recovery](../../docs/public/demos-and-recovery.md) for the input schema,
security rules, recovery runbook and separate verification gates.

The frame contains `origin`, `project`, `environment`, `folder`, `key`, `token`,
`originalIssuedAt`, `expiresAt`, `lifetime` (`finite`, `periodic` or `unknown`),
`maximumTtlSeconds`, and optional `periodSeconds`. Times are ISO-8601 timestamps;
`token:null` means credentials were lost, not a request to log in.

| Control | Effect |
| --- | --- |
| `work` | Read the selected secret, dispose its material, report outcome/version. |
| `renew` | With `--maintain` only: start or join renewal of the selected session. |
| `stop` | Cancel intake/work and drain the host and maintenance. |

`run` alone does not start maintenance. `run --maintain` explicitly starts it;
registration alone starts nothing. Lifetime evidence comes from the selected
input, not a new handoff timestamp or decoded JWT. Finite renewal does not
recreate the original lifetime ceiling; lost/invalid evidence requires recovery.

## Lifecycle to preserve

The required read finishes before host construction/start: `prepared` precedes
`started`. Intake runs on its own task because stdin can complete synchronously.
The bounded channel holds one waiting command; send work after its predecessor's
outcome. EOF drains accepted work; `stop` cancels an outstanding read or renewal.

`renewal-awaiting` is emitted after the native start/join task exists and before
awaiting it. Only `renewed` acknowledges success. Failed work or renewal prevents
further dispatch until stop/EOF; replacement needs a separately authorized new
process. There is no retry, login, fallback principal or mutation replay.

The operation deadline is 30 seconds; host stop/drain has a separate five-second
budget. Native teardown also has explicit five-second budgets. The application
owns input, material, worker, maintenance, client and session. Supplied DI
instances do not transfer ownership. Stop/drain precedes their disposal.

The bare host clears logging providers. Private exception text never becomes a
host log; failures are fixed output categories. Completion is signaled in the
worker's `finally` after its intake task drains. Operator stop differs from
deadline/host cancellation; a prior failure is not reported as a successful stop.

Exit codes: `0` stop/help; `2` invalid input/control; `4` unavailable, denied or
recovery-required; `5` cancellation/deadline; `6` shutdown timeout.
