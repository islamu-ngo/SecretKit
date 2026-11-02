# Infisical installed-package console

**SecretKit is in development, not ready for production.** This app uses local
Core and Infisical packages. It does not establish native provider qualification.

## Read the code

Start with `Program.cs`, which calls `ConsoleDemoApplication.RunAsync(args)`.
In `ConsoleDemoApplication.cs`, follow command classification, the deadline and
cancellation boundary, then the named `ReadAsync`, `CreateAsync` and `UpdateAsync`
operations. The SDK calls stay visible there.

`ConsoleDemoCommand.cs` names the accepted commands; `ConsoleDemoOutcomes.cs`
maps SDK outcomes to bounded output and exit codes. Linked shared sources in
`../Infisical.Demos/` parse input (`DemoInput`, `MutationInput`, `DemoInputReader`),
provide the selected token (`DemoTokenSource`) and serialize results (`DemoOutput`).

## Restore and run

Use the pinned .NET SDK and the selected candidate's reviewed local feed; see
the [local package guide](../../docs/public/local-packages.md) to prepare it.
Set `SECRETKIT_FEED_CONFIG` to its source-mapped `NuGet.Config` and
`SECRETKIT_INPUT_FILE` to a protected input file. From this directory:

```bash
version=0.1.0-local.20261024.1
export NUGET_PACKAGES="$(mktemp -d)"
dotnet restore --locked-mode --configfile "$SECRETKIT_FEED_CONFIG" -p:SecretKitCandidateVersion="$version"
dotnet build --configuration Release --no-restore -p:SecretKitCandidateVersion="$version"
dotnet bin/Release/net10.0/Infisical.ConsoleDemo.dll --help
dotnet bin/Release/net10.0/Infisical.ConsoleDemo.dll read < "$SECRETKIT_INPUT_FILE"
```

The fresh cache avoids reusing previously installed packages. Keep the selected
version, feed and lock together; this project has no SDK project references.
No arguments or `--help` emits help without reading input or contacting a provider.

Input is one **flat JSON object** over redirected stdin, never credentials in
arguments or committed settings. Required fields are `origin`, `project`,
`environment`, `folder`, `key`, `token`; `create` and `update` also require `value`.
Unknown and duplicate fields are rejected. Select a least-privilege read token
or an explicitly authorized writer token for the intended operation.

HTTPS with system trust is the default. `allowLoopbackDevelopmentHttp` permits
only local HTTP. Input is bounded to 64 KiB, with individual field limits.
The input and operation share a 30-second deadline; Ctrl+C cancels that work.
The app disposes input material, reads and its asynchronously owned client.

## Outcomes and recovery

Output is bounded JSON with `outcome`, optional receipt `evidence` and `version`;
absent evidence/version are null. No values, tokens, coordinates, approval IDs or
exception text are printed. A version is observation evidence, not compare-and-swap.

| Exit | Meaning |
| --- | --- |
| 0 | Help, successful read, or applied write |
| 2 | Invalid operation or input |
| 3 | Pending approval, not applied |
| 4 | Native failure or unknown/unavailable outcome |
| 5 | Cancelled; a dispatched write may still have taken effect |

Writes are explicit: no upsert, fallback login or automatic replay. The receipt
survives cancellation and uncertain acknowledgements. Never retry an uncertain
write to discover its effect; reconcile through authorized provider observations.
Readback alone may not identify the writer, and pending approval is not activation.

Protect stdin files and host diagnostics: disposal cannot clear ordinary strings,
terminal history or dumps. The [shared demo guide](../../docs/public/demos-and-recovery.md)
covers recovery and controlled evidence; live permissions and platforms remain
separate qualification gates.
