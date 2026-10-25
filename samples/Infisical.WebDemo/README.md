# Infisical web demo

**In development, not ready for production.** A nonpackable .NET 10 / C# 14
application using installed Core, Infisical and Configuration packages.
ASP.NET Core belongs to this application, not the SDK. There is no browser UI.
See [security boundaries and recovery](../../docs/public/demos-and-recovery.md)
for detailed protected-input, ownership and recovery guidance.

## Reading order

1. `Program.cs` calls `WebDemoApplication.RunAsync(args)`.
2. `WebDemoApplication.cs` reads input, composes the provider/runtime, starts
   Kestrel only after required admission, then stops and disposes owned resources.
3. `WebDemoEndpoints.cs` handles health and work; each request holds one lease
   and its accepted local revision through the downstream operation.
4. `WebDemoRuntime.cs` validates candidates into `JobClient` instances, owns
   collection tasks, processes stdin controls and drains retired generations.
5. `WebDemoOptions.cs` parses downstream policy; `JobClient.cs` shows the fixed
   authenticated HTTP call. Linked shared sources handle protected input/token
   copying and runtime generation/lease mechanics.

## Install and run

Install the SDK pinned by `global.json`. Select an exact local candidate bundle
using the [local package guide](../../docs/public/local-packages.md), its
source-mapped NuGet configuration, matching generated lock and fresh cache.
From the SecretKit checkout, set `SECRETKIT_FEED_CONFIG` to that configuration:

```sh
version=0.1.0-local.20261024.1
export NUGET_PACKAGES="$(mktemp -d)"
dotnet restore samples/Infisical.WebDemo/Infisical.WebDemo.csproj --locked-mode \
  --configfile "$SECRETKIT_FEED_CONFIG" -p:SecretKitCandidateVersion="$version"
dotnet build samples/Infisical.WebDemo/Infisical.WebDemo.csproj -c Release \
  --no-restore -p:SecretKitCandidateVersion="$version"
dotnet samples/Infisical.WebDemo/bin/Release/net10.0/Infisical.WebDemo.dll --help
dotnet samples/Infisical.WebDemo/bin/Release/net10.0/Infisical.WebDemo.dll serve
```

Help performs no input, host or provider I/O. For `serve`, use an application-owned
protected stdin pipe, not credential arguments, settings or shell history.
Supply two LF-terminated JSON frames: common input (64 KiB maximum), then
application policy (8 KiB maximum). Synthetic examples:

```json
{"origin":"https://vault.example.invalid/","project":"selected-project","environment":"selected-environment","folder":"/selected-folder","key":"selected-key","token":"synthetic-example-only"}
{"downstream":"http://127.0.0.1:8081/","optionalKey":"selected-optional-key"}
```

The downstream is one HTTP origin with a literal loopback IP and no user
information, path beyond `/`, query or fragment. `optionalKey` may be omitted.
Infisical requires HTTPS unless the first frame explicitly selects
`allowLoopbackDevelopmentHttp:true` for controlled loopback development only.

## Startup, work, reload and shutdown

Required admission precedes serving. Optional admission has an independent
30-second budget and remains owned through shutdown; failure leaves required
work available. Empty production configuration, cleared logging and Kestrel
allow only IPv4 loopback, an ephemeral port and no request body. The `listening`
JSON event gives the actual already-bound address; do not probe for a port.

| Request | Result |
| --- | --- |
| `GET /health/live` | 200 while serving |
| `GET /health/ready` | 200 for usable required work, otherwise 503 |
| `POST /work` | Submit with the required generation |
| `POST /work?optional=true` | Submit with optional generation, otherwise 503 |

Work sends only `{"operation":"reconcile"}` to downstream `POST /jobs`, with
the selected credential only in its Bearer header. No redirects, proxies,
cookies or activity propagation are enabled; no response prose is exported.
One async lease pins the local revision across replacement. The operation has a
30-second deadline linked to request abort. Responses contain bounded categories
and the pinned revision: acceptance is 200, refusal 502, connected deadline 504;
unavailable selection is 503 and all other routes/methods are 404.

After the frames, send LF-terminated controls (64 bytes maximum): `check`
collects/validates without publication; `enable` explicitly publishes a valid
replacement; `disable` fences late candidates and makes readiness unavailable;
`stop` or EOF stops work. Collection is armed before `collecting` is emitted.
At most 16 collection tasks overlap, including optional startup; excess is `busy`.
Last-known work lasts at most five minutes from collection start or earlier
observed expiry. Checks do not extend it. Old clients retire after leases release.

Startup and collection budgets are 30 seconds. Host stop and retirement each
have a five-second budget; timeout means nonzero exit, not successful drain.
Every task remains awaited even after timeout, so exit can be delayed.
Provider, client and material ownership stays application-local; managed header
strings cannot promise forensic erasure. Native Infisical, Windows, production
networking, trimming and Native AOT remain unqualified.
