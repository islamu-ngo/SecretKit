# Local Infisical sandbox

> **Audience:** SecretKit contributors running authorized live tests
> **Status:** Developer infrastructure; live results remain deployment-specific
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-11-21 source and offline checks; live startup is tracked separately
> **Source anchors:** [pod definition](pod.yaml), [lifecycle script](sandbox.sh),
> [sandbox admission](../../tests/SecretKit.Infisical.Conformance.Tests/Infrastructure/OwnedSandbox.cs)

Run from the SecretKit checkout on Linux x64 with rootless Podman, Bash, curl,
OpenSSL and the repository's pinned .NET SDK. The sandbox uses Infisical
`v0.167.12`, PostgreSQL and Redis. Immutable image digests live in
[`pod.yaml`](pod.yaml); the app digest must also match `OwnedSandbox`.
The service binds to IPv4 loopback. No database or Redis port is published.

```bash
bash eng/live-infisical/sandbox.sh up 18080
```

Keep the printed `owner` and `origin`. Each invocation creates a separate
`secretkit-sdk-<8hex>` pod. Set `OWNER` to that exact printed identifier before
using these commands:

```bash
bash eng/live-infisical/sandbox.sh status "$OWNER"
bash eng/live-infisical/sandbox.sh logs "$OWNER"
```

`status` verifies the selected pod's labels, the app image digest, its single
loopback port mapping and HTTP readiness. `logs` reports recent line counts
without printing container output, which may contain credentials.

Startup generates encryption, authentication and database secrets and streams
them to Podman without creating a checkout file. Podman retains those values
in its private container configuration. Treat access to the container engine
as access to the sandbox credentials. This is disposable local infrastructure;
do not use it for production material or durable storage.

After your testing is complete, explicitly remove the selected pod:

```bash
bash eng/live-infisical/sandbox.sh down "$OWNER"
```

Removal checks exact ownership labels and the inspected pod ID before acting.
It destroys the selected sandbox and its running workloads. If startup fails,
retain the owner printed before the failure for inspection and cleanup.
Do not remove another contributor's pod.

Continue with the [provisioning guide](../../docs/internal/LIVE_INFISICAL_PROVISIONING.md)
for bootstrap, the private clone-root `.env`, fixture reconciliation and live
test runners. Local Community Edition observations establish only the tested
deployment's behavior. Missing Enterprise entitlements remain failed or open
gates; they are never replaced by offline or local results.
