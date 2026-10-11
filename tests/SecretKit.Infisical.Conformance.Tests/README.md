# Owned Infisical conformance

This nonpackable test project runs separately from the offline solution. Live
tests require explicit generated fixture inputs and fail on missing input,
missing entitlement or unavailable service; those conditions are not skipped.
It does not use a personal account or ambient cloud credentials.
The current sandbox/process tooling is Linux-only.

The test-only process runner subscribes to exit before launch, retains the
process until its actual exit, bounds captured evidence and discards stderr.
It clears ambient environment variables and injects only caller-selected values
into the actual process environment. Credentials never belong in CLI arguments
or captured command logs. Failed children report exit codes without raw output.

```sh
dotnet restore tests/SecretKit.Infisical.Conformance.Tests/SecretKit.Infisical.Conformance.Tests.csproj --locked-mode
dotnet build tests/SecretKit.Infisical.Conformance.Tests/SecretKit.Infisical.Conformance.Tests.csproj --configuration Release --no-restore
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/ProcessLifetimeTests/*' --minimum-expected-tests 3
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/OwnedSandboxTests/*' --minimum-expected-tests 11
```

`OwnedSandbox` requires an exact `secretkit-sdk-` owner followed by eight hex
digits, a generated organization ID, and an explicit `http://127.0.0.1` origin
with a nondefault port. Before live work it checks the pod's
`secretkit-sdk-owned=true` label, the pinned app image digest and the sole
loopback port mapping. Server-only initial bootstrap is setup, not SDK proof.

The admitted local image is Infisical v0.166.3 at
`sha256:c063089e4525b033fe6ab9e6858c3afb395ad38d363dcbfa6cbb6122a99a4eea`.
Loopback ingress is not an egress firewall. Do not configure production or
external connection targets. SQL effects require a separate owned test database,
never Infisical's platform database.

Receipts and exact resource IDs remain with the fixture owner. No automatic
mutation retry, signup replay, deletion or credential revocation occurs on
disposal. Live setup deliberately exports applied project/identity coordinates
to a unique ignored `artifacts/conformance/*.jsonl` recovery manifest, created
with owner-read/write permissions. It contains no credentials and is not a
diagnostic log. Retain those manifests before any explicit owned cleanup.
Installed-package and separate restricted-runtime evidence are distinct
from a source-project administrative write/read.

The explicit live scenario requires privately injected `SECRETKIT_LIVE_ORIGIN`,
`SECRETKIT_LIVE_OWNER`, `SECRETKIT_LIVE_ORGANIZATION` and
`SECRETKIT_LIVE_ADMIN_TOKEN`. The last value is the generated server-setup
identity, not the runtime actor. Setup creates a fresh generated administrative
machine, a project-viewer machine and an unassigned denied machine. Universal
Auth login and SDK project/identity/membership factories are exercised. The
runtime actor must read its own project but fail writes and reads of a second
project; the unassigned actor must fail its read.

```sh
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/IdentitySetupTests/*' --minimum-expected-tests 1
```

The installed narrative uses a new generated actor/project fixture and restores
the package consumer into unique cache, intermediate and binary directories.
It checks that every dependency asset is a package, then privately injects
separate generated admin/runtime/denied tokens into the actual consumer process.
Both native-access and bootstrap/configuration/assessment sentinels must pass.
Consumer failures withhold protected diagnostics. Its linked samples consume
the packed libraries, not source-project references.

```sh
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/InstalledReadWriteTests/*' --minimum-expected-tests 1
```

`MutationUncertaintyTests` uses a one-write owned loopback fault boundary. A
pre-canceled write stays absent and undispatched. For post-commit cancellation
and response loss, the boundary observes the owned upstream acknowledgement
before withholding its response; an independent native read then confirms the
actual Unicode/newline value. The caller's receipt stays uncertain and reuse
fails. That fresh read is effect evidence, not automatic receipt reconciliation.
The separate redirect test gives a second origin valid canary material and
requires the original SDK read to refuse it. Offline native tests separately
cover response limits, disposal/drain and redacted diagnostics.

```sh
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/MutationUncertaintyTests/*' --minimum-expected-tests 2
```

`ImportDeliveryTests` uses fresh restricted-runtime reads to verify explicit
import lookup, bottommost-import precedence, local shadowing, denied delivery,
and raw versus expanded references. That scenario passed against the owned
v0.166.3 server. `ImportPolicyTests` separates ordinary creation/delivery
observations from replication entitlement. Successful creation never attests
destination policy or application.

```sh
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/ImportDeliveryTests/*' --minimum-expected-tests 1
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/ImportPolicyTests/CreationAndFreshDeniedDeliveryDoNotAttestDestinationPolicy' --minimum-expected-tests 1
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/ImportPolicyTests/ReplicationRequiresAnActuallyEntitledOwnedSandbox' --minimum-expected-tests 1
```

The owned edition rejected replication with HTTP 400 and a paid-plan restriction;
the receipt was Rejected. This is an explicit conformance gate, not a skipped or
passing scenario. The separate ordinary effect case passed its dedicated
positive-count run; destination policy remains Unknown. No private API,
automatic replay or assumed approval-policy state is used.

`NativeAuthenticationTests` proves read-only authority, finite renewal and fresh
read denial after each of the two native revocation routes. `NativeTokenPolicyTests`
compares configured Universal policy with actual login and renewal. On pinned
v0.166.3, ordinary TTL=10/max=20 yields expiresIn=10/max=20; period=60 retains
configured TTL=10/max=20 but yields expiresIn=60/max=0. Periodic lifetime therefore
must not be capped by the configured finite maximum. Both renewed credentials
perform an actual restricted-runtime read. Separate deterministic hosting tests
verify explicitly started idle renewal, original finite ceilings and bounded
cancellation/drain; they are not wall-clock native longevity proof.

```sh
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/NativeAuthenticationTests/*' --minimum-expected-tests 1
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/NativeTokenPolicyTests/*' --minimum-expected-tests 1
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/NativeBootstrapRecoveryTests/*' --minimum-expected-tests 1
```

The bootstrap-recovery parent launches exact `BootstrapRecoveryChildTests`
stages with cleared ambient environments. These child stages require their
parent's private injection and are not standalone top-level live scenarios.
The parent selects one-use client secrets, observes native consumption after
the login child exits, starts a fresh process without token or bootstrap,
and supplies a separately administrator-authorized replacement only to a new
recovery child. No credential file or consumed-bootstrap retry is used.

`DynamicSqlLifecycleTests` provisions a separate generated PostgreSQL test
container on the validated owner's labelled `<owner>-network` private bridge,
using the pinned PostgreSQL image. It publishes no host database port and uses
a distinct container/DNS host, never the platform database's host or storage.
Final TCP readiness is an exact log event,
not an initdb temporary-server signal or a delay. Database credentials enter
only selected child environments. The backend container is retained and
recorded in the owner-only recovery manifest; local disposal only detaches its
CLI. No database driver is added to SDK packages.

The SQL scenario exercises issuance, read-only backend use, observed role-expiry
renewal, fresh post-revocation denial, and committed acquisition response loss/
cancellation barriers. On the current owned edition it fails earlier at native
definition creation: HTTP400/Rejected, "Failed to create dynamic secret due to
plan restriction. Upgrade plan to create dynamic secret." These later effect
assertions are unrun, not passed or skipped. An entitled owned deployment is
required to complete the scenario.

```sh
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/DynamicSqlLifecycleTests/*' --minimum-expected-tests 1
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/RotationProgressTests/OwnedPostgresRotationConfigurationHasSeparateProgressAndBackendEvidence' --minimum-expected-tests 1
```

`RotationProgressTests` retains one direct Infisical PostgreSQL connection
provisioning step as a test-only owned fixture prerequisite. It is not an SDK
factory or public connector support. The separate standalone connection case
and its selection were removed with the third-party catalog. Its historical
1/1 result on owned v0.166.3 covered connection creation, fresh inspection and
a backend query only; it is not a current runnable check or removal evidence.

The retained rotation scenario historically progressed through successful
connection creation, then failed with HTTP400/Rejected:
"Failed to create secret rotation due to plan restriction. Upgrade plan to
create secret rotations." It is not a passed or skipped rotation case.
Configuration/progress/trigger completion, password changes, runtime refresh
and fleet convergence remain unverified.
The retained rotation fixture builds, but its revised live scenario was not run
during catalog removal. The command above selects only that native scenario. Native SQL rotation configuration and runtime features remain in
scope under the current SDK scope.

The owned server requires documented `ALLOW_INTERNAL_IP_CONNECTIONS=true` for
these private destinations. This does not permit using hosts reserved for
Infisical's own PostgreSQL/Redis. The private bridge and distinct backend host
respect that guard; no host alias or platform database is substituted.
