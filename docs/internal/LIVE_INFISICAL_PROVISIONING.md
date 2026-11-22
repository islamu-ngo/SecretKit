# Live Infisical provisioning

> **Audience:** Contributors operating an owned or explicitly authorized Infisical environment
> **Status:** Developer tooling; native and release qualification require their own evidence
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-11-21 source review; local startup, fresh bootstrap, repeated provisioning and native identity runner passed; remote evidence remains separate
> **Source anchors:** [CLI](../../tools/SecretKit.LiveProvisioner/Program.cs),
> [configuration](../../tools/SecretKit.LiveProvisioner/LiveEnvConfig.cs),
> [reconciliation](../../tools/SecretKit.LiveProvisioner/FixtureReconciler.cs),
> [runner](../../tools/SecretKit.LiveProvisioner/LiveRunner.cs),
> [sandbox](../../eng/live-infisical/)

The nonpackable `SecretKit.LiveProvisioner` host prepares disposable Infisical
fixtures through SecretKit's typed APIs. It stores only automation Universal
Auth credentials in a private clone-root `.env`. Each run issues short-lived,
single-use client secrets for five separate fixture identities and mints their
access tokens in memory. No bearer token cache is required.

## Tutorial: start a local sandbox

Use Linux x64, rootless Podman, Bash, curl, OpenSSL and the SDK pinned in
[`global.json`](../../global.json). Run all commands from the SecretKit root.
Build the host after a locked restore:

```bash
dotnet restore SecretKit.slnx --locked-mode
dotnet build tools/SecretKit.LiveProvisioner/SecretKit.LiveProvisioner.csproj -c Release --no-restore
bash eng/live-infisical/sandbox.sh up 18080
```

The script prints an owner and loopback origin when the exact pinned
Infisical `v0.167.12` instance is ready. Set `OWNER` to that printed owner.
Keep the pod until bootstrap and your intended tests have completed.

Bootstrap requires a new local instance and an absent `.env`. Do not copy the
template before local bootstrap. The password below is a new disposable local
bootstrap password, never your personal Infisical password. It enters through
stdin and is not written to `.env`:

```bash
read -r -s -p 'Disposable local bootstrap password: ' BOOTSTRAP_PASSWORD
printf '\n'
printf '%s\n' "$BOOTSTRAP_PASSWORD" |
  dotnet tools/SecretKit.LiveProvisioner/bin/Release/net10.0/SecretKit.LiveProvisioner.dll \
    bootstrap-local --origin http://127.0.0.1:18080 --owner "$OWNER" \
    --email sdk-bootstrap@example.invalid --organization SecretKitLocal
unset BOOTSTRAP_PASSWORD
```

The server bootstrap creates the initial organization and credential. The host
then uses SDK management operations to create automation Universal Auth and
exclusively creates `.env` with owner-read/write permissions. It refuses to
overwrite existing configuration. Bootstrap is a one-time mutation: if the
response or local write fails, inspect the owned instance before retrying.
Do not replay signup against a partly initialized server.

Reconcile the selected local fixtures, then run the source-built identity
scenario:

```bash
dotnet tools/SecretKit.LiveProvisioner/bin/Release/net10.0/SecretKit.LiveProvisioner.dll --mode local provision
bash eng/live-infisical/live.sh local owned-sandbox
```

`owned-sandbox` selects `IdentitySetupTests` with a positive discovery floor.
It needs the real pod, organization and setup identity; it is not an offline
test or a substitute for installed-package qualification.

## How to use an authorized remote deployment

For a clone without `.env`, prepare private configuration before selecting
remote mode. If local bootstrap already created `.env`, preserve it and add
the remote keys privately instead of replacing the file:

```bash
umask 077
(set -o noclobber; < .env.example > .env)
chmod 600 .env
```

Edit `.env` privately. Set `INFISICAL_MODE=remote`, replace the remote origin,
organization and automation client credentials, and remove unused synthetic
local values. Remote origins require HTTPS without user information, path,
query or fragment. Supply an explicitly authorized machine identity with the
administrative permissions needed to reconcile these fixtures. The tool
cannot grant itself provider authority.

```bash
dotnet tools/SecretKit.LiveProvisioner/bin/Release/net10.0/SecretKit.LiveProvisioner.dll --mode remote status
dotnet tools/SecretKit.LiveProvisioner/bin/Release/net10.0/SecretKit.LiveProvisioner.dll --mode remote provision
```

Provisioning reuses explicitly enrolled fixture identities and projects, aligns
their selected memberships, removes stale optional narrative values,
and seeds distinct fresh A/B canaries plus an import fixture. It requires
complete inventories and fails on ambiguous resources. An existing same-name
resource is a collision until an authorized operator enrolls its immutable ID
in the corresponding `.env` slot, together with the mode's
`ENROLLMENT_ORIGIN` and `ENROLLMENT_ORGANIZATION_ID` fields matching the
selected target. Use the canonical origin with its trailing slash.
Name matches never authorize changing an
existing identity's organization role or authentication configuration.
Confirmed creations checkpoint their IDs into private configuration before
continuing. A failed or uncertain create/checkpoint requires operator review;
the next run does not adopt a resource by name.
Repeating `provision`
does not duplicate the selected resources; it does reset their synthetic values.
`reset` performs the same reconciliation.

Provider failures remain failures. Health does not prove an organization plan
or edition, and status reports entitlement as unverified. HTTP 400/403 and SDK
outcomes retain material-free classifications without copying provider bodies.

## How to run installed and native scenarios

Prepare the exact candidate required by the existing
[package qualification guide](../public/local-packages.md). The runner's
`PackageCandidate` path uses the seven-package family; the separate
four-package local profile remains a different qualification contract.
Pass the directory containing those original archives:

```bash
bash eng/live-infisical/live.sh remote installed-narrative --candidate "$CANDIDATE"
```

The host restores and builds an isolated package-only consumer, verifies its
restored archives, reconciles fixtures, and injects selected admin, runtime and
denied tokens. Success requires both existing markers:

```text
INSTALLED_NATIVE_READ_WRITE_INVENTORY_AND_IDENTITIES_PASSED
INSTALLED_BOOTSTRAP_CONFIGURATION_AND_ASSESSMENT_PASSED
```

Native conformance additionally needs an actual
[`NativeHostInputs`](../../tests/fixtures/SecretKit.TestHarness/NativeConsumerLauncher.cs)
request and a private JSON settings template containing real `families`
configuration for the selected operations. The template's coordinates must
match the selected fixture identities and projects. The basic A/B/import
reconciliation does not create every database, issuer, gateway or licensed
feature required by arbitrary native families.

```bash
chmod 600 "$SETTINGS_TEMPLATE"
bash eng/live-infisical/live.sh remote native-conformance \
  --candidate "$CANDIDATE" --request "$REQUEST" --settings-template "$SETTINGS_TEMPLATE"
```

The runner validates the request/candidate before provisioning, replaces the
template's origin and five role-token fields with fresh selections, and passes
private temporary settings to the existing native launcher. A naming prefix
is never proof of principal binding, native effects or release qualification.

For the local source-built baseline:

```bash
bash eng/live-infisical/live.sh local baseline
```

The baseline's own identity-separation warning remains part of its evidence.
`baseline` and `owned-sandbox` require local mode. The wrapper builds the host,
checks readiness, and delegates a single reconciliation to the runner.

## Reference: configuration and custody

The complete key schema is [`.env.example`](../../.env.example).
`INFISICAL_MODE` selects `local` or `remote`; `--mode` explicitly overrides that
selection. Only the selected mode's origin, organization, automation credentials
and fixture enrollment IDs are loaded. Local mode also requires the exact pod
owner. Duplicate or malformed assignments are rejected. Values are literal;
shell expansion, `export`, quoted shell syntax and sourcing are unsupported.

The common clone's `.env` also serves linked worktrees. Git common-directory
discovery resolves that path; do not copy secrets into a worktree or symlink
`.env`. Tracked configuration and linked paths are rejected. Restrict `.env`
to `0600` and do not stage it. The release source snapshot excludes root
`.env`, `.env.local` and `.env.*.local`, while `.env.example` and nested source
files remain captured. Exclusion does not make a tracked secret safe.

Enrollment updates preserve the other mode, compare the original configuration
before atomic replacement, and serialize cooperating commands with an ignored
`artifacts/live/.enrollment.lock`. Do not edit `.env` during a provisioning run.
If origin or organization changes, clear the old enrollment IDs and scope
fields and explicitly enroll the new target's resources.

Runner children receive selected inputs after their environment is cleared
and only required platform/runtime variables are restored. Private temporary settings under
`artifacts/live/` use exclusive `0600` creation and are deleted in `finally`,
including failed or canceled child runs. Forced host termination cannot execute
`finally`; inspect retained private artifacts before sharing or archiving them.
Logs retain only fixed public result markers and exit classifications; arbitrary
stdout and stderr are withheld. Child failures require private inspection of the
selected environment, not enabling credential-bearing diagnostic capture.

## How to inspect and clean fixtures

Cleanup previews by default. It discovers `sdk-live-*` and
`sdk-conformance-*` candidates in the configured organization. A prefix is not
ownership evidence. Use an exact slug to narrow the preview; deletion requires
an explicitly selected immutable project ID. Names outside those prefixes are
refused even with an ID.

```bash
dotnet tools/SecretKit.LiveProvisioner/bin/Release/net10.0/SecretKit.LiveProvisioner.dll --mode local clean
dotnet tools/SecretKit.LiveProvisioner/bin/Release/net10.0/SecretKit.LiveProvisioner.dll \
  --mode local clean --project-id "$PROJECT_ID" --apply
```

`--apply` is destructive and must have the operator's actual authorization.
Review the configured organization and independently verify the intended ID
first. Enrolling a fixture for reconciliation does not authorize deleting it.
Fixture
cleanup removes projects, not the whole organization or unrelated identities.
For container lifecycle and explicit sandbox removal, use the
[sandbox reference](../../eng/live-infisical/README.md).

## Migration and evidence boundaries

When moving from `~/.local/state/secretkit-live/automation.json`, privately
transfer only the selected endpoint, organization, optional project IDs and
automation Universal Auth credentials into the matching `.env` keys. Do not
copy cached `settings-*.json` bearer tokens. Keep the old files until both the
authorized remote narrative and a fresh local identity run pass. Removing the
old directory is a separate destructive action; never retire it from an
offline result alone.

| Evidence | What it establishes |
| --- | --- |
| Offline tests | Controlled configuration, reconciliation, custody and process behavior |
| Local Podman | Observations against the selected pinned local deployment |
| Remote playground | Observations against the explicitly authorized remote identity, policy and edition |
| Release qualification | Exact archive, source, platform and native gates owned by existing release tooling |

Community Edition results do not satisfy missing Enterprise entitlements.
The [qualification limits](../public/qualification-limitations.md) and
[dated evidence ledger](compatibility/provider-engineering-2026-11.md) record the
known gaps, including inaccessible licensed-template cleanup witnesses.
The later local and remote installed narratives passed in their recorded
scope; neither run establishes complete native family or principal/policy proof.
Dynamic SQL lifecycle, rotation, replication, other issuers and downstream
effects retain their separate requirements and failures. No command here
authorizes publication or establishes complete provider support.
