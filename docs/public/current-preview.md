# Current local preview

> **Audience:** Application developers and support evaluators
> **Status:** Implemented development subsets; unpublished, not ready for production
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25 (local source/documentation review, not a test run)
> **Source anchors:** [Package inputs](../../Directory.Build.props),
> [local profile](../internal/local/infisical-runtime.json),
> [project map](../../PROJECTS.md), [support reference](provider-support.md)

The separate [runtime-hardening evidence profile](../internal/compatibility/runtime-hardening-profile.md)
covers explicit safe/host-controlled transport, acquired generations, renewal
and bounded shutdown from original packages. Its controlled installed results
are distinct from native deployment observations and do not alter the existing
17-case functional or 21-case native denominators.

SecretKit implements .NET 10 secret reads, metadata inventory, selected native
operations and optional runtime composition for Infisical and Azure Key Vault.
**In development. Not ready for production. APIs may change without backward
compatibility.** Package presence does not mean complete provider support.

## Start with your task

| Task | Guide |
| --- | --- |
| Choose packages and understand support limits | [Provider support](provider-support.md), [provider guide index](providers/README.md) |
| Install exact local package originals | [Local packages](local-packages.md), [getting started](getting-started.md) |
| Read values and own their lifetime | [Core API](core-api.md), [Infisical](providers/infisical.md), [Azure Key Vault](providers/azure-key-vault.md) |
| Collect required settings and replace local generations | [Configuration and runtime](configuration-and-runtime.md) |
| Compose explicit login, renewal and shutdown | [Authentication and hosting](authentication-and-hosting.md) |
| Perform separately authorized administrative work | [Management](providers/management.md) |
| Learn installed console, worker and web workflows | [Demos and recovery](demos-and-recovery.md) |
| Diagnose outcomes or assess adoption | [Troubleshooting](troubleshooting.md), [adoption and value](adoption-and-value.md) |

## Candidate and version authority

The tracked [local profile](../internal/local/infisical-runtime.json) selects
`0.1.0-local.20261024.1`, four packages (Core, Infisical, Configuration and Hosting),
eight native members and the S01-S16 scenario denominator. Configuration and
Hosting are independently optional for applications. This profile is distinct
from the seven-package family and the default `0.1.0-preview.1` version in
[Directory.Build.props](../../Directory.Build.props).

Use the [local preparation/check recipe](local-packages.md) to bind exact source,
profile, record bytes and original archive hashes. A version string, successful
pack or relocatable feed alone does not establish an installed or native-qualified
candidate. Local preparation grants no listed or unlisted publication authority.
The current workstream prioritizes Infisical local evaluation; Azure and retained
management remain supported only to their documented implemented/evidence scope.

## Implemented capabilities

- Authority-bound common reads return independent disposable material and bounded
  outcomes. Inventory returns metadata, not proof that an intended identity can
  acquire values. Coordinates, origins, identities and cancellation are explicit.
- Infisical adds qualified raw, non-imported revisions, selected writes, explicit
  Universal/proof authentication, token renewal/revocation, organization/import,
  dynamic-secret and rotation subsets. See the [family map](provider-support.md).
- Azure adds selected/versioned reads, SetSecret, metadata, deleted-secret,
  backup/restore and explicit lifecycle checks. Native validity inspection and
  ordinary consumption have different contracts.
- Optional Configuration prepares complete required local generations and
  deliberate managed-string export. Optional Hosting starts token maintenance
  only through host startup and retains explicit recovery after uncertainty.
- Separate management packages expose typed administration under selected
  administrative credentials; visibility and configuration do not prove runtime
  delivery or effective permissions.

The [runtime contracts](../internal/RUNTIME_CONTRACTS.md) retain ownership,
bounded transport, receipts and cancellation rules. There is no fallback
principal, hidden material cache, automatic mutation replay, remote transaction
or application activation engine. Revealing/exporting material creates ordinary
managed strings that disposal cannot erase process-wide.

## Evidence and current limits

Source and authored offline tests establish implementation scope; dated run
reports establish only their exact inputs and environment. No build, test,
restore or provider call was run for this documentation review. Historical
counts are retained in the [development checkpoints](../internal/compatibility/development-checkpoints.md),
not presented as a current passing total.

The owned Infisical v0.166.3 narrative on 2026-10-10 covered selected installed
reads, denial/isolation, bootstrap/export and generation workflows. It does not
qualify refreshed local archives or every native family. The
[local-profile ledger](../internal/compatibility/infisical-local-profile.md)
separates offline proof protocols, 17-case development-functional acceptance and
full 21-case native qualification. Supplied-token deployment/principal/policy
bindings remain unavailable; causal issuance is a separate proof path, not
introspection of arbitrary tokens. S15 cannot pass from declaration-only input.

Azure live effects, complete Infisical permissions/editions/issuers, SQL backend
effects, import replication and gateway/proxy deployment remain separate gates.
Linux development evidence does not establish the Ubuntu/Windows same-run
release matrix, macOS/ARM, NativeAOT or trimming. The
[demos guide](demos-and-recovery.md) scopes controlled measurements and app evidence.

The broad third-party connection/sync catalog is [removed](connector-scope-decision.md);
native SQL rotation and existing gateway/proxy administration remain. Database
drivers do not ship in SecretKit; [database credentials](database-credentials.md)
stay opaque in Core. Frozen provider research is not current admission.
