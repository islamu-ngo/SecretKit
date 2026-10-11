# Exact-artifact publication protocol

Status: local infrastructure, not an authorized or completed release.
Execution owner: the appointed SecretKit release maintainer.

Scope note (2026-10-11): the
[accepted catalog-removal decision](../../public/connector-scope-decision.md)
supersedes the earlier comprehensive Infisical admission goal. The frozen
`infisical-operations.json` is `ContractResearchOnly`, not current product
admission. The all-registry completion gate described below belongs to the
earlier release infrastructure contract; it does not require restoring removed
connector APIs or establish readiness for the smaller product. Release tooling/
scope-metadata reconciliation is separate work. Local removal checks passed; no publication is authorized.

The BCL-only .NET 10 tool in `tools/SecretKit.Release` publishes only the seven
exact IDs below, at one approved normalized version. It does not build packages,
infer credentials, register publishers, claim live conformance, overwrite a
version, or retry a mutation. The new `publish.yml` is manual and independent of
the existing solution graph. It does not supply the still-required upstream
verification workflow or its release evidence.

## Family and evidence contract

- `SecretKit.Core`
- `SecretKit.Infisical`
- `SecretKit.AzureKeyVault`
- `SecretKit.Extensions.Configuration`
- `SecretKit.Extensions.Hosting`
- `SecretKit.Infisical.Management`
- `SecretKit.AzureKeyVault.Management`

A successful trusted `verify.yml` push run on protected `main` must produce one
immutable GitHub artifact containing the seven unsigned `.nupkg` files and:

| File | Required content |
| --- | --- |
| `manifest.json` | Exact version, source commit/repository, producer run ID, publisher/owner, `SecretKit.` prefix, `release` environment, notices hash, scope file/hash, seven package IDs/filenames/SHA-256 hashes, all nine gate files/hashes |
| The scope file | `version`, `sourceCommit`, `packageIds`, nonempty `platforms`, `nativeOperations`, and `registries` |
| Each gate file | `kind`, `status: passed`, matching `version`, `sourceCommit`, `scopeSha256`, exact `packageIds`, exact `checks`, and a `record` with its filename and SHA-256 |
| Each referenced record | The real reviewed evidence bytes, not a fabricated success document |
| Both provider registries | `infisical-operations.json` and `azure-key-vault-operations.json`, hashed in scope; every admitted row implemented and live-verified |

All referenced filenames are flat, relative ASCII filenames. Symlinks, traversal,
duplicate JSON properties, unknown typed fields, wrong hashes, missing gates,
extra packages, signed local packages and identity/repository mismatches fail.
The artifact manifest and evidence files are not an authorization mechanism.
The artifact ID and GitHub archive digest live in the independent protected
approval, not inside the archive's manifest: GitHub assigns them after upload.
The producer run ID is known before upload. This avoids a circular attempt to
embed an immutable artifact's own post-upload identity or digest in its bytes.

Each `nativeOperations` row has `provider` (`Infisical` or `AzureKeyVault`),
`operation` (the registry ID), `scope` (a public material-free matrix label),
and `depth: complete`. Its check key is `provider/operation/scope/depth`.
Multiple tested scopes may cover one native operation. The distinct operation
IDs must exactly cover all admitted rows in both registries. An Azure row with
`fullOperationImplemented` must also have that field true. The workflow fetches
the registries independently at the approved source commit and replaces the
artifact copies before checking their hashes, preventing a truncated artifact
inventory from defining its own completed scope.

Gate `checks` have these machine values:

| Gate kind | Exact required checks |
| --- | --- |
| `native-operations` | All scope operation keys, including declared depth |
| `live-conformance` | The same complete set; offline fixtures are not evidence |
| `compatibility-install` | Every declared platform label |
| `provenance` | The source commit and each of the seven original package hashes |
| `notices` | The notices SHA-256, also checked against every package's embedded notices |
| `namespace-rights` | All seven exact IDs plus `SecretKit.` |
| `publisher-rights` | `publisher:<username>` and `owner:<owner>` |
| `oidc-registration` | `islamu-ngo/SecretKit/publish.yml/release` and `https://www.nuget.org` |
| `protected-environment` | `release`, `required-reviewers`, `prevent-self-review`, `main-only` |

Every gate also binds the same source, version, scope and family. Hashes prove
that reviewed evidence did not change, not that its assertions are true. The
release/security/provider owners must review the underlying records. The JSON
schema is descriptive and nongranting; semantic cross-file checks belong to the
tool. `manifest.example.json` is deliberately incomplete and rejected. It has no
real package hashes, rights approvals, live evidence or registry completion.

## Protected workflow and external setup

Before execution, maintainers must establish:

1. Protected `main`, reviewed workflow ownership and trusted hosted runners.
2. A GitHub `release` environment with required reviewers, prevention of
   self-review, and deployment restricted to `main`.
3. NuGet.org publisher/organization membership, rights for every exact package
   ID and the `SecretKit.` prefix, and an active trusted-publishing registration
   for this repository, `publish.yml`, and environment `release`.
4. A current independently approved NuGet.org repository certificate fingerprint
   and a functioning .NET SDK signing/timestamp trust store.
5. Real complete operation, live-provider, platform/install, provenance,
   dependency/license/notices and authority evidence for the exact source.

The protected environment variables below must be set by those reviewers.
Empty values fail closed. Values must not be taken from an untrusted artifact
and automatically promoted to approval.

```text
SECRETKIT_APPROVED_MANIFEST_SHA256
SECRETKIT_APPROVED_SOURCE_COMMIT
SECRETKIT_APPROVED_VERSION
SECRETKIT_APPROVED_SOURCE_RUN_ID
SECRETKIT_APPROVED_ARTIFACT_ID
SECRETKIT_APPROVED_ARTIFACT_DIGEST
SECRETKIT_APPROVED_SCOPE_SHA256
SECRETKIT_NUGET_USER
SECRETKIT_NUGET_OWNER
SECRETKIT_NUGET_REPOSITORY_CERT_SHA256
SECRETKIT_APPROVED_JOURNAL_HEAD
SECRETKIT_ENVIRONMENT_PROTECTED
```

Hashes use lowercase SHA-256 hex; source commits use lowercase 40-character
Git SHA. The artifact digest excludes the API's `sha256:` prefix. Journal head
is `new` only for a never-dispatched family; otherwise it is the SHA-256 of the
latest approved checkpoint JSON bytes. `SECRETKIT_ENVIRONMENT_PROTECTED=true`
records a maintainer's configuration check; an environment variable itself
cannot enforce or prove GitHub environment protection.

Dispatch inputs name the exact producer run, immutable artifact ID, reviewed
manifest hash, explicit `execute` authorization (default false), and, on resume,
the previous journal run/artifact IDs. The credential-free `verify` job performs
locked restore, scoped build/tests/format and workflow checks for the release
runner. Its binary archive is transferred by immutable artifact ID and separately
checked against the producing job's SHA-256 output before execution.

Only the `publish` job has `id-token: write`; it requires explicit execute,
the canonical repository, protected `main`, and the protected environment. It
downloads exact IDs, checks GitHub artifact/run provenance and source registries,
verifies package/evidence bytes, and reconciles existing native feed packages
before `NuGet/login` exchanges OIDC for its short-lived key. No package or runner
is rebuilt after verification. Fork and pull-request execution cannot reach
publication. Inspection with `execute=false` runs the local infrastructure
checks only; it does not log in or publish.

The workflow is JSON, a YAML 1.2 subset, to allow BCL parsing of actual workflow
values without adding a YAML library. Tests mutate permissions, triggers,
environment, action pins, checkout credential persistence, checkpoint ordering
and rebuild commands. These checks do not emulate GitHub's scheduler, environment
configuration or OIDC service.

## Publication, checkpoints and uncertainty

The material-free journal is an append-only chain of `000001.json`, etc. Each
checkpoint binds its sequence, previous checkpoint hash, exact manifest hash and
per-package ID, unsigned archive hash, state, availability and dispatch attempt.
Writes use create-new plus disk flush; concurrent local writers are excluded.
Existing snapshots are never overwritten. A corrupt or incomplete local journal
fails closed rather than being repaired by discarding uncertain state.

| State | Meaning and permitted next action |
| --- | --- |
| `pending` | No dispatch recorded; native read reconciliation first, then explicitly authorized preparation |
| `unknown` | Write-ahead dispatch intent or uncertain result; native read reconciliation only on a later attempt |
| `accepted`, unavailable | Native 201/202 acknowledgment, not yet verified available; never republish |
| `accepted`, available | Downloaded, signer-verified, reconstructed original hash matches; no mutation |

For each pending package, preparation first writes `unknown` with the current
GitHub run/attempt. The workflow uploads that complete checkpoint chain as a new
immutable artifact **before** dispatch. Upload failure prevents the request.
The dispatch command requires `--execute`, the execution flag, protected runtime
context, the uploaded checkpoint's artifact ID and the exact head hash. It also
creates a local create-new dispatch marker; the same run/attempt cannot replay it.
GitHub reruns have a different attempt and cannot reuse an unknown checkpoint.

The tool checks the native flat-container endpoint again, verifies any existing
package, and only if it receives a native 404 issues one bounded native multipart
PUT to `https://www.nuget.org/api/v2/package`. Only 201/202 mean acknowledged
acceptance. A conflict, timeout, cancellation, transport failure or lost
acknowledgment remains unknown. There is no retry, `--skip-duplicate`, overwrite,
unlist, rollback, delete or token-refresh mutation path. The response body and
API key are not logged or journaled.
The request uses the required third-party-client header
`X-NuGet-Protocol-Version: 4.1.0`, not the official-client-only version header.

Result checkpoints are uploaded after each attempted package and at final
handoff, including failure paths. If the runner is killed or a result upload
fails, the already-uploaded unknown checkpoint remains the recovery anchor.
Successful publication of some packages does not imply an atomic family release.
Final reconciliation returns exit 2 until all seven are verified available;
indexing delay is not treated as failure permission to republish.

Resume requires a reviewer to select the latest preserved checkpoint artifact
and approve its exact head hash. Reconciliation downloads existing versions,
verifies signatures and compares the reconstructed original hashes. A mismatch
blocks the family; an unresolved unknown is never converted to pending after
a 404. Accepted-but-not-visible packages also remain non-replayable. Only still
pending members may subsequently be dispatched. If checkpoints expire (the
workflow retains them for 90 days), preserve a trusted external copy before
expiration. Missing history is a manual recovery blocker, not permission to
set the head back to `new`.

## Exact original archive reconstruction

NuGet.org repository-signs uploaded archives, so hashing the downloaded signed
file cannot be compared directly with the approved unsigned archive hash.
`PackageArchive` preserves byte identity rather than repacking or comparing
canonicalized entry payloads:

1. Validate EOCD, counts, offsets and lengths; cross-check every central/local
   header, unique name, regular-file type, method, bounded expansion and CRC.
2. Require a contiguous ZIP32 layout without orphan/gap/overlapping data.
3. Exclude exactly the `.signature.p7s` local record/data and directory record.
4. Subtract its physical local-record length from offsets of later local records.
5. Restore EOCD entry counts, central-directory size and start offset.
6. Preserve all other archive bytes and ordering and compare their SHA-256 with
   the originally approved archive.

The supported profile is single-disk ZIP32, contiguous local records, ASCII
regular-file names, stored/deflate methods, and no ZIP extra fields, comments,
data descriptors, encrypted entries or directory entries. ZIP64, traversal,
case-colliding/duplicate names, signature aliases and unsupported layouts fail
closed. This deliberately narrower profile does not claim to accept all valid
NuGet ZIP variants. A future signing/layout change requires explicit support and
new independent fixtures, not a fallback to payload equivalence.

The independent NuGet-signed Microsoft.NETCore.Platforms 1.1.0 fixture checks the
reconstructed bytes against the original SHA-256 embedded in its CMS document.
Its archive hash, retrieval URL, license retention and independent OpenSSL oracle
are recorded in `tests/SecretKit.Release.Tests/Fixtures/PROVENANCE.md`.
Synthetic middle-signature fixtures separately test offset restoration.

Reconstruction is **not signature authentication**. For every existing feed
package the production tool additionally runs bounded `dotnet nuget verify
--all --certificate-fingerprint ... --configfile ...`, with an isolated NuGet.org
repository trust definition, approved certificate and owner. No publishing key
or GitHub token is inherited by that process. Its output is drained, not logged.
Its temporary SDK selection pins 10.0.302 without roll-forward, independently of
other SDKs installed on the runner.
Actual cryptography, timestamp/chain/revocation behavior and trust-store support
are delegated to the installed official SDK. NuGet's trust/revocation policy
limitations remain; archive/specification correctness cannot replace trusted
signer configuration or proof of publisher namespace rights.

## Local verification and present limits

Run from the SecretKit repository:

```sh
dotnet restore tests/SecretKit.Release.Tests/SecretKit.Release.Tests.csproj --locked-mode
dotnet build tests/SecretKit.Release.Tests/SecretKit.Release.Tests.csproj --configuration Release --no-restore
dotnet tests/SecretKit.Release.Tests/bin/Release/net10.0/SecretKit.Release.Tests.dll --minimum-expected-tests 1
dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll workflow-check .github/workflows/publish.yml
dotnet format tools/SecretKit.Release/SecretKit.Release.csproj --verify-no-changes --no-restore --verbosity quiet
dotnet format tests/SecretKit.Release.Tests/SecretKit.Release.Tests.csproj --verify-no-changes --no-restore --verbosity quiet
```

`verify` checks local bundle bytes and captured GitHub metadata without contacting
NuGet. `initialize` and `reconcile` only read the native feed. `prepare` writes
local uncertainty, never publishes. Only `dispatch ... --execute` can PUT.
The command-line boundary emits fixed error codes rather than exception details.

This implementation does not establish a completed SDK, real provider coverage,
NuGet registration, current prefix/publisher rights, a protected GitHub
environment, an actual producer artifact or an executed GitHub/OIDC/NuGet flow.
Those gates remain missing and no release manifest attests otherwise. Source
registries currently record incomplete implementation/live coverage; they cannot
pass this publication gate. Do not replace them with synthetic test evidence.

## Official protocol and action provenance

Functional requirements were independently implemented from official public
specifications, not copied vendor source. Sources checked on 2026-10-09:

- [Signed packages](https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference):
  NuGet.org repository signing and separate signature/trust requirements.
- [Package signatures technical specification](https://github.com/NuGet/Home/wiki/Package-Signatures-Technical-Details):
  original unsigned byte hash, signature exclusion, offset/EOCD restoration.
- [Native package publication](https://learn.microsoft.com/en-us/nuget/api/package-publish-resource):
  one multipart PUT, API-key header, 201/202 acceptance and 409 conflict.
- [Trusted publishing](https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing):
  official login/OIDC exchange, environment/owner policy and one-hour key.
- [Native verification](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-nuget-verify)
  and [trusted signers](https://learn.microsoft.com/en-us/nuget/reference/nuget-config-file):
  certificate fingerprint, repository owner and trust-store configuration.

Action pins were resolved from their official Git remotes using `git ls-remote`.
The annotated `NuGet/login` v1 tag was peeled to its actual commit; its public
action metadata confirms the `user` input and `NUGET_API_KEY` output. Pins are
fixed review inputs, not an automatic moving-tag update policy.

| Action | Observed tag | Pinned commit |
| --- | --- | --- |
| actions/checkout | v4 | `11d5960a326750d5838078e36cf38b85af677262` |
| actions/setup-dotnet | v4 | `67a3573c9a986a3f9c594539f4ab511d57bb3ce9` |
| actions/download-artifact | v4 | `d3f86a106a0bac45b974a628896c90dbdf5c8093` |
| actions/upload-artifact | v4 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| NuGet/login | v1, peeled | `8d196754b4036150537f80ac539e15c2f1028841` |
