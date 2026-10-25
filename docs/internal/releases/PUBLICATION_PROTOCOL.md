# Exact-artifact publication protocol

Status: local infrastructure, not an authorized or completed release.
Execution owner: the appointed SecretKit release maintainer.

The accepted 2026-10-23
[Infisical-first local-readiness direction](../INFISICAL_LOCAL_READINESS.md)
does not change this public protocol. A planned four-package local qualification
profile must have a distinct record kind and cannot create a `VerifiedRelease`,
approval, journal or publication authority. Public NuGet publication and
completion of this protocol are outside that workstream. Existing seven-package
and complete-live evidence requirements below remain intact.

Scope note (2026-10-12): the
[accepted catalog-removal decision](../../public/connector-scope-decision.md)
supersedes the earlier comprehensive Infisical admission goal. The frozen
`infisical-operations.json` is `ContractResearchOnly`, not current product
admission. Semantic release schema **2** uses only the source-owned current
inventories in `docs/internal/releases/admission/{infisical,azure-key-vault}.json`.
Schema 1 and hash-only records are rejected. Current-admission schema 1 is a
different document contract, not legacy release schema 1. No publication is
authorized.

The BCL-only .NET 10 tool in `tools/SecretKit.Release` publishes only the seven
exact IDs below, at one approved normalized version. It does not build packages,
infer credentials, register publishers, claim live conformance, overwrite a
version, or retry a mutation. `publish.yml` is manual and independent of ordinary
verification. Routine `verify.yml` output is offline diagnosis, not release
evidence; the qualifying protected candidate producer remains a separate gate.

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
| The scope file | `version`, `sourceCommit`, `packageIds`, exact `platforms`, `nativeOperations`, `inventories`, `policy: complete-live`, and `providerScopes` |
| Each gate file | `kind`, `status: passed`, matching `version`, `sourceCommit`, `scopeSha256`, exact `packageIds`, exact `checks`, and a `record` with its filename and SHA-256 |
| Each referenced record | `SemanticGateRecord`: `schemaVersion: 2`, `reports`, and nullable `attestation`; automated facts and accountable rights attestations are distinct |
| Both current inventories | Flat bundle names `infisical.json` and `azure-key-vault.json`, hashed in scope; every retained operation/variant and required case is mandatory |

All referenced filenames are flat, relative ASCII filenames. Symlinks, traversal,
duplicate JSON properties, unknown typed fields, wrong hashes, missing gates,
extra packages, signed local packages and identity/repository mismatches fail.
The artifact manifest and evidence files are not an authorization mechanism.
The artifact ID and GitHub archive digest live in the independent protected
approval, not inside the archive's manifest: GitHub assigns them after upload.
The producer run ID is known before upload. This avoids a circular attempt to
embed an immutable artifact's own post-upload identity or digest in its bytes.

Each `nativeOperations` row has `provider` (`Infisical` or `AzureKeyVault`),
`operation` (current admission ID), `variant`, `scope` (an opaque public label),
and `depth: complete`. Its check key is
`provider/operation/Uri.EscapeDataString(variant)/scope/depth`. Every declared
provider scope covers **every** admitted operation and variant, on both
`linux-x64-net10.0` and `windows-x64-net10.0`. No subset selected from passing
tests is admitted. Inventory `contract-gap` rows block release.

`providerScopes` bind `label`, `provider`, `deployment`, `apiVersion`,
`runtimeIdentity`, `observerIdentity`, `setupIdentity`, `deniedIdentity`, and
`administrativeIdentity`. All five identity labels are required and pairwise
distinct within each scope. No role is inferred, defaulted or aliased.
These are reviewed opaque
labels, never secret values, real hostnames, vault/project paths, credentials or
raw exceptions. All reports bind exactly the same labels, inventory hashes,
source commit, version, run/attempt, scope hash and original seven package hashes.
Source/member inventory coverage is a separate prerequisite owned by admission
tests; the release verifier does not inspect provider assemblies.

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

### Independent evidence boundary

`Manifest.Verify(bundle, approval, independent)` requires an
`IndependentEvidence` loaded from a **different directory**; there is no
bundle-only overload or fallback. `Approval.EvidenceSha256` binds the exact
external `evidence-index.json` bytes. An index bundled alongside assertions is
not authority. The trusted collector must fetch all external data independently.
The CLI uses `SECRETKIT_EVIDENCE_DIRECTORY`. The publisher constructs it from
protected `SECRETKIT_APPROVED_EVIDENCE_INDEX` and checks
`SECRETKIT_APPROVED_EVIDENCE_SHA256` before any report selection.

The index (`EvidenceIndex`, schema 1, kind `independent-release-evidence`) binds
repository, source, version, original run ID/attempt, review time, two inventory
digests, exactly eight `ReportOrigin` records, and four accountable attestations.
Each origin binds gate, platform, exact job ID, artifact ID/archive digest, raw
report filename/hash, environment and a reviewed environment evidence locator.
Final approval also retains all existing manifest/scope/source/family/artifact
and publisher/owner bindings.

The external directory must contain:

| File | Independent source |
| --- | --- |
| `evidence-index.json` | Protected independent review, never promoted automatically from the bundle |
| `run-metadata.json` | Exact original GitHub run-attempt API, including `run_attempt` and `created_at`; never the latest rerun |
| `artifact-metadata.json` | Final candidate artifact API, mandatory for post-run verification only |
| `infisical.json`, `azure-key-vault.json` | Current admission paths fetched at the exact approved source SHA |
| `THIRD-PARTY-NOTICES.md` | Repository root file fetched at that same SHA |
| `<jobId>-job.json` | Exact GitHub job API record with source/run/attempt/name/status/timestamps |
| `<artifactId>-artifact.json` | Exact GitHub report artifact API record with digest/run/source/name/creation time and unexpired status |
| `<artifactId>-report.json` | Original material-free report bytes fetched from that immutable report artifact, not a bundle copy |

There are two reports each for `native-operations`, `live-conformance`, and
`compatibility-install` (one per required platform), and one each for
`provenance` and `notices` (`platform: none`). Source-owned job names must be
`<kind>-<platform>`; each uploads an immutable artifact named
`secretkit-report-<jobId>` containing only `report.json`. The collector downloads
by exact ID and uses `extract-report <archive-directory> <artifact-id>
<archive-sha256> <output-directory>`. This command verifies the ZIP digest,
permits one entry only, bounds archive/report bytes at 8 MiB/16 MiB, and
create-new writes `<artifactId>-report.json`; it never extracts archive paths.

The current native case matrix exceeds 4 MiB for one provider. Individual
machine reports therefore have a 16 MiB limit and the combined two-platform
semantic record has a 32 MiB limit. Other JSON retains the 4 MiB limit.
Package and ZIP expansion limits are unchanged; these limits do not permit
dropping cases from the admission denominator.

GitHub's artifact API exposes run origin, **not job origin or protected
environment configuration**. An independently reviewed index must establish
the artifact/job/environment mapping from the trusted producer's upload and
deployment evidence. The verifier cross-checks that mapping against both APIs,
fixed job/artifact names, source/attempt and time ordering. Merely putting a
job ID in a bundled report does not establish this mapping.

### Observation and attestation semantics

The native producer host reads `SECRETKIT_NATIVE_INPUTS` as the original
`candidate-inputs.json`, verifies its scope digest, and binds the gate kind,
platform and actual report job ID from the producer environment. It builds the
isolated installed consumer before reading `SECRETKIT_NATIVE_SETTINGS`. That
protected secret is a JSON object with explicit `Infisical` and `AzureKeyVault`
settings, each containing its own five role credentials and typed family
inputs. Only the selected provider settings enter the child over redirected
stdin; build and child process environments do not inherit the protected secret.

For a local development observation, explicitly supply
`SECRETKIT_NATIVE_REQUEST` as an absolute path to a `NativeHostInputs` file and
`SECRETKIT_NATIVE_SETTINGS` as an absolute path to that provider's private
settings file. Development requests have zero run, attempt and job IDs and may
filter operations; their reports cannot qualify as release evidence. Both modes
create the material-free report at `SECRETKIT_NATIVE_REPORT`.

The Azure runtime family inputs use `C08-AR-AzureKeyVaultClient` and
`C08-AR-AzureNativeLifecycle`. Each requires an owned `namespace` (3-40 ASCII
letters, digits or hyphens); inventory cases also require `inventory.maximumPages`
and `inventory.maximumItems`. Every scenario creates fresh names and independently
checks cleanup. Soft-deleted resources remain retained; cleanup does not purge.
Purge scenarios additionally require explicit `allowOwnedSecretPurge: true`.
Lifecycle status cases use a separate `statusNamespace`; their denied principal
must be permitted to start that lifecycle operation but denied to inspect its
status. Pending variants require an actual independently observed propagation
state, not a simulated response or a timed retry.

Backup/restore cases require `backupDestination`, a full Azure provider settings
object with a distinct vault and five explicitly selected destination credentials.
The destination must permit compatible native restoration and independent
all-version material/metadata reads. A backup acknowledgement alone cannot pass.
An interrupted acquisition without a caller-held backup remains unavailable.
These inputs enable local harness execution; neither configuration nor offline
tests certify tenant identity, principal separation or live provider effects.

The dynamic, periodic-session and rotation runtime families may select an
`observer` object at the family root, outside the per-case `scopes` map. It supplies
`endpoint` (an HTTPS base URI ending in `/`, without userinfo/query/fragment),
`token` (a dedicated private fixture-service credential), `identity` and explicit
`timeoutSeconds` (1-300). The installed consumer creates the same typed observer
clients as the native host. Protected backend credentials or issued session
tokens go only to this explicitly selected host-owned service; neither its
credentials nor bodies enter reports.

Fixture protocol version 1 uses POST requests with `schemaVersion: 1`, a fresh
`nonce` and method-specific fields. Responses contain the same schema/nonce,
`observerIdentity`, fresh `observedAt` and typed `facts`; duplicate fields, wrong
identity/nonce, oversized replies and non-success statuses fail unavailable.
Routes are `dynamic/measure`, `session/measure`, `session/expired`,
`rotation/measure`, `rotation/authenticate`, `rotation/arm`, `rotation/observe`
and `rotation/disarm`. Definitions and typed measurements are in
`InfisicalLifecycleObservers.cs` and the corresponding family effect files.
The service must measure actual credentials, permissions, expiration and native
events; acknowledgements or a `passed` flag are not measurements. Dynamic renewal
requires expiry extension over an independent pre-operation lease snapshot and
agreement between returned and independently observed expiry. A no-op or lifetime
ceiling that prevents distinguishing renewal remains unavailable. Rotation event
registration completes before triggering the SDK operation, and disposal checks
that its owned registration is removed.

Rotation facts require `previousActiveCredentialAuthentication`; the former
ambiguous `previousCredentialAuthentication` field is not an alias and cannot
qualify a measurement. For PostgreSQL, MySQL and MSSQL two-account rotations,
the first bound credential-change event must advance `passwordGeneration` by
exactly one and retain authentication of the immediately previous active pair.
A generation jump or premature revocation fails the witness. A0 → B1 retains
A0; only a later overwrite A2 rejects A0, while B1 remains valid. These are
different credential-history assertions. Offline tests characterize the
two-cycle store; they do not establish native overwritten-history certification.
Observed generations are nonnegative and scoped to the owned rotation.

Runtime manual/automatic rotation mutation-cancellation cases require a bound
server-completion witness before ownership. Without one, native execution reports
unavailable: a send-boundary cancellation plus an unchanged current snapshot
cannot exclude a later commit. Read-only cancellation and explicitly rejected
preconditions retain their separate contracts. Controlled offline transports
exercise deterministic pre-send cancellation without qualifying native effects.

SQL definition rename scenarios generate both owned names before dispatch. An
independent read requires the original name to be absent and the new name to
retain the same definition ID and requested TTL policy. Denial and pre-send
cancellation require the reverse state. After response loss, reconciliation
reads the new name without replaying the update. Cleanup inspects both names,
revokes their leases and deletes their definitions without forced record removal,
then independently checks absence and backend credential rejection.

Non-SQL `profile.<InfisicalDynamicProvider>` cases accept `profile: null` and a
`nonSqlProfile` object containing exactly one matching typed selection, such as
`ssh: { principals: ["owned-principal"] }`. Field names use the private input's
camel-case names; required fields and unknown fields are checked by strict
deserialization. `InfisicalDynamicProfileInputs.cs` defines all 27 selections
and their closed option models. The host constructs actual disposable SDK
profiles; it does not forward arbitrary JSON fields.

These cases execute create, update, policy update, inspect, list and delete
through the SDK, independently inspect definition metadata and reconcile owned
cleanup. They remain `observer-unavailable`: metadata cannot establish protected
input persistence or non-SQL backend effects. SQL-only material acquisition and
lease-dependent scenarios remain unavailable for these selections; the harness
does not invent a generic material API or externally prepared leases.

The six `AwsIam.<authentication>.<credentialKind>` variants additionally bind
`nonSqlProfile.awsIam.authentication` (`AccessKey`, `AssumeRole`, or `Irsa`) and
`credentialKind` (`IamUser` or `Temporary`) to the exact admitted row. Access-key
inputs require both keys and no role ARN; assume-role inputs require a role ARN
and null keys; IRSA requires null keys and no role ARN. The public SDK's actual
alternative constructors serialize the profile. No fallback authentication or
ambient cloud authority is inferred, and cloud effects remain unavailable.

Alternative factory variants use `alternativeProfile` instead of
`nonSqlProfile`, with exactly one matching selection from
`InfisicalDynamicAlternativeProfileInputs.cs`. These cover Elasticsearch API
keys, Kubernetes and LDAP static accounts, manual TOTP with the exact selected
algorithm, and OAuth or federated Tailscale authorities. Both envelopes supplied
together fail before fixture creation. The same SDK dispatch, independent
metadata, cancellation, response-loss and non-forced cleanup checks apply;
backend and protected-input effects still remain unavailable.

The 151 exact non-SQL constructor-option and legacy variants in
`InfisicalDynamicProfileVariants.cs` also use `nonSqlProfile`. Omitted options
are explicitly removed; `.value` requires the configured value; enum and boolean
cases select the corresponding public parameter. Mongo explicit null and omission
remain distinct. Selection snapshots copy mutable containers and reject wrong
or multiple profile selections before fixture creation. Independent definition
metadata still does not establish persistence of these protected options.
The Couchbase bucket aliases require the explicitly selected text or object
representation; the host does not convert one into the other.

The 59 nested-option and collection aliases in
`InfisicalDynamicNestedProfileOptions.cs` require an explicit `optionProvider`.
Alternative factories additionally require the exact `alternativeVariant` for
that provider. Shared option rows do not infer a provider or authority from
credentials. AWS session-policy aliases require explicit assume-role inputs.
Selection occurs before provisioning, preserves caller-owned inputs and uses
the public typed constructors. All 302 admitted create-definition variants now
have dispatch support; that is not protected-field or backend certification.

Imported inventory checks require unique source groups and secret coordinates,
and every source group must belong to the owned fixture. An unexpected successful
material read on a denial path is disposed before reporting the failed assertion.
Environment-only import updates provision the same fresh owned relative path in
two selected environments. Source and replacement must use the same project and
owned namespace, identical seed keys and distinct values for each key. The fixture
reuses its owned folder name, not an existing foreign path. Applied updates must
deliver the replacement values while retaining omitted source path and position;
denial and pre-dispatch cancellation retain the original source. Lost responses
are observed without replay. Both environment-scoped sources and the destination
are cleaned up. This closes the local source-fixture gap, not replication or
independent destination-approval certification.
Organization folder and tag inventory scenarios require complete, unique-ID
results containing the exact owned resource. A matching item inside a truncated
or duplicate inventory cannot qualify the scenario.

Project cleanup retains acknowledged IDs with owned slugs, including renamed
selectors. A cleanup lookup returning another ID fails before clearing protection
or deleting anything. Genuinely unacknowledged creations still use their fresh
owned selector for recovery. Project membership inventory requires unique IDs
and exactly one matching owned membership. Non-secret project-type list rows
remain unavailable until an owned matching-type witness can be provisioned.

Template configuration updates seed and independently instantiate a distinct
baseline policy before PATCH, then observe the changed policy through a fresh
project and runtime canaries. Denial and pre-dispatch cancellation must preserve
that baseline. Organization group ordering scenarios seed two owned groups with
distinct ASCII sort values and inspect their relative order through both selected
administrative and observer requests. These remain offline harness behavior,
not primary-contract or live-provider certification.

Empty-permission role and privilege updates begin with an independently verified
nonempty grant and successful intended access. Applying the empty policy must
remove that access; denial and pre-dispatch cancellation preserve the grant.
Known subject and action selections are compared exactly, including their
scalar/array representation, rather than accepting additional permissions because
the requested read still succeeds. Project privilege lists require unique IDs
and both owned privilege witnesses; a duplicate or omitted peer cannot qualify.
These checks do not project opaque condition values or establish live rights.

Scoped group and auxiliary role cleanup binds acknowledged IDs before deletion,
including renamed group coordinates; genuine lost acknowledgements retain fresh
selector recovery. Group/member/project inventories require complete unique rows
and known owned inclusions/exclusions. Member ordering uses both a machine identity
and a user with contrasting names. Project ordering uses two assigned owned
projects and one unassigned project; OrganizationAll must contain all three.

Every `ListGroupMembers` scope supplies `scopedAccessUserId` and
`scopedAccessUsername`; every `ListGroupUsers` scope supplies
`scopedAccessUnassignedUserId` and `scopedAccessUnassignedUsername`. Runtime user
operations retain `runtimeUserId` and `runtimeUsername`. These inputs select
existing users, not a provisioning path or an authority. Independent native
organization membership reads must show exactly one matching user, accepted
membership and active status. Missing inputs fail `missing-input`; missing
eligibility or a distinguishing contrast fails `observer-unavailable`.
Negative membership filters must include the eligible unassigned witness and
exclude the assigned principal. Mixed-type selectors and name searches verify
their requested subsets independently rather than accepting empty results.

Mixed email/username project invitations and removals additionally require
`secondRuntimeUsername`, `secondRuntimeUserId`, `secondRuntimeEmail` and protected
`secondRuntimeToken` in the selected `C08-IM-MembershipMutations` scope. The first
user is selected by `runtimeUsername`, the second by email. User IDs, usernames,
emails and credential sources must be distinct. These select existing users;
the harness owns only the fresh project and its memberships.

Before case execution, first-only and second-only membership/access contrasts
bind each credential to its independently observed selected user. Different
token text alone does not establish separate principals. Invitation starts with
both users absent and denied; removal starts with both present and able to read
the owned canary. Effects require both exact unique changed-member rows,
independent username membership reads and fresh access checks for both credential
sources, while the denied principal remains denied. Cancellation/denial preserve
the baseline; lost responses are reconciled without repeating the mutation.
Partial batches and organization-user provisioning remain unavailable.

Organization group membership scenarios require a scope-level `groupOwner`
object with `organizationId`, `setupIdentityId`, `observerIdentityId`, protected
`setupToken` and `observerToken`. Owner organization differs from the target
sub-organization; owner principals and credentials must be distinct from each
other and the target selections. Profiles are validated before any ownership.
The parent group and its runtime identity link are created/read under owner
authority, while target roles and membership assignments use target authority.
Add starts with an absent target assignment; Update starts with a non-granting
target baseline. The owner's original assignment is never unlinked.

Authenticated bearer context selects the provider organization; host grant
organization coordinates do not attest that context. Nested group metadata
retains the parent owner. Runtime and denied `GetGroup` witnesses select that
owner resource while using their target credentials. Independent owner group,
membership and exact runtime-link IDs remain stable; target membership IDs must
not alias owner membership IDs. Cleanup removes only the owned target link,
then the owner runtime link/group and target role under their separate authorities.
Native parent/sub-organization eligibility, authenticated principal separation
and entitlement still require qualification.

Organization relative-time Add/Update scenarios use the separate
`organization-group-expiry` protocol through `C08-IM-Memberships.observer`.
Scope inputs select `temporal.nativeDuration: "1m"`, `activationLeadSeconds`
within 1–300, `sourceProfile`, and an explicit `expiredMetadata` policy:
`"RetainedInactive"` or `"RemovedAssignment"`. Target scope also supplies
`setupIdentityId` and `deniedIdentityId`; all seven selected owner/target
principals must be distinct UUIDs. Native case budget covers lead +90s within
the 1–900s limit; observer timeout is at least 60s. Controlled fixtures require
explicit source injection and never count as native qualification.

Prearmed evidence attests authenticated owner/target contexts independently of
request coordinates. Terminal completion binds actual actor, target membership
and temporary assignment IDs. Before/active/expired windows bracket actual SDK
owner-link, target-role, runtime, denied and positive observer reads, alongside
an unaffected project canary under the same runtime credential. Permanent target
assignment IDs are pinned after accepted mutation, not assumed stable through
PATCH. Natural expiry must match the selected metadata policy and preserve the
non-granting baseline. These policies are observation contracts, not claims about
provider behavior. A successful forbidden mutation response stays failed but
is still settled before cleanup; the mutation is never replayed. Interrupted
pre-send cancellation uses only a local NotDispatched fence. Provider scope,
clock, retention/reversion and entitlement remain unverified until native runs.

Project relative-time membership trials use separately selected family-root
`observer` settings for `C08-IM-Memberships` or `C08-IM-ProjectMemberships`.
Their scope supplies `temporal.nativeDuration: "1m"`, positive
`activationLeadSeconds`, `sourceProfile: "NativeProvider"`, and explicit
`caseTimeoutSeconds` within 1–900. The budget must cover lead +60s duration +30s
operation margin; 120s fits a 5s lead. The service timeout must cover the longest
phase wait (at least 60s). Controlled authority is an injected offline test seam,
never an admissible native service profile.

The source chooses the UTC start under a named clock authority/epoch and arms
before the SDK request. Add truly creates a membership; Update retains a permanent
`no-access` baseline alongside temporary `viewer`. Independent readback pins
membership and assignment IDs, relative mode/range/start/end and the complete
relevant role set. A terminal provider request/fence binds denied or applied
work, including a lost SDK response; no snapshot proves late work cannot commit.
Before-send token-barrier cancellation skips nonexistent server completion.

Each source phase brackets local SDK membership and canary reads before activation,
while active, and after expiry. Runtime must be denied/allowed/denied, denied
authority stays denied, and Observer must still read the owned canary. A separate
owned control canary stays readable with the same runtime credential, so expired
tokens cannot masquerade as role expiry. Group membership links remain independently
verified. Permanent `no-access` must survive; a temporary assignment may remain
inactive with its original metadata or disappear after observed expiry. Unexpected
grants or unexplained transformations cannot qualify. Neither sleeps nor
administrative role removal count as expiry evidence.

Cleanup uses the original client-known attempt even after a lost arm response,
requires closed/fenced registrations, settled mutations and complete zero pending
deliveries, then removes only owned group/project resources. The adapter supplies
no provider clock, event-capture service or entitlement; native time authority,
per-operation reversion and enforcement remain separate certification gates.
Organization relative roles use the organization-specific protocol above.

Temporary identity privilege trials in `C08-IM-IdentityPrivilegeChanges` use a
separate `privilege-expiry` observer protocol. V1 temporary creation and update,
V2 creation and update, and V2 by-slug relative inspection bind the operation,
version, selected project/identity/membership, owned privilege ID/slug, full
range, schedule and provider completion fence. V1 updates place lifetime fields
in `privilegeDetails`; V2 uses `type`. SDK timestamps preserve the supplied instant
and serialize as UTC `Z`, including fractional ticks.

The scope supplies `temporal.nativeDuration`, `activationLeadSeconds` within
1–300, `sourceProfile`, and `caseTimeoutSeconds` within 1–900. Native trials
currently admit only `"1m"` with `"NativeProvider"`, a budget covering lead +60s
+30s margin, and observer timeout at least 60s. Exact `"1h"` and `"1d"` trials
are authored under explicit injected `ControlledFixture` time without shortening
their 3,600/86,400-second modeled intervals. Native hour/day qualification needs
a separate long-lived observation design; neither the current deadline nor a
partial active-access observation proves their full lifetime.

Before/active/expired windows bracket actual SDK metadata and permission reads,
retaining permanent `no-access` membership and an unaffected control project under
the same runtime credential. The denied principal and outside permission scope
stay denied. Relative by-slug reads seed their own temporary privilege after
arming, rather than treating successful inspection as permission evidence.
Cleanup closes the original attempt even after lost arm replies, requires a
settled late-commit fence and complete empty registration/delivery inventory,
then removes the independently owned privilege and projects. Explicit deletion
never substitutes for natural expiry. Native clock, activation, expired-row
retention/removal, reversion, entitlement and enforcement remain unverified.

Host-mTLS proof inputs for `C08-IR-InfisicalProofAuthentication` require HTTPS and
separate `proof.certificate` and `deniedProof.certificate` packets. Each packet
contains protected `pkcs12Base64` and `password`; non-TLS strategies reject those
packets. Both are admitted before fixture ownership, including denied cases.
The loader admits one certificate/key with a private key per packet, distinct
accepted/denied leaves, at most 64KiB decoded PKCS12/90KiB encoded text, and a
password of at most 1024 characters. Keys use ephemeral storage and bounded
PKCS12 work limits.

The selected leaf is presented only through a fresh host-owned
`SocketsHttpHandler`. Native server trust is unchanged; redirects, cookies and
activity propagation are disabled. Proof JSON remains identity-only. A denied
certificate must be TLS-valid but application-rejected for the selected identity:
failed TLS transport is `Unknown`/`PossiblyDispatched`, not an observed authority
denial. Outstanding calls drain before handlers and certificates are disposed;
loader byte/password copies are cleared, but the original managed JSON strings
cannot be described as erased.

Offline TLS tests use the public handler overload and an explicitly pinned test
server, not a new SDK trust seam. They prove certificate presentation, handler
ownership, application denial and cancellation/lost-response receipts without
replay. They do not prove native certificate-to-identity authorization or whole
native-family conformance. Native expiry qualification and inaccessible
interrupted-token attribution remain unavailable. TLS management and encrypted-CA/trusted-IP
projection gates are separate.

Universal/Proof successful issued-token cases may select scope
`authLifetime: { deploymentId, sourceProfile, caseTimeoutSeconds }` and a separate
family-root `authentication-expiry` observer. Source is explicitly NativeProvider
or injected ControlledFixture; budget is an integer1–900 seconds. Native budget
covers the expected whole lifetime +20s margin, without shortening policy or
credential lifetimes. Missing profile preserves the existing unavailable
characterization; an explicitly injected source requires the profile. Denied,
cancelled, inaccessible lost-response and periodic-session paths remain separate.

Prearm sends a fresh32-byte private correlation key over the protected channel,
never through evidence DTOs. Qualified independent capture must join the exact
native issuance to its metadata ID. Host verifies domain-bound HMAC in constant
time against caller-owned SDK material; singleton rows and guessed JWT claims
cannot establish that join. Caller key/exports/encoding/hash buffers are cleared,
and source cleanup attests key disposal. HMAC is equality evidence, not source
authentication or native certification.

Active/Expired windows bracket actual HTTP-backed SDK reads using the same issued
material without the local ExpiresAt hint. The allowed canary succeeds before
expiry; both canaries reject after source-observed natural expiry. An independently
authorized observer reads the same unchanged allowed canary in both windows.
Policy/use-limit/identity/method/revocation metadata must match the correlated
row, and source facts exclude renewal, IP/policy mutation, revocation or use-limit
exhaustion. Response expiresIn/maxTTL are compared with captured issuance, not
assumed equal to configured policy TTL/period under deployment caps.

Identity lifecycle cleanup binds both original and renamed selectors to the
acknowledged identity ID before clearing protection or deleting. A genuinely
unacknowledged creation retains fresh-name recovery. Protection-clear updates
start from independently observed protection enabled; omitted protection preserves
that non-default baseline. Lifecycle lists require unique IDs and both matching
owned fixtures. Project search also requires exclusion of an owned nonmatching
identity and verifies the predicate against all returned names.

Identity search/count derives its oracle from complete organization and project
membership inventories and exact native reads, not another search response.
Inventories and results require unique identity/membership coordinates. Matching
owned fixtures must appear and nonmatching fixtures must be excluded; unrelated
matching rows remain valid. `$in` and OR selectors use multiple alternatives, and
combined filters independently exercise both name and role predicates.
Role ordering uses distinct observed roles whose name order deliberately differs.
`updatedIdentityRole` must differ from `identityRole` for role predicates, combined
filters and role ordering. `role.in` also requires `identitySearchExcludedRole`
distinct from both alternatives. Project assignments use `projectIdentityRole`.
`role.contains` requires a discriminating proper substring of `identityRole`.
LastLogin ordering requires an owned LDAP witness profile and distinct successful
logins observed by the provider application clock. Without that profile/source,
the existing unavailable gate remains.

Identity-template cleanup binds acknowledged IDs to original and renamed names.
Configuration updates require contrasting projected fields and preserve unchanged
ones through independent template and fresh-consumer reads. Required-field
contrasts use explicit `baselineOidcDiscoveryUrl`, `baselineBoundIssuer`,
`baselineLdapUrl`, `baselineBindDn`, `baselineSearchBase` and
`baselineTokenReviewMode` where selected; the last is `api` or `gateway` and must
differ from the requested mode. Optional baseline fields may be absent rather
than inventing another issuer, gateway or credential. Template lists/search use
complete unique matching fixtures and an auth-method/name exclusion witness.
Stored-password markers do not certify LDAP password contents. Password-bearing
creates and LDAP updates require independently attributed service/user binds and
actual issued-token access; without the witness source their gates remain.
Kubernetes reviewer-content cases require the actual downstream projected material;
an omitted reviewer field cannot pass from its stored marker alone.

The LDAP bridge uses the selected family's private `observer` settings and
`ldapWitness: { deploymentId, sourceProfile, caseTimeoutSeconds }` (1–900 seconds).
Native inputs cannot select a controlled source. Offline source adapters and
fixtures do not qualify a deployment, its directory, entitlements or clock.
Each owned root has `ldapRootNonce`, `ldapUrl`, `bindDn`, `searchBase` and
`ldapSearchFilter`. Private original/new/wrong service credentials are
`originalBindPassword`, `bindPassword` and `wrongBindPassword`; independent user
credentials are `ldapUsername`, `ldapUserPassword` and `ldapWrongUserPassword`.
The source verifies initial root absence and owns only that isolated root.
Credential packets are clearable command material, never evidence fields.
Each directory packet also carries a host-generated random 32-byte private
`correlationKey`, sent only in `ldap-login/open`. Successful login fences include
`credentialWitness`: Base64 HMAC-SHA256 of UTF8
`"secretkit-ldap-login-v1\0" + directoryAttemptId + "\0" + loginAttemptId + "\0" +
organizationId + "\0" + identityId + "\0" + membershipId + "\0" + templateId +
"\0" + tokenMetadataId + "\0"`, followed by the UTF8 source-captured issued token.
The source must join captured material to the authoritative token metadata row.
The host compares this MAC in constant time against its actual SDK-returned
material before canary reads. Rejected fences carry a null witness. Permission
equivalence, token count and guessed JWT fields cannot replace this join.
`credentialsDestroyed` includes destruction of the source correlation key;
the host clears its key and exported character/UTF8/hash buffers on cleanup.
The MAC proves equality under the challenge, not source authenticity: deployment,
clock and source qualification remain independent native prerequisites.

`ldapCanaries.allowed` and `.denied` select distinct preprovisioned resource
coordinates `{ projectId, environment, path, key }`; `ldapCanaryValue` is the
private expected allowed content. Fresh identities receive viewer membership
only in the allowed project. SDK reads must accept the allowed content and reject
the denied coordinate. Template updates compare distinct old/new service
passwords through already-linked and fresh consumers; omitted passwords preserve
the original accepted credential. User-password rejection is a separate control.
Mutation prearms/completions bind actual caller receipts and terminal source
events, including lost replies, without mutation replay.

LastLogin trials use fresh identities to avoid the ten-second login debounce,
opposed name/login order and a never-login identity. After source visibility is
sealed, all search pages in both directions are checked against complete
non-search membership inventories and actual login events. Equal timestamps use
membership-ID ascending order; nulls are last in both directions. Project rows
must match organization fallback timestamps. Source timestamp writes alone do
not prove token issuance or canary access. No host-clock sorting, backdating or
polling establishes a native witness. Cleanup removes owned SDK resources before
closing the original directory attempt and requires zero residual registrations
or deliveries, credential destruction and unrelated-root preservation.

Identity-authentication field-update scenarios require a distinct baseline rather
than seeding the requested final value. The selected issuer supplies
`baselineParameters` with the contrasting field value and `baselineAllowed` with
its actual proof. Before dispatch the baseline proof must succeed and the final
`allowed` proof must fail; after an applied update those outcomes reverse.
Denied and pre-dispatch cancelled updates preserve the baseline. Missing
witnesses remain unavailable; equal baseline/final values are invalid inputs.
Lockout numeric/boolean updates also seed contrasting configurations.

Successful exchanges compare independently listed issued-token TTL, maximum TTL
and use limit with the observed configuration and returned login lifetime.
These comparisons do not establish expiry or use-limit enforcement. Complete,
unique token inventories must preserve every preexisting token and its exposed
state across both allowed and rejected proof exchanges; unchanged counts alone
are insufficient. Cleanup of the owned consumer role rejects a slug lookup whose
ID differs from the acknowledged creation ID before issuing deletion.

The `C08-IM-Governance` family can select the same explicit `observer` settings for
audit scenarios. Its private routes are `audit/provision`, `audit/trigger`,
`audit/observe` and `audit/cleanup`. Requests bind a fresh owned name, exact
organization/project, selected event class and correlation. The service receives
only the explicitly selected role token copies needed by that operation.
`audit/trigger` must subscribe to the actual producer event before triggering it
under the runtime identity. Returned event coordinates and correlation must
match; the family separately executes its typed SDK requests and verifies
persisted event IDs and enabled classes. Enabled settings require exactly one
persisted occurrence of the produced event, not membership in a duplicated list.
Read scenarios also issue a complementary selector and an outside-window query
that must exclude that event, under both selected administrative and observer
identities when the administrative read succeeds. Cleanup must report zero owned
organizations and projects for that exact name. This adapter does not provision
the fixture service or establish principal separation from an identity label.

`C08-IM-ProxiedServiceAdministration` also accepts explicit family-root observer
settings. Its routes are `proxy/prepare`, `proxy/send` and `proxy/cleanup`.
Preparation binds organization/project/environment and a fresh owned name;
the service provisions the actual isolated credential/backend fixture. Sending
binds the selected service, challenge, identity, credential role and substitution
surface. Measurements must report actual backend requests and substituted
material, not a success acknowledgement. Returned material is owned and disposed
by the scenario. Cleanup binds the same project/name and requires zero remaining
fixture resources. Share and proxy cleanup reject a name lookup whose ID differs
from the acknowledged owned ID before issuing deletion. A genuinely lost creation
acknowledgement still permits recovery through its fresh owned name.
The adapter does not provision the external service.

`C08-IM-GatewayAdministration` selects its own family-root observer. Routes are
`gateway/find`, `gateway/authenticate`, `gateway/enroll`, `gateway/enrollment`
and `gateway/cleanup`. Lookup binds the owned organization/name to an ID, then
the adapter obtains metadata through the typed SDK `Get` operation. The service
must subscribe before starting its owned agent. Authentication/enrollment must
measure the matching native identity, authentication method and fresh heartbeat;
enrollment replies also bind the SHA-256 fingerprint of the selected UTF-8 token.
Cleanup requires explicit zero counts for gateways, agents and enrollment tokens,
followed by an independent absence lookup. Missing measurement fields fail closed;
an identity label or successful metadata read does not prove principal separation.
Independent SDK reads bracket authentication and enrollment. An explicit-null
heartbeat must become present, or the existing heartbeat must strictly advance
and equal the measured heartbeat. Omitted fields, replayed facts and equal-resolution
timestamps cannot certify this invocation.

Governance, gateway and proxy scope inputs may set `caseTimeoutSeconds` to an
integer from 1 to 900; omission retains the 45-second fast-case deadline. A genuine
sharing-expiry scenario must explicitly allow the native five-minute minimum
lifetime plus setup/observation time. The observer's own timeout still bounds each
service call, and caller cancellation always applies. A longer deadline does not
replace the required native expiry/rejection measurement or authorize polling.

Governance sharing uses `share/find`, `share/views` and `share/deliver` on its
explicit observer. Owned lookup is followed by the typed SDK `GetShare`; delivery
receives only the selected runtime/denied token copies and optional proof.
Measurements bind organization/share ID, actual recipient material, one consumed
view, denied access and rejection at the native expiry boundary. Returned material
is caller-owned; the supplied proof stays host-owned. Expiry must be measured from
the actual provider event/state, not fabricated by advancing a reported timestamp.
Finite maximum-view variants additionally require `viewLimit` in the delivery
facts: `maximumViews`, `viewsBeforeExhaustedAccess`, `viewsAfterExhaustedAccess`,
`exhaustedObservationTime`, `exhaustedStatus` and `materialReturned`. Both counters
must equal the configured limit, the first access beyond it must return denied
or absent without material, and its observation must precede expiry. These
variants establish view exhaustion; unlimited variants independently establish
expiry. Later rejection of an already-exhausted share does not establish expiry.
Recipient copies are disposed if subsequent observation throws, and unexpected
successful disposable results are released before cancellation assertion failures.
The adapter does not provision the external service or establish recipient policy
contracts that remain unproven in the native inventory.

When an original share ID was acknowledged, cleanup also requires an Observer
`GetShare` of that exact ID to return absent. Name absence alone cannot certify
removal of a renamed original share. Contradictory observations leave cleanup
incomplete; they do not authorize deleting a replacement. Final removal is
checked against the exact deleted ID as well as the owned-name source.
Unknown-ID recovery after a lost creation response still requires an independently
established original-call ownership and settlement source; native list traversal
is not that source and does not prove absence or snapshot uniqueness.

Azure management mutations require an independent pre-dispatch snapshot after
subscription, before the SDK request. `vault/observe`, `notification/observe` and
`operation/observe` accept the `baseline-before-dispatch` purpose;
`role/observe` uses `assignment-baseline-before-dispatch`. Baseline and subsequent
observations bind the same lease, nonce, identity, scope and subscription, with
nondecreasing observation times. Settings updates must differ in a property the
request changes; creations and deletions require contrasting target existence.
An acknowledged no-op cannot supply an effect witness.

Vault baseline status fields explicitly distinguish absent from existing resources.
Removal compares policy identity (tenant, principal and application), and the whole
resulting policy collection must preserve unrelated entries. Add scenarios use a
previously absent policy identity; replace scenarios change an existing one.
Collections require unique resource/policy/header identities and complete equality
or bounded subsets. Audit event projections instead use multiset matching because
identical public projections may legitimately recur.

Vault measurements supply typed `vaults`, `deletedVaults`, `connections` and
`privateLinks` arrays rather than identity-only arrays. Rows include all exposed
provisioning, authorization, retention, deletion-date, connection-state and
required-member/zone fields. Notification rows compare destination and provisioning
state as well as name. Missing configuration/status/metadata fields cannot become
default observed values. Nullable fields are supplied explicitly as null when
unknown. Successful operation-status scenarios additionally compare the intended
persisted configuration; an approved private connection must actually be Approved.
Role denial preserves the full independently measured assignment set even when
other grants keep effective access unchanged. Role measurements require explicit
`targetPresent` and relevant `assignmentsComplete`/`definitionsComplete` evidence.
The role-only measurement also binds the full original `selector`, lease/nonce,
opaque collection-window `subscriptionId`, increasing `sequence`, `phase`,
`startedAt`/`observedAt`, and exact vault, target parent, assignment, definition
and fixed-version secret coordinates. `intended`, `denied` and `observer` each
carry required status/completeness, actual final native request ID and the
locally computed SHA-256 only for successful material reads. Expected statuses
and digest are checked afterward; they are not collector inputs. Missing or
incomplete inventories or any read cannot establish a complete measurement.
Higher-scope read variants require explicit borrowed group/subscription
assignment IDs; the owned vault assignment ID is not reused at an ancestor scope.
These contracts do not deploy an Azure environment or certify live behavior.
The role and audit source components below implement bounded local hosts; the
other three management services still require their own implementations.

Role preparation now retains the original immutable `FixtureSelector` before
`role/prepare` and enters cleanup protection before sending that request.
`role/release` receives that selector under the same authenticated service owner,
not a returned lease ID. It must work after a lost prepare response, malformed
reply or rejected lease. Its measurement contains the exact `selector`, required
`closing` and `activeDispatches`, plus `ownedResourceIds`, `borrowedResourceIds`,
`absentResourceIds` and `remainingResourceIds`. Completion requires a closed,
drained root, no remaining resources, unique disjoint owned/borrowed sets and
independent absence for exactly the owned set. A validated known lease additionally
binds the expected owned set.

Audit preparation now uses the same original-selector recovery boundary through
`audit/release`, including lost prepare replies and rejected leases. Its explicit
release adopts the same strict closed/drained/owned-absence wire shape; it does
not acquire authority from a returned lease. `AuditFixtureObserverService`
composes this boundary locally with the original audit handler.

Vault and management-operation preparation likewise enter cleanup protection
before sending. Their `vault/release` and `operation/release` routes use the
original selector and the same strict closed/drained/owned-absence wire shape,
including caller cancellation and invalid returned facts. Cleanup requests have
their own bounded uncancelled observer request. Neither family acquires cleanup
authority from a returned lease. Their concrete source services remain separate
authoring work; notification cleanup still uses its existing protocol.

`ManagementOperationNativeCapture` binds the original handler's actual SDK
client, scope, receipt, start task and returned handle, rather than issuing a
second selected mutation. Explicit status calls require that exact handle.
Wire response, native wrapper state, send termination and whole-task completion
are distinct evidence. Vault create/recover updates can require one final
original-resource GET after a terminal status response; capture permits that
bounded second read, not a polling loop. Purge can require a final GET to the same
privately issued continuation after a successful first poll. Cached wrapper success does not replace
a missing status witness.

Its immutable status targets are frozen at the validated provider response and
remain unavailable until the actual SDK start terminates successfully. Only
source-registered windows and issued target references qualify; copied evidence,
lease substitution and later mutable-coordinate changes cannot import another
operation's URL. Original receipt dispatch fences reject credential-time nested
starts; bounded private request ownership accommodates unused installed SDK
message factories without granting additional sends. Whole transport tasks drain
before buffers are cleared or SDK invocation drain is published.
Live authority qualification remains separate.

The source-issued `SynchronousDeleteProof` uses two closed original
selected-contract profiles: DeleteNotification/NotificationScope at revision
2025-02-15 with empty200/204, and DeleteRoleAssignment under VaultScope at
revision2022-04-01 with empty204 only. Role HTTP200 and ancestor assignment
scopes remain excluded. Both require one bodyless DELETE and a completely read
empty response,
without asynchronous/retry headers, encoding, partial content, transfer encoding
or contradictory declared length. Private original task, client, scope, receipt,
handle and wire facts qualify only after successful borrower drain, snapshot
disposal and buffer clearing; cancellation, hook failure and mutable diagnostics
cannot issue proof. Sealing joins private finalization even when window or drain
diagnostics are cleared or forged; request framing must also describe an
unencoded, non-partial, bodyless DELETE. Copied capabilities and coordinate-equivalent replacement
objects carry no authority. This is original synchronous terminal-response
evidence, not independent status-GET evidence; zero-GET cached completion still
does not qualify `OwnsNativeStatusCompletion`.
This prerequisite alone does not admit a deletion observer service or settle a
journal dispatch. Fenced selected-child observation can now return independently
read absence for the original deletion selection without recording journal absence
or settlement. A fresh surviving owned child after selected deletion makes cleanup
incomplete rather than authorizing another DELETE, including after restart.
The service now composes exactly operation.DeleteNotification/selected-contract
for that synchronous profile: owned present baseline, original response proof,
fresh independently owned child absence, then the exact original handle's
captured completion join before journal settlement. The completed wrapper makes
zero native status GETs; its cache alone cannot fill either missing response
proof or independent absence. Nonempty responses,202, continuation/retry headers,
surviving resources, unknown readback and lost provenance remain fenced.
Historical proof cannot reopen a closed root or settle it after disposal.
Restart cannot reconstruct the private proof or original handle from absence.
The separate `RoleManagementOperationFixtureObserverService` now composes
operation.DeleteRoleAssignment/selected-contract using the closed empty204
profile. It generates the owned assignment rather than adopting the requested
identifier, provisions a real protected canary, and validates the independently
read baseline's intended principal, role definition and vault scope. Four owned
resources and one borrowed role definition remain explicit throughout cleanup.
Original response proof, a fresh independent404, and the exact original handle's
captured cached completion must all join before settlement; none substitutes for
another. Role200, asynchronous responses and the other case boundaries remain
unadmitted. Restart preserves fences without reconstructing private authority.
The role provisioner retains the original selected action/receipt before
SDK callbacks, using private selected-admission provenance rather than generic
setup history. Completion is recorded before persistence so explicit same-process
settlement can recover journal contention; restart cannot reconstruct that
receipt. A still-present selected-deleted assignment blocks both another DELETE
and parent teardown. Setup-only cleanup and settled concrete absence retain their
existing paths. Service disposal drains actual selected and resource borrowers
before clearing owned canary material; host credentials and transports remain
borrowed. This local composition does not establish native qualification.

`ManagementOperationStatusCollector` separately makes one independent native
status GET from an issued target, with its own explicit reader authority and
single-use bounded window. Native status is not copied from the requested
variant or selected wrapper. A still-existing notification's provisioning
success cannot establish successful deletion, and 404 cannot establish
asynchronous settlement. Conflicting state fields, partial/error responses and
expired windows remain unknown rather than successful. Both wall and monotonic
time bound dispatch and the remaining deadline.

Actual SDK success now qualifies native targets through private issuer state,
published atomically with task drain. Caller-mutable diagnostic fields cannot
upgrade a rejected SDK start. This is independent status evidence, not persisted
resource, delivery, service deployment or principal/egress qualification.

`ManagementOperationFixtureObserverService` composes `operation.PurgeDeletedVault`
and `operation.DeleteVault`, for selected-contract and independent-effect.
It prepares one owned deleted or active vault root, respectively, and uses
distinct baseline/post resource collector instances with the same original nonce.
Its immutable declared host scope must match the provisioner's actual host
configuration before any preparation. The original invocation is the sole selected
mutation. An eligible private target, independently observed native Succeeded
status and concrete resource absence precede the original handle's status call
and durable settlement. The installed Delete200 path returns cached SDK success
without a status GET; that cache never fills missing independent status evidence.
Absence never supplies
operation state or a provider-authored resource identity; the measured coordinate
is the immutable queried coordinate. After any selected purge attempt, cleanup
cannot purge again or delete an unexpectedly present active vault. Unknown
dispatches and restart without retained provenance remain incomplete.
After proven selected deletion, a narrow three-row history guard permits cleanup
purge only after a fresh native active-vault absence read. Active reappearance
never authorizes retrying DELETE. Native vault endpoints preserve equivalent
root URI forms without changing authority; optional creation-mode metadata is
retained and checked against the installed model rather than discarded.
For `operation.DeleteVault` only, `cancellation-boundary` now retains two distinct
calls on that same original handle: an actual pre-canceled SDK task, then a
non-canceled cached status task. Cancellation propagates without occupying the
later status slot or sending a status GET. Both tasks and retention finalizers
must drain. The original Applied receipt remains unchanged.

This case additionally joins prearmed active-before/after and deleted-before/after
windows with the independent native terminal status. Cached SDK success retains
unavailable wire-status evidence; it does not manufacture a native status proof.
A reference-registered candidate settles the selected fence atomically against
Close. Generic settlement, copied candidates and a canceled borrow alone cannot
clear it. Cleanup still requires fresh guarded absence and purges once without
replaying DELETE.

For `operation.PurgeDeletedVault`, `cancellation-boundary` instead retains the
original POST202, Pending receipt and pending handle. The actual pre-canceled
status task sends no GET; the later actual task must perform both native
continuation GETs. The adapter must consume each of the three response bodies
through EOF and install an exact-byte rebuffer. The native status poll must also
consume its rebuffer; the non-generic Pending start and final response retain no
parsed resource, so neither is claimed as a native resource-parser read.
Independent active/deleted before-and-after windows and terminal status must
join before the reference-registered candidate can settle atomically against
Close. Cleanup requires fresh absence of both vault forms and never repeats
purge or deletes an active resurrection.

For `operation.RecoverVault`, `cancellation-boundary` preserves the complete
trusted pre-delete configuration rather than replacing it from preparation
input. Every field must match the selected recovery configuration before setup;
the immutable baseline is persisted for reconstructed cleanup. The original
PUT201 retains its Pending receipt and handle. The actual pre-canceled check
sends no GET, followed by a distinct actual check that reads the continuation
and then the active vault. All three bodies require adapter EOF and exact-byte
rebuffering; both later responses also require actual native parser consumption.
Four independent active/deleted windows, terminal status, full configuration,
ownership tags and empty relationships must join before Close-atomic settlement.
Only settled recovery allows fresh owned-active/deleted-absent proof, one cleanup
DELETE, fresh active-absent/owned-deleted proof and one authorized purge.
Reconstruction cannot recover an unresolved selected dispatch or replay writes.
Omitted-tag retention and native restoration remain unverified.

For `operation.CreateOrUpdateVault`, `cancellation-boundary` updates only the
prepared source-owned active vault. Its persisted full baseline has public
networking disabled; the selected configuration changes only that field to
enabled. Preparation input cannot replace the trusted baseline. The original
PUT201, unchanged Pending receipt, actual canceled/later tasks and poll/final
resource parser requirements follow the recovery cancellation boundaries above.
Four independent active/deleted windows must prove the complete contrasting
configurations, ownership and empty relationships before atomic settlement.
Cleanup derives the selected configuration from durable baseline history and
requires fresh owned state before one DELETE and one purge. Absent creation,
adoption, unresolved restart settlement and mutation replay remain excluded.

For `operation.DeleteNotification`, `cancellation-boundary` starts with one
source-owned present subscription under its owned active vault. Only the original
empty DELETE200/204 can issue the private start proof: actual adapter EOF and
exact empty rebuffer, successful native task, Succeeded handle and Applied receipt
must agree. The pre-canceled check and distinct later cached check are retained
actual tasks; neither sends a status GET or creates an independent status target.
Independent baseline and post-delete reads retain native task/parser custody,
complete configuration and ownership, with only an exact native NotFound404
admitted as absence. Their reference-registered settlement joins atomically
against Close. Four journal rows preserve the child dependency; cleanup cannot
replay the selected deletion, and parent teardown requires fresh child absence.
Settled cleanup can reconstruct the actual parent and child sources; unresolved
selected work remains fenced across restart. These offline boundaries do not
qualify Event Grid delivery, exclusion or remote closure.

The separate role-operation service supports `operation.DeleteRoleAssignment`
for `cancellation-boundary` only with an original empty DELETE204. Its actual
Succeeded/Applied start, pre-canceled check and later cached check retain private
task custody without status GETs or an independent status target. Source-issued
baseline and absence proofs retain actual native model/error consumption and
complete role metadata, including optional conditions, audit fields and delegated
identity. The bounded local error profile admits only native ResourceNotFound404;
it is not an exhaustive claim about live Azure error codes. Reference-authorized
settlement is atomic against Close. Five journal rows preserve the real canary
and borrowed role definition; fresh assignment absence gates each parent cleanup
stage, and selected assignment deletion cannot be replayed. Reconstructed
cleanup requires durable settlement and cannot manufacture original task proofs.
Effective access and real principal/tenant qualification remain unestablished.

For `operation.UpdatePrivateConnection`, `cancellation-boundary` admits only the
source-bound Pending/Succeeded connection beneath its generated owned endpoint.
Actual native baseline and post-update GETs preserve complete metadata, including
optional missing/null/value distinctions, tags and system data. The original
Approved/Succeeded PUT200 must join its native parser, adapter EOF, exact rebuffer,
Applied receipt and actual task/handle. Actual pre-canceled and later cached
checks send no status GETs. Reference-authorized settlement atomically terminates
the child, clears its dispatch and records approval against Close. A canceled or
timed-out release may stop waiting without detaching the borrower; disposal still
joins it. Cleanup preserves the exact selector and requires native NotFound404
custody plus fresh endpoint, NIC and connection absence before parent teardown.
Reconstruction grants cleanup authority only, never original task proof or PUT
replay. Live synchronous behavior, cascade, permissions and routing remain
unqualified by these controlled fixtures.

For `operation.UpdateNotification`, `cancellation-boundary` retains the original
PATCH201/Updating start and Pending receipt. The actual pre-canceled SDK check
sends no GET; the later check sends one selected-resource GET200/Succeeded and
leaves that receipt Pending. Independent issued-target and full owned-subscription
reads establish the selected state separately. Protected baseline and after
configuration, owner label, topic and native parser custody must agree before
reference-authorized atomic settlement. An invalid owned check attempt burns its
slot; it cannot be retried into cleanup authority. The existing deliberate private
observer configuration exchange remains intact, without endpoint values in the
journal, logs or proof exports. Cleanup and reconstructed cleanup preserve fresh
child dependency checks and cannot replay the selected PATCH. Event delivery,
exclusion and live configuration retention remain unqualified.

For `operation.CreateOrUpdateNotification`, `cancellation-boundary` now has a
separate existing-subscription PUT profile. Its actual request contains only
`properties.destination` and `properties.filter`, preserving the native PUT shape.
Controlled201/Updating yields a Pending handle and receipt; an actual pre-canceled
check sends no GET, and the later actual check sends one GET200/Succeeded without
promoting the receipt to Applied. Independent target status and complete owned
subscription reads must join reference-issued baseline, start and completion
proofs before atomic settlement. Invalid owned attempts cannot be retried into
cleanup authority; reconstructed sources gain cleanup authority only. This
profile requires an already-prepared nonce-labeled subscription. Absent creation
requires a distinct explicit ownership contract and is not implemented by this
profile. Controlled label retention and offline checks do not establish native
writer exclusion, delivery or remote closure.

The absent-subscription variant now has a distinct opt-in source contract.
Its trusted host declares a continuously exclusive namespace epoch before
provisioning. No setup subscription PUT occurs: a fresh armed native404 must join
the captured original PUT, independent target status, complete native candidate
read and actual canceled/later tasks. Only raw absent or empty labels are accepted
in this mode; even an unexpected nonce label is rejected. The source does not
claim Azure issued an ownership label or distributed lock.

Typed durable provenance binds that epoch, resource identities, one selected
dispatch and material-free evidence/configuration digests. Atomic settlement
authorizes ordered cleanup, not selected-mutation replay. A reconstructed source
also requires the same trusted epoch through downtime and a fresh matching
configuration before child deletion. Missing completion, changed configuration,
foreign labels, invalid history or uncertain dispatch preserves the fence.
Controlled tests do not establish continuous live writer exclusion, native
visibility, delivery, platform coverage or remote closure.

Other cancellation cases and status
labels remain separate unimplemented source units; offline evidence does not
qualify native behavior.

For `operation.DeletePrivateConnection`, the status-family cancellation source
now retains one original bodyless DELETE with a nonempty native resource200,
Disconnected/Succeeded response and Pending receipt. It preserves the actual
initial wrapper state through the pre-canceled check. The later actual check
must finish any deferred native parsing and reach Succeeded without a status GET;
independent decoding cannot replace that parser custody.

Complete native Pending200 baseline, strict child NotFound/ResourceNotFound404,
declared endpoint/NIC observations and original task/handle/receipt proofs join a
Close-atomic durable deletion marker. An invalid owned check burns its slot;
copied certificates and generic settlement cannot authorize cleanup. Cleanup
rechecks authenticated native child absence before deleting the endpoint and
before each parent stage, including reconstruction, without repeating the selected
connection DELETE. Caller-canceled release does not stand in for actual borrower
drain. Native response/state propagation, permissions, routing and remote closure
remain controlled profiles rather than live-provider findings.

The same operation's `selected-contract` case now uses distinct source-issued
admission, native read, original start and completion proofs. It makes one actual
uncanceled SDK check, finishes any deferred original-body parsing without a
status GET, and keeps the receipt Pending. Independent baseline/absence and
endpoint/NIC observations must join before atomic settlement under the exact
selected-contract root. Cancellation-case certificates cannot supply this
authority, and local persistence retries cannot repeat the SDK invocation.

This profile is explicitly enabled by its owning service and cleanup readers.
The selector alone does not switch ordinary raw capture or resource-reader
instrumentation into the profile or grant cleanup authority. Reconstruction,
fresh child-absence checks and no-replay cleanup retain their separate evidence
requirements. Native qualification remains open.

The same service also composes `operation.RecoverVault` for those two cases.
Recovery starts from owned deleted preparation, with active-vault 404 and fresh
owned-deleted evidence. Its original update is fenced on the active vault row
without erasing setup history. Independent terminal status, complete persisted
configuration matching the original request, fresh active ownership tags and
deleted-counterpart absence must join before original-handle settlement.
Recovery additionally requires capture-owned successful original status and
final-resource reads after actual task drain; cached handle success and mutable
diagnostic attempts cannot supply that provenance.
Configuration is projected from native reads, not echoed inputs. The original
recovery request does not add ownership tags; controlled tests explicitly assume
tag retention and reject missing or foreign tags. Azure's actual retention of
omitted tags remains unverified. Only settled recovery permits a first cleanup
DELETE followed by authorized purge; lost recovery or cleanup is never replayed.
`operation.CreateOrUpdateVault` supports only an update of a source-owned active
vault for those same two cases. Its measured baseline has public networking
disabled, while the unchanged original request enables it; tenant, location,
SKU, retention, RBAC and empty policies remain bound. Fresh owned-baseline and
post-update reads must agree with the respective independent native
configurations. The update uses the same captured poll/final-read and settlement
requirements as recovery. Absent creation is excluded: the original untagged
request cannot establish native ownership under this source's contract.
Omitted-tag retention remains a controlled-provider assumption.
Other variants/cases are rejected before provisioning; this local composition
does not establish deployment, native principal or egress qualification.

`NotificationAdministrationCollector` separately reads native Event Grid
metadata/inventory and protected delivery attributes/full callback URLs.
Metadata and protected-reader authorities are explicit. Native event-type
strings remain metadata even outside the supported secret-event subset; only
representable configuration converts them to that enum. Empty advanced filters
are unrestricted; nonempty or unknown restrictions prevent that projection.
Hidden fields and separately read action values cannot manufacture atomic
configuration. Concrete GET404 is resource absence, not operation settlement.
This read-only source supplies no runtime deliveries, exclusions or effects.

The original notification consumer also keeps Prepare, validated lease handling
and selected SDK work inside original-selector cleanup protection. Its
notification/release protocol accepts only closed, drained, exact owned-resource
absence, even when Prepare has no usable reply. Validated lease facts enrich
the expected set; they never grant cleanup authority over returned coordinates.
Local original-handler protocol tests do not establish durable source deployment
or real webhook, delivery and exclusion qualification.

`NotificationFixtureProvisioner` owns a subscription's source-selected present/
absent baseline and journaled cleanup beneath an explicit borrowed fixture vault,
or a notification predeclared by its exact retained `VaultFixtureProvisioner`
parent plan. Owned mode shares one original journal/lease and a combined24-row
manifest. It cannot adopt a borrowed vault or append ownership after preparation.
The shared native gate drains child borrowers before parent disposal. Ordered
cleanup requires independently refreshed notification absence before parent
delete/purge; parent absence never certifies child absence. Coordinate-only
cleanup factories restore no material, preparation readiness or task handles.
Timer construction is inside the protected native lifetime for both parent and
child sources, so a throwing host timer cannot strand either gate. A journaled
selected runtime update may replace the preparation canary; cleanup retains
ownership, child-absence dependencies and unresolved-dispatch fences without
requiring that old preparation value afterward.
For the exact original `operation.UpdateNotification` or
`operation.CreateOrUpdateNotification` / selected-contract child,
`ObserveSelectedAsync` can independently read the retained prepared Present plan
while its terminated selected dispatch remains active. It requires the original
four-row owned manifest and private preparation, holds both native gates through
GET/disposal, and rechecks admission before publishing actual state and
caller-owned configuration. It neither renews baseline readiness nor records
absence or settlement; hidden mappings remain unknown. Original notification
PUT/PATCH completion is separately captured as one successful native child GET,
not the vault poll/final-resource sequence or cached success. Controlled tests
explicitly assume, separately for PUT and PATCH, retention of existing labels
and omitted delivery mappings;
they do not establish Azure's behavior.
`ManagementOperationFixtureObserverService` composes exactly
`operation.UpdateNotification` and the already-owned update subset of
`operation.CreateOrUpdateNotification` / selected-contract from an explicit host-owned
child authority pair, fixed protected NearExpiry baseline, and declared ready
HTTPS endpoint. It owns one generated child under the retained active parent,
measures the baseline, then joins independent private-target status and owned
selected readback with the original captured one-GET completion before settling
the dispatch. Absent creation is not admitted: preparation requires a source-created
Present notification and measures its contrasting configuration. Hidden
configuration, foreign labels, cached completion, and lost
responses cannot clear that fence. Cleanup-only restart needs no baseline or
webhook readiness; bounded child deletion and fresh absence after each parent
DELETE/purge stage preserve the four-row ownership contract. Service disposal
drains its children without disposing host objects. This narrow persisted-state
service does not qualify runtime delivery or any live native family.
The child never manages the vault, runtime secret or webhook lifecycle. Cached native
initialization and one actual status GET remain distinct; failed terminal native
operations can settle without becoming ready, while cached202 deletion remains
pending. Buffered native response storage remains source-owned through SDK
consumer close and is cleared after actual task termination. Durable closure
validates host binding atomically before changing an existing root. These local
source behaviors establish neither remote namespace exclusivity nor webhook,
principal, egress, runtime delivery or live family qualification.

`NotificationRuntimeTriggerCapture` retains the original handler's actual runtime
SDK write, receipt and task; its bounded native version/request proof never
substitutes another write or asserts event emission. `NotificationWebhookDeliveryCollector`
accepts bounded native Event Grid packets through an explicit capability path
and links positive deliveries to that captured version. This authentication is
not provider identity. Receiver admission closure is not remote pipeline closure;
old or foreign events never become filter-exclusion witnesses.
Request and content headers share count/byte budgets before typed header parsing.
Per-event native
exclusion and remote completion evidence remain unestablished, so these sources
do not constitute a complete notification observer service or live qualification.

`ManagementOperationResourceCollector` independently reads one fixed typed
resource for each of the ten operation kinds, preserving the original selector,
lease, scope and family revision. Installed native model readers validate
bounded metadata; complete representable configuration, unknown state, concrete
absence and operation settlement remain distinct. It never synthesizes an
operation result from a requested variant, resource provisioning state or an
HTTP404. Local source/tests do not establish authenticated service ingress,
actual principal or egress authority, durable composition or live qualification.
Its review ledger retains asynchronous scheduling and independent test-coverage
limits rather than treating cancellation notification as proof of borrower drain.
Private-connection observations now retain the independently read
`privateEndpoint.id`, with native/raw agreement and a bounded Network endpoint
identifier shape. Missing identity stays missing; malformed identity invalidates
the observation. A valid different endpoint is an observed fact, not ownership
or selection authority. This supplies one prerequisite for generated-child
binding, not endpoint provisioning or private-operation completion proof.

`PrivateEndpointResourceCollector` reads one declared Network endpoint through
an explicit independent authority and the installed generic ARM model reader.
Owner tag, location, subnet, generated NIC, manual connection name, vault target
and group must all agree before Pending/Succeeded metadata can match a
declaration. Source-owned windows, native/raw agreement, bounded replies and
actual borrower drain protect that observation. A matching observation is not
endpoint ownership, generated-child admission or native operation settlement.

`PrivateEndpointNativeCapture` retains the actual original generic ARM creation
task/handle and explicit status task behind source-owned windows. Its private
creation evidence requires bounded original responses and native agreement;
synchronous cached completion retains the original reply until that actual
reader drains. Asynchronous completion permits only the original Network
operation target and final endpoint read. Admission precedes Start callbacks;
close drains actual work and revokes proof. This does not bind a generated
vault connection, establish journal ownership or qualify a private-connection
operation's status handle.

`PrivateEndpointFixtureProvisioner` composes that original creation proof with
independent endpoint and managed-NIC preflight absence, endpoint declaration
agreement, complete bounded vault connection discovery and concrete connection
readback. One predeclared journal slot atomically binds the provider-assigned
Pending connection and clears only its original endpoint creation fence. The
Network-side connection name is not the vault child name. Matching metadata or
an unregistered candidate cannot confer ownership. Only the original parent
source's verified preparation or continuation registers readiness. A final
before-send check prevents root closure during credential acquisition from
reaching the endpoint PUT; already dispatched work drains and can retain cleanup
coordinates without reporting Ready. Restarted parent cleanup remains fenced
by the endpoint, generated connection and independently observed managed NIC.
Setup and binding remain distinct from selected private connection operation
completion and live qualification.

Endpoint cleanup closes the root and deletes only the originally journal-owned
endpoint after global idleness. A separate private original deletion proof
settles that dispatch; independent fresh endpoint, managed-NIC and exact bound
vault-child absence are then committed together against a journal revision.
Neither matching presence nor three absent replies can settle lost creation,
selected work or an uncertain deletion. A remaining NIC or connection keeps
cleanup incomplete; later refresh only reads, without deleting the NIC, subnet
or vault child or replaying endpoint deletion. Validated restart reconstructs
owned coordinates and durably settled state, never original native evidence.
Parent `ReleaseAsync` explicitly accepts `privateEndpointCleanup` to refresh
dependencies before its mutations and final release. Local controlled tests
exercise complete vault delete/purge/release and restart recovery; they do not
establish live cascading deletion or principal/egress authority.

Original private approval capture has a separate closed HTTP200 proof profile:
exact original approval PUT, bounded Approved/Succeeded response, exact child
identity and valid Network endpoint, with installed-model agreement over the
same bytes. It joins the actual original cached status task without inventing
status GETs. Mutated diagnostics, copied scopes and substituted tasks cannot
mint it; journal callbacks cannot alter the authenticated request before send.
This capture proof is not fresh Pending baseline, persisted approval, fixture
ownership or durable selected settlement. Existing cached-success observations
with Pending/Updating bodies and private DELETE completion negatives remain
unchanged and outside this profile.

The owned fixture service separately composes this capture for only
`operation.UpdatePrivateConnection` / `selected-contract`. Its host supplies the
borrowed subnet and explicit endpoint setup, endpoint reader and Key Vault
connection reader authorities. Original registered vault/endpoint plans and a
fresh independent Pending child baseline admit one approval. Independent Approved
readback and the actual original cached status call settle the exact selected
dispatch before root closure. The flushed approval dispatch marker permits
restart cleanup without recreating native proof; unproved selected work remains
fenced. Cleanup deletes only the owned endpoint, then independently checks
endpoint, NIC and bound child absence before vault deletion and purge.
This local composition does not certify live approval timing or Azure cascade
behavior and does not qualify private connection deletion.

`VaultNetworkReadCollector` performs actual versioned canary reads through two
explicit borrowed authorities, without deriving results from connection state.
Native identity/version/hash, bounded raw replies and whole SDK task lifetime
are checked. SDK cached challenge authentication and transport dispatch use the
same per-invocation declared authority and fixed public-cloud context; discovery
cannot add a request. Forbidden, not found and unavailable are distinct. A prior
private success survives independent public failure. Transport labels remain
declarations, not evidence of principal identity or private/public egress.

`VaultPolicyPermissionTrial` executes all eight native action kinds against
explicit prepared owned fixtures, with borrowed intended/denied authorities.
Cold challenge write content and warm SDK bodies converge on a bounded validated
snapshot used for dispatch after credential acquisition. Mutable callbacks
cannot replace that snapshot. Unknown preparation or existing journal work
fails closed; mutations without strict native settlement proof retain durable
uncertainty.

Local source composition prepares11 owned child histories inside one14-row
single-principal vault root, or21 children inside one24-row two-principal root,
sharing only immutable read coordinates. Retained native
backups precede deletion/purge of Restore fixtures. All16 action/authority
observations pass the unchanged effect validator; status projection accepts
only the privately issued measurement, original binding and declared principal.
Native synchronous Set/Restore200 or Purge204 proof, or one explicit observer
GET on the retained Delete/Recover operation, can settle that exact dispatch.
Whole SDK/status task drain precedes fence release. Local tests cover87 trial,
16 composition and81 provisioner cases, including original-root cleanup and
reentrant disposal. This is stateful native-transport evidence; authenticated
source service integration for the remaining policy forms and live principal/
egress qualification remain open.

The separate local `VaultReadFixtureObserverService` composes original
`GetVaultAsync` / `selector.exact` across all five retained boundaries. Measured
active/deleted baseline statuses and configuration precede dispatch; unobserved
connection state remains Unknown. Independent bounded metadata and original SDK
GET evidence remain separate. Original-ready read loans fence credential,
transport, parsing and response-buffer borrowers through actual termination;
generic provisioner observation gates are unchanged. Native denial requires a
validated captured 401/403 response, not just an exception mapped to Denied.
No read replay, mutation receipt or native qualification is inferred.

The same source also composes `GetDeletedVaultAsync` / `selector.exact` across
the five retained boundaries. Its original deleted preparation is separate
from active-read readiness. Independent deleted metadata agrees with the
parent's fresh ownership, original-vault, location, retention and protection
witness and the actual original typed SDK response. Denied-state comparison
uses measured absent-active/present-deleted statuses and empty policies, not
setup defaults. Deleted-read cleanup is purge-only: an unexpected active vault
is not deleted, unknown preparation/read/purge dispatches remain fenced, and
restart recovers cleanup coordinates without reconstructing original readiness.

The source also composes `CheckNameAvailabilityAsync` / `selector.exact` across
all five retained boundaries. It measures the native false availability result
for the exact already-owned vault name together with fresh parent ownership and
configuration. Selected and observer POSTs dispatch source-owned immutable
content over validated bounded bytes, not another serialization of potentially
stateful original content. The actual original SDK result and fresh independent
boolean must agree; request buffers remain live through actual borrowers and
are cleared afterward. This does not reserve names or certify the namespace.

`GetPrivateConnectionAsync` / `selector.exact` also composes the original typed
read across the five retained boundaries. Its original seeded-canary parent and
owned endpoint supply the discovered Pending child. Fresh independent parent,
child and endpoint metadata agree with the original native response and SDK
result. Actual versioned canary reads provide private Forbidden denial and public
success with the prepared digest; the network effect retains the actual private
runtime request ID. This does not establish why the private read was denied or
qualify principal identity or private egress. Registered read-only child loans
retain all actual borrowers, never mint approval settlement, and drain before
endpoint-first cleanup and parent purge. Restart recovers cleanup coordinates,
not original readiness or completion capabilities.

The original `ListPrivateConnectionsAsync` / `collection.bounded` source uses
that same owned topology and actual network-read evidence. Its closed profile
admits one complete page containing exactly the discovered child. Selected and
independent collection responses reject every non-null continuation before SDK
or collector parsing; no second request or filtered inventory can qualify.
The actual SDK inventory must be complete and agree with raw bytes and fresh
independent membership. Caller scope and limits remain the original objects.
This profile does not qualify general pagination or alter public SDK behavior.

`ListPrivateLinkResourcesAsync` / `collection.bounded` additionally joins fresh
child metadata with a separate complete link-resource collection under the
original read loan. Its closed singleton uses the native `vault` group, rejects
all non-null continuations before parsing, and compares full member/zone arrays
without sorting or case normalization. Expected arrays are copied from the fully
validated independent baseline, not guessed or taken from the selected response.
Both metadata observations, endpoint metadata and actual runtime reads must
agree before publication. The metadata resource adds no owned cleanup row.

`ListVaultsAsync.ResourceGroup` / `collection.bounded` uses the ordinary active
three-row root and a complete native group inventory containing only that owned
vault. Foreign members make the profile ineligible; they are never filtered out.
Raw identity, ownership tag and complete configuration must agree with native
projection, a frozen independent baseline and fresh parent witnesses under the
original read loan. Non-null continuations fail before parsing. The actual SDK
item retains the original group and subscription references, while its vault
scope is newly constructed. Larger collection limits do not broaden this profile.

`ListVaultsAsync.Subscription` / `collection.bounded` applies the same closed
inventory proof to the whole subscription. Its sole member must be the original
owned vault in the original host group; another group, a matching tag or an
extra vault cannot qualify through filtering. The SDK constructs both group and
vault scopes while retaining the caller's original subscription object. Fresh
complete metadata and parent witnesses must match the frozen baseline, with
the same original-loan, native-outcome and borrower-drain requirements.

`ListDeletedVaultsAsync` / `collection.bounded` uses the original deleted root
and its actual preparation DELETE. The complete subscription collection must
contain exactly that owned deleted vault. Raw identity, original vault ID,
ownership, dates and protection join the narrower SDK/collector projections
with fresh native parent witnesses; no missing observation fields are invented.
Cleanup is purge-only, and the inventory profile rejects an omitted deleted-only
cleanup flag before ordinary cleanup can close or mutate the root. Partial
preparation and active-vault reappearance never grant active DELETE authority.

The original `UpdateSettingsAsync` source retains the immediate SDK PATCH task,
input object and receipt; it does not create an LRO or poll status. A specialized
journal fence remains active after native return until fresh metadata and parent
observations establish the expected configuration. Only a reference-registered
completion certificate can persist settlement and release that fence. Request
bytes are captured once and forwarded from immutable owned storage.

All nine settings variants retain their five canonical cases. The purge-false
variant throws in the actual patch constructor before any selected SDK task or
send. Applying purge protection intentionally leaves an owned protected deleted
vault after soft deletion: no purge, protection rollback or released claim is
permitted. The four applying canonical cases therefore retain the existing
`CleanupIncomplete` outcome; denied mutation uses its unchanged baseline.

The original `DeleteVaultAsync` source is a separate profile of
`ManagementOperationFixtureObserverService`. It keeps the original vault-family
selector, SDK client, scope, receipt, start task and returned handle; status-family
records are not relabelled as vault-family evidence. The bounded HTTP 200 start
profile requires its captured provider continuation, one independent terminal
status read, fresh active-vault absence and owned deleted-vault presence, and
the original handle's actual cached check with zero selected status GETs.
Native parsers consume source-owned bytes and frozen validated headers.

Typed journal certificates distinguish invocation termination from settlement.
Persisted successful deletion permits only fresh-absence-gated counterpart
purge; native denial with an unchanged owned parent permits ordinary cleanup.
Restart cannot reconstruct an original task, handle or unpersisted certificate.
Cancellation and response-loss cases retain their actual outcome and receipt:
without the returned handle they remain fenced and report `CleanupIncomplete`,
even when independent reads observe deletion. No replay or invented status
request converts those cases into successful settlement. This is local source
behavior, not native qualification or same-run release evidence.

The original `PurgeDeletedVaultAsync` profile retains its own deleted-vault
selector, caller scope, receipt, SDK start task and pending handle. Its bounded
native 202 profile requires one independent terminal status GET, fresh absence
of both active and deleted vaults, and the original handle's actual check with
two authenticated GETs to the captured continuation. A cached zero-GET result
or SDK acceptance of synchronous 200 is not substituted. The original receipt
remains Pending; independent settlement does not rewrite it to Applied.

Preparation uses an ARM-only original deleted root and an actual setup DELETE,
with retained empty native relationship evidence before deletion. A settled
Purged disposition permits fresh absence observation only, never another purge.
Native denial with an unchanged owned deleted counterpart permits one cleanup
purge. Unresolved work, active-vault reappearance and lost cleanup responses
remain fenced. Repeated post-observation retries local journal persistence, not
provider calls. Qualification also requires actual reading of every source-owned
response body through EOF during the SDK lifetime, including its final GET.
Accessing or disposing a response does not establish consumption; a completely
replaced response cannot qualify merely because native capture completed.
Normal SDK extraction is not a response substitution. Termination-certificate
creation and registration share the journal's durable Close gate. Only an exact
certificate registered before Close can finish termination persistence afterward.
Cancellation and response loss without a returned handle
retain `CleanupIncomplete`. These remain local source checks, not qualification.

The original `CreateOrUpdateVaultAsync` profile retains all twelve configuration
selectors and their five original boundaries. Each source holds one trusted
baseline/selected configuration pair and rejects another variant's preparation
before work. It updates an owned, freshly prepared vault; it neither adopts an
absent target nor injects ownership tags into the original SDK request.
Tenant, location and retention stay fixed, the complete configurations must
differ, and enabled purge protection cannot be disabled.

The bounded positive profile captures native 201, its pending vault body and
provider continuation. Post-observation joins one independent terminal status
read with fresh native active/deleted reads while preserving the original Pending
handle. Completion follows the handler's Pending assertion and checks that exact
handle with its actual poll and final-vault GET. Full native configurations select
only the trusted baseline or selected state and are joined to captured raw bytes.
The receipt remains Pending; cached status cannot replace these requests.

Parser custody requires actual byte reads and exact buffer identity, including
the native error parser's buffering. The initial pending body is parsed by the
SDK transport adapter; the native LRO retains its continuation. Independent
response replacement or disposal cannot manufacture parser proof. Typed journal
state and private certificates identify this profile, not selector text reused
by generic fixtures. Certificate creation is atomic with Close; local persistence
retry reuses drained decisions without another provider call. Protected selected
or denied-baseline configurations remain honestly cleanup-incomplete after soft
deletion, without purge. These local source contracts do not qualify native
provider behavior or close a family packet.

The original `RecoverVaultAsync` source covers the same twelve selectors from
an owned deleted baseline. Baseline and selected configurations must be fully
equal: recovery restores that configuration rather than applying a contrasting
one. Preparation retains the actual pre-delete native model and raw response,
then proves active absence and the owned deleted counterpart. Deleted metadata
alone cannot establish retained SKU, authorization or access policies.

Positive recovery joins native 201 and its continuation, an independent terminal
status, fresh active configuration and deleted absence, then completion of the
exact original handle. The original request includes recover mode without
injected ownership tags. Denial requires actual 403 and an unchanged deleted
digest. Typed recovery certificates and the journal's Close gate control
settlement; a restart can resume cleanup from durable disposition but cannot
reconstruct invocation proof from resource presence. Cleanup deletes a recovered
active vault once, or preserves the denied deleted baseline, and purges only
unprotected owned state. Protected, canceled or response-lost cases remain
cleanup-incomplete. Configuration, policy and tag retention in controlled tests
are assumptions to qualify against Azure, not observed native guarantees.

The original `UpdatePrivateConnectionAsync` source distinguishes input rejection
from a provider mutation. Unknown, Pending and Disconnected invoke the actual
SDK method and require Invalid, an untouched receipt and no selected request.
Approved and Rejected require a complete native 200 terminal child response,
the exact original handle and one actual cached completion with no selected GET.
Denial requires native 403 and unchanged parent and child evidence.

Independent observations join the owned parent and prepared canary, bound child,
Network endpoint configuration and both runtime reads. Private access must
succeed after Approved and remain denied after Rejected; public access still
succeeds with the exact canary version and digest. Structural endpoint matching
does not relax the Pending-only setup gate. These observations do not qualify
principal identity or private routing.

Typed child dispatch and certificates fence cancellation, response loss and
unsettled pre-send work. Close revokes new work before draining borrowed tasks.
Cleanup requires durable disposition and endpoint-first deletion with fresh
endpoint, NIC and child absence before parent deletion/purge. A restart cannot
turn present resources into invocation proof or replay a selected mutation.
Controlled endpoint cascade, propagation and runtime behavior remain native
qualification assumptions, not Azure guarantees.

The original `DeletePrivateConnectionAsync` source retains the exact bodyless
DELETE invocation and its real handle. Native 403, the actual error parser,
unchanged parent/child/endpoint evidence and both independent runtime observations
must all agree before a typed Denied certificate permits endpoint-first cleanup.

The positive profile requires a complete native 200 resource body with the exact
child and owned endpoint, Succeeded provisioning and Disconnected state. An
independent typed decode does not substitute for consumption by the original SDK
parser. The original handle must actually complete successfully, with its pending
receipt preserved and no fabricated status GET. Fresh parent/canary, concrete
child absence, endpoint topology/state and both runtime observations must also
agree before Deleted settlement. Termination and settlement certificates register
as one Close-gated pair; only an already registered pair can retry persistence
after Close, without another provider call, check or certificate factory.

Positive 204 normalization remains unestablished. Existing controlled empty-body
200/204 starts return a handle, but its original check returns Unknown and
remains Pending; 202 remains Invalid/Pending. A separate controlled 200 with a
full native resource body completes successfully without a GET. The source
preserves each actual result; absence or successful runtime reads alone never
qualify. These controlled profiles are not live Azure qualification.

Cancellation, response loss and even reservations that fail before the selected
send remain fenced. Restart and all-absent observations cannot clear that fence
or replay DELETE. Deleted cleanup rechecks concrete child absence after endpoint
credentials and before forwarding endpoint DELETE, then rechecks endpoint, NIC
and child absence before later parent actions. Contradictory forbidden 404s do not
prove absence. Empty-body positive cases remain cleanup-incomplete; this is an
explicit support boundary, not evidence of a live provider defect.

The first local `VaultFixtureObserverService` slice now composes one original
`ChangeAccessPoliciesAsync` Add, Remove or Replace invocation for one configured
principal, or one Add for two explicitly configured pairs under policies.multiple.
Authenticated bounded ingress,
actual child preparation, paired independent metadata, sealed permission effects
and original-selector release work together through the existing handler.
The source retains the original SDK client, scope, receipt and actual task;
captured native settlement, SDK drain and independent effects are distinct.
Local HTTPS, denial, cancellation, lost-response, no-effect, malformed proof and
whole-task ownership cases pass in the combined179 provisioner/service cases;
105 collector cases cover the paired policy read. Independent review's throwing
response-disposal and never-dispatched receipt-fence defects were reproduced
and fixed with deterministic regressions. Remove requires the independently
observed intended policy to exist before selection; its sixteen real permission
trials measure denial after removal on the same vault. Replace requires a
contrasting independently observed policy and measures the newly granted rights,
not just continued access to an old permitted action. Each individual secret
permission, empty permissions and omitted application ID also runs through all
five original boundaries. Only a bound empty native REQUEST can normalize the
SDK's omitted empty collection; native RESPONSE proof remains explicit.
The explicit application-ID variant binds preparation, typed input, canonical
dispatch and native policy proof to the constructor-held claim; local reads do
not certify application credential identity. Two independently constructed
permission sources share the original lease, arm once and collect sequentially
without resetting deadlines:32 actual observations produce16 sealed effects.
The global root fence and combined24-row release bound cover both sources.
Journal capacity is24 resources and16MiB cumulative history with unchanged64KiB
frames and hash chain; Prepare preflights maximum reachable serialized frames.
Native/metadata application substitution and a blocked second-principal borrower
have deterministic negative coverage. Other vault operations and live
service/principal/egress qualification remain separate open units.

The local `RoleFixtureJournal` component persists owner/selector, planned
owned/borrowed resources and each dispatch before sending. Release-before-prepare
leaves a tombstone; closing prevents new provisioning. Active or uncertain work
is retained, and neither delete acknowledgements nor process restart prove
absence. Borrowed resources cannot enter mutation or absence cleanup. The host
must supply a private trusted durable directory; torn history is rejected without
rewriting it. It does not establish multi-host locking or filesystem
directory-entry durability after power loss.
Both setup and cleanup admission atomically require every dispatch in the root
to be idle; an earlier idle snapshot cannot authorize a competing mutation.
Same-instance transitions are serialized. Unchanged absence records do not append
history; each later dispatch still invalidates earlier absence. Actual invocation
completion is retained before finalization writes, allowing explicit in-process
recovery after transient journal contention without inferring process-loss drain.

`VaultFixtureProvisioner` separately supports source-selected active, absent and
deleted vault baselines, without the role provisioner's fixed RBAC/four-row
layout. It preserves explicit policy, SKU, network, protection and retention
settings across three owned coordinates and bounded borrowed dependencies.
Independent reads reject foreign or partial metadata and numeric permission
spellings. Before selected dispatch, deleted protection and retention must match
the source baseline. Purge protection is never disabled to make cleanup pass.
The pinned native ARM client can lazily complete a synchronous response from
its validated cached data; this does not require a fabricated extra wire read.
Conversely, its already-completed wrapper for an unsupported DELETE202 response
cannot prove remote settlement, so the source retains pending cleanup.
This is a provisioning component, not the vault collector, authenticated service,
permission/network witness or native qualification.

`VaultAdministrationCollector` separately supplies independent metadata across
nine native read kinds bound to all 17 originating vault members. Concrete reads
use the installed ARM SDK; source-owned bounded inventory requests parse rows
with the SDK's native models. Actual provider-authored continuations remain
fixed to the original origin, scope and API revision. A complete inventory needs
all pages; later failure preserves earlier validated rows without certifying
completeness. Concrete 404 does not establish inventory or authority. Unknown
native values never become named enum values, and configuration that cannot
round-trip without changing soft-delete state is not projected as rebuildable.
Application IDs and empty permission arrays remain intact. This component does
not supply permission effects, private/public probes or an authenticated service.

`RoleFixtureProvisioner` uses separate host-owned setup and observation
credentials/transports to provision an RBAC vault, canary and vault-only assignment.
Native Pending is not success. A separately observed same-nonce terminal vault
may enable first-time downstream setup without replay. Lost or incomplete native
operations retain durable uncertainty. Explicit `SettleAsync` performs one native
status update per call, never a propagation loop. Default soft-deleted vaults
remain cleanup-incomplete; purge requires host and invocation opt-in, a separate
persisted attempt, and independent active/deleted absence afterward.

`RoleFixtureObserverService` binds one authenticated capability owner to an
allowlisted subscription/group/tenant/principal/definition. Its closed POST routes
are `role/prepare`, `role/arm`, `role/observe` and `role/release`.
An explicit release performs one bounded settlement step on owner/selector-bound
retained native operations before continuing cleanup. No retained completion or
handle after process loss means uncertainty remains; release does not poll or
replay mutations.
Arm uses `subscribe-before-trigger`; observation uses the existing baseline or
assignment/effective-permission phase. Complete inventories and three fixed-version
native reads come from `RoleAdministrationCollector`, not selected SDK results.
The host must install `CreateSelectedTransport` before enrollment and route the
selected typed SDK requests through that source-owned channel. It checks native
operation, target, revision and grant coordinates, journals selected mutations
before forwarding, rejects replay/late writes and retains actual in-flight work
through cleanup. Grant validation and forwarding use the same bounded owned byte
snapshot, retained until actual native send termination. Closing seals ingress
before resource deletion. Caller receipt
echoes do not prove drain, native settlement or the observed effect.

`RoleFixtureObserverHost.Start` accepts an explicit address, caller-owned server
certificate and request delegate. It implements real TLS HTTP/1.1 with bounded
workers, headers, bodies, replies and deadlines, closes each connection, rejects
ambiguous framing and drains actual delegates on shutdown. It changes no global
certificate trust and never disposes borrowed credentials, transports or keys.
No standalone deployment or implicit CLI proxy configuration is provided.
Host enrollment must independently establish principal/tenant authority,
source independence and exclusive native egress: a configured object, label,
distinct token strings or a claimed exclusive namespace proves none of those.
Live Azure rights, entitlements and operational qualification remain open.

`AuditIngestionCollector` is a separate read-only native query component, not an
audit provisioning service or ingestion subscription. It uses the pinned
Azure.Monitor.Query client and its public-cloud `api.loganalytics.io` endpoint,
with one source-owned, single-use resource/workspace window. Workspace queries
remain restricted to the intended vault. Response, table, row and deadline
budgets apply before native materialization; partial and overflow results retain
bounded valid rows without becoming complete.
Every raw row must contain exactly six string cells before the buffered body
reaches the native parser. Response-read cancellation drains and clears owned
storage. The host must separately qualify its borrowed transport's no-redirect
and exclusive-egress behavior; checking wrapper request URIs does not establish
the behavior inside an opaque transport.

Its `ResponseComplete` concerns only the query response. Raw native operation
names and optional correlation GUIDs are preserved independently of local enum
projection, including duplicate multiplicity. Missing correlation is not replaced
by a trigger label, version or timestamp. Successful empty results do not prove
absence or monitoring authority.

`AuditNativeTriggerCapture` separately fences the nine native secret trigger
routes at the transport boundary, including the pinned SDK's `/secrets/` list
route. It assigns a fresh client correlation GUID to each actual attempt and
records the native response request ID separately. Owned request snapshots remain
alive until send termination and are cleared afterward. Sealing fences and drains
transport sends only; the enclosing SDK task must also be owned and drained by
the source before fixture cleanup. This does not establish a cloud correlation
mapping or remote settlement.

`AuditDiagnosticSettings` pre-journals the owned vault diagnostic setting and
borrowed workspace in a separate durable root. Independent reads validate the
vault nonce, tenant and location, the workspace ARM/customer identity, and exactly
the intended AuditEvent export. Release preserves the borrowed workspace.
Lost or asynchronous native mutations stay pending without replay; retained
actual invocation completion can repair a failed journal append in the same
source instance, but process loss cannot supply that evidence.

`AuditFixtureObserverService` composes the components through authenticated,
closed `audit/prepare`, `audit/arm`, `audit/trigger`, `audit/observe` and
`audit/release` routes. Each of one or two windows has a separate base-vault
journal and diagnostic journal. Preparation journals all coordinates before
native sends. The source retains the actual original SecretKit Set task through
the typed `SelectedInvocation` seam, and owns the other native trigger tasks.
Closing seals ingress before cleanup; neither captured-send termination nor a
caller-returned version substitutes for SDK task termination or native settlement.
Diagnostic absence precedes vault deletion. Lost or asynchronous native work
cannot acknowledge complete cleanup.

Arming establishes a local trigger barrier, not a remote ingestion subscription.
Observation performs one bounded independent query after actual trigger completion.
A causal label requires one matching actual authorized capture, native operation,
successful result and client correlation. Native response request IDs remain
separate evidence. Unrelated rows retain their full multiplicity without receiving
the trigger label; ambiguous joins fail. No timestamp-only correlation or ingestion
watermark is inferred. The service delegate can run on the existing explicit
`RoleFixtureObserverHost`; credentials, certificate and native transports remain
host-owned. Local integration and TLS evidence do not establish Azure identity,
egress, correlation, ingestion timing, deployment or remote lifecycle qualification.
Service replies serialize through the configured nonexpanding body-byte budget.
An oversized acknowledgement fails closed without removing original-selector
cleanup authority; its source staging buffer is cleared on success and failure.
[Key Vault logging](https://learn.microsoft.com/en-us/azure/key-vault/general/logging)
documents correlation and native operation names; the
[ingestion timing contract](https://learn.microsoft.com/en-us/kusto/query/ingestion-time-function)
does not provide a global completeness fence.

The optional SQL protected-input trial applies to definition create, update and
policy update. Each selected case supplies `sqlInputWitness` with `deploymentId`,
`sourceProfile`, `rootNonce`, `caseTimeoutSeconds` (1-900) and a contrasting
`baseline` using the existing private SQL profile shape. The selected configuration
remains `profile`. Native configuration cannot select `controlled-fixture`; that
source requires explicit test injection. Cases without this profile retain their
previous protected-input gates.

The separately qualified private service uses `sql-input/open`, `arm`, `complete`,
`observe` and `close` over the existing versioned observer envelope. Open receives
clearable private copies of both configurations and selected options. Its evidence
must establish owned administrative principals, independent committed-storage
access, actual administrative-session capture, applicable TLS/gateway capability
and a source-bound clock. Labels and request-body echoes do not qualify storage.
SQL input projections may contain administrative credentials and never enter
reports or diagnostics.

An original-attempt terminal fence binds the exact case, definition, source arm
and actual SDK receipt before reconciliation. `PossiblyDispatched` can settle as
applied or nonapplied, including no upstream request; no replay resolves uncertainty.
The host creates a positive baseline control, then acquires fresh credentials
through the public SDK and checks independent lease inventories, actual backend
authentication, wrong-password rejection, permissions and expiry. Definition and
lease handles remain bound to the client that uses them. Supplied password
requirements must also constrain the actual issued credential; correct stored
policy alone cannot qualify that effect.

PATCH shallow-merges supplied inputs: omitted CA, renewal, SSL and routing fields
retain stored values; explicit gateway/pool null clears the selected field.
Create omission does not inherit a baseline. `sslEnabled` is an MSSQL encryption
control in the pinned provider, not a universal SQL TLS switch. CA qualification
requires an owned nonambient chain and invalid-trust rejection. These facts need
independent committed-storage and administrative-path observations, not merely
authentication by a generated lease.

Cleanup reconciles caller-owned names and every lease without forced record
removal, proves rejection of all retained pairs on their original targets, removes
the owned folder, then closes the source. Close must prove original attempts
settled, owned principals/definitions/leases absent, borrowed state preserved,
private copies destroyed and no pending registrations or deliveries. Unsettled
cleanup remains failure. All six SQL aliases and original admission keys remain;
offline controlled evidence does not qualify native drivers, TLS, routing,
statement privileges, source completeness or deployment entitlement.

The non-SQL protected-input witness contract retains all 27 typed definition
providers and six definition operations: create, update, policy update, inspect,
list and delete. `nonSqlInputWitness` supplies `deploymentId`, `sourceProfile`,
`rootNonce`, `caseTimeoutSeconds` (1-900) and exactly one contrasting `baseline`
or `baselineAlternative` with `baselineAlternativeVariant`. Selected inputs still
use the existing typed profile, alternative and nested-option selectors.
Controlled sources require explicit test injection; native settings cannot
select them. These contract requirements do not qualify a native deployment.

The private source must distinguish `AdministrativeConnection` from
`LocalValidation`. The pinned TOTP and SSH save validators are local; they require
independently committed normalized inputs and, for SSH, generated-key consistency
and retain/regenerate lineage. Other providers require the actual authenticated
save action, principal, target, wrong-authority control and applicable
provider-specific transport/deployment authority. Stored-but-unused inputs prove
persistence only: for example, IBM's saved gateway does not route its save-time
token exchange, and Entra's user/email do not establish a Graph user operation.
Neither submitted-body echoes nor returned definition inputs qualify storage.
Those inputs can contain administrative credentials and stay private.

Create persists validated/transformed inputs. PATCH shallow-merges omitted
top-level fields but replaces supplied nested objects/arrays. Nullable clear,
empty and default behavior remains provider-specific; OAuth's omitted nested
client-secret restoration is an explicit exception, not recursive merging.
Policy-only PATCH can still invoke native connectivity validation.

Source fencing must include upstream actions preceding definition commitment.
Kubernetes validation creates test resources; several authentication validators
mint tokens; OAuth additionally attempts test-token revocation. Rejected,
cancelled or noncommitted definitions do not prove those effects absent. An
original-attempt terminal result excludes late application without replay; read
requests have no mutation receipt and must never count as committed writes.
Close must independently prove all owned upstream resources absent and all owned
material disposed or naturally expired, with borrowed state preserved and zero
pending actions, registrations or deliveries. Expiry still pending is
cleanup-incomplete. Native lifetimes cannot be shortened for the trial.
Non-SQL material acquisition remains unexposed; no public lease or credential
operation is invented to qualify these definition effects.

The optional SQL rotation PATCH witness covers the three typed SQL rotation Update
endpoints. Supply `sqlRotationPatch` in the selected database family scope with
`version`, `deployment`, `sourceId`, `clockId` and positive `epoch`. The existing
database fixture and lifecycle observer channel remain required. The private
`database/patch/arm`, `read`, `controls`, `complete`, `recover`, `release` and
`remaining` endpoints bind the original case, nonce, organization, project,
rotation, backend coordinate, source and clock. Recovery settles the original
attempt; release removes only its subscription, never replays a PATCH or forces
provider deletion.

These trials seed both optional parameter siblings and nondefault allowed symbols.
Supplied nested parameters replace the parent: omitted statement or requirements
disappear, while omitted top-level parameters retain both. Required sibling
omissions are rejection controls, not merge experiments. Mapping and time changes
supply their required unchanged sibling. Independent committed protected values,
the observer GET, terminal job/lock/scheduling journals and existing credential
authentication/mapping must agree. This does not prove a new statement or policy
was executed in a subsequent rotation. Cleanup requires zero pending work, locks,
source registrations and owned resources, with borrowed state preserved.

The optional proxy Update witness supplies `proxyPatchWitness` with `deploymentId`,
`sourceProfile`, `rootNonce` and `caseTimeoutSeconds` (1-900) in the selected proxy
scope. It uses the existing proxy fixture/backend observer plus the private
`proxy-patch/open`, `arm`, `complete`, `observe` and `close` source channel.
Controlled-fixture sources require explicit test injection. Open qualifies
independent committed storage, reference validation, actual runtime delivery and
distinct contrasting references. The host seeds two rows, then supplies one
changed row or omits the array. A supplied nonempty array replaces all rows;
omitted row optionals do not inherit. An omitted array retains both original rows.
An empty supplied array is rejected by the public SDK.

The exact original arm and SDK receipt fence reference validation and commitment
before observation. Runtime substitution, wrong-value rejection and denied zero
delivery must agree with independently stored rows. Source close follows native
service/reference/project cleanup and proves all original attempts settled, no
late creation, zero registrations/deliveries, destroyed private copies and intact
borrowed state. Neither PATCH protocol nor controlled calibration qualifies a
native deployment, source completeness, principal separation or backend authority.

Gateway Update accepts the optional `gatewayPatchWitness` in its selected scope:
`deploymentId`, `sourceProfile`, `rootNonce`, `caseTimeoutSeconds` (1-900), and
typed `baseline`/`selected` authentication profiles. These contain protected
reviewer JWT and CA inputs and must stay in the private channel. The family-level
`gatewayPatchObserver` uses the existing observer settings/envelope; its private
endpoints are `gateway-patch/open`, `arm`, `complete`, `observe` and `close`.
The existing gateway agent observer remains required for owned lookup/removal.
There is no new SDK gateway list/delete operation. Native settings cannot select
a controlled-fixture source without explicit test injection.

Open must qualify independent protected storage, actual effective authentication,
destination validation, contrasting inputs and borrowed attachment preservation.
Omitted top-level authentication retains the prior method. Supplied methods apply
their own defaults/clears; replacing a method removes its previous configuration.
Kubernetes CA and reviewer retention depends on the validated destination.
Source evidence must distinguish retained CA, explicit empty CA, reviewer reuse,
reviewer rejection and destination-dependent drop. A presence flag is insufficient.
Response-only Identity baselines require native source-owned setup, not a fabricated
public creation input.

Authentication persistence and rename are separate effects. Original-attempt
fences retain both outcomes after a lost or rejected response and exclude late
application without replay. Independently committed configuration, actual
authentication/TokenReview, wrong-authority rejection and SDK name readback must
agree. Unsettled work prevents owned deletion. Close follows native gateway and
project cleanup and proves no owned gateways, agents or tokens, zero pending
deliveries/registrations, destroyed private copies and preserved borrowed
attachments. This authoring protocol does not certify a native source, deployment,
clock, TokenReview authority or attachment routing.

Runtime rotation Get/List can select `rotationMaterialWitness` in the existing
operation/variant/case input row. It supplies `deploymentId`, `sourceIdentity`,
`clockEpoch`, `source`, `projectId`, `environment`, `folder`, `rotationId`,
`profile`, `kind`, `generation`, `fields`, `setupCapability`, `allowedActions`,
`deniedActions`, `maximumItems` and `timeoutSeconds` (1-900). Each private field
contains the pinned mapping `field`, destination secret name, exact `version`
and protected baseline `value`. These values and the setup capability never
enter reports or diagnostics. Native source identity must match the family's
existing `observer.identity`; controlled sources require explicit test injection.

The private source uses `rotation-material/open`, `arm`, `authenticate`, `complete`
and `close`. The original local root and cleanup owner exist before Open. Setup
must be independently qualified, owned, terminal and never automatically enabled,
with exact configuration/mapping/material, a complete backend inventory and
accepted/wrong/rechecked administrative controls. This source capability does not
grant the runtime consumer administrative authority.

Mapped material is profile-specific: account/password, DN/password, client
credentials, access keys, single or identified tokens, whole JSON keys and PEM
key pairs cannot share a universal username/password witness. At this authoring
stage all 30 mapping sets are pinned, including Databricks `clientId`/`clientSecret`
and GCP `serviceAccountKey` at Infisical commit
`b44114a1d97e361d6ac55bac15e4b352da6b823c`. GCP material remains one whole JSON
key file, not split key/email fields. All 248 Get/List rows remain.
The host reads actual mapped values under the runtime identity, requires exact
versions and generation coherence, separately checks denied material reads, then
exercises fresh backend authentication, wrong-material rejection, a valid recheck
and the selected allowed/denied actions.

The original read window must settle without configuration, mapping, material or
backend-inventory mutation. Unknown cancellation may reach zero or one original
read; it is not universally pre-send. No replay, late work or pending deliveries
may remain. Close addresses the original root even after lost bootstrap replies
and proves every captured set retired, all owned setup/material/backend resources
absent, private copies destroyed and borrowed state preserved. This read/list
protocol does not certify mutation completion, scheduling, history retirement,
native key lifetime, principal separation or any native deployment.

Runtime rotation mutations can instead select `rotationMutationWitness` in the
same operation/variant/case row. Required fields are `material` (the full private
rotation material input above), `enabled`, and `maximumOriginalDeliveries`
(1-4096). The distinct private source endpoints are `rotation-mutation/open`,
`arm`, `settle`, `authenticate`, and `close`. Source identity must match
`observer.identity`; controlled clocks/sources require explicit test injection.

The original local cleanup root and attempt ID exist before Open. Arm precedes
the only public SDK mutation. CAS/idempotency rejection stays NotDispatched;
denial stays Rejected; response loss/cancellation stays ResponseUnknown even
when independently settled Applied, NonApplied or Partial. These source outcomes
never rewrite or reconcile the caller-held receipt. Actual mapped material,
denied reads, fresh backend controls, complete captured history and qualified
identity/resource retirement are required separately from metadata.

Automatic enable requires committed setting plus an actual qualified scheduled
opportunity and material/backend change. Disable requires settled original and
queued work before a qualified opportunity without change; false is not a drain
operation. Native day-scale opportunities must not be shortened, backdated or
replaced by manual triggers to fit the 1-900-second observation budget. Source
generations are ordinals within the bound epoch, with separate original/queued
delivery counts. Close proves all captured sets retired, complete owned-resource
absence, borrowed preservation and zero pending work, deliveries or registrations.
Native source/image/authority/clock/history qualification remains a separate gate.

DynamicSecrets single-action witnesses select scoped `dynamicPermission` in
`C08-IM-IdentityPrivilegeChanges`, `C08-IM-RoleChanges` or
`C08-IM-ProjectTemplates`. Supply coordinator settings, capability, selected
Read/Create/Edit/Delete/Lease action, timeoutSeconds (1-300), and a profile with
deployment/epoch/revision and six host-pinned journal keys for ownership,
ingress, policy, resources, issuance and backend. Organization and five
authority IDs remain explicit; outer `caseTimeoutSeconds` covers the whole case.
`dynamic-permission/{step,measure}` implements the closed typed protocol.

All five actions across six factories/30 pairs/150 native cases remain. Each
grant must allow its selected action and deny every other action, scope and
principal control. Edit/delete/lease prepare their client-bound definition with
one explicitly selected Setup inspection on the same private client. After that
operation completes, the private token source irreversibly seals to the selected
Runtime/Denied/Observer credential for one measured dispatch. It cannot return
to Setup, reuse failed bootstrap, overlap transitions or fall back after denial.
Measured principals receive no read-root workaround; signed ingress must attest
both actual identities independently of caller labels.

SDK original policy mutation, explicit role assignment and template-name
project copying are followed by fresh definition actions and lease-material
SQL controls. Real original receipts remain immutable through causal settlement.
Host-pinned signatures authenticate complete journal content and terminal
inventories; coordinator transport credentials cannot forge writer evidence.
Root-keyed cleanup recovers partial/lost bootstrap, drains issuance/dispatch
and proves complete resource/lease/credential/SQL absence and borrowed
preservation. Generic factory labels remain unchanged and select the profile's
configured action only when its source is explicitly selected.

Native isolated V2 action prerequisites, inheritance, atomicity, writer/service
provenance and cleanup remain unqualified. Tavily surfaced the permission
migration reference, but extraction was rate-limited. Controlled Linux SQLite
does not establish PostgreSQL/MySQL authentication or Windows support.
When principal, dynamic and metadata profiles share a scope, generic selection
prefers principal, then dynamic, folder, tags, imports and rotation; native
variants retain their own profile.

SecretFolders single-action witnesses select scoped `folderPermission` in
`C08-IM-IdentityPrivilegeChanges`, `C08-IM-RoleChanges` or
`C08-IM-ProjectTemplates`. Supply observer coordinator settings, capability,
Read/Create/Edit/Delete action, timeoutSeconds (1-300) and a profile pinning
deployment/epoch/revision plus five distinct P-256 writer keys for Ownership,
Ingress, Policy, Resources and Issuance. Organization, five authority IDs and
outer `caseTimeoutSeconds` remain explicit. The closed operator route is
`folder-permission/step`.

All 24 retained factory/action pairs and 120 native boundary cases remain.
Six generic factory labels keep their original denominator of 30 boundary
combinations; the controlled suite exercises all 120 action-selected profiles.
Original role/privilege/template SDK mutations, explicit role assignment and
template-name project copying must change actual folder access. Fresh SDK
Get/List/Create/Update/Delete controls compare complete IDs, environment IDs,
names, descriptions, paths, absence and duplicate/completeness witnesses.
Owned setup coordinates do not give mutation-only principals read permission.
Authenticated ingress corroborates the selected credential; whole-content
journal signatures and terminal seals reject coordinator forgery.

Root-keyed lost/partial bootstrap recovery, pre-enrollment, issuer/dispatch
fences and complete terminal resource inventories preserve borrowed state.
Original mutation receipts remain unchanged across denied, pre-send
cancellation and lost Applied/NonApplied/Partial settlement. Private captured
buffers are cleared; ordinary strings are not claimed erased. Native isolated
action prerequisites, parent/child path evaluation, inheritance, atomicity,
writer/coordinator provenance and cleanup remain unqualified.

Tags and SecretImports action witnesses select scoped `tagPermission` or
`importPermission` in the same privilege/role/project-template families.
Each retains four read/create/edit/delete actions, 24 factory/action pairs,
120 native cases and six generic labels/30 boundary combinations. Controlled
generic tests select all 120 action profiles without changing that denominator.
Profiles supply observer/capability/action/timeoutSeconds (1-300) and
deployment/epoch/revision with five distinct P-256 SPKI writers for Ownership,
Ingress, Policy, Resources and Issuance. Organization, five authority IDs and
outer `caseTimeoutSeconds` stay explicit. Closed routes are
`tag-permission/step` and `import-permission/step`.

Tags are project-scoped. Actual SDK Get/List/Create/Update/Delete results and
persisted inventories must match IDs, project, name, slug and color, with
positive read rows and duplicate/missing/substitution controls. SDK tag
condition/inversion gates remain. Import controls compare complete actual
IDs, receiver/source paths and environments, source project, position and
completeness against distinct owned sources. Original policies, role assignment
and template-name project copying must change effective action permissions;
mutation preparation does not grant Runtime read permission.

Imported protected material is tested under explicit Setup/Observer authority
against nonce-owned source bytes. Runtime import grants do not silently grant
secret reads. Additional native secret-read prerequisites remain unqualified.
Material is disposed and private copies cleared before interrupted work; managed
strings and framework/socket copies are not claimed erased. Source and receiver
inventories, signed full-content journals, terminal fences and original-root
recovery reject acknowledgement, forged-coordinator and cleanup-only success.
Original receipts retain causal Applied/NonApplied/Partial uncertainty with no
replay or latest-GET settlement. Native action prerequisites, inherited/default
grants, reserved IDs, atomicity, template inheritance and cleanup remain open.

SecretRotation permission witnesses select scoped `rotationPermission` in the
same privilege/role/project-template families. Six retained actions cover
36 pairs/180 native cases and six generic labels/30 boundaries; controlled
generic checks exercise all 180 configured action profiles. The current owned
configuration shapes are PostgreSQL, MySQL and MSSQL. Each exercises its own
typed configuration and protected credential SDK methods. The controlled profile
matrix has 108 pairs/540 native and 540 generic cases; the admission denominator
remains 36 pairs/180 native cases and six factory labels. Other connector
configuration profiles remain unavailable in this permission unit.

Supply observer/capability/action/timeoutSeconds (1-300), plus profile
deployment/epoch/revision/SqlProfile and six distinct P-256 writers for
Ownership, Ingress, Policy, Resources, Issuance and Backend. Five authority IDs,
organization and outer `caseTimeoutSeconds` stay explicit. The route is
`rotation-permission/step`. The installed native host owns and supplies the
runtime HTTP transport, disables redirects/cookies, preserves native TLS trust
and disposes it with the environment. Missing or non-HTTPS runtime transport
cannot bootstrap a trial. Controlled tests use an explicitly injected HTTPS
facade; native execution does not downgrade HTTPS.

Actual SDK configuration Get/List/Create/Update/Delete and runtime RotateSecrets
must change complete persisted inputs, protected generated credentials and
backend authentication. All three SQL management packages expose typed
GetGeneratedCredentials; it is not replaced with an ordinary secret read.
Role assignment/template-name copying, denied other actions and wrong scope,
connection, principal and credential controls prevent policy acknowledgements
from standing in for access. Causal receipts remain unchanged through denied,
presend cancellation and lost Applied/NonApplied/Partial settlement.

Root-keyed bootstrap recovery, pre-enrollment, signed complete journals, fenced
issuer/backend inventories and borrowed preservation remain required. Private
material/copies clear; ordinary strings/framework copies are not claimed erased.
Controlled Linux SQLite credential authentication does not establish
PostgreSQL/MySQL/MSSQL server login. Native action prerequisites, endpoint
documentation, entitlements, inheritance, atomicity, material retirement,
writer provenance and cleanup remain unqualified.

SecretValidationRules permission inputs select scoped `validationPermission` in
`C08-IM-IdentityPrivilegeChanges`, `C08-IM-RoleChanges` or `C08-IM-ProjectTemplates`.
Supply `Observer`, `Capability`, Project `ScopeProfile`, Machine/User `ActorKind`,
`Action`, `TimeoutSeconds` (1-300), organization and five distinct authority IDs.
`Profile` binds deployment/epoch/revision and nine distinct host-pinned P-256
writers: Ownership, Ingress, Policy, Storage, Issuer, Membership, Access,
Enforcement and Backend, each binding writer/channel/schema/SPKI.
The closed `validation-permission/step` response uses `brotli-base64-v1`
with a base64 `content` field; decoded complete histories are bounded to 8 MiB.
The shared observer response limit is unchanged.

Actual runtime rule CRUD, independent rule revision/configuration evidence,
secret-write authorization, constraint decisions and backend commits must join
on exact actor credential, scope, protected input and parent request.
The enforcement actor is separate from the policy actor; no extra rule or
secret grant is supplied to make an exercising actor pass. Complete append-only
histories survive response loss and cleanup. Provider regex execution is not
SDK behavior, and configuration echoes or HTTP status alone prove neither
enforcement nor committed state.

The authored profile is bounded to static secret rules and typed allowed/
violating secret writes. Six factory labels retain 24 pairs/120 native plus120
configured generic cases; dynamic/rotation kind and provider-specific effects
remain unqualified. Recovery retained before Reserve/Open fences and drains
issuer, dispatch, enforcement and backend work, verifies complete inventories
and borrowed preservation, and clears owned buffers.
Native independent writer enrollment, enforcement and backend guarantees remain
unqualified. The integrated controlled validation matrix passes 2,008 cases;
these inputs do not establish a native pass.

ProxiedServices permissions select scoped `proxyPermission` in
`C08-IM-IdentityPrivilegeChanges`, `C08-IM-RoleChanges` or `C08-IM-ProjectTemplates`.
Supply `Observer`, `Capability`, Project `ScopeProfile`, Machine/User `ActorKind`,
`Action`, `TimeoutSeconds` (1-300), organization and five distinct authority IDs.
`Profile` binds deployment/epoch/revision and eight distinct host-pinned P-256
writers: Ownership, Ingress, Policy, Storage, Issuer, Membership, Access and
Collection, each binding writer/channel/schema/SPKI.
The closed route is `proxy-permission/step`.

Credential IDs are aggregate-owned versioned configuration metadata. Canonical
service/resource bindings keep injective requests and commits; complete ordered
collection histories bind protected input, parent/service, revision and slot to
active/deleted inventories and retirement records. Retained and replaced IDs
are both observed without assuming native allocation policy. Typed SDK readback,
independent collection/storage evidence and exact destination/environment/path
joins must agree. Controlled support covers two static credential-substitution
entries with protected placeholders and explicit header/query surfaces, not
every credential or authentication profile.

All six factories retain 36 pairs/180 native plus180 configured generic cases.
CRUD supports 24 pairs/120 native plus120 generic cases; proxy/report-usage
retain twelve pairs/60 native plus60 generic explicit missing-seam gates.
`canProxy` metadata is not tunneled delivery or trusted usage reporting.
Root recovery precedes Reserve/Open, including committed requests whose IDs
never returned. Cleanup fences/drains work, verifies complete collection
retirement and owned inventories, preserves borrowed resources and clears owned
buffers. Native lifecycle, retirement completeness, observer independence,
runtime routing and usage reporting remain unqualified.

Gateway permissions select scoped `gatewayPermission` in `C08-IM-RoleChanges`.
Supply `Observer`, `Capability`, Organization `ScopeProfile`, User `ActorKind`,
`Action`, `TimeoutSeconds` (1-300), organization and five distinct authority IDs.
`Profile` binds deployment/epoch/revision and eight distinct host-pinned P-256
writers: Ownership, Ingress, Policy, Storage, Issuer, Membership, Access and
Configuration, each binding writer/channel/schema/SPKI.
The closed route is `gateway-permission/step`.

Canonical gateway bindings are immutable; native authentication config IDs are
observed revision metadata. Retained-ID and replaced-ID updates both require
independent parent/request/storage provenance, complete revision history,
inventory and retirement records. No allocation or lifetime guarantee is
assumed. Typed Get supplies fresh projection readback, not list certification.
Controlled support covers explicit AWS account and principal allowlists and
rename/config replacement; other authentication profiles, omission/clearing,
cross-method updates and actual agent authentication remain unqualified.

Both organization-role factories retain all twelve pairs/60 native plus60
configured generic cases. Create/edit support four pairs/20 native plus20 generic
cases. List/delete/attach/revoke retain eight pairs/40 native plus40 generic
explicit missing-seam gates. Recovery retained before Reserve/Open, root-only
loss compensation, complete fenced/drained inventories, configuration retirement,
borrowed preservation and owned-buffer clearing remain required.
Native writer independence, lifecycle completeness, deployment authority and
agent effects remain unqualified.

Settings permissions select scoped `settingsPermission` in
`C08-IM-IdentityPrivilegeChanges`, `C08-IM-RoleChanges` or `C08-IM-ProjectTemplates`.
Supply `Observer`, `Capability`, `Profile` deployment/epoch/revision and seven
distinct P-256 writer pins for Ownership, Issuer, Storage, Policy, Membership,
Ingress and Access. Each pin binds writer/channel/schema/SPKI;
the schema is `settings-history-v1`. Supply Project/Organization `ScopeProfile`,
Machine/User `ActorKind`, `Action`, `TimeoutSeconds` (1-300), organization and
five distinct authority IDs. The closed source route is `settings-permission/step`.

Only the bounded project Settings.edit profile is supported. It uses the actual
typed project PATCH to change name, slug and description on owned SecretManager
projects. Four distinct issued actor/credential slots exercise selected,
wrong-project, wrong-actor, wrong-kind and wrong-credential controls. Independently
persisted complete configuration, including workflow and unprojected digests,
must match each request's authorization and commit. Observer-only typed reads by
ID and slug corroborate exposed fields; missing SDK fields are not inferred
from a mutation response. Unselected configuration must remain unchanged.

Complete cumulative histories bind raw input, canonical allocations, issuance,
request-position policy/membership and configuration changes. Template copies
need actual configuration provenance and separate canonical bindings. Root
cleanup is retained before Reserve/Open and requires terminal count/head seals,
fencing, drained work, complete owned retirement and borrowed preservation.
All 32 pairs/160 native plus160 configured generic rows remain. Six project edit
pairs/30 plus30 are supported; the other26 pairs/130 plus130 remain explicit
gates. Organization settings changes and general settings read/create/delete
are not supplied by this witness. Native writer enrollment and deployment
effects remain unqualified; managed strings/framework copies are not erasable.

MachineIdentityAuthTemplate permissions select scoped `authTemplatePermission`
in `C08-IM-RoleChanges`. Configured generic execution keeps its original
`factory.*` label and resolves the selected organization-role factory and action;
project-role admission is not expanded. Supply `Observer`, `Capability`, `Profile`
deployment/epoch/revision, `Action`, `TimeoutSeconds` (1-300), organization and
five distinct authority IDs. Eight independent P-256 pins bind Ownership, Issuer,
Storage, Policy, Membership, Ingress, Access and Collection writer/channel/schema/
SPKI. The closed source route is `auth-template-permission/step`.

The typed search exercises `list-templates`; auth-method-filtered available
listing exercises `attach-templates`. List-only actors must fail available
listing, and attach-only actors must fail search. Both require the selected owned
row, not an empty successful response. Available listing proves neither actual
attachment nor authentication or template propagation. Organization scope comes
from independently observed authenticated actor context, not the SDK organization
argument alone.

Typed Kubernetes-template create/edit/delete witnesses use persisted configuration
and unchanged peer state, separate observer readback and distinct actor,
organization, kind and credential controls. Complete cumulative signed histories
bind raw inputs to canonical allocation, request-position policy/membership,
authorization, storage changes and collections. Cleanup is retained before
Reserve/Open and requires terminal count/head seals, fencing, drained work,
complete owned retirement and borrowed preservation.

All 12 pairs/60 native plus60 configured generic cases remain. Five actions/
10 pairs/50 plus50 cases have local witnesses. `unlink-templates` remains gated
before enrollment: the researched service return does not establish the array
required by the existing typed response. No response is synthesized. Native
deployment, entitlement, writer enrollment and operational independence remain
unqualified.

Integrations permissions select scoped `integrationPermission` in
`C08-IM-IdentityPrivilegeChanges`, `C08-IM-RoleChanges` or `C08-IM-ProjectTemplates`.
Supply `Observer`, `Capability`, `Profile` deployment/epoch/revision and eight
distinct P-256 writer pins for Ownership, Issuer, Storage, Policy, Membership,
Ingress, Access and Collection. Each pin binds writer/channel/schema/SPKI;
the schema is `integration-history-v1`. Supply Project `ScopeProfile`,
Machine/User `ActorKind`, `Action`, `TimeoutSeconds` (1-300), organization and
five distinct authority IDs. The closed source route is
`integration-permission/step`.

The bounded READ profile uses actual typed `ListIntegrations` metadata.
Rows do not attest project/organization scope: independent canonical allocation,
storage and collection evidence establishes the selected project. The source
retains complete ordered cumulative histories, including intermediate policy
and membership revisions, credential issuance and object retirement. Each
publication seals its terminal count/head; authorization joins policy and
membership at the request's position, not just their final state.

Template copying requires actual configuration provenance and separately bound
project, role, environment, membership and role-assignment resources. Recovery
is retained before Reserve/Open, fences and drains work, and verifies complete
owned retirement, borrowed preservation and erasure of owned credential buffers.
All 24 pairs/120 native plus120 configured generic rows remain. Only six READ
pairs/30 plus30 rows are supported; 18 mutation pairs/90 plus90 remain gated.
Synchronization, delivery, connector-credential use and native writer independence
remain unqualified. This local controlled witness is not native certification.

Workspace permissions select scoped `workspacePermission` in
`C08-IM-IdentityPrivilegeChanges`, `C08-IM-RoleChanges` or `C08-IM-ProjectTemplates`.
Supply `Observer`, `Capability`, `Profile` deployment/epoch/revision and seven
distinct host-pinned P-256 writers for Ownership, Ingress, Policy, Storage,
Issuer, Membership and Access, binding writer/channel/schema/SPKI.
Supply Project/Organization `ScopeProfile`, Machine/User `ActorKind`, `Action`,
`TimeoutSeconds` (1-300), organization and five distinct authority IDs.
The closed source route is `workspace-permission/step`.

Project delete and organization create use actual typed project lifecycle
operations. Project Workspace.edit remains gated: the typed project settings
PATCH requires Settings.edit and cannot prove Workspace.edit.
An empty policy baseline permits denied before-probes without
destroying the scope. Authorized deletion runs last: exact predispatch
policy/actor/credential/membership evidence joins independently sealed project
and dependent-resource absence. Canonical bindings remain immutable tombstones;
recreating or rebinding scope is rejected. Organization actors/credentials,
templates, other projects and borrowed resources must remain intact.

Independent persisted configuration and inventory evidence covers the explicit
bounded creation defaults, not all SDK variants. Template copies require actual
policy/configuration provenance. Recovery is retained before Reserve/Open;
root-only compensation fences and drains work and proves complete owned cleanup
and borrowed preservation. Original receipts remain immutable; only owned
buffers are claimed cleared. Fourteen pairs/70 native plus70 configured generic
cases remain across all eight factories, with scope-legal actions only.
Six edit pairs/30 native plus30 configured generic cases remain explicit gates;
the bounded create/delete profile retains eight pairs/40 plus40 cases.
Native cascades, template copying, settings/defaults, source independence and
deployment authority remain unqualified.

AuditLogs permissions select scoped `auditPermission` in
`C08-IM-IdentityPrivilegeChanges`, `C08-IM-RoleChanges` or `C08-IM-ProjectTemplates`.
Supply `Observer`, `Capability`, Project/Organization `ScopeProfile`,
Machine/User `ActorKind`, `Action`, `TimeoutSeconds` (1-300), organization and
five distinct authority IDs. Supply ordered `From`/`Until` (at most ten minutes)
and `RetainUntil` after Until (at most thirty days). `Profile` binds deployment,
epoch, revision, borrowed-history hash and eight distinct host-pinned P-256
writers: Ownership, Ingress, Policy, Storage, Issuer, Membership, Access and
Publisher. Each pin binds writer/channel/schema/SPKI.

The closed `audit-permission/step` source joins typed SDK seed requests,
authenticated ingress, producer commits, publication events and independently
issued canonical audit rows. Complete contiguous publication censuses, terminal
fences/seals and exact storage inventories must agree. Typed bounded
`ReadAudit` pages validate every row and the complete census; omitted actor/event
metadata cannot prove causality. No observer-only trigger or timestamp
correlation substitutes for independent publication evidence.

Recovery retained before Reserve/Open closes by the original root, drains
producer/publication/issuer/dispatch work and removes mutable owned resources.
Audit rows remain bounded, sealed historical residue under explicit retention
authority; no audit-row DELETE is invented. Borrowed history is preserved.
Original receipts stay immutable, and only owned buffers are claimed cleared.
Eight read pairs/40 native plus40 generic cases are locally supported.
Eight edit pairs/40 native plus40 generic cases remain explicit gates: primary
permission tables list read only, so edit is not mapped to audit-settings PUT.
Native writer independence, publication completeness, collateral inventory,
entitlement, retention and cleanup remain unqualified.

Environments action permissions select scoped `environmentPermission` in
`C08-IM-IdentityPrivilegeChanges`, `C08-IM-RoleChanges` or `C08-IM-ProjectTemplates`.
Supply `Observer`, `Capability`, `Profile` deployment/epoch/revision and seven
distinct host-pinned P-256 writers for Ownership, Ingress, Policy, Storage,
Issuer, Membership and Access, binding writer/channel/schema/SPKI.
Supply Project `ScopeProfile`, Machine/User `ActorKind`, `Action`,
`TimeoutSeconds` (1-300), organization and five distinct authority IDs.
The closed route is `environment-permission/step`.

Actual typed environment Create/Get/GetBySlug/Update and explicit permanent
Delete must agree with independently signed full storage and active/deleted
`GetProject` inventories. Name, slug, position, deletion metadata, project,
policy actor and canonical target bindings must agree; policy acknowledgements
alone do not prove enforcement. Soft-delete/restore variants are not qualified.
Immutable creation intents precede independently attested canonical bindings.
Recovery retained before Reserve/Open compensates unreturned bindings; Close
fences and drains work, verifies complete inventories and borrowed preservation,
and clears owned credential buffers. No exercising-actor secret-read grant or
response replay is permitted.

Six project factories retain 24 pairs/120 native cases and 120 configured-action
generic cases. Organization-role factories are not included. Native enforcement,
user issuance, source instrumentation, deployment authority and cleanup remain
unqualified.

Role action permissions select scoped `rolePermission` in
`C08-IM-IdentityPrivilegeChanges`, `C08-IM-RoleChanges` or `C08-IM-ProjectTemplates`.
Supply `Observer`, `Capability`, `Profile` deployment/epoch/revision and seven
distinct host-pinned P-256 writers for Ownership, Ingress, Policy, Storage,
Issuer, Membership and Access. Each pin binds writer, channel, schema and SPKI.
Supply explicit Project/Organization `ScopeProfile`, Machine/User `ActorKind`,
`Action`, `TimeoutSeconds` (1-300), organization and five distinct authority IDs.
The closed route is `role-permission/step`.

Original grant roles/privileges/templates and downstream target roles are
separate resources. Actual typed project/organization role Get/Create/Update/
Delete and List operations must agree with complete independently signed
target name/slug/description/permission fingerprints and scope/actor bindings.
Native role lists omit permissions; fresh typed reads check available
projections, while full storage journals supply independent persisted state.
Unprojected conditions remain unqualified. Target-role CRUD must not overwrite
the policy actor's grant.

Immutable root-bound creation intents precede canonical IDs, which are bound
only at commit through independent issuance/storage journals. Recovery retained
before Reserve/Open reconciles unreturned bindings after lost/partial Open.
Close fences and drains work, checks complete owned inventories and borrowed
preservation, and clears owned credentials. No exercising-actor secret-read
grant or response replay is permitted.

All eight factories retain 32 pairs/160 native cases and 160 configured-action
generic cases. Project and organization scopes each support read/create/edit/
delete; generic labels retain all eight factories and prior shared-scope
selection precedence. Native user issuance, role enforcement, source
instrumentation, deployment authority, entitlement and cleanup remain unqualified.

Organization ProjectTemplates permissions select scoped
`projectTemplatePermission` in `C08-IM-RoleChanges`.
Supply `Observer`, `Capability`, `Profile` deployment/epoch/revision and seven
distinct host-pinned P-256 writers for Ownership, Ingress, Policy, Storage,
Issuer, Membership and Access. Each pin binds writer, channel, schema and SPKI.
Supply `Action`, `TimeoutSeconds` (1-300), organization and five distinct
authority IDs. The closed route is `project-template-permission/step`.

CreateOrganizationRole and UpdateOrganizationRole grant the selected CRUD
action to an explicitly issued user with independently authenticated organization
membership and exact role binding. Actual typed template Get/Create/Update/Delete
and complete List readback must prove persisted closed-canary configuration
and authorization, not just a role or template acknowledgement. Canonical
template IDs bind to pre-enrolled root intents only at commit; recovery retained
before Reserve/Open reconciles unreturned bindings after lost/partial Open.
Close fences and drains work, checks complete owned inventories and borrowed
preservation, and clears owned credentials. No exercising-actor secret-read
grant or response replay is permitted.

All eight pairs/40 native cases and 40 configured-action generic cases remain;
generic labels retain the two organization-role factories. This subject is
separate from project template policy factories and principal-bearing template
configuration. Native user issuance, role enforcement, source instrumentation,
deployment authority, entitlement and cleanup remain unqualified.

Identity action permissions select scoped `identityPermission` in
`C08-IM-IdentityPrivilegeChanges`, `C08-IM-RoleChanges` or `C08-IM-ProjectTemplates`.
Supply `Observer`, `Capability`, `Profile` deployment/epoch/revision and nine
distinct host-pinned P-256 writers for Ownership, Ingress, Policy, Storage,
Issuer, Membership, Access, Capture and TokenState. Each pin binds writer,
channel, schema and SPKI. Supply explicit Project/Organization `ScopeProfile`,
Machine/User `ActorKind`, `Action`, `TimeoutSeconds` (1-300), organization and
five distinct authority IDs. The closed route is `identity-permission/step`.

Policy actor credentials are fixed after Open; affected-identity tokens have
separate mutable inventories, append-only issuance history and authenticated
capture/state transitions. Exact original request, root intent, canonical ID,
issuer commit, storage and protected credential bindings must agree. Fresh
actual SDK identity-canary probes distinguish authentication/invalidation from
scope denial; target-only read policies never grant reads to the exercising
actor. Token metadata, acknowledgements, a 403 response or an erased local
copy alone do not prove revocation. No ordinary secret-read workaround or login
replay is permitted.

Organization identity CRUD and project identity membership/detail/role/
additional-privilege changes use their actual typed SDK scope selectors.
Explicit Universal/token auth configurations provide bounded authentication
canaries; one strategy does not qualify every provider strategy. Immutable
root-bound logical intents precede creation; independently pinned issuer/storage
bindings attest generated canonical IDs only at commit. Recovery and cleanup
use the original root even after lost/partial Open. Close fences and drains
issuance/capture work, reconciles canonical bindings, revokes owned tokens and
checks authentication invalidation and complete inventories with borrowed
resources preserved.

All eight factories retain 98 pairs/490 cases. Exact typed seams support
86 pairs/430 cases; project legacy grant-privileges and assumption remain gated
at 12 pairs/60 cases. Six generic labels select the configured action and
preserve prior shared-scope selection precedence. Native source instrumentation,
provider authentication/scope enforcement, deployment authority, entitlement
and cleanup remain unqualified. Owned material buffers are cleared; immutable
strings/framework/socket copies are not claimed erased.

Groups action permissions select scoped `groupPermission` in
`C08-IM-IdentityPrivilegeChanges`, `C08-IM-RoleChanges` or `C08-IM-ProjectTemplates`.
Supply `Observer`, `Capability`, `Profile` deployment/epoch/revision and seven
distinct host-pinned P-256 writers for Ownership, Ingress, Policy, Storage,
Issuer, Membership and Access. Each pin binds writer, channel, schema and SPKI.
Supply explicit Project/Organization `ScopeProfile`, Machine/User `ActorKind`,
`Action`, `TimeoutSeconds` (1-300), organization and five distinct authority IDs.
Identity-privilege actors remain machines; role/template actors are explicitly
issued users. The closed route is `group-permission/step`.

The immutable enrollment contains root-bound logical creation intents, not
predicted provider IDs. Independent issuance/storage journals bind each intent
to its canonical ID at commit, with exact scope, normalized inputs, dependency
IDs, issuer work, request and commit. Bindings are injective, append-only and
exclude borrowed IDs. Reserve contains no canonical bindings. Recovery retains
the original root before Reserve/Open and can reconcile unreturned bindings
after lost/partial Open; no singleton/name-only GET or response replay establishes
ownership. Close fences and drains issuer/dispatch work before reconciliation
and terminal inventories.

Actual typed project group membership read/add/remove/role operations and
organization group CRUD/user/identity membership operations provide independent
action witnesses. Project create links an existing group; organization create
creates a group. Delegation conditions bind supported group name and role
selectors. Original policy receipts stay unchanged through causal settlement;
policy acknowledgement alone cannot prove actor assignment or template copying.

All eight factories retain 54 pairs/270 cases. Exact typed seams support
42 pairs/210 cases; project group-details editing and legacy grant-privileges
remain gated at 12 pairs/60 cases. Six generic labels select their configured
action, retaining prior shared-scope selection precedence. Source-absent
organization Groups.read retains its existing canary path. Native journal
instrumentation, generated-ID recovery authority, provider authentication,
scope enforcement, entitlements and cleanup remain unqualified. Owned buffers
are cleared; immutable strings/framework/socket copies are not claimed erased.

Member action permissions select scoped `memberPermission` in
`C08-IM-IdentityPrivilegeChanges`, `C08-IM-RoleChanges` or `C08-IM-ProjectTemplates`.
Supply `Observer`, `Capability`, `Profile` deployment/epoch/revision and seven
distinct host-pinned P-256 writers for Ownership, Ingress, Policy, Storage,
Issuer, Membership and Access. Each pin binds writer, channel, schema and SPKI.
`ScopeProfile` is explicitly Project or Organization; `ActorKind` is Machine
for identity-privilege factories and User for role/template factories. Supply
`Action`, `TimeoutSeconds` (1-300), organization and five distinct authority IDs.
The closed private route is `member-permission/step`.

Policy actors and affected users have separate credential/identity/membership
joins. A user ID never substitutes for an identity-privilege target. Original
policy dispatch and role/template activation use actual typed SDK operations;
project creation from a template selects its name, not its ID. Fresh typed
membership reads, invitations, removal and role/activation changes must agree
with authenticated complete policy, storage, issuance and access journals.
Wrong actor kind, credential, scope, member joins and delegation conditions
fail independently of policy acknowledgements. Unconditioned project CRUD
does not imply a member-specific restriction; only supported delegation
conditions provide that restriction.

All eight factories retain 58 pairs/290 cases. Exact typed downstream seams
support 32 pairs/160 cases: project read/create/delete/assign-role, and
organization read/edit/delete/grant-privileges. Project member-details edit,
legacy permission-level grants, user additional privileges, temporary
assumption and organization invitation remain explicit typed-seam gates,
totalling 26 pairs/130 cases. Generic factories retain their labels and select
the configured action. Other permission profiles keep their existing selection
precedence when sharing a scope.

Root recovery precedes Reserve/Open; resources and issuer work are enrolled
before creation. Original receipts remain unchanged through causal settlement;
incomplete policy application is not treated as a full effective-policy pass.
Close fences and drains work, checks complete owned inventories and borrowed
preservation, and clears owned credential buffers. Native user issuance,
writer independence/completeness, provider enforcement, entitlement and cleanup
remain unqualified. Immutable strings/framework/socket copies are not claimed
erased.

Interrupted authentication selects scoped `authIssuance` in
`C08-IR-InfisicalUniversalAuthentication` or `C08-IR-InfisicalProofAuthentication`.
Supply `Observer` endpoint/token/identity/timeout, `Capability`,
`ObserverIdentity`, and `Profile` deployment/epoch/revision with seven distinct
host-pinned P-256 writers for Ownership, Ingress, Issuer, Delivery, Metadata,
Capture and Access. Each pin binds writer, channel, schema and SPKI public key.
The closed routes are `authentication-issuance/step` and private
`authentication-issuance/capture`; capture material never enters ordinary reports.

Recovery is retained before Reserve/Open and fixture bootstrap. The original
caller-held login receipt is armed before dispatch and stays PossiblyDispatched
after interruption. Applied requires sealed issuer commitment, exact
credential/identity/method/metadata/state joins and fresh SDK allowed/denied
reads with privately captured material. NonApplied requires sealed absence of
commitment and a terminal no-late-commit fence. Missing capture is unavailable,
wrong joins fail, and Partial remains gated because the public login contract
does not establish an independently observable incomplete issuer transition.
No login replay, token-row inference or fallback credential is permitted.

Close drains issuer/capture/delivery work, revokes owned credentials, checks
complete inventories and borrowed preservation, and releases owned material
and keys before normal fixture teardown. Immutable strings/framework/socket
copies are not claimed erased. The controlled unit exercises all21 retained
pairs across42 interruption cases, including host-mTLS with actual TLS peer
presentation and Applied/NonApplied controls. Its denied-certificate control
must leave no issued credential. The host-only fixture pins its ephemeral
server in the proof handler; setup/observer resources use an explicit separate
loopback control origin on the same owned backend. Native JSON cannot select
that fixture seam, and ordinary native server trust is unchanged.
All21 pairs/105 cases remain in admission; the other63
boundaries retain existing expiry/denial paths. Native writer independence,
completeness, issuer instrumentation, capture deployment, proof validity and
cleanup remain unqualified.

Principal-bearing templates select scoped `templatePrincipal` in
`C08-IM-ProjectTemplates`. Supply coordinator endpoint/token/identity, issuance
capability, timeoutSeconds (1-300), Values/Empty shape, and a profile with
deployment/epoch/provider revision and six distinct host-pinned P-256 writers.
Each pin binds writer, channel, schema and public key to ownership, ingress,
template, issuer, membership or access. Organization and five authority IDs
remain explicit; outer `caseTimeoutSeconds` covers the complete case.
`template-principal/step` consumes the closed reservation, issuance, observation,
original mutation, settlement and cleanup sequence.

The 15 retained pairs/75 native cases cover users, groups and project-managed
identities with omitted/value selections and Update null alternatives. Thirty
empty-collection selections remain under `.value`. Both generic factory labels
retain their names and select `users.value` only with the principal profile.
If metadata and principal profiles share a scope, this generic selection prefers
the principal profile; native metadata variants still select their own profile.
Setup uses explicit group enrollment and template-name project instantiation;
managed identities obtain actual SDK-issued tokens. Copied role differences,
fresh user/group/managed reads, wrong principal, denied and valid rechecks
distinguish effective membership from template DTO echo.

The original recovery root precedes reservation. Creation plans and issuer work
are enrolled before resources exist; root-keyed cleanup recovers lost/partial
Open, seals issuance/dispatch, inventories tokens/resources and preserves
borrowed authority. Pinned signatures authenticate complete journal content,
not writer correctness or independence of deployed services. Native issuance,
entitlements, omission/null/default policy, writer provenance and coordinator
guarantees remain unqualified. Captured-byte release does not erase exported
managed strings.

Dynamic metadata permissions select scoped `metadataPermission` in
`C08-IM-IdentityPrivilegeChanges`, `C08-IM-RoleChanges` or
`C08-IM-ProjectTemplates`. Supply observer endpoint/token/identity, capability,
subject, operator, timeoutSeconds (1-300), and a profile with deployment, epoch,
provider revision and six host-selected P-256 SPKI pins. Each pin binds a
distinct writer, channel, schema and journal: ownership, ingress, storage,
policy, issuance or backend. Organization and five identity IDs remain explicit;
outer `caseTimeoutSeconds` covers the complete case.

`metadata-permission/step` consumes the closed Reserve/Open/Before/ObserveBefore/
Arm/Settle/After/ObserveAfter/Close sequence. `metadata-permission/measure`
performs only the typed Select/WrongCredential/ForbiddenWrite/Recheck actions.
The coordinator channel cannot replace journal authentication: signatures cover
complete typed content and the root hash; independently signed terminal seals
prevent record omission. Responses cannot announce or replace trusted keys.
Pinned-writer compromise and implementation correctness still require independent
operator qualification.

All eight metadata pairs/40 native cases and six generic labels/30 cases are
retained. Seven comparisons cover equality, inclusion, inequality, empty match,
empty key/value comparisons and empty inclusion. Actual role/privilege/template
mutations, explicit role assignment and template-to-project copying lead to
fresh SDK SQL leases and protected backend reads. Matching entries are separated
from key-only, value-only, split-entry and cross-scope controls. Static secret
metadata does not substitute for this action; certificates remain gated.
Original receipts, causal settlement, full lease/token/resource cleanup and
borrowed preservation remain separate authenticated obligations.

Controlled backend tests require host SQLite and exercise its native SQL
authorizer. They do not establish PostgreSQL/MySQL authentication conformance;
Windows/macOS SQLite loading is unverified. No SQLite dependency enters the SDK.
Native writers, keys, coordinator, metadata semantics, clocks and cleanup
qualification remain open. Existing workload coordinator trust is unchanged.

Workload reviewer/template transitions select scoped `workloadTransition` in
`C08-IM-WorkloadIdentityAuthentication`. Supply `observer` endpoint/token/identity,
`capability`, `timeoutSeconds` (1-300) and `profile`: revision, deployment,
epoch and five distinct writer/schema records for ingress, storage, reviewer,
issuance and access journals. The profile explicitly qualifies copied-template
retention, reviewer-null client fallback and omitted-reviewer client fallback.
These flags do not substitute for independent causal measurements. Organization
and five identity IDs remain alongside the profile; outer `caseTimeoutSeconds`
(1-900) covers the complete case.

`workload-transition/{reserve,open,begin,observe,arm,settle,close}` binds the
preexisting recovery root and nonce to independently recorded original ingress,
configuration revision, reviewer authentication, proof issuance and access.
Complete original intent fingerprints come from received SDK mutations, not
invented SDK request IDs. Parent event edges establish causality; timestamps and
latest GET do not. Terminal fences classify Applied/NonApplied/Partial while
preserving the caller's actual receipt. Signed proofs, HTTP TokenReview and
fresh issued-token SDK reads contrast old/new/wrong proofs, principal permissions
and client fallback.

All 12 factories/256 label pairs/1,266 cases remain. This optional slice executes
22 pairs/110 cases. Empty-static acceptance remains gated for 2 pairs/10 cases,
and the existing rejected-clear pair retains its five cases. Generic factory
labels remain intact and choose an owned transition only with the scoped profile.
Cleanup recovers original-root partial/lost bootstrap, fences enrolled issuer
work and dispatch, inventories every captured token/resource and preserves
borrowed state. Controlled source evidence requires explicit injection.
Native journal writers, coordinator, semantics, revisions, clocks and cleanup
remain unqualified; null/clear/default behavior is not certified by local tests.

Owned project-type inventory witnesses select scoped `projectType` in
`C08-IM-Projects`. Supply `observer` endpoint/token/identity, `capability`,
`deployment`, `epoch`, `providerRevision` and `timeoutSeconds` (1-300), with the
organization and five explicit identity IDs. Outer `caseTimeoutSeconds` (1-900)
covers the complete case. The closed source routes are
`project-type/{reserve,open,begin,observe,arm,settle,close}`.

The retained cleanup root/nonce precedes reservation and provisioning. Project,
role and pending issuer IDs must enter the root's recoverable inventory before
creation. Each selected profile needs at least two owned projects of each of
the six retained kinds, with independent type/field/role inventory and borrowed
preservation. Complete fresh SDK inventories, positive matching-type witnesses,
wrong-type exclusions, role inclusion/omission, denied reads and valid rechecks
are compared with independent storage and authenticated access journals.
The source prearms and fences 0-1 exact original GET requests; it does not
invent a mutation receipt or admit readonly lost-response.

All 10 ListProjects variants/40 native cases and the generic factory's default
`type.SecretManager` are retained. Cleanup seals provisioning and dispatch,
recovers partial/lost Open without returned IDs, and requires full owned absence
and borrowed preservation. Controlled evidence requires internal injection.
Native provisioning, inventory coordinator, revision, entitlements, clocks and
cleanup remain unqualified. The public list reference currently omits
AgentVault from its query enumeration; that retained SDK branch needs explicit
deployed-revision qualification.

Fresh organization-user membership witnesses select scoped `organizationUser`
in `C08-IM-OrganizationMemberships` or, for batch deletion,
`C08-IM-MembershipMutations`. Supply `observer` endpoint/token/identity,
`capability`, `deployment`, `epoch`, `providerRevision` and `timeoutSeconds`
(1-300), alongside the organization and five explicit authority IDs. The
scope's outer `caseTimeoutSeconds` (1-900) must cover the complete case. The observer and
private issuer have separate authority; issued user credentials, not the
preexisting runtime-role token, drive fresh downstream SDK group reads.

`organization-user/{reserve,open,begin,observe,arm,settle,close}` implements the
closed source contract. Cleanup retains a host root/nonce before reservation.
Every issued user/credential/membership/role/canary and pending issuer work
must be transactionally enrolled before creation; close recovers the complete
inventory without relying on identifiers in a lost Open response. Creation and
dispatch fences prevent resurrection, replay and late delivery. Exact credential
bytes join to the user and membership independently of SDK responses and labels.
Before/after full membership inventories and fresh allowed/wrong/denied/valid
rechecks attest role/activity and access separately. Actual original mutation
receipts remain immutable; partial settlement is classified and cleaned without
being promoted to native success.

All 10 native variants/49 cases remain: 8/39 locally supported, both metadata
variants/10 cases gated. Four generic factories share the typed handlers;
readonly lost-response remains gated. Controlled source evidence requires
explicit injection. Native issuer transactionality, credential joins, clocks,
permissions, service provenance and cleanup remain unqualified, as do metadata
readback and a native-valid partial-batch trigger.

Bulk auxiliary persistence can select `auxiliaryWitness` in the existing
`C08-IR-NativeBulk` operation/variant/case input. It carries typed `bulk`,
protected `baseline`/`expected` full rows, `providerRevision`, `deploymentId`,
`sourceProfile`, `rootNonce` and `timeoutSeconds` (1-300). The authenticated
family `bulkAuxiliaryObserver` supplies the private service; controlled evidence
requires explicit injection. `bulk-auxiliary/open`, `complete`, `observe` and
`close` bind the original origin/scope/identity/method/batch shape and cleanup
owner before Open, check initial namespace absence, then independently fence
the original request before storage readback.

The source proves full plaintext bytes/field sets and separately measured
encrypted representation/authenticated decryption, including comment, metadata,
tags, restricted creation annotations, multiline behavior, nullable reminders,
versions and material. Actual SDK material/inventory and denied controls remain
separate. Omit, empty, clear, rename and batch modes are not interchangeable.
Cleanup requires complete owned absence, borrowed preservation, no pending/late
work/replay and released private copies. All 58 variants/290 cases remain:
50/250 locally supported, 8/40 personal/approval/unobserved-result branches
explicitly unavailable. Native persistence/defaults/encryption/source provenance
and annotation semantics remain unqualified.

SPIFFE HTTPS bundle refresh retains the original external-auth scope and adds
optional `families.ExternalIdentityAuthentication.spiffeRefresh`. It supplies
observer settings, deployment, exclusive capability, source kind,
`providerRevision`, trusted HTTPS `bundleEndpoint`, protected `caCertificate`,
`trustDomain`, `spiffeId`, `audience`, and distinct old/new/wrong-key/wrong-domain/
wrong-audience JWTs. Controlled sources require explicit injection. Static refresh
and immediate old-key retirement are not established; this witness uses an
explicitly selected old/new overlap distribution.

Private endpoints `spiffe-refresh/open`, `arm`, `settle`, `proof` and `close`
bind the original root/nonce/scope/case/revision and cleanup owner before Open.
Arm independently qualifies the issuer/cache, exclusive original window and
autonomous-refresh exclusion. Original request/fetch/cache commits, no foreign/
pending/late work or replay, actual old/new issuer proof exchanges, issued policy,
intended canaries and complete owned cleanup are required. Unchanged cache
timestamps and configuration acknowledgements cannot qualify refresh. Native
source, ingress fencing, rights/entitlements, HTTPS trust and window/clock
qualification remain separate; private inputs never authorize native clock
shortening/backdating or replay.

Management TLS certificate authentication uses the selected external-auth scope's
`issuers.tls-cert`. `configuration` carries protected PEM `caCertificate`,
`allowedCommonNames`, `allowedSubjectAltNames`, measured deployment policy
`defaultTTL`/`defaultMaxTTL`/`defaultUses`, and nullable omission defaults
`defaultAllowedCommonNames`/`defaultAllowedSubjectAltNames`. `allowed` and `denied`
carry only `certificate:{pkcs12Base64,password}`, optional `organizationSlug`
and bounded public `intermediatesPem`. Contrasting updates require
`baselineParameters` and `baselineAllowed`, not identical copies.

Valid and denied leaves must complete real TLS; denial is an application result.
Imported certificates/keys and proof handlers remain isolated from management,
observer, cleanup and runtime-token transports until calls settle. Native HTTPS
server trust and mTLS forwarding are not changed by private input. Observer GET
proves protected plaintext CA persistence; mutation CA remains write-only and
encrypted CA stays opaque. Issued material accesses protected canaries separately
from explicit setup/admin/observer/denied roles. All 65 labels/321 cases remain:
55/273 authored, with encrypted-CA/trusted-IP projections and two trusted-IP
enforcement labels retaining explicit gates. Native trust, principals, image,
clock/lifetime and cleanup qualification remain external.

Periodic token sessions can select `periodicRenewalWitness` alongside the existing
session input. It requires `deployment`, `sourceIdentity`, `epoch`, `source`,
`identityId`, `tokenRow`, `capability`, `allowedKey` and `deniedKey`. Native source
identity must match the family observer identity; controlled sources require
explicit injection. Private endpoints are `periodic-renewal/open`, `expire`,
`arm`, `boundary`, `settle`, `delivery` and `close`.

Arm qualifies an exclusive original window across every ingress for the exact
credential/token row and owns the response gate before the sole SDK renewal.
It is not a host mutex or a new SDK idempotency header. Foreign requests, replay,
late work and incomplete inventories fail qualification. Source settlement binds
all six lifetime fields and preserves the stopped caller's renewal receipt
instance/evidence; Partial never becomes a passing Applied effect. A snapshot or
local Stop alone cannot establish native completion. Captured inaccessible
replacement material is not SDK-delivered. Cleanup preserves borrowed tokens,
identities, grants and qualified lifetime changes while removing owned captures,
resources and registrations. Native ingress fencing, row joins, clocks/lifetimes
and source cleanup remain separately unqualified.

The separate dynamic SQL definition password witness covers PostgreSQL create/update
`passwordRequirements.value`, including its `NativeSqlDefinitionProfile` alias.
Private `profile.passwordRequirements` must select exactly length 24 with six
lowercase, uppercase, digits and symbols, or length 32 with eight of each;
`allowedSymbols` must be `"!"`. UPDATE additionally requires
`profile.baselinePasswordRequirements` selecting the other policy. Missing,
unsupported or equal-length baselines fail before fixture ownership.

An observer must read a complete project-wide dynamic validation-rule inventory
with every rule explicitly inactive; active, unknown or incomplete inventories
leave this witness unavailable because a rule can override definition requirements.
The harness measures actual issued passwords, independent backend authentication,
actions and expiry. UPDATE first measures a baseline lease and then issues a fresh
lease: denial/cancellation preserve the baseline policy, while success/lost response
must expose the selected policy. Cleanup revokes all owned leases and independently
requires rejection of every captured credential, including the baseline.

This narrow witness uses functional facts from Infisical v0.166.3, not proof of the
running deployment version. Other engines and policy shapes, nonliteral username
templates, TLS, gateways and protected metadata retain their separate unavailable witnesses.
Offline regressions establish harness behavior, not live PostgreSQL conformance.

The separate PostgreSQL `usernameTemplate.value` create/update witness accepts
only literal `sk_u_<16 lowercase hex digits>_a` or the matching `_b`.
UPDATE requires private `baselineUsernameTemplate` selecting the other suffix
under the same token; unsupported or equal baselines fail before ownership.
Use a fresh token per concurrent case. SQL must create the exact supplied role
strictly, rather than transform its name or reuse an existing role.

The observer's `dynamic/usernames` endpoint receives the typed engine/host/port/
database `coordinate` and `usernames`, without passwords. It must inspect
cluster-wide PostgreSQL roles and return `coordinate`, exact ordered
`requestedUsernames`, unique matching `existingUsernames`, and `isComplete: true`
inside the existing nonce/identity/time-bound envelope. Missing, incomplete,
foreign or substituted inventory cannot establish ownership. Both planned roles
must be absent before any provider fixture is created.

Alternatively, the family root can explicitly select `postgresRoleCatalog` for
this username inventory only. Its required fields are `host`, `port`, `database`,
`username`, `password`, `timeoutSeconds` (1–60) and `rootCertificate` (an absolute
path to the host-selected CA file). The engine must be PostgreSQL and the
requested host/port/database must exactly match this profile. Unknown, missing
or null fields fail selection; selected native failures never fall back to the
remote username endpoint. The existing `observer` remains required for
`dynamic/measure` and its separate authentication/action/expiry evidence.

The native source requires the host's `psql`/libpq 16 or later, uses verified TLS
and SCRAM channel binding, and runs one fixed read-only `pg_catalog.pg_roles`
query. At most 64 distinct requested names (63 UTF-8 bytes each) are admitted.
Requested names enter SQL as encoded JSON data over stdin, not identifiers or
command-line arguments. Credentials are explicitly injected; an isolated
temporary client home excludes ambient password files and client certificates.
The exact session user and all ordered Boolean result rows must match before
the source returns a complete presence result. Process failure, truncated or
ambiguous output is unavailable, not absence. The process and its streams drain
before the temporary home is removed. No PostgreSQL binary or driver is shipped
in the SecretKit packages.

These observations establish role presence at the query, not role ownership,
exclusive ingress, causal creation, lease settlement or future non-recreation.
Actual client/server, CA, catalog principal and deployment qualification remain
required; controlled process responses do not certify PostgreSQL behavior.

Actual issuance must return the selected literal and independently authenticate
with expected actions and expiry. UPDATE verifies the baseline credential after
the mutation. Success/lost response keeps A active while issuing B, then verifies
A still authenticates. Denial/cancellation first verifies A still works, then
revokes it and requires fresh authentication rejection and cluster-role absence
before reissuing A; strict role creation cannot issue A twice concurrently.
Cleanup reconciles all owned leases, freshly rejects every captured credential,
and checks both intended roles absent. Authentication/action/expiry collection
still requires its selected fixture service; the optional native catalog is not
a supplied PostgreSQL driver or complete lifecycle service. Null clearing, expression expansion,
default naming and other engines remain unverified.

Dynamic validation credential trials belong to `C08-IR-ValidationPolicies`.
Their private `dynamicTrial` supplies an explicit `projectSlug`, PostgreSQL
`profile`, positive `defaultSeconds`/larger `maximumSeconds`, and nonempty
`allowedActions`/`deniedActions`. The profile must use closed32 password
requirements (eight of each category, symbols `"!"`). Project slug is not
inferred from the static fixture's project ID. Family-root observer settings
select the existing `dynamic/measure` and `dynamic/usernames` services.

The narrow rule contract requires min=max24 or32 generation bounds,
exactly `SqlDatabase` provider, explicit active status, and the owned environment
and folder scope. It additionally permits only `^[A-Z]{24}$` / `^[a-z]{24}$`,
prefix null/`A_`/`B_`, and suffix null/`_A`/`_B`. Arbitrary patterns/affixes,
reuse constraints, other providers/engines and scope clearing remain unavailable.
A complete project-wide inventory must be
empty before ownership; even unrelated inactive rules are excluded. Baseline
and post-mutation inventories must contain only the owned rule, or none when
expected absent. Missing trial input fails before provider work.

Create/update/delete/get/list `kind.DynamicSecrets`, SQL-provider create/update,
and explicit activation/deactivation cases issue credentials from one unchanged
definition before and after the selected operation. An active rule replaces the
definition password requirements; it does not require the definition's category
counts. Without regex, rule bounds specify total length including affixes and
the safe alphabet `A–Z`, `a–z`, `0–9`, `-_.~!*`. With either admitted regex, the
middle must have exactly24 uppercase or lowercase ASCII letters, then the literal
affixes wrap it. Regex generation ignores length bounds: bounds32 plus two
two-character affixes yields28, not32. Anchors describe the middle, not the final
affixed password. The harness checks ranges and edges directly rather than
interpreting arbitrary patterns with .NET Regex. Field-isolating update trials
keep the other constraints fixed. No active rule means the closed32 definition policy.
Static `before`/`after` secret trials are unused and may be empty for this slice.

Every actual credential must authenticate with expected actions/expiry. A fresh
wrong-password attempt must fail on the same route, followed by another successful
valid-password attempt. The preceding credential must remain usable after fresh
issuance. The observer service must use fresh non-pooled connections and password
authentication, not cached outcomes or an authentication route that ignores the
password. Cleanup revokes all leases without force, checks complete lease absence,
rejects all captured pairs, checks cluster-role absence for every issued name, and
verifies rule/definition absence. Uncertain issuance without captured material
cannot certify cleanup even when provider records were reconciled.

These trials use pinned v0.166.3 functional facts and offline counterexamples.
They do not establish deployed-image identity, plan entitlement, actual backend
enforcement. Those remain separate native gates.

Rotation-validation fixture clients use two separately selected service identities:
the family-root `observer` for `rotation/measure-credentials`, and `rotationFixture`
for account provisioning. Both use the existing HTTPS endpoint/token/identity/
timeout settings and nonce-bound envelope. Measurement sends the actual supplied
pair and returns coordinate, authentication, authenticated username and allowed/
denied actions; it does not infer those facts from a configuration acknowledgment.

The owner client generates an ownership capability and both account names before
`rotation-accounts/claim`. Requests bind organization, project, borrowed connection,
backend coordinate and the two names. Required facts include the same scope and
capability, exact `ownedUsernames`, empty `unownedUsernames`, measured
`remainingOwnedAccounts`, and `connectionRetained: true`. Cleanup calls
`rotation-accounts/release` then `rotation-accounts/remaining` using only the
original caller-owned tuple, even after a lost, malformed or substituted claim
reply. An acknowledgment without bound final absence fails cleanup. The service
must refuse existing foreign roles, remove only capability-owned accounts, and
leave the borrowed connection intact. These clients do not implement or provision
the external owner/measurement services.

The account client can bind explicit `rotationTrial.profile` selections for
`PostgresCredentials` (the default), `MysqlCredentials`, or `MssqlCredentials`.
Non-PG ownership requires the observer's `rotation/identity-catalog`
channel. Its facts bind the original coordinate and both requested names, with
exactly one matching `mysql` or `mssql` branch. Missing catalog authority stops
before claim. Invalid or incomplete post-claim facts still release only the
original nonce/scope/names and attempt final independent catalog measurement.

MySQL observations cover requested usernames across **all account Hosts**, not
only the connection hostname. Claimed accounts must be exactly `username@%`,
with a supported password plugin. Complete password-validator/component discovery
must describe either no validator with inapplicable settings or one recognized
LOW-policy implementation permitting the closed generation shapes. The measured
policy is pinned before claim and must remain compatible and unchanged afterward.
The client never installs, disables or rewrites borrowed server policy.

The family root can explicitly select `mysqlIdentityCatalog` for native Oracle
MySQL account/policy collection instead of the remote catalog terminal. Its exact
private fields are `host`, `port`, `database`, `username`, `password`,
`principal`, `rootCertificate`, and `timeoutSeconds`. The first three bind the
server/database; each observation binds the exact requested rotation coordinate
and account names, including nonce-owned names generated after selection.
The subject account never selects a different server/database or reader.
`principal` binds the observed `CURRENT_USER()`,
including its Host. Use an independently authorized catalog reader, not either
account being rotated. The host supplies `mysql`; no database package is shipped.
The client uses explicit TCP/VERIFY_IDENTITY TLS, the selected absolute CA path,
isolated client-home/default-file authority, bounded stdin/output and actual
process drain. Passwords do not enter arguments, SQL or returned diagnostics.

One fixed query inventories requested usernames across all Hosts in `mysql.user`,
active password-validation plugins, registered components in `mysql.component`,
and effective global validation variables. Unknown components/validators or
missing/duplicate/null settings fail closed rather than imply no enforcement.
This source currently accepts no registered components except the known password
validation component. Thus even unrelated registered components need a reviewed
extension before this collector can qualify that environment.
Selection errors and collection failures never fall back to remote catalog facts.
All other observer terminals, including authentication and ownership settlement,
remain independently required.

Controlled integration does not qualify a native MySQL installation. Actual
client/server version, complete read privileges, TLS/principal binding, absence
of unenumerated/custom policy hooks, and policy stability remain native
prerequisites. The query is not an atomic snapshot across grant tables and
dynamic plugin/component/global-variable state. Neither one absent inventory nor
process completion fences future or late account creation.

MSSQL observations require both complete server-principal and selected-database
principal catalogs. Claimed subjects must be enabled SQL logins with measured
policy/expiration checks disabled, and instance-authenticated SQL users whose
nonempty SIDs match their corresponding login SIDs. Each account has a distinct
SID; equal bytes, not array object identity, establish mapping. Non-SQL and
contained-user collisions cannot be filtered out of preflight absence evidence.
Final cleanup requires neither owned name in either catalog.

An explicit family-root `mssqlIdentityCatalog` selects native SQL Server catalog
collection. Its exact private fields are `host`, `port`, `database`, `username`,
`password`, `serverIdentity`, and `timeoutSeconds`. Server/port/database and the
enrolled reader stay fixed; nonce-owned subject accounts bind to each request,
not configuration. MySQL and MSSQL native selectors can coexist: the requested
rotation profile selects the matching source. A selected native source never
falls back to HTTP; a profile without a matching source in that native selection
fails closed.

The selected host tool is Linux x64 ODBC
`/opt/mssql-tools18/bin/sqlcmd`, with mssql-tools18 and Microsoft ODBC Driver
18.7.1.1 as the qualification contract. No executable/PATH/Go fallback or
installation is performed. The actual binary, driver and version must be
qualified separately; controlled process output does not attest them.
Explicit TCP, SQL login and mandatory certificate-validated encryption use the
host trust store without `-C`, alternate certificate hostname or trust changes.
The password enters only the selected child environment, never arguments or SQL.
Startup/variable authority is cleared; fixed stdin SQL uses encoded name data.

The source separately observes `master` and the selected database. Both must
report the expected server, original/current reader login and equal nonempty
login SIDs, database user `dbo`, traditional SQL Server edition and sysadmin
membership exactly one. This deliberately narrow observer authority prevents
ordinary metadata-filtered reads from falsely certifying absence. It grants no
permission to provision a server, modify its policy or use a fallback identity.
Native principal-name column collations must agree with each context's observed
catalog collation. Equivalent requested names or returned equivalent spellings
outside the exact request invalidate collection rather than disappear from it.

All matching server/database principal types are retained. SQL-login flags
remain nullable; SID null invalidates the observation, while empty SID remains
measured data that cannot establish owned SQL-login/user mapping. One bounded
scalar JSON document per context carries hexadecimal text/SIDs; incomplete,
duplicate, malformed, overflowing or failed output never becomes complete absence.
The two observations are not an atomic cross-catalog snapshot.

Actual native TLS positive/negative cases, long-output framing, unrestricted
catalog visibility and collation fixtures remain qualification prerequisites.
This source supplies neither the account-owner service nor authentication,
effective permissions, expiry, late-claim fencing or remote settlement.

For the prepared `C08-IR-InfisicalRotationClient` consumer-read branch, explicit
`mysqlConsumerAuthentication` can select an accepted-session source. Its ten
private fields are `host`, `port`, `database`, `account`, `username1`, `username2`,
`accountHost1`, `accountHost2`, `rootCertificate`, and `timeoutSeconds`. They must
match the prepared backend and two account names, not a later validation-trial
nonce. Material- and mutation-specific authentication terminals stay separate.

This source may report `Accepted` only after a fresh host-owned Oracle MySQL8.4
Linux client returns the exact authenticated `CURRENT_USER()` and database over
certificate/hostname-validated TLS, with complete output and custody cleanup.
It does not report `Rejected`: exit status, including a CLI 1045 diagnostic,
does not attest the original error's authenticated TLS stage. Every failed,
ambiguous, unsupported or mismatched attempt remains unavailable. Authoritative
refusal is still an open source requirement; negative qualification is not waived.

Both borrowed credentials use clearable exports and an invocation-owned0600
option file in a directory created0700 before protected writes. Neither credential
enters argv or environment. The first argument selects that exclusive file;
login-path/default authority is isolated, and dynamic authentication plugins
cannot load from an ambient directory. The initial representable domain is
printable ASCII, preserving spaces, quotes and backslashes; unsupported encoding
is unavailable before launch, not a failed-password claim.

Bounded stdout binding and stderr scratch remain clearable, not diagnostic
strings. Actual process and reader tasks must drain before overwrite/flush,
close/delete and buffer clearing. Cleanup failure cannot report acceptance.
This is logical live-invocation custody, not forensic or crash-recovery erasure.
Native client/build, TLS negatives, option round trips, plugin behavior, output
framing and protected temporary storage remain qualification prerequisites.

The prepared consumer-read branch also accepts an explicit
`postgresConsumerAuthentication` selector with eight private fields: `host`,
`port`, `database`, `account`, `username1`, `username2`, `rootCertificate`, and
`timeoutSeconds`. PostgreSQL and MySQL sources may coexist; the requested profile
selects its native source, and no selected native failure falls back remotely.
The PostgreSQL source requires a trusted host-owned `/usr/bin/psql` with the
PostgreSQL18/libpq18 contract on Linux. Native binary/library qualification is
separate from controlled process-seam tests.

Both delivered PostgreSQL credentials remain in clearable exports and private
files: a service file holds the username and an exact-match passfile holds the
password. Restrictive modes apply before writes; retained handles support
overwrite/flush/delete after actual child and reader drain. No protected value
enters argv, environment or output strings. Inherited service, password, startup,
certificate, GSS, OAuth, loader and OpenSSL configuration authority is isolated.
TLS verify-full, explicit CA, SCRAM-SHA-256 and required channel binding precede
a fixed read-only query of session/effective principal and database.

Only one complete, bounded, exactly bound three-field hex row with no diagnostic
and successful custody may become `Accepted`. All failures stay unavailable,
including psql refusal-like errors: broad exit codes do not establish an
authenticated rejection stage. Authoritative refusal, native TLS/SCRAM/channel
binding, service/passfile parsing, defaults and protected storage remain open
qualification obligations. The bounded ASCII source domain does not remove
unsupported credential variants from admission.

The typed catalog channel and profile-bound owner are local infrastructure.
The trial helper uses native typed creation/read/deletion for all three SQL
profiles. The owner service must journal its nonce-owned
identities and settle or fence a late claim before reporting cleanup; a client
nonce and an empty current catalog cannot establish that guarantee.

For `C08-IM-Governance`, audit-setting requests contain exactly the mutable
`Authentication` and `Authorization` pair. `Management` and `DataAccess` remain
read/filter classes and permanent logging classes; their setter variants are
explicit local precondition rejections, not provider-side suppression, denial,
cancellation or lost-response evidence. All original admission labels remain.
Legal write cases retain the original independent event/persistence witnesses,
and configuration readback alone never proves effective policy. Authorization
logging requires the native new-privilege system; published propagation may take
up to ten minutes. Missing producer or propagation authority stays unavailable.

Rotation-validation trials also belong to `C08-IR-ValidationPolicies`. Their
private `rotationTrial` requires `organizationId`, a UUID `connectionId`, `host`,
`port`, `database`, positive `rotationInterval`, and nonempty `allowedActions`/
`deniedActions`. The connection is borrowed; the owner service creates two fresh
capability-owned accounts. Missing trial inputs fail before ownership.

The implemented rule slice supports min=max24 or32 generation bounds,
`PostgresCredentials`, `MysqlCredentials`, or `MssqlCredentials` matching the
explicit rotation profile, active status, and exact owned environment/folder
scope. Regex and affix support has the same closed shapes and middle-then-wrapping
semantics described for dynamic trials above. Other providers, arbitrary
patterns/affixes, reuse constraints and scope clearing remain unavailable.
Complete project-wide rotation-rule inventory must initially be empty
and contain only the expected owned rule throughout the trial.

Create/update/delete/get/list rotation-kind and selected SQL-provider variants, plus
activation/deactivation variants, use one unchanged closed32 rotation configuration
with automatic rotation disabled from creation. Two administrative manual rotations
must each switch the active account exactly once. Public runtime SDK reads obtain
the actual mapped username/password; configuration metadata alone cannot qualify.
An active rule controls the generated shape and safe alphabet described above; without
it, eight characters from each category and symbols `"!"` are required.

Fresh backend password authentication must identify the expected account and
measure the declared actions. A wrong-password attempt must reject, followed by a
valid-password control; the preceding active pair must remain usable after the
second rotation. Accepted MySQL facts require actual `CURRENT_USER()` equal to
the supplied username at `%` and the selected database. MSSQL facts separately
bind original connecting login, current execution login and database user to the
supplied username and initially admitted SID bytes; dbo/guest/impersonation or
SID rekeying cannot qualify. Rejection requires null username and identity.
Cleanup deletes the owned rotation with generated-credential
revocation and mapped-secret removal, observes their absence, and freshly rejects
both captured pairs **before** removing the accounts. It then checks complete,
bound account absence and retention of the borrowed connection. Uncertain rotation
without captured material cannot certify cleanup.

Native `RequestHeadersStart` cancellation remains unavailable without a bound
server-completion witness: a post-cancel snapshot cannot exclude a later commit.
Controlled offline tests prove pre-send non-occurrence only. Pinned v0.166.3
synchronous manual-rotation behavior and offline trials do not establish deployed
image identity, licensing, native authentication or actual owner-service effects.

SQL administration families select database fixture settings at their own
family roots. The adapter generates its ownership nonce before `database/claim`
and `database/provision`; the service must bind that caller capability to the
owned project/name. Even a malformed or lost claim is released by that capability,
never by arbitrary returned coordinates. `database/catalog`, `database/authority`
and `database/authenticate` measure exact native connection/catalog/backend state.
Rejection observations use `database/arm`, `database/rejected` and
`database/disarm`, with registration established before the SDK mutation.
`database/release` and `database/remaining` must explicitly measure zero owned
connections, accounts and registrations. Returned profile data constructs only
public typed SQL models. The adapter does not supply a database driver or provision
the service; those remain independently operated fixtures.

This client does not provision the external fixture service. The runtime rotation
family provisions fresh owned Postgres, MySQL and Microsoft SQL Server rotation
configurations through their typed management APIs, using the selected connection
and two isolated, task-owned accounts in `RotationInput`. The runtime rotation
client requires a trusted HTTPS origin. An independently selected observer reads the
configuration before execution. Cleanup reconciles the owned configuration once,
requests generated-credential revocation and checks configuration absence; the
backend observer must separately measure authentication rejection. Other profiles
still require an owned fixture factory, and unresolved profile/field observations
remain explicit unavailable cases.

Each automated report is a `MachineReport` with `schemaVersion: 2`,
`purpose: release-observation`, gate kind, immutable bindings, job/platform/
environment, start/completion times, positive `discovered`, zero `failed`,
`skipped` and `exitCode`, `checks`, `nativeCases`, `prerequisites`, and nullable
`installation`. Raw failed reports may record false results; the release gate
rejects them rather than dropping cases or sanitizing a failure into a pass.

For native/live reports, discovery equals the exact number of required native
cases; `checks` summarize scope, not additional discovered tests. Every
inventory `requiredCases` entry for every operation/variant/scope must appear
once, with `passed: true`, `effectObserved: true`, and `reasonCode: observed`.
The effect is the case's expected native/backend outcome, including observed
non-occurrence for denial tests, not just a setup call or status code.
Prerequisites exactly cover the union of inventory prerequisite IDs for each
provider scope, all confirmed. Both native gates require the reviewed
`release-evidence` environment.

Native/live reports and compatibility reports require an
`InstallationObservation` with actual OS, `architecture: x64`,
`framework: net10.0`, zero process exit and project references, an isolated
cache, and `packageSource: candidate-only`. Report package hashes must be the
original bytes actually restored, not just a same-version assertion. Each
provider's native report is validated before aggregation; their installation
observations must be identical and are preserved in the aggregate. Native
cases must execute against that installed candidate, never source project
references, a shared cache or a substitute platform. Development raw outputs
are explicitly nonqualifying and cannot use `purpose: release-observation`.
Compatibility reports use only their own platform check.
Provenance and notices checks exactly cover the existing gate keys above.
Provenance and notices reports have null installation observations.
For these non-native reports, discovery equals the number of checked results.
No report carries stdout, response dumps, material or unbounded failure prose.

The bundled typed report must equal the independently fetched parsed raw report.
A false substituted observation fails even after recomputing every bundled hash
and preserving source/run IDs. A report from another job fails independently
of any synthetic marker. Fixture/offline purposes, omitted/duplicate cases,
zero discovery, wrong scope/source/platform, missing effects or entitlements
also fail.

The four rights/environment gates contain an `AuthorityAttestation`, no
automated reports. It binds kind, subject owner, issuer, independent reviewer,
observation time, opaque native evidence locator/hash, and exact confirmed
checks. Reviewer differs from issuer, publisher and owner. These records must
match the independently approved index; YAML settings or a self-authored
`passed` assertion are not an owner or native registry attestation.

Immutable timestamps establish original-run provenance: report observations
fall within their exact completed job, before artifact creation, and before the
index review. Owner evidence is observed during the original run/review period.
There is **no current-wall-clock age rule** here. Initial admission, recovery
and fresh action approval policies belong to the later purpose-specific
authorization boundary, not to rewritten immutable facts or journals.

Trust assumptions: reviewed canonical source/harnesses, runners, the trusted
collector, native providers and accountable protected reviewers are not
compromised. Hashes, schemas and these checks cannot detect a consistently
fabricated raw report by trusted compromised code, or prove a false real-world
owner attestation. They do prevent a bundle from supplying its own evidence
authority. `TestBundle` is fixture-only; controlled test oracles are not real
GitHub or provider evidence and must never be copied into a producer.

`manifest.schema.json` describes these documents in named `$defs`; the BCL
verifier owns cross-file semantics. `manifest.example.json` is deliberately
incomplete and rejected, with no invented hashes, passed gates or approvals.

### Pre-upload content check

`candidate-check <bundle> <independent-evidence>` validates archives, admission,
all typed facts and completed dependency jobs. It permits the canonical overall
run to be `in_progress` and needs no final artifact metadata or protected final
approval. It returns only `candidate-content-consistent-not-approved`, never a
`VerifiedRelease`, artifact identity, journal or publishing permission.

The acyclic order is original pack -> installed/native observation jobs -> raw
report uploads -> independent collection -> candidate content check -> final
bundle upload -> successful overall run -> independent protected approval ->
`verify`. Post-run `verify` still requires successful same-repository main-push
`verify.yml`, the exact final artifact ID/digest, the protected index hash and
all independent inputs. Ordinary offline `checks.txt`, `sdk.txt`, TRX and
`packages.sha256` outputs cannot stand in for this bundle.

## Protected workflow and external setup

### Candidate producer inputs and independent review

`verify.yml` now contains the conditional producer graph. An ordinary PR or
push still runs format, all offline hosts and the two installed-platform jobs
without secrets, provider authority or publication credentials. Only a canonical
protected-main **push** with a source-owned
`docs/internal/releases/candidate.json` requests candidate production. Its
absence means ordinary verification, not a failed or approved release. A
requested candidate with invalid inputs or missing evidence fails.

The proposal is a `CandidateProposal` JSON object with `schemaVersion: 1`,
normalized `version`, `publisher`, `owner`, and the reviewed `providerScopes`
defined above. No real proposal is supplied by this change. The producer binds
the actual run SHA, run ID and attempt; the proposal cannot supply them. It
derives the entire operation/variant scope from both current source inventories,
checks their source hashes, and rejects every remaining `contract-gap`.
Changing scope to fit available observations is not supported.

The offline build makes one fresh original family at the proposal version.
`candidate-prepare` copies those exact seven originals, both inventories,
notices and scope into a nonauthoritative input artifact. Symbol packages never
enter it. All subsequent jobs download that current run/attempt input; none
rebuilds, signs or repacks a package. Building the nonpackable runner/test hosts
does not replace the original family. Each installed consumer still restores
into its own empty cache and verifies the restored original archive hashes.

The producer dependency order is:

1. Offline source-locked restore/build/fresh pack and all offline tests.
2. Protected `prerequisites` preparation, independent provenance/notices
   measurements, both installed-original platforms, and both native/live gates
   on Ubuntu 24.04 x64 and Windows Server 2025 x64.
3. Independent review at the **separate** `release-candidate` environment,
   current-attempt collection, assembly and content checking.
4. Immutable candidate upload, successful run completion, then the separate
   publisher's final independent metadata/approval and nonpublishing `verify`.

The `release-evidence` and `release-candidate` environments must both enforce
main-only deployment, required independent reviewers, prevention of self-review
and no administrator bypass. YAML names do not configure these protections.
Do not define these approval inputs as repository or organization secrets:
they must be environment secrets. GitHub reads environment secrets when the
referencing job starts, after its protection gate; repository secrets are read
when the run is queued.

While `prerequisites` is waiting for approval, the accountable owners and
independent reviewer supply `SECRETKIT_REVIEWED_PREPARATION` in `release-evidence`.
Its `CandidatePreparation` JSON contains:

- `schemaVersion: 1`, current `sourceCommit`, `runId`, `runAttempt`, `scopeSha256`.
- Distinct `issuer` and `reviewer`, `observedAt`, and `retainUntil` covering at
  least the next 90 days.
- The exact confirmed provider/scope/prerequisite union from admission,
  including setup ownership, separately selected identities, rights, native
  backend observers, entitlements and bounded cleanup where required.
- All four genuine `AuthorityAttestation` records. Their native evidence
  locators/hashes identify retained owner proofs, not output invented by a CI
  test. Owners must retain those underlying material-free proofs for the same
  recovery period.

Native jobs additionally require protected `SECRETKIT_NATIVE_SETTINGS` and
source-owned native hosts. The future harness must explicitly consume that
owned-settings contract; this workflow does not reinterpret a generic token as
every required identity. It must emit `Infisical.json` and `AzureKeyVault.json`
at each supplied absolute `SECRETKIT_NATIVE_REPORT` path. The files are
`MachineReport` values: each contains its provider's measured checks, cases and
prerequisites, with all common scope/package/source/job bindings. The host
receives `SECRETKIT_NATIVE_INPUTS`, `SECRETKIT_NATIVE_KIND`,
`SECRETKIT_NATIVE_PLATFORM` and `SECRETKIT_REPORT_JOB_ID`. The collector
combines only these actual facts and rejects omissions, failed/skipped cases,
wrong identities and missing effects. A positive TUnit count alone creates
no report. Missing `NativeObservationReport.cs`, either native project, owned
settings or either report is a hard failure. Native projects run separately
from the offline solution.

After all eight report jobs finish, an independent reviewer inspects their
current-attempt job/upload/deployment records and the retained preparation.
The reviewer constructs the exact eight-origin/four-attestation `EvidenceIndex`
and supplies its UTF-8 JSON and SHA-256 as environment secrets
`SECRETKIT_REVIEWED_EVIDENCE_INDEX` and `SECRETKIT_REVIEWED_EVIDENCE_SHA256`
in `release-candidate`, **before approving** the waiting assembly job.
The attestations must exactly match the independently prepared records.
This is an operator review step, not a self-approving collector API. The
collector never emits or selects an index for promotion. Failed or partial
reruns need fresh current-attempt review; old jobs cannot fill their gaps.

The collector checks the independently supplied index hash, fetches the exact
run attempt, report job/artifact metadata, SHA-locked inventories/notices and
digest-verified raw report archives. GitHub's artifact API does not supply job
origin, so the review must establish that binding. `candidate-assemble` checks
the retained preparation and serializes measured gates; `candidate-check`
validates the resulting content before upload. Neither command creates final
artifact metadata, successful-run metadata, a final approval or a journal.
No producer job has publication OIDC, NuGet credentials or feed access.

Producer inputs, preparation, raw reports, independent evidence and candidate
artifacts request **120 days** retention. This provides margin for preceding
jobs and protected review before the common 90-day recovery window begins.
Assembly additionally checks each actual report artifact's `expires_at`
against its current time plus 90 days; requested retention alone is not proof.
Maintainers must configure a repository/service plan supporting this retention.
Public repositories restricted to 90-day artifacts cannot satisfy this setup
merely by truncating the request: a separately reviewed preservation strategy
or protocol change is required. Final post-run admission must check the
earliest actual expiry against the original completion time, and missing or
expired evidence blocks recovery rather than resetting the journal.

Current readiness blockers remain concrete:

- The full native observation harness, Azure owned host and cross-platform
  settings contract are not complete; existing Linux sandbox narratives do
  not implement this denominator.
- Retained contract gaps prevent `candidate-prepare`.
- No real protected preparation/index, service retention settings, Windows
  execution or hosted producer run has been supplied or observed.

The environment-secret timing and protection behavior were checked against
[GitHub's secrets reference](https://docs.github.com/en/actions/reference/security/secrets)
and [deployment review](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/review-deployments).
These are interface facts, not evidence that this repository's environments
are configured.

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
SECRETKIT_APPROVED_EVIDENCE_INDEX
SECRETKIT_APPROVED_EVIDENCE_SHA256
SECRETKIT_NUGET_USER
SECRETKIT_NUGET_OWNER
SECRETKIT_NUGET_REPOSITORY_CERT_SHA256
SECRETKIT_APPROVED_JOURNAL_HEAD
SECRETKIT_APPROVED_JOURNAL_ARTIFACT_DIGEST
SECRETKIT_APPROVED_JOURNAL_WORKFLOW_COMMIT
SECRETKIT_APPROVED_ORIGINAL_ADMISSION_SHA256
SECRETKIT_APPROVED_ACTION_AUTHORIZATION_SHA256
SECRETKIT_ENVIRONMENT_PROTECTED
```

Hashes use lowercase SHA-256 hex; source commits use lowercase 40-character
Git SHA. The artifact digest excludes the API's `sha256:` prefix. Journal head
is `new` only for a never-dispatched family; otherwise it is the SHA-256 of the
latest approved checkpoint JSON bytes. `SECRETKIT_ENVIRONMENT_PROTECTED=true`
records a maintainer's configuration check; an environment variable itself
cannot enforce or prove GitHub environment protection.

Reviewers also supply protected environment secrets
`SECRETKIT_ORIGINAL_ADMISSION` and, only for mutation,
`SECRETKIT_ACTION_AUTHORIZATION`: exact UTF-8 JSON whose separate SHA-256
approvals bind the materialized files outside the candidate bundle. The workflow
never creates approval values, changes approval times, or advances the approved
head automatically. Reviewers select the latest retained journal and bind its
archive digest and producing workflow commit separately from its JSON head.

The original admission binds the original manifest/evidence hashes, artifact
ID/digest, admission time and `ProducerCompletedAt`. The independent collector
fetches the exact approved producer run attempt's jobs, requires exactly one
successful completed `candidate` job with the approved source SHA, and fetches
its exact job API record as `producer-job.json`. Original admission must occur
within 24 hours of that completion. Recovery is supported for at most 90 days
from the original completion, subject to actual artifact availability.
Neither recovery nor subsequent publication renews that date.

Initial admission checks the independently fetched candidate artifact and every
required report artifact's actual `expires_at` against
`ProducerCompletedAt + 90 days`, with equality accepted. An unexpired artifact
with a shorter horizon still fails admission. Requested workflow retention and
the earlier pre-upload report check do not establish final candidate retention.

Before mutation dispatch, the persisted unknown-state checkpoint must also have
an independently fetched actual `expires_at` at or beyond
`ProducerCompletedAt + 90 days`. Equality is accepted; missing, malformed or
shorter expiry fails closed even when the artifact is currently unexpired and
its ID, digest, execution and source bindings are correct. This preserves the
original recovery horizon rather than renewing it at each action. The requested
120-day workflow setting is not evidence that the host actually retained it.

Dispatch inputs name `mode` (`initial-admission`, `read-only-recovery`, or
`publish-one`), the exact producer run/artifact, reviewed manifest hash, and
the journal run/artifact for recovery or publication. `package_id` selects one
of the seven exact IDs; it has effect only in `publish-one`. `execute` defaults
to false and is additionally required for mutation. The read-only `verify` job
performs locked restore, scoped build/tests/format and workflow checks for the
release runner. Its frozen binary archive is transferred by immutable artifact
ID and separately checked against that job's SHA-256 output before execution.

The protected `observe` job independently collects the source/evidence and
original admission, then verifies the initial candidate or exact approved
journal. Only after verification does it initialize a new journal or perform
read-only native-feed reconciliation. It retains the resulting immutable head,
including an unresolved reconciliation result. It has no publication OIDC,
NuGet login, key fetch, prepare or dispatch. Initial observation is limited to
`new`; recovery requires an existing approved SHA-256 head. Observation changes
local append-only history, never the package feed.

Only `publish_one` has `id-token: write`. It requires `mode: publish-one`,
explicit execute, the canonical repository, protected `main`, the protected
`release` environment and the first workflow attempt. It independently fetches
exact source/report/job/artifact evidence and verifies the original admission
and existing approved journal before preparation or credentials. It never
initializes or reconciles a journal.

The separate action approval is at most 24 hours old and binds approved starting
head H0, `PackageId`, original `PackageSha256`, `ExecutionAttempt` (run-attempt),
`WorkflowCommit` (`github.sha`), and refreshed reviewer/rights/environment
confirmation. Preparation permits only that pending member and no unknown
member, producing exactly one H0-to-H1 transition. H1 is uploaded before login
as `publication-checkpoint-<runId>-<runAttempt>-before`. The workflow independently
fetches its API metadata and ZIP, checks the archive digest, exact ID, name,
current run/source SHA and unexpired status, and passes
`SECRETKIT_CHECKPOINT_METADATA_FILE` and
`SECRETKIT_CHECKPOINT_ARTIFACT_DIGEST` to dispatch. The runner verifies the proof,
the exact transition and the fresh original action again before key use.
After the native read, `NativeFeed` invokes the protected action validator again
immediately before PUT. Crossing either the action deadline or original recovery
deadline while awaiting that read blocks the request and preserves unknown
history; a publishing key alone cannot bypass this check.

One uninterrupted run dispatches only the selected package and retains its
result afterward. No recovered checkpoint or rerun dispatches: use observation
to reconcile and obtain a new protected action for a still-pending member.
The approved H0 stays fixed throughout the transaction. Each subsequent member
requires separate review of the latest journal and a separate action. No package
or runner is rebuilt after verification. These local checks do not establish
that hosted protection, retention or publisher registration is configured.

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
workflow requests 120 days), preserve a trusted external copy before
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

`verify` checks local bundle bytes and independently collected GitHub metadata
and raw evidence without contacting
NuGet. `initialize` and `reconcile` only read the native feed. `prepare` writes
local uncertainty, never publishes. Only `dispatch ... --execute` can PUT.
The command-line boundary emits fixed error codes rather than exception details.

This implementation does not establish a completed SDK, real provider coverage,
NuGet registration, current prefix/publisher rights, a protected GitHub
environment, an actual producer artifact or an executed GitHub/OIDC/NuGet flow.
Those gates remain missing and no release manifest attests otherwise. Current
admission coverage and native contract completion remain separately reviewed
inputs; tests never establish live coverage. Do not replace missing native
evidence with synthetic test records.

The report collector's API field contract was checked against the official
[artifact](https://docs.github.com/en/rest/actions/artifacts#get-an-artifact)
and [job](https://docs.github.com/en/rest/actions/workflow-jobs) documentation
on 2026-10-12. Only functional field facts were used; no external implementation
was copied.

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
