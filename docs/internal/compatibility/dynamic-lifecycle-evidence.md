# Native dynamic lifecycle evidence

Observed 2026-10-09; optional-input matrix updated 2026-10-10 in the validated
SecretKit `main` checkout. This is an
independently authored offline native lifecycle slice, not full Infisical
coverage, live conformance, edition availability, permission evidence or
cross-provider support. No Core promotion, official Infisical SDK, automatic
leases, replay, cache, persistence, fallback, background maintenance or implicit
remote cleanup is involved. Parent integration owns the project graph and registry.

## Authority and transport

### Owned native gate observed 2026-10-11

The separate native SQL scenario compiled and passed formatting, but its
actual owned v0.166.3 run failed at definition creation with HTTP400/Rejected:
"Failed to create dynamic secret due to plan restriction. Upgrade plan to
create dynamic secret." Separate generated PostgreSQL backend TCP readiness,
database/schema setup succeeded. No platform database was used.
Credential acquisition, backend use, role-expiry renewal, revoke denial and
committed-acquisition fault assertions therefore remain unrun. No skip, replay
or inferred downstream pass replaces this entitlement gate.

Current-public OpenAPI and pinned documentation research still leave all27
non-SQL material variants unestablished. Optional unconstrained `data` and
nullable untyped `lease.config` are not credential models. Pinned documentation
references the unversioned live specification. OAuth2/Tailscale output labels
do not establish HTTP paths/types/nullability; Kubernetes token lifetime remains
fixed and lease deletion is not JWT revocation.

`InfisicalDynamicClient` requires one immutable trusted origin, host-selected
token source and exact `InfisicalDynamicScope`. The scope requires the expected
native folder UUID in addition to project/environment slugs and path. Returned
definitions must match folder UUID and name; targeted updates/deletes/acquisition
also match definition UUID/provider. Lease observations must match definition
UUID and the requested lease UUID when known. Slugs are not inferred from IDs.
This validates the coordinates actually returned, not omitted project membership
or server permission.

The handwritten internal `IInfisicalDynamicWire` has ten explicit Refit request
builder methods, each with a `CancellationToken`. Refit 16.3.0 builds
`Task<HttpRequestMessage>` requests from these declarations; it never receives
a lifecycle response for automatic deserialization or `ApiException` creation.
Method-argument and request-content capture are disabled. The owned `HttpClient`
sends with `ResponseHeadersRead`, and the independent parser enforces bounded
streaming. There is no public endpoint, JSON, object or dictionary executor.
The only JSON writer entrypoints are private, fixed native request fields and
handwritten typed profiles. No downloaded-schema or client-generation pipeline
is used; Refit's request builders come only from the handwritten declarations.

`InfisicalDynamicDispatchHandler` supplies an independently owned token copy,
checks expiry/origin, and marks the typed receipt at the last controlled send
boundary. Receipt operation and target are checked before request construction.
The receipt is a local evidence object, not a remote idempotency/query handle.
Host token sources and injected transport handlers remain host-owned. The default
transport disables redirects, cookies and activity propagation and retains
standard TLS validation. An injected handler must honor the same no-redirect,
no-retry, no-payload-capture contract; arbitrary host handler internals cannot be
verified by the SDK. Responses claiming another request URI fail closed.

The default request/response byte budget is 1 MiB, configurable from 1 KiB to
16 MiB. The per-array/per-object item budget defaults to 128, configurable from
1 to 1024. Nesting is limited to 32; returned strings are limited to 65536
characters and field names to 1024. Duplicate JSON properties and duplicate
definition/lease identities are rejected. Native profile arrays are capped at
128, string members at 4096, and native scalar strings at 65536 or their
published smaller constraint. Request buffers and stream collection buffers
are cleared. Parsing creates transient managed strings; no secure erasure of
managed strings or HTTP framework internals is claimed.

## Operation matrix

All operations below refer to admitted `DynamicSecrets` registry rows and
`wire-facts-0410` through `wire-facts-0428`. The source registry remains unchanged.

| Native operation | Implementation | Exact boundary or gap |
| --- | --- | --- |
| `GET /api/v1/dynamic-secrets` | `ListDefinitionsAsync` | Bounded metadata projection for all 28 admitted types; no input credential export or issuance |
| `POST /api/v1/dynamic-secrets` | `CreateDefinitionAsync` | 28 independently typed templates; common default/max TTL, username template and protected metadata; bounded profile options below |
| `GET /api/v1/dynamic-secrets/{name}` | `InspectDefinitionAsync` | Validated metadata, never lease issuance; unspecified `inputs` not exposed |
| `PATCH /api/v1/dynamic-secrets/{name}` | `UpdateDefinitionAsync`, `UpdateDefinitionPolicyAsync` | Typed inputs matching existing provider, rename, default/max policy, explicit max/template clearing, protected metadata; no arbitrary `data.inputs` |
| `DELETE /api/v1/dynamic-secrets/{name}` | `DeleteDefinitionAsync` | Typed receipt and validated definition response; forced record removal distinguished; external credential deletion not certified |
| `GET /api/v1/dynamic-secrets/{name}/leases` | `ListLeasesAsync` | Metadata-only bounded list for all admitted types; validates every definition UUID; no `config` or credential export |
| `GET /api/v1/dynamic-secrets/leases/{leaseId}` | `InspectLeaseAsync` | Validated lease UUID, definition UUID/name/folder and native timestamps; no material acquisition |
| `POST /api/v1/dynamic-secrets/leases` | `AcquireDatabaseAsync`: supported SQL subset | Only `sql-database` material acquisition is implemented. Other 27 profiles return `ContractNotEstablished` before dispatch; `data`/optional `config` are unspecified in the registry, and exact output field/primitive variants are not established |
| `POST /api/v1/dynamic-secrets/leases/{leaseId}/renew` | `RenewAsync`, `RenewLeaseAsync` | Explicit database-owned-material renewal or metadata-only renewal for any observed profile; actual returned expiry/version; no replacement credential issuance, forced renewal or replay |
| `DELETE /api/v1/dynamic-secrets/leases/{leaseId}` | `RevokeAsync`, `RevokeLeaseAsync` | Explicit material-handle cleanup or retained-reference cleanup after local disposal, for any observed profile; force is record removal, not proof of external revocation |
| `POST /api/v1/dynamic-secrets/leases/kubernetes` | **ContractNotEstablished, no callable placeholder** | Request fields are established; public `response.data` is an unconstrained `{}` schema and nullable `lease.config` has no shape. Credential field names/types/nullability and namespace echo remain unspecified; no guessed JWT field or material-free issuance substitute |

## Profile matrix

Each row has a handwritten constructor covering its required fields and named
authentication alternatives. Definition creation/inspection/update can use
these types; that does not establish material acquisition for that provider.
Only SQL material output has established exact public field names in the
retrieved documentation. No credential dictionary substitutes for other outputs.
Established optional definition fields are exposed through the named bounded
profiles/options below. This covers field alternatives, not every native numeric,
string or duration value. Peer-verification bypass is deliberately not exposed.
Optional omitted fields retain native server policy, not an SDK promise.

| Registry template | Independent public profile | Implemented variants and exact remaining input gaps |
| --- | --- | --- |
| `sql-database` | `NativeSqlDefinitionProfile` | postgres/mysql2/oracledb/mssql/sap-ase/vertica, statements including renew, protected CA, explicit TLS flag, selected/cleared gateway IDs and typed password requirements; peer verification bypass excluded |
| `clickhouse` | `NativeClickhouseDefinitionProfile` | Required inputs, CA/renew, selected/cleared gateway IDs and password requirements |
| `cassandra` | `NativeCassandraDefinitionProfile` | Required inputs, keyspace, CA, renew; peer verification bypass excluded |
| `sap-ase` | `NativeSapAseDefinitionProfile` | All published input fields implemented |
| `aws-iam` | `NativeAwsIamDefinitionProfile` | access-key/assume-role/irsa; iam-user/temporary-credentials; path, permission boundary, policy ARNs/document, groups and copied tags; session-policy fields restricted to assume-role |
| `redis` | `NativeRedisDefinitionProfile` | Required inputs, optional password/CA/renew; peer verification bypass excluded |
| `sap-hana` | `NativeSapHanaDefinitionProfile` | Required inputs, CA/renew; peer verification bypass excluded |
| `aws-elasticache` | `NativeAwsElasticacheDefinitionProfile` | All published input fields implemented |
| `aws-memorydb` | `NativeAwsMemorydbDefinitionProfile` | Published IAM authentication and all required input fields implemented |
| `mongo-db-atlas` | `NativeAtlasDefinitionProfile` | All published input fields, independently typed roles/scopes including optional collection name |
| `elastic-search` | `NativeElasticsearchDefinitionProfile` | user/api-key authentication and roles; CA on both branches; peer verification bypass excluded |
| `mongo-db` | `NativeMongoDefinitionProfile` | Required inputs, optional port/CA and explicit null clearing; contradictory value/clear selection rejected; peer verification bypass excluded |
| `rabbit-mq` | `NativeRabbitDefinitionProfile` | Required inputs, typed vhost permissions, tags/CA; peer verification bypass excluded |
| `azure-entra-id` | `NativeAzureEntraDefinitionProfile` | All published input fields implemented |
| `azure-sql-database` | `NativeAzureSqlDefinitionProfile` | Required inputs, master database, CA/renew, selected/cleared gateways, password requirements and omitted/false/true SSL; peer verification bypass excluded |
| `ldap` | `NativeLdapDefinitionProfile` | dynamic/static accounts, required LDIF fields, rollback/CA; peer verification bypass excluded |
| `snowflake` | `NativeSnowflakeDefinitionProfile` | All published input fields implemented, including renew |
| `totp` | `NativeTotpDefinitionProfile` | manual/url, typed sha1/sha256/sha512, digits/period; positive integral local numeric budget is narrower than the unspecified published numeric policy |
| `kubernetes` | `NativeKubernetesDefinitionProfile` | dynamic/static accounts, role/cluster-role, audiences, optional API URL/token/CA, API/gateway mode, selected/cleared gateway IDs and omitted/false/true SSL; peer verification bypass excluded |
| `vertica` | `NativeVerticaDefinitionProfile` | Required inputs, selected/cleared gateways and password requirements |
| `gcp-iam` | `NativeGcpIamDefinitionProfile` | Service-account email and token scopes; no implicit host cloud credential chain |
| `github` | `NativeGithubDefinitionProfile` | Published required IDs and protected private key |
| `couchbase` | `NativeCouchbaseDefinitionProfile` | Required API authority/coordinates/roles; string or copied bucket/scope/collection arrays and provider-specific password requirements |
| `milvus` | `NativeMilvusDefinitionProfile` | Required inputs, optional database/CA, selected/cleared gateways and copied privilege objects; peer verification bypass excluded |
| `ssh` | `NativeSshDefinitionProfile` | Principals and both key algorithm selections (RSA 2048/4096, EC prime256v1/secp384r1, ED25519); acquisition `config`/additional principals remain unestablished |
| `ibm-api-connect` | `NativeIbmApiDefinitionProfile` | Required inputs and selected/cleared gateways |
| `tailscale` | `NativeTailscaleDefinitionProfile` | auth_keys/federated_keys/oauth_keys with api_key/oauth authorities; tailnet/tags/description on factory alternatives; reusable/preauthorized restricted to auth keys and audience to federated keys |
| `oauth2` | `NativeOauthDefinitionProfile` | client-credentials, client_secret_basic/client_secret_post, scope and copied typed extra-parameter objects |

Input constraints are explicitly local where the public facts are broad:
positive integral ports 1..65535, bounded positive whole-second durations up to
one year, nonempty credential fields and bounded arrays. Not all native numeric,
empty-string or duration grammar variants are supported. Definition TTL parsing
accepts only positive integer `s`, `m`, `h`, `d` values within that local budget;
unrecognized native policy evidence fails closed rather than fabricating a cap.
`NativePasswordRequirements` admits whole-number length 1..250 and nonnegative
character counts whose sum does not exceed that length; optional allowed symbols
are bounded to 4,096 characters and excluded from default serialization.
This is a typed server input, not a local password generator. SQL gateway omission
and explicit null clearing are distinct; `sslEnabled: false` is retained rather
than omitted. The server's certificate-verification default is not weakened.

## Material, expiry and uncertainty

`InfisicalDatabaseLease` owns its private native database credentials and returns
independent `InfisicalDatabaseCredentials` copies. Disposing one copy or the
lease cannot clear another copy. Copies share observed remote lifecycle evidence
so a successful explicit revoke, uncertain mutation or native deadline blocks
normal exports. Lease disposal alone does not invalidate independent copies;
expiry/revocation still does. Exports are explicitly managed strings, whose
lifetime belongs to the caller.

Local expiry is the actual returned `lease.expireAt`, checked with injected
`TimeProvider`, not login success, permission, application readiness or fleet
convergence. A non-null native status is protected and not guessed as usable.
Renewals reject an already expired local observation, consume the returned
native expiry/version, preserve original creation time and reject responses
exceeding an established native maximum lifetime. The SDK does not locally add
TTL, issue a replacement lease or infer unlimited renewal.

Pre-send cancellation propagates with `NotDispatched`. Possible-dispatch or
post-commit cancellation propagates with `PossiblyDispatched`; lost/malformed/
mismatched successful mutation responses return `Unknown`. Lost acquisition
does not produce a guessed lease identifier or automatic revoke. Lost renewal
leaves material locally unusable, with no automatic retry/revoke. Each receipt
is single-use and operation/target-bound. Remote permission/validation failures
are material-free bounded statuses. Error response bodies are never read.

Explicit metadata inspection does not reconcile a previously uncertain material
handle. Hosts may retain observed references for reviewed cleanup; the SDK does
not claim that listing identifies which unknown acquisition was theirs. Two
metadata-only observations can be independently mutated; no remote CAS or
cross-observation ordering is established. Competing mutations of the same
database material handle fail locally with `Conflict` before a second dispatch.

Normal and forced cleanup remain separate. A successful delete response records
the acknowledged native effect, but `ExternalRevocationVerified` remains false:
there is no live downstream credential-use/deletion proof or universal native
status interpretation. No cleanup request is made on material/client disposal.

## Source facts and provenance

The admitted registry and source-free
`dev/active/secretkit-sdk/infisical-contract-facts.md`, observed 2026-10-09,
establish v1 method/path and primitive fields. Their `data`, definition `inputs`,
lease `config` and some union roots are explicitly unspecified. Handwritten
input branches use their concrete discriminated field facts, not copied schema
organization or vendor implementation.

Context7 official documentation established:

- [Python SDK documentation](https://infisical.com/docs/sdks/languages/python):
  generated SQL credentials use `data.DB_USERNAME` and `data.DB_PASSWORD`.
- [Go SDK documentation](https://infisical.com/docs/sdks/languages/go):
  renewal extends an existing lease before expiry and remains subject to
  maximum total lifetime; forced deletion can remove a record without external
  revocation. Forced renewal is not in the admitted request body and is not exposed.
- [AWS IAM dynamic secrets](https://infisical.com/docs/documentation/platform/dynamic-secrets/aws-iam):
  user versus temporary credentials have different material outputs, but the
  retrieved facts do not establish exact wire keys/primitives for native mapping.
- [Dynamic secrets overview](https://infisical.com/docs/documentation/platform/dynamic-secrets/overview):
  on-demand generated credentials are distinct from definition inspection.
- [Dedicated Kubernetes acquisition](https://infisical.com/docs/api-reference/endpoints/dynamic-secrets/kubernetes/create-lease.md):
  the request requires `dynamicSecretName`, `projectSlug` and `environmentSlug`;
  `ttl`, `path` and nonempty `config.namespace` are optional. Rechecked against
  the public schema on 2026-10-09: credential output and returned configuration
  remain unconstrained rather than guaranteed empty.
- [Kubernetes dynamic secrets](https://infisical.com/docs/documentation/platform/dynamic-secrets/kubernetes.md):
  issued service-account JWTs have fixed expiration; deleting a lease does not
  revoke its token. Product behavior does not establish credential wire fields.

Tavily extracted official lifecycle pages/overview; guessed `_llms` page URLs
returned 404 and a subsequent extraction was rate limited. These failures did
not become negative provider claims. Context7 supplied documentation facts;
no external code, implementation layout, SDK schema, dependency or copied
documentation prose is included in these owned files. Parent selected and
verified Refit provenance/dependencies; this worker edits no root/package files.

## Offline verification

R6 optional inputs passed 71 focused cases, with 11 definition and 13 lifecycle
cases retained. The later native login delivery ran the complete native module:
262/262 passed, zero skipped. Parent reviewed option copies/disposal, conditional
AWS/Tailscale fields, nullable clearing and the 28-row matrix. These are offline
wire/control proofs; no external issuer, database or Kubernetes effect is implied.

`LeaseLifecycleTests` and `DynamicDefinitionTests` use actual in-memory resource
state behind an injected managed HTTP handler. Material is generated per test.
The fixture changes definitions/leases before optionally losing or holding a
response. Event barriers are armed before triggering requests, with bounded
awaits; no sleeps, timing-luck polling, mock call-count tests or live requests.

Coverage includes all 28 definition templates, 12 additional authority/config
branches, typed policy/input/rename/clear/delete effects, inspection versus
issuance, independent disposal, native max-lifetime renewal, deadline expiry,
scoped revoke, retained-reference cleanup, lost committed acquisition/renewal,
pre/post-send cancellation, competing renew/revoke, foreign scope/receipt/
returned coordinates, byte/count/nesting/duplicate-property limits, redaction,
and an unbufferable unknown-length response proving controlled streaming.

Actual retained checks, all monitored from the validated SecretKit root:

- Locked restore of `tests/SecretKit.Infisical.Tests/SecretKit.Infisical.Tests.csproj`
  passed after parent-owned Refit dependency/lock integration.
- Release provider build and affected test-project build with `--no-restore`
  passed, exit 0. The final profile-constructor disposal correction was rebuilt.
- Explicit `/*/*/LeaseLifecycleTests/*` selector with
  `--minimum-expected-tests 13`: 13 passed, 0 failed.
- Explicit `/*/*/DynamicDefinitionTests/*` selector with
  `--minimum-expected-tests 7`: 7 passed, 0 failed. The final profile correction
  was rechecked with these seven tests.
- Scoped `dotnet format SecretKit.slnx --no-restore --verify-no-changes`
  over the eight owned C# files passed, exit 0. The final profile file was
  separately rechecked after its last edit, exit 0.
- Parent SQL optional-input increment built successfully before behavioral Red:
  four selected cases discovered, three failed on absent fields/contradictory
  gateway acceptance and one omission case passed. After native serialization and
  validation were implemented, the complete provider suite passed **132/132**
  with positive minimum 132, exit 0. Touched diagnostics and scoped formatting
  passed. No remote database, gateway or password-generation effect was tested.

The initial combined selector discovered only the 13 lifecycle cases; the two
explicit positive selectors above establish the actual 20-case native coverage.
Earlier shared builds failed on organization-owned assertion analyzer errors
and Task-versus-ValueTask Refit exception factories in shared/rotation-owned
files. Their owners corrected those integration blockers; this worker did not
edit them. The language server initially retained old package-resolution
diagnostics after the parent added Refit; the actual restored compiler gates
passed. No failing test was skipped, weakened or excluded to obtain a pass.

These results prove the managed offline control seam and fixture state only.
Live identity permission, deployment/edition, actual external credential effects,
status vocabulary, clock skew and all non-SQL material shapes remain unverified.
