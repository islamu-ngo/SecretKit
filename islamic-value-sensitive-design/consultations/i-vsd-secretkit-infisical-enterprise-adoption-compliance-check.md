# SecretKit Infisical and Shared Packages: Enterprise Adoption Readiness Review

Last Updated: 2026-11-05

## Review Metadata

- Mode: standalone
- Project: SecretKit
- Subject: secretkit-infisical-enterprise-adoption
- Workstream: none
- Report kind: compliance-check
- Report status: current
- Disposition: changes-required
- Evidence cutoff: 2026-11-05
- Reviewed input: working-tree on `main`, based on Git object `3734dc28ad5a5fcaaf02afa50033299d30770136`, including existing modified and untracked files
- Supersedes: none
- Decision baseline: general enterprise production adoption, with controlled evaluation assessed separately; confirmed by the requester on 2026-11-05
- Criticality: Tier 1 security; administrative mutations also carry potentially irreversible consequences
- Validation level: I-VSD design reasoning and implementation traceability; no new stakeholder or operational validation
- Evidence fingerprint: review-specific 359-file integrity inventory, SHA-256 `faac980b60016c8b0691395ce12f565f1e4328229c603ea4c5a8e045973bcdbb`; see Evidence Reviewed for coverage and limitations

## Adoption Decision

**SecretKit is a credible candidate for carefully bounded enterprise evaluation, but the reviewed evidence does not support recommending general production adoption yet.** Its current documentation reaches the same production-readiness conclusion. The main problem is the remaining assurance and operating evidence, rather than a demonstrated absence of basic security engineering.

The inspected implementation has unusually explicit boundaries around identity selection, protected material ownership, response acceptance, mutation uncertainty, local generations, transport ownership, and artifact qualification. Those controls deserve credit. They do not establish that an enterprise's chosen Infisical deployment, identities, transport, telemetry, application recovery, and support arrangements meet its requirements.

No exploitable code defect was substantiated in the reviewed paths. This was an extensive static assessment, not a penetration test or proof that defects are absent. Source tests were inspected but not executed. Existing historical results are identified as historical; no passing count is presented as a result of this review.

| Adoption decision | Recommendation | Basis and conditions |
| --- | --- | --- |
| Synthetic, credential-free development evaluation | Proceed with normal local engineering controls | Inspect the documented examples and selected APIs. This creates no provider or production qualification. |
| Controlled pilot using an authorized Infisical environment | Conditional | Select exact package originals, a small operation set, explicitly scoped identities, an admitted transport, material-free diagnostics, bounded recovery, and an accountable operator. Obtain actual evidence before claiming that pilot succeeded. |
| General enterprise production runtime use | Withhold approval on the present evidence | Current candidate, deployment, security operations, and application acceptance evidence remain incomplete or were not reviewed. Findings F001-F008 and F010-F011 identify the main gates. |
| Administrative automation | Separate, stricter admission | Management is optional. Its privileged actions need independent authority, audit, reconciliation, and selected-operation qualification. Runtime success does not admit administration. |
| Dynamic credentials, SQL rotation, imports, approval-dependent writes, gateway/proxy deployment | Admit each selected behavior separately | Remote effects, entitlements, cleanup, and downstream recovery require independent witnesses. A supported request or acknowledgement is insufficient. |
| Native AOT, trimming, additional platforms or another hosting abstraction | No support inference | The declared posture is JIT on `net10.0`. Expand only for an actual consumer with the required evidence. |
| Public publication | Outside this adoption decision | Publisher rights and the repository's public-family release protocol remain separate. Private package evaluation does not require public publication. |

Evidence: E01, E11-E19, E23-E25. The runtime-only pilot decision must not inherit every optional management requirement. Conversely, a deliberately smaller pilot must not relabel itself as passing the existing full native qualification profile.

## Scope

The requested subject is enterprise adoption in real .NET applications and infrastructure. The assessed software runs inside the consuming process and handles credentials, secret values, protected coordinates, and potentially powerful administrative requests.

| Package | Reviewed responsibility | Important adoption boundary |
| --- | --- | --- |
| `SecretKit.Core` | Material, references, authority identity, observations, outcomes, inventory contracts, mutation receipts | BCL-only; does not authenticate users, enforce application tenancy, or become a vault |
| `SecretKit.Infisical` | Runtime reads/inventory, selected writes, authentication, token sessions, organization/imports, dynamic and rotation subsets, transport | Provider-native semantics and supported response subsets remain explicit |
| `SecretKit.Infisical.Management` | Separately selected identity/access/project/governance administration, authentication configuration, retained SQL rotation and gateway/proxy administration | High-privilege host authority and remote effects require separate admission |
| `SecretKit.Extensions.Configuration` | Bounded collection, pinned snapshots, validated client generations, explicit configuration export | Optional; plaintext export and application activation are deliberate boundaries |
| `SecretKit.Extensions.Hosting` | Infisical DI/options, explicit startup admission, health, opt-in maintenance and shutdown | Optional; depends on Infisical and does not define general application readiness |

Both Azure Key Vault packages and their provider-specific behavior are excluded. Common build/release documents sometimes describe the full package family; their shared integrity and execution controls were considered without assessing Azure functionality or treating Azure-specific gaps as Infisical defects. Infisical authentication strategies named after a cloud remain Infisical capabilities, not a review of that cloud's SDK.

The review covered strategy, developer experience, architecture, data handling, operations, governance, support, portability, and evaluation. There is no assumed industry sector, regulatory jurisdiction, availability target, corporate procurement policy, or promise to support older target frameworks.

Target guidance takes precedence over compatible cockpit defaults. SecretKit is explicitly greenfield: breaking development changes are permitted. This report does not demand compatibility aliases, extra target frameworks, restoration of the removed connector catalog, database drivers, another provider, or a speculative orchestration layer.

Only this cockpit report was authorized as an output. Product source, tests, dependencies, project configuration, provider state, and publication were not changed.

## Claim Boundary

This is **I-VSD provider-responsibility design reasoning**, supported by source, tests, documentation, and selected public guidance. It is not a fatwa, Sharia or product certification, a legal opinion, a SOC 2/ISO assessment, an independent security audit, or proof of ethical outcomes.

Selected Sunni ethical principles supply the normative framework. Compatible engineering guidance helps operationalize those principles; neither legal compliance nor market preference establishes moral sufficiency.

The following distinctions govern every assessment:

- **Pass / source** means the reviewed implementation and inspected assertions support a narrowly stated control. It does not mean those tests passed during this review.
- **Concern** means partial assurance, a documented open gate, a material responsibility requiring deployment evidence, or missing reviewed evidence.
- **Not reviewed** means this review cannot establish the claim. It does not prove the evidence or control does not exist elsewhere.
- **N/A** is an applicability decision with a stated reason, never a substitute for checking an applicable control.
- **Fail** would require evidence of a violated non-negotiable control or serious unresolved design harm. No such finding is asserted solely because a test was not rerun.
- Severity describes adoption risk and potential harm, not a CVSS score or a confirmed vulnerability.

Host-process compromise, malicious code with equivalent process privileges, exported managed strings, and arbitrary host instrumentation are not isolated by an in-process SDK. Provider permissions, identity issuance, audit retention, DNS/proxy policy, application tenancy, downstream validation, and production incident handling cross organizational and deployment boundaries.

## Responsibility And Threat Model

The central flow is:

```text
Trusted host configuration and credential injection
  -> selected origin, transport and runtime/admin identity
  -> authority-bound typed operation
  -> token acquisition and bounded HTTP exchange
  -> operation-specific response acceptance
  -> owned material or native outcome/receipt
  -> application validation and explicit activation
  -> optional plaintext export and downstream use
```

| Boundary | SecretKit controls | Adopter/provider responsibilities | Main affected stakeholders |
| --- | --- | --- | --- |
| Bootstrap and identity | Explicit selection; no automatic fallback principal or hidden re-login | Protect injection; establish principal, permission, lifetime and recovery authority | Secret owners, tenant administrators, operators |
| Local authority and application tenancy | References and grants bind particular owners and exact selections | Authorize tenant-to-project/environment/path mappings; protect grant issuers | Tenants and people whose data downstream systems hold |
| Provider authorization | Preserve denial and supported native distinctions | Infisical enforces effective policy; administrators provision and review least privilege | Runtime users and organization owners |
| Network | Safe transport defaults, fixed origin, bounded representations; explicit arbitrary host mode | Decide trust roots, revocation, egress, DNS, proxy and borrowed-pipeline policies | Credential owners and infrastructure operators |
| Material | Clear owned buffers; copy and disposal contracts; protected default representations | Govern explicit exports, process access, dump/debug rights and downstream copies | Data subjects, businesses and support staff |
| Mutation | Typed scope, caller-held dispatch evidence, no SDK replay | Persist material-free recovery records; reconcile under explicit authority | Resource owners, on-call staff and downstream users |
| Generations and readiness | Complete local candidates, leases, revision fences and selected freshness policy | Validate actual dependencies; select stale policy; coordinate replicas and work admission | Application users and reliability teams |
| Delivery | Archive, source, graph and test-owner checks | Establish trusted execution, real CI protections, current audits and accepted artifacts | Maintainers, security reviewers and adopters |
| Ongoing operation | Bounded classifications and documented limitations | Staff support, patching, audit retention, notification, recovery and EOL | Present and future adopters |

Credible adversaries include a mistaken integrator, a compromised lower-privilege identity, cross-tenant request input, a hostile or malformed response, a substituted artifact/evidence record, an unsafe telemetry sink, and an untrusted workflow context. A provider or fully privileged host compromise remains a root-of-trust failure requiring external controls.

The existing threat and recovery contract is substantive: E11 defines foreign-scope challenges, credential canaries, causal issuance, original artifacts, uncertainty and cleanup. The missing assurance must not be inaccurately described as “no threat model exists.”

## Enterprise Control Assessment

The following 120 checks are deliberately separate from the material findings. They describe breadth, responsibility and evidence; they are not equally weighted and must not be added into a “compliance percentage.” References resolve through Evidence Reviewed.

### Material, Privacy And Error Surfaces

| ID | Check | Assessment | Evidence and consequence |
| --- | --- | --- | --- |
| C001 | Core runtime dependencies | Pass / source | Core has no package/project references; BCL-only boundary is visible. E02, E21. |
| C002 | Independent material ownership | Pass / source | `Copy` creates separate owned storage; successful results remain caller-disposed. E02. |
| C003 | Clear owned buffers | Pass / source | Disposal clears the owned character array; temporary callback storage clears in `finally`. E02. |
| C004 | Character/UTF-8 callback lifetime | Pass / source | Snapshots execute outside the owner lock and survive concurrent owner disposal. E02. |
| C005 | Strict text conversion | Pass / source | Malformed encoding becomes a fixed argument failure without rejected-input exception properties. E02. |
| C006 | Non-disclosing default representations | Pass / source | Material markers, ignored protected properties and bounded outcomes are intentional; reviewed tests exercise canaries. E02-E03, E10. |
| C007 | Managed-string and array exports | Concern | `Reveal`, configuration and caller copies deliberately leave SDK clearing control; adopter must accept and govern this boundary. E02, E05, E10. |
| C008 | Disposal equals process-wide erasure | N/A | No such protection is promised. Treat dumps, prior strings and downstream copies as host responsibilities. E10. |
| C009 | Provider error and credential exception prose | Pass / source | Closed outcomes and sanitized boundary failures avoid returning raw provider prose on inspected paths. E03, E07-E10. |
| C010 | Telemetry privacy in the deployed application | Concern | Closed SDK tags are supported; actual host exporters, crash capture, retention and access policy were not qualified. E10, E16, F004. |

### Identity, Authorization And Tenant Isolation

| ID | Check | Assessment | Evidence and consequence |
| --- | --- | --- | --- |
| C011 | Explicit principal selection | Pass / source | Runtime/admin credentials are supplied rather than discovered as fallback identities. E07-E09. |
| C012 | Reference bound to exact local authority | Pass / source | Object identity prevents same-name/same-origin references from silently changing clients. E03, E07. |
| C013 | Foreign reference rejected before credentials | Pass / source | Runtime, selection and management boundaries have negative assertions. E03-E04, E07, E09. |
| C014 | Application tenant-to-provider authorization | Concern | SDK scope is not application access control; trusted mapping and negative tenant tests belong to the host. E10, F002, F010. |
| C015 | Effective least privilege at Infisical | Concern | Grants and scope objects encode selection; they do not observe effective remote policy. E07, E09, E12, F002. |
| C016 | Runtime/admin separation | Pass / source | Management is optional and separately supplied authority; this supports, but does not enforce, organizational separation of duties. E09, E21. |
| C017 | Wildcard keyed credentials | Pass / source | Hosting rejects the wildcard service key; keyed runtimes have independent ownership. E06. |
| C018 | Supplied token proves principal or policy | Concern | Token labels, expiry metadata, decoded JWTs and digests cannot supply the required independent bindings. E07, E11-E13. |
| C019 | Identity replacement on configuration reload | Pass / source | Resolved runtime selection is frozen; replacement requires a new owner and reference binding. E06, E22. |
| C020 | Same-principal cross-scope isolation in deployment | Concern | The real allowed runtime actor must be challenged against an independently populated foreign scope. Another denied actor is insufficient. E11-E13, F002. |

### Network, Trust And Resource Budgets

| ID | Check | Assessment | Evidence and consequence |
| --- | --- | --- | --- |
| C021 | Fixed origin and request destination | Pass / source | Origin syntax and final request binding constrain SDK selection before sending. E08. |
| C022 | Safe default TLS | Pass / source | Safe mode uses HTTPS and ordinary certificate checks; development HTTP is explicit and loopback-limited. E08. |
| C023 | Redirect/cookie/propagation defaults | Pass / source | SDK-created transport disables redirects, cookies and activity-header propagation. E08. |
| C024 | Ambient proxy behavior | Pass / source | Safe transport omits ambient proxy selection unless explicitly configured; borrowed pipelines retain theirs. E08, E10. |
| C025 | Private trust roots | Pass / source | Public certificate data is copied; custom roots retain hostname/validity/usage checks. Deployment acceptance remains separate. E08. |
| C026 | Certificate revocation assurance | Concern | The documented safe/private-trust policy does not perform revocation lookup. An enterprise requiring it needs an accepted transport policy. E08, E10, F003. |
| C027 | Arbitrary borrowed pipeline | Concern | Explicit host-controlled mode can relax TLS, log, redirect or retry. Its name does not certify its internals. E08, F003. |
| C028 | Borrowed resource ownership | Pass / source | SDK disposal does not transfer ownership of supplied clients, handlers or credential sources. E06, E08-E10. |
| C029 | Encoded request and streamed response limits | Pass / source | Limits are independent; streamed byte counts, structural bounds and overflow paths are checked. They are not whole-process heap limits. E07-E09. |
| C030 | Operation duration and caller cancellation | Pass / source | Relative operation budgets use elapsed time; caller/shutdown/deadline evidence and late-result disposal are distinct. Arbitrary host code remains cooperative. E08, F005. |

### Authentication And Credential Lifecycle

| ID | Check | Assessment | Evidence and consequence |
| --- | --- | --- | --- |
| C031 | Registration/construction does not log in | Pass / source | DI, clients and helpers are inert until explicit admission/use. E06-E07. |
| C032 | Bootstrap custody | Pass / source | Runtime opening retains a caller-held attempt and avoids retaining bootstrap material for hidden re-login. E06-E07. |
| C033 | Universal login uncertainty | Pass / source | Receipts precede dispatch; failure/cancellation does not erase possible issuance. E07. |
| C034 | Authentication response evolution | Pass / source | Known fields retain exact checks; bounded additive fields are accepted while duplicate members and contradictory known evidence reject. E07. |
| C035 | Host-acquired workload proofs | Concern | Typed proof exchange does not qualify each external issuer, signing source, workload platform or mTLS deployment. E07, E19. |
| C036 | Original token lifetime authority | Concern | Lifetime objects require independently established original timing and policy. Response TTL alone does not prove finite/periodic semantics. E07, E11-E13. |
| C037 | Single-flight renewal and finite ceiling | Pass / source | Session state keeps renewal explicit and preserves the original ceiling. E07. |
| C038 | Expired or uncertain token recovery | Pass / source | Recovery does not silently substitute an identity, reuse consumed bootstrap or slide original lifetime. E06-E07. |
| C039 | Remote invalidation after revocation | Concern | Accepted revocation acknowledgement needs an independent subsequent denial witness. Local disposal is different. E07, F006. |
| C040 | Rotation/restart/fleet credential procedure | Concern | Real orchestration, replica convergence, bootstrap provisioning and restart recovery require host drills. E10-E13, F010. |

### Reads, Revisions And Native Response Acceptance

| ID | Check | Assessment | Evidence and consequence |
| --- | --- | --- | --- |
| C041 | Absence distinct from denial/outage | Pass / source | Outcomes and convenience reads preserve explicit absence without turning other failures into missing secrets. E03, E07. |
| C042 | Returned coordinates | Pass / source | Contradictory scope and visibility evidence reject before material publication. E07. |
| C043 | Qualified revision identity | Pass / source | Raw, non-imported revisions require resource identity and a positive provider version. E07, E19. |
| C044 | Timestamp/hash as invented revision | Pass / source | Local generation IDs and timing are not promoted into provider resource identity. E04, E07, E10. |
| C045 | Duplicate/oversized/malformed bodies | Pass / source | Operation-specific structural validation and streaming budgets are visible and negatively exercised in source tests. E07-E09. |
| C046 | Numeric fidelity | Pass / source | Management/native projection contracts preserve exact numeric tokens and reject invalid checked conversions. E09, E13. |
| C047 | Inventory proves value-read authority | Pass / source | Inventory is explicitly metadata; intended-identity delivery remains separate. E03, E10, E19. |
| C048 | Inventory completeness/concurrent changes | Concern | Callers must inspect completeness and item outcomes; bounded pages do not establish a transactional snapshot. E18. |
| C049 | Current Infisical version/edition/API support | Concern | Historical narratives and frozen research do not qualify the chosen contemporary deployment or every route. E12, E19, F002. |
| C050 | Unsupported native result shapes | Pass / source | Missing material contracts remain `ContractNotEstablished` rather than fabricated credential schemas. E07, E19. |

### Writes, Receipts And Native Effects

| ID | Check | Assessment | Evidence and consequence |
| --- | --- | --- | --- |
| C051 | Receipt retained before awaiting mutation | Pass / source | Core/native/management surfaces expose caller-held evidence bound to the relevant owner/target. E03, E07, E09. |
| C052 | Forged/foreign/reused receipt | Pass / source | Private issuer identity and dispatch state reject reassignment or replay in inspected flows. E03, E07, E09. |
| C053 | Cancellation/lost acknowledgement | Pass / source | Possibly dispatched effects remain uncertain; known accepted evidence can survive cancellation. E07-E09. |
| C054 | Automatic SDK mutation replay | Pass / source | No general SDK replay or fallback principal is introduced; arbitrary host retry policy is separate. E08, E10. |
| C055 | Approval submission versus application | Pass / source | Pending remains distinct from applied material. E07, E11, E18. |
| C056 | Pending approval ownership and teardown | Concern | The documented full-qualification cleanup contract remains open for pending requests. Do not invent an endpoint or infer closure. E11, F006. |
| C057 | Partial bulk effects | Pass / source | Earlier observed rows and later uncertainty are retained; a batch is not a remote transaction. E07. |
| C058 | Durable reconciliation after process loss | Concern | Local receipts are not a durable journal, remote lookup handle or idempotency key. The application must own recovery records. E03, E09-E11, F006. |
| C059 | Dynamic credential lease semantics | Concern | Supported SQL-shaped material has local expiry/uncertainty fencing; actual backend renewal/revoke/use effects need witnesses. E07, E20. |
| C060 | Rotation/import/gateway delivery | Concern | Configuration, accepted triggers and status strings do not prove downstream credential change, import application or deployed connectivity. E07, E09, E20. |

### Configuration, Freshness And Activation

| ID | Check | Assessment | Evidence and consequence |
| --- | --- | --- | --- |
| C061 | Required/optional selection policy | Pass / source | Required is default; optional admits explicit absence, not denied/expired/unavailable delivery. E04. |
| C062 | Selection authority and key collisions | Pass / source | Selection verifies the exact reader authority; consumer keys use ordinal comparison. Export destinations reject case-insensitive collisions. E04-E05. |
| C063 | Bounded collection work | Pass / source | Concurrency, selection count, UTF-8 candidate bytes and collection timeout are explicit. E04. |
| C064 | Complete valid publication | Pass / source | Wrong reference, invalid validity, expiry, limits or cancellation prevent candidate publication and dispose candidate material. E04. |
| C065 | Old generation on failed refresh | Pass / source | Loader failure preserves old pinned storage. Application stale-use permission is a separate decision. E04, E22. |
| C066 | Lease/coherent multi-key consumption | Pass / source | Handles and client leases pin one local generation with independent read copies and retirement ownership. E04-E05. |
| C067 | Stale policy and absolute usable deadline | Pass / source | Explicit fail-closed/bounded-last-known choices preserve the original deadline; held work has its own lifetime. E05, E22. |
| C068 | Check/reload versus activation | Pass / source | Check-only candidates do not activate; local revision and enabled-state fences reject superseded work. E05, E22. |
| C069 | Single-root plaintext configuration | Pass / source | Export builds one provider once; replacement publishes a complete local dictionary and signals separately. Escaped strings remain plaintext. E05. |
| C070 | Remote transaction or fleet convergence | Concern | Local coherence cannot establish remote multi-key atomicity, cross-replica convergence or downstream usability. E10, E18, F010. |

### Hosting, Health And Shutdown

| ID | Check | Assessment | Evidence and consequence |
| --- | --- | --- | --- |
| C071 | Deferred authentication/admission | Pass / source | Startup authentication is opt-in and awaited through the explicit hosted lifecycle service. E06. |
| C072 | Options validation before provider use | Pass / source | Origin/network/lifetime selection is validated without acquiring credentials. E06. |
| C073 | Independent keyed runtime sessions | Pass / source | Separate keys retain distinct options, authorities, bootstrap attempts and scope owners. E06. |
| C074 | Borrowed aliases and disposal | Pass / source | Explicit borrowed registrations survive container disposal; owned composition has a different owner. E06. |
| C075 | Hidden worker or renewal on health query | Pass / source | Maintenance starts explicitly; resolution/health do not silently authenticate or schedule. E06. |
| C076 | Health equals application readiness | Concern | Token-local health is useful evidence, not downstream credential validation or service/fleet readiness. E06, E16, F010. |
| C077 | Request/client retirement | Pass / source | Running callback pins defer client retirement; rejected candidates and retirement failures retain bounded outcomes. E05, E22. |
| C078 | One original shutdown attempt | Pass / source | Maintenance/session/native clients retain their original bounded outcome and continue owned cleanup where cooperation permits. E06-E08. |
| C079 | Forcefully terminating arbitrary callbacks | N/A | No in-process hard-kill guarantee exists. Host deadlines and process termination policy require explicit design. E10-E11, F005. |
| C080 | Production termination budgets and drainage | Concern | Kubernetes/service-manager/host deadlines, telemetry callbacks and long-held work require application-specific testing. E10, E16, F005. |

### Administration, Audit And Privileged Operations

| ID | Check | Assessment | Evidence and consequence |
| --- | --- | --- | --- |
| C081 | Exact local administrative grant | Pass / source | Issuer, client, operation and target must match; null project is absence, not wildcard permission. E09. |
| C082 | Independently checked typed dispatch | Pass / source | Method/origin/path/query checks precede credential attachment; there is no public raw-request executor. E09. |
| C083 | Effective admin identity and privilege | Concern | `IssueGrant` records trusted host intent and explicitly requires out-of-band correspondence checks. E09, F002. |
| C084 | Mutation body integrity | Pass / source | Typed request storage and separate factory/execution budgets restrict mutation construction. E09. |
| C085 | Arbitrary returned authentication nodes | Pass / source | Protected JSON retains returned shape without inferring it from request models. E09. |
| C086 | Missing/null/value and permission predicates | Pass / source | Protected projections retain distinctions and conditions; explicit exports have separate custody. E09. |
| C087 | Administrative approval/separation of duties | Concern | Grant issuance belongs inside the trusted host; human approval, privileged provisioning and policy review are external duties. E09-E10. |
| C088 | Audit setting readback | Pass / source | Settings and bounded audit row outcomes are modeled; malformed/foreign rows do not become valid evidence. E09. |
| C089 | Real privileged event production/retention | Concern | Neither successful configuration nor one page proves event completeness, actor attribution, retention or investigation access. E09, F007. |
| C090 | SQL/gateway feature boundaries | Pass / source | Native configuration remains typed; database connectivity, drivers and deployed agent effects are not smuggled into Core. E09, E19, E21. |

### Delivery, Dependency And Release Integrity

| ID | Check | Assessment | Evidence and consequence |
| --- | --- | --- | --- |
| C091 | Pin SDK/language/framework inputs | Pass / source | Current inputs select `net10.0`, C# 14 and SDK `10.0.403` with patch roll-forward; actual execution versions still need records. E21. |
| C092 | Dependency locks and source selection | Pass / source | Central versions, generated locks, mapped feeds and CI locked restore are configured. E14, E21. |
| C093 | Connected advisory clearance | Concern | The executable gate is present; no current connected report for this reviewed candidate was evaluated. E14, F008. |
| C094 | Advisory exception governance | Pass / source | Exact owner/rationale/evidence/expiry records do not turn a vulnerable result or native audit failure into clearance. E14. |
| C095 | Original archives/source/symbol binding | Pass / source | The cohort checks originals, selected subsets, source content, symbols and independent rebuild evidence. E15. |
| C096 | Installed-consumer graph completeness | Pass / source | Final graph/receipt inventory detects omission, substitution, added graphs and deleted inputs. E14-E15. |
| C097 | License/notices/package metadata | Pass / source | MIT declaration and packaged notices/readmes/XML evidence have archive-level test owners. Rights approval is a separate legal judgment. E21, E24. |
| C098 | Release-bound machine-readable SBOM | Not reviewed | A generation/admission contract was not found in the inspected release controls; provide one if selected procurement requires it. Existing graphs/notices are useful inputs. F009. |
| C099 | CI least privilege and trusted contexts | Pass / source | SHA-pinned actions, read-only defaults, selected source and protected-context conditions exist in workflow policy. E17. |
| C100 | Actual hosted protection and publication rights | Concern | YAML does not establish live settings, reviewers, publisher/namespace rights or a successful run; private adoption and public publication remain distinct. E17, E23. |

### Testing, Platforms And Qualification Claims

| ID | Check | Assessment | Evidence and consequence |
| --- | --- | --- | --- |
| C101 | Public-boundary negative tests | Pass / source | Inspected tests assert foreign authority, malformed responses, late results, uncertainty, ownership and consumer state. E02-E09, E22. |
| C102 | Deterministic asynchronous tests | Pass / source | Named lifecycle tests use event barriers/injected time; bounded timeouts serve failure limits. This is not a claim about every test file. E04-E08, E22. |
| C103 | Missing/zero-discovery tests | Pass / source | Verification compares solution host ownership and requires positive discovery; failures aggregate. E17. |
| C104 | Real installed worker/web behavior | Pass / source | Authored process/HTTP tests exercise request pinning, explicit activation, denial, readiness and diagnostics. Execution was not repeated here. E16. |
| C105 | Mutation-sensitive release tests | Pass / source | Workflow/audit/cohort tests deliberately remove or alter required evidence and expect rejection. E14-E17. |
| C106 | Current source/build/test qualification | Concern | Historical results cannot qualify the present dirty working tree or new originals. This review ran no SDK checks. E01, E12-E15, F001. |
| C107 | Native case denominator and custody | Concern | Local protocol, 17 functional cases, 21 native cases, six supplements and other namespaces must retain their distinct requirements. E11-E13. |
| C108 | Enterprise supplemental declaration | Pass / source | Declaration is explicitly non-native; S24 owner admission is scoped and does not qualify all S01-S28 scenarios. E13. |
| C109 | Production platform breadth | Concern | Linux development evidence does not establish the required hosted Linux/Windows matrix or macOS/ARM. E18-E19, E23, F001. |
| C110 | JIT versus trimming/AOT | Concern | Current JIT scope can serve a compatible consumer; named AOT/trim consumers need their own accepted analysis and execution. E11, E18-E19. |

### Stewardship, Developer Experience And Ethical Outcomes

| ID | Check | Assessment | Evidence and consequence |
| --- | --- | --- | --- |
| C111 | Truthful production/support claims | Pass / source | Preview, unsupported behavior and source/native distinctions are prominently disclosed. E01, E19, E25. |
| C112 | Adoption value and alternatives | Pass / source | Documentation acknowledges direct-provider alternatives and does not claim unmeasured superiority or savings. E25. |
| C113 | Named operating accountability/deputies | Concern | The reviewed maintenance table explicitly proposes roles; it does not establish completed appointments or capacity. E24, F011. |
| C114 | Vulnerability intake | Pass / source | Private reporting, sanitized reproductions and provider/SDK boundary guidance exist. Intake performance is unvalidated. E10. |
| C115 | Independent security assurance/incident drills | Concern | Existing adversarial tests are valuable; independent assessment and exercised incident/recovery operations were not established. E10-E11, F011. |
| C116 | Stable support, patching and EOL contract | Concern | No stable-release support window or response SLA is promised. An enterprise needs accepted maintenance/exit arrangements. E10, E24, F011. |
| C117 | Accessible onboarding and operator comprehension | Concern | Plaintext, uncertainty and ownership are documented; affected-user comprehension/accessibility results were not reviewed. E25-E26, F012. |
| C118 | Privacy, portability and exit | Concern | Minimal SDK diagnostics and open contracts support these aims; host retention, provider export and actual migration need evidence. E10, E25, F007, F012. |
| C119 | Billing/riba, ranking, religious-content moderation | N/A | No such SDK-operated feature is in this scope. External provider contracts, sponsors or host applications require their own review when selected. |
| C120 | Stakeholder/operational ethical outcomes | Not reviewed | No interviews, adoption study, operational harm register or longitudinal evaluation was supplied or inspected. Passing code tests cannot establish these outcomes. F012. |

## Findings

All findings below have lifecycle **open**. They concern the reviewed adoption decision and evidence boundaries. Owners are proposed accountable roles; this report does not appoint people or imply that a named team accepted a duty.

### IVSD-F001 — Current Candidate And Platform Admission Is Unestablished

- Severity / assessment: High / Concern; production admission gate.
- Claim type / validation: implementation traceability plus an explicitly unclosed qualification claim, not an observed runtime defect.
- Principles / domains: Trust, Truthfulness, Promise-Keeping, Excellence; Technical, Operational, Evaluation.
- Stakeholders / decision: adopters, maintainers and downstream users; whether to represent exact package bytes as approved for production.
- Evidence: E01, E12-E15, E17-E19, E23. `current-preview.md:91-108` separates source and historical evidence; the actual tree contains extensive modified and untracked inputs. Cohort/source/platform controls already exist.
- Cause and consequence: reviewed source, an earlier successful suite, a version string and a packed archive are different objects. Without current source/archive/installed/platform joins, an adopter can deploy bytes never covered by the relied-upon evidence.
- Counter-check: `VerificationCohort.cs:66-82,97-145` already rejects changed source and substituted originals. `Verification.cs:48-82,114-138` protects test ownership/discovery. This is an execution/admission gap, not a request to build another pipeline.
- Mitigation / owner: **IVSD-M001**, release/provenance maintainer and adopting organization's security authority.
- Observable acceptance: freeze the selected source-content projection; retain original package/symbol hashes and independent rebuild results; execute required source and installed lanes with positive discovery; join actual SDK/runtime/OS/architecture and required hosted-platform results. Any changed bound input invalidates dependent evidence.
- Missing evidence / escalation: exact current candidate records and actual CI/protection observations were not reviewed. Release security acceptance belongs to the responsible organization. Public publication is not a prerequisite for private evaluation.

### IVSD-F002 — Deployment Identity, Effective Policy And Entitlement Need Independent Proof

- Severity / assessment: High / Concern; applies to each selected runtime or administrative deployment.
- Claim type / validation: documented trust boundary and missing deployment validation.
- Principles / domains: Trust, Justice, Non-Harm, Rights of People; Technical, Governance, Evaluation.
- Stakeholders / decision: tenants, secret owners and administrators; which principal may access which project/environment/path and operation.
- Evidence: E07, E09, E11-E13, E19; `ManagementAuthorization.cs:47-83` explicitly distinguishes local grants from provider proof.
- Cause and consequence: authority objects and lifetime declarations preserve host intent but cannot attest arbitrary supplied-token principal/policy correspondence. Misprovisioned credentials can be overprivileged even when local scope checks behave correctly.
- Counter-check: foreign-owner and substituted-evidence tests fail closed locally. The owned producer has causal proof paths; these are not evidence that every supplied token is introspectable or every deployment already qualifies.
- Mitigation / owner: **IVSD-M002**, adopter IAM/security owner and Infisical qualification owner.
- Observable acceptance: retain authorized deployment/version/edition and selected identity records; independently observe relevant policy, issue the actual runtime credentials, exercise allowed actions and denied actions, and challenge that same allowed actor against a populated foreign scope. Bind actual tokens by protected custody, never by including them or their fingerprints in this report.
- Missing evidence / escalation: effective runtime/admin policies, selected external issuers and entitlements were not validated. Do not replace missing proof with JWT decoding, labels, unrelated denied actors or Boolean flags.

### IVSD-F003 — Enterprise Network Trust Must Match The Selected Transport

- Severity / assessment: High when an unqualified host pipeline is selected / Concern; intentional authority tradeoff.
- Claim type / validation: implementation traceability and deployment-policy acceptance.
- Principles / domains: Trust, Non-Harm, Avoiding Spying; Technical, Operational, Governance.
- Stakeholders / decision: credential owners, network administrators and telemetry recipients; who controls destinations, TLS, proxies, retries and observation.
- Evidence: E08, E10, E13. `InfisicalTransportBinding.cs:57-76` configures safe defaults and no revocation lookup; explicit host mode retains arbitrary host policy.
- Cause and consequence: SDK checks cannot constrain opaque borrowed-handler internals. An enterprise may require revocation, corporate proxy, private CA or mTLS behavior beyond the safe profile, or inadvertently select a pipeline that discloses/replays credentials.
- Counter-check: safe redirect/private-trust tests and borrowed-ownership tests support their named contracts. The owner's pinned loopback HTTP observation cannot qualify a production HTTPS/private-CA deployment.
- Mitigation / owner: **IVSD-M003**, enterprise network/security owner with application maintainers.
- Observable acceptance: record the actual selected mode and pipeline; observe intended destinations and proxy path; reject wrong hostname/issuer and cross-origin credential redirects; verify actual retry/cookie/diagnostic policy and borrowed lifetime. Where certificate revocation is required, test the chosen policy rather than inferring it from private trust.
- Missing evidence / escalation: production DNS/egress/trust/proxy/revocation configuration and observations were not reviewed. Prefer safe mode when it meets the requirement; the deliberate host-controlled option remains legitimate when explicitly governed.

### IVSD-F004 — Deployed Diagnostic And Plaintext Boundaries Remain Unqualified

- Severity / assessment: High / Concern; disclosure assurance gap, not a reproduced exploit.
- Claim type / validation: supported SDK omission controls; missing host operational validation.
- Principles / domains: Trust, Non-Harm, Rights of People, Avoiding Spying, Modesty; Design, Technical, Operational, Evaluation.
- Stakeholders / decision: secret owners, data subjects, support and telemetry administrators; what may leave the process and who can retain it.
- Evidence: E02, E05, E08, E10, E16. Native HTTP representations necessarily contain selected coordinates and authorization headers; wrapper formatting cannot erase them.
- Cause and consequence: SDK-authored fields are only part of a deployed observation stack. Configuration dumps, exception enrichment, HTTP listeners, profilers, crash dumps and exported strings can bypass wrapper omission and expose reusable credentials.
- Counter-check: `InfisicalTransportOwnershipTests.cs:167-224,249-293` has positive diagnostic probes and inspects native HTTP payload members. `DemoDiagnosticsTests.cs:15-49,72-89` checks installed-process capture presence and canaries. Neither result was rerun here; this report does not declare those assertions failing.
- Mitigation / owner: **IVSD-M004**, adopter application/security/observability owners.
- Observable acceptance: on the exact runtime/artifacts and intended telemetry configuration, demonstrate active capture plus absence of synthetic value/token/coordinate canaries across success, denial, malformed input, transport error, renewal and shutdown. Check native HTTP surfaces separately from SDK Activity/Meter tags. Inventory explicit exports and approve dump/debug/log retention and access.
- Missing evidence / escalation: enterprise sinks, exporter configuration, dump policy and their access/retention records were not inspected. Do not install the nonpackable demo observer as an assumed production redaction component.

### IVSD-F005 — Cooperative Cleanup Needs A Real Application Termination Contract

- Severity / assessment: Medium, rising to High where unfinished work has security or availability consequences / Concern.
- Claim type / validation: intentional lifecycle limits and missing application validation.
- Principles / domains: Trust, Non-Harm, Promise-Keeping; Technical, Operational.
- Stakeholders / decision: on-call teams and application users; when to stop admission, drain accepted work, report timeout and terminate the process.
- Evidence: E04-E08, E10-E11, E22. Maintenance/native owners retain latched bounded shutdown outcomes; configuration owners retain lease/retirement completion.
- Cause and consequence: borrowed callbacks, credential sources, readers and disposers cannot be forcibly stopped by cancellation. A host may kill the process before safe drainage or hang waiting for callbacks whose ownership it misunderstood.
- Counter-check: blocked-reader, callback-pin and original-deadline tests deliberately exercise these limits. A timeout does not become success after eventual cleanup. The raw snapshot loader also deliberately drains uncooperative reads before returning.
- Mitigation / owner: **IVSD-M005**, application/platform reliability owner.
- Observable acceptance: hold active requests, credential acquisition and cleanup callbacks at event barriers; observe new-admission closure, bounded native stop failure, intact held work, eventual cleanup after release, no late publication, and repeated stop retaining its original outcome. Test actual service-manager/container grace periods against this sequence.
- Missing evidence / escalation: production callbacks and process termination configuration were not evaluated. Give separate budgets to collection, semantic validation, downstream work and shutdown; do not assume a provider operation timeout bounds every application callback.

### IVSD-F006 — Remote Effects And Uncertain/Pending Cleanup Need Independent Reconciliation

- Severity / assessment: High for selected mutating/lifecycle features / Concern; includes a documented approval-cleanup contract gap.
- Claim type / validation: implementation traceability, declared missing contract and missing native effects.
- Principles / domains: Trust, Non-Harm, Rights of People, Truthfulness; Technical, Operational, Governance.
- Stakeholders / decision: resource owners, operators and downstream users; whether a requested effect occurred, can be attributed, and can be safely cleaned up.
- Evidence: E03, E07, E09, E11, E18, E20. `RUNTIME_ADOPTION_SECURITY.md:182-188` explicitly keeps pending request teardown unresolved.
- Cause and consequence: a local receipt, HTTP acknowledgement, configured rotation, lease deletion or open-ended status string is not independent evidence of downstream credential replacement/invalidation. After process loss, local evidence alone is not durable reconciliation.
- Counter-check: partial bulk, lost-response, intended-reader denial and dynamic uncertainty tests preserve evidence rather than invent a result. Historical SQL dynamic/rotation runs encountered entitlement rejection; that does not prove all deployments incapable.
- Mitigation / owner: **IVSD-M006**, selected operation's application owner, provider administrator and downstream resource owner.
- Observable acceptance: keep caller-held original receipts and a durable material-free operation record; use independently observed resulting values, old-credential denial, allowed new use, original acknowledged handles and complete owned cleanup. Preserve uncertainty and obtain explicit recovery authority. A pending approval remains gated until a supported ownership/teardown contract exists.
- Missing evidence / escalation: actual selected backend/edition effects and producer cleanup are open or unreviewed. Do not add DB drivers to shipped packages, infer MariaDB from MySQL, invent cleanup endpoints, replace original handles, broaden principals, or weaken required denominators.
- Applicability: a read-only pilot can exclude these features from its own declared scope; it cannot claim the full mutation/native profile passed.

### IVSD-F007 — Audit Configuration Does Not Establish Accountability Or Retention

- Severity / assessment: High for privileged administration / Concern.
- Claim type / validation: implementation traceability and missing operational evidence.
- Principles / domains: Trust, Justice, Rights of People, Avoiding Spying; Technical, Operational, Governance, Evaluation.
- Stakeholders / decision: affected tenants, administrators, investigators and data subjects; what privileged actions are attributable, retained and contestable.
- Evidence: E09-E10, E18, E24; `Audit/Governance.cs:54-105,158-193,227-260` separates settings, bounded rows and protected metadata.
- Cause and consequence: settings readback and valid row parsing cannot show that all required actions produced events, actor attribution is adequate, or evidence survives the required retention period.
- Counter-check: row ordinal/outcome preservation and foreign-scope rejection protect local evidence quality. Automatically exporting every field or retaining everything would introduce different privacy harms.
- Mitigation / owner: **IVSD-M007**, adopter security operations, privacy owner and provider administrators.
- Observable acceptance: perform known authorized and denied actions; retrieve attributable provider events within a declared observation window; prove required export/access/retention and missing-event handling. Restrict retention and investigative access by purpose, and provide a correction/escalation path.
- Missing evidence / escalation: real events, event completeness, retention tests, investigation permissions and privacy/legal policy were not reviewed. External legal retention obligations require jurisdiction-specific counsel, not an SDK assertion.

### IVSD-F008 — Present Advisory Clearance Must Be Obtained, Not Inferred From Lockfiles

- Severity / assessment: High / Concern; current assurance evidence gap.
- Claim type / validation: implemented gate, unreviewed connected observation.
- Principles / domains: Trust, Non-Harm, Excellence, Promise-Keeping; Technical, Operational, Governance.
- Stakeholders / decision: package consumers and maintainers; whether to admit the exact resolved dependency graphs.
- Evidence: E14, E17, E21. Root inputs enable low-severity/all-dependency auditing; `DependencyAudit.cs:347-372,405-427` protects exceptions, native output and before/after joins.
- Cause and consequence: pinned versions and consistent lockfiles establish selection, not absence of known advisories or availability of current advisory data. Stale or incomplete reports can create false procurement assurance.
- Counter-check: source and installed audit orchestration, omission-resistant graph inventory and non-waiver behavior already exist. No missing audit-engine implementation was found.
- Mitigation / owner: **IVSD-M008**, dependency/provenance maintainer and security/release authority.
- Observable acceptance: run existing connected source and exact installed-graph audits; retain native stdout/stderr/exits, source identity, exact project/framework/package/version coverage, observation time and disposition. Missing/unavailable data, changed graphs or native failure must block clearance. Valid risk records must not waive the current vulnerable-report gate.
- Missing evidence / escalation: no current connected reports were inspected or produced here. This review neither identifies a new CVE nor asserts that the selected graph is vulnerability-free.

### IVSD-F009 — Procurement Distribution Inventory May Need An Additional Deliverable

- Severity / assessment: Medium / Not reviewed; applicability depends on the adopter's procurement policy.
- Claim type / validation: bounded absence of reviewed evidence, not a legal noncompliance conclusion.
- Principles / domains: Trust, Truthfulness, Rights of People; Strategic, Technical, Governance.
- Stakeholders / decision: procurement, legal, security and downstream distributors; whether exact shipped components and rights are sufficiently inspectable.
- Evidence: E14-E15, E21, E24. Notices, locked graphs, original archives and package metadata are present. A release-bound SPDX/CycloneDX generation/admission contract was not found in the reviewed build/release paths.
- Cause and consequence: human-readable notices and internal graph records may not satisfy a consumer's machine-readable distribution inventory requirements.
- Counter-check: substantial provenance infrastructure already exists. A new generic pipeline or duplicate dependency inventory would add inconsistency risk.
- Mitigation / owner: **IVSD-M009**, provenance/legal/procurement owners.
- Observable acceptance: if required, generate the selected SBOM format from the exact shipped runtime closure, join original package hashes, reconcile license/notices, validate the document and define refresh ownership. If not required, record the accepted alternative inventory and rationale.
- Missing evidence / escalation: procurement requirements and independent rights review were not supplied. MIT metadata alone is not an opinion on all contributor/transitive rights or another provider's commercial terms.

### IVSD-F010 — Application Readiness, Semantic Validation And Fleet Recovery Remain Host Duties

- Severity / assessment: High / Concern; application acceptance gate.
- Claim type / validation: supported composition contracts, missing production consumer evidence.
- Principles / domains: Trust, Non-Harm, Excellence, Truthfulness; Design, Technical, Operational, Evaluation.
- Stakeholders / decision: application users, platform engineers and tenant owners; when newly acquired material may drive real work.
- Evidence: E04-E06, E10-E11, E16, E18, E22. Real HTTP test source demonstrates held old/new clients and distinct liveness/readiness.
- Cause and consequence: a valid provider response, token-local healthy state, complete snapshot or configuration reload cannot show downstream authentication, safe rollout, application authorization or replica convergence.
- Counter-check: the coordinator already offers explicit validation, enable/check separation, selected stale policy, revision fences and leases. Recreating those mechanisms would not resolve production topology evidence.
- Mitigation / owner: **IVSD-M010**, adopter application and reliability owners.
- Observable acceptance: await required preparation before dependent service admission; test optional grouping, rejected replacements, old/new held work, known expiry, fail-closed/bounded-stale policy, identity replacement and restart. Independently demonstrate downstream use/denial and the selected multi-replica rollout policy. Keep business validation and durable convergence outside the SDK.
- Missing evidence / escalation: no enterprise application, request authorization model, topology, load target, stale tolerance or downstream recovery exercise was supplied. This is not a requirement to implement all those policies inside SecretKit.

### IVSD-F011 — Maintenance, Independent Assurance And Incident Capacity Are Not Established

- Severity / assessment: High / Concern; production stewardship gate.
- Claim type / validation: documented commitments and missing organizational/operational validation.
- Principles / domains: Trust, Non-Harm, Promise-Keeping, Justice, Excellence; Strategic, Operational, Governance, Evaluation.
- Stakeholders / decision: present/future adopters, maintainers and downstream users; who accepts security obligations after adoption.
- Evidence: E10, E11, E24. `DELIVERY_AND_MAINTENANCE.md:229-238` explicitly distinguishes proposed role labels from completed appointments. `SECURITY.md:3,17` avoids a stable support window and response SLA.
- Cause and consequence: strong code controls require people, backups for those people, vendor/dependency monitoring, remediation authority and communication capacity. A reporting address alone cannot establish those capabilities.
- Counter-check: vulnerability intake, contribution boundaries, threat scenarios, adversarial tests and release gates are meaningful existing safeguards. This review does not call them absent or demand an unsupported 24/7 promise.
- Mitigation / owner: **IVSD-M011**, project governance/security leaders and adopter risk owner.
- Observable acceptance: identify accountable people and deputies; accept the threat model and independent security-review disposition; exercise intake, triage, compromise containment, authorized revocation/recovery, adopter notification and postmortem. Define realistic supported versions, patch cadence, escalation, EOL notice and migration/continuity arrangements.
- Missing evidence / escalation: named appointments, independent audit/remediation evidence, actual response performance and incident drills were not established in reviewed material. Contractual support commitments require actual agreement and capacity.

### IVSD-F012 — Stakeholder Comprehension, Accessibility And Longitudinal Outcomes Need Validation

- Severity / assessment: Medium / Concern; outcome assurance gap.
- Claim type / validation: design reasoning and missing stakeholder/operational validation.
- Principles / domains: Justice, Rights of People, Excellence, Truthfulness, Avoiding Deception; Strategic, Design, Governance, Evaluation.
- Stakeholders / decision: integrators, operators, disabled developers, small teams, contributors and downstream non-users; whether the design's costs and failure meanings are understood fairly.
- Evidence: E25-E26. The adoption guide explicitly disclaims comparative evaluation/outreach and measured superiority; community policy includes accessibility and private/proportionate reporting.
- Cause and consequence: documentation can be technically accurate while users still misunderstand plaintext export, local versus remote authority, `Unknown`, readiness or disposal ownership. Those errors shift risk onto downstream people.
- Counter-check: focused package guides, clear preview language, meaningful examples and truthful alternatives reduce this risk. Missing interviews are not evidence that users currently misunderstand the API.
- Mitigation / owner: **IVSD-M012**, adoption/documentation/accessibility owner with representative enterprise evaluators.
- Observable acceptance: run representative console/worker/web adoption tasks; observe handling of denial, unknown mutation, expired session, replacement and explicit export; evaluate documentation/CLI accessibility; measure errors, support burden and exit/migration success over a declared period. Correct misleading guidance and disclose the limits of the sample.
- Missing evidence / escalation: interviews, accessibility assessment, complaints/incident trend data, funding/sponsor governance and longitudinal adoption evidence were not reviewed. Escalate actual conflicts of interest or religious/legal questions if they arise; do not infer them from absent documents.

## Recommendations

### Admission Sequence

This sequence specifies acceptance outcomes and responsibility. It is not an implementation plan or an instruction to perform provider actions.

| Gate | Required outcome | Findings / mitigations | Accountable decision |
| --- | --- | --- | --- |
| A1: Select the adoption slice | Name required packages, operations, provider deployment, identities, JIT/platform profile, exports and application topology | F002, F003, F009-F010 / M002-M003, M009-M010 | Adopter architecture and security owners |
| A2: Admit exact software | Existing source/installed/test/provenance/advisory controls pass for the actual selected bytes; required platform observations are joined | F001, F008 / M001, M008 | Release/provenance/security owners |
| A3: Admit authority and network | Observe actual principal/policy/entitlements and selected TLS/proxy/egress behavior | F002-F003 / M002-M003 | IAM, network and provider owners |
| A4: Admit consumer safety | Demonstrate semantic validation, diagnostic omission, freshness, held-work replacement and shutdown under the selected host | F004-F005, F010 / M004-M005, M010 | Application, observability and reliability owners |
| A5: Admit selected remote effects | Independently prove mutations, revocation/rotation/import delivery, attributable evidence and owned cleanup where used | F006-F007 / M006-M007 | Operation, downstream resource and security-operations owners |
| A6: Accept continuing responsibility | Establish people, incident response, independent review disposition, support/EOL and stakeholder evaluation commitments | F011-F012 / M011-M012 | Governance/security and adopter risk authorities |

Keep runtime, optional administrative admission, private deployment and public publication separate. Existing full profiles keep their denominators. A smaller production proposal needs explicit scope and its own accepted evidence; it may not silently turn failed/unavailable full-profile cases into success.

### Minimum Consumer Evidence For Real .NET Projects

| Consumer | Evidence needed beyond the library source |
| --- | --- |
| Console/automation job | Protected injection; bounded operation; absence distinct from denial; truthful nonzero failure outcomes; no material in console or exception sinks; original receipts for explicit writes |
| Generic Host worker | Awaited admission; separately opted-in renewal; verified original lifetime; stopping admission before drain/disposal; uncertainty/restart recovery; platform termination budget |
| ASP.NET Core service | Application tenant authorization; required preparation before serving; separate liveness/readiness; one accepted generation per request/job; held-request replacement; authenticated management kept out of ordinary request paths |
| Configuration consumer | Explicit mappings/precedence; acceptance of plaintext string exposure; ordinary debug/options/log review; coherent handle use where required; reload distinguished from validated client activation |
| Multi-replica infrastructure | Independent downstream effect witnesses; selected stale/expiry tolerance; durable material-free change/recovery records; replica acknowledgement and failure policy; no presumed fleet transaction |
| Privileged administration tool | Trusted grant issuance; separately selected admin identity; approval/change authorization; attributable audit evidence; uncertain-effect reconciliation and run-owned cleanup |

The installed examples provide useful behavioral starting points. Their loopback bindings, controlled providers and test-only observation components are not complete production infrastructure.

### Rejected Alternatives And Tradeoffs

| Alternative considered | Reason rejected or bounded |
| --- | --- |
| Declare “enterprise compliant” from package count, code quality or historical passing tests | It collapses source, artifacts, runtime authority, deployed effects and operating capacity into an unsupported claim. |
| Remove unavailable cases or reduce native denominators | It would manufacture assurance precisely where provider/identity/effect evidence is missing. Preserve the published profile and label smaller evaluations accurately. |
| Infer supplied-token authority from decoded JWTs, host labels or token hashes | Those facts cannot establish effective provider policy or causal custody. |
| Enforce safe-mode guarantees inside any arbitrary borrowed pipeline | The host deliberately owns that pipeline. Select safe mode or qualify the selected host policy explicitly. |
| Ban all host-controlled transport | Legitimate private trust, corporate proxy and host integration needs remain. Explicit authority and evidence are preferable to an inaccurate universal guarantee. |
| Retry uncertain writes, re-login silently or switch to an administrator | This can duplicate effects, consume limited credentials and cross authority boundaries. Preserve uncertainty and explicit recovery. |
| Add a durable workflow engine, DB drivers or fleet orchestration to the SDK | Those are application/infrastructure duties and would widen the secrets library's attack surface and support burden. |
| Treat every SDK-internal temporary string as a fixable secure-erasure violation | The published boundary is clearing owned storage, with explicit managed/plaintext limits. Govern actual exposure and minimize copies without promising process-wide erasure. |
| Introduce a general new verification framework | Existing cohort, audit, workflow and test-owner mechanisms are substantial. Execute and close their evidence gates rather than duplicate them. |
| Require every optional management/native family before any runtime pilot | Admission should match the selected operation slice. Optional scope does not justify promoting a subset into full-profile qualification. |
| Add old-framework support, compatibility aliases or provider-neutral hosting in advance | The target is greenfield/net10.0, with named expansion triggers. Evidence and actual demand should drive additional obligations. |
| Substitute an industry checklist for I-VSD or stakeholder participation | Security practice can operationalize duties; it cannot prove moral outcomes or remove scholarly/legal authority boundaries. |

## Stakeholders

| Stakeholder | Interest, possible harm and review duty |
| --- | --- |
| Secret/credential owners | Unauthorized access, disclosure, unclear revocation and loss of recovery authority; require explicit custody and effect evidence |
| Tenant and organization administrators | Cross-scope access, excess privilege and unattributable changes; require policy and administrative accountability |
| Application developers | Integration mistakes, confusing ownership and misleading convenience APIs; require usable contracts and representative examples |
| Operators/on-call teams | Unknown mutations, uncooperative shutdown, expired credentials and missing audit evidence; require actionable bounded status and realistic runbooks |
| Application end users and non-users represented in downstream data | Service interruption or exposure even without using SecretKit directly; their interests constrain deployment shortcuts |
| Disabled developers and teams with limited specialist capacity | Documentation/CLI barriers and hidden operational burden; require accessible guidance and comprehension validation |
| Maintainers/contributors | Unsustainable support promises, unclear responsibility and unsafe disclosure; require realistic appointments, escalation and respectful participation |
| Procurement, legal, security and audit reviewers | False claims, missing component provenance and unclear accountability; require inspectable records without credential disclosure |
| Infisical/deployment operators, external identity and network providers | Shared operational duties, entitlements, policy changes and incident cooperation; require explicit responsibility assignment |
| Future adopters and maintainers | Abandonment, stale support claims and hard exit; require continuity/EOL/migration decisions and preserved knowledge |

## I-VSD Principles And Domains

### Principle Derivation

| Principle | Provider-facing heuristic for this SDK | Evidence and remaining question |
| --- | --- | --- |
| Trust / Amanah | Treat credential access, material custody and privileged changes as entrusted authority; preserve actual ownership and uncertainty | E02-E15 support inspectable controls; F001-F008 and F011 address unclosed assurance/operating duties |
| Truthfulness / Sidq | State exactly what source, test, installed and native evidence establish; never market unsupported production/security guarantees | Preview/support/adoption disclosures are strong; retain current bindings and bounded claims |
| Justice / Adl | Do not shift tenant, operator or accessibility costs invisibly; preserve correction and accountable administration | Local scope checks/community policy help; real policy, audit and stakeholder evidence remain |
| Non-Harm / La Darar | Reduce foreseeable disclosure, privilege misuse, uncertain effects and disruption before extending automation | Strong negative-boundary tests exist; application and deployment validation must follow |
| Rights of People | Protect secrets and affected people's downstream data, permission boundaries, correction, continuity and exit | No in-process erasure guarantee; hosts must govern plaintext, logs, audit access and retention |
| Avoiding Spying / Tajassus | Emit only justified material-free diagnostics and restrict observation/retention | Closed SDK tags support minimization; actual host exporters and provider audit use need review |
| Avoiding Deception | Do not turn a declaration, digest, catalogue count, healthy token or successful acknowledgement into a trust badge | Existing qualification distinctions are valuable; this report preserves them |
| Reducing Gharar | Make capability, lifetime, unknown outcome, support and export limits understandable before adoption | Typed failures and honest support scope help; comprehension and operating agreements remain unvalidated |
| Promise-Keeping | Make support, response, platform, portability and EOL commitments only with capacity and evidence | No false SLA is promised; production adopters still need accepted continuing arrangements |
| Excellence / Ihsan | Prefer deterministic boundary tests, independent effects, safe defaults and maintainable scope over cosmetic checkmarks | Strong source controls are visible; independent assessment and continuous evaluation remain |
| Modesty / Haya | Avoid unnecessary exposure of material and sensitive coordinates in routine representations | Protected default surfaces support this narrow heuristic; no wider content judgment is made |
| Avoiding Riba | Examine actual financial contracts if selected, through qualified authority | No SDK-operated credit/billing/financial product is in scope; no religious-legal conclusion is drawn about external contracts |

### Six-Domain Review

| Domain | Supported direction | Remaining provider responsibility |
| --- | --- | --- |
| Strategic | Focused Infisical-first adoption, optional composition, MIT intent and candid alternatives avoid unsupported expansion | Establish sustainable stewardship, funding/conflict governance where applicable, and continuity |
| Design | Explicit ownership, absence/denial separation, safe defaults, deliberate export and bounded statuses reduce misleading affordances | Validate that integrators/operators understand the dangerous choices and can use guidance accessibly |
| Technical | Narrow Core, explicit native capabilities, authority checks, bounded parsing, conservative receipts and leases are substantial | Qualify exact deployments, host transports, actual consumer integrations and selected effects |
| Operational | Vulnerability intake, recovery guidance, explicit shutdown and qualification contracts exist | Exercise and staff response, audit retention, restoration, notification, patching and EOL |
| Governance | Target-native contribution, provenance, scope, release authority and private reporting are documented | Establish actual accountable appointments, independent security decisions, hosted protections and escalation |
| Evaluation | Authored source/installed/negative tests and precise evidence namespaces are strong | Obtain current executions, stakeholder participation, independent reviews and longitudinal harm/outcome data |

No normative claim here replaces qualified Sunni scholarly judgment on a religious-legal question. No current finding requires inventing a religious ruling to decide the engineering mitigation.

## Evaluation And Monitoring Proposal

These are proposed measures, not collected results or claims of achieved safety. Appoint the stated owner and adapt cadence/thresholds to the accepted deployment.

| Measure | Owner / source | Cadence / action threshold | Stakeholders and limitations |
| --- | --- | --- | --- |
| Candidate evidence completeness | Release owner / source, cohort, archive, installed, platform and audit records | Every candidate; any required missing/mismatched/failed record blocks its claim | Adopters; digests verify correspondence, not truth of observations |
| Credential disclosure checks | Security/observability / synthetic canary tests and restricted incident records | Every relevant runtime/telemetry change; any protected canary in a prohibited sink blocks admission and triggers incident triage | Secret owners/data subjects; a negative test does not cover unknown sinks |
| Denial/isolation correctness | IAM/application / same-actor negative challenges and authorization tests | Every identity/policy/scope change; unauthorized success blocks the deployment | Tenants; tests cover named boundaries, not every possible policy |
| Uncertain mutation reconciliation | Operation owner / material-free receipt journal and independent effect observations | Per uncertain operation and routine operational review; unresolved effects exceeding the agreed window escalate rather than replay | Resource owners/operators; safe windows depend on the operation |
| Credential expiry/recovery | Reliability/IAM / session outcomes and restart/replacement exercises | Every lifecycle-policy change and scheduled drill; missed admission cutoff or unowned recovery blocks acceptance | Application users; token-local health is not downstream readiness |
| Shutdown/retirement | Platform/application / held-work and actual termination observations | Every host/platform lifecycle change; premature disposal, late publication or falsely reported drain blocks rollout | Users/operators; arbitrary callbacks remain cooperative |
| Dependency/advisory response | Security/provenance / connected exact-graph reports and remediation records | Each admitted candidate plus an accepted monitoring schedule; unavailable/failed clearance stays blocked under present policy | Adopters; this is not a universal vulnerability-free claim |
| Vulnerability and incident handling | Security lead/deputy / private intake, drills and restricted postmortems | Exercise before production, then agreed review; unassigned severity/notification owner or failed drill requires correction | Affected people/maintainers; do not publish sensitive raw evidence |
| Audit availability and purpose | Security operations/privacy / known-event retrieval, export and retention tests | At policy change and agreed operating interval; missing required event or excess retention triggers review | Investigators/data subjects; completeness is bounded by observed sources |
| Onboarding/accessibility comprehension | Documentation/adoption / representative tasks and accessibility findings | Before enterprise claims and significant API changes; material misunderstanding or blocking access issue requires remediation | Developers/operators; small samples are not population-wide proof |
| Exit, support and continuity | Governance/adopter / support agreements and migration/recovery exercises | Before production and at support/EOL decisions; unowned exit or unsupported promise blocks the corresponding commitment | Future adopters; open source alone does not guarantee a successful migration |

No engagement, revenue, adoption count or theological concept is used as a proxy for moral success.

## Validation Gaps

| Evidence level | What this review establishes | What remains |
| --- | --- | --- |
| Design validation | Principles, stakeholders, responsibility boundaries, tradeoffs and concrete mitigations are mapped | Independent challenge and organizational acceptance of the recommendations |
| Implementation traceability | Named code, configuration, documentation and test assertions support the stated scoped controls | New execution evidence, fuzzing/penetration results and exhaustive endpoint verification |
| Stakeholder validation | No new validation | Interviews, representative task studies, accessibility and affected-party feedback |
| Operational validation | Historical records are read as historical claims; operational acceptance is not newly established | Current candidate/platform/native runs, real protected CI settings, incident/retention/recovery observations |
| Theological/scholarly validation | No religious-legal ruling requested or issued | Qualified review if actual finance, disputed obligations or religious claims enter scope |

Specific non-executions:

- No `dotnet restore`, build, test, format, pack, publish, sample execution, installed consumer execution or conformance host was run.
- No provider, database, identity issuer, cloud, proxy or credential operation was attempted.
- No runtime secret input, actual credentials, process memory or private task artifact was inspected. External documentation examples were not used as evidence of SecretKit's implementation or current runtime behavior.
- Hosted repository settings, current workflow run outputs, original package archives, connected advisory outputs, incident records and production applications were not inspected.
- Source-file hashes and report structure/reference/whitespace checks are review-integrity/document checks, not product tests.

These limits constrain the claim level, not the ability to produce a useful current readiness report. Missing remote authority does not invalidate independently completed source engineering or prove universal SDK impossibility.

## Escalation Needed

| Authority | Question or acceptance needed | When |
| --- | --- | --- |
| Enterprise security/IAM/network owners | Accept threat boundaries, selected principal/policy, transport, telemetry and credential recovery | Before the corresponding real deployment is admitted |
| Application/platform reliability owners | Accept downstream validation, stale tolerance, tenant mapping, fleet behavior and termination ordering | Before serving affected work |
| Project governance and security leadership | Name accountable people/deputies; accept independent assessment, support, incident and EOL arrangements | Before a production-readiness/support commitment |
| Procurement/legal/privacy counsel | Determine actual inventory, license, provider-contract, retention and jurisdictional obligations | When those contractual/regulatory requirements are selected |
| Qualified Sunni scholarly authority | Decide any actual halal/haram/makrooh/wajib, riba or contested religious-legal issue | If such a question arises; none is decided by this report |

No reporting address, local grant, scholarly label or content digest delegates these authorities to the reviewer.

## Evidence Reviewed

### Method And Revision Binding

The target resolved to the independent repository `repos/SecretKit`, on `main`, with the Git object recorded in metadata. Read-only Git root/revision/status inspection completed successfully. The tree contained extensive pre-existing modified and untracked files, including security, diagnostics, release and enterprise-profile changes. This report assesses those actual files rather than pretending the Git object alone represents them.

Three independent read-only evidence tracks examined Infisical runtime, Infisical Management, and delivery/operating controls. The lead separately traced shared packages and direct consumers, read primary management/network/delivery boundaries, and counter-checked important test assertions. Delegation memos are supporting analysis, not a substitute for the primary file locators below.

Two additional independent challenges read the completed report and counter-checked its cited primary evidence without seeing each other's analysis. Weights were assigned before their conclusions. Neither found a material contradiction; no cross-evaluation of conflicting proposals was needed. This is a review-quality judgment, not an adoption/compliance score or independent product certification.

```json
{
  "review": "static-report-evidence-fidelity",
  "proposals": [
    {
      "id": "A",
      "weight": 0.6,
      "verdict": "deliver",
      "evidenceFidelity": 4,
      "scaleMaximum": 5,
      "newMaterialDefects": []
    },
    {
      "id": "B",
      "weight": 0.4,
      "verdict": "deliver",
      "evidenceFidelity": 4,
      "scaleMaximum": 5,
      "newMaterialDefects": []
    }
  ],
  "weightedEvidenceFidelity": 4,
  "dissent": [],
  "requiredCorrectnessPatches": [],
  "requiredProductExecutionForThisStaticReport": [],
  "residualLimits": [
    "Focused static corroboration, not exhaustive reconstruction of every claim",
    "No product tests, native qualification or operational assessment executed",
    "Production adoption gates and all twelve open findings remain"
  ]
}
```

Report checks verified the required structure, 120 unique sequential control IDs, 12 unique finding/mitigation pairs, all 29 evidence IDs, 139 explicit or shortened source locators and their applicable line bounds, and clean whitespace. These checks do not evaluate product behavior.

A 359-file integrity inventory covered the five scoped `src` package roots, their ordinary Core/Infisical/Management/Configuration/Hosting test roots, Consumer/Release/Package/Demo test roots, and `tools/SecretKit.Release`. It included `.cs`, `.csproj`, `.json`, and `.md` files under those roots and excluded `bin`/`obj`. It was captured at `2026-11-05T12:17:52Z`; a subsequent comparison before report drafting found no changes to those inventoried bytes. Separately fingerprinted lead-reviewed files also showed no drift at that comparison.

The aggregate hashes records sorted by ordinal relative path, each encoded as UTF-8 `path`, NUL, lowercase SHA-256 of file bytes, and newline. This is a review-specific fingerprint, **not** SecretKit's canonical release source-content projection, installed qualification, an atomic filesystem snapshot, or a statement that all 359 files were read line by line. Conformance-source references and other documents below retain their individual locators; they are not all members of that inventory.

Representative exact file hashes:

| File | SHA-256 |
| --- | --- |
| `src/SecretKit.Core/Material/SecretMaterial.cs` | `8ce46226656462810469c535d7e9576753e9d0ee288d9c1ea9a6a95829f9522c` |
| `src/SecretKit.Extensions.Configuration/Generations/SecretGenerationCoordinator.cs` | `91678d637c79572199bb82a70043b9ca20217497e4efb666dbc70be684eeb3d4` |
| `src/SecretKit.Extensions.Hosting/Registration/InfisicalServiceCollectionExtensions.cs` | `3c4349b2ac2abf86740f18a1a28f56eb6bbc85228d4d1090760b374d0a03472d` |
| `src/SecretKit.Infisical/Transport/InfisicalTransportBinding.cs` | `efeac4c76eb0d657542fc55f3889c724b747134995ea2827475333f70937a4e2` |
| `src/SecretKit.Infisical/Internal/InfisicalOperationBudget.cs` | `7bfa1ca73125736e56c707b69d47e3b6e2a7b6522b9923f12e23bf700f37896d` |
| `src/SecretKit.Infisical.Management/Transport/ManagementClient.cs` | `a537e72febf7f197fb68fcf2ed54817b3302b5d5ba5305d09fa271ecbc84b88e` |
| `tools/SecretKit.Release/DependencyAudit.cs` | `c2ec332feb6f6e2660c8bba6baadad492a4eaaa798fc4f277b5683c31ea182b7` |
| `tools/SecretKit.Release/VerificationCohort.cs` | `75cf777eaa2bd39b032df91365e772774fd32ad4e409802adfa5c017c9919eda` |
| `docs/internal/compatibility/enterprise-hardening-profile.json` | `555bc021b90fee1591d42448eecc5287b70e2ae870bdb8bc134eb2ce147fb48d` |
| `.github/workflows/verify.yml` | `7a562138069912b5f42d953a5f9433def08a728a23d64dfc4715ca802186546d` |

### Primary Evidence Register

All paths in this register are relative to `repos/SecretKit`. Line ranges identify the reviewed source sections, not executed test results. Companion test names/locators identify concrete negative or stateful witnesses.

| ID | Primary sources / symbols | Inspected witnesses or relevance |
| --- | --- | --- |
| E01 | `AGENTS.md:1-64`; `CLAUDE.md:1-5`; `CONTRIBUTING.md:1-55`; `PROJECTS.md`; `README.md:1-7`; `docs/public/current-preview.md:1-37,91-135` | Target authority, greenfield rules, preview claim and historical/current evidence distinction |
| E02 | `src/SecretKit.Core/Material/SecretMaterial.cs:18-40,93-123,164-187,229-278` | `tests/SecretKit.Core.Tests/SecretMaterialOwnershipTests.cs`; `SecretMaterialSpanTests.cs:33-102`; `Utf8MaterialTests.cs:43-87` |
| E03 | `src/SecretKit.Core/Primitives/SecretReference.cs:5-68`; `Outcomes/SecretOutcome.cs:6-139`; `Receipts/MutationReceipt.cs:22-93`; `Receipts/MutationReceiptIssuer.cs:3-46` under the same Core root | Core `AuthorityIsolationTests.cs`, `MutationReceiptIssuerTests.cs`, `MutationReceiptTests.cs`, `OutcomeContractTests.cs` |
| E04 | `src/SecretKit.Extensions.Configuration/Snapshots/SecretSelection.cs:6-49`; `SecretCollectionOptions.cs:7-31`; `SecretSnapshotLoader.cs:24-44,111-247,249-308`; `SecretSnapshotHandle.cs:35-75,81-137` | `tests/SecretKit.Configuration.Tests/BoundedCollectionTests.cs:14-298`; `OptionalSelectionTests.cs`; `ConfigurationTests.cs` |
| E05 | `src/SecretKit.Extensions.Configuration/Generations/SecretGenerationCoordinator.cs:75-97,149-218,308-376`; `SecretGenerationLease.cs:23-78,95-125`; `Export/SecretConfigurationExport.cs:30-34,52-108,114-183`; `Generations/ConfigurationDiagnostics.cs:27-46,95-178` | Configuration `SecretGenerationCoordinatorTests.cs:9-194`; `ConfigurationDiagnosticsTests.cs:17-59`; explicit export and retirement contracts |
| E06 | `src/SecretKit.Extensions.Hosting/Registration/InfisicalServiceCollectionExtensions.cs:16-66,70-132,160-190`; `InfisicalHostingOptions.cs:25-43`; `Lifecycle/InfisicalStartupAdmissionService.cs:13-88`; `Lifecycle/InfisicalAuthenticationMaintenance.cs:76-115,150-293` | `tests/SecretKit.Hosting.Tests/HostingRegistrationTests.cs:15-88`; `HostingOptionsTests.cs:16-335`; `TokenMaintenanceTests.cs`; `HostingDiagnosticsTests.cs` |
| E07 | `src/SecretKit.Infisical/Secrets/InfisicalClient.cs:139-222,320-385,425-465,515-581`; `Authentication/NativeAuthority.cs:55-97`; `InfisicalUniversalAuthentication.cs:72-174,234-254`; `InfisicalProofAuthentication.cs:245-301,327-339`; `InfisicalRuntimeSession.cs:116-138,239-241`; `InfisicalPeriodicTokenSession.cs:370-445,490-498`; `InfisicalTokenRevocation.cs:41-95`; runtime `NativeBulk.cs:259-276`, `Imports/ImportEffectObservation.cs:26-87`, `Dynamic/InfisicalDynamicClient.cs:373-409`, `Dynamic/InfisicalLeaseTypes.cs:72-88,150-176`, `Rotation/InfisicalRotationClient.cs:169-177` | Infisical `InfisicalReadTests.cs:17`; `InfisicalRevisionTests.cs:41`; `UniversalAuthenticationTests.cs:151,167`; `AuthenticationEnvelopeTests.cs:25-104`; `RuntimeSessionTests.cs:61,148`; `ProofAuthenticationTests.cs:169`; `TokenRevocationTests.cs:75,112`; `LeaseLifecycleTests.cs:151-175,203-235`; `BulkReceiptTests.cs:16-49`; `ImportEffectTests.cs:46-62`; `RotationOutcomeTests.cs:162-173,311` |
| E08 | `src/SecretKit.Infisical/Transport/InfisicalTransportBinding.cs:15-30,44-105`; `InfisicalTransportOptions.cs:5-51`; `Internal/InfisicalOperationBudget.cs:20-69,74-140,145-205`; `Secrets/InfisicalStaticWire.cs:9-19` | Infisical `TransportPolicyTests.cs:169,301-378`; `OperationBudgetTests.cs:77-160`; `InfisicalTransportOwnershipTests.cs:16,61,167-224,249-293` |
| E09 | `src/SecretKit.Infisical.Management/Access/ManagementAuthorization.cs:6-147`; `Transport/ManagementContracts.cs:13-78`; `ManagementRequestBuilder.cs:64-99`; `ManagementClient.cs:120-281`; `ManagementDiagnostics.cs:13-88`; `Access/RolePermissions.cs:353-369,471-517,556-609`; `Identities/IdentityAuthenticationTypes.cs:364-367`; `Projects/ProjectFieldVariants.cs:25-46`; `Audit/Governance.cs:54-105,158-193,227-260`; `Rotations/PostgresSecretRotations.cs:15-98`; `Gateways/GatewayAdministration.cs:8-61` | Management `ManagementBoundaryTests.cs:136-173,221-261,344-379,414-456`; `TypedDispatchGuardTests.cs:19-79`; `ManagementBudgetTests.cs:16-31,46-87,128-142`; `AuthenticationProjectionTests.cs:186-271,319-377`; `PermissionResultTests.cs:187-213`; `RoleChangeTests.cs:320-415`; `ManagementDiagnosticsTests.cs:34-102`; `PostgresSecretRotationTests.cs:332-348`; `GatewayAdministrationTests.cs:248-257` |
| E10 | `SECURITY.md:1-43`; `docs/public/security-and-ownership.md:13-35,37-62,69-147,154-197` | Explicit host/plaintext/network/health boundaries, private intake and unpromised support terms |
| E11 | `docs/internal/RUNTIME_ADOPTION_SECURITY.md:14-51,54-95,97-155,157-193` | Existing threat scenarios, causal proof, cleanup, native denominators and trim/AOT limitations |
| E12 | `docs/internal/compatibility/infisical-local-profile.md:140-185`; `docs/public/local-packages.md:160-185` | Separate functional/full-native claims, unavailable arbitrary-token binding and current original-byte obligations |
| E13 | `docs/internal/compatibility/enterprise-hardening-profile.json:1-65`; corresponding `.md:9-27,62-116,118-157,168-193` | Declaration, G1/G3/G4/G5 relevance, distinct evidence kinds and S24-scoped native owner path |
| E14 | `tools/SecretKit.Release/DependencyAudit.cs:247-372,375-437`; `docs/internal/DELIVERY_AND_MAINTENANCE.md:150-215` | `tests/SecretKit.Release.Tests/DependencyAuditTests.cs:84-145`; native reports, exceptions and complete installed graph ownership |
| E15 | `tools/SecretKit.Release/VerificationCohort.cs:20-94,97-145` | Release `VerificationCohortTests.cs:113,129`; `LocalQualificationTests.cs:65,88,103`; Package `PackageDebuggingTests.cs:12-29` |
| E16 | `tests/SecretKit.Demo.Tests/WebDemoTests.cs:84-157`; `WorkerDemoTests.cs:82-174`; `DemoDiagnosticsTests.cs:15-89` | Real installed-process/HTTP behavior is authored; tests were not run during this review |
| E17 | `.github/workflows/verify.yml:7-23,46-84,336-394`; `tools/SecretKit.Release/Verification.cs:48-82,110-138`; `WorkflowPolicy.cs` | Release `WorkflowTests.cs:19-29,54-57,195,234`; `VerificationTests.cs:85-128`; declared source/privileged-context separation |
| E18 | `docs/public/operations-and-compatibility.md:92-123,130-203`; `docs/internal/INTEGRATION_QUALITY_FOLLOW_UPS.md:7-27` | Completeness, mutation recovery, identity replacement, JIT posture and demand-triggered expansion |
| E19 | `docs/public/provider-support.md:10-60,64-70,100-134` | Reviewed Infisical/shared rows only; package presence, research inventories and endpoint selection are not full support |
| E20 | `docs/internal/compatibility/dynamic-lifecycle-evidence.md:13-29,31-59`; `rotation-progress-evidence.md:7-29` | Dated entitlement failures and explicitly unrun downstream effects; historical statements are not current universal limits |
| E21 | `global.json:1-9`; `Directory.Build.props:3-26`; `Directory.Packages.props:3-20`; `NuGet.Config:3-15`; the five scoped package `.csproj` files | Direct dependency boundaries and configured build/audit inputs, not a connected vulnerability result |
| E22 | `tests/SecretKit.Consumer.Tests/ActivationRevisionTests.cs:10`; `StalePolicyTests.cs:12-115`; `tests/SecretKit.Configuration.Tests/SecretGenerationCoordinatorTests.cs:9-194` | Deliberate owner replacement, stale/expiry policy, request/client pins, validation and retirement |
| E23 | `docs/internal/releases/PUBLICATION_PROTOCOL.md:31-72,123-154`; `.github/workflows/publish.yml:282-314,421-474` | Release `PublicationTests.cs:168-216`; `ReleaseAuthorizationTests.cs:137,185`; `ProducerWorkflowTests.cs:40`; no publication/settings inspection |
| E24 | `LICENSE`; `THIRD-PARTY-NOTICES.md:142-178`; `Directory.Build.targets:2-6`; `docs/internal/DELIVERY_AND_MAINTENANCE.md:217-246` | Package `PackageSelectionTests.cs:11-32`; Release `ArchiveTests.cs:73-88`; proposed maintenance roles and narrow reproducibility claims |
| E25 | `docs/public/adoption-and-value.md:18-58,61-79,81-110`; `docs/README.md:9-38` | Honest alternatives, absent comparative study/outreach and developer guidance |
| E26 | `CODE_OF_CONDUCT.md:3-20`; `CONTRIBUTING.md` | Community privacy, accessibility needs, proportionate assessment and correction channels |

Some register cells use a common package/test directory followed by sibling filenames to keep them readable. Their directory context is the first fully qualified file in that cell. No shortened locator refers to an Azure package.

### Supporting Public Guidance

These sources inform the risk-based engineering criteria. They do not supply SecretKit implementation evidence or an attestation. Access date: 2026-11-05.

| ID | Source and selected facts | Use and limits |
| --- | --- | --- |
| X01 | NIST SP 800-218, SSDF version 1.1 final, February 2022: `https://csrc.nist.gov/pubs/sp/800/218/final`; framework overview: `https://csrc.nist.gov/projects/ssdf`; linked publication: `https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf` | Supports organizing supplier duties around preparation, software protection, secure production and vulnerability response. This is the selected published baseline, not a claim about the latest revision or formal SSDF attestation. |
| X02 | OWASP Secrets Management Cheat Sheet: `https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html` | Supports treating secret handling as lifecycle responsibility involving least privilege, rotation/revocation, audit and incident response. No claim of exhaustive OWASP compliance is made. |
| X03 | Microsoft .NET Generic Host: `https://learn.microsoft.com/en-us/dotnet/core/extensions/generic-host`; DI guidance: `https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection-guidelines` | Supports explicit host lifecycle and disposal ownership. No legacy WebHost timing default is imported into SecretKit's contract. |

The .NET documentation lookup also returned legacy implementation examples. They were not used as current shutdown timing authority and no external implementation expression was copied into this report or the repository. No vendor implementation source informed the assessment.

A limited supporting crosswalk is appropriate: SSDF preparation corresponds to ownership/threat acceptance; software protection to source/archive/CI integrity; secure production to boundary tests, dependencies and consumer evidence; vulnerability response to intake, remediation and incident capacity. OWASP lifecycle concerns correspond to C011-C040, C051-C060 and C081-C089. These are relevance mappings, not exhaustive standards-control audits.

## Missing Evidence

“Missing” here means unavailable to or not established by this review unless a primary source explicitly declares the gate open.

1. Current exact-source build/test/format/pack and installed-consumer records for the reviewed working tree and selected original archives.
2. Complete, authorized, current native provider evidence with deployment/version/edition, actual principal/policy/entitlements, independent effects and required cleanup.
3. Current hosted Linux/Windows runs and actual repository/environment protection, reviewer and publisher settings.
4. Production HTTPS/private-CA/proxy/revocation/egress configuration, selected host-pipeline behavior and infrastructure observations.
5. Production telemetry/export/dump/debug inventory, access/retention policy and negative disclosure observations.
6. Actual enterprise .NET application authorization, startup/readiness, lifecycle, semantic validation, multi-replica rollout and downstream recovery evidence.
7. Independent security-assessment report and accepted remediation/risk disposition.
8. Appointed maintainers/deputies, vulnerability/incident drills, notification practice, patch/support/EOL and continuity agreements.
9. Real audit event production, attribution, export, retention, missing-event handling and privacy-purpose evidence.
10. Current connected source and installed-graph advisory clearance.
11. A selected procurement SBOM requirement and its artifact, if applicable; independent rights/legal review where required.
12. Stakeholder participation, accessible onboarding assessment, representative operator comprehension, complaint/support trends, migration outcomes and longitudinal evaluation.
13. Actual business/funding/partner terms if they become relevant to the SDK's governance or adoption. No undisclosed financial misconduct is inferred.

## Context Inventory

- Repository/workspace: SecretKit's root instructions, security/contribution/community/license material, shared and Infisical sources/tests/configuration, public/internal contracts, compatibility declarations, release tool and workflows.
- User-provided context: `repos/SecretKit`; enterprise adoption in real .NET/infrastructure; high criticality of secrets; explicit Azure exclusion; confirmation of the general enterprise baseline.
- Existing planning/private context: no active triad was selected and no private `dev/` task material was inspected. This is a standalone consultation, not technical approval of an implementation plan.
- Project-context integrations: no issue, support, incident, hosted-settings, analytics or customer record was supplied or connected for this assessment. Available integration tooling was not treated as evidence of relevant records.
- Retrieval: local file inspection and bounded source searches; independent read-only evidence tracks; official NIST/OWASP/Microsoft guidance for supporting criteria. No provider account or protected-input access.
- Output identity: this project-qualified compliance report under the cockpit's `consultations/` directory. No matching report existed at this canonical path when checked.

## Review Lifecycle

| Date | Previous status | New status | Trigger | Evidence/replacement |
| --- | --- | --- | --- | --- |
| 2026-11-05 | none | draft | Enterprise adoption scope and evidence plan confirmed | User-confirmed Infisical/shared baseline and target guidance |
| 2026-11-05 | draft | current | Extensive source assessment, independent evidence tracks and report validation completed | Named working-tree input, review fingerprint and E01-E26; disposition remains changes-required |

“Current” means the report corresponds to its reviewed inputs. It does not mean production ready, findings resolved, stakeholder validated or release authorized.

Revalidate affected findings when source/package/lock/SDK inputs, profile/denominator rules, origins/transport/trust, principal/policy/lifetime, telemetry/export, supported effects/cleanup, application topology or operating commitments change. Attach new execution/operational evidence to its exact inputs; do not close findings by updating a date, reusing a historical count, changing a declaration, or substituting a matching digest.
