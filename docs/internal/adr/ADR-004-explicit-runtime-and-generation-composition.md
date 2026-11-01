# ADR-004: Explicit runtime and generation composition

- Date: 2026-11-01.
- Status: Accepted design; implementation evidence belongs to the execution ledger.
- Scope: Core, Infisical, Configuration, Hosting and exact local package consumers.

## Context

Applications previously assembled authentication, material, generation and export
owners separately. Convenience must reduce cleanup mistakes without selecting
authority, hiding I/O, retrying mutations or claiming downstream readiness.
Development APIs may change directly; compatibility aliases are not required.

## Decisions

1. Keep one material owner. Strict UTF-8 construction copies into clearable
   characters; byte count and bounded export synchronize with disposal. Reject
   malformed encoding with fixed exceptions, not fallback exception graphs.
2. Preserve closed failure reasons and bounded retry advice independently from
   status and mutation evidence. Diagnostics contain closed categories and
   numbers only. Listeners are host code, not an erasure or return-time boundary.
3. Give native operations independent encoded request, response and cooperative
   duration budgets. Cancellation is not preemption. Retain ownership until
   accepted work settles, reject late results and preserve dispatched effects.
4. Accept bounded additive token-response metadata while rejecting ambiguous
   duplicate root members and invalid known fields or lifetime evidence.
   Local credentials and qualification input retain their own strict schemas.
5. Own runtime composition explicitly. A caller-held single-use open attempt
   retains actual login evidence. A runtime owns its created client/session,
   never bootstrap recovery, borrowed transports or application policy.
6. Treat optional absence as an explicit complete observation, not permission to
   ignore denied, invalid or unavailable input. Export absence as a null mask.
7. Bound collection by selections, contiguous concurrent window, encoded material
   payload and admitted duration. Reduce by input ordinal, drain started work,
   revalidate reference/expiry before publication and publish once.
8. Prepare configuration asynchronously with one owner, then make string export
   a separate single-use action. Validate mappings before reveal. Export commit
   and notification failure remain distinct from rollback or app activation.
9. Keep Hosting's actual Infisical dependency. Registration borrows an already
   opened owner through instance descriptors; only explicitly selected maintenance
   starts at host startup. Helper stop ends the dedicated session generation.
10. Bind installed evidence to exact original archives, matching source and
    generated locks. Local PDB document checksums do not establish remote
    SourceLink resolution. A changed archive starts a new cohort.

## Alternatives rejected

A binary material hierarchy, generic outcome mapper, universal credential factory,
second lifecycle lease framework, automatic relogin, broad retry policy, hidden
refresh worker and second release pipeline would increase ownership ambiguity or
invent unsupported semantics. An empty provider-neutral hosting package has no
second real hosting contract to justify it.

## Consequences and verification

Core remains BCL-only; provider semantics stay native. Configuration and Hosting
remain independently optional. Plaintext exports, arbitrary host transports and
noncooperative callbacks retain explicit host responsibility. Local generation
coherence is not remote snapshot isolation. Encoded payload limits do not bound
total heap usage.

The execution triad tracks IQ-S01 through IQ-S20 and actual RED/GREEN evidence.
Existing native and local scenario denominators are unchanged. Offline tests,
controlled process demos, live provider conformance and public publication remain
separate claims. See [follow-ups](../INTEGRATION_QUALITY_FOLLOW_UPS.md),
[runtime contracts](../RUNTIME_CONTRACTS.md) and
[local qualification](../INFISICAL_LOCAL_READINESS.md).
