# Admission of another secrets provider

## Current decision

Keep the existing Infisical-first local adoption priority and the documented
Azure implementation. Runtime adoption hardening adds consumers and evidence,
not another backend. No third provider, provider stub, universal lifecycle
facade, older framework target or restored connection/sync catalog is admitted
by this workstream.

This decision preserves the [core-first scope](CORE_SCOPE_AND_ROADMAP.md),
[public provider boundaries](../public/provider-support.md) and the existing
seven-package, two-provider public release authority. A local four-package
Infisical profile does not replace that public authority.

## Evidence required for a proposal

A proposal needs the following reviewable evidence before provider implementation
is selected:

| Decision | Required evidence |
| --- | --- |
| Demand | A named consuming application and concrete secret operation that the existing providers do not meet; an owner who can validate the useful outcome. A vendor feature list alone is insufficient. |
| Interface | Official read, write, authentication and relevant lifecycle contracts, including denial, absence, uncertainty, cancellation, version and retry semantics. Mark unsupported or unknown operations explicitly. |
| Boundaries | Selected authority, trusted endpoints, credential custody, caller-owned resources, disclosure surfaces, failure behavior and recovery ownership. Core must not acquire provider-specific or database behavior. |
| Maintenance | A responsible maintainer, a bounded first consumer slice and a test/update strategy for the selected native contract. |
| Provenance | Source attribution, distribution-compatible dependency/license review and an independently authored implementation. Researched interface facts are not permission to copy a vendor implementation. |
| Native verification | A named deployment/profile, required permissions/edition, separately authorized protected inputs and effect-level observations. Identify unavailable environments or entitlements rather than inventing qualification. |

Start with one useful vertical slice, not a catalog. Keep provider-native
authentication and lifecycle typed in the provider. Add a common Core operation
only when it has a demonstrated cross-provider meaning and reviewed failure
semantics; do not flatten every vendor capability into a common request facade.
Configuration export and hosting remain independently optional.

Database credentials remain opaque material. Database drivers and consumer
connections belong outside shipped secrets packages; optional native test
infrastructure does not create a general database-support matrix. See the
[database boundary](../public/database-credentials.md).

## Separate implementation from qualification

The review records the scope, evidence, unresolved assumptions and decision:

1. **Not admitted:** demand, contract or ownership is missing. Retain a bounded
   proposal rather than adding an empty provider project or public API.
2. **Admitted for a bounded implementation:** the selected consumer and contract
   justify authoring. Record the native verification plan and missing inputs.
   An unavailable credential or executor is not, by itself, an authoring blocker
   for an otherwise authorized implementation.
3. **Implemented with offline evidence:** deterministic tests and exact installed
   package consumers verify the named local behaviors. This is not native support.
4. **Natively observed:** bind exact package/source/profile identities to actual
   authorized native outcomes and cleanup. A successful read does not qualify
   writes, token identity, renewal, other editions or another backend.
5. **Release decision:** apply the existing release protocol and actual publisher
   authority. Implementation or native access does not authorize publication.

Do not repair an uncertain mutation with replay or a broader identity. Keep a
missing proof unavailable and retain its original denominator. Reopen the owning
implementation/evidence phase when a required invariant fails; narrow the claim
instead of weakening the test or recording an unobserved combination as supported.

The [runtime security contract](RUNTIME_ADOPTION_SECURITY.md) owns the current
threat boundaries and qualification requirements. Revisit this admission
decision when demonstrated demand changes, not merely when another provider
could be implemented.
