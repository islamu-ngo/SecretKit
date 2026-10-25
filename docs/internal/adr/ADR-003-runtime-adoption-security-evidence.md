# ADR-003: Installed runtime adoption with causal security evidence

- Status: Accepted design, 2026-10-24; implementation and native gates remain separate
- Owners: SecretKit runtime/security maintainers
- Related: [runtime adoption contract](../RUNTIME_ADOPTION_SECURITY.md), [ADR-002](ADR-002-infisical-local-qualification.md)

## Context

Existing native APIs, generation examples and package-only fixtures establish
useful offline boundaries, but do not deliver three independent app models or
causal deployment/actor/policy qualification. Declaration-only tokens and
successful administrative reads cannot establish intended-runtime authority.

## Decision

Keep the small BCL-only Core and typed native provider behavior. Implement
console, worker and loopback-only web consumers against exact installed packages,
with independently optional Configuration/Hosting. Put app validation,
activation/readiness and client retirement in nonpackable examples, not the SDK.

Require failing disclosure/isolation/effect/lifecycle tests before implementation.
Produce native proof through explicitly authorized fresh issuance, same-actor
cross-scope challenges and independent effect observations. Cover partial setup
with a protected acknowledged-resource ledger and bounded authorized cleanup.
Retain original 21 cases, six lifetime supplements and separate producer cleanup.

Freeze source/profile/original archives before final native observations.
Keep local evidence separate from public release authority. Development breaking
changes are allowed; update real consumers rather than add compatibility aliases.

## Alternatives rejected

An umbrella facade or universal writer would flatten native outcomes and couple
optional dependencies. Source-only demos would not prove installability.
Application orchestration inside Hosting would impose policy. Supplied-token
labels, JWT decoding or policy digests would invent principal proof. Automatic
re-login/replay or broad cleanup could widen authority after uncertain effects.

## Consequences

More explicit test/proof composition is necessary, but it stays outside shipped
libraries. Operator setup, cleanup grants, edition capabilities and platform
executors are real external gates. A missing input never counts as qualification.
No production-readiness, general AOT support or publication claim follows.
