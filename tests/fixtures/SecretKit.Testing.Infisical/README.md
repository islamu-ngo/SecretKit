# SecretKit.Testing.Infisical

Nonpackable Infisical fixtures for repository tests and offline examples.
Reference this project and import `SecretKit.Testing.Infisical` for
`InMemoryInfisicalSecretReader` or `TestTokenSource`.

The reader builds on [SecretKit.Testing](../SecretKit.Testing/), matches all native
selector fields and supports bounded metadata inventory. `Set` and reads copy
material independently; dispose successful reads and the fixture. Foreign
authorities remain invalid, injected failures remain outcomes, and cancellation
remains an exception.

`TestTokenSource` copies values on rotation and issuance and evaluates expiry
using the supplied `TimeProvider`. Issued copies survive later rotation.
Neither fixture simulates provider permissions, transport behavior, imports,
entitlement, renewal or live conformance. Neither is part of the seven-package release.
