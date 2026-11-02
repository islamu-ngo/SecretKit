# SecretKit.Testing

Nonpackable fixtures for this repository and its offline examples. Reference the
project from tests; it is deliberately absent from the seven-package release.

This project depends only on SecretKit.Core. `InMemorySecretReader` uses
address-instance identity. `Set` copies input material; reads return independently owned copies. Dispose every successful
read and the fixture. `Failure` injects native failure statuses; cancellation
remains an exception and foreign authorities remain invalid.

Provider-specific fixtures live in [SecretKit.Testing.Infisical](../SecretKit.Testing.Infisical/).
The Core fixture does not establish provider permissions, transport behavior,
entitlement or live conformance.
