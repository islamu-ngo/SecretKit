# SecretKit.Testing

Nonpackable fixtures for this repository and its offline examples. Reference the
project from tests; it is deliberately absent from the seven-package release.

`InMemorySecretReader` uses address-instance identity. The Infisical variant uses
all native selector fields and supports bounded metadata inventory. `Set` copies
input material; reads return independently owned copies. Dispose every successful
read and the fixture. `Failure` injects native failure statuses; cancellation
remains an exception and foreign authorities remain invalid.

`TestTokenSource` copies values on rotation and issuance, and reports expiry using
the supplied `TimeProvider`. Existing issued copies survive a later rotation.
These fakes do not establish provider permissions, transport behavior, import
resolution, entitlement, renewal semantics, or live conformance.
