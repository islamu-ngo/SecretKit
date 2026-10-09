# SecretKit

SecretKit is a .NET 10 secret-management SDK under development for Infisical and
Azure Key Vault. It keeps a small provider-independent read contract while
preserving provider-native lifecycle and administrative semantics.

This checkout is not a published or fully verified release. See
[the design](docs/public/README.md), [architecture](docs/internal/SDK_ARCHITECTURE.md)
and [runtime contracts](docs/internal/RUNTIME_CONTRACTS.md). Implemented support
and live-provider conformance are separate evidence.
The [current local preview](docs/public/current-preview.md) names the implemented
implemented subset, networking controls and remaining support gates.

Select the provider and identity explicitly. Dispose owned secret material after
use. Deliberate string/configuration exports cannot be erased by disposing the
SDK buffer. Hosts own credential injection, instrumentation and consumer policy.

Build and test with .NET SDK 10.0.302 using the commands in [AGENTS.md](AGENTS.md).
Local preview artifacts are not a publication or completed coverage claim.
