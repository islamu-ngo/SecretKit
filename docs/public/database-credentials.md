# Database credentials: API support, not database clients

> **Audience:** Developers using database credentials and provider-native lifecycle APIs
> **Status:** Current package boundary, not a database compatibility claim
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25 against package boundaries and retained source guidance
> **Source anchors:** [Core](../../src/SecretKit.Core/), [Infisical](providers/infisical.md), [management](providers/management.md)

SecretKit supports secret-provider APIs, not a general database-support matrix.
Database drivers do not belong in any shipped SecretKit package: not for SQL
Server, PostgreSQL, MySQL, MariaDB, or another database. Reading a credential and
verifying that it works are separate responsibilities.

## Core SDK: opaque secret material

Core defines common secret reads, references, outcomes and owned
`SecretMaterial`. Applications can retrieve database credentials through these
contracts, but Core does not interpret them as a database connection, open a
connection, execute SQL or validate a database login. Core remains BCL-only.

The application owns its database client, driver and connection lifecycle.
It decides how to use the returned material. Explicit plaintext exports have
their own lifetime; disposing `SecretMaterial` does not erase an exported string.

## Infisical adapter: typed provider APIs

The Infisical packages may expose Infisical's typed credential-generation,
dynamic-secret and rotation APIs for PostgreSQL, MySQL and SQL Server in their
documented subsets. Runtime access and administrative configuration retain their
respective package and identity boundaries.

These operations call Infisical. They do not make SecretKit a database client
or require database drivers in its shipped packages. Infisical may connect to
the configured database as part of its own generation or rotation service;
that is distinct from the SecretKit adapter connecting to the database.

Support claims describe the particular Infisical API, model, operation and
verified provider behavior. They do not imply that SecretKit implements a
database driver, a universal database abstraction or every database/version
combination. See [current provider support](provider-support.md) and the
[current preview](current-preview.md) for implemented subsets and evidence limits.

## Optional integration tests: verify returned credentials

An optional integration test may connect to a database to check that credentials
returned through the SDK actually authenticate, or that an intended rotation,
revocation or permission effect occurred. Such tests can use database clients,
drivers or native tools under explicitly selected test identities.

Those tools, dependencies and process adapters belong in nonpackable test
projects or fixtures under `tests/`, outside shipped packages under `src/`.
Installing or using SecretKit does not require them. They must not become
runtime dependencies of Core, either Infisical package or another shipped
SecretKit package.

A successful Infisical API response and successful database authentication are
different observations. Likewise, controlled test results do not establish live
compatibility. Test evidence must name its actual environment and effect without
turning that environment into a general SecretKit database-support claim.

## MariaDB requires separate verification

Supporting Infisical's MySQL rotation API does not establish MariaDB compatibility.
MariaDB would require separate verification of the relevant Infisical operation
and actual deployment. A MySQL API/profile label or a passing MySQL test cannot
stand in for that evidence.

## SQL Server / ODBC research status

As of October 22, 2026, the MSSQL/ODBC investigation was peripheral integration-test
infrastructure research. No ODBC helper was implemented, and no ODBC or database
driver dependency was added to the shipped libraries.

Existing database verification fixtures and any future optional test tooling
remain subject to the same separation above. Research into a possible test
transport does not expand the SDK's product scope or establish database support.

## Next steps

Use [Core ownership](core-api.md#material-and-read-ownership) when passing material
to your application-owned database client. Use the
[Infisical native guide](providers/infisical.md) for dynamic credentials and
rotation observations, and [management](providers/management.md) for separately
authorized SQL rotation configuration.
