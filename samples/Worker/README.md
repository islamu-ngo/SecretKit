# Worker

Run `dotnet run --project samples/Worker --configuration Release`. Without
configuration this single-operation worker prints setup instructions and exits
without network I/O. It uses the shared framework only in this nonpackable sample.

For an owned Infisical environment, inject `SECRETKIT_ORIGIN` (HTTPS),
`SECRETKIT_CLIENT_ID`, `SECRETKIT_CLIENT_SECRET`, `SECRETKIT_PROJECT_ID`,
`SECRETKIT_ENVIRONMENT` and `SECRETKIT_KEY` using your host secret-injection tool.
Do not commit credentials or paste them into shell history. The sample selects a
finite Universal Auth lifetime; change this only from verified provider evidence.

Host startup admission authenticates first. The worker then reads one selected
secret, invokes a synchronous material callback, and stops the host. Substitute
your operation inside that callback; never retain its borrowed span. The sample
prints only completion and never mutates the provider. Environment strings remain
host-owned plaintext. Offline execution does not establish provider conformance.
