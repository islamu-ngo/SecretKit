# AspNetCore

Run `dotnet run --project samples/AspNetCore --configuration Release`. Without
configuration it prints setup instructions and exits without network I/O.

For an owned Infisical environment, inject `SECRETKIT_ORIGIN` (HTTPS),
`SECRETKIT_CLIENT_ID`, `SECRETKIT_CLIENT_SECRET`, `SECRETKIT_PROJECT_ID` and
`SECRETKIT_ENVIRONMENT` through your host or development secret injection tool.
Do not commit credentials or paste them into command history. This sample selects
a finite Universal Auth lifetime; adapt that policy only with verified provider
evidence. It authenticates before listening on `http://127.0.0.1:5080`.

The root endpoint reports startup only and does not return secret material or
claim downstream readiness. Stop with Ctrl+C. Environment strings remain
host-owned plaintext. Live execution requires your own selected identity and
permissions; the offline startup path does not establish provider conformance.
