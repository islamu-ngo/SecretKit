# Documentation architecture and maintenance

> **Audience:** SDK maintainers, documentation contributors, and AI agents
> **Status:** Maintenance contract for the current Markdown documentation
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25 against repository source and official documentation
> **Source anchors:** [contributor contract](../../AGENTS.md), [build properties](../../Directory.Build.props), [public hub](../public/README.md)

Keep adopter guidance accurate, task-oriented and independently understandable.
Documentation describes implemented contracts without upgrading local evidence
to live-provider or release qualification.

## Information architecture

| Reader need | Canonical owner |
| --- | --- |
| Find a guide | [docs hub](../README.md), [public hub](../public/README.md) |
| Learn the first workflow | [Getting started](../public/getting-started.md) |
| Complete a task | Provider, configuration, authentication, installation and troubleshooting guides |
| Look up the common API contract | [Core reference](../public/core-api.md) |
| Look up provider-specific members/models | [Provider map](../public/providers/README.md), linked package declarations and inventories |
| Decide whether to adopt | [Adoption and value](../public/adoption-and-value.md), [scope](../public/scope-and-orchestration.md) |
| Determine implemented/verified scope | [Current preview](../public/current-preview.md), [provider support](../public/provider-support.md) |
| Explain design/invariants | [Architecture](SDK_ARCHITECTURE.md), [runtime contracts](RUNTIME_CONTRACTS.md), [ADRs](adr/) |
| Preserve dated observations | [Compatibility evidence](compatibility/), [research evidence](RESEARCH_EVIDENCE.md) |
| Navigate a code change | [Project map](../../PROJECTS.md), [agent reading map](../public/ai-agents.md) |

Use tutorial, how-to, reference and explanation as distinct reader intents.
A tutorial needs prerequisites, a repeatable path and observable results.
A how-to needs a concrete goal, declared inputs, steps and recovery.
A reference needs exact names, defaults, constraints and ownership.
An explanation needs decisions, alternatives and boundaries.

Keep historical checkpoints out of the first-use path. Link a canonical owner
instead of repeating changing counts, versions or support claims on every page.

## Source accuracy

For each behavior claim, inspect the declaration, implementation and relevant
test where available. Link the source that owns the claim; a test proves only
its actual execution environment and seam.

Use metadata below a page title: audience, status, owner, last verified and
source anchors. "Last verified" identifies a source review, not a new test or
native qualification run. Date historical evidence separately and retain its
original scope.

Separate four questions:

1. Does a callable typed implementation exist?
2. What input/response subset does it admit?
3. What offline or installed evidence exercised that subset?
4. What exact deployment, identity, policy, entitlement and effect was verified?

Read proposed sections and historical registries as design/research unless
current implementation and evidence establish more. Do not claim complete
provider coverage from a package, row count, or published vendor API.

## Example conventions

- Prefer existing runnable samples for first-use tutorials.
- Label standalone examples, command transcripts and integration fragments.
- Declare every external input's type and source in an integration fragment.
- Use current signatures and namespaces, deterministic setup and bounded
  cancellation. Never invent helper APIs.
- Dispose successful reads, material copies and acquired handles.
- Show deliberate string export only where needed; state its independent
  plaintext lifetime.
- Keep credentials, protected coordinates and realistic token examples out of
  snippets. Use synthetic material or clearly described host input.
- Do not imply comments or omitted application policy are executable setup.
- Keep provider I/O asynchronous; synchronous configuration loading cannot do
  secret acquisition.
- Distinguish expected output from output actually observed during this change.

Examples here are independently written from SecretKit's declarations and
samples. External documentation informs requirements and functional facts,
not copied prose or implementation.

## Checks for documentation changes

The repository requires documentation-only changes to use links, formatting and
command/path checks rather than SDK builds. Before handoff:

1. Check relative file and directory links, Markdown heading anchors, reference
   definitions and fenced code blocks across `docs/`.
2. Check changed files for trailing whitespace, malformed tables, broken fences
   and unresolved merge markers. A read-only `git diff --check` from the
   repository root covers diff whitespace.
3. Compare API names, overload inputs, defaults, enum values and ownership with
   the linked source; use neighboring tests for failures and concurrency.
4. Verify command projects, paths and configuration names. Separate commands
   intended to run from commands actually run.
5. Review discovery from the hubs: each new public page must be reachable, and
   readers must be able to find the next practical task.
6. Inspect the final diff for product/config/lock changes and unsupported
   provider/platform claims.

Do not add tests that pin prose. When source behavior changes, follow the full
SDK verification contract and update the matching documentation in the same
increment.

## API browser and IntelliSense

The current reference is Markdown with source-linked declarations. There is no
configured generated per-member API site. The build properties do not currently
enable `GenerateDocumentationFile`; a Markdown expansion must not be described
as complete packaged IntelliSense documentation.

Microsoft recommends documenting public types and members with XML comments,
including summaries and applicable parameter, return, exception and remarks
information. DocFX can combine that metadata with conceptual Markdown. A future
API-browser increment needs complete public XML documentation, explicit
documentation-file generation, a repository-owned tool/version/configuration,
cross-reference validation and a checked generation workflow. That changes
source/build/tooling beyond this `docs/`-only update; do not silently introduce
a dependency or suppress missing-documentation warnings.

Until then, the public type/family maps link exact source declarations. Avoid
manual copies of thousands of signatures that would drift independently.

## Research and design provenance

Official documentation was consulted on **2026-10-25**. The documentation
structure and examples are independently authored for SecretKit.

| Source | Owner | Applied factual guidance |
| --- | --- | --- |
| [Diataxis](https://diataxis.fr/) | Daniele Procida / Diataxis project | Separate tutorial, how-to, reference and explanation reader needs |
| [Recommended C# XML tags](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/xmldoc/recommended-tags) | Microsoft .NET documentation | Public types/members, summaries, parameters, returns, exceptions and linked remarks |
| [GenerateDocumentationFile](https://learn.microsoft.com/en-us/dotnet/core/project-sdk/msbuild-props#generatedocumentationfile) | Microsoft .NET SDK documentation | XML documentation generation is an explicit build setting |
| [DocFX .NET API docs](https://dotnet.github.io/docfx/docs/dotnet-api-docs.html) | .NET / DocFX maintainers | API metadata and conceptual content can be combined in a generated reference |

Context7 MCP resolved the official `/dotnet/docs` collection and retrieved
documentation-comment and generation guidance. Web lookup verified the
documentation architecture and API-tooling references. These are interface and
authoring facts, not vendor implementation inputs. No third-party code, assets,
packages or tooling were added.
