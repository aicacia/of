# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`GLOSSARY.md`** at the repo root, or
- **`GLOSSARY-MAP.md`** at the repo root if it exists: it points at each context's glossary and named design, contract, and operations documents. Read each one relevant to the topic.

If any of these files don't exist, **proceed silently**. Don't flag their absence; don't suggest creating them upfront. Create domain documentation lazily when terms or design actually get resolved.

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `GLOSSARY.md`. Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal: either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/domain-modeling`).

## Document current concepts and design

Keep definitions in the relevant `GLOSSARY.md`, without implementation details. Keep current design, contracts, and operational guidance in stable topic files such as `docs/design.md`, `docs/api.md`, `docs/security.md`, or `docs/operations.md`. Shared topics belong in root `docs/`; context-specific topics belong in `crates/<context>-service/docs/`.

Update topic documents in place and link them from `GLOSSARY-MAP.md`. Include rationale and constraints alongside the design they explain, not in numbered decision records or historical status sections. Do not create ADRs, even when a general-purpose skill suggests them. Distinguish design requirements from verified implementation behavior and acceptance evidence.

## Flag conflicts

If your output contradicts an existing definition or design contract, surface it explicitly rather than silently overriding it.
