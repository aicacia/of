# Domain Docs

## Before exploring code

- Read `GLOSSARY-MAP.md` to select relevant contexts.
- Read the shared `GLOSSARY.md` and relevant context glossaries.
- Read relevant system-wide decisions in `docs/adr/`.
- Read relevant context contracts in `crates/<context>-service/docs/` and decisions in its `adr/` directory, as listed in the glossary map.
- Read `.scratch/unified-server/spec.md` for unified service requirements, `map.md` in that feature for active tickets, and `evidence.md` for historical implementation results. Operator procedures are in `operations.md` in the same feature.

If a mapped file or directory is absent, proceed silently. Create glossaries and ADRs only when terms or decisions are resolved.

## Layout

This repo has shared terms and three contexts: IdP, Management, and Storage. The root `GLOSSARY-MAP.md` lists their paths and relationships. Glossaries contain domain terms, not implementation rules or plans.

## Vocabulary and conflicts

Use glossary terms in issues, proposals, hypotheses, and tests. If a required term is missing, note the gap rather than invent a competing term.

Read ADR status before using a decision. State any conflict with an existing ADR; do not silently override it.
