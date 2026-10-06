# Issue tracker: Local Markdown

Issues and specs live in `.scratch/`.

## Conventions

- Feature directory: `.scratch/<feature-slug>/`.
- Spec: `.scratch/<feature-slug>/spec.md`.
- Tickets: `.scratch/<feature-slug>/issues/<NN>-<slug>.md`. Number from `01`. Use one file per ticket.
- Record triage state in a `Status:` line near the top. Use the labels in `triage-labels.md`.
- Append comments under `## Comments`.

## Publish and fetch

To publish, create the spec or ticket at its defined path. Create parent directories as needed.

To fetch, read the referenced file. Resolve issue numbers within the specified feature.

## Wayfinding operations

- Map: `.scratch/<effort>/map.md`, with Notes, Decisions-so-far, and Fog sections.
- Child ticket: `.scratch/<effort>/issues/<NN>-<slug>.md`. Put the question in the body.
- Type: `research`, `prototype`, `grilling`, or `task`.
- Work status: `open`, `claimed`, or `resolved`. This is separate from triage state.
- Dependencies: `Blocked by: NN, NN`. A ticket is unblocked when all listed tickets are resolved.
- Frontier: choose the lowest-numbered open, unblocked ticket.
- Claim: set `Status: claimed` and save before work.
- Resolve: append `## Answer`, set `Status: resolved`, and add a summary and ticket link to Decisions-so-far in the map.
