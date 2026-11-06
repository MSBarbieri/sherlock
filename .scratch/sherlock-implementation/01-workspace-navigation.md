# Build the secret workspace list and investigation detail

## Goal

Replace finding-first navigation with a searchable workspace list and an in-context detail view, following `docs/investigation-workspace.md`.

## Acceptance criteria

- Exact nonempty values group their findings; missing values remain separate and explain why.
- Workspace rows summarize per-finding review states; selecting a workspace shows its findings and selected finding evidence.
- Search and filters cover review state, scanner, rule, path, and commit, excluding secret values.
- Affected-branch and redaction actions remain available in context, and incomplete findings retain accurate limitations.
- Use the agreed GitButler-inspired desktop hierarchy and preserve keyboard access.
