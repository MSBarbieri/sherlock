# Shape the post-scan investigation workspace

Label: wayfinder:grilling
Type: grilling
Status: resolved
Assignee: Codex
Blocked by: none

## Question

How should a developer navigate from scan results into a secret workspace, understand its findings and evidence, and decide what to investigate or classify next? Establish the primary information hierarchy, key actions, and relationships between repository, secret workspace, and finding.

## Reference observations

- The supplied GitButler screenshot uses a narrow navigation rail, dense file list, distinct workspace lanes, contextual actions, and visual commit relationships.
- [GitButler's branch page](https://docs.gitbutler.com/features/branch-management/branch-lanes) pairs a branch list with a selected branch view; its [desktop overview](https://docs.gitbutler.com/overview) describes lanes for parallel branches and movable changes.
- [GitButler's terminal interface](https://docs.gitbutler.com/gitbutler-tui) provides a keyboard-first overview, contextual shortcut hints, and a details pane for the selected item.
- Sherlock currently selects individual findings and shows their evidence, exact-value related findings, and branch actions in a details panel. Its glossary also defines developer-linked related values, which are not yet exposed as a complete workspace in the current interface.

These are observations and design prompts, not resolved decisions.

## Answer

Use a workspace list and in-context finding details. Group exact nonempty values and permit developers to link related distinct values. Findings retain individual review decisions, with summaries and explicit bulk review. Keep missing values separate with an explanation, mask values by default with explicit reveal, and search metadata rather than secrets. Offer branch inspection and redaction in context. See the [investigation workspace specification](../../../docs/investigation-workspace.md) for the agreed requirements and current limitations.
