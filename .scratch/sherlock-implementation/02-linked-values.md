# Link related values into a secret workspace

## Goal

Integrate the existing persistent related-value links into workspace-oriented navigation while preserving individual findings and classifications.

## Acceptance criteria

- Developers can explicitly link and unlink related values and see which findings belong to each value.
- Links survive rescans and restarts without persisting raw secrets or scanner reports; handle unavailable or incomplete identities explicitly.
- Linking never changes finding classifications or silently expands redaction scope.
- Define and test behavior for merges, unlinking, and stale links before implementation.
