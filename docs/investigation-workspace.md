# Secret investigation workspace

## Purpose and scope

After scanning a repository, help a developer investigate related potential secrets, classify individual findings, and reach branch inspection and redaction. The primary audience understands Git but may not be a security specialist. This document records the agreed direction; visual details and the full scan and redaction journeys still need design work.

## Reference and layout

GitButler is the main reference for dense desktop panels, dark surfaces, restrained borders, contextual actions, and visible Git relationships. Sherlock should retain its own identity. Use a navigation rail, a searchable secret-workspace list, and a selected-workspace detail area. Keep finding evidence in context. Explore branch lanes only where they make relationships easier to understand.

## Workspace and findings

- Group findings with the same nonempty detected value. Let developers manually link distinct related values into the same secret workspace, while retaining their separate identities and findings.
- Display findings without a usable value separately and explain why they cannot be automatically grouped. Do not imply that incomplete findings can always be classified or persisted: the current review store requires complete identifying fields.
- Summarize the individual review decisions in each workspace row. A workspace does not have one shared classification.
- Classify each finding separately. Provide a deliberate bulk action for selected eligible findings, making the affected selection and any failures clear.
- Make findings and evidence the primary content. Provide access in the workspace to affected-branch inspection and redaction actions.
- Mask detected values by default; provide explicit reveal when needed. Do not include values in ordinary search.
- Support filtering and search by review state, scanner, rule, file path, and commit.

## Existing behavior and constraints

Sherlock currently groups exact values and supports persistent related-value links in its resolution interface. It persists eligible per-finding decisions without writing raw values or scanner reports. A finding with incomplete identifying fields cannot have a persisted review. The current redaction workflow creates a separate mirror retaining original sensitive refs and processes exact values; it is not a guarantee of complete remediation. The UI must accurately communicate those limitations and preserve the source repository.

Workspace-oriented navigation, explicit value reveal, and bulk review are available in the investigation interface. Bulk review saves eligible decisions together and reports skipped findings; a storage failure leaves the batch unchanged. The remaining design questions are tracked in the local [design map](../.scratch/sherlock-design/map.md).

## References

- [GitButler desktop overview](https://docs.gitbutler.com/overview)
- [GitButler branch management](https://docs.gitbutler.com/features/branch-management/branch-lanes)
- [GitButler terminal interface](https://docs.gitbutler.com/gitbutler-tui)
