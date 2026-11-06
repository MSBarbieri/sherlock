# Sherlock desktop design and interface

Label: wayfinder:map

## Destination

An implementation-ready design and interface specification for Sherlock's complete desktop journey: choose a repository, scan it, investigate and classify findings, and prepare redacted branches. Start with the post-scan investigation experience.

## Notes

- Primary audience: developers comfortable with Git who may not be security specialists.
- GitButler is the primary reference for both visual language and workspace interactions: dark, compact panels, restrained borders, contextual actions, and visible Git relationships. Sherlock should have its own identity and serve its own investigation workflow.
- The proposed post-scan screen brings a list of secret workspaces together with the selected workspace's evidence and actions. Validate and refine this through the design decisions.
- Use the project's `GLOSSARY.md`; consult the grilling and domain-modeling skills for conversations, and the prototype skill for visual decisions.
- This is a planning map: implementation follows the specification. The existing project map is [on GitHub](https://github.com/MSBarbieri/sherlock/issues/1); implementation issues are tracked in the same repository. This local design map has not been migrated.

## Decisions so far

- [Shape the post-scan investigation workspace](issues/01-investigation-workspace.md): use a workspace list and contextual finding details, with individual reviews and explicit value linking.

## Not yet specified

- Detailed interaction states, component behavior, accessibility, and visual tokens that depend on the workspace structure and visual direction.
- How the design will be divided into implementation work after the specification is agreed.

## Out of scope

- Implementing the redesign or changing scanner and Git behavior during this planning effort.
