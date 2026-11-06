# Architecture

Sherlock is a Cargo workspace. The desktop executable composes the libraries; the libraries do not depend on egui or the executable.

- `sherlock-domain` defines findings, scanner evidence, review decisions, and the rule for combining exact matches. Findings and reports can contain secrets and deliberately do not implement `Debug`.
- `sherlock-scan` runs Gitleaks and TruffleHog, normalizes their output into domain findings, and combines reports when both scanners are selected. `Scanner` restricts callers to supported scanner choices. Selecting both is all-or-error: a failed scanner does not produce a partial success. TruffleHog verification is disabled.
- `sherlock-reviews` persists review decisions using a digest of repository path and finding identity. `ReviewStore::at` accepts a caller-specified file; `ReviewStore::standard` uses the platform data directory. The store does not coordinate concurrent writers. Raw reports and secret values are not serialized.
- `sherlock-git` finds containing refs, fetches remotes, and prepares a separate mirror with rewritten branches. Its operations invoke Git and may create files or change remote-tracking refs; failed mirror creation may leave the destination behind.
- `sherlock-rewrite` rewrites Git objects and returns new commit IDs; callers decide whether to update refs. Its interface is deliberately scoped to literal replacement in supported text blobs, not full git-filter-repo compatibility.
- `src/app.rs` owns desktop state and composes the interface. `src/app/tasks.rs` manages background results; `src/app/rewrite.rs` coordinates rewrite checks; `src/app/investigation.rs` handles filtering and masking; and `src/app/ui/` separates the shell, discovery, and resolution views. `src/theme.rs` defines the visual theme, and `src/main.rs` starts the application.

The workflow still requires external `git`, `gitleaks`, and/or `trufflehog` executables as described in the README. The library interfaces and errors remain early-stage and may evolve as the wayfinder decisions are resolved. In particular, rewritten mirrors retain original sensitive refs, and exact-value checks cover reachable file blobs at recorded tips, not commit messages, LFS payloads, submodule repositories, unselected refs, or broader scanner coverage.

Run all crate tests with `cargo test --workspace`.
