# Sherlock

Sherlock is a local desktop workspace for reviewing potential repository secrets and preparing redacted Git branches. It uses Rust and egui, with a thin interface over scanner and Git operations.

## Architecture

The workspace separates the finding model, scanner adapters, review storage, Git operations, history rewriting, and desktop interface. See [Architecture](docs/architecture.md) for the crate responsibilities and their interfaces.

## Requirements

- Rust and Cargo
- Git
- [Gitleaks](https://github.com/gitleaks/gitleaks) and/or [TruffleHog](https://github.com/trufflesecurity/trufflehog) on `PATH`

Run `cargo run --release`.

## Workflow

1. Choose a local repository and scan it with either scanner or both. Matching reports with the same commit, path, line, and detected value are grouped; ambiguous reports remain separate. Findings and secret values remain in memory; values are masked in the interface. Classifications default to potential secrets, and you can mark false positives or accepted risks. Review decisions are stored locally across scans and restarts using a hash of the repository path, location, and detected value; raw reports and values are not written to the review file. Reports missing identifying fields cannot be marked.
2. Fetch remotes when needed, select a finding, and find local and remote-tracking refs containing any known commit with the same exact detected value. Fetch can change local remote-tracking refs and prune stale ones.
3. Select refs and create redacted branches in a **new mirror**. Each selected ref becomes `refs/heads/sherlock/redacted-N`; the activity panel lists the mapping. The exact detected value is replaced throughout each selected branch's history, not just at the reported location. The source repository is not rewritten and nothing is pushed.
4. On the resolution page, check the exact detected value in reachable file blobs at the recorded output tips, and optionally rerun the selected scanner on each output branch. These checks have different coverage and do not prove that history is free of secrets. Independently inspect the results before sharing or pushing. The mirror also retains original refs and objects, including the secret. Treat the entire mirror as sensitive. Rewriting history does not revoke exposed credentials: rotate them separately.

## Current limitations

This is an early local workflow, not an automated remediation guarantee. Scanners have their own coverage and may miss secrets. The built-in `sherlock-rewrite` crate handles literal replacements in text blobs, including multiline values. It is purpose-built for this workflow and does not implement all of git-filter-repo’s features. One exact value is processed per mirror; linked variants and multiple distinct secrets require additional work. Findings without a commit cannot identify affected branches. Git LFS, submodules, binary files (blobs containing a NUL byte), commit/tag messages, encoded variants, and provider-side pull requests or caches are not remediated. The exact-value check covers reachable file blobs, including binary blobs, but excludes commit/tag messages, LFS payloads, submodule repositories, and unselected refs; it rejects shallow repositories. Scanner results depend on the scanner’s own history and detection coverage. Rewriting changes commit IDs; signatures and embedded merge tags are removed from rewritten commits because they are no longer valid. Review repository policy and coordinate any eventual force push. If a rewrite fails, its destination may be left behind and must be inspected or removed manually. TruffleHog credential verification is disabled. Scan reports are temporarily written to a private temporary file by Gitleaks and removed after the scan.
