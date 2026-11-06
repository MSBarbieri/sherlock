//! Exact-value checks of file blobs in selected Git histories.
use crate::{run, RefSnapshot};
use std::{collections::BTreeMap, path::Path, process::Command};

/// Results for one pinned ref. Blob IDs identify evidence without exposing the value.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedRef {
    pub name: String,
    pub tip: String,
    pub commits_checked: usize,
    pub matching_blobs: Vec<String>,
}

/// Check file blobs reachable from each selected ref's pinned tip, including binary files.
///
/// This does not scan commit messages, tags, submodule repositories, LFS payloads,
/// unselected refs, or run secret scanners. Shallow repositories are rejected.
/// Results describe the supplied immutable tips, not subsequent ref changes.
pub fn verify_exact_values(
    repo: &Path,
    refs: &[RefSnapshot],
    values: &[&[u8]],
) -> Result<Vec<VerifiedRef>, String> {
    if refs.is_empty() || values.is_empty() || values.iter().any(|v| v.is_empty()) {
        return Err("Select at least one ref and one nonempty value to verify.".into());
    }
    if run("git", &["rev-parse", "--is-shallow-repository"], Some(repo))?.trim() != "false" {
        return Err("Cannot verify complete history in a shallow repository.".into());
    }
    let mut cache = BTreeMap::<String, bool>::new();
    let mut results = Vec::new();
    for entry in refs {
        // Accept only full object IDs, never arbitrary revision expressions or options.
        if !matches!(entry.tip.len(), 40 | 64) || !entry.tip.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("Verification requires full commit IDs.".into());
        }
        let commits = run(
            "git",
            &["--no-replace-objects", "rev-list", &entry.tip],
            Some(repo),
        )?;
        let objects = run(
            "git",
            &[
                "--no-replace-objects",
                "rev-list",
                "--objects",
                "--no-object-names",
                &entry.tip,
            ],
            Some(repo),
        )?;
        let mut matching_blobs = Vec::new();
        for oid in objects.lines() {
            let matched = if let Some(matched) = cache.get(oid) {
                *matched
            } else {
                let kind = run(
                    "git",
                    &["--no-replace-objects", "cat-file", "-t", oid],
                    Some(repo),
                )?;
                let matched = if kind.trim() == "blob" {
                    let output = Command::new("git")
                        .current_dir(repo)
                        .args(["--no-replace-objects", "cat-file", "blob", oid])
                        .output()
                        .map_err(|e| format!("Could not start git: {e}"))?;
                    if !output.status.success() {
                        return Err(
                            "Could not read a reachable blob; verification is incomplete.".into(),
                        );
                    }
                    values.iter().any(|value| {
                        output
                            .stdout
                            .windows(value.len())
                            .any(|window| window == *value)
                    })
                } else {
                    false
                };
                cache.insert(oid.to_owned(), matched);
                matched
            };
            if matched {
                matching_blobs.push(oid.to_owned());
            }
        }
        results.push(VerifiedRef {
            name: entry.name.clone(),
            tip: entry.tip.clone(),
            commits_checked: commits.lines().count(),
            matching_blobs,
        });
    }
    Ok(results)
}
