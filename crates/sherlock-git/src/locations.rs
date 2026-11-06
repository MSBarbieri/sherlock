//! Exact-value locations in pinned Git history.
use crate::{run, verify_exact_values, RefSnapshot};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    process::Command,
};

/// A file blob containing one or more searched values at a commit and path.
/// Paths are raw Git path bytes, not necessarily UTF-8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactLocation {
    pub commit: String,
    pub path: Vec<u8>,
    pub blob: String,
    pub containing_refs: Vec<String>,
    /// One-based lines containing match starts, when the entire blob is UTF-8
    /// text with no NUL bytes; binary or non-UTF-8 blobs have no line numbers.
    pub matching_lines: Option<Vec<usize>>,
}

/// Find exact byte matches in reachable file blobs, including binary blobs and
/// paths that changed across commits. Occurrences are snapshots, not inferred
/// moves or first appearances. Results do not identify which value matched.
/// Commit messages, LFS payloads, submodules and unselected refs are excluded.
/// Shallow history and grafts are rejected. Uses pinned tips, not live refs.
pub fn exact_history_locations(
    repo: &Path,
    refs: &[RefSnapshot],
    values: &[&[u8]],
) -> Result<Vec<ExactLocation>, String> {
    // Reuse the verifier's graph safety checks and binary-safe blob search.
    let verified = verify_exact_values(repo, refs, values)?;
    // Cache only matching tree entries, not every file in every commit. Every
    // ref uses the same searched values, so the union is safe across refs.
    let matching_blob_ids: BTreeSet<String> = verified
        .iter()
        .flat_map(|entry| entry.matching_blobs.iter().cloned())
        .collect();
    let mut locations: BTreeMap<(String, Vec<u8>, String), BTreeSet<String>> = BTreeMap::new();
    let mut trees: BTreeMap<String, Vec<(String, Vec<u8>)>> = BTreeMap::new();
    let mut lines_by_blob: BTreeMap<String, Option<Vec<usize>>> = BTreeMap::new();
    for checked in verified {
        let matches: BTreeSet<_> = checked.matching_blobs.into_iter().collect();
        if matches.is_empty() {
            continue;
        }
        let commits = run(
            "git",
            &[
                "--no-replace-objects",
                "rev-list",
                "--topo-order",
                &checked.tip,
            ],
            Some(repo),
        )?;
        for commit in commits.lines() {
            if !trees.contains_key(commit) {
                let output = Command::new("git")
                    .current_dir(repo)
                    .args([
                        "--no-replace-objects",
                        "ls-tree",
                        "-r",
                        "-z",
                        "--full-tree",
                        commit,
                    ])
                    .output()
                    .map_err(|e| format!("Could not start git: {e}"))?;
                if !output.status.success() {
                    return Err(
                        "Could not read a commit tree; history search is incomplete.".into(),
                    );
                }
                let mut entries = Vec::new();
                for record in output.stdout.split(|b| *b == 0).filter(|r| !r.is_empty()) {
                    let tab = record
                        .iter()
                        .position(|b| *b == b'\t')
                        .ok_or("Invalid Git tree output")?;
                    let header = std::str::from_utf8(&record[..tab])
                        .map_err(|_| "Invalid Git tree output")?;
                    let fields: Vec<_> = header.split_whitespace().collect();
                    if fields.len() != 3 {
                        return Err("Invalid Git tree output".into());
                    }
                    if fields[1] == "blob" && matching_blob_ids.contains(fields[2]) {
                        entries.push((fields[2].to_owned(), record[tab + 1..].to_vec()));
                    }
                }
                trees.insert(commit.to_owned(), entries);
            }
            for (blob, path) in &trees[commit] {
                if matches.contains(blob) {
                    if !lines_by_blob.contains_key(blob) {
                        let output = Command::new("git")
                            .current_dir(repo)
                            .args(["--no-replace-objects", "cat-file", "blob", blob])
                            .output()
                            .map_err(|e| format!("Could not start git: {e}"))?;
                        if !output.status.success() {
                            return Err(
                                "Could not read a matching blob; history search is incomplete."
                                    .into(),
                            );
                        }
                        let content = &output.stdout;
                        let lines = if content.contains(&0) || std::str::from_utf8(content).is_err()
                        {
                            None
                        } else {
                            let mut found = BTreeSet::new();
                            let mut line = 1;
                            for (offset, byte) in content.iter().enumerate() {
                                if values
                                    .iter()
                                    .any(|value| content[offset..].starts_with(value))
                                {
                                    found.insert(line);
                                }
                                if *byte == b'\n' {
                                    line += 1;
                                }
                            }
                            Some(found.into_iter().collect())
                        };
                        lines_by_blob.insert(blob.clone(), lines);
                    }
                    locations
                        .entry((commit.to_owned(), path.clone(), blob.clone()))
                        .or_default()
                        .insert(checked.name.clone());
                }
            }
        }
    }
    Ok(locations
        .into_iter()
        .map(|((commit, path, blob), refs)| {
            let matching_lines = lines_by_blob.get(&blob).cloned().flatten();
            ExactLocation {
                commit,
                path,
                blob,
                containing_refs: refs.into_iter().collect(),
                matching_lines,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot_refs;
    #[test]
    fn finds_renamed_and_binary_occurrences_in_history() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        let git = |args: &[&str]| run("git", args, Some(repo)).unwrap();
        git(&["init", "-q"]);
        git(&["config", "user.name", "Test"]);
        git(&["config", "user.email", "test@example.com"]);
        std::fs::write(repo.join("old"), b"\0test-secret\xff").unwrap();
        git(&["add", "old"]);
        git(&["commit", "-qm", "old"]);
        let first = git(&["rev-parse", "HEAD"]).trim().to_owned();
        git(&["branch", "shared"]);
        git(&["mv", "old", "new"]);
        git(&["commit", "-qm", "move"]);
        let second = git(&["rev-parse", "HEAD"]).trim().to_owned();
        std::fs::write(repo.join("new"), b"clean").unwrap();
        git(&["add", "new"]);
        git(&["commit", "-qm", "clean"]);
        let refs = snapshot_refs(repo, &["HEAD".into(), "refs/heads/shared".into()]).unwrap();
        let found = exact_history_locations(repo, &refs, &[b"test-secret"]).unwrap();
        assert_eq!(found.len(), 2);
        let old = found.iter().find(|x| x.commit == first).unwrap();
        assert_eq!(old.path, b"old");
        assert_eq!(old.containing_refs, vec!["HEAD", "refs/heads/shared"]);
        let new = found.iter().find(|x| x.commit == second).unwrap();
        assert_eq!(new.path, b"new");
        assert_eq!(new.containing_refs, vec!["HEAD"]);
        assert_eq!(old.blob, new.blob);
        assert_eq!(old.matching_lines, None);
    }

    #[test]
    fn reports_text_lines_without_including_the_value() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        let git = |args: &[&str]| run("git", args, Some(repo)).unwrap();
        git(&["init", "-q"]);
        git(&["config", "user.name", "Test"]);
        git(&["config", "user.email", "test@example.com"]);
        std::fs::write(repo.join("file"), b"first\nsecret\nsecret\n").unwrap();
        git(&["add", "file"]);
        git(&["commit", "-qm", "fixture"]);
        let refs = snapshot_refs(repo, &["HEAD".into()]).unwrap();
        let found = exact_history_locations(repo, &refs, &[b"secret"]).unwrap();
        assert_eq!(found[0].matching_lines, Some(vec![2, 3]));
        assert!(!format!("{found:?}").contains("secret"));
    }
}
