//! Evidence from scanner-reported commits; this is not a reconstruction of file moves.
use crate::{run, snapshot_refs, RefSnapshot};
use sherlock_domain::Finding;
use std::{
    collections::BTreeMap,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

/// A known occurrence commit and the supplied branch snapshots that contain it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryCommit {
    pub commit: String,
    /// Indices into the input findings. Findings remain independent review decisions.
    pub finding_indices: Vec<usize>,
    pub containing_refs: Vec<String>,
}

/// A finding that could not be placed in the repository's commit graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnplacedFinding {
    pub finding_index: usize,
    pub reason: String,
}

pub struct SecretHistory {
    /// Commit IDs and branch tips are snapshots taken during this call.
    pub refs: Vec<RefSnapshot>,
    /// Git topological order: descendants precede ancestors; unrelated commits
    /// have no guaranteed relative order. An empty `containing_refs` means none
    /// of the supplied snapshots contains that occurrence.
    pub commits: Vec<HistoryCommit>,
    pub unplaced: Vec<UnplacedFinding>,
    pub shallow: bool,
}

/// Git's graph drawing and the commit represented by each row, when present.
pub struct GraphLine {
    pub drawing: String,
    pub commit: Option<String>,
    pub parents: Vec<String>,
    pub subject: String,
}

/// Draw the ancestry of the recorded ref tips and occurrence commits. The walk
/// is bounded; callers must not present it as complete beyond the limit.
pub fn history_graph(
    repo: &Path,
    history: &SecretHistory,
) -> Result<(Vec<GraphLine>, bool), String> {
    history_graph_page(repo, history, 500)
}

pub fn history_graph_page(
    repo: &Path,
    history: &SecretHistory,
    limit: usize,
) -> Result<(Vec<GraphLine>, bool), String> {
    let count_limit = limit.checked_add(1).ok_or("History limit too large")?;
    let mut starts: Vec<String> = history.refs.iter().map(|r| r.tip.clone()).collect();
    starts.extend(history.commits.iter().map(|c| c.commit.clone()));
    starts.sort();
    starts.dedup();
    if starts.is_empty() {
        return Ok((Vec::new(), false));
    }
    let output = Command::new("git")
        .current_dir(repo)
        .args(["log", "--graph", "--topo-order", "--format=%H%x1f%P%x1f%s"])
        .arg(format!("--max-count={count_limit}"))
        .args(&starts)
        .output()
        .map_err(|e| format!("Could not start git: {e}"))?;
    if !output.status.success() {
        return Err("Could not draw commit history.".into());
    }
    // Commit subjects can contain non-UTF-8 bytes; object IDs and graph cells are ASCII.
    let text = String::from_utf8_lossy(&output.stdout);
    let mut count = 0;
    let mut lines = Vec::new();
    for line in text.lines() {
        let (head, details) = line
            .split_once('\x1f')
            .map_or((line, None), |(head, details)| (head, Some(details)));
        let commit = head
            .split_whitespace()
            .last()
            .filter(|s| matches!(s.len(), 40 | 64) && s.chars().all(|c| c.is_ascii_hexdigit()));
        if commit.is_some() {
            count += 1;
        }
        if count > limit {
            break;
        }
        let drawing = match commit {
            Some(id) => head[..head.len() - id.len()].to_owned(),
            None => line.to_owned(),
        };
        let (parents, subject) = if commit.is_some() {
            details.and_then(|text| text.split_once('\x1f')).map_or(
                (Vec::new(), String::new()),
                |(parents, subject)| {
                    (
                        parents.split_whitespace().map(str::to_owned).collect(),
                        subject.to_owned(),
                    )
                },
            )
        } else {
            (Vec::new(), String::new())
        };
        lines.push(GraphLine {
            drawing,
            commit: commit.map(str::to_owned),
            parents,
            subject,
        });
    }
    Ok((lines, count > limit))
}

/// Locate reported finding commits in the supplied branch histories. This only reports
/// scanner evidence: it does not establish first appearance, disappearance, or a move.
/// Missing and invalid occurrence commits are retained as unplaced findings.
pub fn secret_history(
    repo: &Path,
    findings: &[Finding],
    refs: &[String],
) -> Result<SecretHistory, String> {
    let snapshots = snapshot_refs(repo, refs)?;
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut unplaced = Vec::new();
    for (index, finding) in findings.iter().enumerate() {
        if finding.commit.is_empty() || !finding.commit.chars().all(|c| c.is_ascii_hexdigit()) {
            unplaced.push(UnplacedFinding {
                finding_index: index,
                reason: "Missing or invalid commit ID".into(),
            });
            continue;
        }
        let spec = format!("{}^{{commit}}", finding.commit);
        match run("git", &["rev-parse", "--verify", &spec], Some(repo)) {
            Ok(id) => groups.entry(id.trim().to_owned()).or_default().push(index),
            Err(_) => unplaced.push(UnplacedFinding {
                finding_index: index,
                reason: "Commit is unavailable in this repository".into(),
            }),
        }
    }
    // Start at every occurrence, including those outside the selected refs. Git's
    // graph walk preserves ordering even when intermediate commits have no finding.
    let order = if groups.is_empty() {
        Vec::new()
    } else {
        let mut child = Command::new("git")
            .current_dir(repo)
            .args(["rev-list", "--topo-order", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Could not start git: {e}"))?;
        let mut input = child.stdin.take().ok_or("Could not open git stdin")?;
        let starts: Vec<_> = groups.keys().cloned().collect();
        let writer = std::thread::spawn(move || -> std::io::Result<()> {
            for commit in starts {
                writeln!(input, "{commit}")?;
            }
            Ok(())
        });
        let output = child.wait_with_output().map_err(|e| e.to_string())?;
        writer
            .join()
            .map_err(|_| "Could not write commits to git")?
            .map_err(|e| format!("Could not write commits to git: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "Could not order history: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        String::from_utf8(output.stdout)
            .map_err(|e| e.to_string())?
            .lines()
            .filter(|id| groups.contains_key(*id))
            .map(str::to_owned)
            .collect()
    };
    let mut commits = Vec::with_capacity(groups.len());
    for commit in order {
        let finding_indices = groups.remove(&commit).expect("ordered occurrence exists");
        let mut containing_refs = Vec::new();
        for snapshot in &snapshots {
            let status = Command::new("git")
                .current_dir(repo)
                .args(["merge-base", "--is-ancestor", &commit, &snapshot.tip])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|e| format!("Could not start git: {e}"))?;
            match status.code() {
                Some(0) => containing_refs.push(snapshot.name.clone()),
                Some(1) => {}
                _ => return Err("Could not check occurrence commit reachability".into()),
            }
        }
        commits.push(HistoryCommit {
            commit,
            finding_indices,
            containing_refs,
        });
    }
    Ok(SecretHistory {
        refs: snapshots,
        commits,
        unplaced,
        shallow: run("git", &["rev-parse", "--is-shallow-repository"], Some(repo))?.trim()
            == "true",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sherlock_domain::Review;

    fn finding(commit: &str) -> Finding {
        Finding {
            scanner: "test",
            rule: String::new(),
            file: String::new(),
            commit: commit.into(),
            line: String::new(),
            secret: "fixture".into(),
            evidence: vec![],
            review: Review::Unreviewed,
        }
    }

    #[test]
    fn maps_occurrences_to_snapshot_branches_and_keeps_unplaced_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        let git = |args: &[&str]| run("git", args, Some(repo)).unwrap();
        git(&["init", "-q"]);
        git(&["config", "user.email", "test@example.com"]);
        git(&["config", "user.name", "Test"]);
        git(&["commit", "--allow-empty", "-qm", "shared"]);
        let shared = git(&["rev-parse", "HEAD"]).trim().to_owned();
        git(&["checkout", "-qb", "one"]);
        git(&["commit", "--allow-empty", "-qm", "one"]);
        let one = git(&["rev-parse", "HEAD"]).trim().to_owned();
        git(&["checkout", "-qb", "two", &shared]);
        git(&["commit", "--allow-empty", "-qm", "two"]);
        let two = git(&["rev-parse", "HEAD"]).trim().to_owned();
        git(&["checkout", "-qb", "excluded", &shared]);
        git(&["commit", "--allow-empty", "-qm", "excluded"]);
        let excluded = git(&["rev-parse", "HEAD"]).trim().to_owned();
        let refs = vec!["refs/heads/one".into(), "refs/heads/two".into()];
        let findings = vec![
            finding(&shared),
            finding(&one),
            finding(&one[..10]),
            finding(""),
            finding("deadbeef"),
            finding(&two),
            finding(&excluded),
        ];
        let history = secret_history(repo, &findings, &refs).unwrap();
        let shared_entry = history
            .commits
            .iter()
            .find(|entry| entry.commit == shared)
            .unwrap();
        assert_eq!(shared_entry.containing_refs, refs);
        let one_entry = history
            .commits
            .iter()
            .find(|entry| entry.commit == one)
            .unwrap();
        assert_eq!(one_entry.finding_indices, vec![1, 2]);
        assert_eq!(one_entry.containing_refs, vec!["refs/heads/one"]);
        let position = |id: &str| {
            history
                .commits
                .iter()
                .position(|entry| entry.commit == id)
                .unwrap()
        };
        assert!(position(&one) < position(&shared));
        assert!(position(&two) < position(&shared));
        assert!(position(&excluded) < position(&shared));
        assert!(history.commits[position(&excluded)]
            .containing_refs
            .is_empty());
        assert_eq!(
            history
                .unplaced
                .iter()
                .map(|entry| entry.finding_index)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );
        assert_eq!(history.refs.len(), 2);
    }
}
