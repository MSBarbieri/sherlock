//! Git repository discovery and creation of isolated redacted mirrors.
mod history;
mod verification;
pub use history::{secret_history, HistoryCommit, SecretHistory, UnplacedFinding};
pub use verification::{verify_exact_values, VerifiedRef};

use sherlock_domain::Finding;
use std::{
    path::{Path, PathBuf},
    process::Command,
};

fn run(program: &str, args: &[&str], dir: Option<&Path>) -> Result<String, String> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some(dir) = dir {
        cmd.current_dir(dir);
    }
    let output = cmd
        .output()
        .map_err(|e| format!("Could not start {program}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
pub fn fetch(repo: &Path) -> Result<String, String> {
    run("git", &["fetch", "--all", "--prune"], Some(repo))?;
    Ok("Fetched all remotes. Find containing branches again to refresh the list.".into())
}
pub fn branches(repo: &Path, commit: &str) -> Result<Vec<String>, String> {
    if commit.is_empty() || !commit.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("The finding has no valid commit ID.".into());
    }
    let out = run(
        "git",
        &[
            "for-each-ref",
            "--format=%(refname)",
            "--contains",
            commit,
            "refs/heads",
            "refs/remotes",
        ],
        Some(repo),
    )?;
    Ok(out
        .lines()
        .filter(|s| !s.ends_with("/HEAD"))
        .map(str::to_owned)
        .collect())
}

/// Find refs containing any identified occurrence of the same value.
pub fn branches_for_findings(repo: &Path, findings: &[Finding]) -> Result<Vec<String>, String> {
    let mut refs = std::collections::BTreeSet::new();
    let mut found_commit = false;
    for finding in findings {
        if finding.commit.is_empty() {
            continue;
        }
        found_commit = true;
        refs.extend(branches(repo, &finding.commit)?);
    }
    if !found_commit {
        return Err("No finding has a commit ID; affected branches cannot be determined.".into());
    }
    Ok(refs.into_iter().collect())
}

#[derive(Clone)]
pub struct RefSnapshot {
    pub name: String,
    pub tip: String,
}

pub fn snapshot_refs(repo: &Path, refs: &[String]) -> Result<Vec<RefSnapshot>, String> {
    refs.iter()
        .map(|name| {
            let tip = run(
                "git",
                &["rev-parse", "--verify", &format!("{name}^{{commit}}")],
                Some(repo),
            )?;
            Ok(RefSnapshot {
                name: name.clone(),
                tip: tip.trim().to_owned(),
            })
        })
        .collect()
}

pub fn rewrite(
    repo: &Path,
    destination: &Path,
    finding: &Finding,
    refs: &[String],
) -> Result<String, String> {
    rewrite_related(repo, destination, std::slice::from_ref(finding), refs)
}

/// Rewrite selected refs containing any known occurrence of one exact value.
pub fn rewrite_related(
    repo: &Path,
    destination: &Path,
    findings: &[Finding],
    refs: &[String],
) -> Result<String, String> {
    let snapshot = snapshot_refs(repo, refs)?;
    rewrite_related_at(repo, destination, findings, &snapshot)
}

pub fn rewrite_related_at(
    repo: &Path,
    destination: &Path,
    findings: &[Finding],
    snapshot: &[RefSnapshot],
) -> Result<String, String> {
    let refs: Vec<String> = snapshot.iter().map(|entry| entry.name.clone()).collect();
    let current = snapshot_refs(repo, &refs)?;
    if current.iter().zip(snapshot).any(|(a, b)| a.tip != b.tip) {
        return Err(
            "A selected branch changed; find affected branches again before rewriting.".into(),
        );
    }
    let finding = findings.first().ok_or("No findings selected.")?;
    if findings.iter().any(|f| f.secret != finding.secret) {
        return Err("Findings must have the same detected value.".into());
    }
    if refs.is_empty() {
        return Err("No containing branches selected.".into());
    }
    if finding.secret.is_empty() || finding.secret.as_bytes().contains(&0) {
        return Err("The detected value is empty or binary and cannot be redacted.".into());
    }
    if destination.exists() {
        return Err("Destination already exists; choose a new path.".into());
    }
    let containing = branches_for_findings(repo, findings)?;
    if refs.iter().any(|r| !containing.contains(r)) {
        return Err(
            "A selected branch no longer contains the finding; refresh the branch list.".into(),
        );
    }
    let source = repo.to_str().ok_or("Repository path is not UTF-8")?;
    let dest = destination
        .to_str()
        .ok_or("Destination path is not UTF-8")?;
    run(
        "git",
        &["clone", "--mirror", "--no-local", source, dest],
        None,
    )?;
    let mut tips = Vec::new();
    let mut new_refs = Vec::new();
    for (i, source_ref) in refs.iter().enumerate() {
        let oid = run(
            "git",
            &["rev-parse", "--verify", &format!("{source_ref}^{{commit}}")],
            Some(destination),
        )?;
        if oid.trim() != snapshot[i].tip {
            return Err("A selected branch changed while creating the mirror; inspect the destination and retry.".into());
        }
        let mut contained = false;
        for occurrence in findings.iter().filter(|f| !f.commit.is_empty()) {
            let present = Command::new("git")
                .current_dir(destination)
                .args([
                    "cat-file",
                    "-e",
                    &format!("{}^{{commit}}", occurrence.commit),
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map_err(|e| e.to_string())?;
            if !present.success() {
                continue;
            }
            let status = Command::new("git")
                .current_dir(destination)
                .args([
                    "merge-base",
                    "--is-ancestor",
                    &occurrence.commit,
                    oid.trim(),
                ])
                .status()
                .map_err(|e| e.to_string())?;
            match status.code() {
                Some(0) => {
                    contained = true;
                    break;
                }
                Some(1) => {}
                _ => return Err("Could not check a finding commit in the mirror.".into()),
            }
        }
        if !contained {
            return Err("A selected branch changed and no longer contains a known finding; refresh and retry.".into());
        }
        tips.push(oid.trim().to_owned());
        new_refs.push(format!("refs/heads/sherlock/redacted-{}", i + 1));
    }
    let rewritten =
        sherlock_rewrite::redact(destination, &tips, finding.secret.as_bytes(), b"[REDACTED]")?;
    // Publish all new refs in one transaction, only after every object was written.
    use std::io::Write;
    use std::process::Stdio;
    let mut command = Command::new("git")
        .args(["update-ref", "--stdin"])
        .current_dir(destination)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Could not start git: {e}"))?;
    {
        let mut input = command.stdin.take().ok_or("Could not open git stdin")?;
        writeln!(input, "start").map_err(|e| e.to_string())?;
        for (name, id) in new_refs.iter().zip(&rewritten) {
            writeln!(input, "create {name} {id}").map_err(|e| e.to_string())?;
        }
        writeln!(input, "prepare\ncommit").map_err(|e| e.to_string())?;
    }
    let output = command.wait_with_output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "Could not create rewritten refs: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mapping = refs
        .iter()
        .zip(&new_refs)
        .map(|(a, b)| format!("{a} → {b}"))
        .collect::<Vec<_>>()
        .join("\n");
    let unchanged: Vec<&str> = refs
        .iter()
        .zip(tips.iter().zip(&rewritten))
        .filter_map(|(name, (old, new))| (old == new).then_some(name.as_str()))
        .collect();
    let note = if unchanged.is_empty() {
        String::new()
    } else {
        format!("\nUnchanged selected refs (no supported replacement was made): {}. These branches may still contain the value.\n", unchanged.join(", "))
    };
    Ok(format!("Prepared in {}:\n{mapping}\n{note}\nOriginal refs in this mirror still contain the secret. Verify the new branches before sharing or pushing.", destination.display()))
}

pub fn suggested_destination(repo: &Path) -> PathBuf {
    let name = repo.file_name().unwrap_or_default().to_string_lossy();
    repo.with_file_name(format!("{name}-sherlock.git"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sherlock_domain::Review;
    #[test]
    fn prepares_separate_redacted_history() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("source");
        std::fs::create_dir(&repo).unwrap();
        run("git", &["init", "-q"], Some(&repo)).unwrap();
        run(
            "git",
            &["config", "user.email", "test@example.com"],
            Some(&repo),
        )
        .unwrap();
        run("git", &["config", "user.name", "Test"], Some(&repo)).unwrap();
        std::fs::write(repo.join("config.txt"), "token=example-secret-value\n").unwrap();
        run("git", &["add", "."], Some(&repo)).unwrap();
        run("git", &["commit", "-qm", "fixture"], Some(&repo)).unwrap();
        let commit = run("git", &["rev-parse", "HEAD"], Some(&repo))
            .unwrap()
            .trim()
            .to_owned();
        let refs = branches(&repo, &commit).unwrap();
        let f = Finding {
            scanner: "test",
            rule: String::new(),
            file: "config.txt".into(),
            commit,
            line: "1".into(),
            secret: "example-secret-value".into(),
            evidence: vec![],
            review: Review::Unreviewed,
        };
        let destination = temp.path().join("output.git");
        rewrite(&repo, &destination, &f, &refs).unwrap();
        let redacted = run(
            "git",
            &["show", "refs/heads/sherlock/redacted-1:config.txt"],
            Some(&destination),
        )
        .unwrap();
        assert_eq!(redacted, "token=[REDACTED]\n");
        let original = std::fs::read_to_string(repo.join("config.txt")).unwrap();
        assert_eq!(original, "token=example-secret-value\n");
    }
    #[test]
    fn rewrites_refs_containing_different_occurrences_together() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("source");
        std::fs::create_dir(&repo).unwrap();
        run("git", &["init", "-q"], Some(&repo)).unwrap();
        run(
            "git",
            &["config", "user.email", "test@example.com"],
            Some(&repo),
        )
        .unwrap();
        run("git", &["config", "user.name", "Test"], Some(&repo)).unwrap();
        run(
            "git",
            &["commit", "--allow-empty", "-qm", "base"],
            Some(&repo),
        )
        .unwrap();
        run("git", &["checkout", "-qb", "one"], Some(&repo)).unwrap();
        std::fs::write(repo.join("one.txt"), "example-secret-value").unwrap();
        run("git", &["add", "one.txt"], Some(&repo)).unwrap();
        run("git", &["commit", "-qm", "first occurrence"], Some(&repo)).unwrap();
        let first = run("git", &["rev-parse", "HEAD"], Some(&repo))
            .unwrap()
            .trim()
            .to_owned();
        run("git", &["checkout", "-qb", "two", "HEAD^"], Some(&repo)).unwrap();
        std::fs::write(repo.join("two.txt"), "example-secret-value").unwrap();
        run("git", &["add", "two.txt"], Some(&repo)).unwrap();
        run("git", &["commit", "-qm", "second occurrence"], Some(&repo)).unwrap();
        let second = run("git", &["rev-parse", "HEAD"], Some(&repo))
            .unwrap()
            .trim()
            .to_owned();
        let make = |commit: String| Finding {
            scanner: "test",
            rule: String::new(),
            file: String::new(),
            commit,
            line: String::new(),
            secret: "example-secret-value".into(),
            evidence: vec![],
            review: Review::Unreviewed,
        };
        let findings = vec![make(first), make(second)];
        let refs = branches_for_findings(&repo, &findings).unwrap();
        assert_eq!(refs, vec!["refs/heads/one", "refs/heads/two"]);
        let destination = temp.path().join("output.git");
        rewrite_related(&repo, &destination, &findings, &refs).unwrap();
        for (name, file) in [("redacted-1", "one.txt"), ("redacted-2", "two.txt")] {
            let spec = format!("refs/heads/sherlock/{name}:{file}");
            assert_eq!(
                run("git", &["show", &spec], Some(&destination)).unwrap(),
                "[REDACTED]"
            );
        }
        let parent1 = run(
            "git",
            &["rev-parse", "refs/heads/sherlock/redacted-1^"],
            Some(&destination),
        )
        .unwrap();
        let parent2 = run(
            "git",
            &["rev-parse", "refs/heads/sherlock/redacted-2^"],
            Some(&destination),
        )
        .unwrap();
        assert_eq!(parent1, parent2);
    }
    #[test]
    fn refuses_to_rewrite_when_selected_branch_tip_changes() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("source");
        std::fs::create_dir(&repo).unwrap();
        run("git", &["init", "-q"], Some(&repo)).unwrap();
        run(
            "git",
            &["config", "user.email", "test@example.com"],
            Some(&repo),
        )
        .unwrap();
        run("git", &["config", "user.name", "Test"], Some(&repo)).unwrap();
        std::fs::write(repo.join("secret.txt"), "example-secret-value").unwrap();
        run("git", &["add", "secret.txt"], Some(&repo)).unwrap();
        run("git", &["commit", "-qm", "fixture"], Some(&repo)).unwrap();
        let commit = run("git", &["rev-parse", "HEAD"], Some(&repo))
            .unwrap()
            .trim()
            .to_owned();
        let finding = Finding {
            scanner: "test",
            rule: String::new(),
            file: "secret.txt".into(),
            commit,
            line: "1".into(),
            secret: "example-secret-value".into(),
            evidence: vec![],
            review: Review::Unreviewed,
        };
        let refs = branches_for_findings(&repo, std::slice::from_ref(&finding)).unwrap();
        let snapshot = snapshot_refs(&repo, &refs).unwrap();
        run(
            "git",
            &["commit", "--allow-empty", "-qm", "later commit"],
            Some(&repo),
        )
        .unwrap();
        let destination = temp.path().join("output.git");
        assert!(rewrite_related_at(&repo, &destination, &[finding], &snapshot).is_err());
        assert!(!destination.exists());
    }
    #[test]
    fn reports_selected_branch_that_was_not_changed() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("source");
        std::fs::create_dir(&repo).unwrap();
        run("git", &["init", "-q"], Some(&repo)).unwrap();
        run(
            "git",
            &["config", "user.email", "test@example.com"],
            Some(&repo),
        )
        .unwrap();
        run("git", &["config", "user.name", "Test"], Some(&repo)).unwrap();
        run(
            "git",
            &["commit", "--allow-empty", "-qm", "base"],
            Some(&repo),
        )
        .unwrap();
        run("git", &["checkout", "-qb", "text"], Some(&repo)).unwrap();
        std::fs::write(repo.join("text"), b"example-secret-value").unwrap();
        run("git", &["add", "text"], Some(&repo)).unwrap();
        run("git", &["commit", "-qm", "text"], Some(&repo)).unwrap();
        let text_commit = run("git", &["rev-parse", "HEAD"], Some(&repo))
            .unwrap()
            .trim()
            .to_owned();
        run("git", &["checkout", "-qb", "binary", "HEAD^"], Some(&repo)).unwrap();
        std::fs::write(repo.join("binary"), b"\0example-secret-value").unwrap();
        run("git", &["add", "binary"], Some(&repo)).unwrap();
        run("git", &["commit", "-qm", "binary"], Some(&repo)).unwrap();
        let binary_commit = run("git", &["rev-parse", "HEAD"], Some(&repo))
            .unwrap()
            .trim()
            .to_owned();
        let make = |commit: String| Finding {
            scanner: "test",
            rule: String::new(),
            file: String::new(),
            commit,
            line: String::new(),
            secret: "example-secret-value".into(),
            evidence: vec![],
            review: Review::Unreviewed,
        };
        let findings = vec![make(text_commit), make(binary_commit)];
        let refs = branches_for_findings(&repo, &findings).unwrap();
        let status =
            rewrite_related(&repo, &temp.path().join("output.git"), &findings, &refs).unwrap();
        assert!(status.contains("Unchanged"));
        assert!(status.contains("refs/heads/binary"));
    }
}
