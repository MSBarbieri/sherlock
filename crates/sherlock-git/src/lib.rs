//! Git repository discovery and creation of isolated redacted mirrors.
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

pub fn rewrite(
    repo: &Path,
    destination: &Path,
    finding: &Finding,
    refs: &[String],
) -> Result<String, String> {
    if refs.is_empty() {
        return Err("No containing branches selected.".into());
    }
    if finding.secret.is_empty() || finding.secret.as_bytes().contains(&0) {
        return Err("The detected value is empty or binary and cannot be redacted.".into());
    }
    if destination.exists() {
        return Err("Destination already exists; choose a new path.".into());
    }
    let containing = branches(repo, &finding.commit)?;
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
        let contained = Command::new("git")
            .current_dir(destination)
            .args(["merge-base", "--is-ancestor", &finding.commit, oid.trim()])
            .status()
            .map_err(|e| e.to_string())?;
        if !contained.success() {
            return Err(
                "A selected branch changed and no longer contains the finding; refresh and retry."
                    .into(),
            );
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
    Ok(format!("Prepared in {}:\n{mapping}\n\nOriginal refs in this mirror still contain the secret. Verify the new branches before sharing or pushing.", destination.display()))
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
}
