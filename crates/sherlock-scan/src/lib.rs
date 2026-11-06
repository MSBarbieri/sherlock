//! Scanner process adapters and report normalization.
use serde_json::Value;
use sherlock_domain::{merge_findings, Finding, Review, ScannerReport};
use std::{path::Path, process::Command};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scanner {
    Gitleaks,
    TruffleHog,
    Both,
}
impl Scanner {
    pub fn label(self) -> &'static str {
        match self {
            Self::Gitleaks => "Gitleaks",
            Self::TruffleHog => "TruffleHog",
            Self::Both => "Both scanners",
        }
    }
}
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
fn field(v: &Value, path: &[&str]) -> String {
    let mut current = v;
    for key in path {
        current = &current[*key];
    }
    match current {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

pub fn scan(repo: &Path, scanner: Scanner) -> Result<Vec<Finding>, String> {
    run("git", &["rev-parse", "--git-dir"], Some(repo))?;
    if scanner == Scanner::Both {
        let mut findings = scan(repo, Scanner::Gitleaks)?;
        let other = scan(repo, Scanner::TruffleHog)?;
        merge_findings(&mut findings, other);
        return Ok(findings);
    }
    if scanner == Scanner::Gitleaks {
        let report = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
        let path = report.path().to_str().ok_or("Report path is not UTF-8")?;
        run(
            "gitleaks",
            &[
                "git",
                repo.to_str().ok_or("Repository path is not UTF-8")?,
                "--report-format",
                "json",
                "--report-path",
                path,
                "--exit-code",
                "0",
                "--no-banner",
            ],
            None,
        )?;
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        parse_gitleaks(&text)
    } else {
        let url = format!(
            "file://{}",
            repo.canonicalize().map_err(|e| e.to_string())?.display()
        );
        let output = run(
            "trufflehog",
            &[
                "git",
                &url,
                "--json",
                "--no-update",
                "--no-verification",
                "--fail-on-scan-errors",
            ],
            None,
        )?;
        parse_trufflehog(&output)
    }
}

/// Findings produced by scanning one local branch's history at a recorded tip.
/// Scanner detection and history coverage have limits; an empty result does not
/// prove that the branch contains no secret.
pub struct BranchScan {
    pub branch: String,
    pub tip: String,
    pub scanner: Scanner,
    pub findings: Vec<Finding>,
}

fn branch_tip(repo: &Path, branch: &str) -> Result<String, String> {
    if branch.starts_with('-') || branch.is_empty() {
        return Err("Expected a local branch name".into());
    }
    run("git", &["check-ref-format", "--branch", branch], Some(repo))?;
    let reference = format!("refs/heads/{branch}");
    let revision = format!("{reference}^{{commit}}");
    let tip = run(
        "git",
        &["rev-parse", "--verify", "--end-of-options", &revision],
        Some(repo),
    )?;
    Ok(tip.trim().to_owned())
}

/// Scan a named local branch, refusing to present results if its tip changed.
/// TruffleHog may scan a broader set of refs depending on its version; results
/// are scanner reports, not proof of complete blob-by-blob coverage.
pub fn scan_branch(repo: &Path, branch: &str, scanner: Scanner) -> Result<BranchScan, String> {
    scan_branch_with(repo, branch, scanner, "gitleaks", "trufflehog")
}

fn scan_branch_with(
    repo: &Path,
    branch: &str,
    scanner: Scanner,
    gitleaks: &str,
    trufflehog: &str,
) -> Result<BranchScan, String> {
    let tip = branch_tip(repo, branch)?;
    let repo_str = repo.to_str().ok_or("Repository path is not UTF-8")?;
    let mut findings = Vec::new();
    if matches!(scanner, Scanner::Gitleaks | Scanner::Both) {
        let report = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
        let path = report.path().to_str().ok_or("Report path is not UTF-8")?;
        run(
            gitleaks,
            &[
                "git",
                repo_str,
                "--report-format",
                "json",
                "--report-path",
                path,
                "--exit-code",
                "0",
                "--no-banner",
                "--log-opts",
                &tip,
            ],
            None,
        )?;
        findings = parse_gitleaks(&std::fs::read_to_string(path).map_err(|e| e.to_string())?)?;
    }
    if matches!(scanner, Scanner::TruffleHog | Scanner::Both) {
        let url = format!(
            "file://{}",
            repo.canonicalize().map_err(|e| e.to_string())?.display()
        );
        let output = run(
            trufflehog,
            &[
                "git",
                &url,
                "--json",
                "--no-update",
                "--no-verification",
                "--fail-on-scan-errors",
                "--skip-additional-refs",
                "--branch",
                branch,
            ],
            None,
        )?;
        merge_findings(&mut findings, parse_trufflehog(&output)?);
    }
    if branch_tip(repo, branch)? != tip {
        return Err("Branch tip changed during scanning; scan the branch again.".into());
    }
    Ok(BranchScan {
        branch: branch.to_owned(),
        tip,
        scanner,
        findings,
    })
}

fn parse_gitleaks(text: &str) -> Result<Vec<Finding>, String> {
    let values: Vec<Value> = if text.trim().is_empty() {
        vec![]
    } else {
        serde_json::from_str(text).map_err(|e| format!("Invalid Gitleaks report: {e}"))?
    };
    let mut findings = Vec::new();
    for v in values {
        findings.push(Finding {
            scanner: "Gitleaks",
            rule: field(&v, &["RuleID"]),
            file: field(&v, &["File"]),
            commit: field(&v, &["Commit"]),
            line: field(&v, &["StartLine"]),
            secret: field(&v, &["Secret"]),
            evidence: vec![ScannerReport {
                scanner: "Gitleaks",
                rule: field(&v, &["RuleID"]),
                raw: v.clone(),
            }],
            review: Review::Unreviewed,
        });
    }
    Ok(findings)
}

fn parse_trufflehog(output: &str) -> Result<Vec<Finding>, String> {
    let mut findings = Vec::new();
    for line in output.lines().filter(|s| !s.trim().is_empty()) {
        let v: Value =
            serde_json::from_str(line).map_err(|e| format!("Invalid TruffleHog report: {e}"))?;
        let meta = ["SourceMetadata", "Data", "Git"];
        findings.push(Finding {
            scanner: "TruffleHog",
            rule: field(&v, &["DetectorName"]),
            file: field(&v, &[meta[0], meta[1], meta[2], "file"]),
            commit: field(&v, &[meta[0], meta[1], meta[2], "commit"]),
            line: field(&v, &[meta[0], meta[1], meta[2], "line"]),
            secret: field(&v, &["Raw"]),
            evidence: vec![ScannerReport {
                scanner: "TruffleHog",
                rule: field(&v, &["DetectorName"]),
                raw: v.clone(),
            }],
            review: Review::Unreviewed,
        });
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalizes_scanner_formats_without_losing_evidence() {
        let a = parse_gitleaks(r#"[{"RuleID":"rule-a","File":"a.env","Commit":"abcd","StartLine":4,"Secret":"secret"}]"#).unwrap();
        let b = parse_trufflehog(r#"{"DetectorName":"rule-b","Raw":"secret","SourceMetadata":{"Data":{"Git":{"file":"a.env","commit":"abcd","line":4}}}}"#).unwrap();
        let mut combined = a;
        merge_findings(&mut combined, b);
        assert_eq!(combined.len(), 1);
        assert_eq!(combined[0].evidence.len(), 2);
        assert_eq!(combined[0].evidence[1].raw["DetectorName"], "rule-b");
        assert!(parse_gitleaks("broken").is_err());
        assert!(parse_trufflehog("broken").is_err());
    }
    #[cfg(unix)]
    #[test]
    fn scoped_scan_uses_local_branch_and_rejects_tip_changes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        run("git", &["init", "-q"], Some(&repo)).unwrap();
        run(
            "git",
            &["config", "user.email", "test@example.org"],
            Some(&repo),
        )
        .unwrap();
        run("git", &["config", "user.name", "Test"], Some(&repo)).unwrap();
        run(
            "git",
            &["commit", "-q", "--allow-empty", "-m", "initial"],
            Some(&repo),
        )
        .unwrap();
        run("git", &["branch", "test-branch"], Some(&repo)).unwrap();
        let fake = dir.path().join("scanner");
        std::fs::write(&fake, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$(dirname \"$0\")/args\"\nwhile [ $# -gt 0 ]; do\n if [ \"$1\" = --report-path ]; then shift; printf '[]' > \"$1\"; fi\n shift\ndone\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o700)).unwrap();
        let fake = fake.to_str().unwrap();
        let result = scan_branch_with(&repo, "test-branch", Scanner::Both, fake, fake).unwrap();
        assert_eq!(result.tip, branch_tip(&repo, "test-branch").unwrap());
        let args = std::fs::read_to_string(dir.path().join("args")).unwrap();
        assert!(args.contains("--skip-additional-refs\n--branch\ntest-branch"));
        assert!(scan_branch_with(&repo, "missing", Scanner::Gitleaks, fake, fake).is_err());
        assert!(branch_tip(&repo, "--all").is_err());

        std::fs::write(
            fake,
            format!(
                "#!/bin/sh\ngit -C '{}' update-ref refs/heads/test-branch {}\n",
                repo.display(),
                "0000000000000000000000000000000000000000"
            ),
        )
        .unwrap();
        assert!(scan_branch_with(&repo, "test-branch", Scanner::TruffleHog, fake, fake).is_err());
    }
}
