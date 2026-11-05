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
                "--source",
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
}
