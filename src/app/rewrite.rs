use super::*;

#[derive(Clone)]
pub(super) struct PreparedRewrite {
    pub(super) source: PathBuf,
    pub(super) destination: PathBuf,
    pub(super) source_refs: Vec<String>,
    pub(super) excluded_refs: Vec<String>,
    pub(super) has_unplaced_findings: bool,
    pub(super) refs: Vec<sherlock_git::RefSnapshot>,
    pub(super) value: String,
}

pub(super) fn check_exact(prepared: &PreparedRewrite) -> Result<String, String> {
    let results = sherlock_git::verify_exact_values(
        &prepared.destination,
        &prepared.refs,
        &[prepared.value.as_bytes()],
    )?;
    let mut output =
        String::from("Exact-value check of reachable file blobs (not a scanner or a guarantee):\n");
    for result in results {
        let outcome = if result.matching_blobs.is_empty() {
            "not found".to_owned()
        } else {
            format!("found in {} blob(s)", result.matching_blobs.len())
        };
        output.push_str(&format!(
            "{} @ {}: {} commits checked; {}\n",
            result.name, result.tip, result.commits_checked, outcome
        ));
    }
    Ok(output)
}

pub(super) fn scan_prepared(
    prepared: &PreparedRewrite,
    scanner: Scanner,
) -> Result<(String, Vec<Finding>), String> {
    let mut output = format!(
        "{} results (scanner coverage is limited):\n",
        scanner.label()
    );
    let mut findings = Vec::new();
    for entry in &prepared.refs {
        let branch = entry
            .name
            .strip_prefix("refs/heads/")
            .ok_or("Invalid output branch name")?;
        let report = sherlock_scan::scan_branch(&prepared.destination, branch, scanner)?;
        if report.tip != entry.tip {
            return Err(format!(
                "{} changed since rewrite; its scan results do not describe the recorded output.",
                entry.name
            ));
        }
        let exact = report
            .findings
            .iter()
            .filter(|finding| finding.secret == prepared.value)
            .count();
        output.push_str(&format!(
            "{} @ {}: {} finding(s), {} with the same exact value\n",
            entry.name,
            entry.tip,
            report.findings.len(),
            exact
        ));
        for finding in &report.findings {
            let clean = |text: &str| {
                let masked = if prepared.value.is_empty() {
                    text.to_owned()
                } else {
                    text.replace(&prepared.value, "[MASKED]")
                };
                if finding.secret.is_empty() {
                    masked
                } else {
                    masked.replace(&finding.secret, "[MASKED]")
                }
            };
            output.push_str(&format!(
                "  {} · {} · {}:{} · commit {}{}\n",
                clean(finding.scanner),
                clean(&finding.rule),
                clean(&finding.file),
                clean(&finding.line),
                clean(&finding.commit),
                if finding.secret == prepared.value {
                    " · same value"
                } else {
                    ""
                }
            ));
        }
        sherlock_domain::merge_findings(&mut findings, report.findings);
    }
    Ok((output, findings))
}
