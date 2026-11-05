//! Shared finding and review types, independent of scanners and presentation.
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Review {
    Unreviewed,
    FalsePositive,
    AcceptedRisk,
}

impl Review {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Unreviewed => "Potential secret",
            Self::FalsePositive => "False positive",
            Self::AcceptedRisk => "Accepted risk",
        }
    }
}

#[derive(Clone)]
pub struct ScannerReport {
    pub scanner: &'static str,
    pub rule: String,
    // Preserve the complete scanner report for future evidence inspection. It can contain secrets.
    pub raw: Value,
}

#[derive(Clone)]
pub struct Finding {
    pub scanner: &'static str,
    pub rule: String,
    pub file: String,
    pub commit: String,
    pub line: String,
    pub secret: String,
    pub evidence: Vec<ScannerReport>,
    pub review: Review,
}

// Only merge reports with complete, identical identifying fields. Ambiguous reports stay separate.
pub fn merge_findings(findings: &mut Vec<Finding>, incoming: Vec<Finding>) {
    for mut next in incoming {
        let complete = !next.commit.is_empty()
            && !next.file.is_empty()
            && !next.line.is_empty()
            && !next.secret.is_empty();
        if complete {
            if let Some(existing) = findings.iter_mut().find(|f| {
                f.commit == next.commit
                    && f.file == next.file
                    && f.line == next.line
                    && f.secret == next.secret
            }) {
                existing.evidence.append(&mut next.evidence);
                continue;
            }
        }
        findings.push(next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(scanner: &'static str, line: &str, secret: &str) -> Finding {
        Finding {
            scanner,
            rule: "rule".into(),
            file: "config".into(),
            commit: "abc123".into(),
            line: line.into(),
            secret: secret.into(),
            review: Review::Unreviewed,
            evidence: vec![ScannerReport {
                scanner,
                rule: "rule".into(),
                raw: serde_json::json!({"detector": scanner}),
            }],
        }
    }
    #[test]
    fn combines_only_complete_matching_reports_and_preserves_evidence() {
        let mut findings = vec![report("Gitleaks", "2", "example")];
        merge_findings(
            &mut findings,
            vec![
                report("TruffleHog", "2", "example"),
                report("TruffleHog", "", "example"),
                report("TruffleHog", "2", "different"),
            ],
        );
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].evidence.len(), 2);
        assert_eq!(findings[0].evidence[0].raw["detector"], "Gitleaks");
        assert_eq!(findings[0].evidence[1].raw["detector"], "TruffleHog");
        findings[0].review = Review::FalsePositive;
        assert_eq!(findings[0].evidence.len(), 2);
        findings[0].review = Review::AcceptedRisk;
        assert_eq!(findings[0].evidence.len(), 2);
    }
}
