use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ReviewFilter {
    All,
    Potential,
    FalsePositive,
    AcceptedRisk,
}

impl ReviewFilter {
    pub(super) fn matches(self, review: &Review) -> bool {
        match self {
            Self::All => true,
            Self::Potential => *review == Review::Unreviewed,
            Self::FalsePositive => *review == Review::FalsePositive,
            Self::AcceptedRisk => *review == Review::AcceptedRisk,
        }
    }
}

#[cfg(test)]
fn mask_detected_value(text: &str, value: &str) -> String {
    if value.is_empty() {
        text.to_owned()
    } else {
        text.replace(value, "[MASKED]")
    }
}

pub(super) fn mask_known_values(text: &str, values: &[String]) -> String {
    values
        .iter()
        .filter(|value| !value.is_empty())
        .fold(text.to_owned(), |masked, value| {
            masked.replace(value, "[MASKED]")
        })
}

pub(super) fn workspace_finding_matches(
    finding: &Finding,
    values: &[String],
    filter: ReviewFilter,
    search: &str,
) -> bool {
    let query = search.trim().to_lowercase();
    filter.matches(&finding.review)
        && (query.is_empty()
            || [&finding.rule, &finding.file, &finding.commit, &finding.line]
                .iter()
                .any(|value| {
                    mask_known_values(value, values)
                        .to_lowercase()
                        .contains(&query)
                })
            || mask_known_values(finding.scanner, values)
                .to_lowercase()
                .contains(&query)
            || finding.evidence.iter().any(|report| {
                [report.scanner, report.rule.as_str()].iter().any(|value| {
                    mask_known_values(value, values)
                        .to_lowercase()
                        .contains(&query)
                })
            }))
}

#[cfg(test)]
fn finding_matches(finding: &Finding, filter: ReviewFilter, search: &str) -> bool {
    workspace_finding_matches(finding, &[finding.secret.clone()], filter, search)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sherlock_domain::ScannerReport;

    #[test]
    fn finding_search_respects_classification_and_excludes_secret_values() {
        let mut finding = Finding {
            scanner: "Gitleaks",
            rule: "Example rule".into(),
            file: "config/settings.env".into(),
            commit: "abc123def".into(),
            line: "7".into(),
            secret: "synthetic-secret-value".into(),
            evidence: vec![ScannerReport {
                scanner: "TruffleHog",
                rule: "Other rule".into(),
                raw: Default::default(),
            }],
            review: Review::FalsePositive,
        };
        for query in [
            " SETTINGS ",
            "ABC123",
            "example",
            "trufflehog",
            "other rule",
        ] {
            assert!(finding_matches(
                &finding,
                ReviewFilter::FalsePositive,
                query
            ));
        }
        assert!(finding_matches(&finding, ReviewFilter::All, ""));
        assert!(!finding_matches(
            &finding,
            ReviewFilter::Potential,
            "settings"
        ));
        assert!(!finding_matches(&finding, ReviewFilter::AcceptedRisk, ""));
        assert!(!finding_matches(
            &finding,
            ReviewFilter::All,
            "synthetic-secret-value"
        ));
        assert!(!finding_matches(&finding, ReviewFilter::All, "unmatched"));
        finding.file = "config/synthetic-secret-value.env".into();
        finding.evidence[0].rule = "synthetic-secret-value".into();
        assert!(!finding_matches(
            &finding,
            ReviewFilter::All,
            "synthetic-secret-value"
        ));
        assert_eq!(
            mask_detected_value(&finding.file, &finding.secret),
            "config/[MASKED].env"
        );
    }
}
