//! Local persistence for review decisions; raw scanner reports are never written.
use sha2::{Digest, Sha256};
use sherlock_domain::{Finding, Review};
use std::path::{Path, PathBuf};

/// Persist review choices only; scanner reports and secret values are never serialized.
fn review_key(repo: &Path, finding: &Finding) -> Result<String, String> {
    if finding.commit.is_empty()
        || finding.file.is_empty()
        || finding.line.is_empty()
        || finding.secret.is_empty()
    {
        return Err(
            "This report has incomplete location data, so its review cannot be persisted.".into(),
        );
    }
    let repo = repo
        .canonicalize()
        .map_err(|e| format!("Could not identify repository: {e}"))?;
    let mut hash = Sha256::new();
    for part in [
        repo.to_string_lossy().as_bytes(),
        finding.commit.as_bytes(),
        finding.file.as_bytes(),
        finding.line.as_bytes(),
        finding.secret.as_bytes(),
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn reviews_path() -> Result<PathBuf, String> {
    let dirs = directories::ProjectDirs::from("", "", "sherlock")
        .ok_or("Could not determine an application data directory")?;
    Ok(dirs.data_local_dir().join("reviews.json"))
}

fn read_reviews(path: &Path) -> Result<std::collections::HashMap<String, Review>, String> {
    match std::fs::read(path) {
        Ok(data) => {
            serde_json::from_slice(&data).map_err(|e| format!("Could not read saved reviews: {e}"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
        Err(e) => Err(format!("Could not read saved reviews: {e}")),
    }
}

fn save_review_at(path: &Path, repo: &Path, finding: &Finding) -> Result<(), String> {
    let key = review_key(repo, finding)?;
    let mut reviews = read_reviews(path)?;
    if finding.review == Review::Unreviewed {
        reviews.remove(&key);
    } else {
        reviews.insert(key, finding.review.clone());
    }
    write_reviews(path, &reviews)
}

fn write_reviews(
    path: &Path,
    reviews: &std::collections::HashMap<String, Review>,
) -> Result<(), String> {
    let dir = path.parent().ok_or("Invalid review file path")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("Could not create review directory: {e}"))?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| format!("Could not create review file: {e}"))?;
    serde_json::to_writer(&mut tmp, reviews)
        .map_err(|e| format!("Could not write reviews: {e}"))?;
    tmp.persist(path)
        .map_err(|e| format!("Could not save reviews: {}", e.error))?;
    Ok(())
}

/// A local review store. The file contains only digests and review decisions.
/// Concurrent writers are not coordinated; use one store writer per file.
pub struct ReviewStore {
    path: PathBuf,
}

/// Indices refer to the supplied slice; each rejected entry explains why it was skipped.
pub struct BatchSaveResult {
    pub saved: Vec<usize>,
    pub rejected: Vec<(usize, String)>,
}

impl ReviewStore {
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn standard() -> Result<Self, String> {
        Ok(Self::at(reviews_path()?))
    }

    pub fn restore(&self, repo: &Path, findings: &mut [Finding]) -> Result<(), String> {
        let reviews = read_reviews(&self.path)?;
        for finding in findings {
            if let Ok(key) = review_key(repo, finding) {
                if let Some(review) = reviews.get(&key) {
                    finding.review = review.clone();
                }
            }
        }
        Ok(())
    }

    pub fn save(&self, repo: &Path, finding: &Finding) -> Result<(), String> {
        save_review_at(&self.path, repo, finding)
    }

    /// Save eligible decisions in one file replacement. An I/O error means no
    /// decision in this batch was saved; rejected indices can be shown to the user.
    pub fn save_many(&self, repo: &Path, findings: &[Finding]) -> Result<BatchSaveResult, String> {
        let mut result = BatchSaveResult {
            saved: Vec::new(),
            rejected: Vec::new(),
        };
        let mut reviews = read_reviews(&self.path)?;
        let mut decisions = std::collections::HashMap::<String, Review>::new();
        for (index, finding) in findings.iter().enumerate() {
            match review_key(repo, finding) {
                Ok(key) => {
                    if decisions
                        .get(&key)
                        .is_some_and(|review| review != &finding.review)
                    {
                        result
                            .rejected
                            .push((index, "Conflicting decisions for the same finding.".into()));
                        continue;
                    }
                    decisions.insert(key.clone(), finding.review.clone());
                    if finding.review == Review::Unreviewed {
                        reviews.remove(&key);
                    } else {
                        reviews.insert(key, finding.review.clone());
                    }
                    result.saved.push(index);
                }
                Err(error) => result.rejected.push((index, error)),
            }
        }
        if !result.saved.is_empty() {
            write_reviews(&self.path, &reviews)?;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sherlock_domain::ScannerReport;
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
    fn review_storage_does_not_store_secret_and_can_be_cleared() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("reviews.json");
        let mut finding = report("Gitleaks", "2", "a-secret-to-keep-private");
        finding.review = Review::AcceptedRisk;
        ReviewStore::at(&path).save(tmp.path(), &finding).unwrap();
        let data = std::fs::read_to_string(&path).unwrap();
        assert!(!data.contains("a-secret-to-keep-private"));
        assert!(!data.contains("config"));
        assert_eq!(
            read_reviews(&path)
                .unwrap()
                .get(&review_key(tmp.path(), &finding).unwrap()),
            Some(&Review::AcceptedRisk)
        );
        finding.review = Review::Unreviewed;
        ReviewStore::at(&path).save(tmp.path(), &finding).unwrap();
        assert!(read_reviews(&path).unwrap().is_empty());
        finding.line.clear();
        assert!(ReviewStore::at(&path).save(tmp.path(), &finding).is_err());
    }
}

pub mod links;
