use sherlock_domain::{Finding, Review};
use sherlock_reviews::ReviewStore;

fn finding(line: &str) -> Finding {
    Finding {
        scanner: "Gitleaks",
        rule: "rule".into(),
        file: "config".into(),
        commit: "abc123".into(),
        line: line.into(),
        secret: "secret".into(),
        review: Review::Unreviewed,
        evidence: vec![],
    }
}

#[test]
fn bulk_review_persists_eligible_findings_and_identifies_incomplete_ones() {
    let dir = tempfile::tempdir().unwrap();
    let store = ReviewStore::at(dir.path().join("reviews.json"));
    let mut selected = vec![finding("1"), finding(""), finding("3")];
    for item in &mut selected {
        item.review = Review::FalsePositive;
    }
    let result = store.save_many(dir.path(), &selected).unwrap();
    assert_eq!(result.saved, vec![0, 2]);
    assert_eq!(result.rejected.len(), 1);
    assert_eq!(result.rejected[0].0, 1);
    let mut restored = vec![finding("1"), finding("2"), finding("3")];
    store.restore(dir.path(), &mut restored).unwrap();
    assert_eq!(restored[0].review, Review::FalsePositive);
    assert_eq!(restored[1].review, Review::Unreviewed);
    assert_eq!(restored[2].review, Review::FalsePositive);
}

#[test]
fn bulk_review_can_clear_decisions_without_changing_unselected_findings() {
    let dir = tempfile::tempdir().unwrap();
    let store = ReviewStore::at(dir.path().join("reviews.json"));
    let mut first = finding("1");
    let mut second = finding("2");
    first.review = Review::AcceptedRisk;
    second.review = Review::FalsePositive;
    store.save_many(dir.path(), &[first, second]).unwrap();
    store.save_many(dir.path(), &[finding("1")]).unwrap();
    let mut restored = vec![finding("1"), finding("2")];
    store.restore(dir.path(), &mut restored).unwrap();
    assert_eq!(restored[0].review, Review::Unreviewed);
    assert_eq!(restored[1].review, Review::FalsePositive);
}

#[test]
fn bulk_review_reports_storage_failures() {
    let dir = tempfile::tempdir().unwrap();
    let blocking_file = dir.path().join("not-a-directory");
    std::fs::write(&blocking_file, "x").unwrap();
    let store = ReviewStore::at(blocking_file.join("reviews.json"));
    let mut item = finding("1");
    item.review = Review::AcceptedRisk;
    assert!(store.save_many(dir.path(), &[item]).is_err());
}

#[test]
fn bulk_review_rejects_conflicting_decisions_for_same_identity() {
    let dir = tempfile::tempdir().unwrap();
    let store = ReviewStore::at(dir.path().join("reviews.json"));
    let mut first = finding("1");
    first.review = Review::AcceptedRisk;
    let mut conflicting = finding("1");
    conflicting.review = Review::FalsePositive;
    let result = store.save_many(dir.path(), &[first, conflicting]).unwrap();
    assert_eq!(result.saved, vec![0]);
    assert_eq!(result.rejected[0].0, 1);
    let mut restored = vec![finding("1")];
    store.restore(dir.path(), &mut restored).unwrap();
    assert_eq!(restored[0].review, Review::AcceptedRisk);
}
