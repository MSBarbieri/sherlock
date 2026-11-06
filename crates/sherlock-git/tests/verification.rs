use sherlock_git::{snapshot_refs, verify_exact_values};
use std::{path::Path, process::Command};

fn git(repo: &Path, args: &[&str]) {
    let result = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn checks_historical_and_binary_blobs_per_selected_ref_at_pinned_tips() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path();
    git(repo, &["init", "-q"]);
    git(repo, &["config", "user.name", "Test"]);
    git(repo, &["config", "user.email", "test@example.com"]);
    git(repo, &["commit", "--allow-empty", "-qm", "base"]);
    git(repo, &["branch", "clean"]);
    std::fs::write(repo.join("secret"), b"\0secret-value\0").unwrap();
    git(repo, &["add", "secret"]);
    git(repo, &["commit", "-qm", "add binary"]);
    git(repo, &["rm", "-q", "secret"]);
    git(repo, &["commit", "-qm", "remove"]);
    let refs = vec!["HEAD".to_string(), "refs/heads/clean".to_string()];
    let snapshot = snapshot_refs(repo, &refs).unwrap();
    // Advance HEAD after taking the snapshot: the report must describe the pinned tip.
    git(repo, &["commit", "--allow-empty", "-qm", "later"]);
    let report = verify_exact_values(repo, &snapshot, &[b"secret-value"]).unwrap();
    assert_eq!(report[0].tip, snapshot[0].tip);
    assert_eq!(report[0].commits_checked, 3);
    assert_eq!(report[0].matching_blobs.len(), 1);
    assert_eq!(report[1].commits_checked, 1);
    assert!(report[1].matching_blobs.is_empty());
    assert!(verify_exact_values(repo, &snapshot, &[b""]).is_err());
    assert!(verify_exact_values(repo, &[], &[b"secret-value"]).is_err());
}
