use sherlock_domain::{Finding, Review};
use std::{path::Path, process::Command};

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[test]
fn graph_limit_can_be_expanded_to_reveal_older_history() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    git(repo, &["init", "-q"]);
    git(repo, &["config", "user.name", "Test"]);
    git(repo, &["config", "user.email", "test@example.com"]);
    for _ in 0..4 {
        git(repo, &["commit", "--allow-empty", "-qm", "step"]);
    }
    let tip = git(repo, &["rev-parse", "HEAD"]);
    let finding = Finding {
        scanner: "test",
        rule: String::new(),
        file: String::new(),
        commit: tip,
        line: String::new(),
        secret: "value".into(),
        evidence: vec![],
        review: Review::Unreviewed,
    };
    let history = sherlock_git::secret_history(repo, &[finding], &[]).unwrap();
    let (short, truncated) = sherlock_git::history_graph_page(repo, &history, 2).unwrap();
    assert!(truncated);
    assert_eq!(short.iter().filter(|row| row.commit.is_some()).count(), 2);
    let (expanded, truncated) = sherlock_git::history_graph_page(repo, &history, 5).unwrap();
    assert!(!truncated);
    assert_eq!(
        expanded.iter().filter(|row| row.commit.is_some()).count(),
        4
    );
}
