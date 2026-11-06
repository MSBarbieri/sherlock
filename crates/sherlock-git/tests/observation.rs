use std::{path::Path, process::Command};

fn git(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn observes_refs_and_repeated_worktree_edits_but_ignores_ignored_files() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path();
    git(repo, &["init", "-q"]);
    git(repo, &["config", "user.name", "Test"]);
    git(repo, &["config", "user.email", "test@example.com"]);
    std::fs::write(repo.join(".gitignore"), "ignored\n").unwrap();
    std::fs::write(repo.join("tracked"), "base").unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "-qm", "base"]);
    let clean = sherlock_git::repository_snapshot(repo).unwrap();
    assert!(!clean.worktree_dirty);
    std::fs::write(repo.join("ignored"), "ignored contents").unwrap();
    assert_eq!(clean, sherlock_git::repository_snapshot(repo).unwrap());
    std::fs::write(repo.join("tracked"), "first change").unwrap();
    let changed = sherlock_git::repository_snapshot(repo).unwrap();
    assert!(changed.worktree_dirty);
    assert_eq!(clean.refs, changed.refs);
    assert_ne!(clean.worktree, changed.worktree);
    std::fs::write(repo.join("tracked"), "second different change").unwrap();
    let changed_again = sherlock_git::repository_snapshot(repo).unwrap();
    assert_ne!(changed.worktree, changed_again.worktree);
    git(repo, &["add", "tracked"]);
    git(repo, &["commit", "-qm", "change"]);
    let committed = sherlock_git::repository_snapshot(repo).unwrap();
    assert_ne!(clean.refs, committed.refs);
    assert!(!committed.worktree_dirty);
}

#[test]
fn observes_unborn_bare_and_linked_worktrees() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    assert!(
        !sherlock_git::repository_snapshot(&repo)
            .unwrap()
            .worktree_dirty
    );
    git(&repo, &["config", "user.name", "Test"]);
    git(&repo, &["config", "user.email", "test@example.com"]);
    git(&repo, &["commit", "--allow-empty", "-qm", "base"]);
    let linked = temp.path().join("linked");
    git(
        &repo,
        &["worktree", "add", "-qb", "linked", linked.to_str().unwrap()],
    );
    let before = sherlock_git::repository_snapshot(&linked).unwrap();
    std::fs::write(linked.join("new"), "change").unwrap();
    assert_ne!(
        before.worktree,
        sherlock_git::repository_snapshot(&linked).unwrap().worktree
    );
    let bare = temp.path().join("bare.git");
    git(
        temp.path(),
        &["init", "--bare", "-q", bare.to_str().unwrap()],
    );
    assert!(
        !sherlock_git::repository_snapshot(&bare)
            .unwrap()
            .worktree_dirty
    );
}
