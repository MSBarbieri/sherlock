use std::process::Command;

#[test]
fn opens_repository_roots_and_rejects_subdirectories() {
    let root = tempfile::tempdir().unwrap();
    let worktree = root.path().join("worktree");
    let bare = root.path().join("bare.git");
    std::fs::create_dir(&worktree).unwrap();
    assert!(Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(&worktree)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("git")
        .args(["init", "--bare", "--quiet"])
        .arg(&bare)
        .status()
        .unwrap()
        .success());
    let nested = worktree.join("nested");
    std::fs::create_dir(&nested).unwrap();
    for path in [&worktree, &bare] {
        assert_eq!(
            sherlock_git::open_repository(path).unwrap(),
            path.canonicalize().unwrap()
        );
    }
    assert!(sherlock_git::open_repository(&nested)
        .unwrap_err()
        .contains("repository root"));
    assert!(sherlock_git::open_repository(root.path()).is_err());
    assert!(sherlock_git::open_repository(&root.path().join("missing")).is_err());
}
