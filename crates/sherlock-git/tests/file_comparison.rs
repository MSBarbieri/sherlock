use std::{fs, path::Path, process::Command};

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
fn compares_actual_file_contents_from_the_corresponding_commits() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    git(repo, &["init", "-q"]);
    git(repo, &["config", "user.name", "Test"]);
    git(repo, &["config", "user.email", "test@example.com"]);
    fs::write(repo.join("config"), "token=secret\n").unwrap();
    git(repo, &["add", "config"]);
    git(repo, &["commit", "-qm", "original"]);
    let original = git(repo, &["rev-parse", "HEAD"]);
    fs::write(repo.join("config"), "token=actual-result\n").unwrap();
    git(repo, &["commit", "-qam", "rewritten"]);
    let rewritten = git(repo, &["rev-parse", "HEAD"]);

    let comparison = sherlock_git::compare_files(repo, &original, &rewritten, "config").unwrap();
    assert_eq!(comparison.original, "token=secret\n");
    assert_eq!(comparison.rewritten, "token=actual-result\n");
}
