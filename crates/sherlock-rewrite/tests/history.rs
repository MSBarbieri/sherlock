use std::{fs, path::Path, process::Command};

fn git(repo: &Path, args: &[&str]) -> String {
    let o = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout).unwrap().trim().to_string()
}
fn init() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    git(tmp.path(), &["init", "-q", "-b", "main"]);
    git(tmp.path(), &["config", "user.name", "Test"]);
    git(tmp.path(), &["config", "user.email", "test@example.com"]);
    tmp
}
#[test]
fn rewrites_merge_and_shared_ancestry_without_modifying_refs() {
    let tmp = init();
    let p = tmp.path();
    fs::write(p.join("secret.txt"), "before one\ntwo after\n").unwrap();
    fs::write(p.join("binary.dat"), b"\0one\ntwo\0").unwrap();
    git(p, &["add", "."]);
    git(p, &["commit", "-qm", "root"]);
    git(p, &["checkout", "-qb", "feature"]);
    fs::write(p.join("feature"), "feature").unwrap();
    git(p, &["add", "."]);
    git(p, &["commit", "-qm", "feature"]);
    let feature = git(p, &["rev-parse", "HEAD"]);
    git(p, &["checkout", "-q", "main"]);
    fs::write(p.join("main"), "main").unwrap();
    git(p, &["add", "."]);
    git(p, &["commit", "-qm", "main"]);
    git(p, &["merge", "--no-ff", "-qm", "merge", "feature"]);
    let merge = git(p, &["rev-parse", "HEAD"]);
    let rewritten = sherlock_rewrite::redact(
        p,
        &[merge.clone(), feature.clone()],
        b"one\ntwo",
        b"[REDACTED]",
    )
    .unwrap();
    assert_ne!(merge, rewritten[0]);
    assert_eq!(
        git(p, &["show", &format!("{}:secret.txt", rewritten[0])]),
        "before [REDACTED] after"
    );
    let binary = Command::new("git")
        .current_dir(p)
        .args(["show", &format!("{}:binary.dat", rewritten[0])])
        .output()
        .unwrap();
    assert_eq!(binary.stdout, b"\0one\ntwo\0");
    let parents = git(p, &["rev-list", "--parents", "-n", "1", &rewritten[0]]);
    assert_eq!(parents.split_whitespace().count(), 3);
    assert_eq!(
        parents.split_whitespace().nth(2),
        Some(rewritten[1].as_str())
    );
    assert_eq!(git(p, &["rev-parse", "HEAD"]), merge);
    assert_eq!(git(p, &["rev-parse", "feature"]), feature);
    git(p, &["fsck", "--no-reflogs"]);
}
#[test]
fn rejects_empty_and_absent_values() {
    let tmp = init();
    let p = tmp.path();
    fs::write(p.join("a"), "contents").unwrap();
    git(p, &["add", "."]);
    git(p, &["commit", "-qm", "root"]);
    let tip = git(p, &["rev-parse", "HEAD"]);
    assert!(sherlock_rewrite::redact(p, std::slice::from_ref(&tip), b"", b"x").is_err());
    assert!(sherlock_rewrite::redact(p, &[tip], b"missing", b"x").is_err());
}
