//! Lightweight, polling-friendly repository change snapshots.
//!
//! Only Git metadata and filesystem metadata are retained. File contents are never read.
use std::{path::Path, process::Command, time::SystemTime};

/// Comparable repository state. Comparing the fields independently lets a caller
/// distinguish a history change from an uncommitted worktree change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositorySnapshot {
    pub refs: RefState,
    pub worktree: WorktreeState,
    pub worktree_dirty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefState {
    refs: Vec<u8>,
    head: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeState {
    status: Vec<u8>,
    files: Vec<FileState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileState {
    len: Option<u64>,
    modified: Option<SystemTime>,
}

fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .current_dir(repo)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .map_err(|e| format!("Could not start git: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "Could not inspect repository: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

#[cfg(unix)]
fn path_from_bytes(bytes: &[u8]) -> &std::ffi::OsStr {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::OsStr::from_bytes(bytes)
}

#[cfg(not(unix))]
fn path_from_bytes(bytes: &[u8]) -> &std::ffi::OsStr {
    // Git emits UTF-8 paths on supported non-Unix platforms.
    std::ffi::OsStr::new(std::str::from_utf8(bytes).unwrap_or(""))
}

/// Capture current refs and non-ignored worktree status. Callers should debounce
/// changes and run this off the UI thread. A bare repository has a clean worktree.
/// This is an observation, not an atomic snapshot of a changing repository.
pub fn repository_snapshot(repo: &Path) -> Result<RepositorySnapshot, String> {
    let refs = git(repo, &["for-each-ref", "--format=%(refname) %(objectname)"])?;
    // symbolic-ref also works for an unborn branch; detached HEAD needs its oid.
    let head = match git(repo, &["symbolic-ref", "-q", "HEAD"]) {
        Ok(head) => head,
        Err(_) => git(repo, &["rev-parse", "--verify", "HEAD"])?,
    };
    let bare = git(repo, &["rev-parse", "--is-bare-repository"])?;
    let status = if bare.starts_with(b"true") {
        Vec::new()
    } else {
        git(
            repo,
            &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        )?
    };
    // Porcelain v1 -z stores one path after the two status bytes; a rename or
    // copy adds a second NUL-terminated path. Metadata makes a second edit to
    // an already-dirty file observable even when its porcelain status is unchanged.
    let mut files = Vec::new();
    let mut records = status.split(|byte| *byte == 0);
    while let Some(record) = records.next() {
        if record.is_empty() {
            break;
        }
        if record.len() < 4 {
            return Err("Invalid Git status output".into());
        }
        let metadata = std::fs::symlink_metadata(repo.join(path_from_bytes(&record[3..]))).ok();
        files.push(FileState {
            len: metadata.as_ref().map(|m| m.len()),
            modified: metadata.and_then(|m| m.modified().ok()),
        });
        if record[0] == b'R' || record[0] == b'C' || record[1] == b'R' || record[1] == b'C' {
            records.next().ok_or("Invalid Git rename status")?;
        }
    }
    Ok(RepositorySnapshot {
        refs: RefState { refs, head },
        worktree_dirty: !status.is_empty(),
        worktree: WorktreeState { status, files },
    })
}
