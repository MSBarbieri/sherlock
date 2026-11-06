use std::{path::Path, process::Command};

/// Text of a file at a specific commit, with the same replacement used by the rewriter.
pub struct FilePreview {
    pub original: String,
    pub rewritten: String,
    pub replacements: usize,
}

pub struct FileComparison {
    pub original: String,
    pub rewritten: String,
}

/// Compare the actual bytes at two commits. The caller must establish the
/// correspondence between those commits; this function does not infer it.
pub fn compare_files(
    repo: &Path,
    original: &str,
    rewritten: &str,
    path: &str,
) -> Result<FileComparison, String> {
    Ok(FileComparison {
        original: read_file(repo, original, path)?,
        rewritten: read_file(repo, rewritten, path)?,
    })
}

/// Preview one exact value in one historical file. Binary and non-UTF-8 files cannot
/// be displayed; a successful preview is not evidence about any other file or commit.
pub fn preview_file(
    repo: &Path,
    commit: &str,
    path: &str,
    value: &str,
) -> Result<FilePreview, String> {
    if path.is_empty() || value.is_empty() || value.as_bytes().contains(&0) {
        return Err("A file path and a non-binary detected value are required.".into());
    }
    if value.contains(['\n', '\r']) {
        return Err("Multiline values cannot be displayed in this preview; the rewrite may still process them.".into());
    }
    let original = read_file(repo, commit, path)?;
    let replacements = original.matches(value).count();
    let rewritten = original.replace(value, "[REDACTED]");
    Ok(FilePreview {
        original,
        rewritten,
        replacements,
    })
}

fn read_file(repo: &Path, commit: &str, path: &str) -> Result<String, String> {
    if commit.is_empty() || !commit.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("No valid commit is available for this finding.".into());
    }
    if path.is_empty() {
        return Err("No file path is available.".into());
    }
    let spec = format!("{commit}:{path}");
    let output = Command::new("git")
        .current_dir(repo)
        .args(["cat-file", "blob", &spec])
        .output()
        .map_err(|e| format!("Could not start git: {e}"))?;
    if !output.status.success() {
        return Err("File is unavailable at this commit or is not a file blob.".into());
    }
    if output.stdout.contains(&0) {
        return Err("Binary files are not supported by the redaction preview or rewrite.".into());
    }
    String::from_utf8(output.stdout)
        .map_err(|_| "This file is not UTF-8 and cannot be displayed. The rewrite may still process its bytes.".to_owned())
}
