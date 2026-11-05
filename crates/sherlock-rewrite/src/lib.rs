//! Literal redaction in Git blob history. This is not a general git-filter-repo replacement.
use std::{
    collections::HashMap,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

fn git(repo: &Path, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let mut command = Command::new("git");
    command
        .current_dir(repo)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("Could not start git: {e}"))?;
    if let Some(data) = input {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(data)
            .map_err(|e| format!("Could not write to git: {e}"))?;
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}
fn text(bytes: Vec<u8>) -> Result<String, String> {
    String::from_utf8(bytes)
        .map(|s| s.trim().to_owned())
        .map_err(|e| e.to_string())
}
fn oid(repo: &Path, kind: &str, data: &[u8]) -> Result<String, String> {
    text(git(
        repo,
        &["hash-object", "-t", kind, "-w", "--stdin"],
        Some(data),
    )?)
}
fn replace(data: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut pos = 0;
    while let Some(offset) = data[pos..].windows(needle.len()).position(|w| w == needle) {
        let end = pos + offset;
        result.extend_from_slice(&data[pos..end]);
        result.extend_from_slice(replacement);
        pos = end + needle.len();
    }
    result.extend_from_slice(&data[pos..]);
    result
}

struct Rewriter<'a> {
    repo: &'a Path,
    needle: &'a [u8],
    replacement: &'a [u8],
    trees: HashMap<String, String>,
    blobs: HashMap<String, String>,
    commits: HashMap<String, String>,
}
impl Rewriter<'_> {
    fn tree(&mut self, id: &str) -> Result<String, String> {
        if let Some(found) = self.trees.get(id) {
            return Ok(found.clone());
        }
        let entries = git(self.repo, &["ls-tree", "-z", id], None)?;
        let mut updated = Vec::new();
        for entry in entries.split(|b| *b == 0).filter(|e| !e.is_empty()) {
            let tab = entry
                .iter()
                .position(|b| *b == b'\t')
                .ok_or("Malformed tree entry")?;
            let header = std::str::from_utf8(&entry[..tab]).map_err(|_| "Invalid tree header")?;
            let mut parts = header.split(' ');
            let mode = parts.next().ok_or("Missing tree mode")?;
            let kind = parts.next().ok_or("Missing tree kind")?;
            let old = parts.next().ok_or("Missing tree object ID")?;
            let new = match kind {
                "tree" => self.tree(old)?,
                "blob" => {
                    if let Some(value) = self.blobs.get(old) {
                        value.clone()
                    } else {
                        let data = git(self.repo, &["cat-file", "blob", old], None)?;
                        // Do not rewrite binary files, matching the documented safety boundary.
                        let result = if data.contains(&0) {
                            old.to_owned()
                        } else {
                            let changed = replace(&data, self.needle, self.replacement);
                            if changed == data {
                                old.to_owned()
                            } else {
                                oid(self.repo, "blob", &changed)?
                            }
                        };
                        self.blobs.insert(old.to_owned(), result.clone());
                        result
                    }
                }
                "commit" => old.to_owned(), // submodule link
                _ => return Err(format!("Unsupported tree object type: {kind}")),
            };
            updated.extend_from_slice(format!("{mode} {kind} {new}\t").as_bytes());
            updated.extend_from_slice(&entry[tab + 1..]);
            updated.push(0);
        }
        let new = text(git(
            self.repo,
            &["mktree", "-z", "--missing"],
            Some(&updated),
        )?)?;
        self.trees.insert(id.to_owned(), new.clone());
        Ok(new)
    }
    fn commit(&mut self, id: &str) -> Result<String, String> {
        let raw = git(self.repo, &["cat-file", "commit", id], None)?;
        let split = raw
            .windows(2)
            .position(|w| w == b"\n\n")
            .ok_or("Malformed commit")?;
        let mut out = Vec::new();
        let mut removing = false;
        let mut changed = false;
        for line in raw[..split].split(|b| *b == b'\n') {
            if line.starts_with(b" ") {
                if !removing {
                    out.extend_from_slice(line);
                    out.push(b'\n');
                }
                continue;
            }
            // Signatures and embedded merge tags cannot remain valid after rewriting.
            removing = line.starts_with(b"gpgsig ")
                || line.starts_with(b"gpgsig-sha256 ")
                || line.starts_with(b"mergetag ");
            if removing {
                continue;
            }
            if let Some(tree) = line.strip_prefix(b"tree ") {
                let tree = std::str::from_utf8(tree).map_err(|_| "Invalid tree ID")?;
                let new_tree = self.tree(tree)?;
                changed |= new_tree != tree;
                out.extend_from_slice(format!("tree {new_tree}\n").as_bytes());
            } else if let Some(parent) = line.strip_prefix(b"parent ") {
                let parent = std::str::from_utf8(parent).map_err(|_| "Invalid parent ID")?;
                let new = self.commits.get(parent).ok_or(
                    "Parent commit missing from traversal (shallow repositories are not supported)",
                )?;
                changed |= new != parent;
                out.extend_from_slice(format!("parent {new}\n").as_bytes());
            } else {
                out.extend_from_slice(line);
                out.push(b'\n');
            }
        }
        out.push(b'\n');
        out.extend_from_slice(&raw[split + 2..]);
        let new = if !changed {
            id.to_owned()
        } else {
            oid(self.repo, "commit", &out)?
        };
        self.commits.insert(id.to_owned(), new.clone());
        Ok(new)
    }
}

/// Rewrite histories reachable from `tips`, returning their new object IDs in the same order.
/// Writes Git objects only; callers decide which refs to update. Existing refs are untouched.
pub fn redact(
    repo: &Path,
    tips: &[String],
    needle: &[u8],
    replacement: &[u8],
) -> Result<Vec<String>, String> {
    if needle.is_empty() {
        return Err("Cannot redact an empty value".into());
    }
    if tips.is_empty() {
        return Err("No commit tips supplied".into());
    }
    if needle.contains(&0) {
        return Err("Binary values cannot be redacted".into());
    }
    for tip in tips {
        if !matches!(tip.len(), 40 | 64) || !tip.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Invalid commit object ID".into());
        }
    }
    let mut args = vec!["rev-list", "--reverse", "--topo-order"];
    args.extend(tips.iter().map(String::as_str));
    let order = text(git(repo, &args, None)?)?;
    let mut rw = Rewriter {
        repo,
        needle,
        replacement,
        trees: HashMap::new(),
        blobs: HashMap::new(),
        commits: HashMap::new(),
    };
    for commit in order.lines() {
        rw.commit(commit)?;
    }
    if tips.iter().all(|tip| rw.commits.get(tip) == Some(tip)) {
        return Err(
            "The value was not found in any supported text blob in the selected history".into(),
        );
    }
    tips.iter()
        .map(|tip| {
            rw.commits
                .get(tip)
                .cloned()
                .ok_or_else(|| "Tip was not traversed".into())
        })
        .collect()
}
