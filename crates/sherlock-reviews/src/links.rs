//! Persistent related-value links. Raw values never leave memory.
//! The credential store owns the random HMAC key; keep its entry when backing up
//! link data. Deleting or resetting it makes the link file unreadable.
use chacha20poly1305::{
    aead::{Aead, Payload as AeadPayload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use fs2::FileExt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    path::{Path, PathBuf},
};

type HmacSha256 = Hmac<Sha256>;
fn digest(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut h = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
    h.update(message);
    h.finalize().into_bytes().to_vec()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[derive(Default, Serialize, Deserialize)]
struct Payload {
    version: u8,
    edges: BTreeSet<(String, String)>,
    #[serde(default)]
    repositories: BTreeMap<String, BTreeSet<(String, String)>>,
    #[serde(default)]
    completions: BTreeMap<String, BTreeMap<String, CompletionRecord>>,
    #[serde(default)]
    aliases: BTreeMap<String, Alias>,
}
#[derive(Serialize, Deserialize)]
struct Alias {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// Developer-supplied historical review context, not a claim of current safety.
/// Callers must never put secret values or scanner output in these fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionRecord {
    pub output_tips: Vec<CompletionTip>,
    pub scanners: Vec<String>,
    pub checks_summary: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionTip {
    pub reference: String,
    pub commit: String,
}
/// A persistent link endpoint; `present` means its value appeared in this scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkNode {
    pub id: String,
    pub present: bool,
}
/// Opaque endpoints of a directly linked pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkEdge {
    pub left: LinkNode,
    pub right: LinkNode,
}
#[derive(Serialize, Deserialize)]
struct Envelope {
    payload: String,
    tag: Vec<u8>,
}
trait Keys {
    fn get(&self) -> Result<Option<Vec<u8>>, String>;
    fn set(&self, key: &[u8]) -> Result<(), String>;
}
struct KeyringKey {
    account: String,
}
impl Keys for KeyringKey {
    fn get(&self) -> Result<Option<Vec<u8>>, String> {
        let entry = keyring::Entry::new("sherlock.secret-links.v1", &self.account)
            .map_err(|e| format!("Could not open credential store: {e}"))?;
        match entry.get_secret() {
            Ok(key) => Ok(Some(key)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(format!("Could not read secret links key: {e}")),
        }
    }
    fn set(&self, key: &[u8]) -> Result<(), String> {
        keyring::Entry::new("sherlock.secret-links.v1", &self.account)
            .and_then(|e| e.set_secret(key))
            .map_err(|e| format!("Could not save secret links key: {e}"))
    }
}
/// A link file and its permanent sidecar lock. All Sherlock writers must use
/// this API. Never remove the lock file while Sherlock may be running.
pub struct LinkStore {
    path: PathBuf,
    account: String,
}
impl LinkStore {
    pub fn standard() -> Result<Self, String> {
        let dirs = directories::ProjectDirs::from("", "", "sherlock")
            .ok_or("Could not determine application data directory")?;
        Self::at(dirs.data_local_dir().join("secret-links.json"))
    }
    pub fn at(path: impl Into<PathBuf>) -> Result<Self, String> {
        let path = path.into();
        let dir = path.parent().ok_or("Invalid secret links path")?;
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("Could not create links directory: {e}"))?;
        let dir = dir
            .canonicalize()
            .map_err(|e| format!("Could not identify links directory: {e}"))?;
        let path = dir.join(path.file_name().ok_or("Invalid secret links filename")?);
        // Identifies the store, not a secret. No secret-derived unkeyed hash.
        let account = path
            .to_str()
            .ok_or("Links path is not valid UTF-8")?
            .to_owned();
        Ok(Self { path, account })
    }
    fn locked<T>(&self, op: impl FnOnce(&dyn Keys) -> Result<T, String>) -> Result<T, String> {
        let lock_path = self.path.with_extension("lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(lock_path)
            .map_err(|e| format!("Could not open links lock: {e}"))?;
        file.lock_exclusive()
            .map_err(|e| format!("Could not lock secret links: {e}"))?;
        op(&KeyringKey {
            account: self.account.clone(),
        })
    }
    fn key(&self, keys: &dyn Keys, create: bool) -> Result<Option<Vec<u8>>, String> {
        match keys.get()? {
            Some(k) if k.len() == 32 => Ok(Some(k)),
            Some(_) => Err("Secret links key has an invalid length".into()),
            None if self
                .path
                .try_exists()
                .map_err(|e| format!("Could not check secret links: {e}"))? =>
            {
                Err(
                    "Secret links key is missing; restore it from the credential store backup"
                        .into(),
                )
            }
            None if !create => Ok(None),
            None => {
                let mut k = vec![0u8; 32];
                getrandom::fill(&mut k)
                    .map_err(|e| format!("Could not generate secret links key: {e}"))?;
                keys.set(&k)?;
                Ok(Some(k))
            }
        }
    }
    fn id(key: &[u8], repo: &Path, value: &str) -> Result<String, String> {
        if value.is_empty() {
            return Err("Cannot link an empty value".into());
        }
        let repo = repo
            .canonicalize()
            .map_err(|e| format!("Could not identify repository: {e}"))?;
        let repo = repo.to_str().ok_or("Repository path is not valid UTF-8")?;
        let mut msg = b"sherlock-link-value-v1\0".to_vec();
        for part in [repo.as_bytes(), value.as_bytes()] {
            msg.extend_from_slice(&(part.len() as u64).to_be_bytes());
            msg.extend_from_slice(part);
        }
        Ok(hex(&digest(key, &msg)))
    }
    fn repo_id(key: &[u8], repo: &Path) -> Result<String, String> {
        let repo = repo
            .canonicalize()
            .map_err(|e| format!("Could not identify repository: {e}"))?;
        let path = repo.to_str().ok_or("Repository path is not valid UTF-8")?;
        let mut message = b"sherlock-link-repository-v1\0".to_vec();
        message.extend_from_slice(path.as_bytes());
        Ok(hex(&digest(key, &message)))
    }
    // v1 edges lacked repository metadata. Move only components provably
    // connected to observed values into this repository; preserve the rest.
    fn migrate(p: &mut Payload, repo_id: &str, anchors: &BTreeSet<String>) -> bool {
        let mut nodes = anchors.clone();
        loop {
            let before = nodes.len();
            for (a, b) in &p.edges {
                if nodes.contains(a) || nodes.contains(b) {
                    nodes.insert(a.clone());
                    nodes.insert(b.clone());
                }
            }
            if nodes.len() == before {
                break;
            }
        }
        let moved: Vec<_> = p
            .edges
            .iter()
            .filter(|(a, b)| nodes.contains(a) || nodes.contains(b))
            .cloned()
            .collect();
        for edge in &moved {
            p.edges.remove(edge);
            p.repositories
                .entry(repo_id.to_string())
                .or_default()
                .insert(edge.clone());
        }
        !moved.is_empty()
    }
    fn resolve_repo(&self, keys: &dyn Keys, repo: &Path) -> Result<PathBuf, String> {
        let repo = repo
            .canonicalize()
            .map_err(|e| format!("Could not identify repository: {e}"))?;
        if !self
            .path
            .try_exists()
            .map_err(|e| format!("Could not check secret links: {e}"))?
        {
            return Ok(repo);
        }
        let key = self
            .key(keys, false)?
            .ok_or("Secret links key is missing")?;
        let p = self.read(&key)?;
        let id = Self::repo_id(&key, &repo)?;
        let Some(alias) = p.aliases.get(&id) else {
            return Ok(repo);
        };
        if alias.nonce.len() != 24 {
            return Err("Invalid repository alias nonce".into());
        }
        let encryption_key = digest(&key, b"sherlock-repository-alias-key-v1");
        let cipher =
            XChaCha20Poly1305::new_from_slice(&encryption_key).map_err(|_| "Invalid alias key")?;
        let bytes = cipher
            .decrypt(
                XNonce::from_slice(&alias.nonce),
                AeadPayload {
                    msg: &alias.ciphertext,
                    aad: id.as_bytes(),
                },
            )
            .map_err(|_| "Repository alias authentication failed")?;
        let path = String::from_utf8(bytes).map_err(|_| "Invalid repository alias path")?;
        PathBuf::from(path)
            .canonicalize()
            .map_err(|e| format!("Could not access original repository for this mirror: {e}"))
    }
    fn register_alias_with(
        &self,
        keys: &dyn Keys,
        source: &Path,
        mirror: &Path,
    ) -> Result<(), String> {
        let source = self.resolve_repo(keys, source)?;
        let mirror = mirror
            .canonicalize()
            .map_err(|e| format!("Could not identify mirror: {e}"))?;
        if source == mirror {
            return Err("A repository cannot be its own mirror alias".into());
        }
        let key = self.key(keys, true)?.ok_or("Secret links key is missing")?;
        let mut p = self.read(&key)?;
        let id = Self::repo_id(&key, &mirror)?;
        if !p.edges.is_empty() {
            return Err(
                "Unassigned legacy links exist; scan their repository before registering a mirror"
                    .into(),
            );
        }
        if p.repositories.get(&id).is_some_and(|e| !e.is_empty())
            || p.completions.get(&id).is_some_and(|c| !c.is_empty())
        {
            return Err(
                "Mirror already has independent workspace data; refusing to hide it".into(),
            );
        }
        if p.aliases.contains_key(&id) {
            let existing = self.resolve_repo(keys, &mirror)?;
            if existing == source {
                return Ok(());
            }
            return Err("Mirror is already linked to a different repository".into());
        }
        let mut nonce = vec![0u8; 24];
        getrandom::fill(&mut nonce).map_err(|e| format!("Could not generate alias nonce: {e}"))?;
        let encryption_key = digest(&key, b"sherlock-repository-alias-key-v1");
        let cipher =
            XChaCha20Poly1305::new_from_slice(&encryption_key).map_err(|_| "Invalid alias key")?;
        let plaintext = source
            .to_str()
            .ok_or("Repository path is not valid UTF-8")?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                AeadPayload {
                    msg: plaintext.as_bytes(),
                    aad: id.as_bytes(),
                },
            )
            .map_err(|_| "Could not encrypt repository alias")?;
        p.aliases.insert(id, Alias { nonce, ciphertext });
        self.write(&key, &p)
    }
    /// Associate a verified Sherlock-created mirror with its original repository.
    /// The original path must remain available; changing paths requires a new alias.
    pub fn register_mirror(&self, source: &Path, mirror: &Path) -> Result<(), String> {
        self.locked(|keys| self.register_alias_with(keys, source, mirror))
    }
    fn read(&self, key: &[u8]) -> Result<Payload, String> {
        let bytes = match std::fs::read(&self.path) {
            Ok(x) => x,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Payload {
                    version: 1,
                    ..Default::default()
                })
            }
            Err(e) => return Err(format!("Could not read secret links: {e}")),
        };
        let env: Envelope =
            serde_json::from_slice(&bytes).map_err(|e| format!("Invalid secret links: {e}"))?;
        let mut h = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
        h.update(env.payload.as_bytes());
        h.verify_slice(&env.tag)
            .map_err(|_| "Secret links authentication failed")?;
        let p: Payload = serde_json::from_str(&env.payload)
            .map_err(|e| format!("Invalid authenticated secret links: {e}"))?;
        if p.version != 1 {
            return Err("Unsupported secret links version".into());
        }
        Ok(p)
    }
    fn write(&self, key: &[u8], p: &Payload) -> Result<(), String> {
        let payload = serde_json::to_string(p).map_err(|e| e.to_string())?;
        let env = Envelope {
            tag: digest(key, payload.as_bytes()),
            payload,
        };
        let mut tmp =
            tempfile::NamedTempFile::new_in(self.path.parent().ok_or("Invalid links path")?)
                .map_err(|e| e.to_string())?;
        serde_json::to_writer(&mut tmp, &env).map_err(|e| e.to_string())?;
        tmp.persist(&self.path)
            .map_err(|e| format!("Could not save secret links: {}", e.error))?;
        Ok(())
    }
    fn set_with(
        &self,
        keys: &dyn Keys,
        repo: &Path,
        a: &str,
        b: &str,
        linked: bool,
    ) -> Result<(), String> {
        if a.is_empty() || b.is_empty() || a == b {
            return Err("Choose two distinct nonempty values".into());
        }
        let Some(key) = self.key(keys, linked)? else {
            return Ok(());
        };
        let mut a = Self::id(&key, repo, a)?;
        let mut b = Self::id(&key, repo, b)?;
        if a > b {
            std::mem::swap(&mut a, &mut b)
        }
        let mut p = self.read(&key)?;
        let repo_id = Self::repo_id(&key, repo)?;
        Self::migrate(&mut p, &repo_id, &BTreeSet::from([a.clone(), b.clone()]));
        let edges = p.repositories.entry(repo_id.clone()).or_default();
        let changed = if linked {
            edges.insert((a, b))
        } else {
            edges.remove(&(a, b))
        };
        if changed {
            p.completions.remove(&repo_id);
        }
        self.write(&key, &p)
    }
    /// Changes a direct link. Removing it may leave an indirect connection.
    pub fn set_link(&self, repo: &Path, a: &str, b: &str, linked: bool) -> Result<(), String> {
        self.locked(|keys| {
            let repo = self.resolve_repo(keys, repo)?;
            self.set_with(keys, &repo, a, b, linked)
        })
    }
    fn groups_with(
        &self,
        keys: &dyn Keys,
        repo: &Path,
        values: &[&str],
    ) -> Result<Vec<Vec<usize>>, String> {
        let key = if self
            .path
            .try_exists()
            .map_err(|e| format!("Could not check secret links: {e}"))?
        {
            self.key(keys, false)?
        } else {
            None
        };
        let ids: Vec<Option<String>> = values
            .iter()
            .map(|v| {
                if v.is_empty() {
                    Ok(None)
                } else if let Some(k) = &key {
                    Self::id(k, repo, v).map(Some)
                } else {
                    Ok(Some(v.to_string()))
                }
            })
            .collect::<Result<_, _>>()?;
        let mut p = if let Some(k) = &key {
            self.read(k)?
        } else {
            Payload::default()
        };
        let edges = if let Some(k) = &key {
            let repo_id = Self::repo_id(k, repo)?;
            let anchors = ids.iter().flatten().cloned().collect();
            if Self::migrate(&mut p, &repo_id, &anchors) {
                self.write(k, &p)?;
            }
            p.repositories.get(&repo_id).cloned().unwrap_or_default()
        } else {
            BTreeSet::new()
        };
        let mut groups = Vec::new();
        let mut seen = vec![false; values.len()];
        for i in 0..values.len() {
            if seen[i] {
                continue;
            }
            seen[i] = true;
            let mut group = vec![i];
            if let Some(id) = &ids[i] {
                let mut connected = BTreeSet::from([id.clone()]);
                loop {
                    let n = connected.len();
                    for (a, b) in &edges {
                        if connected.contains(a) || connected.contains(b) {
                            connected.insert(a.clone());
                            connected.insert(b.clone());
                        }
                    }
                    if n == connected.len() {
                        break;
                    }
                }
                for j in i + 1..values.len() {
                    if !seen[j] && ids[j].as_ref().is_some_and(|id| connected.contains(id)) {
                        seen[j] = true;
                        group.push(j)
                    }
                }
            }
            groups.push(group);
        }
        Ok(groups)
    }
    fn edges_with(
        &self,
        keys: &dyn Keys,
        repo: &Path,
        values: &[&str],
    ) -> Result<Vec<LinkEdge>, String> {
        if !self
            .path
            .try_exists()
            .map_err(|e| format!("Could not check secret links: {e}"))?
        {
            return Ok(Vec::new());
        }
        let key = self
            .key(keys, false)?
            .ok_or("Secret links key is missing")?;
        let repo_id = Self::repo_id(&key, repo)?;
        let present = values
            .iter()
            .filter(|v| !v.is_empty())
            .map(|v| Self::id(&key, repo, v))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let mut p = self.read(&key)?;
        if Self::migrate(&mut p, &repo_id, &present) {
            self.write(&key, &p)?;
        }
        Ok(p.repositories
            .get(&repo_id)
            .into_iter()
            .flatten()
            .map(|(a, b)| LinkEdge {
                left: LinkNode {
                    id: a.clone(),
                    present: present.contains(a),
                },
                right: LinkNode {
                    id: b.clone(),
                    present: present.contains(b),
                },
            })
            .collect())
    }
    /// All persisted links for this repository, including absent endpoints.
    pub fn edges(&self, repo: &Path, current_values: &[&str]) -> Result<Vec<LinkEdge>, String> {
        self.locked(|keys| {
            let repo = self.resolve_repo(keys, repo)?;
            self.edges_with(keys, &repo, current_values)
        })
    }
    fn unlink_ids_with(
        &self,
        keys: &dyn Keys,
        repo: &Path,
        left: &str,
        right: &str,
    ) -> Result<(), String> {
        if !self
            .path
            .try_exists()
            .map_err(|e| format!("Could not check secret links: {e}"))?
        {
            return Err("No saved secret links".into());
        }
        let key = self
            .key(keys, false)?
            .ok_or("Secret links key is missing")?;
        let repo_id = Self::repo_id(&key, repo)?;
        let mut p = self.read(&key)?;
        let pair = if left < right {
            (left.to_string(), right.to_string())
        } else {
            (right.to_string(), left.to_string())
        };
        if !p
            .repositories
            .get_mut(&repo_id)
            .is_some_and(|edges| edges.remove(&pair))
        {
            return Err("Link not found in this repository".into());
        }
        p.completions.remove(&repo_id);
        self.write(&key, &p)
    }
    /// Remove one direct link by the opaque IDs returned by `edges`.
    pub fn unlink_ids(&self, repo: &Path, left: &str, right: &str) -> Result<(), String> {
        self.locked(|keys| {
            let repo = self.resolve_repo(keys, repo)?;
            self.unlink_ids_with(keys, &repo, left, right)
        })
    }
    fn component_id(
        key: &[u8],
        repo: &str,
        anchor: String,
        edges: &BTreeSet<(String, String)>,
    ) -> String {
        let mut nodes = BTreeSet::from([anchor]);
        loop {
            let n = nodes.len();
            for (a, b) in edges {
                if nodes.contains(a) || nodes.contains(b) {
                    nodes.insert(a.clone());
                    nodes.insert(b.clone());
                }
            }
            if n == nodes.len() {
                break;
            }
        }
        let mut msg = b"sherlock-completed-component-v1\0".to_vec();
        msg.extend_from_slice(repo.as_bytes());
        for id in nodes {
            msg.extend_from_slice(id.as_bytes());
        }
        hex(&digest(key, &msg))
    }
    fn completion_with(
        &self,
        keys: &dyn Keys,
        repo: &Path,
        value: &str,
        update: Option<Option<&CompletionRecord>>,
    ) -> Result<Option<CompletionRecord>, String> {
        if value.is_empty() {
            return Err("A secret value is required to identify the workspace".into());
        }
        if update.is_none()
            && !self
                .path
                .try_exists()
                .map_err(|e| format!("Could not check secret links: {e}"))?
        {
            return Ok(None);
        }
        let create = matches!(update, Some(Some(_)));
        let Some(key) = self.key(keys, create)? else {
            return Ok(None);
        };
        let repo_id = Self::repo_id(&key, repo)?;
        let anchor = Self::id(&key, repo, value)?;
        let mut p = self.read(&key)?;
        let migrated = Self::migrate(&mut p, &repo_id, &BTreeSet::from([anchor.clone()]));
        let component = Self::component_id(
            &key,
            &repo_id,
            anchor,
            p.repositories.get(&repo_id).unwrap_or(&BTreeSet::new()),
        );
        let previous = p
            .completions
            .get(&repo_id)
            .and_then(|m| m.get(&component))
            .cloned();
        if let Some(change) = update {
            match change {
                Some(record) => {
                    if record.output_tips.is_empty()
                        || record
                            .output_tips
                            .iter()
                            .any(|t| t.reference.is_empty() || t.commit.is_empty())
                        || record.scanners.is_empty()
                        || record.scanners.iter().any(String::is_empty)
                        || record.checks_summary.is_empty()
                    {
                        return Err(
                            "Completion requires output tips, scanners, and a checks summary"
                                .into(),
                        );
                    }
                    p.completions
                        .entry(repo_id)
                        .or_default()
                        .insert(component, record.clone());
                }
                None => {
                    if let Some(records) = p.completions.get_mut(&repo_id) {
                        records.remove(&component);
                    }
                }
            }
            self.write(&key, &p)?;
        } else if migrated {
            self.write(&key, &p)?;
        }
        Ok(previous)
    }
    /// Historical developer decision; does not establish current coverage or cleanliness.
    pub fn previously_completed(
        &self,
        repo: &Path,
        value: &str,
    ) -> Result<Option<CompletionRecord>, String> {
        self.locked(|keys| {
            let repo = self.resolve_repo(keys, repo)?;
            self.completion_with(keys, &repo, value, None)
        })
    }
    /// Mark or clear completion after explicit developer review. The caller is
    /// responsible for supplying accurate, non-sensitive historical evidence.
    pub fn set_completion(
        &self,
        repo: &Path,
        value: &str,
        record: Option<&CompletionRecord>,
    ) -> Result<(), String> {
        self.locked(|keys| {
            let repo = self.resolve_repo(keys, repo)?;
            self.completion_with(keys, &repo, value, Some(record))
                .map(|_| ())
        })
    }
    pub fn groups(&self, repo: &Path, values: &[&str]) -> Result<Vec<Vec<usize>>, String> {
        self.locked(|keys| {
            let repo = self.resolve_repo(keys, repo)?;
            self.groups_with(keys, &repo, values)
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    #[derive(Default)]
    struct Fake(Mutex<Option<Vec<u8>>>);
    impl Keys for Fake {
        fn get(&self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn set(&self, k: &[u8]) -> Result<(), String> {
            *self.0.lock().unwrap() = Some(k.to_vec());
            Ok(())
        }
    }
    #[test]
    fn persistence_authentication_and_missing_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = LinkStore::at(dir.path().join("links.json")).unwrap();
        let key = Fake::default();
        store
            .set_with(&key, dir.path(), "first-secret", "second-secret", true)
            .unwrap();
        assert_eq!(
            store
                .groups_with(&key, dir.path(), &["first-secret", "second-secret", ""])
                .unwrap(),
            vec![vec![0, 1], vec![2]]
        );
        assert!(!std::fs::read_to_string(&store.path)
            .unwrap()
            .contains("secret"));
        assert!(store
            .groups_with(&Fake::default(), dir.path(), &["first-secret"])
            .is_err());
        assert!(store
            .set_with(&Fake::default(), dir.path(), "a", "b", true)
            .is_err());
        *key.0.lock().unwrap() = Some(vec![7; 32]);
        assert!(store
            .groups_with(&key, dir.path(), &["first-secret"])
            .is_err());
    }
    #[test]
    fn lock_serializes_instances() {
        use std::sync::mpsc;
        use std::time::Duration;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("links.json");
        let store = LinkStore::at(&path).unwrap();
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path.with_extension("lock"))
            .unwrap();
        file.lock_exclusive().unwrap();
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            store
                .locked(|_| {
                    tx.send(()).unwrap();
                    Ok(())
                })
                .unwrap()
        });
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
        FileExt::unlock(&file).unwrap();
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        worker.join().unwrap();
    }
    #[test]
    fn links_bridge_absent_values_and_unlink_by_edge_with_repository_scope() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let store = LinkStore::at(dir.path().join("links.json")).unwrap();
        let keys = Fake::default();
        store.set_with(&keys, dir.path(), "a", "b", true).unwrap();
        store.set_with(&keys, dir.path(), "b", "c", true).unwrap();
        assert_eq!(
            store.groups_with(&keys, dir.path(), &["a", "c"]).unwrap(),
            vec![vec![0, 1]]
        );
        assert_eq!(
            store
                .groups_with(&keys, other.path(), &["a", "c", "a"])
                .unwrap(),
            vec![vec![0, 2], vec![1]]
        );
        store.set_with(&keys, dir.path(), "b", "c", false).unwrap();
        assert_eq!(
            store
                .groups_with(&keys, dir.path(), &["a", "c", "b"])
                .unwrap(),
            vec![vec![0, 2], vec![1]]
        );
    }
    #[test]
    fn tampering_does_not_overwrite_data() {
        let dir = tempfile::tempdir().unwrap();
        let store = LinkStore::at(dir.path().join("links.json")).unwrap();
        let keys = Fake::default();
        store.set_with(&keys, dir.path(), "a", "b", true).unwrap();
        let mut env: Envelope =
            serde_json::from_slice(&std::fs::read(&store.path).unwrap()).unwrap();
        env.payload.push(' ');
        let bytes = serde_json::to_vec(&env).unwrap();
        std::fs::write(&store.path, &bytes).unwrap();
        assert!(store.set_with(&keys, dir.path(), "c", "d", true).is_err());
        assert_eq!(std::fs::read(&store.path).unwrap(), bytes);
    }
    #[test]
    fn first_scan_groups_exact_values_without_keyring() {
        struct Unavailable;
        impl Keys for Unavailable {
            fn get(&self) -> Result<Option<Vec<u8>>, String> {
                Err("keyring unavailable".into())
            }
            fn set(&self, _: &[u8]) -> Result<(), String> {
                panic!("should not create key")
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let store = LinkStore::at(dir.path().join("links.json")).unwrap();
        assert_eq!(
            store
                .groups_with(&Unavailable, dir.path(), &["a", "b", "a", "", ""])
                .unwrap(),
            vec![vec![0, 2], vec![1], vec![3], vec![4]]
        );
        std::fs::write(&store.path, b"existing").unwrap();
        assert!(store.groups_with(&Unavailable, dir.path(), &["a"]).is_err());
    }
    #[test]
    fn absent_nodes_are_visible_and_unlinkable_only_in_their_repository() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let store = LinkStore::at(dir.path().join("links.json")).unwrap();
        let keys = Fake::default();
        store
            .set_with(&keys, dir.path(), "old", "new", true)
            .unwrap();
        let edges = store.edges_with(&keys, dir.path(), &[]).unwrap();
        assert_eq!(edges.len(), 1);
        assert!(!edges[0].left.present && !edges[0].right.present);
        assert!(store
            .edges_with(&keys, other.path(), &[])
            .unwrap()
            .is_empty());
        assert!(store
            .unlink_ids_with(&keys, other.path(), &edges[0].left.id, &edges[0].right.id)
            .is_err());
        store
            .unlink_ids_with(&keys, dir.path(), &edges[0].left.id, &edges[0].right.id)
            .unwrap();
        assert!(store.edges_with(&keys, dir.path(), &[]).unwrap().is_empty());
    }
    #[test]
    fn legacy_edges_migrate_when_an_endpoint_is_seen() {
        let dir = tempfile::tempdir().unwrap();
        let store = LinkStore::at(dir.path().join("links.json")).unwrap();
        let keys = Fake::default();
        keys.set(&[4; 32]).unwrap();
        let a = LinkStore::id(&[4; 32], dir.path(), "a").unwrap();
        let b = LinkStore::id(&[4; 32], dir.path(), "b").unwrap();
        let mut p = Payload {
            version: 1,
            ..Default::default()
        };
        p.edges.insert(if a < b { (a, b) } else { (b, a) });
        store.write(&[4; 32], &p).unwrap();
        assert!(store.edges_with(&keys, dir.path(), &[]).unwrap().is_empty());
        assert_eq!(
            store.edges_with(&keys, dir.path(), &["a"]).unwrap().len(),
            1
        );
        assert_eq!(store.edges_with(&keys, dir.path(), &[]).unwrap().len(), 1);
    }
    #[test]
    fn completion_is_historical_scoped_and_invalidated_by_link_changes() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let store = LinkStore::at(dir.path().join("links.json")).unwrap();
        let keys = Fake::default();
        store.set_with(&keys, dir.path(), "a", "b", true).unwrap();
        let record = CompletionRecord {
            output_tips: vec![CompletionTip {
                reference: "refs/heads/main".into(),
                commit: "abc123".into(),
            }],
            scanners: vec!["Gitleaks".into()],
            checks_summary: "Exact value checked in reachable blobs".into(),
        };
        store
            .completion_with(&keys, dir.path(), "a", Some(Some(&record)))
            .unwrap();
        assert_eq!(
            store.completion_with(&keys, dir.path(), "b", None).unwrap(),
            Some(record.clone())
        );
        assert_eq!(
            store
                .completion_with(&keys, other.path(), "a", None)
                .unwrap(),
            None
        );
        assert!(store
            .completion_with(&Fake::default(), dir.path(), "a", None)
            .is_err());
        store.set_with(&keys, dir.path(), "b", "c", true).unwrap();
        assert_eq!(
            store.completion_with(&keys, dir.path(), "a", None).unwrap(),
            None
        );
        store
            .completion_with(&keys, dir.path(), "a", Some(Some(&record)))
            .unwrap();
        let edge = store.edges_with(&keys, dir.path(), &[]).unwrap().remove(0);
        store
            .unlink_ids_with(&keys, dir.path(), &edge.left.id, &edge.right.id)
            .unwrap();
        assert_eq!(
            store.completion_with(&keys, dir.path(), "a", None).unwrap(),
            None
        );
    }
    #[test]
    fn mirror_alias_survives_restart_and_reuses_original_links_without_plaintext_path() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("original");
        let mirror = dir.path().join("mirror");
        std::fs::create_dir_all(&original).unwrap();
        std::fs::create_dir_all(&mirror).unwrap();
        let path = dir.path().join("links.json");
        let keys = Fake::default();
        let store = LinkStore::at(&path).unwrap();
        store
            .set_with(&keys, &original, "one", "two", true)
            .unwrap();
        store
            .register_alias_with(&keys, &original, &mirror)
            .unwrap();
        assert!(!std::fs::read_to_string(&path).unwrap().contains("original"));
        let reopened = LinkStore::at(&path).unwrap();
        let resolved = reopened.resolve_repo(&keys, &mirror).unwrap();
        assert_eq!(
            reopened
                .groups_with(&keys, &resolved, &["one", "two"])
                .unwrap(),
            vec![vec![0, 1]]
        );
        assert!(reopened.resolve_repo(&Fake::default(), &mirror).is_err());
        let other = dir.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        assert!(reopened
            .register_alias_with(&keys, &other, &mirror)
            .is_err());
    }
    #[test]
    fn mirror_alias_refuses_to_hide_existing_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let mirror = dir.path().join("mirror");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&mirror).unwrap();
        let store = LinkStore::at(dir.path().join("links.json")).unwrap();
        let keys = Fake::default();
        store.set_with(&keys, &mirror, "one", "two", true).unwrap();
        assert!(store.register_alias_with(&keys, &source, &mirror).is_err());
        assert_eq!(
            store.groups_with(&keys, &mirror, &["one", "two"]).unwrap(),
            vec![vec![0, 1]]
        );
    }
}
