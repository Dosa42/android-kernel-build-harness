use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

const SCANNER_VERSION: &str = "m2.0";
const READ_CHUNK: usize = 64 * 1024;
const OVERLAP: usize = 96;

const SIGNATURES: &[(&str, &str)] = &[
    ("codex", "codex"),
    ("codex_app_server", "codex_app_server"),
    ("codex-app-server", "codex-app-server"),
    ("codex exec-server", "codex exec-server"),
    ("backend-api/codex", "backend-api/codex"),
    ("json schema", "json schema"),
    ("$schema", "$schema"),
    ("$defs", "$defs"),
    ("properties", "\"properties\""),
    ("schemars", "schemars"),
    ("zod", "zod"),
    ("rpc", "rpc"),
    ("protocol", "protocol"),
    ("request", "request"),
    ("response", "response"),
    ("notification", "notification"),
];

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub scanner_version: String,
    pub elapsed_ms: u64,
    pub roots: Vec<String>,
    pub directories_seen: u64,
    pub files_seen: u64,
    pub symlinks_seen: u64,
    pub codex_anchors: Vec<CodexAnchor>,
    pub hits: Vec<ScanHit>,
    pub blocked: Vec<BlockedPath>,
    pub excluded_virtual_trees: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexAnchor {
    pub discovered_path: String,
    pub resolved_realpath: Option<String>,
    pub found_by: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanHit {
    pub discovered_path: String,
    pub resolved_realpath: String,
    pub classification: String,
    pub reasons: Vec<String>,
    pub signatures: Vec<String>,
    pub size: u64,
    pub modified_unix_seconds: Option<u64>,
    pub sha256: String,
    pub device: Option<u64>,
    pub inode: Option<u64>,
    pub duplicate_of: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockedPath {
    pub path: String,
    pub operation: String,
    pub error_kind: String,
    pub error: String,
}

pub fn scan_system_json() -> Result<String, String> {
    let report = scan_system();
    serde_json::to_string_pretty(&report).map_err(|e| e.to_string())
}

pub fn scan_system() -> ScanReport {
    let started = Instant::now();
    let roots = discover_roots();
    let mut state = ScanState::default();
    state.anchors = discover_codex_anchors();

    let excluded_virtual_trees = virtual_tree_exclusions();
    let excluded: HashSet<PathBuf> = excluded_virtual_trees.iter().map(PathBuf::from).collect();

    for root in &roots {
        walk_root(root, &excluded, &mut state);
    }

    state.hits.sort_by(|a, b| a.discovered_path.cmp(&b.discovered_path));
    state.blocked.sort_by(|a, b| a.path.cmp(&b.path).then(a.operation.cmp(&b.operation)));
    state.anchors.sort_by(|a, b| a.discovered_path.cmp(&b.discovered_path));
    state.anchors.dedup_by(|a, b| a.discovered_path == b.discovered_path && a.found_by == b.found_by);
    mark_duplicates(&mut state.hits);

    ScanReport {
        scanner_version: SCANNER_VERSION.to_owned(),
        elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        roots: roots.iter().map(display_path).collect(),
        directories_seen: state.directories_seen,
        files_seen: state.files_seen,
        symlinks_seen: state.symlinks_seen,
        codex_anchors: state.anchors,
        hits: state.hits,
        blocked: state.blocked,
        excluded_virtual_trees,
    }
}

#[derive(Default)]
struct ScanState {
    directories_seen: u64,
    files_seen: u64,
    symlinks_seen: u64,
    visited_dirs: HashSet<FileIdentity>,
    hits: Vec<ScanHit>,
    blocked: Vec<BlockedPath>,
    anchors: Vec<CodexAnchor>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum FileIdentity {
    #[cfg(unix)]
    Unix(u64, u64),
    Path(PathBuf),
}

fn discover_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    #[cfg(unix)]
    roots.push(PathBuf::from("/"));

    #[cfg(windows)]
    {
        if let Some(drive) = env::var_os("SystemDrive") {
            roots.push(PathBuf::from(format!("{}\\", drive.to_string_lossy())));
        }
    }

    for key in ["HOME", "USERPROFILE", "CODEX_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "LOCALAPPDATA", "APPDATA"] {
        if let Some(value) = env::var_os(key) {
            let p = PathBuf::from(value);
            if p.exists() {
                roots.push(p);
            }
        }
    }

    if let Ok(cwd) = env::current_dir() {
        roots.push(cwd);
    }

    roots.sort();
    roots.dedup();

    // If a filesystem root is already present, narrower descendants would only
    // repeat the same traversal. Keep them as discovery inputs elsewhere, but
    // scan the broadest roots once.
    let snapshot = roots.clone();
    roots.retain(|candidate| {
        !snapshot.iter().any(|other| other != candidate && candidate.starts_with(other))
    });
    roots
}

fn discover_codex_anchors() -> Vec<CodexAnchor> {
    let mut anchors = Vec::new();

    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            for name in codex_binary_names() {
                let candidate = dir.join(name);
                if candidate.is_file() || candidate.is_symlink() {
                    anchors.push(CodexAnchor {
                        discovered_path: display_path(&candidate),
                        resolved_realpath: fs::canonicalize(&candidate).ok().map(|p| display_path(&p)),
                        found_by: "PATH".into(),
                    });
                }
            }
        }
    }

    if let Some(home) = env::var_os("CODEX_HOME") {
        let p = PathBuf::from(home);
        anchors.push(CodexAnchor {
            discovered_path: display_path(&p),
            resolved_realpath: fs::canonicalize(&p).ok().map(|v| display_path(&v)),
            found_by: "CODEX_HOME".into(),
        });
    }

    anchors
}

fn codex_binary_names() -> &'static [&'static str] {
    #[cfg(windows)]
    { &["codex.exe", "codex.cmd", "codex.bat"] }
    #[cfg(not(windows))]
    { &["codex"] }
}

fn virtual_tree_exclusions() -> Vec<String> {
    #[cfg(unix)]
    {
        vec!["/proc".into(), "/sys".into(), "/dev".into()]
    }
    #[cfg(not(unix))]
    {
        Vec::new()
    }
}

fn walk_root(root: &Path, excluded: &HashSet<PathBuf>, state: &mut ScanState) {
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        if excluded.contains(&dir) {
            continue;
        }

        let metadata = match fs::symlink_metadata(&dir) {
            Ok(m) => m,
            Err(e) => {
                push_blocked(state, &dir, "metadata", &e);
                continue;
            }
        };

        if !metadata.is_dir() {
            process_entry(&dir, metadata, state);
            continue;
        }

        let id = file_identity(&dir, &metadata);
        if !state.visited_dirs.insert(id) {
            continue;
        }
        state.directories_seen += 1;

        let entries = match fs::read_dir(&dir) {
            Ok(v) => v,
            Err(e) => {
                push_blocked(state, &dir, "read_dir", &e);
                continue;
            }
        };

        let mut children = Vec::new();
        for entry in entries {
            match entry {
                Ok(v) => children.push(v.path()),
                Err(e) => push_blocked(state, &dir, "read_dir_entry", &e),
            }
        }
        children.sort();
        children.reverse();

        for child in children {
            let meta = match fs::symlink_metadata(&child) {
                Ok(m) => m,
                Err(e) => {
                    push_blocked(state, &child, "metadata", &e);
                    continue;
                }
            };

            if meta.file_type().is_symlink() {
                state.symlinks_seen += 1;
                process_symlink(&child, state);
            } else if meta.is_dir() {
                stack.push(child);
            } else {
                process_entry(&child, meta, state);
            }
        }
    }
}

fn process_symlink(path: &Path, state: &mut ScanState) {
    let real = match fs::canonicalize(path) {
        Ok(v) => v,
        Err(e) => {
            push_blocked(state, path, "canonicalize_symlink", &e);
            return;
        }
    };

    let target_meta = match fs::metadata(path) {
        Ok(v) => v,
        Err(e) => {
            push_blocked(state, path, "metadata_symlink_target", &e);
            return;
        }
    };

    // Never recurse through a directory symlink: that creates cycles and duplicate
    // tree walks. File symlinks are inspected and retain both discovered + real path.
    if target_meta.is_file() {
        process_regular_file(path, &real, &target_meta, state);
    }
}

fn process_entry(path: &Path, metadata: Metadata, state: &mut ScanState) {
    if metadata.is_file() {
        process_regular_file(path, path, &metadata, state);
    }
}

fn process_regular_file(discovered: &Path, real_hint: &Path, metadata: &Metadata, state: &mut ScanState) {
    state.files_seen += 1;

    let signatures = match scan_signatures(discovered) {
        Ok(v) => v,
        Err(e) => {
            push_blocked(state, discovered, "content_scan", &e);
            Vec::new()
        }
    };

    let path_lower = discovered.to_string_lossy().to_ascii_lowercase();
    let real = fs::canonicalize(discovered).unwrap_or_else(|_| real_hint.to_path_buf());
    let real_lower = real.to_string_lossy().to_ascii_lowercase();

    let path_codex = path_lower.contains("codex") || real_lower.contains("codex");
    let path_schema = path_has_schema_signal(&path_lower) || path_has_schema_signal(&real_lower);
    let content_codex = signatures.iter().any(|s| is_codex_signature(s));
    let content_schema = signatures.iter().any(|s| is_schema_signature(s));

    let classification = if (path_codex && (path_schema || content_schema)) || (content_codex && content_schema) {
        Some("confirmed_codex_schema")
    } else if content_codex || path_codex {
        Some("codex_anchor_or_related")
    } else {
        None
    };

    let Some(classification) = classification else { return; };

    let mut reasons = Vec::new();
    if path_codex { reasons.push("path_contains_codex".into()); }
    if path_schema { reasons.push("path_contains_schema_or_protocol_signal".into()); }
    if content_codex { reasons.push("content_contains_codex_signature".into()); }
    if content_schema { reasons.push("content_contains_schema_or_protocol_signature".into()); }

    let sha256 = match sha256_file(discovered) {
        Ok(v) => v,
        Err(e) => {
            push_blocked(state, discovered, "sha256", &e);
            String::new()
        }
    };

    let (device, inode) = metadata_device_inode(metadata);
    state.hits.push(ScanHit {
        discovered_path: display_path(discovered),
        resolved_realpath: display_path(&real),
        classification: classification.into(),
        reasons,
        signatures,
        size: metadata.len(),
        modified_unix_seconds: metadata.modified().ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs()),
        sha256,
        device,
        inode,
        duplicate_of: None,
    });
}

fn path_has_schema_signal(path: &str) -> bool {
    [
        "config-schema", "schema", "protocol", "rpc", "app-server", "app_server",
        "exec-server", "exec_server", "generated", "types.rs", "types.ts", "openapi",
    ].iter().any(|needle| path.contains(needle))
}

fn is_codex_signature(signature: &str) -> bool {
    matches!(signature,
        "codex" | "codex_app_server" | "codex-app-server" | "codex exec-server" | "backend-api/codex")
}

fn is_schema_signature(signature: &str) -> bool {
    matches!(signature,
        "json schema" | "$schema" | "$defs" | "properties" | "schemars" | "zod" |
        "rpc" | "protocol" | "request" | "response" | "notification")
}

fn scan_signatures(path: &Path) -> io::Result<Vec<String>> {
    let mut file = File::open(path)?;
    let mut found = vec![false; SIGNATURES.len()];
    let mut carry = Vec::<u8>::new();
    let mut buffer = vec![0u8; READ_CHUNK];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 { break; }

        let mut window = Vec::with_capacity(carry.len() + n);
        window.extend_from_slice(&carry);
        window.extend_from_slice(&buffer[..n]);
        window.make_ascii_lowercase();

        for (idx, (_, needle)) in SIGNATURES.iter().enumerate() {
            if !found[idx] && contains_bytes(&window, needle.as_bytes()) {
                found[idx] = true;
            }
        }

        if found.iter().all(|v| *v) { break; }
        let keep = window.len().min(OVERLAP);
        carry.clear();
        carry.extend_from_slice(&window[window.len() - keep..]);
    }

    Ok(SIGNATURES.iter().enumerate()
        .filter_map(|(idx, (label, _))| found[idx].then(|| (*label).to_owned()))
        .collect())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    if needle.len() > haystack.len() { return false; }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; READ_CHUNK];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn mark_duplicates(hits: &mut [ScanHit]) {
    let mut first_by_hash: HashMap<(String, u64), String> = HashMap::new();
    for hit in hits {
        if hit.sha256.is_empty() { continue; }
        let key = (hit.sha256.clone(), hit.size);
        if let Some(first) = first_by_hash.get(&key) {
            if first != &hit.discovered_path {
                hit.duplicate_of = Some(first.clone());
            }
        } else {
            first_by_hash.insert(key, hit.discovered_path.clone());
        }
    }
}

fn file_identity(path: &Path, metadata: &Metadata) -> FileIdentity {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return FileIdentity::Unix(metadata.dev(), metadata.ino());
    }
    #[allow(unreachable_code)]
    FileIdentity::Path(fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()))
}

fn metadata_device_inode(metadata: &Metadata) -> (Option<u64>, Option<u64>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return (Some(metadata.dev()), Some(metadata.ino()));
    }
    #[allow(unreachable_code)]
    (None, None)
}

fn push_blocked(state: &mut ScanState, path: &Path, operation: &str, error: &io::Error) {
    state.blocked.push(BlockedPath {
        path: display_path(path),
        operation: operation.into(),
        error_kind: format!("{:?}", error.kind()),
        error: error.to_string(),
    });
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_match_handles_plain_ascii() {
        assert!(contains_bytes(b"abc codex schema xyz", b"codex"));
        assert!(!contains_bytes(b"abc", b"codex"));
    }

    #[test]
    fn schema_path_detection_covers_protocol_names() {
        assert!(path_has_schema_signal("/tmp/codex/protocol.rs"));
        assert!(path_has_schema_signal("/tmp/config-schema.json"));
        assert!(!path_has_schema_signal("/tmp/readme.md"));
    }
}
