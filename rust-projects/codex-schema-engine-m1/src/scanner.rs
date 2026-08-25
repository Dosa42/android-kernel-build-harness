use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

const SCANNER_VERSION: &str = "m2.2";
const READ_CHUNK: usize = 64 * 1024;
const OVERLAP: usize = 256;

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
    pub installations: Vec<InstallationGroup>,
    pub relations: Vec<FileRelation>,
    pub hits: Vec<ScanHit>,
    pub blocked: Vec<BlockedPath>,
    pub excluded_virtual_trees: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexAnchor {
    pub discovered_path: String,
    pub resolved_realpath: Option<String>,
    pub found_by: String,
    pub installation_root: Option<String>,
    pub installation_layout: Option<String>,
    pub installation_evidence: Vec<String>,
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
    pub installation_root: Option<String>,
    pub installation_layout: Option<String>,
    pub installation_evidence: Vec<String>,
    pub references: Vec<String>,
    pub referenced_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileRelation {
    pub from_path: String,
    pub to_path: String,
    pub relation: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallationGroup {
    pub root: String,
    pub layout: String,
    pub evidence: Vec<String>,
    pub anchors: Vec<String>,
    pub files: Vec<String>,
    pub confirmed_schema_files: u64,
    pub related_files: u64,
    pub relation_count: u64,
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
    serde_json::to_string_pretty(&report).map_err(|error| error.to_string())
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

    state
        .hits
        .sort_by(|left, right| left.discovered_path.cmp(&right.discovered_path));
    state.blocked.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.operation.cmp(&right.operation))
    });
    state
        .anchors
        .sort_by(|left, right| left.discovered_path.cmp(&right.discovered_path));
    state.anchors.dedup_by(|left, right| {
        left.discovered_path == right.discovered_path && left.found_by == right.found_by
    });

    mark_duplicates(&mut state.hits);
    correlate_installations(&mut state.anchors, &mut state.hits);
    let relations = discover_relations(&state.hits, &mut state.blocked);
    apply_relations(&relations, &mut state.hits);
    let installations = build_installation_groups(&state.anchors, &state.hits, &relations);

    ScanReport {
        scanner_version: SCANNER_VERSION.to_owned(),
        elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        roots: roots.iter().map(|path| display_path(path)).collect(),
        directories_seen: state.directories_seen,
        files_seen: state.files_seen,
        symlinks_seen: state.symlinks_seen,
        codex_anchors: state.anchors,
        installations,
        relations,
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
    #[cfg(not(unix))]
    Path(PathBuf),
}

#[derive(Debug, Clone)]
struct InstallationGuess {
    root: String,
    layout: String,
    evidence: Vec<String>,
}

#[derive(Default)]
struct InstallationBuilder {
    layout: String,
    evidence: Vec<String>,
    anchors: Vec<String>,
    files: Vec<String>,
    confirmed_schema_files: u64,
    related_files: u64,
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

    for key in [
        "HOME",
        "USERPROFILE",
        "CODEX_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "LOCALAPPDATA",
        "APPDATA",
        "NPM_CONFIG_PREFIX",
        "PNPM_HOME",
        "CARGO_HOME",
        "RUSTUP_HOME",
    ] {
        if let Some(value) = env::var_os(key) {
            let path = PathBuf::from(value);
            if path.exists() {
                roots.push(path);
            }
        }
    }

    if let Ok(cwd) = env::current_dir() {
        roots.push(cwd);
    }

    roots.sort();
    roots.dedup();

    let snapshot = roots.clone();
    roots.retain(|candidate| {
        !snapshot
            .iter()
            .any(|other| other != candidate && candidate.starts_with(other))
    });
    roots
}

fn discover_codex_anchors() -> Vec<CodexAnchor> {
    let mut anchors = Vec::new();

    if let Some(path_var) = env::var_os("PATH") {
        for directory in env::split_paths(&path_var) {
            for name in codex_binary_names() {
                let candidate = directory.join(name);
                if candidate.is_file() || candidate.is_symlink() {
                    anchors.push(anchor_from_path(candidate, "PATH"));
                }
            }
        }
    }

    if let Some(home) = env::var_os("CODEX_HOME") {
        anchors.push(anchor_from_path(PathBuf::from(home), "CODEX_HOME"));
    }

    anchors
}

fn anchor_from_path(path: PathBuf, found_by: &str) -> CodexAnchor {
    let real = fs::canonicalize(&path).ok();
    let guess_path = real.as_deref().unwrap_or(&path);
    let guess = infer_installation(guess_path);
    CodexAnchor {
        discovered_path: display_path(&path),
        resolved_realpath: real.as_deref().map(display_path),
        found_by: found_by.to_owned(),
        installation_root: guess.as_ref().map(|value| value.root.clone()),
        installation_layout: guess.as_ref().map(|value| value.layout.clone()),
        installation_evidence: guess.map(|value| value.evidence).unwrap_or_default(),
    }
}

fn codex_binary_names() -> &'static [&'static str] {
    #[cfg(windows)]
    {
        &["codex.exe", "codex.cmd", "codex.bat"]
    }
    #[cfg(not(windows))]
    {
        &["codex"]
    }
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

    while let Some(directory) = stack.pop() {
        if excluded.contains(&directory) {
            continue;
        }

        let metadata = match fs::symlink_metadata(&directory) {
            Ok(value) => value,
            Err(error) => {
                push_blocked(state, &directory, "metadata", &error);
                continue;
            }
        };

        if !metadata.is_dir() {
            process_entry(&directory, metadata, state);
            continue;
        }

        let id = file_identity(&directory, &metadata);
        if !state.visited_dirs.insert(id) {
            continue;
        }
        state.directories_seen += 1;

        let entries = match fs::read_dir(&directory) {
            Ok(value) => value,
            Err(error) => {
                push_blocked(state, &directory, "read_dir", &error);
                continue;
            }
        };

        let mut children = Vec::new();
        for entry in entries {
            match entry {
                Ok(value) => children.push(value.path()),
                Err(error) => push_blocked(state, &directory, "read_dir_entry", &error),
            }
        }
        children.sort();
        children.reverse();

        for child in children {
            let metadata = match fs::symlink_metadata(&child) {
                Ok(value) => value,
                Err(error) => {
                    push_blocked(state, &child, "metadata", &error);
                    continue;
                }
            };

            if metadata.file_type().is_symlink() {
                state.symlinks_seen += 1;
                process_symlink(&child, state);
            } else if metadata.is_dir() {
                stack.push(child);
            } else {
                process_entry(&child, metadata, state);
            }
        }
    }
}

fn process_symlink(path: &Path, state: &mut ScanState) {
    let real = match fs::canonicalize(path) {
        Ok(value) => value,
        Err(error) => {
            push_blocked(state, path, "canonicalize_symlink", &error);
            return;
        }
    };

    let target_metadata = match fs::metadata(path) {
        Ok(value) => value,
        Err(error) => {
            push_blocked(state, path, "metadata_symlink_target", &error);
            return;
        }
    };

    if target_metadata.is_file() {
        process_regular_file(path, &real, &target_metadata, state);
    }
}

fn process_entry(path: &Path, metadata: Metadata, state: &mut ScanState) {
    if metadata.is_file() {
        process_regular_file(path, path, &metadata, state);
    }
}

fn process_regular_file(
    discovered: &Path,
    real_hint: &Path,
    metadata: &Metadata,
    state: &mut ScanState,
) {
    state.files_seen += 1;

    let signatures = match scan_signatures(discovered) {
        Ok(value) => value,
        Err(error) => {
            push_blocked(state, discovered, "content_scan", &error);
            Vec::new()
        }
    };

    let path_lower = discovered.to_string_lossy().to_ascii_lowercase();
    let real = fs::canonicalize(discovered).unwrap_or_else(|_| real_hint.to_path_buf());
    let real_lower = real.to_string_lossy().to_ascii_lowercase();

    let path_codex = path_lower.contains("codex") || real_lower.contains("codex");
    let path_schema = path_has_schema_signal(&path_lower) || path_has_schema_signal(&real_lower);
    let content_codex = signatures
        .iter()
        .any(|signature| is_codex_signature(signature));
    let content_schema = signatures
        .iter()
        .any(|signature| is_schema_signature(signature));

    let classification = if (path_codex && (path_schema || content_schema))
        || (content_codex && content_schema)
    {
        Some("confirmed_codex_schema")
    } else if content_codex || path_codex {
        Some("codex_anchor_or_related")
    } else {
        None
    };

    let Some(classification) = classification else {
        return;
    };

    let mut reasons = Vec::new();
    if path_codex {
        reasons.push("path_contains_codex".into());
    }
    if path_schema {
        reasons.push("path_contains_schema_or_protocol_signal".into());
    }
    if content_codex {
        reasons.push("content_contains_codex_signature".into());
    }
    if content_schema {
        reasons.push("content_contains_schema_or_protocol_signature".into());
    }

    let sha256 = match sha256_file(discovered) {
        Ok(value) => value,
        Err(error) => {
            push_blocked(state, discovered, "sha256", &error);
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
        modified_unix_seconds: metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs()),
        sha256,
        device,
        inode,
        duplicate_of: None,
        installation_root: None,
        installation_layout: None,
        installation_evidence: Vec::new(),
        references: Vec::new(),
        referenced_by: Vec::new(),
    });
}

fn correlate_installations(anchors: &mut [CodexAnchor], hits: &mut [ScanHit]) {
    for anchor in anchors.iter_mut() {
        let path = anchor
            .resolved_realpath
            .as_deref()
            .unwrap_or(&anchor.discovered_path);
        if let Some(guess) = infer_installation(Path::new(path)) {
            anchor.installation_root = Some(guess.root);
            anchor.installation_layout = Some(guess.layout);
            anchor.installation_evidence = guess.evidence;
        }
    }

    for hit in hits.iter_mut() {
        if let Some(guess) = infer_installation(Path::new(&hit.resolved_realpath)) {
            hit.installation_root = Some(guess.root);
            hit.installation_layout = Some(guess.layout);
            hit.installation_evidence = guess.evidence;
        }
    }

    let anchor_roots: Vec<(String, String)> = anchors
        .iter()
        .filter_map(|anchor| {
            let root = anchor.installation_root.clone()?;
            let layout = anchor
                .installation_layout
                .clone()
                .unwrap_or_else(|| "unknown".into());
            Some((root, layout))
        })
        .collect();

    for hit in hits
        .iter_mut()
        .filter(|hit| hit.installation_root.is_none())
    {
        let hit_path = Path::new(&hit.resolved_realpath);
        if let Some((root, layout)) = anchor_roots
            .iter()
            .filter(|(root, _)| hit_path.starts_with(Path::new(root)))
            .max_by_key(|(root, _)| Path::new(root).components().count())
        {
            hit.installation_root = Some(root.clone());
            hit.installation_layout = Some(layout.clone());
            hit.installation_evidence
                .push("matched_discovered_codex_anchor_tree".into());
        }
    }
}

fn infer_installation(path: &Path) -> Option<InstallationGuess> {
    let components: Vec<OsString> = path
        .components()
        .map(|component| component.as_os_str().to_os_string())
        .collect();
    let lowered: Vec<String> = components
        .iter()
        .map(|component| component.to_string_lossy().to_ascii_lowercase())
        .collect();

    if let Some(index) = lowered
        .iter()
        .position(|component| component == "node_modules")
    {
        let mut package_end = index.saturating_add(1);
        if lowered
            .get(package_end)
            .is_some_and(|component| component.starts_with('@'))
        {
            package_end = package_end.saturating_add(1);
        }
        if package_end < components.len() {
            let layout = if lowered.iter().any(|component| component == ".pnpm") {
                "pnpm_node_modules"
            } else if lowered.iter().any(|component| component == ".yarn") {
                "yarn_node_modules"
            } else {
                "npm_node_modules"
            };
            return Some(InstallationGuess {
                root: display_path(&path_through_component(&components, package_end)),
                layout: layout.into(),
                evidence: vec![format!("path_component:node_modules[{index}]")],
            });
        }
    }

    if let Some(index) = lowered.iter().position(|component| component == "cellar") {
        if lowered
            .get(index + 1)
            .is_some_and(|component| component.contains("codex"))
        {
            let end = (index + 2).min(components.len().saturating_sub(1));
            return Some(InstallationGuess {
                root: display_path(&path_through_component(&components, end)),
                layout: "homebrew_cellar".into(),
                evidence: vec!["path_component:Cellar/codex".into()],
            });
        }
    }

    if lowered
        .windows(2)
        .any(|pair| pair[0] == ".cargo" && pair[1] == "bin")
    {
        if let Some(index) = lowered.iter().position(|component| component == ".cargo") {
            return Some(InstallationGuess {
                root: display_path(&path_through_component(&components, index)),
                layout: "cargo_home".into(),
                evidence: vec!["path_component:.cargo/bin".into()],
            });
        }
    }

    if let Some(index) = lowered.iter().position(|component| component == "snap") {
        if lowered
            .get(index + 1)
            .is_some_and(|component| component.contains("codex"))
        {
            return Some(InstallationGuess {
                root: display_path(&path_through_component(&components, index + 1)),
                layout: "snap".into(),
                evidence: vec!["path_component:snap/codex".into()],
            });
        }
    }

    if let Some((root, layout, evidence)) = nearest_manifest_root(path) {
        return Some(InstallationGuess {
            root: display_path(&root),
            layout,
            evidence,
        });
    }

    if let Some(index) = lowered
        .iter()
        .position(|component| component.contains("codex") && !looks_like_file_name(component))
    {
        return Some(InstallationGuess {
            root: display_path(&path_through_component(&components, index)),
            layout: "codex_named_tree".into(),
            evidence: vec![format!("codex_named_path_component:{}", lowered[index])],
        });
    }

    let file_name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if codex_binary_names()
        .iter()
        .any(|name| file_name == name.to_ascii_lowercase())
    {
        if let Some(parent) = path.parent() {
            return Some(InstallationGuess {
                root: display_path(parent),
                layout: "codex_binary_directory".into(),
                evidence: vec!["codex_binary_filename".into()],
            });
        }
    }

    path.parent().map(|parent| InstallationGuess {
        root: display_path(parent),
        layout: "content_detected_tree".into(),
        evidence: vec!["fallback_parent_of_content_detected_codex_file".into()],
    })
}

fn nearest_manifest_root(path: &Path) -> Option<(PathBuf, String, Vec<String>)> {
    let start = if path.is_dir() { path } else { path.parent()? };
    for ancestor in start.ancestors() {
        if ancestor.join("package.json").is_file() {
            return Some((
                ancestor.to_path_buf(),
                "node_package_tree".into(),
                vec!["manifest:package.json".into()],
            ));
        }

        if ancestor.join("Cargo.toml").is_file() {
            return Some((
                ancestor.to_path_buf(),
                "cargo_project_tree".into(),
                vec!["manifest:Cargo.toml".into()],
            ));
        }

        if ancestor.join("pyproject.toml").is_file() {
            return Some((
                ancestor.to_path_buf(),
                "python_project_tree".into(),
                vec!["manifest:pyproject.toml".into()],
            ));
        }

        if ancestor.join(".git").is_dir() {
            return Some((
                ancestor.to_path_buf(),
                "git_source_tree".into(),
                vec!["marker:.git".into()],
            ));
        }
    }
    None
}

fn path_through_component(components: &[OsString], end_inclusive: usize) -> PathBuf {
    let mut result = PathBuf::new();
    for component in components.iter().take(end_inclusive.saturating_add(1)) {
        result.push(component);
    }
    result
}

fn looks_like_file_name(component: &str) -> bool {
    [
        ".rs", ".ts", ".js", ".json", ".toml", ".yaml", ".yml", ".md", ".exe", ".cmd",
        ".bat",
    ]
    .iter()
    .any(|suffix| component.ends_with(suffix))
}

fn discover_relations(hits: &[ScanHit], blocked: &mut Vec<BlockedPath>) -> Vec<FileRelation> {
    let mut targets: Vec<(String, String, String, Option<String>)> = Vec::new();
    let mut seen_targets = HashSet::new();

    for hit in hits {
        let path = Path::new(&hit.resolved_realpath);
        let Some(file_name) = path
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
        else {
            continue;
        };
        let token = file_name.to_ascii_lowercase();
        let identity = (token.clone(), hit.resolved_realpath.clone());
        if relation_worthy_filename(&token) && seen_targets.insert(identity) {
            targets.push((
                token,
                hit.discovered_path.clone(),
                hit.resolved_realpath.clone(),
                hit.installation_root.clone(),
            ));
        }
    }

    let mut relations = Vec::new();
    let mut seen_relations = HashSet::new();

    for source in hits {
        let source_path = Path::new(&source.discovered_path);
        let candidates: Vec<(&[u8], &str, &str)> = targets
            .iter()
            .filter(|(token, target_path, target_realpath, target_root)| {
                if target_path == &source.discovered_path
                    || target_realpath == &source.resolved_realpath
                {
                    return false;
                }

                let global_matches = targets
                    .iter()
                    .filter(|(other_token, other_path, other_realpath, _)| {
                        other_token == token
                            && other_path != &source.discovered_path
                            && other_realpath != &source.resolved_realpath
                    })
                    .count();
                if global_matches == 1 {
                    return true;
                }

                let Some(source_root) = source.installation_root.as_deref() else {
                    return false;
                };
                if target_root.as_deref() != Some(source_root) {
                    return false;
                }

                targets
                    .iter()
                    .filter(|(other_token, other_path, other_realpath, other_root)| {
                        other_token == token
                            && other_path != &source.discovered_path
                            && other_realpath != &source.resolved_realpath
                            && other_root.as_deref() == Some(source_root)
                    })
                    .count()
                    == 1
            })
            .map(|(token, target_path, _, _)| {
                (token.as_bytes(), token.as_str(), target_path.as_str())
            })
            .collect();

        if !candidates.is_empty() {
            match find_tokens_in_file(source_path, &candidates) {
                Ok(found) => {
                    for (token, target_path) in found {
                        let key = (
                            source.discovered_path.clone(),
                            target_path.clone(),
                            "direct_text_reference",
                        );
                        if seen_relations.insert(key) {
                            relations.push(FileRelation {
                                from_path: source.discovered_path.clone(),
                                to_path: target_path,
                                relation: "direct_text_reference".into(),
                                evidence: format!(
                                    "source bytes contain unambiguous target filename: {token}"
                                ),
                            });
                        }
                    }
                }
                Err(error) => blocked.push(BlockedPath {
                    path: source.discovered_path.clone(),
                    operation: "relation_content_scan".into(),
                    error_kind: format!("{:?}", error.kind()),
                    error: error.to_string(),
                }),
            }
        }
    }

    for hit in hits {
        if let Some(duplicate) = &hit.duplicate_of {
            let key = (
                hit.discovered_path.clone(),
                duplicate.clone(),
                "same_content",
            );
            if seen_relations.insert(key) {
                relations.push(FileRelation {
                    from_path: hit.discovered_path.clone(),
                    to_path: duplicate.clone(),
                    relation: "same_content".into(),
                    evidence: format!("same SHA-256 and size: {}", hit.sha256),
                });
            }
        }
    }

    relations.sort_by(|left, right| {
        left.from_path
            .cmp(&right.from_path)
            .then(left.to_path.cmp(&right.to_path))
            .then(left.relation.cmp(&right.relation))
    });
    relations
}

fn relation_worthy_filename(file_name: &str) -> bool {
    file_name.len() >= 6
        && [
            "schema",
            "protocol",
            "types",
            "openapi",
            "config",
            "rpc",
            "app-server",
            "app_server",
            "exec-server",
            "exec_server",
            "codex",
        ]
        .iter()
        .any(|needle| file_name.contains(needle))
}

fn find_tokens_in_file(
    path: &Path,
    candidates: &[(&[u8], &str, &str)],
) -> io::Result<Vec<(String, String)>> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0_u8; READ_CHUNK];
    let mut carry = Vec::<u8>::new();
    let mut found = HashSet::<(String, String)>::new();

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }

        let mut window = Vec::with_capacity(carry.len() + count);
        window.extend_from_slice(&carry);
        window.extend_from_slice(&buffer[..count]);
        window.make_ascii_lowercase();

        for (needle, label, target_path) in candidates {
            if contains_bytes(&window, needle) {
                found.insert(((*label).to_owned(), (*target_path).to_owned()));
            }
        }

        let keep = window.len().min(OVERLAP);
        carry.clear();
        carry.extend_from_slice(&window[window.len() - keep..]);
    }

    let mut result: Vec<(String, String)> = found.into_iter().collect();
    result.sort();
    Ok(result)
}

fn apply_relations(relations: &[FileRelation], hits: &mut [ScanHit]) {
    let index: HashMap<String, usize> = hits
        .iter()
        .enumerate()
        .map(|(position, hit)| (hit.discovered_path.clone(), position))
        .collect();

    for relation in relations
        .iter()
        .filter(|relation| relation.relation == "direct_text_reference")
    {
        if let Some(position) = index.get(&relation.from_path) {
            hits[*position].references.push(relation.to_path.clone());
        }
        if let Some(position) = index.get(&relation.to_path) {
            hits[*position]
                .referenced_by
                .push(relation.from_path.clone());
        }
    }

    for hit in hits {
        hit.references.sort();
        hit.references.dedup();
        hit.referenced_by.sort();
        hit.referenced_by.dedup();
    }
}

fn build_installation_groups(
    anchors: &[CodexAnchor],
    hits: &[ScanHit],
    relations: &[FileRelation],
) -> Vec<InstallationGroup> {
    let mut builders: BTreeMap<String, InstallationBuilder> = BTreeMap::new();

    for anchor in anchors {
        let Some(root) = &anchor.installation_root else {
            continue;
        };
        let builder = builders.entry(root.clone()).or_default();
        if builder.layout.is_empty() {
            builder.layout = anchor
                .installation_layout
                .clone()
                .unwrap_or_else(|| "unknown".into());
        }
        builder.evidence.extend(anchor.installation_evidence.clone());
        builder.anchors.push(anchor.discovered_path.clone());
    }

    for hit in hits {
        let Some(root) = &hit.installation_root else {
            continue;
        };
        let builder = builders.entry(root.clone()).or_default();
        if builder.layout.is_empty() {
            builder.layout = hit
                .installation_layout
                .clone()
                .unwrap_or_else(|| "unknown".into());
        }
        builder.evidence.extend(hit.installation_evidence.clone());
        builder.files.push(hit.discovered_path.clone());
        match hit.classification.as_str() {
            "confirmed_codex_schema" => builder.confirmed_schema_files += 1,
            _ => builder.related_files += 1,
        }
    }

    let mut groups = Vec::new();
    for (root, mut builder) in builders {
        builder.evidence.sort();
        builder.evidence.dedup();
        builder.anchors.sort();
        builder.anchors.dedup();
        builder.files.sort();
        builder.files.dedup();

        let file_set: HashSet<&str> = builder.files.iter().map(String::as_str).collect();
        let relation_count = relations
            .iter()
            .filter(|relation| {
                file_set.contains(relation.from_path.as_str())
                    && file_set.contains(relation.to_path.as_str())
            })
            .count() as u64;

        groups.push(InstallationGroup {
            root,
            layout: if builder.layout.is_empty() {
                "unknown".into()
            } else {
                builder.layout
            },
            evidence: builder.evidence,
            anchors: builder.anchors,
            files: builder.files,
            confirmed_schema_files: builder.confirmed_schema_files,
            related_files: builder.related_files,
            relation_count,
        });
    }

    groups.sort_by(|left, right| left.root.cmp(&right.root));
    groups
}

fn path_has_schema_signal(path: &str) -> bool {
    [
        "config-schema",
        "schema",
        "protocol",
        "rpc",
        "app-server",
        "app_server",
        "exec-server",
        "exec_server",
        "generated",
        "types.rs",
        "types.ts",
        "openapi",
    ]
    .iter()
    .any(|needle| path.contains(needle))
}

fn is_codex_signature(signature: &str) -> bool {
    matches!(
        signature,
        "codex"
            | "codex_app_server"
            | "codex-app-server"
            | "codex exec-server"
            | "backend-api/codex"
    )
}

fn is_schema_signature(signature: &str) -> bool {
    matches!(
        signature,
        "json schema"
            | "$schema"
            | "$defs"
            | "properties"
            | "schemars"
            | "zod"
            | "rpc"
            | "protocol"
            | "request"
            | "response"
            | "notification"
    )
}

fn scan_signatures(path: &Path) -> io::Result<Vec<String>> {
    let mut file = File::open(path)?;
    let mut found = vec![false; SIGNATURES.len()];
    let mut carry = Vec::<u8>::new();
    let mut buffer = vec![0_u8; READ_CHUNK];

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }

        let mut window = Vec::with_capacity(carry.len() + count);
        window.extend_from_slice(&carry);
        window.extend_from_slice(&buffer[..count]);
        window.make_ascii_lowercase();

        for (index, (_, needle)) in SIGNATURES.iter().enumerate() {
            if !found[index] && contains_bytes(&window, needle.as_bytes()) {
                found[index] = true;
            }
        }

        if found.iter().all(|value| *value) {
            break;
        }
        let keep = window.len().min(OVERLAP);
        carry.clear();
        carry.extend_from_slice(&window[window.len() - keep..]);
    }

    Ok(SIGNATURES
        .iter()
        .enumerate()
        .filter_map(|(index, (label, _))| found[index].then(|| (*label).to_owned()))
        .collect())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; READ_CHUNK];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn mark_duplicates(hits: &mut [ScanHit]) {
    let mut first_by_hash: HashMap<(String, u64), String> = HashMap::new();
    for hit in hits {
        if hit.sha256.is_empty() {
            continue;
        }
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

fn file_identity(_path: &Path, metadata: &Metadata) -> FileIdentity {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        FileIdentity::Unix(metadata.dev(), metadata.ino())
    }
    #[cfg(not(unix))]
    {
        FileIdentity::Path(fs::canonicalize(_path).unwrap_or_else(|_| _path.to_path_buf()))
    }
}

fn metadata_device_inode(metadata: &Metadata) -> (Option<u64>, Option<u64>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (Some(metadata.dev()), Some(metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        (None, None)
    }
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

    #[test]
    fn relation_filename_filter_rejects_generic_sources() {
        assert!(relation_worthy_filename("config-schema.json"));
        assert!(relation_worthy_filename("protocol.rs"));
        assert!(!relation_worthy_filename("main.rs"));
    }

    #[test]
    fn node_modules_layout_is_correlated_to_package_root() {
        let path = Path::new("/opt/node_modules/@openai/codex/dist/protocol.js");
        let guess = infer_installation(path).expect("installation must be inferred");
        assert_eq!(guess.layout, "npm_node_modules");
        assert!(guess.root.ends_with("node_modules/@openai/codex"));
    }
}
