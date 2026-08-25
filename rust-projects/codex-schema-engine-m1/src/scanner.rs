use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::ffi::OsStr;
use std::fs::{self, Metadata};
use std::io::{self, ErrorKind};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const SCAN_ROOT: &str = "/";
const FULL_PASSES: usize = 3;
const IO_ATTEMPTS: usize = 5;
const RETRY_DELAY_MS: u64 = 12;

// Concrete filenames only. These are the well-known names discussed for the
// Codex/config surface. Config keys such as developer_instructions,
// model_instructions_file, config_file, permissions and path are deliberately
// not treated as filenames.
const IMPORTANT_FILE_NAMES: &[&[u8]] = &[
    b"config.toml",
    b"AGENTS.md",
    b"AGENTS.override.md",
    b"SKILL.md",
    b"hooks.json",
    b"auth.json",
    b".credentials.json",
    b"history.jsonl",
    b"pet.json",
    b"config-schema.json",
];

type DirectoryId = (u64, u64);

#[derive(Clone)]
struct WorkItem {
    path: PathBuf,
    ancestors: Arc<Vec<DirectoryId>>,
}

#[derive(Default)]
struct DirectoryPassStats {
    directory_paths_examined: u64,
    directories_enumerated: u64,
    directory_entries_seen: u64,
    directory_candidates_seen: u64,
    symlink_candidates_seen: u64,
    symlink_directories_followed: u64,
    cycle_edges_stopped: u64,
    duplicate_paths_stopped: u64,
    transient_disappearances: u64,
    io_retries: u64,
}

#[derive(Default)]
struct DirectoryScanStats {
    passes_completed: usize,
    directory_paths_examined: u64,
    directories_enumerated: u64,
    directory_entries_seen: u64,
    directory_candidates_seen: u64,
    symlink_candidates_seen: u64,
    symlink_directories_followed: u64,
    cycle_edges_stopped: u64,
    duplicate_paths_stopped: u64,
    transient_disappearances: u64,
    io_retries: u64,
}

impl DirectoryScanStats {
    fn absorb(&mut self, pass: &DirectoryPassStats) {
        self.passes_completed += 1;
        self.directory_paths_examined += pass.directory_paths_examined;
        self.directories_enumerated += pass.directories_enumerated;
        self.directory_entries_seen += pass.directory_entries_seen;
        self.directory_candidates_seen += pass.directory_candidates_seen;
        self.symlink_candidates_seen += pass.symlink_candidates_seen;
        self.symlink_directories_followed += pass.symlink_directories_followed;
        self.cycle_edges_stopped += pass.cycle_edges_stopped;
        self.duplicate_paths_stopped += pass.duplicate_paths_stopped;
        self.transient_disappearances += pass.transient_disappearances;
        self.io_retries += pass.io_retries;
    }
}

#[derive(Default)]
struct FileScanStats {
    codex_roots_received: u64,
    codex_roots_scanned: u64,
    directory_paths_examined: u64,
    directories_enumerated: u64,
    directory_entries_seen: u64,
    regular_files_seen: u64,
    file_symlinks_seen: u64,
    directory_symlinks_followed: u64,
    cycle_edges_stopped: u64,
    duplicate_paths_stopped: u64,
    transient_disappearances: u64,
    io_retries: u64,
}

#[derive(Default)]
struct FileHit {
    canonical_name: String,
    roots: BTreeSet<PathBuf>,
}

pub fn run_preflight_wizard<F>(mut progress: F) -> Result<String, String>
where
    F: FnMut(String),
{
    progress("Pre-flight 1/2 — scanning entire Linux filesystem for Codex directories…".into());
    let (codex_directories, directory_stats) = discover_codex_directories()?;

    progress(format!(
        "Pre-flight 1/2 complete — {} Codex director{} found. Verifying hand-off to file discovery…",
        codex_directories.len(),
        if codex_directories.len() == 1 { "y" } else { "ies" }
    ));

    verify_phase_one_handoff(&codex_directories)?;

    progress(format!(
        "Pre-flight 2/2 — searching {} verified Codex director{} for {} important filenames…",
        codex_directories.len(),
        if codex_directories.len() == 1 { "y" } else { "ies" },
        IMPORTANT_FILE_NAMES.len()
    ));

    let (file_hits, file_stats) = discover_important_files(&codex_directories)?;

    progress(format!(
        "Pre-flight 2/2 complete — {} matching file path{} found.",
        file_hits.len(),
        if file_hits.len() == 1 { "" } else { "s" }
    ));

    Ok(render_wizard_report(
        &codex_directories,
        &directory_stats,
        &file_hits,
        &file_stats,
    ))
}

pub fn scan_codex_directories() -> Result<String, String> {
    let (found, stats) = discover_codex_directories()?;
    Ok(render_directory_only_report(&found, &stats))
}

fn discover_codex_directories() -> Result<(BTreeSet<PathBuf>, DirectoryScanStats), String> {
    preflight_root()?;

    let mut found = BTreeSet::<PathBuf>::new();
    let mut totals = DirectoryScanStats::default();

    // Multiple complete passes are intentional. Linux directory trees can change
    // while a scan is running; repeating the whole traversal reduces the chance
    // that a short-lived rename/mount transition hides a persistent Codex folder.
    for _ in 0..FULL_PASSES {
        let pass = scan_one_full_directory_pass(&mut found)?;
        totals.absorb(&pass);
    }

    Ok((found, totals))
}

fn preflight_root() -> Result<(), String> {
    let root = Path::new(SCAN_ROOT);
    let metadata = fs::metadata(root).map_err(|error| hard_access_error("metadata", root, &error))?;

    if !metadata.is_dir() {
        return Err(format!("SCAN_FAILED: {SCAN_ROOT} is not a directory"));
    }

    fs::read_dir(root).map_err(|error| hard_access_error("read directory", root, &error))?;
    Ok(())
}

fn scan_one_full_directory_pass(
    found: &mut BTreeSet<PathBuf>,
) -> Result<DirectoryPassStats, String> {
    let mut stats = DirectoryPassStats::default();
    let mut queue = VecDeque::<WorkItem>::new();
    let mut seen_paths = HashSet::<PathBuf>::new();

    queue.push_back(WorkItem {
        path: PathBuf::from(SCAN_ROOT),
        ancestors: Arc::new(Vec::new()),
    });

    while let Some(item) = queue.pop_front() {
        if !seen_paths.insert(item.path.clone()) {
            stats.duplicate_paths_stopped += 1;
            continue;
        }

        let Some((metadata, through_symlink)) =
            resolve_directory_metadata_phase_one(&item.path, &mut stats)?
        else {
            continue;
        };

        stats.directory_paths_examined += 1;
        if through_symlink {
            stats.symlink_directories_followed += 1;
        }

        if is_codex_directory(&item.path) {
            found.insert(item.path.clone());
        }

        let identity = directory_id(&metadata);
        if item.ancestors.contains(&identity) {
            stats.cycle_edges_stopped += 1;
            continue;
        }

        let lineage = extend_lineage(&item.ancestors, identity);
        let Some(children) = snapshot_directory_phase_one(&item.path, &mut stats)? else {
            continue;
        };

        stats.directories_enumerated += 1;
        for child in children {
            queue.push_back(WorkItem {
                path: child,
                ancestors: Arc::clone(&lineage),
            });
        }
    }

    Ok(stats)
}

fn resolve_directory_metadata_phase_one(
    path: &Path,
    stats: &mut DirectoryPassStats,
) -> Result<Option<(Metadata, bool)>, String> {
    let Some(link_metadata) = metadata_with_retry_directory_stats(path, false, stats)? else {
        return Ok(None);
    };

    if link_metadata.file_type().is_dir() {
        return Ok(Some((link_metadata, false)));
    }

    if !link_metadata.file_type().is_symlink() {
        return Ok(None);
    }

    stats.symlink_candidates_seen += 1;
    match metadata_with_retry_directory_stats(path, true, stats)? {
        Some(target_metadata) if target_metadata.is_dir() => Ok(Some((target_metadata, true))),
        Some(_) | None => Ok(None),
    }
}

fn snapshot_directory_phase_one(
    directory: &Path,
    stats: &mut DirectoryPassStats,
) -> Result<Option<Vec<PathBuf>>, String> {
    for attempt in 0..IO_ATTEMPTS {
        match snapshot_directory_phase_one_once(directory, stats) {
            Ok(children) => return Ok(Some(children)),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                if attempt + 1 < IO_ATTEMPTS {
                    stats.io_retries += 1;
                    retry_pause(attempt);
                    continue;
                }
                stats.transient_disappearances += 1;
                return Ok(None);
            }
            Err(error) if retryable(&error) && attempt + 1 < IO_ATTEMPTS => {
                stats.io_retries += 1;
                retry_pause(attempt);
            }
            Err(error) => return Err(hard_access_error("enumerate directory", directory, &error)),
        }
    }

    unreachable!("directory retry loop always returns")
}

fn snapshot_directory_phase_one_once(
    directory: &Path,
    stats: &mut DirectoryPassStats,
) -> io::Result<Vec<PathBuf>> {
    let entries = fs::read_dir(directory)?;
    let mut children = Vec::<PathBuf>::new();

    // Phase 1 sees directory entries but queues only directories and symlinks.
    // It never opens a regular file.
    for entry_result in entries {
        let entry = entry_result?;
        stats.directory_entries_seen += 1;

        let file_type = entry.file_type()?;
        if file_type.is_dir() || file_type.is_symlink() {
            stats.directory_candidates_seen += 1;
            children.push(entry.path());
        }
    }

    children.sort_unstable();
    Ok(children)
}

fn metadata_with_retry_directory_stats(
    path: &Path,
    follow_symlink: bool,
    stats: &mut DirectoryPassStats,
) -> Result<Option<Metadata>, String> {
    for attempt in 0..IO_ATTEMPTS {
        let result = if follow_symlink {
            fs::metadata(path)
        } else {
            fs::symlink_metadata(path)
        };

        match result {
            Ok(metadata) => return Ok(Some(metadata)),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                if attempt + 1 < IO_ATTEMPTS {
                    stats.io_retries += 1;
                    retry_pause(attempt);
                    continue;
                }
                stats.transient_disappearances += 1;
                return Ok(None);
            }
            Err(error) if retryable(&error) && attempt + 1 < IO_ATTEMPTS => {
                stats.io_retries += 1;
                retry_pause(attempt);
            }
            Err(error) if follow_symlink && is_symlink_loop(&error) => return Ok(None),
            Err(error) => {
                let operation = if follow_symlink {
                    "follow directory symlink"
                } else {
                    "inspect directory candidate"
                };
                return Err(hard_access_error(operation, path, &error));
            }
        }
    }

    unreachable!("metadata retry loop always returns")
}

fn verify_phase_one_handoff(codex_directories: &BTreeSet<PathBuf>) -> Result<(), String> {
    for directory in codex_directories {
        let metadata = fs::metadata(directory).map_err(|error| {
            hard_access_error("verify discovered Codex directory", directory, &error)
        })?;

        if !metadata.is_dir() {
            return Err(format!(
                "PREFLIGHT_FAILED: discovered Codex path is no longer a directory: {}",
                directory.display()
            ));
        }

        fs::read_dir(directory).map_err(|error| {
            hard_access_error("verify access to discovered Codex directory", directory, &error)
        })?;
    }

    Ok(())
}

fn discover_important_files(
    codex_directories: &BTreeSet<PathBuf>,
) -> Result<(BTreeMap<PathBuf, FileHit>, FileScanStats), String> {
    let mut hits = BTreeMap::<PathBuf, FileHit>::new();
    let mut stats = FileScanStats {
        codex_roots_received: codex_directories.len() as u64,
        ..Default::default()
    };

    for codex_root in codex_directories {
        scan_one_codex_tree_for_files(codex_root, &mut hits, &mut stats)?;
        stats.codex_roots_scanned += 1;
    }

    Ok((hits, stats))
}

fn scan_one_codex_tree_for_files(
    codex_root: &Path,
    hits: &mut BTreeMap<PathBuf, FileHit>,
    stats: &mut FileScanStats,
) -> Result<(), String> {
    let mut queue = VecDeque::<WorkItem>::new();
    let mut seen_paths = HashSet::<PathBuf>::new();

    queue.push_back(WorkItem {
        path: codex_root.to_path_buf(),
        ancestors: Arc::new(Vec::new()),
    });

    while let Some(item) = queue.pop_front() {
        if !seen_paths.insert(item.path.clone()) {
            stats.duplicate_paths_stopped += 1;
            continue;
        }

        let Some((metadata, through_symlink)) =
            resolve_directory_metadata_file_phase(&item.path, stats)?
        else {
            continue;
        };

        stats.directory_paths_examined += 1;
        if through_symlink {
            stats.directory_symlinks_followed += 1;
        }

        let identity = directory_id(&metadata);
        if item.ancestors.contains(&identity) {
            stats.cycle_edges_stopped += 1;
            continue;
        }

        let lineage = extend_lineage(&item.ancestors, identity);
        let Some(entries) = snapshot_directory_file_phase(&item.path, stats)? else {
            continue;
        };

        stats.directories_enumerated += 1;

        for entry in entries {
            match entry.kind {
                EntryKind::Directory => queue.push_back(WorkItem {
                    path: entry.path,
                    ancestors: Arc::clone(&lineage),
                }),
                EntryKind::DirectorySymlink => {
                    stats.directory_symlinks_followed += 0;
                    queue.push_back(WorkItem {
                        path: entry.path,
                        ancestors: Arc::clone(&lineage),
                    });
                }
                EntryKind::RegularFile => {
                    stats.regular_files_seen += 1;
                    record_if_important(&entry.path, codex_root, hits);
                }
                EntryKind::FileSymlink => {
                    stats.file_symlinks_seen += 1;
                    record_if_important(&entry.path, codex_root, hits);
                }
            }
        }
    }

    Ok(())
}

#[derive(Clone, Copy)]
enum EntryKind {
    Directory,
    DirectorySymlink,
    RegularFile,
    FileSymlink,
}

struct FilePhaseEntry {
    path: PathBuf,
    kind: EntryKind,
}

fn resolve_directory_metadata_file_phase(
    path: &Path,
    stats: &mut FileScanStats,
) -> Result<Option<(Metadata, bool)>, String> {
    let Some(link_metadata) = metadata_with_retry_file_stats(path, false, stats)? else {
        return Ok(None);
    };

    if link_metadata.file_type().is_dir() {
        return Ok(Some((link_metadata, false)));
    }

    if !link_metadata.file_type().is_symlink() {
        return Ok(None);
    }

    match metadata_with_retry_file_stats(path, true, stats)? {
        Some(target_metadata) if target_metadata.is_dir() => Ok(Some((target_metadata, true))),
        Some(_) | None => Ok(None),
    }
}

fn snapshot_directory_file_phase(
    directory: &Path,
    stats: &mut FileScanStats,
) -> Result<Option<Vec<FilePhaseEntry>>, String> {
    for attempt in 0..IO_ATTEMPTS {
        match snapshot_directory_file_phase_once(directory, stats) {
            Ok(entries) => return Ok(Some(entries)),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                if attempt + 1 < IO_ATTEMPTS {
                    stats.io_retries += 1;
                    retry_pause(attempt);
                    continue;
                }
                stats.transient_disappearances += 1;
                return Ok(None);
            }
            Err(error) if retryable(&error) && attempt + 1 < IO_ATTEMPTS => {
                stats.io_retries += 1;
                retry_pause(attempt);
            }
            Err(error) => return Err(hard_access_error("enumerate Codex tree", directory, &error)),
        }
    }

    unreachable!("file discovery retry loop always returns")
}

fn snapshot_directory_file_phase_once(
    directory: &Path,
    stats: &mut FileScanStats,
) -> io::Result<Vec<FilePhaseEntry>> {
    let entries = fs::read_dir(directory)?;
    let mut output = Vec::<FilePhaseEntry>::new();

    for entry_result in entries {
        let entry = entry_result?;
        stats.directory_entries_seen += 1;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            output.push(FilePhaseEntry {
                path,
                kind: EntryKind::Directory,
            });
            continue;
        }

        if file_type.is_file() {
            output.push(FilePhaseEntry {
                path,
                kind: EntryKind::RegularFile,
            });
            continue;
        }

        if file_type.is_symlink() {
            match fs::metadata(&path) {
                Ok(metadata) if metadata.is_dir() => output.push(FilePhaseEntry {
                    path,
                    kind: EntryKind::DirectorySymlink,
                }),
                Ok(metadata) if metadata.is_file() => output.push(FilePhaseEntry {
                    path,
                    kind: EntryKind::FileSymlink,
                }),
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::NotFound || is_symlink_loop(&error) => {}
                Err(error) => return Err(error),
            }
        }
    }

    output.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    Ok(output)
}

fn metadata_with_retry_file_stats(
    path: &Path,
    follow_symlink: bool,
    stats: &mut FileScanStats,
) -> Result<Option<Metadata>, String> {
    for attempt in 0..IO_ATTEMPTS {
        let result = if follow_symlink {
            fs::metadata(path)
        } else {
            fs::symlink_metadata(path)
        };

        match result {
            Ok(metadata) => return Ok(Some(metadata)),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                if attempt + 1 < IO_ATTEMPTS {
                    stats.io_retries += 1;
                    retry_pause(attempt);
                    continue;
                }
                stats.transient_disappearances += 1;
                return Ok(None);
            }
            Err(error) if retryable(&error) && attempt + 1 < IO_ATTEMPTS => {
                stats.io_retries += 1;
                retry_pause(attempt);
            }
            Err(error) if follow_symlink && is_symlink_loop(&error) => return Ok(None),
            Err(error) => {
                let operation = if follow_symlink {
                    "follow Codex-tree directory symlink"
                } else {
                    "inspect Codex-tree directory"
                };
                return Err(hard_access_error(operation, path, &error));
            }
        }
    }

    unreachable!("metadata retry loop always returns")
}

fn record_if_important(
    path: &Path,
    codex_root: &Path,
    hits: &mut BTreeMap<PathBuf, FileHit>,
) {
    let Some(file_name) = path.file_name() else {
        return;
    };

    let Some(canonical_name) = canonical_important_name(file_name) else {
        return;
    };

    let hit = hits.entry(path.to_path_buf()).or_default();
    if hit.canonical_name.is_empty() {
        hit.canonical_name = canonical_name;
    }
    hit.roots.insert(codex_root.to_path_buf());
}

fn canonical_important_name(name: &OsStr) -> Option<String> {
    let bytes = name.as_bytes();
    IMPORTANT_FILE_NAMES
        .iter()
        .find(|candidate| ascii_eq_ignore_case(bytes, candidate))
        .map(|candidate| String::from_utf8_lossy(candidate).into_owned())
}

fn extend_lineage(ancestors: &Arc<Vec<DirectoryId>>, identity: DirectoryId) -> Arc<Vec<DirectoryId>> {
    let mut lineage = Vec::with_capacity(ancestors.len() + 1);
    lineage.extend_from_slice(ancestors.as_slice());
    lineage.push(identity);
    Arc::new(lineage)
}

fn directory_id(metadata: &Metadata) -> DirectoryId {
    (metadata.dev(), metadata.ino())
}

fn is_codex_directory(path: &Path) -> bool {
    path.file_name().is_some_and(is_requested_codex_name)
}

fn is_requested_codex_name(name: &OsStr) -> bool {
    let bytes = name.as_bytes();
    bytes == b".codex" || ascii_eq_ignore_case(bytes, b"codex")
}

fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left_byte, right_byte)| left_byte.eq_ignore_ascii_case(right_byte))
}

fn retryable(error: &io::Error) -> bool {
    matches!(error.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock)
}

fn is_symlink_loop(error: &io::Error) -> bool {
    error.raw_os_error() == Some(40)
}

fn retry_pause(attempt: usize) {
    let factor = (attempt as u64).saturating_add(1);
    thread::sleep(Duration::from_millis(RETRY_DELAY_MS.saturating_mul(factor)));
}

fn hard_access_error(operation: &str, path: &Path, error: &io::Error) -> String {
    format!(
        "SCAN_FAILED: cannot {operation} {}: {error}. A valid scan requires complete Linux filesystem access.",
        path.display()
    )
}

fn render_wizard_report(
    codex_directories: &BTreeSet<PathBuf>,
    directory_stats: &DirectoryScanStats,
    file_hits: &BTreeMap<PathBuf, FileHit>,
    file_stats: &FileScanStats,
) -> String {
    let mut output = String::new();
    output.push_str("CODEX PREFLIGHT WIZARD\n");
    output.push_str("======================\n\n");

    output.push_str("PHASE 1 — CODEX DIRECTORY DISCOVERY: OK\n");
    output.push_str(&format!("scan_root={}\n", SCAN_ROOT));
    output.push_str(&format!("full_passes={}\n", directory_stats.passes_completed));
    output.push_str(&format!(
        "directory_paths_examined={}\n",
        directory_stats.directory_paths_examined
    ));
    output.push_str(&format!(
        "directories_enumerated={}\n",
        directory_stats.directories_enumerated
    ));
    output.push_str(&format!(
        "directory_entries_seen={}\n",
        directory_stats.directory_entries_seen
    ));
    output.push_str(&format!(
        "codex_directories_found={}\n\n",
        codex_directories.len()
    ));

    output.push_str("FOUND CODEX DIRECTORIES\n");
    if codex_directories.is_empty() {
        output.push_str("none\n");
    } else {
        for directory in codex_directories {
            output.push_str(&directory.to_string_lossy());
            output.push('\n');
        }
    }

    output.push_str("\nPHASE 2 — IMPORTANT FILE DISCOVERY: OK\n");
    output.push_str("filename_targets=\n");
    for name in IMPORTANT_FILE_NAMES {
        output.push_str("  - ");
        output.push_str(&String::from_utf8_lossy(name));
        output.push('\n');
    }
    output.push_str(&format!("codex_roots_received={}\n", file_stats.codex_roots_received));
    output.push_str(&format!("codex_roots_scanned={}\n", file_stats.codex_roots_scanned));
    output.push_str(&format!(
        "directories_enumerated={}\n",
        file_stats.directories_enumerated
    ));
    output.push_str(&format!("regular_files_seen={}\n", file_stats.regular_files_seen));
    output.push_str(&format!("file_symlinks_seen={}\n", file_stats.file_symlinks_seen));
    output.push_str(&format!("matching_files_found={}\n\n", file_hits.len()));

    output.push_str("FOUND IMPORTANT FILES\n");
    if file_hits.is_empty() {
        output.push_str("none\n");
    } else {
        for (path, hit) in file_hits {
            output.push_str(&format!("{}\n", path.to_string_lossy()));
            output.push_str(&format!("  name={}\n", hit.canonical_name));
            output.push_str("  discovered_under=\n");
            for root in &hit.roots {
                output.push_str("    - ");
                output.push_str(&root.to_string_lossy());
                output.push('\n');
            }
        }
    }

    output
}

fn render_directory_only_report(found: &BTreeSet<PathBuf>, stats: &DirectoryScanStats) -> String {
    let mut output = String::new();
    output.push_str("scan_scope=entire_linux_tree_from_/\n");
    output.push_str("regular_file_contents_read=0\n");
    output.push_str("directory_name_filter=.codex_or_codex_case_insensitive\n");
    output.push_str(&format!("full_passes={}\n", stats.passes_completed));
    output.push_str(&format!(
        "directory_paths_examined={}\n",
        stats.directory_paths_examined
    ));
    output.push_str(&format!(
        "directories_enumerated={}\n",
        stats.directories_enumerated
    ));
    output.push_str(&format!("codex_directories_found={}\n", found.len()));
    output.push_str("\nFOUND CODEX DIRECTORIES\n");

    if found.is_empty() {
        output.push_str("none\n");
    } else {
        for path in found {
            output.push_str(&path.to_string_lossy());
            output.push('\n');
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::{ascii_eq_ignore_case, canonical_important_name, is_codex_directory};
    use std::ffi::OsStr;
    use std::path::Path;

    #[test]
    fn matches_only_requested_directory_names() {
        assert!(is_codex_directory(Path::new("/home/user/.codex")));
        assert!(is_codex_directory(Path::new("/opt/Codex")));
        assert!(is_codex_directory(Path::new("/opt/cOdEx")));
        assert!(!is_codex_directory(Path::new("/opt/.Codex")));
        assert!(!is_codex_directory(Path::new("/opt/codex-cli")));
        assert!(!is_codex_directory(Path::new("/opt/codex-schema")));
        assert!(!is_codex_directory(Path::new("/opt/schema")));
    }

    #[test]
    fn important_file_match_is_filename_only() {
        assert_eq!(
            canonical_important_name(OsStr::new("AGENTS.md")).as_deref(),
            Some("AGENTS.md")
        );
        assert_eq!(
            canonical_important_name(OsStr::new("agents.override.md")).as_deref(),
            Some("AGENTS.override.md")
        );
        assert_eq!(
            canonical_important_name(OsStr::new("CONFIG.TOML")).as_deref(),
            Some("config.toml")
        );
        assert!(canonical_important_name(OsStr::new("developer_instructions")).is_none());
        assert!(canonical_important_name(OsStr::new("permissions")).is_none());
    }

    #[test]
    fn ascii_match_does_not_depend_on_unicode_paths() {
        assert!(ascii_eq_ignore_case(b"CODEX", b"codex"));
        assert!(!ascii_eq_ignore_case(b"codex2", b"codex"));
    }
}
