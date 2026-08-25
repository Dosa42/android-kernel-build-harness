#[path = "scanner_m2/app_server_probe.rs"]
mod app_server_probe;
#[path = "scanner_m2/phase2.rs"]
mod phase2;
#[path = "scanner_m2/phase3_v2.rs"]
mod phase3;
#[path = "scanner_m2/schema_check.rs"]
mod schema_check;

use serde::Serialize;
use std::collections::{BTreeSet, HashSet, VecDeque};
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

type DirectoryId = (u64, u64);

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Phase1Result {
    pub roots: BTreeSet<PathBuf>,
    pub stats: Phase1Stats,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct Phase1Stats {
    pub passes_completed: usize,
    pub directory_paths_examined: u64,
    pub directories_enumerated: u64,
    pub directory_entries_seen: u64,
    pub directory_candidates_seen: u64,
    pub symlink_candidates_seen: u64,
    pub symlink_directories_followed: u64,
    pub cycle_edges_stopped: u64,
    pub duplicate_paths_stopped: u64,
    pub transient_disappearances: u64,
    pub io_retries: u64,
}

#[derive(Debug, Clone, Default)]
struct PassStats {
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

impl Phase1Stats {
    fn absorb(&mut self, pass: &PassStats) {
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

#[derive(Clone)]
struct WorkItem {
    path: PathBuf,
    ancestors: Arc<Vec<DirectoryId>>,
}

/// Runs Milestone 2 as a strict three-phase wizard.
///
/// Phase 1 discovers Codex/.codex directories across Linux.
/// Phase 2 inventories protocol-relevant file candidates and patterns.
/// Phase 3 verifies them against the official protocol and the installed
/// Codex App Server's read-only runtime state.
pub fn run_preflight_wizard<F>(mut progress: F) -> Result<String, String>
where
    F: FnMut(String),
{
    progress("Pre-flight 1/3 — exhaustive Linux Codex/.codex directory discovery…".into());
    let phase1 = discover_codex_directories()?;
    progress(format!(
        "Pre-flight 1/3 complete — {} Codex directory path(s) discovered; handing candidates to Phase 2…",
        phase1.roots.len()
    ));

    progress("Pre-flight 2/3 — protocol-complete filename and pattern discovery…".into());
    let phase2 = phase2::discover_candidates(&phase1.roots)?;
    progress(format!(
        "Pre-flight 2/3 complete — {} candidate file path(s) inventoried from {} scan root(s).",
        phase2.candidates.len(),
        phase2.scan_roots.len()
    ));

    progress("Pre-flight 3/3 — App Server-backed protocol, syntax and effective-state verification…".into());
    let phase3 = phase3::verify(&phase1, &phase2)?;
    progress(format!(
        "Pre-flight 3/3 complete — {} verdict(s), App Server available={}, {} cross-check diagnostic(s).",
        phase3.verdicts.len(),
        phase3.app_server.available,
        phase3.runtime_diagnostics.len()
    ));

    Ok(render_report(&phase1, &phase2, &phase3))
}

fn discover_codex_directories() -> Result<Phase1Result, String> {
    preflight_root()?;
    let mut roots = BTreeSet::<PathBuf>::new();
    let mut totals = Phase1Stats::default();

    for _ in 0..FULL_PASSES {
        let pass = scan_full_pass(&mut roots)?;
        totals.absorb(&pass);
    }

    Ok(Phase1Result { roots, stats: totals })
}

fn preflight_root() -> Result<(), String> {
    let root = Path::new(SCAN_ROOT);
    let metadata = fs::metadata(root).map_err(|error| hard_error("read metadata for", root, &error))?;
    if !metadata.is_dir() {
        return Err(format!("SCAN_FAILED: {SCAN_ROOT} is not a directory"));
    }
    fs::read_dir(root).map_err(|error| hard_error("enumerate", root, &error))?;
    Ok(())
}

fn scan_full_pass(found: &mut BTreeSet<PathBuf>) -> Result<PassStats, String> {
    let mut stats = PassStats::default();
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

        let Some((metadata, through_symlink)) = resolve_directory(&item.path, &mut stats)? else {
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
        let Some(children) = snapshot_directory(&item.path, &mut stats)? else {
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

fn resolve_directory(path: &Path, stats: &mut PassStats) -> Result<Option<(Metadata, bool)>, String> {
    let Some(link_meta) = metadata_with_retry(path, false, stats)? else {
        return Ok(None);
    };
    if link_meta.file_type().is_dir() {
        return Ok(Some((link_meta, false)));
    }
    if !link_meta.file_type().is_symlink() {
        return Ok(None);
    }

    stats.symlink_candidates_seen += 1;
    match metadata_with_retry(path, true, stats)? {
        Some(target) if target.is_dir() => Ok(Some((target, true))),
        Some(_) | None => Ok(None),
    }
}

fn metadata_with_retry(
    path: &Path,
    follow_symlink: bool,
    stats: &mut PassStats,
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
                return Err(hard_error(operation, path, &error));
            }
        }
    }
    unreachable!("metadata retry loop always returns")
}

fn snapshot_directory(path: &Path, stats: &mut PassStats) -> Result<Option<Vec<PathBuf>>, String> {
    for attempt in 0..IO_ATTEMPTS {
        match snapshot_once(path, stats) {
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
            Err(error) => return Err(hard_error("enumerate directory", path, &error)),
        }
    }
    unreachable!("directory retry loop always returns")
}

fn snapshot_once(path: &Path, stats: &mut PassStats) -> io::Result<Vec<PathBuf>> {
    let mut children = Vec::<PathBuf>::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
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

fn extend_lineage(ancestors: &Arc<Vec<DirectoryId>>, id: DirectoryId) -> Arc<Vec<DirectoryId>> {
    let mut lineage = Vec::with_capacity(ancestors.len() + 1);
    lineage.extend_from_slice(ancestors.as_slice());
    lineage.push(id);
    Arc::new(lineage)
}

fn directory_id(metadata: &Metadata) -> DirectoryId {
    (metadata.dev(), metadata.ino())
}

fn is_codex_directory(path: &Path) -> bool {
    path.file_name().is_some_and(is_codex_name)
}

fn is_codex_name(name: &OsStr) -> bool {
    let bytes = name.as_bytes();
    bytes == b".codex" || ascii_eq_ignore_case(bytes, b"codex")
}

pub(crate) fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
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

fn hard_error(operation: &str, path: &Path, error: &io::Error) -> String {
    format!(
        "SCAN_FAILED: cannot {operation} {}: {error}. A valid Milestone 2 scan requires complete Linux filesystem access.",
        path.display()
    )
}

fn render_report(
    phase1: &Phase1Result,
    phase2: &phase2::Phase2Result,
    phase3: &phase3::Phase3Result,
) -> String {
    let mut output = String::new();
    output.push_str("CODEX MILESTONE 2 PREFLIGHT WIZARD\n");
    output.push_str("==================================\n\n");
    output.push_str(
        &serde_json::to_string_pretty(&serde_json::json!({
            "phase1": phase1,
            "phase2": phase2,
            "phase3": phase3,
        }))
        .unwrap_or_else(|error| format!("{{\"report_error\":\"{}\"}}", error)),
    );
    output.push('\n');
    output
}

#[cfg(test)]
mod tests {
    use super::{ascii_eq_ignore_case, is_codex_directory};
    use std::path::Path;

    #[test]
    fn phase1_matches_only_codex_directory_names() {
        assert!(is_codex_directory(Path::new("/home/user/.codex")));
        assert!(is_codex_directory(Path::new("/opt/Codex")));
        assert!(is_codex_directory(Path::new("/opt/cOdEx")));
        assert!(!is_codex_directory(Path::new("/opt/.Codex")));
        assert!(!is_codex_directory(Path::new("/opt/codex-cli")));
    }

    #[test]
    fn ascii_comparison_is_case_insensitive_without_unicode_conversion() {
        assert!(ascii_eq_ignore_case(b"CODEX", b"codex"));
        assert!(!ascii_eq_ignore_case(b"codex2", b"codex"));
    }
}
