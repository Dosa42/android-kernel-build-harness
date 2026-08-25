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

#[derive(Clone)]
struct WorkItem {
    path: PathBuf,
    ancestors: Arc<Vec<DirectoryId>>,
}

#[derive(Default)]
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

#[derive(Default)]
struct ScanStats {
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

impl ScanStats {
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

pub fn scan_codex_directories() -> Result<String, String> {
    preflight_root()?;

    let mut found = BTreeSet::<PathBuf>::new();
    let mut totals = ScanStats::default();

    // Multiple complete passes are intentional. Linux directory trees can change
    // while a scan is running; repeating the whole traversal reduces the chance
    // that a short-lived rename/mount transition hides a persistent Codex folder.
    for _ in 0..FULL_PASSES {
        let pass = scan_one_full_pass(&mut found)?;
        totals.absorb(&pass);
    }

    Ok(render_report(&found, &totals))
}

fn preflight_root() -> Result<(), String> {
    let root = Path::new(SCAN_ROOT);
    let metadata = fs::metadata(root).map_err(|error| hard_access_error("metadata", root, &error))?;

    if !metadata.is_dir() {
        return Err(format!("SCAN_FAILED: {SCAN_ROOT} is not a directory"));
    }

    // Opening the root directory here is only a permission/access preflight.
    // No regular file is opened or read by this scanner.
    fs::read_dir(root).map_err(|error| hard_access_error("read directory", root, &error))?;
    Ok(())
}

fn scan_one_full_pass(found: &mut BTreeSet<PathBuf>) -> Result<PassStats, String> {
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

        let Some((metadata, through_symlink)) =
            resolve_directory_metadata(&item.path, &mut stats)?
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

        // This is ancestry-based, not a global inode de-duplication. Therefore
        // bind mounts and directory aliases are scanned under every visible path,
        // while true cycles (including symlinks back to an ancestor) cannot loop.
        if item.ancestors.contains(&identity) {
            stats.cycle_edges_stopped += 1;
            continue;
        }

        let mut lineage = Vec::with_capacity(item.ancestors.len() + 1);
        lineage.extend_from_slice(item.ancestors.as_slice());
        lineage.push(identity);
        let lineage = Arc::new(lineage);

        let Some(children) = snapshot_directory(&item.path, &mut stats)? else {
            // The directory ceased to exist during traversal. This is not treated
            // as an access bypass; later full passes rescan the current filesystem.
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

fn resolve_directory_metadata(
    path: &Path,
    stats: &mut PassStats,
) -> Result<Option<(Metadata, bool)>, String> {
    let Some(link_metadata) = metadata_with_retry(path, false, stats)? else {
        return Ok(None);
    };

    if link_metadata.file_type().is_dir() {
        return Ok(Some((link_metadata, false)));
    }

    if !link_metadata.file_type().is_symlink() {
        return Ok(None);
    }

    stats.symlink_candidates_seen += 1;

    // Follow only a symlink whose target is itself a directory. A symlink to a
    // regular file is ignored without ever opening the target file contents.
    match metadata_with_retry(path, true, stats)? {
        Some(target_metadata) if target_metadata.is_dir() => Ok(Some((target_metadata, true))),
        Some(_) => Ok(None),
        None => Ok(None),
    }
}

fn metadata_with_retry(
    path: &Path,
    follow_symlink: bool,
    stats: &mut PassStats,
) -> Result<Option<Metadata>, String> {
    let operation = if follow_symlink {
        "follow directory symlink"
    } else {
        "inspect directory candidate"
    };

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
            Err(error) if follow_symlink && is_symlink_loop(&error) => {
                // A self/looping symlink is not an actual traversable directory.
                return Ok(None);
            }
            Err(error) => return Err(hard_access_error(operation, path, &error)),
        }
    }

    unreachable!("metadata retry loop always returns")
}

fn snapshot_directory(
    directory: &Path,
    stats: &mut PassStats,
) -> Result<Option<Vec<PathBuf>>, String> {
    for attempt in 0..IO_ATTEMPTS {
        match snapshot_directory_once(directory, stats) {
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

fn snapshot_directory_once(directory: &Path, stats: &mut PassStats) -> io::Result<Vec<PathBuf>> {
    let entries = fs::read_dir(directory)?;
    let mut children = Vec::<PathBuf>::new();

    // Only directory entries and symlink entries become scan candidates.
    // Regular files, sockets, devices, pipes, etc. are never opened and are not
    // queued for later metadata/content inspection.
    for entry_result in entries {
        let entry = entry_result?;
        stats.directory_entries_seen += 1;

        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            stats.directory_candidates_seen += 1;
            children.push(entry.path());
        } else if file_type.is_symlink() {
            stats.directory_candidates_seen += 1;
            children.push(entry.path());
        }
    }

    // Sorting makes traversal deterministic for a filesystem snapshot. This also
    // makes repeated runs easier to compare without changing what is scanned.
    children.sort_unstable();
    Ok(children)
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
    // Linux ELOOP. This is a malformed/cyclic symlink, not a permission failure.
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

fn render_report(found: &BTreeSet<PathBuf>, stats: &ScanStats) -> String {
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
    output.push_str(&format!(
        "directory_entries_seen={}\n",
        stats.directory_entries_seen
    ));
    output.push_str(&format!(
        "directory_candidates_seen={}\n",
        stats.directory_candidates_seen
    ));
    output.push_str(&format!(
        "directory_symlinks_followed={}\n",
        stats.symlink_directories_followed
    ));
    output.push_str(&format!("cycle_edges_stopped={}\n", stats.cycle_edges_stopped));
    output.push_str(&format!("io_retries={}\n", stats.io_retries));
    output.push_str(&format!(
        "transient_disappearances={}\n",
        stats.transient_disappearances
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
    use super::{ascii_eq_ignore_case, is_codex_directory};
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
    fn ascii_match_does_not_depend_on_unicode_paths() {
        assert!(ascii_eq_ignore_case(b"CODEX", b"codex"));
        assert!(!ascii_eq_ignore_case(b"codex2", b"codex"));
    }
}
