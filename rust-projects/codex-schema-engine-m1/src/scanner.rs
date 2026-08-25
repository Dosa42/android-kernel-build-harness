use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub fn scan_codex_directories() -> Result<String, String> {
    let mut stack = vec![PathBuf::from("/")];
    let mut visited = HashSet::<(u64, u64)>::new();
    let mut found = Vec::<String>::new();
    let mut directories_scanned = 0_u64;

    while let Some(directory) = stack.pop() {
        let metadata = fs::metadata(&directory).map_err(|error| {
            format!(
                "SCAN_FAILED: cannot read metadata for {}: {}. Full filesystem access is required.",
                directory.display(),
                error
            )
        })?;

        if !metadata.is_dir() {
            continue;
        }

        if !visited.insert((metadata.dev(), metadata.ino())) {
            continue;
        }

        directories_scanned += 1;

        if is_codex_directory(&directory) {
            found.push(directory.to_string_lossy().into_owned());
        }

        let entries = fs::read_dir(&directory).map_err(|error| {
            format!(
                "SCAN_FAILED: cannot read directory {}: {}. Full filesystem access is required.",
                directory.display(),
                error
            )
        })?;

        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "SCAN_FAILED: cannot enumerate directory {}: {}. Full filesystem access is required.",
                    directory.display(),
                    error
                )
            })?;

            let file_type = entry.file_type().map_err(|error| {
                format!(
                    "SCAN_FAILED: cannot inspect {}: {}. Full filesystem access is required.",
                    entry.path().display(),
                    error
                )
            })?;

            if file_type.is_dir() {
                stack.push(entry.path());
            }
        }
    }

    found.sort();
    found.dedup();

    let mut output = String::new();
    output.push_str(&format!("directories_scanned={}\n", directories_scanned));
    output.push_str(&format!("codex_directories_found={}\n", found.len()));
    output.push_str("\nFOUND CODEX DIRECTORIES\n");

    if found.is_empty() {
        output.push_str("none\n");
    } else {
        for path in found {
            output.push_str(&path);
            output.push('\n');
        }
    }

    Ok(output)
}

fn is_codex_directory(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };

    name == ".codex" || name.eq_ignore_ascii_case("codex")
}

#[cfg(test)]
mod tests {
    use super::is_codex_directory;
    use std::path::Path;

    #[test]
    fn matches_only_requested_directory_names() {
        assert!(is_codex_directory(Path::new("/home/user/.codex")));
        assert!(is_codex_directory(Path::new("/opt/Codex")));
        assert!(is_codex_directory(Path::new("/opt/cOdEx")));
        assert!(!is_codex_directory(Path::new("/opt/codex-cli")));
        assert!(!is_codex_directory(Path::new("/opt/schema")));
    }
}
