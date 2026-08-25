use super::ascii_eq_ignore_case;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Phase2Result {
    pub scan_roots: Vec<ScanRoot>,
    pub candidates: Vec<FileCandidate>,
    pub stats: Phase2Stats,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ScanRoot {
    pub path: PathBuf,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FileCandidate {
    pub path: PathBuf,
    pub kind: CandidateKind,
    pub matched_rule: String,
    pub exact_case: bool,
    pub discovered_under: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CandidateKind {
    ConfigToml,
    ProfileConfigToml,
    AgentsMd,
    AgentsOverrideMd,
    SkillMd,
    HooksJson,
    PluginHooksJson,
    AuthJson,
    HistoryJsonl,
    PetJson,
    ConfigSchemaJson,
    RequirementsToml,
    MarketplaceJson,
    PluginManifestJson,
    SkillOpenAiYaml,
    RuleFile,
    PluginAppJson,
    PluginMcpJson,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct Phase2Stats {
    pub roots_considered: u64,
    pub roots_scanned: u64,
    pub directories_enumerated: u64,
    pub entries_seen: u64,
    pub regular_files_seen: u64,
    pub file_symlinks_seen: u64,
    pub directory_symlinks_followed: u64,
    pub cycles_stopped: u64,
    pub candidates_found: u64,
}

#[derive(Clone)]
struct QueueItem {
    path: PathBuf,
    ancestry: Vec<(u64, u64)>,
}

pub(crate) fn discover_candidates(phase1_roots: &BTreeSet<PathBuf>) -> Result<Phase2Result, String> {
    let root_map = build_scan_roots(phase1_roots)?;
    let mut stats = Phase2Stats {
        roots_considered: root_map.len() as u64,
        ..Default::default()
    };
    let mut candidates = BTreeMap::<PathBuf, FileCandidate>::new();

    for root in root_map.keys() {
        if !root.exists() {
            continue;
        }
        scan_root(root, &mut candidates, &mut stats)?;
        stats.roots_scanned += 1;
    }

    let scan_roots = root_map
        .into_iter()
        .map(|(path, sources)| ScanRoot {
            path,
            sources: sources.into_iter().collect(),
        })
        .collect::<Vec<_>>();

    let candidates = candidates.into_values().collect::<Vec<_>>();
    stats.candidates_found = candidates.len() as u64;

    Ok(Phase2Result {
        scan_roots,
        candidates,
        stats,
    })
}

fn build_scan_roots(
    phase1_roots: &BTreeSet<PathBuf>,
) -> Result<BTreeMap<PathBuf, BTreeSet<String>>, String> {
    let mut roots = BTreeMap::<PathBuf, BTreeSet<String>>::new();

    for root in phase1_roots {
        add_root(&mut roots, root.clone(), "phase1_codex_directory");
    }

    let home = env::var_os("HOME").map(PathBuf::from).or_else(dirs::home_dir);
    let codex_home = env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|path| path.join(".codex")));

    if let Some(path) = codex_home {
        add_root(&mut roots, path, "official_codex_home");
    }

    add_root(
        &mut roots,
        PathBuf::from("/etc/codex"),
        "official_unix_system_codex_root",
    );
    add_root(
        &mut roots,
        PathBuf::from("/etc/codex/skills"),
        "official_admin_skill_root",
    );

    if let Some(home) = home {
        add_root(
            &mut roots,
            home.join(".agents/skills"),
            "official_user_skill_root",
        );
        add_root(
            &mut roots,
            home.join(".agents/plugins"),
            "official_user_plugin_marketplace_root",
        );
    }

    let cwd = env::current_dir().map_err(|error| format!("PHASE2_FAILED: cannot read CWD: {error}"))?;
    let project_root = find_project_root(&cwd);

    // AGENTS.md and AGENTS.override.md are project documents, not .codex files.
    // Phase 2 therefore scans the project tree itself as a candidate-discovery
    // surface. Phase 3 later applies the exact root-to-CWD selection protocol.
    add_root(
        &mut roots,
        project_root.clone().unwrap_or_else(|| cwd.clone()),
        if project_root.is_some() {
            "official_project_instruction_tree"
        } else {
            "official_current_directory_instruction_scope"
        },
    );

    for ancestor in cwd.ancestors() {
        if let Some(project_root) = project_root.as_deref() {
            if !ancestor.starts_with(project_root) {
                break;
            }
        }

        add_root(
            &mut roots,
            ancestor.join(".codex"),
            "official_project_codex_layer_candidate",
        );
        add_root(
            &mut roots,
            ancestor.join(".agents/skills"),
            "official_project_skill_root_candidate",
        );
        add_root(
            &mut roots,
            ancestor.join(".agents/plugins"),
            "official_project_plugin_marketplace_root_candidate",
        );

        if project_root.as_deref() == Some(ancestor) {
            break;
        }
    }

    Ok(roots)
}

fn add_root(
    roots: &mut BTreeMap<PathBuf, BTreeSet<String>>,
    path: PathBuf,
    source: &str,
) {
    roots.entry(path).or_default().insert(source.to_owned());
}

fn find_project_root(cwd: &Path) -> Option<PathBuf> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !output.status.success() {
        return cwd
            .ancestors()
            .find(|ancestor| ancestor.join(".git").exists())
            .map(Path::to_path_buf);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let value = text.trim();
    (!value.is_empty()).then(|| PathBuf::from(value))
}

fn scan_root(
    root: &Path,
    candidates: &mut BTreeMap<PathBuf, FileCandidate>,
    stats: &mut Phase2Stats,
) -> Result<(), String> {
    let mut queue = VecDeque::<QueueItem>::new();
    let mut seen_paths = HashSet::<PathBuf>::new();
    queue.push_back(QueueItem {
        path: root.to_path_buf(),
        ancestry: Vec::new(),
    });

    while let Some(item) = queue.pop_front() {
        if !seen_paths.insert(item.path.clone()) {
            continue;
        }

        let link_meta = match fs::symlink_metadata(&item.path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "PHASE2_FAILED: cannot inspect {}: {error}",
                    item.path.display()
                ))
            }
        };

        let (metadata, through_symlink) = if link_meta.file_type().is_symlink() {
            let target = fs::metadata(&item.path).map_err(|error| {
                format!(
                    "PHASE2_FAILED: cannot follow symlink {}: {error}",
                    item.path.display()
                )
            })?;
            (target, true)
        } else {
            (link_meta, false)
        };

        if !metadata.is_dir() {
            continue;
        }
        if through_symlink {
            stats.directory_symlinks_followed += 1;
        }

        use std::os::unix::fs::MetadataExt;
        let identity = (metadata.dev(), metadata.ino());
        if item.ancestry.contains(&identity) {
            stats.cycles_stopped += 1;
            continue;
        }
        let mut ancestry = item.ancestry.clone();
        ancestry.push(identity);

        let entries = fs::read_dir(&item.path).map_err(|error| {
            format!(
                "PHASE2_FAILED: cannot enumerate {}: {error}",
                item.path.display()
            )
        })?;
        stats.directories_enumerated += 1;

        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "PHASE2_FAILED: cannot enumerate entry under {}: {error}",
                    item.path.display()
                )
            })?;
            stats.entries_seen += 1;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|error| {
                format!("PHASE2_FAILED: cannot inspect {}: {error}", path.display())
            })?;

            if file_type.is_dir() {
                queue.push_back(QueueItem {
                    path,
                    ancestry: ancestry.clone(),
                });
                continue;
            }

            if file_type.is_symlink() {
                match fs::metadata(&path) {
                    Ok(target) if target.is_dir() => {
                        queue.push_back(QueueItem {
                            path,
                            ancestry: ancestry.clone(),
                        });
                    }
                    Ok(target) if target.is_file() => {
                        stats.file_symlinks_seen += 1;
                        record_candidate(&path, root, candidates);
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(format!(
                            "PHASE2_FAILED: cannot follow file symlink {}: {error}",
                            path.display()
                        ))
                    }
                }
                continue;
            }

            if file_type.is_file() {
                stats.regular_files_seen += 1;
                record_candidate(&path, root, candidates);
            }
        }
    }

    Ok(())
}

fn record_candidate(
    path: &Path,
    scan_root: &Path,
    candidates: &mut BTreeMap<PathBuf, FileCandidate>,
) {
    let Some((kind, rule, exact_case)) = classify(path) else {
        return;
    };

    let hit = candidates.entry(path.to_path_buf()).or_insert_with(|| FileCandidate {
        path: path.to_path_buf(),
        kind,
        matched_rule: rule.clone(),
        exact_case,
        discovered_under: Vec::new(),
    });

    if !hit.discovered_under.iter().any(|root| root == scan_root) {
        hit.discovered_under.push(scan_root.to_path_buf());
        hit.discovered_under.sort();
    }
}

fn classify(path: &Path) -> Option<(CandidateKind, String, bool)> {
    let name = path.file_name()?;
    let bytes = name.as_bytes();
    let parent = path.parent().and_then(Path::file_name);

    if parent.is_some_and(|value| value.as_bytes() == b"rules") && ends_with_ascii_case(bytes, b".rules") {
        return Some((
            CandidateKind::RuleFile,
            "rules/*.rules".into(),
            bytes.ends_with(b".rules"),
        ));
    }

    if parent.is_some_and(|value| value.as_bytes() == b".codex-plugin")
        && ascii_eq_ignore_case(bytes, b"plugin.json")
    {
        return Some((
            CandidateKind::PluginManifestJson,
            ".codex-plugin/plugin.json".into(),
            bytes == b"plugin.json",
        ));
    }

    if parent.is_some_and(|value| value.as_bytes() == b"agents")
        && ascii_eq_ignore_case(bytes, b"openai.yaml")
    {
        return Some((
            CandidateKind::SkillOpenAiYaml,
            "agents/openai.yaml".into(),
            bytes == b"openai.yaml",
        ));
    }

    if parent.is_some_and(|value| value.as_bytes() == b"hooks")
        && ascii_eq_ignore_case(bytes, b"hooks.json")
    {
        return Some((
            CandidateKind::PluginHooksJson,
            "hooks/hooks.json".into(),
            bytes == b"hooks.json",
        ));
    }

    if ends_with_ascii_case(bytes, b".config.toml") && !ascii_eq_ignore_case(bytes, b"config.toml") {
        return Some((
            CandidateKind::ProfileConfigToml,
            "<profile>.config.toml".into(),
            bytes.ends_with(b".config.toml"),
        ));
    }

    const EXACT: &[(&[u8], CandidateKind, &str)] = &[
        (b"config.toml", CandidateKind::ConfigToml, "config.toml"),
        (b"AGENTS.md", CandidateKind::AgentsMd, "AGENTS.md"),
        (b"AGENTS.override.md", CandidateKind::AgentsOverrideMd, "AGENTS.override.md"),
        (b"SKILL.md", CandidateKind::SkillMd, "SKILL.md"),
        (b"hooks.json", CandidateKind::HooksJson, "hooks.json"),
        (b"auth.json", CandidateKind::AuthJson, "auth.json"),
        (b"history.jsonl", CandidateKind::HistoryJsonl, "history.jsonl"),
        (b"pet.json", CandidateKind::PetJson, "pet.json"),
        (b"config-schema.json", CandidateKind::ConfigSchemaJson, "config-schema.json"),
        (b"requirements.toml", CandidateKind::RequirementsToml, "requirements.toml"),
        (b"marketplace.json", CandidateKind::MarketplaceJson, "marketplace.json"),
        (b".app.json", CandidateKind::PluginAppJson, ".app.json"),
        (b".mcp.json", CandidateKind::PluginMcpJson, ".mcp.json"),
    ];

    EXACT.iter().find_map(|(expected, kind, rule)| {
        ascii_eq_ignore_case(bytes, expected).then(|| (*kind, (*rule).to_owned(), bytes == *expected))
    })
}

fn ends_with_ascii_case(value: &[u8], suffix: &[u8]) -> bool {
    value.len() >= suffix.len()
        && ascii_eq_ignore_case(&value[value.len() - suffix.len()..], suffix)
}

pub(crate) fn candidate_by_path<'a>(
    result: &'a Phase2Result,
    path: &Path,
) -> Option<&'a FileCandidate> {
    result.candidates.iter().find(|candidate| candidate.path == path)
}

pub(crate) fn candidates_of_kind<'a>(
    result: &'a Phase2Result,
    kind: CandidateKind,
) -> impl Iterator<Item = &'a FileCandidate> {
    result.candidates.iter().filter(move |candidate| candidate.kind == kind)
}

pub(crate) fn os_name_eq(name: &OsStr, expected: &[u8]) -> bool {
    name.as_bytes() == expected
}

#[cfg(test)]
mod tests {
    use super::{classify, CandidateKind};
    use std::path::Path;

    #[test]
    fn classifies_phase2_protocol_paths() {
        assert_eq!(classify(Path::new("/x/config.toml")).unwrap().0, CandidateKind::ConfigToml);
        assert_eq!(classify(Path::new("/x/dev.config.toml")).unwrap().0, CandidateKind::ProfileConfigToml);
        assert_eq!(classify(Path::new("/x/rules/default.rules")).unwrap().0, CandidateKind::RuleFile);
        assert_eq!(classify(Path::new("/x/.codex-plugin/plugin.json")).unwrap().0, CandidateKind::PluginManifestJson);
        assert_eq!(classify(Path::new("/x/agents/openai.yaml")).unwrap().0, CandidateKind::SkillOpenAiYaml);
    }
}
