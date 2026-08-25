use super::app_server_probe::{self, AppServerSnapshot};
use super::phase2::{candidate_by_path, CandidateKind, FileCandidate, Phase2Result};
use super::schema_check;
use super::Phase1Result;
use serde::Serialize;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use toml::Value as TomlValue;

const DEFAULT_PROJECT_DOC_MAX_BYTES: usize = 32 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Phase3Result {
    pub context: RuntimeContext,
    pub app_server: AppServerSnapshot,
    pub phase1_verification: Phase1Verification,
    pub config_layers: Vec<RuntimeConfigLayer>,
    pub instruction_chain: InstructionChain,
    pub dynamic_targets: Vec<DynamicTarget>,
    pub verdicts: Vec<Verdict>,
    pub runtime_diagnostics: Vec<RuntimeDiagnostic>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RuntimeContext {
    pub effective_uid: Option<String>,
    pub effective_user: Option<String>,
    pub home: Option<PathBuf>,
    pub codex_home: PathBuf,
    pub codex_home_source: String,
    pub cwd: PathBuf,
    pub project_root: PathBuf,
    pub project_root_markers: Vec<String>,
    pub project_trust: ProjectTrust,
    pub codex_executable: Option<PathBuf>,
    pub codex_version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProjectTrust {
    Trusted,
    Untrusted,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Phase1Verification {
    pub required_runtime_roots: Vec<PathBuf>,
    pub missing_from_phase1: Vec<PathBuf>,
    pub discovered: Vec<DirectoryVerdict>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DirectoryVerdict {
    pub path: PathBuf,
    pub role: String,
    pub runtime_required: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RuntimeConfigLayer {
    pub runtime_order: usize,
    pub source_type: String,
    pub source_path: Option<PathBuf>,
    pub profile: Option<String>,
    pub version: Option<String>,
    pub disabled_reason: Option<String>,
    pub active: bool,
    pub raw_config: JsonValue,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InstructionChain {
    pub project_trust: ProjectTrust,
    pub fallback_filenames: Vec<String>,
    pub project_doc_max_bytes: usize,
    pub global: Vec<InstructionEntry>,
    pub project: Vec<InstructionEntry>,
    pub shadowed: Vec<InstructionEntry>,
    pub remaining_project_budget: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InstructionEntry {
    pub path: PathBuf,
    pub scope: String,
    pub selected_bytes: usize,
    pub file_bytes: usize,
    pub truncated: bool,
    pub sha256_selected: String,
    pub reason: String,
    pub runtime_model_visible: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DynamicTarget {
    pub source_layer: Option<PathBuf>,
    pub config_key: String,
    pub resolved_path: PathBuf,
    pub exists: bool,
    pub present_in_phase2: bool,
    pub syntax_valid: Option<bool>,
    pub schema_valid: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Verdict {
    pub subject: String,
    pub kind: String,
    pub states: Vec<VerificationState>,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum VerificationState {
    Discovered,
    LocationRecognized,
    SyntaxValid,
    SyntaxInvalid,
    SchemaValid,
    SchemaInvalid,
    RuntimeConfirmed,
    RuntimeRejected,
    RuntimeUnavailable,
    LayerActive,
    LayerDisabled,
    Selected,
    Shadowed,
    Truncated,
    TrustConfirmed,
    TrustRejected,
    TrustUnknown,
    ManagedPolicyPresent,
    Effective,
    StateArtifact,
    Phase1DiscoveryMiss,
    Phase2DiscoveryMiss,
    InvalidNameCase,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RuntimeDiagnostic {
    pub name: String,
    pub command: Vec<String>,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Copy)]
enum DynamicKind {
    TomlConfig,
    Json,
    Text,
}

#[derive(Debug, Clone)]
struct DynamicSpec {
    source_layer: Option<PathBuf>,
    key: String,
    path: PathBuf,
    kind: DynamicKind,
}

pub(crate) fn verify(phase1: &Phase1Result, phase2: &Phase2Result) -> Result<Phase3Result, String> {
    let mut context = RuntimeContext::capture_base()?;
    let app_server = app_server_probe::probe(context.codex_executable.as_deref(), &context.cwd);

    if let Some(runtime_home) = app_server.codex_home() {
        context.codex_home = PathBuf::from(runtime_home);
        context.codex_home_source = "app_server_initialize".into();
    }

    context.project_root_markers = project_root_markers(app_server.effective_config());
    context.project_root = find_project_root_from_markers(&context.cwd, &context.project_root_markers);

    let config_layers = parse_runtime_layers(&app_server);
    context.project_trust = derive_project_trust(&context, &config_layers);

    let runtime_diagnostics = collect_runtime_diagnostics(&context);
    let prompt_json = runtime_diagnostics
        .iter()
        .find(|diagnostic| diagnostic.name == "prompt input" && diagnostic.success)
        .and_then(|diagnostic| serde_json::from_str::<JsonValue>(&diagnostic.stdout).ok());

    let phase1_verification = verify_phase1(phase1, &context, &config_layers);
    let fallback_filenames = string_array(
        app_server
            .effective_config()
            .and_then(|value| value.get("project_doc_fallback_filenames")),
    );
    let project_doc_max_bytes = app_server
        .effective_config()
        .and_then(|value| value.get("project_doc_max_bytes"))
        .and_then(JsonValue::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(DEFAULT_PROJECT_DOC_MAX_BYTES);

    let instruction_chain = build_instruction_chain(
        &context,
        &fallback_filenames,
        project_doc_max_bytes,
        prompt_json.as_ref(),
    )?;

    let dynamic_specs = collect_dynamic_specs(&app_server, &config_layers);
    let dynamic_targets = verify_dynamic_targets(&dynamic_specs, phase2);

    let mut verdicts = Vec::<Verdict>::new();
    add_phase1_verdicts(&phase1_verification, &mut verdicts);
    add_config_layer_verdicts(&config_layers, phase2, &mut verdicts);
    add_phase2_candidate_verdicts(
        phase2,
        &context,
        &app_server,
        &config_layers,
        &instruction_chain,
        &mut verdicts,
    )?;
    add_instruction_verdicts(&instruction_chain, phase2, &mut verdicts);
    add_dynamic_verdicts(&dynamic_targets, &mut verdicts);

    verdicts.sort_by(|left, right| left.subject.cmp(&right.subject).then(left.kind.cmp(&right.kind)));

    Ok(Phase3Result {
        context,
        app_server,
        phase1_verification,
        config_layers,
        instruction_chain,
        dynamic_targets,
        verdicts,
        runtime_diagnostics,
    })
}

impl RuntimeContext {
    fn capture_base() -> Result<Self, String> {
        let cwd = env::current_dir().map_err(|error| format!("PHASE3_FAILED: cannot read CWD: {error}"))?;
        let home = env::var_os("HOME").map(PathBuf::from).or_else(dirs::home_dir);
        let codex_home = env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|path| path.join(".codex")))
            .ok_or_else(|| "PHASE3_FAILED: HOME and CODEX_HOME are both unavailable".to_owned())?;
        let codex_executable = find_executable("codex");
        let codex_version = codex_executable
            .as_deref()
            .and_then(|binary| run_output(binary, &["--version"], Some(&cwd)).ok())
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned());

        Ok(Self {
            effective_uid: command_text("id", &["-u"], None),
            effective_user: command_text("id", &["-un"], None).or_else(|| env::var("USER").ok()),
            home,
            codex_home,
            codex_home_source: "environment_or_default".into(),
            cwd: cwd.clone(),
            project_root: cwd,
            project_root_markers: vec![".git".into()],
            project_trust: ProjectTrust::Unknown,
            codex_executable,
            codex_version,
        })
    }
}

fn parse_runtime_layers(snapshot: &AppServerSnapshot) -> Vec<RuntimeConfigLayer> {
    snapshot
        .layers()
        .unwrap_or_default()
        .iter()
        .enumerate()
        .map(|(runtime_order, raw)| {
            let name = raw.get("name").unwrap_or(&JsonValue::Null);
            let source_type = name
                .get("type")
                .and_then(JsonValue::as_str)
                .unwrap_or("unknown")
                .to_owned();
            let source_path = runtime_layer_path(name, &source_type);
            let profile = name.get("profile").and_then(JsonValue::as_str).map(str::to_owned);
            let version = raw.get("version").and_then(JsonValue::as_str).map(str::to_owned);
            let disabled_reason = raw
                .get("disabledReason")
                .and_then(JsonValue::as_str)
                .map(str::to_owned);
            let active = disabled_reason.is_none();
            let raw_config = raw.get("config").cloned().unwrap_or(JsonValue::Null);
            RuntimeConfigLayer {
                runtime_order,
                source_type,
                source_path,
                profile,
                version,
                disabled_reason,
                active,
                raw_config,
            }
        })
        .collect()
}

fn runtime_layer_path(name: &JsonValue, source_type: &str) -> Option<PathBuf> {
    match source_type {
        "project" => name
            .get("dotCodexFolder")
            .and_then(JsonValue::as_str)
            .map(PathBuf::from)
            .map(|path| path.join("config.toml")),
        "user" | "system" | "packagedDefaults" | "legacyManagedConfigTomlFromFile" => name
            .get("file")
            .and_then(JsonValue::as_str)
            .map(PathBuf::from),
        _ => None,
    }
}

fn project_root_markers(config: Option<&JsonValue>) -> Vec<String> {
    match config.and_then(|value| value.get("project_root_markers")) {
        Some(JsonValue::Array(values)) => values
            .iter()
            .filter_map(JsonValue::as_str)
            .map(str::to_owned)
            .collect(),
        _ => vec![".git".into()],
    }
}

fn find_project_root_from_markers(cwd: &Path, markers: &[String]) -> PathBuf {
    if markers.is_empty() {
        return cwd.to_path_buf();
    }
    for ancestor in cwd.ancestors() {
        if markers.iter().any(|marker| ancestor.join(marker).exists()) {
            return ancestor.to_path_buf();
        }
    }
    cwd.to_path_buf()
}

fn derive_project_trust(context: &RuntimeContext, layers: &[RuntimeConfigLayer]) -> ProjectTrust {
    let chain = path_chain(&context.project_root, &context.cwd);
    let project_layers = layers
        .iter()
        .filter(|layer| layer.source_type == "project")
        .filter(|layer| {
            layer
                .source_path
                .as_deref()
                .and_then(Path::parent)
                .and_then(Path::parent)
                .is_some_and(|project_dir| chain.iter().any(|directory| directory == project_dir))
        })
        .collect::<Vec<_>>();

    if project_layers.iter().any(|layer| layer.disabled_reason.is_some()) {
        ProjectTrust::Untrusted
    } else if !project_layers.is_empty() {
        ProjectTrust::Trusted
    } else {
        ProjectTrust::Unknown
    }
}

fn verify_phase1(
    phase1: &Phase1Result,
    context: &RuntimeContext,
    layers: &[RuntimeConfigLayer],
) -> Phase1Verification {
    let mut required = BTreeSet::<PathBuf>::new();
    if context.codex_home.exists() {
        required.insert(context.codex_home.clone());
    }
    let system = PathBuf::from("/etc/codex");
    if system.exists() {
        required.insert(system);
    }
    for layer in layers.iter().filter(|layer| layer.source_type == "project") {
        if let Some(dot_codex) = layer
            .source_path
            .as_deref()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
        {
            required.insert(dot_codex);
        }
    }

    let missing_from_phase1 = required
        .iter()
        .filter(|path| !phase1.roots.contains(*path))
        .cloned()
        .collect::<Vec<_>>();

    let discovered = phase1
        .roots
        .iter()
        .map(|path| DirectoryVerdict {
            path: path.clone(),
            role: classify_directory(path, context, layers),
            runtime_required: required.contains(path),
        })
        .collect();

    Phase1Verification {
        required_runtime_roots: required.into_iter().collect(),
        missing_from_phase1,
        discovered,
    }
}

fn classify_directory(path: &Path, context: &RuntimeContext, layers: &[RuntimeConfigLayer]) -> String {
    if path == context.codex_home {
        return "codex_home".into();
    }
    if path == Path::new("/etc/codex") {
        return "unix_system_codex".into();
    }
    if layers.iter().any(|layer| {
        layer.source_type == "project"
            && layer
                .source_path
                .as_deref()
                .and_then(Path::parent)
                .is_some_and(|dot_codex| dot_codex == path)
    }) {
        return "runtime_project_codex_layer".into();
    }
    if path.components().any(|component| {
        matches!(
            component.as_os_str().to_string_lossy().as_ref(),
            "usr" | "lib" | "lib64" | "share" | "node_modules" | "src" | "target"
        )
    }) {
        return "installation_or_source_tree".into();
    }
    "discovered_codex_directory".into()
}

fn build_instruction_chain(
    context: &RuntimeContext,
    fallback_filenames: &[String],
    project_doc_max_bytes: usize,
    prompt_json: Option<&JsonValue>,
) -> Result<InstructionChain, String> {
    let mut global = Vec::new();
    let mut project = Vec::new();
    let mut shadowed = Vec::new();

    let global_candidates = [
        context.codex_home.join("AGENTS.override.md"),
        context.codex_home.join("AGENTS.md"),
    ];
    if let Some(selected) = first_nonempty(&global_candidates)? {
        global.push(read_instruction_entry(
            &selected,
            "global",
            usize::MAX,
            "first non-empty global instruction file",
            prompt_json,
        )?);
        for candidate in global_candidates {
            if candidate != selected && candidate.is_file() {
                shadowed.push(read_instruction_entry(
                    &candidate,
                    "global",
                    0,
                    "not selected because an earlier global filename won",
                    prompt_json,
                )?);
            }
        }
    }

    let mut remaining = project_doc_max_bytes;
    if !matches!(context.project_trust, ProjectTrust::Untrusted) {
        for directory in path_chain(&context.project_root, &context.cwd) {
            if remaining == 0 {
                break;
            }
            let mut candidates = vec![directory.join("AGENTS.override.md"), directory.join("AGENTS.md")];
            candidates.extend(fallback_filenames.iter().map(|name| directory.join(name)));
            if let Some(selected) = first_nonempty(&candidates)? {
                let file_size = fs::metadata(&selected)
                    .map_err(|error| format!("PHASE3_FAILED: cannot stat {}: {error}", selected.display()))?
                    .len() as usize;
                let selected_bytes = file_size.min(remaining);
                project.push(read_instruction_entry(
                    &selected,
                    "project",
                    selected_bytes,
                    "first non-empty project instruction filename at this directory level",
                    prompt_json,
                )?);
                remaining = remaining.saturating_sub(selected_bytes);

                for candidate in candidates {
                    if candidate != selected && candidate.is_file() {
                        shadowed.push(read_instruction_entry(
                            &candidate,
                            "project",
                            0,
                            "shadowed by an earlier instruction filename at the same directory level",
                            prompt_json,
                        )?);
                    }
                }
            }
        }
    }

    Ok(InstructionChain {
        project_trust: context.project_trust.clone(),
        fallback_filenames: fallback_filenames.to_vec(),
        project_doc_max_bytes,
        global,
        project,
        shadowed,
        remaining_project_budget: remaining,
    })
}

fn first_nonempty(paths: &[PathBuf]) -> Result<Option<PathBuf>, String> {
    for path in paths {
        if !path.is_file() {
            continue;
        }
        let bytes = fs::read(path)
            .map_err(|error| format!("PHASE3_FAILED: cannot read instruction {}: {error}", path.display()))?;
        if !String::from_utf8_lossy(&bytes).trim().is_empty() {
            return Ok(Some(path.clone()));
        }
    }
    Ok(None)
}

fn read_instruction_entry(
    path: &Path,
    scope: &str,
    selected_bytes: usize,
    reason: &str,
    prompt_json: Option<&JsonValue>,
) -> Result<InstructionEntry, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("PHASE3_FAILED: cannot read instruction {}: {error}", path.display()))?;
    let count = selected_bytes.min(bytes.len());
    let selected = &bytes[..count];
    let selected_text = String::from_utf8_lossy(selected).to_string();
    let runtime_model_visible = prompt_json.map(|value| json_contains_text(value, &selected_text));
    Ok(InstructionEntry {
        path: path.to_path_buf(),
        scope: scope.into(),
        selected_bytes: count,
        file_bytes: bytes.len(),
        truncated: count < bytes.len(),
        sha256_selected: sha256_bytes(selected),
        reason: reason.into(),
        runtime_model_visible,
    })
}

fn collect_dynamic_specs(snapshot: &AppServerSnapshot, layers: &[RuntimeConfigLayer]) -> Vec<DynamicSpec> {
    let mut specs = BTreeMap::<(String, PathBuf), DynamicSpec>::new();

    for key in [
        "model_instructions_file",
        "experimental_compact_prompt_file",
        "model_catalog_json",
    ] {
        if let Some((layer, value)) = highest_active_layer_value(layers, key) {
            if let Some(path) = value.as_str() {
                let kind = if key == "model_catalog_json" {
                    DynamicKind::Json
                } else {
                    DynamicKind::Text
                };
                let resolved = resolve_layer_relative(layer, path);
                specs.insert(
                    (key.to_owned(), resolved.clone()),
                    DynamicSpec {
                        source_layer: layer.source_path.clone(),
                        key: key.to_owned(),
                        path: resolved,
                        kind,
                    },
                );
            }
        }
    }

    let mut roles = BTreeMap::<String, (&RuntimeConfigLayer, String)>::new();
    for layer in layers.iter().filter(|layer| layer.active) {
        let Some(agents) = layer.raw_config.get("agents").and_then(JsonValue::as_object) else {
            continue;
        };
        for (role_name, role) in agents {
            if let Some(config_file) = role.get("config_file").and_then(JsonValue::as_str) {
                roles.insert(role_name.clone(), (layer, config_file.to_owned()));
            }
        }
    }
    for (role_name, (layer, value)) in roles {
        let resolved = resolve_layer_relative(layer, &value);
        let key = format!("agents.{role_name}.config_file");
        specs.insert(
            (key.clone(), resolved.clone()),
            DynamicSpec {
                source_layer: layer.source_path.clone(),
                key,
                path: resolved,
                kind: DynamicKind::TomlConfig,
            },
        );
    }

    // The effective config is already runtime-resolved by Codex. If an installed
    // version serializes one of these paths only in the effective object rather
    // than in its layer fragments, keep it visible with no guessed source layer.
    if let Some(config) = snapshot.effective_config() {
        for (key, kind) in [
            ("model_instructions_file", DynamicKind::Text),
            ("experimental_compact_prompt_file", DynamicKind::Text),
            ("model_catalog_json", DynamicKind::Json),
        ] {
            if let Some(path) = config.get(key).and_then(JsonValue::as_str) {
                let path = PathBuf::from(path);
                if path.is_absolute() {
                    specs.entry((key.to_owned(), path.clone())).or_insert(DynamicSpec {
                        source_layer: None,
                        key: key.to_owned(),
                        path,
                        kind,
                    });
                }
            }
        }
    }

    specs.into_values().collect()
}

fn highest_active_layer_value<'a>(
    layers: &'a [RuntimeConfigLayer],
    key: &str,
) -> Option<(&'a RuntimeConfigLayer, &'a JsonValue)> {
    layers
        .iter()
        .rev()
        .filter(|layer| layer.active)
        .find_map(|layer| layer.raw_config.get(key).map(|value| (layer, value)))
}

fn resolve_layer_relative(layer: &RuntimeConfigLayer, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        return path;
    }
    layer
        .source_path
        .as_deref()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .join(path)
}

fn verify_dynamic_targets(specs: &[DynamicSpec], phase2: &Phase2Result) -> Vec<DynamicTarget> {
    specs
        .iter()
        .map(|spec| {
            let exists = spec.path.is_file();
            let present_in_phase2 = candidate_by_path(phase2, &spec.path).is_some();
            let (syntax_valid, schema_valid) = if exists {
                validate_dynamic_file(&spec.path, spec.kind)
            } else {
                (None, None)
            };
            DynamicTarget {
                source_layer: spec.source_layer.clone(),
                config_key: spec.key.clone(),
                resolved_path: spec.path.clone(),
                exists,
                present_in_phase2,
                syntax_valid,
                schema_valid,
            }
        })
        .collect()
}

fn validate_dynamic_file(path: &Path, kind: DynamicKind) -> (Option<bool>, Option<bool>) {
    match kind {
        DynamicKind::Text => (fs::read(path).ok().map(|bytes| !bytes.is_empty()), None),
        DynamicKind::Json => (
            fs::read_to_string(path)
                .ok()
                .map(|text| serde_json::from_str::<JsonValue>(&text).is_ok()),
            None,
        ),
        DynamicKind::TomlConfig => match parse_toml(path) {
            Ok(value) => {
                let check = schema_check::validate_config(&value);
                (Some(true), Some(check.valid))
            }
            Err(_) => (Some(false), Some(false)),
        },
    }
}

fn add_phase1_verdicts(verification: &Phase1Verification, verdicts: &mut Vec<Verdict>) {
    for path in &verification.missing_from_phase1 {
        verdicts.push(Verdict {
            subject: path.display().to_string(),
            kind: "phase1_runtime_root".into(),
            states: vec![VerificationState::Phase1DiscoveryMiss, VerificationState::RuntimeConfirmed],
            details: vec!["Codex runtime exposed this root/layer, but Phase 1 did not return it.".into()],
        });
    }
}

fn add_config_layer_verdicts(
    layers: &[RuntimeConfigLayer],
    phase2: &Phase2Result,
    verdicts: &mut Vec<Verdict>,
) {
    for layer in layers {
        let Some(path) = layer.source_path.as_deref() else {
            continue;
        };
        if !path.is_file() {
            continue;
        }

        let mut states = vec![VerificationState::RuntimeConfirmed, VerificationState::LocationRecognized];
        states.push(if layer.active {
            VerificationState::LayerActive
        } else {
            VerificationState::LayerDisabled
        });
        if candidate_by_path(phase2, path).is_none() {
            states.push(VerificationState::Phase2DiscoveryMiss);
        }

        let mut details = vec![format!(
            "App Server config/read layer order={} source={}",
            layer.runtime_order, layer.source_type
        )];
        if let Some(reason) = &layer.disabled_reason {
            details.push(format!("disabledReason={reason}"));
        }

        match parse_toml(path) {
            Ok(value) => {
                states.push(VerificationState::SyntaxValid);
                let schema = schema_check::validate_config(&value);
                if schema.valid {
                    states.push(VerificationState::SchemaValid);
                    if layer.active {
                        states.push(VerificationState::Effective);
                    }
                } else {
                    states.push(VerificationState::SchemaInvalid);
                    details.extend(schema.errors.into_iter().take(20));
                }
            }
            Err(error) => {
                states.push(VerificationState::SyntaxInvalid);
                details.push(error);
            }
        }

        normalize_states(&mut states);
        verdicts.push(Verdict {
            subject: path.display().to_string(),
            kind: "runtime_config_layer".into(),
            states,
            details,
        });
    }
}

fn add_phase2_candidate_verdicts(
    phase2: &Phase2Result,
    context: &RuntimeContext,
    snapshot: &AppServerSnapshot,
    layers: &[RuntimeConfigLayer],
    chain: &InstructionChain,
    verdicts: &mut Vec<Verdict>,
) -> Result<(), String> {
    for candidate in &phase2.candidates {
        let mut states = vec![VerificationState::Discovered];
        let mut details = vec![format!("phase2_rule={}", candidate.matched_rule)];
        if !candidate.exact_case {
            states.push(VerificationState::InvalidNameCase);
        }

        match candidate.kind {
            CandidateKind::ConfigToml | CandidateKind::ProfileConfigToml => {
                verify_config_candidate(candidate, layers, &mut states, &mut details);
            }
            CandidateKind::AgentsMd | CandidateKind::AgentsOverrideMd => {
                verify_agents_candidate(candidate, context, chain, &mut states, &mut details);
            }
            CandidateKind::SkillMd => {
                verify_skill_candidate(candidate, snapshot, &mut states, &mut details)?;
            }
            CandidateKind::SkillOpenAiYaml => {
                verify_skill_yaml_candidate(candidate, snapshot, &mut states, &mut details)?;
            }
            CandidateKind::HooksJson | CandidateKind::PluginHooksJson => {
                verify_hook_candidate(candidate, snapshot, &mut states, &mut details)?;
            }
            CandidateKind::RuleFile => {
                verify_rule_candidate(candidate, context, layers, &mut states, &mut details);
            }
            CandidateKind::RequirementsToml => {
                verify_requirements_candidate(candidate, context, snapshot, &mut states, &mut details);
            }
            CandidateKind::MarketplaceJson => {
                verify_marketplace_candidate(candidate, snapshot, &mut states, &mut details)?;
            }
            CandidateKind::PluginManifestJson => {
                verify_plugin_manifest(candidate, snapshot, &mut states, &mut details)?;
            }
            CandidateKind::PluginAppJson | CandidateKind::PluginMcpJson => {
                verify_plugin_aux_json(candidate, snapshot, &mut states, &mut details)?;
            }
            CandidateKind::AuthJson
            | CandidateKind::HistoryJsonl
            | CandidateKind::PetJson
            | CandidateKind::ConfigSchemaJson => {
                verify_state_artifact(candidate, context, &mut states, &mut details)?;
            }
        }

        normalize_states(&mut states);
        verdicts.push(Verdict {
            subject: candidate.path.display().to_string(),
            kind: format!("{:?}", candidate.kind),
            states,
            details,
        });
    }
    Ok(())
}

fn verify_config_candidate(
    candidate: &FileCandidate,
    layers: &[RuntimeConfigLayer],
    states: &mut Vec<VerificationState>,
    details: &mut Vec<String>,
) {
    let runtime_layer = layers
        .iter()
        .find(|layer| layer.source_path.as_deref() == Some(candidate.path.as_path()));
    if let Some(layer) = runtime_layer {
        states.push(VerificationState::LocationRecognized);
        states.push(VerificationState::RuntimeConfirmed);
        states.push(if layer.active {
            VerificationState::LayerActive
        } else {
            VerificationState::LayerDisabled
        });
        if let Some(reason) = &layer.disabled_reason {
            details.push(format!("disabledReason={reason}"));
        }
    }

    match parse_toml(&candidate.path) {
        Ok(value) => {
            states.push(VerificationState::SyntaxValid);
            let schema = schema_check::validate_config(&value);
            if schema.valid {
                states.push(VerificationState::SchemaValid);
                if runtime_layer.is_some_and(|layer| layer.active) && candidate.exact_case {
                    states.push(VerificationState::Effective);
                }
            } else {
                states.push(VerificationState::SchemaInvalid);
                details.extend(schema.errors.into_iter().take(20));
            }
        }
        Err(error) => {
            states.push(VerificationState::SyntaxInvalid);
            details.push(error);
        }
    }
}

fn verify_agents_candidate(
    candidate: &FileCandidate,
    context: &RuntimeContext,
    chain: &InstructionChain,
    states: &mut Vec<VerificationState>,
    details: &mut Vec<String>,
) {
    let selected = chain
        .global
        .iter()
        .chain(chain.project.iter())
        .find(|entry| entry.path == candidate.path);
    let shadowed = chain.shadowed.iter().find(|entry| entry.path == candidate.path);

    if candidate.path.parent() == Some(context.codex_home.as_path())
        || path_chain(&context.project_root, &context.cwd)
            .iter()
            .any(|directory| candidate.path.parent() == Some(directory.as_path()))
    {
        states.push(VerificationState::LocationRecognized);
    }

    match fs::read(&candidate.path) {
        Ok(bytes) if !String::from_utf8_lossy(&bytes).trim().is_empty() => {
            states.push(VerificationState::SyntaxValid)
        }
        Ok(_) => states.push(VerificationState::SyntaxInvalid),
        Err(error) => {
            states.push(VerificationState::SyntaxInvalid);
            details.push(format!("read error: {error}"));
        }
    }

    if let Some(entry) = selected {
        states.push(VerificationState::Selected);
        if entry.truncated {
            states.push(VerificationState::Truncated);
        }
        match entry.scope.as_str() {
            "project" => match context.project_trust {
                ProjectTrust::Trusted => states.push(VerificationState::TrustConfirmed),
                ProjectTrust::Untrusted => states.push(VerificationState::TrustRejected),
                ProjectTrust::Unknown => states.push(VerificationState::TrustUnknown),
            },
            _ => states.push(VerificationState::TrustConfirmed),
        }
        match entry.runtime_model_visible {
            Some(true) => states.push(VerificationState::RuntimeConfirmed),
            Some(false) => states.push(VerificationState::RuntimeRejected),
            None => states.push(VerificationState::RuntimeUnavailable),
        }

        let trust_allows = entry.scope != "project"
            || matches!(context.project_trust, ProjectTrust::Trusted)
            || entry.runtime_model_visible == Some(true);
        if trust_allows && entry.runtime_model_visible != Some(false) && candidate.exact_case {
            states.push(VerificationState::Effective);
        }
    } else if shadowed.is_some() {
        states.push(VerificationState::Shadowed);
    } else if candidate.path.starts_with(&context.project_root)
        && matches!(context.project_trust, ProjectTrust::Untrusted)
    {
        states.push(VerificationState::TrustRejected);
        details.push("Project instructions are not loaded for the untrusted active project.".into());
    }
}

fn verify_skill_candidate(
    candidate: &FileCandidate,
    snapshot: &AppServerSnapshot,
    states: &mut Vec<VerificationState>,
    details: &mut Vec<String>,
) -> Result<(), String> {
    let valid = validate_skill_md(&candidate.path)?;
    states.push(if valid {
        VerificationState::SyntaxValid
    } else {
        VerificationState::SyntaxInvalid
    });

    match runtime_skill(snapshot, &candidate.path) {
        Some(skill) => {
            states.push(VerificationState::LocationRecognized);
            states.push(VerificationState::RuntimeConfirmed);
            let enabled = skill.get("enabled").and_then(JsonValue::as_bool).unwrap_or(false);
            if enabled && valid && candidate.exact_case {
                states.push(VerificationState::Effective);
            } else if !enabled {
                states.push(VerificationState::RuntimeRejected);
            }
            if let Some(scope) = skill.get("scope").and_then(JsonValue::as_str) {
                details.push(format!("runtime_skill_scope={scope}"));
            }
            if let Some(plugin_id) = skill.get("pluginId").and_then(JsonValue::as_str) {
                details.push(format!("runtime_plugin_id={plugin_id}"));
            }
        }
        None => {
            states.push(if snapshot.skills_list.is_some() {
                VerificationState::RuntimeRejected
            } else {
                VerificationState::RuntimeUnavailable
            });
        }
    }
    Ok(())
}

fn verify_skill_yaml_candidate(
    candidate: &FileCandidate,
    snapshot: &AppServerSnapshot,
    states: &mut Vec<VerificationState>,
    details: &mut Vec<String>,
) -> Result<(), String> {
    let text = fs::read_to_string(&candidate.path)
        .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", candidate.path.display()))?;
    let valid = serde_yaml::from_str::<serde_yaml::Value>(&text).is_ok();
    states.push(if valid {
        VerificationState::SyntaxValid
    } else {
        VerificationState::SyntaxInvalid
    });

    let skill_md = candidate
        .path
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("SKILL.md"));
    if let Some(skill_md) = skill_md {
        if let Some(skill) = runtime_skill(snapshot, &skill_md) {
            states.push(VerificationState::LocationRecognized);
            states.push(VerificationState::RuntimeConfirmed);
            if skill.get("enabled").and_then(JsonValue::as_bool) == Some(true)
                && valid
                && candidate.exact_case
            {
                states.push(VerificationState::Effective);
            }
            details.push(format!("associated_skill={}", skill_md.display()));
        }
    }
    Ok(())
}

fn runtime_skill<'a>(snapshot: &'a AppServerSnapshot, path: &Path) -> Option<&'a JsonValue> {
    for entry in snapshot.skills_entries()? {
        for skill in entry.get("skills")?.as_array()? {
            if skill.get("path").and_then(JsonValue::as_str).is_some_and(|value| Path::new(value) == path) {
                return Some(skill);
            }
        }
    }
    None
}

fn verify_hook_candidate(
    candidate: &FileCandidate,
    snapshot: &AppServerSnapshot,
    states: &mut Vec<VerificationState>,
    details: &mut Vec<String>,
) -> Result<(), String> {
    let text = fs::read_to_string(&candidate.path)
        .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", candidate.path.display()))?;
    let valid = serde_json::from_str::<JsonValue>(&text).is_ok();
    states.push(if valid {
        VerificationState::SyntaxValid
    } else {
        VerificationState::SyntaxInvalid
    });

    let runtime_hooks = runtime_hooks_for_source(snapshot, &candidate.path);
    if runtime_hooks.is_empty() {
        states.push(if snapshot.hooks_list.is_some() {
            VerificationState::RuntimeRejected
        } else {
            VerificationState::RuntimeUnavailable
        });
        return Ok(());
    }

    states.push(VerificationState::LocationRecognized);
    states.push(VerificationState::RuntimeConfirmed);
    let mut any_effective = false;
    for hook in runtime_hooks {
        let enabled = hook.get("enabled").and_then(JsonValue::as_bool).unwrap_or(false);
        let managed = hook.get("isManaged").and_then(JsonValue::as_bool).unwrap_or(false);
        let trust = hook.get("trustStatus").and_then(JsonValue::as_str).unwrap_or("unknown");
        if managed {
            states.push(VerificationState::ManagedPolicyPresent);
        }
        if enabled && (managed || matches!(trust, "managed" | "trusted" | "Managed" | "Trusted")) {
            any_effective = true;
        }
        details.push(format!(
            "hook key={} enabled={} managed={} trustStatus={}",
            hook.get("key").and_then(JsonValue::as_str).unwrap_or("?"),
            enabled,
            managed,
            trust
        ));
    }
    if valid && any_effective && candidate.exact_case {
        states.push(VerificationState::Effective);
    }
    Ok(())
}

fn runtime_hooks_for_source<'a>(snapshot: &'a AppServerSnapshot, source: &Path) -> Vec<&'a JsonValue> {
    let mut result = Vec::new();
    let Some(entries) = snapshot.hooks_entries() else {
        return result;
    };
    for entry in entries {
        let Some(hooks) = entry.get("hooks").and_then(JsonValue::as_array) else {
            continue;
        };
        for hook in hooks {
            if hook
                .get("sourcePath")
                .and_then(JsonValue::as_str)
                .is_some_and(|value| Path::new(value) == source)
            {
                result.push(hook);
            }
        }
    }
    result
}

fn verify_rule_candidate(
    candidate: &FileCandidate,
    context: &RuntimeContext,
    layers: &[RuntimeConfigLayer],
    states: &mut Vec<VerificationState>,
    details: &mut Vec<String>,
) {
    let config_path = candidate
        .path
        .parent()
        .and_then(Path::parent)
        .map(|parent| parent.join("config.toml"));
    let active_layer = config_path
        .as_deref()
        .and_then(|config| layers.iter().find(|layer| layer.source_path.as_deref() == Some(config)))
        .filter(|layer| layer.active);
    if active_layer.is_some() {
        states.push(VerificationState::LocationRecognized);
        states.push(VerificationState::LayerActive);
    }

    let Some(binary) = context.codex_executable.as_deref() else {
        states.push(VerificationState::RuntimeUnavailable);
        return;
    };
    let rules_arg = candidate.path.to_string_lossy().to_string();
    match run_output(binary, &["execpolicy", "check", "--rules", &rules_arg, "true"], Some(&context.cwd)) {
        Ok(output) if output.status.success() => {
            states.push(VerificationState::SyntaxValid);
            states.push(VerificationState::RuntimeConfirmed);
            if active_layer.is_some() && candidate.exact_case {
                states.push(VerificationState::Effective);
            }
            let stdout = truncate_output(&output.stdout);
            if !stdout.trim().is_empty() {
                details.push(format!("execpolicy_check={}", stdout.trim()));
            }
        }
        Ok(output) => {
            states.push(VerificationState::SyntaxInvalid);
            states.push(VerificationState::RuntimeRejected);
            details.push(truncate_output(&output.stderr));
        }
        Err(error) => {
            states.push(VerificationState::RuntimeUnavailable);
            details.push(error);
        }
    }
}

fn verify_requirements_candidate(
    candidate: &FileCandidate,
    context: &RuntimeContext,
    snapshot: &AppServerSnapshot,
    states: &mut Vec<VerificationState>,
    details: &mut Vec<String>,
) {
    if candidate.path == context.codex_home.join("requirements.toml")
        || candidate.path == PathBuf::from("/etc/codex/requirements.toml")
    {
        states.push(VerificationState::LocationRecognized);
    }
    match parse_toml(&candidate.path) {
        Ok(_) => states.push(VerificationState::SyntaxValid),
        Err(error) => {
            states.push(VerificationState::SyntaxInvalid);
            details.push(error);
        }
    }
    if snapshot.requirements().is_some_and(|value| !value.is_null()) {
        states.push(VerificationState::ManagedPolicyPresent);
        states.push(VerificationState::RuntimeConfirmed);
        details.push("configRequirements/read returned managed requirements; this RPC does not by itself attribute them to one physical source file.".into());
    } else if snapshot.config_requirements_read.is_some() {
        states.push(VerificationState::RuntimeRejected);
    } else {
        states.push(VerificationState::RuntimeUnavailable);
    }
}

fn verify_marketplace_candidate(
    candidate: &FileCandidate,
    snapshot: &AppServerSnapshot,
    states: &mut Vec<VerificationState>,
    details: &mut Vec<String>,
) -> Result<(), String> {
    let text = fs::read_to_string(&candidate.path)
        .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", candidate.path.display()))?;
    let valid = serde_json::from_str::<JsonValue>(&text).is_ok();
    states.push(if valid {
        VerificationState::SyntaxValid
    } else {
        VerificationState::SyntaxInvalid
    });

    let runtime_match = snapshot
        .installed_plugin_marketplaces()
        .unwrap_or_default()
        .iter()
        .find(|marketplace| {
            marketplace
                .get("path")
                .and_then(JsonValue::as_str)
                .is_some_and(|value| Path::new(value) == candidate.path)
        });
    if let Some(marketplace) = runtime_match {
        states.push(VerificationState::LocationRecognized);
        states.push(VerificationState::RuntimeConfirmed);
        if valid && candidate.exact_case {
            states.push(VerificationState::Effective);
        }
        if let Some(name) = marketplace.get("name").and_then(JsonValue::as_str) {
            details.push(format!("runtime_marketplace={name}"));
        }
    } else {
        states.push(if snapshot.plugin_installed.is_some() {
            VerificationState::RuntimeRejected
        } else {
            VerificationState::RuntimeUnavailable
        });
    }
    Ok(())
}

fn verify_plugin_manifest(
    candidate: &FileCandidate,
    snapshot: &AppServerSnapshot,
    states: &mut Vec<VerificationState>,
    details: &mut Vec<String>,
) -> Result<(), String> {
    let text = fs::read_to_string(&candidate.path)
        .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", candidate.path.display()))?;
    let parsed = serde_json::from_str::<JsonValue>(&text);
    states.push(if parsed.is_ok() {
        VerificationState::SyntaxValid
    } else {
        VerificationState::SyntaxInvalid
    });
    let Ok(manifest) = parsed else {
        return Ok(());
    };

    let root = candidate
        .path
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("/"));
    if let Some(plugin) = runtime_plugin_for_manifest(snapshot, root, &manifest) {
        states.push(VerificationState::LocationRecognized);
        states.push(VerificationState::RuntimeConfirmed);
        let installed = plugin.get("installed").and_then(JsonValue::as_bool).unwrap_or(false);
        let enabled = plugin.get("enabled").and_then(JsonValue::as_bool).unwrap_or(false);
        if installed && enabled && candidate.exact_case {
            states.push(VerificationState::Effective);
        } else {
            states.push(VerificationState::RuntimeRejected);
        }
        details.push(format!("runtime_installed={installed} runtime_enabled={enabled}"));
    } else {
        states.push(if snapshot.plugin_installed.is_some() {
            VerificationState::RuntimeRejected
        } else {
            VerificationState::RuntimeUnavailable
        });
    }
    Ok(())
}

fn verify_plugin_aux_json(
    candidate: &FileCandidate,
    snapshot: &AppServerSnapshot,
    states: &mut Vec<VerificationState>,
    details: &mut Vec<String>,
) -> Result<(), String> {
    let text = fs::read_to_string(&candidate.path)
        .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", candidate.path.display()))?;
    let valid = serde_json::from_str::<JsonValue>(&text).is_ok();
    states.push(if valid {
        VerificationState::SyntaxValid
    } else {
        VerificationState::SyntaxInvalid
    });

    if let Some(root) = find_plugin_root(&candidate.path) {
        let manifest_path = root.join(".codex-plugin/plugin.json");
        if let Ok(text) = fs::read_to_string(&manifest_path) {
            if let Ok(manifest) = serde_json::from_str::<JsonValue>(&text) {
                if let Some(plugin) = runtime_plugin_for_manifest(snapshot, &root, &manifest) {
                    states.push(VerificationState::LocationRecognized);
                    states.push(VerificationState::RuntimeConfirmed);
                    if valid
                        && candidate.exact_case
                        && plugin.get("installed").and_then(JsonValue::as_bool) == Some(true)
                        && plugin.get("enabled").and_then(JsonValue::as_bool) == Some(true)
                    {
                        states.push(VerificationState::Effective);
                    }
                    details.push(format!("plugin_root={}", root.display()));
                }
            }
        }
    }
    Ok(())
}

fn runtime_plugin_for_manifest<'a>(
    snapshot: &'a AppServerSnapshot,
    root: &Path,
    manifest: &JsonValue,
) -> Option<&'a JsonValue> {
    let manifest_id = manifest.get("id").and_then(JsonValue::as_str);
    let manifest_name = manifest.get("name").and_then(JsonValue::as_str);
    let root_text = root.to_string_lossy();

    for marketplace in snapshot.installed_plugin_marketplaces()? {
        let Some(plugins) = marketplace.get("plugins").and_then(JsonValue::as_array) else {
            continue;
        };
        for plugin in plugins {
            if json_contains_text(plugin, root_text.as_ref()) {
                return Some(plugin);
            }
            let id_match = manifest_id.is_some_and(|id| plugin.get("id").and_then(JsonValue::as_str) == Some(id));
            let name_match = manifest_name.is_some_and(|name| plugin.get("name").and_then(JsonValue::as_str) == Some(name));
            if id_match || name_match {
                return Some(plugin);
            }
        }
    }
    None
}

fn find_plugin_root(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|ancestor| ancestor.join(".codex-plugin/plugin.json").is_file())
        .map(Path::to_path_buf)
}

fn verify_state_artifact(
    candidate: &FileCandidate,
    context: &RuntimeContext,
    states: &mut Vec<VerificationState>,
    details: &mut Vec<String>,
) -> Result<(), String> {
    if candidate.path.starts_with(&context.codex_home) {
        states.push(VerificationState::LocationRecognized);
    }
    states.push(VerificationState::StateArtifact);

    match candidate.kind {
        CandidateKind::HistoryJsonl => {
            let text = fs::read_to_string(&candidate.path)
                .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", candidate.path.display()))?;
            let valid = text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .all(|line| serde_json::from_str::<JsonValue>(line).is_ok());
            states.push(if valid {
                VerificationState::SyntaxValid
            } else {
                VerificationState::SyntaxInvalid
            });
        }
        _ => {
            let text = fs::read_to_string(&candidate.path)
                .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", candidate.path.display()))?;
            let valid = serde_json::from_str::<JsonValue>(&text).is_ok();
            states.push(if valid {
                VerificationState::SyntaxValid
            } else {
                VerificationState::SyntaxInvalid
            });
        }
    }
    details.push("State/reference artifact: never promoted to effective configuration by Phase 3.".into());
    Ok(())
}

fn add_instruction_verdicts(
    chain: &InstructionChain,
    phase2: &Phase2Result,
    verdicts: &mut Vec<Verdict>,
) {
    for entry in chain.global.iter().chain(chain.project.iter()) {
        if candidate_by_path(phase2, &entry.path).is_none() {
            let mut states = vec![VerificationState::Selected, VerificationState::Phase2DiscoveryMiss];
            if entry.truncated {
                states.push(VerificationState::Truncated);
            }
            if entry.runtime_model_visible == Some(true) {
                states.push(VerificationState::RuntimeConfirmed);
            }
            verdicts.push(Verdict {
                subject: entry.path.display().to_string(),
                kind: "instruction_chain_dynamic_or_missed".into(),
                states,
                details: vec![entry.reason.clone()],
            });
        }
    }
}

fn add_dynamic_verdicts(targets: &[DynamicTarget], verdicts: &mut Vec<Verdict>) {
    for target in targets {
        let mut states = Vec::new();
        let mut details = vec![format!("resolved_from_key={}", target.config_key)];
        if let Some(source) = &target.source_layer {
            details.push(format!("source_layer={}", source.display()));
        }
        if target.exists {
            states.push(VerificationState::Discovered);
            states.push(VerificationState::LocationRecognized);
        }
        if !target.present_in_phase2 && target.exists {
            states.push(VerificationState::Phase2DiscoveryMiss);
        }
        match target.syntax_valid {
            Some(true) => states.push(VerificationState::SyntaxValid),
            Some(false) => states.push(VerificationState::SyntaxInvalid),
            None => {}
        }
        match target.schema_valid {
            Some(true) => states.push(VerificationState::SchemaValid),
            Some(false) => states.push(VerificationState::SchemaInvalid),
            None => {}
        }
        if target.exists
            && target.syntax_valid != Some(false)
            && target.schema_valid != Some(false)
        {
            states.push(VerificationState::Effective);
        }
        normalize_states(&mut states);
        verdicts.push(Verdict {
            subject: target.resolved_path.display().to_string(),
            kind: "effective_config_dynamic_target".into(),
            states,
            details,
        });
    }
}

fn validate_skill_md(path: &Path) -> Result<bool, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", path.display()))?;
    let mut lines = text.lines();
    if lines.next().map(str::trim) != Some("---") {
        return Ok(false);
    }
    let mut yaml = String::new();
    let mut closed = false;
    for line in lines {
        if line.trim() == "---" {
            closed = true;
            break;
        }
        yaml.push_str(line);
        yaml.push('\n');
    }
    if !closed {
        return Ok(false);
    }
    let mapping = match serde_yaml::from_str::<serde_yaml::Mapping>(&yaml) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let name = serde_yaml::Value::String("name".into());
    let description = serde_yaml::Value::String("description".into());
    Ok(mapping
        .get(&name)
        .and_then(serde_yaml::Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
        && mapping
            .get(&description)
            .and_then(serde_yaml::Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()))
}

fn parse_toml(path: &Path) -> Result<TomlValue, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", path.display()))?;
    text.parse::<TomlValue>()
        .map_err(|error| format!("TOML parse error in {}: {error}", path.display()))
}

fn collect_runtime_diagnostics(context: &RuntimeContext) -> Vec<RuntimeDiagnostic> {
    let Some(binary) = context.codex_executable.as_deref() else {
        return vec![RuntimeDiagnostic {
            name: "codex runtime".into(),
            command: vec!["codex".into()],
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: "Codex executable not found on PATH.".into(),
        }];
    };

    vec![
        diagnostic(binary, "doctor", &["doctor", "--json"], &context.cwd),
        diagnostic(binary, "prompt input", &["debug", "prompt-input"], &context.cwd),
        diagnostic(binary, "features list", &["features", "list"], &context.cwd),
    ]
}

fn diagnostic(binary: &Path, name: &str, args: &[&str], cwd: &Path) -> RuntimeDiagnostic {
    match run_output(binary, args, Some(cwd)) {
        Ok(output) => RuntimeDiagnostic {
            name: name.into(),
            command: std::iter::once(binary.display().to_string())
                .chain(args.iter().map(|value| (*value).to_owned()))
                .collect(),
            success: output.status.success(),
            exit_code: output.status.code(),
            stdout: truncate_output(&output.stdout),
            stderr: truncate_output(&output.stderr),
        },
        Err(error) => RuntimeDiagnostic {
            name: name.into(),
            command: std::iter::once(binary.display().to_string())
                .chain(args.iter().map(|value| (*value).to_owned()))
                .collect(),
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: error,
        },
    }
}

fn string_array(value: Option<&JsonValue>) -> Vec<String> {
    value
        .and_then(JsonValue::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(JsonValue::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn path_chain(root: &Path, cwd: &Path) -> Vec<PathBuf> {
    if !cwd.starts_with(root) {
        return vec![cwd.to_path_buf()];
    }
    let mut values = Vec::new();
    let mut current = cwd.to_path_buf();
    loop {
        values.push(current.clone());
        if current == root {
            break;
        }
        let Some(parent) = current.parent() else {
            break;
        };
        current = parent.to_path_buf();
    }
    values.reverse();
    values
}

fn json_contains_text(value: &JsonValue, needle: &str) -> bool {
    if needle.trim().is_empty() {
        return false;
    }
    match value {
        JsonValue::String(text) => text.contains(needle),
        JsonValue::Array(values) => values.iter().any(|value| json_contains_text(value, needle)),
        JsonValue::Object(object) => object.values().any(|value| json_contains_text(value, needle)),
        _ => false,
    }
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}

fn command_text(program: &str, args: &[&str], cwd: Option<&Path>) -> Option<String> {
    let output = run_output(Path::new(program), args, cwd).ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn run_output(program: &Path, args: &[&str], cwd: Option<&Path>) -> Result<Output, String> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command
        .output()
        .map_err(|error| format!("failed to execute {}: {error}", program.display()))
}

fn truncate_output(bytes: &[u8]) -> String {
    let end = bytes.len().min(MAX_DIAGNOSTIC_BYTES);
    let mut text = String::from_utf8_lossy(&bytes[..end]).into_owned();
    if bytes.len() > end {
        text.push_str("\n[output truncated by verifier]\n");
    }
    text
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn normalize_states(states: &mut Vec<VerificationState>) {
    states.sort();
    states.dedup();
}

#[cfg(test)]
mod tests {
    use super::{find_project_root_from_markers, path_chain};
    use std::path::Path;

    #[test]
    fn project_chain_runs_root_to_cwd() {
        let values = path_chain(Path::new("/repo"), Path::new("/repo/a/b"));
        assert_eq!(
            values,
            vec![Path::new("/repo"), Path::new("/repo/a"), Path::new("/repo/a/b")]
        );
    }

    #[test]
    fn empty_markers_disable_parent_traversal() {
        let cwd = Path::new("/tmp/a/b");
        assert_eq!(find_project_root_from_markers(cwd, &[]), cwd);
    }
}
