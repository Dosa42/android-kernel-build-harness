use super::phase2::{candidate_by_path, candidates_of_kind, CandidateKind, FileCandidate, Phase2Result};
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
    pub phase1_verification: Phase1Verification,
    pub config_layers: Vec<ConfigLayer>,
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
    pub cwd: PathBuf,
    pub project_root: PathBuf,
    pub codex_executable: Option<PathBuf>,
    pub codex_version: Option<String>,
    pub selected_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Phase1Verification {
    pub discovered: Vec<DirectoryVerdict>,
    pub required_roots_not_discovered: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DirectoryVerdict {
    pub path: PathBuf,
    pub role: DirectoryRole,
    pub states: Vec<VerificationState>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DirectoryRole {
    CodexHome,
    ProjectCodexLayer,
    UnixSystemCodex,
    InstallationOrSourceTree,
    UnrecognizedCodexDirectory,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ConfigLayer {
    pub path: PathBuf,
    pub kind: ConfigLayerKind,
    pub precedence: u32,
    pub activation: Activation,
    pub syntax_valid: bool,
    pub version_valid: Option<bool>,
    pub sha256: Option<String>,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConfigLayerKind {
    System,
    User,
    Profile,
    Project,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Activation {
    Active,
    Inactive,
    RuntimeConfirmed,
    RuntimeRejected,
    TrustUnconfirmed,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InstructionChain {
    pub selected: Vec<InstructionEntry>,
    pub shadowed: Vec<InstructionEntry>,
    pub fallback_filenames: Vec<String>,
    pub max_bytes: usize,
    pub total_selected_bytes: usize,
    pub model_instructions_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InstructionEntry {
    pub path: PathBuf,
    pub scope: String,
    pub reason: String,
    pub bytes: u64,
    pub sha256: String,
    pub runtime_model_visible: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DynamicTarget {
    pub source_config: PathBuf,
    pub config_key: String,
    pub resolved_path: PathBuf,
    pub exists: bool,
    pub present_in_phase2: bool,
    pub syntax_valid: Option<bool>,
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
    VersionValid,
    VersionInvalid,
    LayerActive,
    LayerInactive,
    Selected,
    Shadowed,
    TrustUnconfirmed,
    RuntimeConfirmed,
    RuntimeRejected,
    Effective,
    InvalidNameCase,
    Phase1DiscoveryMiss,
    Phase2DiscoveryMiss,
    StateArtifact,
    RuntimeUnavailable,
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

#[derive(Debug, Clone)]
struct ParsedLayer {
    info: ConfigLayer,
    value: TomlValue,
}

#[derive(Debug, Clone, Default)]
struct EffectiveConfig {
    fallback_filenames: Vec<String>,
    project_doc_max_bytes: usize,
    model_instructions_file: Option<(PathBuf, PathBuf)>,
    dynamic_targets: Vec<(PathBuf, String, PathBuf, DynamicTargetKind)>,
}

#[derive(Debug, Clone, Copy)]
enum DynamicTargetKind {
    Toml,
    Json,
    Text,
}

pub(crate) fn verify(phase1: &Phase1Result, phase2: &Phase2Result) -> Result<Phase3Result, String> {
    let context = RuntimeContext::capture()?;
    let runtime_diagnostics = collect_runtime_diagnostics(&context);
    let doctor_json = diagnostic_json(&runtime_diagnostics, "codex doctor --json");
    let strict_ok = runtime_diagnostics
        .iter()
        .find(|diagnostic| diagnostic.name == "strict config doctor")
        .map(|diagnostic| diagnostic.success);

    let phase1_verification = verify_phase1(phase1, &context);
    let (parsed_layers, mut layer_verdicts) = build_config_layers(phase2, &context, doctor_json.as_ref(), strict_ok)?;
    let effective_config = resolve_effective_config(&parsed_layers, &context);
    let dynamic_targets = resolve_dynamic_targets(&effective_config, phase2, &mut layer_verdicts);

    let prompt_output = runtime_diagnostics
        .iter()
        .find(|diagnostic| diagnostic.name == "prompt input")
        .filter(|diagnostic| diagnostic.success)
        .map(|diagnostic| diagnostic.stdout.as_str());
    let instruction_chain = build_instruction_chain(&context, &effective_config, prompt_output)?;

    let mut verdicts = verify_phase2_candidates(phase2, &context, &parsed_layers, &runtime_diagnostics)?;
    verdicts.extend(layer_verdicts);
    add_instruction_verdicts(&instruction_chain, &mut verdicts);
    add_dynamic_target_verdicts(&dynamic_targets, &mut verdicts);
    add_phase1_miss_verdicts(&phase1_verification, &mut verdicts);
    verdicts.sort_by(|left, right| left.subject.cmp(&right.subject).then(left.kind.cmp(&right.kind)));

    let config_layers = parsed_layers.into_iter().map(|layer| layer.info).collect();

    Ok(Phase3Result {
        context,
        phase1_verification,
        config_layers,
        instruction_chain,
        dynamic_targets,
        verdicts,
        runtime_diagnostics,
    })
}

impl RuntimeContext {
    fn capture() -> Result<Self, String> {
        let cwd = env::current_dir().map_err(|error| format!("PHASE3_FAILED: cannot read CWD: {error}"))?;
        let home = env::var_os("HOME").map(PathBuf::from).or_else(dirs::home_dir);
        let codex_home = env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|path| path.join(".codex")))
            .ok_or_else(|| "PHASE3_FAILED: HOME and CODEX_HOME are both unavailable".to_owned())?;
        let project_root = find_project_root(&cwd).unwrap_or_else(|| cwd.clone());
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
            cwd,
            project_root,
            codex_executable,
            codex_version,
            selected_profile: detect_selected_profile(),
        })
    }
}

fn verify_phase1(phase1: &Phase1Result, context: &RuntimeContext) -> Phase1Verification {
    let mut discovered = Vec::new();
    for path in &phase1.roots {
        let role = classify_codex_directory(path, context);
        let mut states = vec![VerificationState::Discovered];
        if !matches!(role, DirectoryRole::UnrecognizedCodexDirectory | DirectoryRole::InstallationOrSourceTree) {
            states.push(VerificationState::LocationRecognized);
        }
        discovered.push(DirectoryVerdict {
            path: path.clone(),
            role,
            states,
        });
    }

    let mut required = BTreeSet::<PathBuf>::new();
    if context.codex_home.exists() {
        required.insert(context.codex_home.clone());
    }
    let system = PathBuf::from("/etc/codex");
    if system.exists() {
        required.insert(system);
    }
    for ancestor in path_chain(&context.project_root, &context.cwd) {
        let candidate = ancestor.join(".codex");
        if candidate.exists() {
            required.insert(candidate);
        }
    }

    let required_roots_not_discovered = required
        .into_iter()
        .filter(|path| !phase1.roots.contains(path))
        .collect();

    Phase1Verification {
        discovered,
        required_roots_not_discovered,
    }
}

fn classify_codex_directory(path: &Path, context: &RuntimeContext) -> DirectoryRole {
    if path == context.codex_home {
        return DirectoryRole::CodexHome;
    }
    if path == Path::new("/etc/codex") {
        return DirectoryRole::UnixSystemCodex;
    }
    if path.file_name().is_some_and(|name| name == ".codex")
        && path.parent().is_some_and(|parent| parent.starts_with(&context.project_root))
    {
        return DirectoryRole::ProjectCodexLayer;
    }
    if path.components().any(|component| {
        let value = component.as_os_str().to_string_lossy();
        matches!(value.as_ref(), "usr" | "lib" | "lib64" | "share" | "node_modules" | "src" | "target")
    }) {
        return DirectoryRole::InstallationOrSourceTree;
    }
    DirectoryRole::UnrecognizedCodexDirectory
}

fn build_config_layers(
    phase2: &Phase2Result,
    context: &RuntimeContext,
    doctor_json: Option<&JsonValue>,
    strict_ok: Option<bool>,
) -> Result<(Vec<ParsedLayer>, Vec<Verdict>), String> {
    let mut layers = Vec::<ParsedLayer>::new();
    let mut verdicts = Vec::<Verdict>::new();
    let runtime_active_paths = doctor_json.map(extract_runtime_active_paths).unwrap_or_default();

    let system = PathBuf::from("/etc/codex/config.toml");
    add_layer_if_exists(
        &mut layers,
        &mut verdicts,
        system,
        ConfigLayerKind::System,
        10,
        Activation::Active,
        strict_ok,
    )?;

    let user = context.codex_home.join("config.toml");
    add_layer_if_exists(
        &mut layers,
        &mut verdicts,
        user,
        ConfigLayerKind::User,
        20,
        Activation::Active,
        strict_ok,
    )?;

    if let Some(profile) = &context.selected_profile {
        let path = context.codex_home.join(format!("{profile}.config.toml"));
        add_layer_if_exists(
            &mut layers,
            &mut verdicts,
            path,
            ConfigLayerKind::Profile,
            30,
            Activation::Active,
            strict_ok,
        )?;
    }

    let mut precedence = 40_u32;
    for directory in path_chain(&context.project_root, &context.cwd) {
        let path = directory.join(".codex/config.toml");
        if !path.exists() {
            precedence += 1;
            continue;
        }
        let activation = if runtime_active_paths.contains(&path) {
            Activation::RuntimeConfirmed
        } else if doctor_json.is_some() {
            Activation::TrustUnconfirmed
        } else {
            Activation::TrustUnconfirmed
        };
        add_layer_if_exists(
            &mut layers,
            &mut verdicts,
            path,
            ConfigLayerKind::Project,
            precedence,
            activation,
            strict_ok,
        )?;
        precedence += 1;
    }

    for candidate in candidates_of_kind(phase2, CandidateKind::ProfileConfigToml) {
        if layers.iter().any(|layer| layer.info.path == candidate.path) {
            continue;
        }
        if candidate.path.parent() == Some(context.codex_home.as_path()) {
            let parsed = parse_toml_file(&candidate.path)?;
            verdicts.push(Verdict {
                subject: candidate.path.display().to_string(),
                kind: "profile_config".into(),
                states: if parsed.is_some() {
                    vec![VerificationState::Discovered, VerificationState::LocationRecognized, VerificationState::SyntaxValid, VerificationState::LayerInactive]
                } else {
                    vec![VerificationState::Discovered, VerificationState::LocationRecognized, VerificationState::SyntaxInvalid]
                },
                details: vec!["Profile config exists but is not selected by the observable runtime context.".into()],
            });
        }
    }

    Ok((layers, verdicts))
}

fn add_layer_if_exists(
    layers: &mut Vec<ParsedLayer>,
    verdicts: &mut Vec<Verdict>,
    path: PathBuf,
    kind: ConfigLayerKind,
    precedence: u32,
    activation: Activation,
    strict_ok: Option<bool>,
) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }

    let text = fs::read_to_string(&path)
        .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", path.display()))?;
    let parsed = text.parse::<TomlValue>();
    let syntax_valid = parsed.is_ok();
    let sha256 = sha256_bytes(text.as_bytes());
    let mut details = Vec::new();
    if let Err(error) = &parsed {
        details.push(format!("TOML parse error: {error}"));
    }

    let version_valid = if activation_matches_runtime(activation) { strict_ok } else { None };
    let info = ConfigLayer {
        path: path.clone(),
        kind,
        precedence,
        activation,
        syntax_valid,
        version_valid,
        sha256: Some(sha256),
        details,
    };

    let mut states = vec![VerificationState::Discovered, VerificationState::LocationRecognized];
    states.push(if syntax_valid { VerificationState::SyntaxValid } else { VerificationState::SyntaxInvalid });
    match activation {
        Activation::Active | Activation::RuntimeConfirmed => states.push(VerificationState::LayerActive),
        Activation::Inactive => states.push(VerificationState::LayerInactive),
        Activation::TrustUnconfirmed => states.push(VerificationState::TrustUnconfirmed),
        Activation::RuntimeRejected => states.push(VerificationState::RuntimeRejected),
    }
    if let Some(valid) = version_valid {
        states.push(if valid { VerificationState::VersionValid } else { VerificationState::VersionInvalid });
    }

    verdicts.push(Verdict {
        subject: path.display().to_string(),
        kind: "config_layer".into(),
        states,
        details: info.details.clone(),
    });

    if let Ok(value) = parsed {
        layers.push(ParsedLayer { info, value });
    }
    Ok(())
}

fn activation_matches_runtime(activation: Activation) -> bool {
    matches!(activation, Activation::Active | Activation::RuntimeConfirmed)
}

fn resolve_effective_config(layers: &[ParsedLayer], context: &RuntimeContext) -> EffectiveConfig {
    let mut effective = EffectiveConfig {
        project_doc_max_bytes: DEFAULT_PROJECT_DOC_MAX_BYTES,
        ..Default::default()
    };

    let mut ordered = layers
        .iter()
        .filter(|layer| activation_matches_runtime(layer.info.activation))
        .collect::<Vec<_>>();
    ordered.sort_by_key(|layer| layer.info.precedence);

    for layer in ordered {
        if let Some(values) = layer
            .value
            .get("project_doc_fallback_filenames")
            .and_then(TomlValue::as_array)
        {
            effective.fallback_filenames = values
                .iter()
                .filter_map(TomlValue::as_str)
                .map(str::to_owned)
                .collect();
        }
        if let Some(value) = layer.value.get("project_doc_max_bytes").and_then(TomlValue::as_integer) {
            if value >= 0 {
                effective.project_doc_max_bytes = value as usize;
            }
        }
        if let Some(value) = layer.value.get("model_instructions_file").and_then(TomlValue::as_str) {
            let resolved = resolve_from_config(&layer.info.path, value);
            effective.model_instructions_file = Some((layer.info.path.clone(), resolved.clone()));
            effective.dynamic_targets.push((
                layer.info.path.clone(),
                "model_instructions_file".into(),
                resolved,
                DynamicTargetKind::Text,
            ));
        }
        if let Some(value) = layer.value.get("experimental_compact_prompt_file").and_then(TomlValue::as_str) {
            effective.dynamic_targets.push((
                layer.info.path.clone(),
                "experimental_compact_prompt_file".into(),
                resolve_from_config(&layer.info.path, value),
                DynamicTargetKind::Text,
            ));
        }
        if let Some(value) = layer.value.get("model_catalog_json").and_then(TomlValue::as_str) {
            effective.dynamic_targets.push((
                layer.info.path.clone(),
                "model_catalog_json".into(),
                resolve_from_config(&layer.info.path, value),
                DynamicTargetKind::Json,
            ));
        }
        if let Some(agents) = layer.value.get("agents").and_then(TomlValue::as_table) {
            for (name, role) in agents {
                let Some(role_table) = role.as_table() else { continue };
                let Some(config_file) = role_table.get("config_file").and_then(TomlValue::as_str) else { continue };
                effective.dynamic_targets.push((
                    layer.info.path.clone(),
                    format!("agents.{name}.config_file"),
                    resolve_from_config(&layer.info.path, config_file),
                    DynamicTargetKind::Toml,
                ));
            }
        }
    }

    if effective.fallback_filenames.is_empty() {
        effective.fallback_filenames = Vec::new();
    }

    let _ = context;
    effective
}

fn resolve_dynamic_targets(
    config: &EffectiveConfig,
    phase2: &Phase2Result,
    verdicts: &mut Vec<Verdict>,
) -> Vec<DynamicTarget> {
    let mut targets = Vec::new();
    for (source, key, path, kind) in &config.dynamic_targets {
        let exists = path.exists();
        let in_phase2 = candidate_by_path(phase2, path).is_some();
        let syntax_valid = exists.then(|| validate_dynamic_target(path, *kind)).flatten();
        if exists && !in_phase2 {
            verdicts.push(Verdict {
                subject: path.display().to_string(),
                kind: "dynamic_config_target".into(),
                states: vec![VerificationState::Phase2DiscoveryMiss],
                details: vec![format!("Referenced by {} in {}", key, source.display())],
            });
        }
        targets.push(DynamicTarget {
            source_config: source.clone(),
            config_key: key.clone(),
            resolved_path: path.clone(),
            exists,
            present_in_phase2: in_phase2,
            syntax_valid,
        });
    }
    targets
}

fn validate_dynamic_target(path: &Path, kind: DynamicTargetKind) -> Option<bool> {
    match kind {
        DynamicTargetKind::Toml => parse_toml_file(path).ok().map(|value| value.is_some()),
        DynamicTargetKind::Json => fs::read_to_string(path).ok().map(|text| serde_json::from_str::<JsonValue>(&text).is_ok()),
        DynamicTargetKind::Text => fs::read(path).ok().map(|bytes| !bytes.is_empty()),
    }
}

fn build_instruction_chain(
    context: &RuntimeContext,
    config: &EffectiveConfig,
    prompt_output: Option<&str>,
) -> Result<InstructionChain, String> {
    let mut selected = Vec::<InstructionEntry>::new();
    let mut shadowed = Vec::<InstructionEntry>::new();
    let mut total = 0_usize;

    let global_override = context.codex_home.join("AGENTS.override.md");
    let global_agents = context.codex_home.join("AGENTS.md");
    if let Some(path) = first_nonempty(&[global_override.clone(), global_agents.clone()])? {
        push_instruction(&path, "global", "first non-empty global instruction file", prompt_output, &mut selected, &mut total)?;
        for other in [global_override, global_agents] {
            if other != path && other.exists() {
                push_shadowed(&other, "global", "not selected at global level", &mut shadowed)?;
            }
        }
    }

    for directory in path_chain(&context.project_root, &context.cwd) {
        let mut candidates = vec![directory.join("AGENTS.override.md"), directory.join("AGENTS.md")];
        candidates.extend(config.fallback_filenames.iter().map(|name| directory.join(name)));
        if let Some(path) = first_nonempty(&candidates)? {
            let size = fs::metadata(&path).map(|metadata| metadata.len() as usize).unwrap_or(0);
            if total.saturating_add(size) > config.project_doc_max_bytes {
                break;
            }
            push_instruction(&path, "project", "first non-empty instruction file at directory level", prompt_output, &mut selected, &mut total)?;
            for other in candidates {
                if other != path && other.exists() {
                    push_shadowed(&other, "project", "shadowed by earlier filename at same directory level", &mut shadowed)?;
                }
            }
        }
    }

    Ok(InstructionChain {
        selected,
        shadowed,
        fallback_filenames: config.fallback_filenames.clone(),
        max_bytes: config.project_doc_max_bytes,
        total_selected_bytes: total,
        model_instructions_file: config.model_instructions_file.as_ref().map(|(_, path)| path.clone()),
    })
}

fn first_nonempty(paths: &[PathBuf]) -> Result<Option<PathBuf>, String> {
    for path in paths {
        if !path.is_file() {
            continue;
        }
        let bytes = fs::read(path)
            .map_err(|error| format!("PHASE3_FAILED: cannot read instruction {}: {error}", path.display()))?;
        if !bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(Some(path.clone()));
        }
    }
    Ok(None)
}

fn push_instruction(
    path: &Path,
    scope: &str,
    reason: &str,
    prompt_output: Option<&str>,
    selected: &mut Vec<InstructionEntry>,
    total: &mut usize,
) -> Result<(), String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("PHASE3_FAILED: cannot read instruction {}: {error}", path.display()))?;
    *total = total.saturating_add(bytes.len());
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    let runtime_model_visible = prompt_output.map(|output| !trimmed.is_empty() && output.contains(trimmed));
    selected.push(InstructionEntry {
        path: path.to_path_buf(),
        scope: scope.into(),
        reason: reason.into(),
        bytes: bytes.len() as u64,
        sha256: sha256_bytes(&bytes),
        runtime_model_visible,
    });
    Ok(())
}

fn push_shadowed(
    path: &Path,
    scope: &str,
    reason: &str,
    shadowed: &mut Vec<InstructionEntry>,
) -> Result<(), String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("PHASE3_FAILED: cannot read instruction {}: {error}", path.display()))?;
    shadowed.push(InstructionEntry {
        path: path.to_path_buf(),
        scope: scope.into(),
        reason: reason.into(),
        bytes: bytes.len() as u64,
        sha256: sha256_bytes(&bytes),
        runtime_model_visible: Some(false),
    });
    Ok(())
}

fn verify_phase2_candidates(
    phase2: &Phase2Result,
    context: &RuntimeContext,
    layers: &[ParsedLayer],
    runtime: &[RuntimeDiagnostic],
) -> Result<Vec<Verdict>, String> {
    let mut verdicts = Vec::new();
    let plugin_json = diagnostic_json(runtime, "plugin list");
    let marketplace_json = diagnostic_json(runtime, "plugin marketplace list");

    for candidate in &phase2.candidates {
        let mut states = vec![VerificationState::Discovered];
        let mut details = Vec::<String>::new();
        if !candidate.exact_case {
            states.push(VerificationState::InvalidNameCase);
            details.push("Filename differs in case from the documented Linux filename.".into());
        }

        let location_ok = recognized_location(candidate, context, layers);
        if location_ok {
            states.push(VerificationState::LocationRecognized);
        }

        let syntax = validate_candidate(candidate, context, runtime)?;
        match syntax {
            Some(true) => states.push(VerificationState::SyntaxValid),
            Some(false) => states.push(VerificationState::SyntaxInvalid),
            None => {}
        }

        match candidate.kind {
            CandidateKind::AuthJson | CandidateKind::HistoryJsonl | CandidateKind::PetJson | CandidateKind::ConfigSchemaJson => {
                states.push(VerificationState::StateArtifact);
            }
            CandidateKind::PluginManifestJson => {
                match plugin_runtime_mentions(plugin_json.as_ref(), &candidate.path) {
                    Some(true) => states.push(VerificationState::RuntimeConfirmed),
                    Some(false) => states.push(VerificationState::RuntimeRejected),
                    None => states.push(VerificationState::RuntimeUnavailable),
                }
            }
            CandidateKind::MarketplaceJson => {
                match marketplace_runtime_mentions(marketplace_json.as_ref(), &candidate.path) {
                    Some(true) => states.push(VerificationState::RuntimeConfirmed),
                    Some(false) => states.push(VerificationState::RuntimeRejected),
                    None => states.push(VerificationState::RuntimeUnavailable),
                }
            }
            _ => {}
        }

        if states.contains(&VerificationState::LocationRecognized)
            && states.contains(&VerificationState::SyntaxValid)
            && !states.contains(&VerificationState::InvalidNameCase)
            && !states.contains(&VerificationState::StateArtifact)
        {
            states.push(VerificationState::Effective);
        }

        states.sort();
        states.dedup();
        verdicts.push(Verdict {
            subject: candidate.path.display().to_string(),
            kind: format!("{:?}", candidate.kind),
            states,
            details,
        });
    }

    Ok(verdicts)
}

fn recognized_location(candidate: &FileCandidate, context: &RuntimeContext, layers: &[ParsedLayer]) -> bool {
    match candidate.kind {
        CandidateKind::ConfigToml => layers.iter().any(|layer| layer.info.path == candidate.path),
        CandidateKind::ProfileConfigToml => candidate.path.parent() == Some(context.codex_home.as_path()),
        CandidateKind::AgentsMd | CandidateKind::AgentsOverrideMd => {
            candidate.path.parent() == Some(context.codex_home.as_path())
                || path_chain(&context.project_root, &context.cwd)
                    .iter()
                    .any(|directory| candidate.path.parent() == Some(directory.as_path()))
        }
        CandidateKind::HooksJson => {
            layers.iter().any(|layer| candidate.path.parent() == layer.info.path.parent())
        }
        CandidateKind::RuleFile => layers.iter().any(|layer| {
            layer.info.path.parent().is_some_and(|parent| candidate.path.parent() == Some(parent.join("rules").as_path()))
        }),
        CandidateKind::SkillMd | CandidateKind::SkillOpenAiYaml => is_under_skill_root(&candidate.path, context),
        CandidateKind::PluginManifestJson | CandidateKind::PluginHooksJson | CandidateKind::PluginAppJson | CandidateKind::PluginMcpJson => {
            candidate.path.ancestors().any(|ancestor| ancestor.file_name().is_some_and(|name| name == ".codex-plugin"))
                || candidate.path.ancestors().any(|ancestor| ancestor.join(".codex-plugin/plugin.json").is_file())
        }
        CandidateKind::RequirementsToml => true,
        CandidateKind::MarketplaceJson => candidate.path.ancestors().any(|ancestor| ancestor.ends_with(".agents/plugins")),
        CandidateKind::AuthJson | CandidateKind::HistoryJsonl | CandidateKind::PetJson | CandidateKind::ConfigSchemaJson => {
            candidate.path.starts_with(&context.codex_home)
        }
    }
}

fn is_under_skill_root(path: &Path, context: &RuntimeContext) -> bool {
    if path.starts_with("/etc/codex/skills") {
        return true;
    }
    if let Some(home) = &context.home {
        if path.starts_with(home.join(".agents/skills")) {
            return true;
        }
    }
    path_chain(&context.project_root, &context.cwd)
        .iter()
        .any(|directory| path.starts_with(directory.join(".agents/skills")))
        || path.ancestors().any(|ancestor| ancestor.join(".codex-plugin/plugin.json").is_file())
}

fn validate_candidate(
    candidate: &FileCandidate,
    context: &RuntimeContext,
    runtime: &[RuntimeDiagnostic],
) -> Result<Option<bool>, String> {
    match candidate.kind {
        CandidateKind::ConfigToml | CandidateKind::ProfileConfigToml | CandidateKind::RequirementsToml => {
            Ok(Some(parse_toml_file(&candidate.path)?.is_some()))
        }
        CandidateKind::HooksJson
        | CandidateKind::PluginHooksJson
        | CandidateKind::AuthJson
        | CandidateKind::PetJson
        | CandidateKind::ConfigSchemaJson
        | CandidateKind::MarketplaceJson
        | CandidateKind::PluginManifestJson
        | CandidateKind::PluginAppJson
        | CandidateKind::PluginMcpJson => {
            let text = fs::read_to_string(&candidate.path)
                .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", candidate.path.display()))?;
            Ok(Some(serde_json::from_str::<JsonValue>(&text).is_ok()))
        }
        CandidateKind::HistoryJsonl => {
            let text = fs::read_to_string(&candidate.path)
                .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", candidate.path.display()))?;
            Ok(Some(text.lines().filter(|line| !line.trim().is_empty()).all(|line| serde_json::from_str::<JsonValue>(line).is_ok())))
        }
        CandidateKind::AgentsMd | CandidateKind::AgentsOverrideMd => {
            let bytes = fs::read(&candidate.path)
                .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", candidate.path.display()))?;
            Ok(Some(!bytes.iter().all(u8::is_ascii_whitespace)))
        }
        CandidateKind::SkillMd => validate_skill_md(&candidate.path).map(Some),
        CandidateKind::SkillOpenAiYaml => {
            let text = fs::read_to_string(&candidate.path)
                .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", candidate.path.display()))?;
            Ok(Some(serde_yaml::from_str::<serde_yaml::Value>(&text).is_ok()))
        }
        CandidateKind::RuleFile => {
            let Some(binary) = context.codex_executable.as_deref() else { return Ok(None) };
            let output = run_output(
                binary,
                &["execpolicy", "check", "--rules", candidate.path.to_string_lossy().as_ref(), "--", "true"],
                Some(&context.cwd),
            );
            Ok(output.ok().map(|output| output.status.success()))
        }
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
    Ok(mapping.get(&name).and_then(serde_yaml::Value::as_str).is_some_and(|value| !value.trim().is_empty())
        && mapping.get(&description).and_then(serde_yaml::Value::as_str).is_some_and(|value| !value.trim().is_empty()))
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
        diagnostic(binary, "codex doctor --json", &["doctor", "--json"], &context.cwd),
        diagnostic(binary, "strict config doctor", &["--strict-config", "doctor", "--json"], &context.cwd),
        diagnostic(binary, "features list", &["features", "list"], &context.cwd),
        diagnostic(binary, "plugin list", &["plugin", "list", "--json"], &context.cwd),
        diagnostic(binary, "plugin marketplace list", &["plugin", "marketplace", "list", "--json"], &context.cwd),
        diagnostic(binary, "prompt input", &["debug", "prompt-input"], &context.cwd),
    ]
}

fn diagnostic(binary: &Path, name: &str, args: &[&str], cwd: &Path) -> RuntimeDiagnostic {
    match run_output(binary, args, Some(cwd)) {
        Ok(output) => RuntimeDiagnostic {
            name: name.into(),
            command: std::iter::once(binary.display().to_string()).chain(args.iter().map(|value| (*value).to_owned())).collect(),
            success: output.status.success(),
            exit_code: output.status.code(),
            stdout: truncate_output(&output.stdout),
            stderr: truncate_output(&output.stderr),
        },
        Err(error) => RuntimeDiagnostic {
            name: name.into(),
            command: std::iter::once(binary.display().to_string()).chain(args.iter().map(|value| (*value).to_owned())).collect(),
            success: false,
            exit_code: None,
            stdout: String::new(),
            stderr: error,
        },
    }
}

fn diagnostic_json(diagnostics: &[RuntimeDiagnostic], name: &str) -> Option<JsonValue> {
    diagnostics
        .iter()
        .find(|diagnostic| diagnostic.name == name && diagnostic.success)
        .and_then(|diagnostic| serde_json::from_str(&diagnostic.stdout).ok())
}

fn extract_runtime_active_paths(value: &JsonValue) -> BTreeSet<PathBuf> {
    let mut result = BTreeSet::new();
    visit_json(value, &mut |object| {
        let active = object
            .get("active")
            .or_else(|| object.get("enabled"))
            .or_else(|| object.get("on"))
            .and_then(JsonValue::as_bool)
            .unwrap_or(false);
        if active {
            if let Some(path) = object
                .get("path")
                .or_else(|| object.get("config_path"))
                .and_then(JsonValue::as_str)
            {
                result.insert(PathBuf::from(path));
            }
        }
    });
    result
}

fn plugin_runtime_mentions(value: Option<&JsonValue>, path: &Path) -> Option<bool> {
    let value = value?;
    let root = plugin_root_for(path)?;
    let needle = root.to_string_lossy();
    Some(value.to_string().contains(needle.as_ref()))
}

fn marketplace_runtime_mentions(value: Option<&JsonValue>, path: &Path) -> Option<bool> {
    let value = value?;
    let root = path.parent()?.to_string_lossy();
    Some(value.to_string().contains(root.as_ref()))
}

fn plugin_root_for(path: &Path) -> Option<&Path> {
    path.ancestors().find(|ancestor| ancestor.join(".codex-plugin/plugin.json").is_file())
}

fn visit_json(value: &JsonValue, callback: &mut impl FnMut(&serde_json::Map<String, JsonValue>)) {
    match value {
        JsonValue::Object(object) => {
            callback(object);
            for child in object.values() {
                visit_json(child, callback);
            }
        }
        JsonValue::Array(values) => {
            for child in values {
                visit_json(child, callback);
            }
        }
        _ => {}
    }
}

fn add_instruction_verdicts(chain: &InstructionChain, verdicts: &mut Vec<Verdict>) {
    for entry in &chain.selected {
        let mut states = vec![VerificationState::Discovered, VerificationState::LocationRecognized, VerificationState::SyntaxValid, VerificationState::Selected];
        match entry.runtime_model_visible {
            Some(true) => {
                states.push(VerificationState::RuntimeConfirmed);
                states.push(VerificationState::Effective);
            }
            Some(false) => states.push(VerificationState::RuntimeRejected),
            None => states.push(VerificationState::RuntimeUnavailable),
        }
        verdicts.push(Verdict {
            subject: entry.path.display().to_string(),
            kind: "instruction_chain".into(),
            states,
            details: vec![entry.reason.clone()],
        });
    }
    for entry in &chain.shadowed {
        verdicts.push(Verdict {
            subject: entry.path.display().to_string(),
            kind: "instruction_chain".into(),
            states: vec![VerificationState::Discovered, VerificationState::Shadowed],
            details: vec![entry.reason.clone()],
        });
    }
}

fn add_dynamic_target_verdicts(targets: &[DynamicTarget], verdicts: &mut Vec<Verdict>) {
    for target in targets {
        let mut states = vec![VerificationState::Discovered];
        if target.exists {
            if target.syntax_valid == Some(true) {
                states.push(VerificationState::SyntaxValid);
            } else if target.syntax_valid == Some(false) {
                states.push(VerificationState::SyntaxInvalid);
            }
            if !target.present_in_phase2 {
                states.push(VerificationState::Phase2DiscoveryMiss);
            }
        }
        verdicts.push(Verdict {
            subject: target.resolved_path.display().to_string(),
            kind: "dynamic_config_target".into(),
            states,
            details: vec![format!("Resolved from {} in {}", target.config_key, target.source_config.display())],
        });
    }
}

fn add_phase1_miss_verdicts(phase1: &Phase1Verification, verdicts: &mut Vec<Verdict>) {
    for path in &phase1.required_roots_not_discovered {
        verdicts.push(Verdict {
            subject: path.display().to_string(),
            kind: "required_codex_root".into(),
            states: vec![VerificationState::Phase1DiscoveryMiss],
            details: vec!["Official/runtime-derived Codex root exists but was not returned by Phase 1 name discovery.".into()],
        });
    }
}

fn parse_toml_file(path: &Path) -> Result<Option<TomlValue>, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", path.display()))?;
    Ok(text.parse::<TomlValue>().ok())
}

fn resolve_from_config(config_path: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        config_path.parent().unwrap_or_else(|| Path::new(".")).join(path)
    }
}

fn path_chain(root: &Path, cwd: &Path) -> Vec<PathBuf> {
    if !cwd.starts_with(root) {
        return vec![cwd.to_path_buf()];
    }
    let mut values = Vec::<PathBuf>::new();
    let mut current = cwd.to_path_buf();
    loop {
        values.push(current.clone());
        if current == root {
            break;
        }
        let Some(parent) = current.parent() else { break };
        current = parent.to_path_buf();
    }
    values.reverse();
    values
}

fn find_project_root(cwd: &Path) -> Option<PathBuf> {
    let output = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !path.is_empty() {
            return Some(PathBuf::from(path));
        }
    }
    cwd.ancestors().find(|ancestor| ancestor.join(".git").exists()).map(Path::to_path_buf)
}

fn detect_selected_profile() -> Option<String> {
    if let Some(value) = env::var_os("CODEX_PROFILE") {
        let value = value.to_string_lossy().trim().to_owned();
        if !value.is_empty() {
            return Some(value);
        }
    }
    let args = env::args().collect::<Vec<_>>();
    for index in 0..args.len() {
        if args[index] == "--profile" || args[index] == "-p" {
            if let Some(value) = args.get(index + 1) {
                return Some(value.clone());
            }
        }
        if let Some(value) = args[index].strip_prefix("--profile=") {
            return Some(value.to_owned());
        }
    }
    None
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}

fn command_text(program: &str, args: &[&str], cwd: Option<&Path>) -> Option<String> {
    let output = run_output(Path::new(program), args, cwd).ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn run_output(program: &Path, args: &[&str], cwd: Option<&Path>) -> Result<Output, String> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.output().map_err(|error| format!("failed to execute {}: {error}", program.display()))
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

#[cfg(test)]
mod tests {
    use super::{path_chain, resolve_from_config};
    use std::path::Path;

    #[test]
    fn project_chain_runs_root_to_cwd() {
        let values = path_chain(Path::new("/repo"), Path::new("/repo/a/b"));
        assert_eq!(values, vec![Path::new("/repo"), Path::new("/repo/a"), Path::new("/repo/a/b")]);
    }

    #[test]
    fn relative_dynamic_paths_resolve_from_declaring_config() {
        let value = resolve_from_config(Path::new("/repo/.codex/config.toml"), "agents/reviewer.toml");
        assert_eq!(value, Path::new("/repo/.codex/agents/reviewer.toml"));
    }
}
