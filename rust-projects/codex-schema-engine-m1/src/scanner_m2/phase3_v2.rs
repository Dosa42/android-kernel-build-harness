#[path = "phase3_final/dynamic.rs"]
mod dynamic;
#[path = "phase3_final/files.rs"]
mod files;
#[path = "phase3_final/instructions.rs"]
mod instructions;
#[path = "phase3_final/runtime.rs"]
mod runtime;

use super::app_server_probe::AppServerSnapshot;
use super::phase2::Phase2Result;
use super::Phase1Result;
use serde::Serialize;
use serde_json::Value as JsonValue;
use std::path::{Path, PathBuf};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

pub(crate) fn verify(phase1: &Phase1Result, phase2: &Phase2Result) -> Result<Phase3Result, String> {
    let (context, app_server, config_layers) = runtime::capture()?;
    let runtime_diagnostics = runtime::collect_diagnostics(&context);
    let prompt_json = runtime::diagnostic_json(&runtime_diagnostics, "prompt input");
    let phase1_verification = runtime::verify_phase1(phase1, &context, &config_layers);

    let instruction_chain = instructions::build(&context, &app_server, prompt_json.as_ref())?;
    let dynamic_targets = dynamic::collect_and_verify(&app_server, &config_layers, phase2);

    let mut verdicts = Vec::<Verdict>::new();
    runtime::add_phase1_verdicts(&phase1_verification, &mut verdicts);
    runtime::add_config_layer_verdicts(&config_layers, phase2, &mut verdicts);
    files::verify_candidates(
        phase2,
        &context,
        &app_server,
        &config_layers,
        &instruction_chain,
        &mut verdicts,
    )?;
    instructions::add_missing_discovery_verdicts(&instruction_chain, phase2, &mut verdicts);
    dynamic::add_verdicts(&dynamic_targets, &mut verdicts);
    reconcile_runtime_config_verdicts(&config_layers, &mut verdicts);

    verdicts.sort_by(|left, right| {
        left.subject
            .cmp(&right.subject)
            .then(left.kind.cmp(&right.kind))
    });

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

fn reconcile_runtime_config_verdicts(
    layers: &[RuntimeConfigLayer],
    verdicts: &mut [Verdict],
) {
    for verdict in verdicts.iter_mut().filter(|verdict| {
        verdict.kind == "ConfigToml" || verdict.kind == "ProfileConfigToml"
    }) {
        let path = Path::new(&verdict.subject);
        let Some(layer) = layers
            .iter()
            .find(|layer| layer.source_path.as_deref() == Some(path))
        else {
            continue;
        };
        if layer.active
            && verdict.states.contains(&VerificationState::SyntaxValid)
            && !verdict.states.contains(&VerificationState::InvalidNameCase)
        {
            verdict.states.push(VerificationState::RuntimeConfirmed);
            verdict.states.push(VerificationState::LayerActive);
            verdict.states.push(VerificationState::Effective);
            if verdict.states.contains(&VerificationState::SchemaInvalid) {
                verdict.details.push(
                    "Installed Codex runtime loaded this active layer; embedded current-schema disagreement is reported separately as version/schema skew."
                        .into(),
                );
            }
            normalize_states(&mut verdict.states);
        }
    }
}

fn normalize_states(states: &mut Vec<VerificationState>) {
    states.sort();
    states.dedup();
}
