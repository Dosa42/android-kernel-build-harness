use super::{
    InstructionChain, InstructionEntry, ProjectTrust, RuntimeContext, Verdict, VerificationState,
};
use crate::scanner::app_server_probe::AppServerSnapshot;
use crate::scanner::phase2::{candidate_by_path, Phase2Result};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_PROJECT_DOC_MAX_BYTES: usize = 32 * 1024;

pub(super) fn build(
    context: &RuntimeContext,
    app_server: &AppServerSnapshot,
    prompt_json: Option<&JsonValue>,
) -> Result<InstructionChain, String> {
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

    let mut global = Vec::new();
    let mut project = Vec::new();
    let mut shadowed = Vec::new();

    // Codex home: AGENTS.override.md first, then AGENTS.md. Only the first
    // non-empty file at this level is loaded.
    let global_candidates = [
        context.codex_home.join("AGENTS.override.md"),
        context.codex_home.join("AGENTS.md"),
    ];
    if let Some(selected) = first_nonempty(&global_candidates)? {
        global.push(read_entry(
            &selected,
            "global",
            None,
            "first non-empty Codex-home instruction file",
            prompt_json,
        )?);
        for candidate in global_candidates {
            if candidate != selected && candidate.is_file() {
                shadowed.push(read_entry(
                    &candidate,
                    "global",
                    Some(0),
                    "not selected because an earlier Codex-home filename won",
                    prompt_json,
                )?);
            }
        }
    }

    // The project byte budget applies to project docs only; global user
    // instructions do not consume project_doc_max_bytes.
    let mut remaining = project_doc_max_bytes;
    if context.project_trust != ProjectTrust::Untrusted {
        for directory in super::runtime::path_chain(&context.project_root, &context.cwd) {
            if remaining == 0 {
                break;
            }

            let mut candidates = vec![directory.join("AGENTS.override.md"), directory.join("AGENTS.md")];
            candidates.extend(fallback_filenames.iter().map(|name| directory.join(name)));

            if let Some(selected) = first_nonempty(&candidates)? {
                let size = fs::metadata(&selected)
                    .map_err(|error| format!("PHASE3_FAILED: cannot stat {}: {error}", selected.display()))?
                    .len() as usize;
                let selected_bytes = size.min(remaining);
                project.push(read_entry(
                    &selected,
                    "project",
                    Some(selected_bytes),
                    "first non-empty instruction filename at this project directory level",
                    prompt_json,
                )?);
                remaining = remaining.saturating_sub(selected_bytes);

                for candidate in candidates {
                    if candidate != selected && candidate.is_file() {
                        shadowed.push(read_entry(
                            &candidate,
                            "project",
                            Some(0),
                            "shadowed by an earlier filename at the same directory level",
                            prompt_json,
                        )?);
                    }
                }
            }
        }
    }

    Ok(InstructionChain {
        project_trust: context.project_trust,
        fallback_filenames,
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

fn read_entry(
    path: &Path,
    scope: &str,
    selected_bytes: Option<usize>,
    reason: &str,
    prompt_json: Option<&JsonValue>,
) -> Result<InstructionEntry, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("PHASE3_FAILED: cannot read instruction {}: {error}", path.display()))?;
    let count = selected_bytes.unwrap_or(bytes.len()).min(bytes.len());
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

pub(super) fn add_missing_discovery_verdicts(
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
                kind: "instruction_chain_discovery_miss".into(),
                states,
                details: vec![entry.reason.clone()],
            });
        }
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

/// A positive match is strong runtime evidence. A negative match is intentionally
/// not treated as proof of absence by the verifier because debug output shape may
/// vary by installed Codex version.
pub(super) fn json_contains_text(value: &JsonValue, needle: &str) -> bool {
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

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
