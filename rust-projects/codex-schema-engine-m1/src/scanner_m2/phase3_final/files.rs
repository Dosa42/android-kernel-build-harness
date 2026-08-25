use super::{
    InstructionChain, ProjectTrust, RuntimeConfigLayer, RuntimeContext, Verdict, VerificationState,
};
use crate::scanner::app_server_probe::AppServerSnapshot;
use crate::scanner::phase2::{CandidateKind, FileCandidate, Phase2Result};
use crate::scanner::schema_check;
use serde_json::Value as JsonValue;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn verify_candidates(
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
                verify_config(candidate, layers, &mut states, &mut details);
            }
            CandidateKind::AgentsMd | CandidateKind::AgentsOverrideMd => {
                verify_agents(candidate, context, chain, &mut states, &mut details)?;
            }
            CandidateKind::SkillMd => {
                verify_skill(candidate, snapshot, &mut states, &mut details)?;
            }
            CandidateKind::SkillOpenAiYaml => {
                verify_skill_yaml(candidate, snapshot, &mut states, &mut details)?;
            }
            CandidateKind::HooksJson | CandidateKind::PluginHooksJson => {
                verify_hooks(candidate, snapshot, &mut states, &mut details)?;
            }
            CandidateKind::RuleFile => {
                verify_rule(candidate, context, layers, &mut states, &mut details);
            }
            CandidateKind::RequirementsToml => {
                verify_requirements(candidate, context, snapshot, &mut states, &mut details);
            }
            CandidateKind::MarketplaceJson => {
                verify_marketplace(candidate, snapshot, &mut states, &mut details)?;
            }
            CandidateKind::PluginManifestJson => {
                verify_plugin_manifest(candidate, snapshot, &mut states, &mut details)?;
            }
            CandidateKind::PluginAppJson | CandidateKind::PluginMcpJson => {
                verify_plugin_aux(candidate, snapshot, &mut states, &mut details)?;
            }
            CandidateKind::AuthJson
            | CandidateKind::HistoryJsonl
            | CandidateKind::PetJson
            | CandidateKind::ConfigSchemaJson => {
                verify_state_reference(candidate, context, &mut states, &mut details)?;
            }
        }

        super::normalize_states(&mut states);
        verdicts.push(Verdict {
            subject: candidate.path.display().to_string(),
            kind: format!("{:?}", candidate.kind),
            states,
            details,
        });
    }
    Ok(())
}

fn verify_config(
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
        details.push(format!(
            "runtime_layer_order={} source={}",
            layer.runtime_order, layer.source_type
        ));
        if let Some(reason) = &layer.disabled_reason {
            details.push(format!("disabledReason={reason}"));
        }
    }

    match super::runtime::parse_toml(&candidate.path) {
        Ok(value) => {
            states.push(VerificationState::SyntaxValid);
            let check = schema_check::validate_config(&value);
            if check.valid {
                states.push(VerificationState::SchemaValid);
                if candidate.exact_case && runtime_layer.is_some_and(|layer| layer.active) {
                    states.push(VerificationState::Effective);
                }
            } else {
                states.push(VerificationState::SchemaInvalid);
                details.extend(check.errors.into_iter().take(20));
            }
        }
        Err(error) => {
            states.push(VerificationState::SyntaxInvalid);
            details.push(error);
        }
    }
}

fn verify_agents(
    candidate: &FileCandidate,
    context: &RuntimeContext,
    chain: &InstructionChain,
    states: &mut Vec<VerificationState>,
    details: &mut Vec<String>,
) -> Result<(), String> {
    let bytes = fs::read(&candidate.path)
        .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", candidate.path.display()))?;
    if String::from_utf8_lossy(&bytes).trim().is_empty() {
        states.push(VerificationState::SyntaxInvalid);
    } else {
        states.push(VerificationState::SyntaxValid);
    }

    let selected = chain
        .global
        .iter()
        .chain(chain.project.iter())
        .find(|entry| entry.path == candidate.path);
    let shadowed = chain.shadowed.iter().find(|entry| entry.path == candidate.path);

    if candidate.path.parent() == Some(context.codex_home.as_path())
        || super::runtime::path_chain(&context.project_root, &context.cwd)
            .iter()
            .any(|directory| candidate.path.parent() == Some(directory.as_path()))
    {
        states.push(VerificationState::LocationRecognized);
    }

    if let Some(entry) = selected {
        states.push(VerificationState::Selected);
        if entry.truncated {
            states.push(VerificationState::Truncated);
        }
        if entry.scope == "project" {
            match context.project_trust {
                ProjectTrust::Trusted => states.push(VerificationState::TrustConfirmed),
                ProjectTrust::Untrusted => states.push(VerificationState::TrustRejected),
                ProjectTrust::Unknown => states.push(VerificationState::TrustUnknown),
            }
        } else {
            states.push(VerificationState::TrustConfirmed);
        }

        // Positive prompt-input observation is extra proof. A negative substring
        // observation is not treated as proof of absence because output shape can
        // differ across installed Codex versions.
        if entry.runtime_model_visible == Some(true) {
            states.push(VerificationState::RuntimeConfirmed);
        } else if entry.runtime_model_visible.is_none() {
            states.push(VerificationState::RuntimeUnavailable);
        } else {
            details.push("Selected text was not positively matched in debug prompt-input; this is not treated as a rejection.".into());
        }

        let effective = if entry.scope == "global" {
            true
        } else {
            match context.project_trust {
                ProjectTrust::Trusted => true,
                ProjectTrust::Untrusted => false,
                ProjectTrust::Unknown => entry.runtime_model_visible == Some(true),
            }
        };
        if effective && candidate.exact_case {
            states.push(VerificationState::Effective);
        }
    } else if shadowed.is_some() {
        states.push(VerificationState::Shadowed);
    } else if candidate.path.starts_with(&context.project_root)
        && context.project_trust == ProjectTrust::Untrusted
    {
        states.push(VerificationState::TrustRejected);
        details.push("Project instructions are suppressed for the untrusted active project.".into());
    }

    Ok(())
}

fn verify_skill(
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

    if let Some(skill) = runtime_skill(snapshot, &candidate.path) {
        states.push(VerificationState::LocationRecognized);
        states.push(VerificationState::RuntimeConfirmed);
        let enabled = skill.get("enabled").and_then(JsonValue::as_bool).unwrap_or(false);
        if let Some(scope) = skill.get("scope").and_then(JsonValue::as_str) {
            details.push(format!("runtime_scope={scope}"));
        }
        if let Some(plugin_id) = skill.get("pluginId").and_then(JsonValue::as_str) {
            details.push(format!("runtime_plugin_id={plugin_id}"));
        }
        if enabled && valid && candidate.exact_case {
            states.push(VerificationState::Effective);
        } else if !enabled {
            states.push(VerificationState::RuntimeRejected);
        }
    } else {
        states.push(if snapshot.skills_list.is_some() {
            VerificationState::RuntimeRejected
        } else {
            VerificationState::RuntimeUnavailable
        });
    }
    Ok(())
}

fn verify_skill_yaml(
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
            details.push(format!("associated_skill={}", skill_md.display()));
            if valid
                && candidate.exact_case
                && skill.get("enabled").and_then(JsonValue::as_bool) == Some(true)
            {
                states.push(VerificationState::Effective);
            }
        } else if snapshot.skills_list.is_some() {
            states.push(VerificationState::RuntimeRejected);
        } else {
            states.push(VerificationState::RuntimeUnavailable);
        }
    }
    Ok(())
}

fn runtime_skill<'a>(snapshot: &'a AppServerSnapshot, path: &Path) -> Option<&'a JsonValue> {
    let entries = snapshot.skills_entries()?;
    for entry in entries {
        let Some(skills) = entry.get("skills").and_then(JsonValue::as_array) else {
            continue;
        };
        for skill in skills {
            if skill
                .get("path")
                .and_then(JsonValue::as_str)
                .is_some_and(|value| Path::new(value) == path)
            {
                return Some(skill);
            }
        }
    }
    None
}

fn verify_hooks(
    candidate: &FileCandidate,
    snapshot: &AppServerSnapshot,
    states: &mut Vec<VerificationState>,
    details: &mut Vec<String>,
) -> Result<(), String> {
    let text = fs::read_to_string(&candidate.path)
        .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", candidate.path.display()))?;
    let valid_json = serde_json::from_str::<JsonValue>(&text).is_ok();
    states.push(if valid_json {
        VerificationState::SyntaxValid
    } else {
        VerificationState::SyntaxInvalid
    });

    let hooks = runtime_hooks_for_source(snapshot, &candidate.path);
    if hooks.is_empty() {
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
    for hook in hooks {
        let enabled = hook.get("enabled").and_then(JsonValue::as_bool).unwrap_or(false);
        let managed = hook.get("isManaged").and_then(JsonValue::as_bool).unwrap_or(false);
        let trust = hook
            .get("trustStatus")
            .and_then(JsonValue::as_str)
            .unwrap_or("unknown");
        let trust_lower = trust.to_ascii_lowercase();
        if managed {
            states.push(VerificationState::ManagedPolicyPresent);
        }
        if enabled && (managed || trust_lower == "trusted" || trust_lower == "managed") {
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

    if valid_json && any_effective && candidate.exact_case {
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

fn verify_rule(
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
        .and_then(|config| {
            layers
                .iter()
                .find(|layer| layer.source_path.as_deref() == Some(config))
        })
        .filter(|layer| layer.active);
    if active_layer.is_some() {
        states.push(VerificationState::LocationRecognized);
        states.push(VerificationState::LayerActive);
    }

    let Some(binary) = context.codex_executable.as_deref() else {
        states.push(VerificationState::RuntimeUnavailable);
        return;
    };
    let rule_path = candidate.path.to_string_lossy().to_string();
    match super::runtime::run_output(
        binary,
        &["execpolicy", "check", "--rules", &rule_path, "true"],
        Some(&context.cwd),
    ) {
        Ok(output) if output.status.success() => {
            states.push(VerificationState::SyntaxValid);
            states.push(VerificationState::RuntimeConfirmed);
            if active_layer.is_some() && candidate.exact_case {
                states.push(VerificationState::Effective);
            }
            let stdout = super::runtime::truncate_output(&output.stdout);
            if !stdout.trim().is_empty() {
                details.push(format!("execpolicy_check={}", stdout.trim()));
            }
        }
        Ok(output) => {
            states.push(VerificationState::SyntaxInvalid);
            states.push(VerificationState::RuntimeRejected);
            details.push(super::runtime::truncate_output(&output.stderr));
        }
        Err(error) => {
            states.push(VerificationState::RuntimeUnavailable);
            details.push(error);
        }
    }
}

fn verify_requirements(
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

    match super::runtime::parse_toml(&candidate.path) {
        Ok(_) => states.push(VerificationState::SyntaxValid),
        Err(error) => {
            states.push(VerificationState::SyntaxInvalid);
            details.push(error);
        }
    }

    if snapshot.requirements().is_some_and(|value| !value.is_null()) {
        states.push(VerificationState::ManagedPolicyPresent);
        states.push(VerificationState::RuntimeConfirmed);
        details.push("configRequirements/read confirms managed requirements are active, but does not uniquely attribute them to this physical file when multiple managed sources exist.".into());
    } else if snapshot.config_requirements_read.is_some() {
        states.push(VerificationState::RuntimeRejected);
    } else {
        states.push(VerificationState::RuntimeUnavailable);
    }
}

fn verify_marketplace(
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
    let manifest = match serde_json::from_str::<JsonValue>(&text) {
        Ok(value) => {
            states.push(VerificationState::SyntaxValid);
            value
        }
        Err(error) => {
            states.push(VerificationState::SyntaxInvalid);
            details.push(error.to_string());
            return Ok(());
        }
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
        details.push(format!("runtime_installed={installed} runtime_enabled={enabled}"));
        if installed && enabled && candidate.exact_case {
            states.push(VerificationState::Effective);
        } else {
            states.push(VerificationState::RuntimeRejected);
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

fn verify_plugin_aux(
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
        if let Ok(manifest_text) = fs::read_to_string(&manifest_path) {
            if let Ok(manifest) = serde_json::from_str::<JsonValue>(&manifest_text) {
                if let Some(plugin) = runtime_plugin_for_manifest(snapshot, &root, &manifest) {
                    states.push(VerificationState::LocationRecognized);
                    states.push(VerificationState::RuntimeConfirmed);
                    let installed = plugin.get("installed").and_then(JsonValue::as_bool) == Some(true);
                    let enabled = plugin.get("enabled").and_then(JsonValue::as_bool) == Some(true);
                    if valid && candidate.exact_case && installed && enabled {
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
        let market_path = marketplace
            .get("path")
            .and_then(JsonValue::as_str)
            .map(PathBuf::from);
        let market_directory = market_path.as_deref().and_then(Path::parent);
        let location_related = market_directory.is_some_and(|directory| {
            root.starts_with(directory) || directory.starts_with(root)
        });
        let Some(plugins) = marketplace.get("plugins").and_then(JsonValue::as_array) else {
            continue;
        };
        for plugin in plugins {
            if super::instructions::json_contains_text(plugin, root_text.as_ref()) {
                return Some(plugin);
            }
            let id_match = manifest_id.is_some_and(|id| {
                plugin.get("id").and_then(JsonValue::as_str) == Some(id)
            });
            let name_match = manifest_name.is_some_and(|name| {
                plugin.get("name").and_then(JsonValue::as_str) == Some(name)
            });
            if location_related && (id_match || name_match) {
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

fn verify_state_reference(
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
    details.push("State/reference artifact: not an effective configuration layer.".into());
    Ok(())
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
