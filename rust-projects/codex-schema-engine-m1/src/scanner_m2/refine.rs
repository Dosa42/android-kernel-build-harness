use super::phase2::{CandidateKind, Phase2Result};
use super::phase3::{Activation, ConfigLayer, Phase3Result, RuntimeDiagnostic, VerificationState};
use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use toml::Value as TomlValue;

/// Removes generic "parseable + plausible location == effective" conclusions and
/// reapplies EFFECTIVE only when the protocol for that artifact type supports it.
pub(crate) fn refine(result: &mut Phase3Result, phase2: &Phase2Result) {
    let candidate_kinds = phase2
        .candidates
        .iter()
        .map(|candidate| (candidate.path.display().to_string(), candidate.kind))
        .collect::<BTreeMap<_, _>>();

    let hooks_feature = feature_state(&result.runtime_diagnostics, "hooks");
    let doctor = diagnostic_json(&result.runtime_diagnostics, "codex doctor --json");
    let plugins = diagnostic_json(&result.runtime_diagnostics, "plugin list");
    let marketplaces = diagnostic_json(&result.runtime_diagnostics, "plugin marketplace list");
    let plugin_roots = enabled_plugin_roots(plugins.as_ref());
    let marketplace_roots = runtime_marketplace_roots(marketplaces.as_ref());
    let disabled_skills = disabled_skill_paths(&result.config_layers);

    for verdict in &mut result.verdicts {
        let Some(kind) = candidate_kinds.get(&verdict.subject).copied() else {
            continue;
        };

        verdict.states.retain(|state| *state != VerificationState::Effective);
        let path = Path::new(&verdict.subject);
        let syntax_ok = verdict.states.contains(&VerificationState::SyntaxValid);
        let location_ok = verdict.states.contains(&VerificationState::LocationRecognized);
        let name_ok = !verdict.states.contains(&VerificationState::InvalidNameCase);

        match kind {
            CandidateKind::ConfigToml | CandidateKind::ProfileConfigToml => {
                if let Some(layer) = config_layer_for(path, &result.config_layers) {
                    apply_layer_state(verdict, layer);
                    if syntax_ok
                        && name_ok
                        && matches!(layer.activation, Activation::Active | Activation::RuntimeConfirmed)
                        && layer.version_valid != Some(false)
                    {
                        push_state(&mut verdict.states, VerificationState::Effective);
                    }
                }
            }
            CandidateKind::AgentsMd | CandidateKind::AgentsOverrideMd => {
                // Selection/effectiveness is decided by the separate instruction-chain
                // verdict, which can be cross-checked with `codex debug prompt-input`.
            }
            CandidateKind::HooksJson => {
                refine_hook(
                    verdict,
                    path,
                    syntax_ok,
                    location_ok,
                    name_ok,
                    hooks_feature,
                    &result.config_layers,
                    doctor.as_ref(),
                    false,
                );
            }
            CandidateKind::PluginHooksJson => {
                let plugin_enabled = plugin_root_for(path)
                    .is_some_and(|root| plugin_roots.contains(&root));
                if plugin_enabled {
                    push_state(&mut verdict.states, VerificationState::RuntimeConfirmed);
                } else if plugins.is_some() {
                    push_state(&mut verdict.states, VerificationState::RuntimeRejected);
                } else {
                    push_state(&mut verdict.states, VerificationState::RuntimeUnavailable);
                }
                refine_hook(
                    verdict,
                    path,
                    syntax_ok,
                    location_ok && plugin_enabled,
                    name_ok,
                    hooks_feature,
                    &result.config_layers,
                    doctor.as_ref(),
                    true,
                );
            }
            CandidateKind::RuleFile => {
                refine_rule(verdict, path, syntax_ok, name_ok, &result.config_layers);
            }
            CandidateKind::SkillMd => {
                let plugin_ok = plugin_root_for(path).map(|root| plugin_roots.contains(&root));
                let enabled = !disabled_skills.contains(path);
                if syntax_ok && location_ok && name_ok && enabled && plugin_ok != Some(false) {
                    if plugin_ok == Some(true) {
                        push_state(&mut verdict.states, VerificationState::RuntimeConfirmed);
                    }
                    push_state(&mut verdict.states, VerificationState::Effective);
                }
                if !enabled {
                    push_state(&mut verdict.states, VerificationState::LayerInactive);
                    verdict.details.push("Disabled by an active [[skills.config]] entry.".into());
                }
            }
            CandidateKind::SkillOpenAiYaml => {
                let skill_root = path.parent().and_then(Path::parent);
                let skill_md = skill_root.map(|root| root.join("SKILL.md"));
                let enabled = skill_md
                    .as_deref()
                    .is_some_and(|skill| skill.is_file() && !disabled_skills.contains(skill));
                let plugin_ok = plugin_root_for(path).map(|root| plugin_roots.contains(&root));
                if syntax_ok && location_ok && name_ok && enabled && plugin_ok != Some(false) {
                    if plugin_ok == Some(true) {
                        push_state(&mut verdict.states, VerificationState::RuntimeConfirmed);
                    }
                    push_state(&mut verdict.states, VerificationState::Effective);
                }
            }
            CandidateKind::PluginManifestJson => {
                if let Some(root) = plugin_root_for(path) {
                    if plugin_roots.contains(&root) && syntax_ok && name_ok {
                        push_state(&mut verdict.states, VerificationState::RuntimeConfirmed);
                        push_state(&mut verdict.states, VerificationState::Effective);
                    } else if plugins.is_some() {
                        push_state(&mut verdict.states, VerificationState::RuntimeRejected);
                    }
                }
            }
            CandidateKind::PluginAppJson | CandidateKind::PluginMcpJson => {
                if plugin_root_for(path).is_some_and(|root| plugin_roots.contains(&root))
                    && syntax_ok
                    && location_ok
                    && name_ok
                {
                    push_state(&mut verdict.states, VerificationState::RuntimeConfirmed);
                    push_state(&mut verdict.states, VerificationState::Effective);
                }
            }
            CandidateKind::MarketplaceJson => {
                let root = path.parent().unwrap_or_else(|| Path::new("/"));
                if marketplace_roots.iter().any(|runtime_root| {
                    runtime_root == root || runtime_root.starts_with(root) || root.starts_with(runtime_root)
                }) && syntax_ok && name_ok
                {
                    push_state(&mut verdict.states, VerificationState::RuntimeConfirmed);
                    push_state(&mut verdict.states, VerificationState::Effective);
                } else if marketplaces.is_some() {
                    push_state(&mut verdict.states, VerificationState::RuntimeRejected);
                }
            }
            CandidateKind::RequirementsToml => {
                if syntax_ok && name_ok && json_mentions_path(doctor.as_ref(), path) {
                    push_state(&mut verdict.states, VerificationState::RuntimeConfirmed);
                    push_state(&mut verdict.states, VerificationState::Effective);
                } else if doctor.is_some() {
                    push_state(&mut verdict.states, VerificationState::RuntimeRejected);
                } else {
                    push_state(&mut verdict.states, VerificationState::RuntimeUnavailable);
                }
            }
            CandidateKind::AuthJson
            | CandidateKind::HistoryJsonl
            | CandidateKind::PetJson
            | CandidateKind::ConfigSchemaJson => {
                // State/reference artifacts are deliberately never promoted to
                // effective configuration by this verifier.
            }
        }

        verdict.states.sort();
        verdict.states.dedup();
    }

    refine_config_layer_verdicts(result);
    refine_dynamic_targets(result);
}

fn refine_config_layer_verdicts(result: &mut Phase3Result) {
    for verdict in result.verdicts.iter_mut().filter(|verdict| verdict.kind == "config_layer") {
        verdict.states.retain(|state| *state != VerificationState::Effective);
        let path = Path::new(&verdict.subject);
        let Some(layer) = config_layer_for(path, &result.config_layers) else { continue };
        if layer.syntax_valid
            && layer.version_valid != Some(false)
            && matches!(layer.activation, Activation::Active | Activation::RuntimeConfirmed)
        {
            push_state(&mut verdict.states, VerificationState::Effective);
        }
    }
}

fn refine_dynamic_targets(result: &mut Phase3Result) {
    for target in &result.dynamic_targets {
        let source_active = config_layer_for(&target.source_config, &result.config_layers)
            .is_some_and(|layer| matches!(layer.activation, Activation::Active | Activation::RuntimeConfirmed));
        if !source_active || !target.exists || target.syntax_valid != Some(true) {
            continue;
        }
        let target_subject = target.resolved_path.display().to_string();
        for verdict in result
            .verdicts
            .iter_mut()
            .filter(|verdict| verdict.kind == "dynamic_config_target" && verdict.subject == target_subject)
        {
            push_state(&mut verdict.states, VerificationState::LocationRecognized);
            push_state(&mut verdict.states, VerificationState::LayerActive);
            push_state(&mut verdict.states, VerificationState::Effective);
            verdict.states.sort();
            verdict.states.dedup();
        }
    }
}

fn refine_hook(
    verdict: &mut super::phase3::Verdict,
    path: &Path,
    syntax_ok: bool,
    location_ok: bool,
    name_ok: bool,
    hooks_feature: Option<bool>,
    layers: &[ConfigLayer],
    doctor: Option<&JsonValue>,
    plugin_hook: bool,
) {
    if hooks_feature == Some(false) {
        push_state(&mut verdict.states, VerificationState::LayerInactive);
        verdict.details.push("The installed Codex runtime reports the hooks feature disabled.".into());
        return;
    }

    let source_active = if plugin_hook {
        location_ok
    } else {
        active_layer_for_adjacent_file(path, layers).is_some()
    };
    if source_active {
        push_state(&mut verdict.states, VerificationState::LayerActive);
    }

    let trust = hook_trust_from_doctor(doctor, path);
    match trust {
        Some(true) => push_state(&mut verdict.states, VerificationState::RuntimeConfirmed),
        Some(false) => push_state(&mut verdict.states, VerificationState::RuntimeRejected),
        None => push_state(&mut verdict.states, VerificationState::TrustUnconfirmed),
    }

    if syntax_ok
        && location_ok
        && name_ok
        && source_active
        && hooks_feature != Some(false)
        && trust == Some(true)
    {
        push_state(&mut verdict.states, VerificationState::Effective);
    }
}

fn refine_rule(
    verdict: &mut super::phase3::Verdict,
    path: &Path,
    syntax_ok: bool,
    name_ok: bool,
    layers: &[ConfigLayer],
) {
    let Some(parent) = path.parent().and_then(Path::parent) else { return };
    let config_path = parent.join("config.toml");
    let Some(layer) = config_layer_for(&config_path, layers) else { return };
    match layer.activation {
        Activation::Active | Activation::RuntimeConfirmed => {
            push_state(&mut verdict.states, VerificationState::LayerActive);
            if syntax_ok && name_ok && layer.version_valid != Some(false) {
                push_state(&mut verdict.states, VerificationState::Effective);
            }
        }
        Activation::TrustUnconfirmed => push_state(&mut verdict.states, VerificationState::TrustUnconfirmed),
        Activation::Inactive | Activation::RuntimeRejected => push_state(&mut verdict.states, VerificationState::LayerInactive),
    }
}

fn config_layer_for<'a>(path: &Path, layers: &'a [ConfigLayer]) -> Option<&'a ConfigLayer> {
    layers.iter().find(|layer| layer.path == path)
}

fn active_layer_for_adjacent_file<'a>(path: &Path, layers: &'a [ConfigLayer]) -> Option<&'a ConfigLayer> {
    let parent = path.parent()?;
    layers.iter().find(|layer| {
        layer.path.parent() == Some(parent)
            && matches!(layer.activation, Activation::Active | Activation::RuntimeConfirmed)
    })
}

fn feature_state(diagnostics: &[RuntimeDiagnostic], feature: &str) -> Option<bool> {
    let diagnostic = diagnostics.iter().find(|diagnostic| diagnostic.name == "features list" && diagnostic.success)?;
    let feature_lower = feature.to_ascii_lowercase();
    for line in diagnostic.stdout.lines() {
        let lower = line.to_ascii_lowercase();
        let words = lower
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_' && character != '-')
            .collect::<Vec<_>>();
        if !words.iter().any(|word| *word == feature_lower.as_str()) {
            continue;
        }
        if words.iter().any(|word| matches!(*word, "true" | "enabled" | "on")) {
            return Some(true);
        }
        if words.iter().any(|word| matches!(*word, "false" | "disabled" | "off")) {
            return Some(false);
        }
    }
    None
}

fn disabled_skill_paths(layers: &[ConfigLayer]) -> BTreeSet<PathBuf> {
    let mut disabled = BTreeSet::new();
    for layer in layers.iter().filter(|layer| {
        layer.syntax_valid && matches!(layer.activation, Activation::Active | Activation::RuntimeConfirmed)
    }) {
        let Ok(text) = fs::read_to_string(&layer.path) else { continue };
        let Ok(value) = text.parse::<TomlValue>() else { continue };
        let Some(skills) = value.get("skills").and_then(TomlValue::as_table) else { continue };
        let Some(configs) = skills.get("config").and_then(TomlValue::as_array) else { continue };
        for config in configs {
            let Some(table) = config.as_table() else { continue };
            if table.get("enabled").and_then(TomlValue::as_bool) != Some(false) {
                continue;
            }
            let Some(path) = table.get("path").and_then(TomlValue::as_str) else { continue };
            disabled.insert(resolve_from_layer(&layer.path, path));
        }
    }
    disabled
}

fn enabled_plugin_roots(value: Option<&JsonValue>) -> BTreeSet<PathBuf> {
    let mut roots = BTreeSet::new();
    let Some(value) = value else { return roots };
    visit_objects(value, &mut |object| {
        if object.get("enabled").and_then(JsonValue::as_bool) != Some(true) {
            return;
        }
        if let Some(path) = object
            .get("installedPath")
            .or_else(|| object.get("installed_path"))
            .or_else(|| object.get("root"))
            .or_else(|| object.get("path"))
            .and_then(JsonValue::as_str)
        {
            roots.insert(PathBuf::from(path));
        }
    });
    roots
}

fn runtime_marketplace_roots(value: Option<&JsonValue>) -> BTreeSet<PathBuf> {
    let mut roots = BTreeSet::new();
    let Some(value) = value else { return roots };
    visit_objects(value, &mut |object| {
        if let Some(path) = object.get("root").and_then(JsonValue::as_str) {
            roots.insert(PathBuf::from(path));
        }
    });
    roots
}

fn hook_trust_from_doctor(value: Option<&JsonValue>, path: &Path) -> Option<bool> {
    let value = value?;
    let needle = path.to_string_lossy();
    let mut answer = None;
    visit_objects(value, &mut |object| {
        let mentions = object
            .values()
            .any(|value| value.as_str().is_some_and(|text| text.contains(needle.as_ref())));
        if !mentions {
            return;
        }
        answer = object
            .get("trusted")
            .or_else(|| object.get("is_trusted"))
            .or_else(|| object.get("approved"))
            .and_then(JsonValue::as_bool)
            .or(answer);
    });
    answer
}

fn json_mentions_path(value: Option<&JsonValue>, path: &Path) -> bool {
    let Some(value) = value else { return false };
    value.to_string().contains(path.to_string_lossy().as_ref())
}

fn diagnostic_json(diagnostics: &[RuntimeDiagnostic], name: &str) -> Option<JsonValue> {
    diagnostics
        .iter()
        .find(|diagnostic| diagnostic.name == name && diagnostic.success)
        .and_then(|diagnostic| serde_json::from_str(&diagnostic.stdout).ok())
}

fn plugin_root_for(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|ancestor| ancestor.join(".codex-plugin/plugin.json").is_file())
        .map(Path::to_path_buf)
}

fn resolve_from_layer(layer: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        layer.parent().unwrap_or_else(|| Path::new(".")).join(path)
    }
}

fn visit_objects(value: &JsonValue, callback: &mut impl FnMut(&serde_json::Map<String, JsonValue>)) {
    match value {
        JsonValue::Object(object) => {
            callback(object);
            for child in object.values() {
                visit_objects(child, callback);
            }
        }
        JsonValue::Array(values) => {
            for child in values {
                visit_objects(child, callback);
            }
        }
        _ => {}
    }
}

fn apply_layer_state(verdict: &mut super::phase3::Verdict, layer: &ConfigLayer) {
    match layer.activation {
        Activation::Active | Activation::RuntimeConfirmed => {
            push_state(&mut verdict.states, VerificationState::LayerActive)
        }
        Activation::Inactive | Activation::RuntimeRejected => {
            push_state(&mut verdict.states, VerificationState::LayerInactive)
        }
        Activation::TrustUnconfirmed => {
            push_state(&mut verdict.states, VerificationState::TrustUnconfirmed)
        }
    }
    if layer.version_valid == Some(true) {
        push_state(&mut verdict.states, VerificationState::VersionValid);
    } else if layer.version_valid == Some(false) {
        push_state(&mut verdict.states, VerificationState::VersionInvalid);
    }
}

fn push_state(states: &mut Vec<VerificationState>, state: VerificationState) {
    if !states.contains(&state) {
        states.push(state);
    }
}
