use super::{DynamicTarget, RuntimeConfigLayer, Verdict, VerificationState};
use crate::scanner::app_server_probe::AppServerSnapshot;
use crate::scanner::phase2::{candidate_by_path, Phase2Result};
use crate::scanner::schema_check;
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

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

pub(super) fn collect_and_verify(
    snapshot: &AppServerSnapshot,
    layers: &[RuntimeConfigLayer],
    phase2: &Phase2Result,
) -> Vec<DynamicTarget> {
    collect_specs(snapshot, layers)
        .into_iter()
        .map(|spec| verify_spec(spec, phase2))
        .collect()
}

fn collect_specs(snapshot: &AppServerSnapshot, layers: &[RuntimeConfigLayer]) -> Vec<DynamicSpec> {
    let mut specs = BTreeMap::<(String, PathBuf), DynamicSpec>::new();

    for (key, kind) in [
        ("model_instructions_file", DynamicKind::Text),
        ("experimental_compact_prompt_file", DynamicKind::Text),
        ("model_catalog_json", DynamicKind::Json),
    ] {
        if let Some((layer, value)) = highest_active_layer_value(layers, key) {
            if let Some(path) = value.as_str() {
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

    // Agent roles are merged by role name. Walking low-to-high and overwriting
    // the map implements the same effective-role selection without guessing a
    // filename in Phase 2.
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
        let path = resolve_layer_relative(layer, &value);
        let key = format!("agents.{role_name}.config_file");
        specs.insert(
            (key.clone(), path.clone()),
            DynamicSpec {
                source_layer: layer.source_path.clone(),
                key,
                path,
                kind: DynamicKind::TomlConfig,
            },
        );
    }

    // Keep absolute paths that the installed runtime exposes only in the final
    // effective config, even if the per-layer JSON shape changed across versions.
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
    if let Some(base) = layer.source_path.as_deref().and_then(Path::parent) {
        return base.join(path);
    }
    env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(path)
}

fn verify_spec(spec: DynamicSpec, phase2: &Phase2Result) -> DynamicTarget {
    let exists = spec.path.is_file();
    let present_in_phase2 = candidate_by_path(phase2, &spec.path).is_some();
    let (syntax_valid, schema_valid) = if exists {
        validate_dynamic_file(&spec.path, spec.kind)
    } else {
        (None, None)
    };

    DynamicTarget {
        source_layer: spec.source_layer,
        config_key: spec.key,
        resolved_path: spec.path,
        exists,
        present_in_phase2,
        syntax_valid,
        schema_valid,
    }
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
        DynamicKind::TomlConfig => match super::runtime::parse_toml(path) {
            Ok(value) => {
                let check = schema_check::validate_config(&value);
                (Some(true), Some(check.valid))
            }
            Err(_) => (Some(false), Some(false)),
        },
    }
}

pub(super) fn add_verdicts(targets: &[DynamicTarget], verdicts: &mut Vec<Verdict>) {
    for target in targets {
        let mut states = Vec::new();
        let mut details = vec![format!("effective_config_key={}", target.config_key)];
        if let Some(source) = &target.source_layer {
            details.push(format!("source_layer={}", source.display()));
        }
        if target.exists {
            states.push(VerificationState::Discovered);
            states.push(VerificationState::LocationRecognized);
        }
        if target.exists && !target.present_in_phase2 {
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

        // The target was obtained from the effective runtime config (or from an
        // active runtime layer) rather than merely guessed from its filename.
        if target.exists
            && target.syntax_valid != Some(false)
            && target.schema_valid != Some(false)
        {
            states.push(VerificationState::RuntimeConfirmed);
            states.push(VerificationState::Effective);
        }

        super::normalize_states(&mut states);
        verdicts.push(Verdict {
            subject: target.resolved_path.display().to_string(),
            kind: "effective_config_dynamic_target".into(),
            states,
            details,
        });
    }
}
