use super::{
    DirectoryVerdict, Phase1Verification, ProjectTrust, RuntimeConfigLayer, RuntimeContext,
    RuntimeDiagnostic, Verdict, VerificationState,
};
use crate::scanner::app_server_probe::{self, AppServerSnapshot};
use crate::scanner::phase2::{candidate_by_path, Phase2Result};
use crate::scanner::schema_check;
use crate::scanner::Phase1Result;
use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use toml::Value as TomlValue;

const MAX_DIAGNOSTIC_BYTES: usize = 256 * 1024;

pub(super) fn capture() -> Result<(RuntimeContext, AppServerSnapshot, Vec<RuntimeConfigLayer>), String> {
    let cwd = env::current_dir().map_err(|error| format!("PHASE3_FAILED: cannot read CWD: {error}"))?;
    let home = env::var_os("HOME").map(PathBuf::from).or_else(dirs::home_dir);
    let initial_codex_home = env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|path| path.join(".codex")))
        .ok_or_else(|| "PHASE3_FAILED: HOME and CODEX_HOME are both unavailable".to_owned())?;
    let codex_executable = find_executable("codex");
    let codex_version = codex_executable
        .as_deref()
        .and_then(|binary| run_output(binary, &["--version"], Some(&cwd)).ok())
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned());

    let app_server = app_server_probe::probe(codex_executable.as_deref(), &cwd);
    let (codex_home, codex_home_source) = app_server
        .codex_home()
        .map(|path| (PathBuf::from(path), "app_server_initialize".to_owned()))
        .unwrap_or((initial_codex_home, "environment_or_default".to_owned()));

    let config_layers = parse_runtime_layers(&app_server);
    let project_root_markers = project_root_markers(app_server.effective_config());
    let project_root = find_project_root_from_markers(&cwd, &project_root_markers);

    let mut context = RuntimeContext {
        effective_uid: command_text("id", &["-u"], None),
        effective_user: command_text("id", &["-un"], None).or_else(|| env::var("USER").ok()),
        home,
        codex_home,
        codex_home_source,
        cwd,
        project_root,
        project_root_markers,
        project_trust: ProjectTrust::Unknown,
        codex_executable,
        codex_version,
    };
    context.project_trust = derive_project_trust(&context, &config_layers);

    Ok((context, app_server, config_layers))
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
            let profile = name
                .get("profile")
                .and_then(JsonValue::as_str)
                .map(str::to_owned);
            let version = raw
                .get("version")
                .and_then(JsonValue::as_str)
                .map(str::to_owned);
            let disabled_reason = raw
                .get("disabledReason")
                .and_then(JsonValue::as_str)
                .map(str::to_owned);
            RuntimeConfigLayer {
                runtime_order,
                source_type,
                source_path,
                profile,
                version,
                active: disabled_reason.is_none(),
                disabled_reason,
                raw_config: raw.get("config").cloned().unwrap_or(JsonValue::Null),
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
    let applicable = layers
        .iter()
        .filter(|layer| layer.source_type == "project")
        .filter(|layer| {
            layer
                .source_path
                .as_deref()
                .and_then(Path::parent)
                .and_then(Path::parent)
                .is_some_and(|directory| chain.iter().any(|item| item == directory))
        })
        .collect::<Vec<_>>();

    if applicable.iter().any(|layer| layer.disabled_reason.is_some()) {
        ProjectTrust::Untrusted
    } else if !applicable.is_empty() {
        ProjectTrust::Trusted
    } else {
        ProjectTrust::Unknown
    }
}

pub(super) fn verify_phase1(
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
        .collect::<Vec<_>>();

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

pub(super) fn add_phase1_verdicts(verification: &Phase1Verification, verdicts: &mut Vec<Verdict>) {
    for path in &verification.missing_from_phase1 {
        verdicts.push(Verdict {
            subject: path.display().to_string(),
            kind: "phase1_runtime_root".into(),
            states: vec![VerificationState::Phase1DiscoveryMiss, VerificationState::RuntimeConfirmed],
            details: vec!["Codex runtime exposed this root/layer, but Phase 1 did not return it.".into()],
        });
    }
}

pub(super) fn add_config_layer_verdicts(
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
                let check = schema_check::validate_config(&value);
                if check.valid {
                    states.push(VerificationState::SchemaValid);
                    if layer.active {
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
        super::normalize_states(&mut states);
        verdicts.push(Verdict {
            subject: path.display().to_string(),
            kind: "runtime_config_layer".into(),
            states,
            details,
        });
    }
}

pub(super) fn collect_diagnostics(context: &RuntimeContext) -> Vec<RuntimeDiagnostic> {
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

pub(super) fn diagnostic_json(diagnostics: &[RuntimeDiagnostic], name: &str) -> Option<JsonValue> {
    diagnostics
        .iter()
        .find(|diagnostic| diagnostic.name == name && diagnostic.success)
        .and_then(|diagnostic| serde_json::from_str(&diagnostic.stdout).ok())
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

pub(super) fn parse_toml(path: &Path) -> Result<TomlValue, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("PHASE3_FAILED: cannot read {}: {error}", path.display()))?;
    text.parse::<TomlValue>()
        .map_err(|error| format!("TOML parse error in {}: {error}", path.display()))
}

pub(super) fn path_chain(root: &Path, cwd: &Path) -> Vec<PathBuf> {
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

pub(super) fn run_output(program: &Path, args: &[&str], cwd: Option<&Path>) -> Result<Output, String> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command
        .output()
        .map_err(|error| format!("failed to execute {}: {error}", program.display()))
}

pub(super) fn truncate_output(bytes: &[u8]) -> String {
    let end = bytes.len().min(MAX_DIAGNOSTIC_BYTES);
    let mut text = String::from_utf8_lossy(&bytes[..end]).into_owned();
    if bytes.len() > end {
        text.push_str("\n[output truncated by verifier]\n");
    }
    text
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

#[cfg(test)]
mod tests {
    use super::{find_project_root_from_markers, path_chain};
    use std::path::Path;

    #[test]
    fn root_chain_is_root_to_cwd() {
        assert_eq!(
            path_chain(Path::new("/repo"), Path::new("/repo/a/b")),
            vec![Path::new("/repo"), Path::new("/repo/a"), Path::new("/repo/a/b")]
        );
    }

    #[test]
    fn empty_markers_disable_parent_search() {
        let cwd = Path::new("/tmp/a/b");
        assert_eq!(find_project_root_from_markers(cwd, &[]), cwd);
    }
}
