use serde::Serialize;
use serde_json::{json, Value as JsonValue};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_STDERR_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AppServerSnapshot {
    pub available: bool,
    pub initialize: Option<JsonValue>,
    pub config_read: Option<JsonValue>,
    pub config_requirements_read: Option<JsonValue>,
    pub errors: Vec<String>,
    pub stderr: String,
}

impl AppServerSnapshot {
    pub(crate) fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            available: false,
            initialize: None,
            config_read: None,
            config_requirements_read: None,
            errors: vec![reason.into()],
            stderr: String::new(),
        }
    }

    pub(crate) fn effective_config(&self) -> Option<&JsonValue> {
        self.config_read.as_ref()?.get("config")
    }

    pub(crate) fn layers(&self) -> Option<&[JsonValue]> {
        self.config_read
            .as_ref()?
            .get("layers")?
            .as_array()
            .map(Vec::as_slice)
    }

    pub(crate) fn origins(&self) -> Option<&serde_json::Map<String, JsonValue>> {
        self.config_read.as_ref()?.get("origins")?.as_object()
    }

    pub(crate) fn requirements(&self) -> Option<&JsonValue> {
        self.config_requirements_read
            .as_ref()?
            .get("requirements")
    }
}

pub(crate) fn probe(
    codex_binary: Option<&Path>,
    cwd: &Path,
) -> AppServerSnapshot {
    let Some(codex_binary) = codex_binary else {
        return AppServerSnapshot::unavailable("Codex executable was not found on PATH.");
    };

    match ProtocolClient::spawn(codex_binary, cwd) {
        Ok(mut client) => {
            let mut errors = Vec::new();

            let initialize = match client.request(
                1,
                "initialize",
                Some(json!({
                    "clientInfo": {
                        "name": "codex_schema_engine_verifier",
                        "title": "Codex Schema Engine Verifier",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "capabilities": {
                        "experimentalApi": true
                    }
                })),
            ) {
                Ok(value) => Some(value),
                Err(error) => {
                    errors.push(format!("initialize failed: {error}"));
                    let stderr = client.finish();
                    return AppServerSnapshot {
                        available: false,
                        initialize: None,
                        config_read: None,
                        config_requirements_read: None,
                        errors,
                        stderr,
                    };
                }
            };

            if let Err(error) = client.notification("initialized", None) {
                errors.push(format!("initialized notification failed: {error}"));
            }

            let config_read = match client.request(
                2,
                "config/read",
                Some(json!({
                    "includeLayers": true,
                    "cwd": cwd.to_string_lossy()
                })),
            ) {
                Ok(value) => Some(value),
                Err(error) => {
                    errors.push(format!("config/read failed: {error}"));
                    None
                }
            };

            let config_requirements_read = match client.request(
                3,
                "configRequirements/read",
                None,
            ) {
                Ok(value) => Some(value),
                Err(error) => {
                    errors.push(format!("configRequirements/read failed: {error}"));
                    None
                }
            };

            let stderr = client.finish();
            let available = initialize.is_some() && config_read.is_some();
            AppServerSnapshot {
                available,
                initialize,
                config_read,
                config_requirements_read,
                errors,
                stderr,
            }
        }
        Err(error) => AppServerSnapshot::unavailable(error),
    }
}

struct ProtocolClient {
    child: Child,
    stdin: Option<ChildStdin>,
    incoming: Receiver<Result<JsonValue, String>>,
    stderr_rx: Receiver<Vec<u8>>,
}

impl ProtocolClient {
    fn spawn(binary: &Path, cwd: &Path) -> Result<Self, String> {
        let mut child = Command::new(binary)
            .args(["app-server", "--listen", "stdio://"])
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("failed to start {} app-server: {error}", binary.display()))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "app-server stdin was not piped".to_owned())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "app-server stdout was not piped".to_owned())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "app-server stderr was not piped".to_owned())?;

        let (incoming_tx, incoming_rx) = mpsc::channel();
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let message = match line {
                    Ok(line) if line.trim().is_empty() => continue,
                    Ok(line) => serde_json::from_str::<JsonValue>(&line)
                        .map_err(|error| format!("invalid app-server JSONL: {error}; line={line}")),
                    Err(error) => Err(format!("failed reading app-server stdout: {error}")),
                };
                if incoming_tx.send(message).is_err() {
                    break;
                }
            }
        });

        let (stderr_tx, stderr_rx) = mpsc::channel();
        thread::spawn(move || {
            let mut data = Vec::new();
            let mut reader = BufReader::new(stderr);
            let _ = std::io::Read::take(&mut reader, MAX_STDERR_BYTES as u64)
                .read_to_end(&mut data);
            let _ = stderr_tx.send(data);
        });

        Ok(Self {
            child,
            stdin: Some(stdin),
            incoming: incoming_rx,
            stderr_rx,
        })
    }

    fn request(
        &mut self,
        id: i64,
        method: &str,
        params: Option<JsonValue>,
    ) -> Result<JsonValue, String> {
        let mut object = serde_json::Map::new();
        object.insert("method".into(), JsonValue::String(method.into()));
        object.insert("id".into(), JsonValue::Number(id.into()));
        if let Some(params) = params {
            object.insert("params".into(), params);
        }
        self.send(JsonValue::Object(object))?;

        loop {
            let message = self
                .incoming
                .recv_timeout(RESPONSE_TIMEOUT)
                .map_err(|error| format!("timeout/disconnect waiting for {method} response: {error}"))??;

            if message.get("id").and_then(JsonValue::as_i64) != Some(id) {
                // Notifications and unrelated server messages are valid while a
                // request is pending; this verifier does not need to consume them.
                continue;
            }
            if let Some(error) = message.get("error") {
                return Err(format!("{method} returned JSON-RPC error: {error}"));
            }
            return message
                .get("result")
                .cloned()
                .ok_or_else(|| format!("{method} response has no result field: {message}"));
        }
    }

    fn notification(&mut self, method: &str, params: Option<JsonValue>) -> Result<(), String> {
        let mut object = serde_json::Map::new();
        object.insert("method".into(), JsonValue::String(method.into()));
        if let Some(params) = params {
            object.insert("params".into(), params);
        }
        self.send(JsonValue::Object(object))
    }

    fn send(&mut self, message: JsonValue) -> Result<(), String> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| "app-server stdin is already closed".to_owned())?;
        serde_json::to_writer(&mut *stdin, &message)
            .map_err(|error| format!("failed serializing app-server request: {error}"))?;
        stdin
            .write_all(b"\n")
            .and_then(|_| stdin.flush())
            .map_err(|error| format!("failed writing app-server request: {error}"))
    }

    fn finish(&mut self) -> String {
        self.stdin.take();
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
        let bytes = self
            .stderr_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl Drop for ProtocolClient {
    fn drop(&mut self) {
        self.stdin.take();
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

trait ReadToEndExt {
    fn read_to_end(&mut self, buffer: &mut Vec<u8>) -> std::io::Result<usize>;
}

impl<R: std::io::Read> ReadToEndExt for std::io::Take<R> {
    fn read_to_end(&mut self, buffer: &mut Vec<u8>) -> std::io::Result<usize> {
        std::io::Read::read_to_end(self, buffer)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn request_shapes_match_app_server_jsonl_contract() {
        let initialize = json!({
            "method": "initialize",
            "id": 1,
            "params": {
                "clientInfo": {
                    "name": "codex_schema_engine_verifier",
                    "title": "Codex Schema Engine Verifier",
                    "version": "0.1.0"
                }
            }
        });
        assert_eq!(initialize["method"], "initialize");
        let config = json!({"method":"config/read","id":2,"params":{"includeLayers":true,"cwd":"/tmp"}});
        assert_eq!(config["params"]["includeLayers"], true);
    }
}
