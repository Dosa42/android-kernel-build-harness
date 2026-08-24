use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn log_path() -> Option<PathBuf> {
    let mut dir = dirs::data_local_dir()?;
    dir.push("codex-schema-engine");
    fs::create_dir_all(&dir).ok()?;
    dir.push("schema-engine.log");
    Some(dir)
}

pub fn event(kind: &str, message: &str) {
    let Some(path) = log_path() else { return };
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let clean = message.replace('\n', " ").replace('\r', " ");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{}\t{}\t{}", ts, kind, clean);
    }
}
