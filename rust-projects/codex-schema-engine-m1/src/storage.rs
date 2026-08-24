use crate::oauth::OAuthSession;
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

fn session_path() -> Result<PathBuf> {
    let mut dir = dirs::config_dir().context("no user config directory available")?;
    dir.push("codex-schema-engine");
    fs::create_dir_all(&dir)?;
    dir.push("oauth-session.json");
    Ok(dir)
}

pub fn load_session() -> Option<OAuthSession> {
    let path = session_path().ok()?;
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn save_session(session: &OAuthSession) -> Result<()> {
    let path = session_path()?;
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(session)?;

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    fs::write(&tmp, &bytes)?;

    fs::rename(&tmp, &path).context("atomic OAuth session save failed")?;
    Ok(())
}

pub fn clear_session() -> Result<()> {
    let path = session_path()?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}
