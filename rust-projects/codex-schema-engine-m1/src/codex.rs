use crate::oauth::OAuthSession;
use crate::schema::CODEX_SCHEMA;
use anyhow::{anyhow, Context, Result};
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::time::Duration;

pub const BASE_URL: &str = "https://chatgpt.com/backend-api/codex";
pub const MODEL: &str = "gpt-5.6-sol";

pub fn ask(session: &OAuthSession, user_input: &str) -> Result<String> {
    let body = json!({
        "model": MODEL,
        "instructions": CODEX_SCHEMA,
        "store": false,
        "stream": true,
        "input": [{
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": user_input}]
        }]
    });

    let client = Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(180))
        .build()?;

    let response = client
        .post(format!("{BASE_URL}/responses"))
        .bearer_auth(&session.access_token)
        .header("ChatGPT-Account-ID", &session.account_id)
        .header("originator", "codex_cli_rs")
        .header("OpenAI-Beta", "responses=experimental")
        .header("Accept", "text/event-stream")
        .header("Content-Type", "application/json")
        .header("User-Agent", "codex_schema_engine/0.1")
        .json(&body)
        .send()?;

    let status = response.status();
    if !status.is_success() {
        let raw = response.text().unwrap_or_default();
        return Err(anyhow!("Codex HTTP {}: {}", status.as_u16(), raw));
    }

    let mut text = String::new();
    let reader = BufReader::new(response);
    let mut completed = false;
    for line in reader.lines() {
        let line = line.context("failed reading Codex SSE stream")?;
        let Some(data) = line.strip_prefix("data:") else { continue };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" { continue; }
        let event: Value = serde_json::from_str(data).context("Codex stream contained invalid JSON")?;
        match event.get("type").and_then(Value::as_str).unwrap_or("") {
            "response.output_text.delta" => {
                if let Some(delta) = event.get("delta").and_then(Value::as_str) { text.push_str(delta); }
            }
            "response.output_text.done" if text.is_empty() => {
                if let Some(done) = event.get("text").and_then(Value::as_str) { text.push_str(done); }
            }
            "response.completed" => completed = true,
            "response.failed" => return Err(anyhow!("Codex response failed: {}", event)),
            "error" => return Err(anyhow!("Codex stream error: {}", event)),
            _ => {}
        }
    }
    if !completed { return Err(anyhow!("Codex stream disconnected before response.completed")); }
    if text.trim().is_empty() { return Err(anyhow!("Codex completed without output text")); }
    Ok(text)
}
