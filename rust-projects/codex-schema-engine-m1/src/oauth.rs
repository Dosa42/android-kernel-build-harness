use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use url::Url;

pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const AUTH_ENDPOINT: &str = "https://auth.openai.com/oauth/authorize";
pub const TOKEN_ENDPOINT: &str = "https://auth.openai.com/oauth/token";
pub const REDIRECT_URI: &str = "http://localhost:1455/auth/callback";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthSession {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub id_token: String,
    pub account_id: String,
    pub expires_at: u64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)] refresh_token: String,
    #[serde(default)] id_token: String,
    #[serde(default)] expires_in: u64,
}

fn now_epoch() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn verifier() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn challenge(v: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()))
}

fn jwt_payload(jwt: &str) -> Option<Value> {
    let payload = jwt.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn account_id(jwt: &str) -> Option<String> {
    jwt_payload(jwt)?
        .get("https://api.openai.com/auth")?
        .get("chatgpt_account_id")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn jwt_exp(jwt: &str) -> Option<u64> {
    jwt_payload(jwt)?.get("exp")?.as_u64()
}

fn write_callback_page(mut stream: TcpStream, success: bool) {
    let body = if success {
        "<html><body style='font-family:sans-serif;background:#101827;color:#20e58b;text-align:center;padding-top:64px'><h2>Codex login succeeded</h2><p>You can close this tab.</p></body></html>"
    } else {
        "<html><body style='font-family:sans-serif;background:#101827;color:#ff6577;text-align:center;padding-top:64px'><h2>Codex login failed</h2><p>Return to Codex Schema Engine.</p></body></html>"
    };
    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

pub fn login() -> Result<OAuthSession> {
    let verifier = verifier();
    let state = format!("{:032x}", rand::random::<u128>());
    let listener = TcpListener::bind("127.0.0.1:1455")
        .context("cannot bind OAuth callback on 127.0.0.1:1455")?;
    listener.set_nonblocking(true)?;

    let mut auth = Url::parse(AUTH_ENDPOINT)?;
    auth.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", CLIENT_ID)
        .append_pair("redirect_uri", REDIRECT_URI)
        .append_pair("scope", "openid profile email offline_access api.connectors.read api.connectors.invoke")
        .append_pair("code_challenge", &challenge(&verifier))
        .append_pair("code_challenge_method", "S256")
        .append_pair("id_token_add_organizations", "true")
        .append_pair("codex_cli_simplified_flow", "true")
        .append_pair("originator", "codex_cli_rs")
        .append_pair("state", &state);

    open::that(auth.as_str()).context("failed to open browser for ChatGPT OAuth")?;

    let deadline = Instant::now() + Duration::from_secs(180);
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(anyhow!("OAuth callback timed out after 180 seconds"));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error).context("OAuth callback accept failed"),
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let cloned = stream.try_clone()?;
    let mut reader = BufReader::new(cloned);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let target = request_line.split_whitespace().nth(1).unwrap_or("");
    let callback = Url::parse(&format!("http://localhost{}", target))?;
    let params: std::collections::HashMap<_, _> = callback.query_pairs().into_owned().collect();
    let returned_state = params.get("state").cloned().unwrap_or_default();
    let code = params.get("code").cloned().unwrap_or_default();
    let oauth_error = params.get("error_description").or_else(|| params.get("error")).cloned();
    let ok = returned_state == state && !code.is_empty() && oauth_error.is_none();
    write_callback_page(stream, ok);

    if returned_state != state { return Err(anyhow!("OAuth state mismatch")); }
    if let Some(e) = oauth_error { return Err(anyhow!("Codex login rejected: {e}")); }
    if code.is_empty() { return Err(anyhow!("no authorization code received")); }

    exchange_code(&code, &verifier)
}

fn exchange_code(code: &str, verifier: &str) -> Result<OAuthSession> {
    let client = Client::builder().timeout(Duration::from_secs(30)).build()?;
    let response = client.post(TOKEN_ENDPOINT).form(&[
        ("grant_type", "authorization_code"),
        ("client_id", CLIENT_ID),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("code_verifier", verifier),
    ]).send()?;
    let status = response.status();
    let raw = response.text()?;
    if !status.is_success() { return Err(anyhow!("OAuth token request failed (HTTP {}): {}", status.as_u16(), raw)); }
    let token: TokenResponse = serde_json::from_str(&raw).context("invalid OAuth token response")?;
    let account_id = account_id(&token.id_token)
        .or_else(|| account_id(&token.access_token))
        .ok_or_else(|| anyhow!("OAuth response missing ChatGPT account id"))?;
    let expires_at = jwt_exp(&token.access_token).unwrap_or_else(|| now_epoch() + token.expires_in.max(3600));
    Ok(OAuthSession { access_token: token.access_token, refresh_token: token.refresh_token, id_token: token.id_token, account_id, expires_at })
}

pub fn refresh(session: &OAuthSession) -> Result<OAuthSession> {
    if session.expires_at == 0 || session.expires_at > now_epoch() + 300 { return Ok(session.clone()); }
    if session.refresh_token.is_empty() { return Err(anyhow!("Codex session expired; login again")); }
    let client = Client::builder().timeout(Duration::from_secs(30)).build()?;
    let response = client.post(TOKEN_ENDPOINT).form(&[
        ("grant_type", "refresh_token"),
        ("client_id", CLIENT_ID),
        ("refresh_token", session.refresh_token.as_str()),
    ]).send()?;
    let status = response.status();
    let raw = response.text()?;
    if !status.is_success() { return Err(anyhow!("OAuth refresh failed (HTTP {}): {}", status.as_u16(), raw)); }
    let token: TokenResponse = serde_json::from_str(&raw)?;
    let id_token = if token.id_token.is_empty() { session.id_token.clone() } else { token.id_token };
    let refresh_token = if token.refresh_token.is_empty() { session.refresh_token.clone() } else { token.refresh_token };
    let account_id = account_id(&id_token).or_else(|| account_id(&token.access_token)).unwrap_or_else(|| session.account_id.clone());
    let expires_at = jwt_exp(&token.access_token).unwrap_or_else(|| now_epoch() + token.expires_in.max(3600));
    Ok(OAuthSession { access_token: token.access_token, refresh_token, id_token, account_id, expires_at })
}
