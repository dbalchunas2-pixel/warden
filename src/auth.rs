//! Local authentication for the Warden dashboard.
//! - Master password: Argon2id hash stored in a local credentials file.
//! - Optional GitHub identity via OAuth device flow (token + login in same file).
//! No macOS Keychain — no permission prompts, no code-signing issues.

use anyhow::{anyhow, bail, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, SaltString};
use rand_core::OsRng;
use argon2::{Argon2, PasswordVerifier};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tracing::info;

const KEY_PASSWORD: &str = "master-password-hash";
const KEY_GITHUB_TOKEN: &str = "github-token";
const KEY_GITHUB_LOGIN: &str = "github-login";

/// Credentials file: ~/Library/Application Support/Warden/credentials.json
fn creds_path() -> PathBuf {
    let home = std::env::var_os("HOME").unwrap_or_default();
    let dir = PathBuf::from(home).join("Library/Application Support/Warden");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("credentials.json")
}

/// Load all credentials from the JSON file.
fn load_all() -> HashMap<String, String> {
    let path = creds_path();
    match std::fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

/// Save all credentials to the JSON file with 0600 permissions.
fn save_all(map: &HashMap<String, String>) -> Result<()> {
    let path = creds_path();
    let json = serde_json::to_string_pretty(map)
        .map_err(|e| anyhow!("Serialize credentials: {}", e))?;
    std::fs::write(&path, &json)
        .map_err(|e| anyhow!("Write credentials file: {}", e))?;
    // Restrict to owner-only (0600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| anyhow!("Set permissions: {}", e))?;
    }
    Ok(())
}

pub fn store_secret(key: &str, val: &str) -> Result<()> {
    let mut map = load_all();
    map.insert(key.to_string(), val.to_string());
    save_all(&map)
}

pub fn load_secret(key: &str) -> Option<String> {
    load_all().get(key).cloned()
}

pub fn delete_secret(key: &str) {
    let mut map = load_all();
    map.remove(key);
    let _ = save_all(&map);
}

pub fn has_master_password() -> bool {
    load_secret(KEY_PASSWORD).is_some()
}

pub fn set_master_password(pw: &str) -> Result<()> {
    let trimmed = pw.trim();
    if trimmed.chars().count() < 8 {
        bail!("Master password must be at least 8 characters");
    }
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(trimmed.as_bytes(), &salt)
        .map_err(|e| anyhow!("Hashing failed: {}", e))?
        .to_string();
    store_secret(KEY_PASSWORD, &hash)?;
    info!("Master password set (Argon2id, file-based)");
    Ok(())
}

/// Returns Ok(false) when no password is configured yet.
pub fn verify_master_password(pw: &str) -> Result<bool> {
    let Some(hash) = load_secret(KEY_PASSWORD) else {
        return Ok(false);
    };
    let parsed = PasswordHash::new(&hash).map_err(|e| anyhow!("Corrupt stored hash: {}", e))?;
    Ok(Argon2::default()
        .verify_password(pw.trim().as_bytes(), &parsed)
        .is_ok())
}

// ---------- GitHub OAuth device flow ----------

pub struct DeviceCodeStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub interval: u64,
}

fn http() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| anyhow!("HTTP client: {}", e))
}

pub async fn device_start(client_id: &str) -> Result<DeviceCodeStart> {
    let body = format!("client_id={}&scope=read%3Auser", client_id);
    let resp = http()?
        .post("https://github.com/login/device/code")
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|e| anyhow!("Device code request failed: {}", e))?;
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow!("Bad device-code response: {}", e))?;
    Ok(DeviceCodeStart {
        device_code: v["device_code"]
            .as_str()
            .ok_or_else(|| anyhow!("GitHub response missing device_code"))?
            .to_string(),
        user_code: v["user_code"]
            .as_str()
            .ok_or_else(|| anyhow!("GitHub response missing user_code"))?
            .to_string(),
        verification_uri: v["verification_uri"]
            .as_str()
            .unwrap_or("https://github.com/login/device")
            .to_string(),
        interval: v["interval"].as_u64().unwrap_or(5),
    })
}

/// One poll attempt. Ok(None) = still pending.
pub async fn device_poll(client_id: &str, device_code: &str) -> Result<Option<String>> {
    let body = format!(
        "client_id={}&device_code={}&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code",
        client_id, device_code
    );
    let resp = http()?
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|e| anyhow!("Token poll failed: {}", e))?;
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow!("Bad token response: {}", e))?;
    if let Some(t) = v["access_token"].as_str() {
        return Ok(Some(t.to_string()));
    }
    match v["error"].as_str().unwrap_or("") {
        "authorization_pending" | "slow_down" => Ok(None),
        other => bail!("OAuth error: {}", if other.is_empty() { "unknown" } else { other }),
    }
}

pub async fn fetch_login(token: &str) -> Result<String> {
    let v: serde_json::Value = http()?
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {}", token))
        .header("User-Agent", "warden-security-gateway")
        .send()
        .await
        .map_err(|e| anyhow!("GitHub /user failed: {}", e))?
        .json()
        .await
        .map_err(|e| anyhow!("Bad /user response: {}", e))?;
    v["login"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("GitHub /user response missing login"))
}

pub fn save_identity(token: &str, login: &str) -> Result<()> {
    store_secret(KEY_GITHUB_TOKEN, token)?;
    store_secret(KEY_GITHUB_LOGIN, login)?;
    info!("GitHub identity linked: {}", login);
    Ok(())
}

pub fn identity() -> Option<String> {
    load_secret(KEY_GITHUB_LOGIN)
}
