use crate::classify;
use crate::rules::{RuleEngine, RuleEntry};
use crate::state::AppState;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tauri::State;

/// Newest-first audit entries from the in-memory buffer.
#[tauri::command]
pub fn get_audit_log(state: State<'_, Arc<AppState>>) -> Vec<Value> {
    let entries = state.entries.lock().unwrap();
    entries.iter().rev().cloned().collect()
}

#[tauri::command]
pub fn get_rules(state: State<'_, Arc<AppState>>) -> Vec<RuleEntry> {
    state.engine.read().unwrap().list_rules()
}

/// Add a path/cmd regex rule at runtime. Validates the regex before installing.
#[tauri::command]
pub fn add_rule(
    state: State<'_, Arc<AppState>>,
    rule_type: String,
    pattern: String,
) -> Result<Value, String> {
    gate(&state)?;
    if pattern.trim().is_empty() {
        return Err("Pattern is empty".into());
    }
    if rule_type != "path" && rule_type != "cmd" {
        return Err(format!("Invalid rule type: {} (must be path or cmd)", rule_type));
    }
    regex::Regex::new(&pattern).map_err(|e| format!("Invalid regex: {}", e))?;

    let mut engine = state.engine.write().unwrap();
    let mut current = engine.list_rules();
    current.push(RuleEntry {
        rule_type: rule_type.clone(),
        pattern: pattern.clone(),
            enabled: true,
    });
    let block = engine.block_tools.clone();
    let allow = engine.allow_tools.clone();
    let new_engine =
        RuleEngine::from_entries(block, allow, &current).map_err(|e| e.to_string())?;
    *engine = new_engine;
    Ok(json!({"ok": true, "total": current.len(), "pattern": pattern, "type": rule_type}))
}

#[tauri::command]
pub fn delete_rule(state: State<'_, Arc<AppState>>, idx: usize) -> Result<Value, String> {
    gate(&state)?;
    let mut engine = state.engine.write().unwrap();
    let mut current = engine.list_rules();
    if idx >= current.len() {
        return Err(format!("Rule index {} out of range ({} rules)", idx, current.len()));
    }
    current.remove(idx);
    let block = engine.block_tools.clone();
    let allow = engine.allow_tools.clone();
    let new_engine =
        RuleEngine::from_entries(block, allow, &current).map_err(|e| e.to_string())?;
    *engine = new_engine;
    Ok(json!({"ok": true, "total": current.len()}))
}

/// Run an arbitrary tool call (method + JSON args) through the full pipeline:
/// deterministic rules first, then Nemotron LLM classification if no rule matches.
#[tauri::command]
pub fn toggle_rule(state: State<'_, Arc<AppState>>, idx: usize) -> Result<Value, String> {
    gate(&state)?;
    let entries = {
        let mut engine = state.engine.write().unwrap();
        engine.toggle(idx).map_err(|e| e.to_string())?;
        engine.list_rules()
    };
    persist_rules(&state, &entries)?;
    Ok(json!({ "ok": true, "enabled": entries[idx].enabled }))
}

/// Write the full rule list back to the user's warden.toml
fn persist_rules(state: &Arc<AppState>, entries: &[crate::rules::RuleEntry]) -> Result<(), String> {
    let path = state.config_path.read().unwrap().as_ref().map(|p| p.display().to_string());
    let Some(path) = path else { return Ok(()) };
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let mut cfg: toml::Value = content.parse().unwrap_or(toml::Value::Table(Default::default()));
    let arr: Vec<toml::Value> = entries.iter().map(|r| toml::Value::Table([
        ("type".to_string(), toml::Value::String(r.rule_type.clone())),
        ("pattern".to_string(), toml::Value::String(r.pattern.clone())),
        ("enabled".to_string(), toml::Value::Boolean(r.enabled)),
    ].into_iter().collect())).collect();
    if let Some(t) = cfg.as_table_mut() {
        let rules = t.entry("rules").or_insert_with(|| toml::Value::Table(Default::default()));
        if let Some(rt) = rules.as_table_mut() {
            rt.insert("entries".to_string(), toml::Value::Array(arr));
        }
    }
    std::fs::write(&path, toml::to_string_pretty(&cfg).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

/// Export the in-memory audit log as CSV to ~/Desktop
#[tauri::command]
pub fn export_audit(state: State<'_, Arc<AppState>>) -> Result<Value, String> {
    let entries: Vec<Value> = state.entries.lock().unwrap().iter().cloned().collect();
    if entries.is_empty() {
        return Err("Audit log is empty".into());
    }
    let esc = |v: &Value| -> String {
        let s = v.as_str().unwrap_or(&v.to_string()).to_string();
        format!("\"{}\"", s.replace('\"', "\"\""))
    };
    let mut csv = String::from("timestamp,ms,method,verdict,layer,category,reason,params\n");
    for e in entries {
        csv += &format!("{},{},{},{},{},{},{},{}\n",
            esc(e.get("timestamp").unwrap_or(&json!(""))),
            esc(e.get("ms").unwrap_or(&json!(""))),
            esc(e.get("method").unwrap_or(&json!(""))),
            esc(e.get("verdict").unwrap_or(&json!(""))),
            esc(e.get("layer").unwrap_or(&json!(""))),
            esc(e.get("category").unwrap_or(&json!(""))),
            esc(e.get("reason").unwrap_or(&json!(""))),
            esc(e.get("params").unwrap_or(&json!(""))));
    }
    let home = std::env::var("HOME").map_err(|_| "no HOME".to_string())?;
    let path = format!("{}/Desktop/warden-audit-{}.csv", home, chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    std::fs::write(&path, csv).map_err(|e| e.to_string())?;
    Ok(json!({ "path": path }))
}

#[tauri::command]
pub async fn test_tool_call(
    state: State<'_, Arc<AppState>>,
    method: String,
    args_json: String,
) -> Result<Value, String> {
    let t0 = std::time::Instant::now();
    let params: Value = if args_json.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(&args_json).map_err(|e| format!("Invalid JSON args: {}", e))?
    };

    let decision = {
        let engine = state.engine.read().unwrap();
        engine.check(&method, &params)
    };

    if let Some(d) = decision {
        return Ok(json!({
            "verdict": if d.allow { "allowed" } else { "blocked" },
            "reason": d.reason,
            "layer": "RULES",
            "confidence": 1.0,
            "category": "rule_match",
            "method": method,
            "params": params,
            "ms": t0.elapsed().as_millis() as u64
        }));
    }

    match state.api_key() {
        Some(key) => match state.classify_cached(&method, &params, &key).await {
            Ok(c) => Ok(json!({
                "verdict": c.verdict,
                "reason": c.reasoning,
                "confidence": c.confidence,
                "category": c.category,
                "layer": "LLM",
                "method": method,
                "params": params,
                "ms": t0.elapsed().as_millis() as u64
            })),
            Err(e) => Ok(json!({
                "verdict": "blocked",
                "reason": format!("Classification error: {}", e),
                "layer": "ERROR",
                "error": e.to_string(),
                "method": method,
                "params": params,
                "ms": t0.elapsed().as_millis() as u64
            })),
        },
        None => Ok(json!({
            "verdict": "blocked",
            "reason": "No rule match and LLM disabled (no API key). Blocked conservatively.",
            "layer": "RULES",
            "confidence": 1.0,
            "category": "no_key",
            "method": method,
            "params": params,
            "ms": t0.elapsed().as_millis() as u64
        })),
    }
}

#[tauri::command]
pub fn get_stats(state: State<'_, Arc<AppState>>) -> Value {
    let entries = state.entries.lock().unwrap();
    let total = entries.len();
    let allowed = entries.iter().filter(|e| e.get("verdict").and_then(|v| v.as_str()) == Some("allowed")).count();
    let blocked = entries.iter().filter(|e| e.get("verdict").and_then(|v| v.as_str()) == Some("blocked")).count();
    let rules = state.engine.read().unwrap().rule_count();
    let rate = if total > 0 { (blocked as f64 / total as f64 * 100.0).round() as u64 } else { 0 };
    json!({
        "total": total,
        "allowed": allowed,
        "blocked": blocked,
        "block_rate": rate,
        "rules": rules
    })
}

#[tauri::command]
pub fn get_status(state: State<'_, Arc<AppState>>) -> Value {
    let upstream = state.upstream_cmd.read().unwrap().clone();
    let proxy_status = state.proxy_status.read().unwrap().clone();
    let llm_enabled = state.api_key().is_some();
    let rules = state.engine.read().unwrap().rule_count();
    let config_path = state
        .config_path
        .read()
        .unwrap()
        .as_ref()
        .map(|p| p.display().to_string());
    let (bucket_tokens, bucket_burst, bucket_refill) = {
        let mut b = state.llm_bucket.lock().unwrap();
        (b.available(), b.burst, b.refill_per_sec)
    };
    json!({
        "proxy_running": state.proxy_running.load(Ordering::SeqCst),
        "proxy_status": proxy_status,
        "upstream": upstream,
        "llm_enabled": llm_enabled,
        "threshold": state.confidence_threshold,
        "rules": rules,
        "config_path": config_path,
        "llm_bucket_tokens": (bucket_tokens * 10.0).round() / 10.0,
        "llm_bucket_burst": bucket_burst,
        "llm_bucket_refill": bucket_refill,
        "llm_timeout_secs": 20
    })
}

/// First-run setup: persist upstream (and optional API key) to warden.toml.
#[tauri::command]
pub fn save_setup(
    state: State<'_, Arc<AppState>>,
    upstream: String,
    api_key: Option<String>,
    client_id: Option<String>,
) -> Result<Value, String> {
    gate(&state)?;
    if upstream.trim().is_empty() {
        return Err("Upstream command is empty".into());
    }
    state
        .save_setup(
            upstream.trim(),
            api_key.filter(|k| !k.trim().is_empty()),
            client_id.filter(|k| !k.trim().is_empty()),
        )
        .map(|path| json!({"ok": true, "path": path}))
        .map_err(|e| e.to_string())
}

/// Start (or restart) the stdio proxy against the configured upstream.
#[tauri::command]
pub fn start_proxy(state: State<'_, Arc<AppState>>) -> Result<Value, String> {
    let upstream = state
        .upstream_cmd
        .read()
        .unwrap()
        .clone()
        .or_else(|| state.upstream_from_config());
    match upstream {
        Some(cmd) if !cmd.trim().is_empty() => {
            state
                .start_proxy(cmd.trim())
                .map(|_| json!({"ok": true, "upstream": cmd.trim()}))
                .map_err(|e| e.to_string())
        }
        _ => Err("No upstream configured".into()),
    }
}

// ---------- Auth: master password + GitHub identity ----------

/// Policy-mutating commands require the dashboard to be unlocked.
fn gate(state: &Arc<AppState>) -> Result<(), String> {
    if crate::auth::has_master_password() && !state.unlocked.load(Ordering::SeqCst) {
        return Err("Warden is locked. Unlock to change policy.".into());
    }
    Ok(())
}

#[tauri::command]
pub fn auth_status(state: State<'_, Arc<AppState>>) -> Value {
    json!({
        "has_password": crate::auth::has_master_password(),
        "unlocked": state.unlocked.load(Ordering::SeqCst),
        "identity": crate::auth::identity()
    })
}

#[tauri::command]
pub fn set_master_password(state: State<'_, Arc<AppState>>, password: String) -> Result<Value, String> {
    if crate::auth::has_master_password() {
        gate(&state)?;
    }
    crate::auth::set_master_password(&password).map_err(|e| format!("{:#}", e))?;
    state.unlocked.store(true, Ordering::SeqCst);
    Ok(json!({"ok": true}))
}

#[tauri::command]
pub fn unlock(state: State<'_, Arc<AppState>>, password: String) -> Result<Value, String> {
    if !crate::auth::has_master_password() {
        return Err("No master password configured yet.".into());
    }
    match crate::auth::verify_master_password(&password) {
        Ok(true) => {
            state.unlocked.store(true, Ordering::SeqCst);
            Ok(json!({"ok": true}))
        }
        Ok(false) => Err("Incorrect password".into()),
        Err(e) => Err(format!("Auth error: {:#}", e)),
    }
}

#[tauri::command]
pub fn lock_app(state: State<'_, Arc<AppState>>) -> Value {
    state.unlocked.store(false, Ordering::SeqCst);
    json!({"ok": true})
}

fn oauth_client_id(state: &Arc<AppState>) -> Option<String> {
    if let Ok(v) = std::env::var("WARDEN_GITHUB_CLIENT_ID") {
        if !v.trim().is_empty() {
            return Some(v.trim().to_string());
        }
    }
    state
        .config
        .read()
        .unwrap()
        .get("auth")
        .and_then(|a| a.get("github_client_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[tauri::command]
pub async fn oauth_start(
    state: State<'_, Arc<AppState>>,
    client_id: Option<String>,
) -> Result<Value, String> {
    let cid = client_id
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| oauth_client_id(&state))
        .ok_or_else(|| {
            "GitHub OAuth not configured. Paste your OAuth Client ID in setup, or set WARDEN_GITHUB_CLIENT_ID / [auth] github_client_id in warden.toml.".to_string()
        })?;
    let dc = crate::auth::device_start(&cid).await.map_err(|e| format!("{:#}", e))?;
    let _ = std::process::Command::new("open").arg(&dc.verification_uri).spawn();
    Ok(json!({
        "device_code": dc.device_code,
        "user_code": dc.user_code,
        "verification_uri": dc.verification_uri,
        "interval": dc.interval
    }))
}

#[tauri::command]
pub async fn oauth_check(
    state: State<'_, Arc<AppState>>,
    device_code: String,
    client_id: Option<String>,
) -> Result<Value, String> {
    let cid = client_id
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| oauth_client_id(&state))
        .ok_or_else(|| "GitHub OAuth not configured".to_string())?;
    let cid = oauth_client_id(&state)
        .ok_or_else(|| "GitHub OAuth not configured".to_string())?;
    match crate::auth::device_poll(&cid, &device_code).await.map_err(|e| format!("{:#}", e))? {
        None => Ok(json!({"linked": false})),
        Some(token) => {
            let login = crate::auth::fetch_login(&token).await.map_err(|e| format!("{:#}", e))?;
            crate::auth::save_identity(&token, &login).map_err(|e| format!("{:#}", e))?;
            Ok(json!({"linked": true, "login": login}))
        }
    }
}

// ---------- MCP server registry ----------
// Each registered server gets its own warden.toml (own rules baseline + own
// audit log) and a copy-paste client config. No routing, no aggregation:
// Warden stays a single-server stdio gateway per instance.

fn config_target(state: &Arc<AppState>) -> Result<PathBuf, String> {
    let cur = state.config_path.read().unwrap().clone();
    if let Some(p) = cur {
        return Ok(p);
    }
    let home = std::env::var("HOME").map_err(|_| "no HOME".to_string())?;
    let dir = PathBuf::from(&home).join("Library/Application Support/Warden");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("warden.toml"))
}

fn servers_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "no HOME".to_string())?;
    let dir = PathBuf::from(&home).join("Library/Application Support/Warden/servers");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn safe_name(name: &str) -> String {
    name.trim()
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn read_servers(state: &Arc<AppState>) -> Result<Vec<Value>, String> {
    let path = config_target(state)?;
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let cfg: toml::Value = content.parse().unwrap_or(toml::Value::Table(Default::default()));
    let arr = cfg
        .get("servers")
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(arr
        .iter()
        .filter_map(|v| {
            let name = v.get("name").and_then(|x| x.as_str())?;
            let command = v.get("command").and_then(|x| x.as_str())?;
            let added = v.get("added").and_then(|x| x.as_str()).unwrap_or("");
            Some(json!({"name": name, "command": command, "added": added}))
        })
        .collect())
}

fn write_servers(state: &Arc<AppState>, servers: &[Value]) -> Result<PathBuf, String> {
    let path = config_target(state)?;
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let mut cfg: toml::Value = content.parse().unwrap_or(toml::Value::Table(Default::default()));
    let arr: Vec<toml::Value> = servers
        .iter()
        .map(|s| {
            toml::Value::Table(
                [
                    ("name".to_string(), toml::Value::String(s["name"].as_str().unwrap_or("").to_string())),
                    ("command".to_string(), toml::Value::String(s["command"].as_str().unwrap_or("").to_string())),
                    ("added".to_string(), toml::Value::String(s["added"].as_str().unwrap_or("").to_string())),
                ]
                .into_iter()
                .collect(),
            )
        })
        .collect();
    if let Some(t) = cfg.as_table_mut() {
        t.insert("servers".to_string(), toml::Value::Array(arr));
    }
    std::fs::write(&path, toml::to_string_pretty(&cfg).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    Ok(path)
}

fn generate_server_config(state: &Arc<AppState>, name: &str, command: &str) -> Result<PathBuf, String> {
    let dir = servers_dir()?;
    let path = config_target(state)?;
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let mut cfg: toml::Value = content.parse().unwrap_or(toml::Value::Table(Default::default()));
    if let Some(t) = cfg.as_table_mut() {
        t.insert("upstream_command".to_string(), toml::Value::String(command.to_string()));
        if let Some(a) = t.get_mut("audit").and_then(|v| v.as_table_mut()) {
            a.insert(
                "log_path".to_string(),
                toml::Value::String(dir.join(format!("{}-audit.jsonl", name)).display().to_string()),
            );
        }
    }
    let out = dir.join(format!("{}.toml", name));
    std::fs::write(&out, toml::to_string_pretty(&cfg).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

#[tauri::command]
pub fn list_servers(state: State<'_, Arc<AppState>>) -> Vec<Value> {
    read_servers(&state).unwrap_or_default()
}

#[tauri::command]
pub fn add_server(state: State<'_, Arc<AppState>>, name: String, command: String) -> Result<Value, String> {
    gate(&state)?;
    let clean = safe_name(&name);
    if clean.is_empty() {
        return Err("Server name is empty".into());
    }
    if command.trim().is_empty() {
        return Err("Upstream command is empty".into());
    }
    let mut servers = read_servers(&state)?;
    servers.retain(|s| s["name"].as_str() != Some(&clean));
    servers.push(json!({
        "name": clean.clone(),
        "command": command.trim(),
        "added": chrono::Utc::now().to_rfc3339()
    }));
    write_servers(&state, &servers)?;
    let cfg_path = generate_server_config(&state, &clean, command.trim())?;
    Ok(json!({
        "ok": true,
        "name": clean,
        "config_path": cfg_path.display().to_string(),
        "total": servers.len()
    }))
}

#[tauri::command]
pub fn remove_server(state: State<'_, Arc<AppState>>, name: String) -> Result<Value, String> {
    gate(&state)?;
    let clean = safe_name(&name);
    let mut servers = read_servers(&state)?;
    let before = servers.len();
    servers.retain(|s| s["name"].as_str() != Some(&clean));
    if servers.len() == before {
        return Err(format!("No server named '{}'", clean));
    }
    write_servers(&state, &servers)?;
    let dir = servers_dir()?;
    let _ = std::fs::remove_file(dir.join(format!("{}.toml", clean)));
    let _ = std::fs::remove_file(dir.join(format!("{}-audit.jsonl", clean)));
    Ok(json!({"ok": true, "total": servers.len()}))
}

/// Copy-paste client config (Claude Desktop / Claude Code .mcp.json shape)
/// pointing the client at the warden binary with this server's config.
#[tauri::command]
pub fn client_snippet(state: State<'_, Arc<AppState>>, name: String) -> Result<Value, String> {
    let clean = safe_name(&name);
    let servers = read_servers(&state)?;
    let entry = servers
        .iter()
        .find(|s| s["name"].as_str() == Some(&clean))
        .ok_or_else(|| format!("No server named '{}'", clean))?;
    let dir = servers_dir()?;
    let cfg_path = dir.join(format!("{}.toml", clean));
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut server_cfg = serde_json::Map::new();
    server_cfg.insert("command".to_string(), json!(exe.display().to_string()));
    server_cfg.insert(
        "args".to_string(),
        json!(["--config", cfg_path.display().to_string()]),
    );
    let mut servers_map = serde_json::Map::new();
    servers_map.insert(clean.clone(), Value::Object(server_cfg));
    let snippet = serde_json::to_string_pretty(&json!({"mcpServers": Value::Object(servers_map)}))
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "snippet": snippet,
        "config_path": cfg_path.display().to_string(),
        "command": entry["command"].as_str().unwrap_or("")
    }))
}


// ─── LLM-powered features (Nebius Nemotron) ────────────────────────────────

/// Feature 1: Explain why a blocked call was blocked.
#[tauri::command]
pub async fn explain_block(
    state: State<'_, Arc<AppState>>,
    entry: Value,
) -> Result<String, String> {
    gate(&state)?;
    let key = state.api_key().ok_or_else(|| {
        "No Nebius API key configured. Add it in Security or setup to use LLM features.".to_string()
    })?;
    let method = entry.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let params = entry.get("params").cloned().unwrap_or(serde_json::Value::Null);
    let reason = entry.get("reason").and_then(|v| v.as_str()).unwrap_or("");
    let verdict = entry.get("verdict").and_then(|v| v.as_str()).unwrap_or("blocked");
    crate::classify::explain_block(method, &params, reason, verdict, &key)
        .await
        .map_err(|e| e.to_string())
}

/// Feature 2: Convert a natural-language policy into a regex rule.
#[tauri::command]
pub async fn synthesize_rule(
    state: State<'_, Arc<AppState>>,
    description: String,
) -> Result<Value, String> {
    gate(&state)?;
    let key = state.api_key().ok_or_else(|| {
        "No Nebius API key configured. Add it in Security or setup to use LLM features.".to_string()
    })?;
    let result = crate::classify::synthesize_rule(&description, &key)
        .await
        .map_err(|e| e.to_string())?;
    // Validate the regex before returning
    let pattern = result.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
    let rule_type = result.get("rule_type").and_then(|v| v.as_str()).unwrap_or("path");
    if !pattern.is_empty() {
        regex::Regex::new(pattern).map_err(|e| format!("LLM produced invalid regex '{}': {}", pattern, e))?;
    }
    if rule_type != "path" && rule_type != "cmd" {
        return Err(format!("LLM produced invalid rule_type '{}': must be path or cmd", rule_type));
    }
    Ok(result)
}

/// Feature 3: Review a server's tools for security risks at registration time.
#[tauri::command]
pub async fn review_tools(
    state: State<'_, Arc<AppState>>,
    tools: Vec<Value>,
) -> Result<Value, String> {
    gate(&state)?;
    let key = state.api_key().ok_or_else(|| {
        "No Nebius API key configured. Add it in Security or setup to use LLM features.".to_string()
    })?;
    crate::classify::review_tools(&tools, &key)
        .await
        .map_err(|e| e.to_string())
}

/// Feature 4: Summarize the audit log.
#[tauri::command]
pub async fn summarize_audit(
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    gate(&state)?;
    let key = state.api_key().ok_or_else(|| {
        "No Nebius API key configured. Add it in Security or setup to use LLM features.".to_string()
    })?;
    let entries = state.entries.lock().unwrap().iter().cloned().collect::<Vec<_>>();
    crate::classify::summarize_audit(&entries, &key)
        .await
        .map_err(|e| e.to_string())
}
