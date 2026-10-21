use crate::classify;
use crate::rules::{RuleEngine, RuleEntry};
use crate::state::AppState;
use serde_json::{json, Value};
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
        Some(key) => match classify::classify_tool_call(&method, &params, &key).await {
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
) -> Result<Value, String> {
    if upstream.trim().is_empty() {
        return Err("Upstream command is empty".into());
    }
    state
        .save_setup(upstream.trim(), api_key.filter(|k| !k.trim().is_empty()))
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
