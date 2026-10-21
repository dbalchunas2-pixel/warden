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
pub async fn test_tool_call(
    state: State<'_, Arc<AppState>>,
    method: String,
    args_json: String,
) -> Result<Value, String> {
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
            "params": params
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
                "params": params
            })),
            Err(e) => Ok(json!({
                "verdict": "blocked",
                "reason": format!("Classification error: {}", e),
                "layer": "ERROR",
                "error": e.to_string(),
                "method": method,
                "params": params
            })),
        },
        None => Ok(json!({
            "verdict": "blocked",
            "reason": "No rule match and LLM disabled (no API key). Blocked conservatively.",
            "layer": "RULES",
            "confidence": 1.0,
            "category": "no_key",
            "method": method,
            "params": params
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
    json!({
        "proxy_running": state.proxy_running.load(Ordering::SeqCst),
        "proxy_status": proxy_status,
        "upstream": upstream,
        "llm_enabled": llm_enabled,
        "threshold": state.confidence_threshold,
        "rules": rules,
        "config_path": config_path
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
