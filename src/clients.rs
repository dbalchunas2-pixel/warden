// Warden — MCP client config injection: discover, protect (route through Warden), restore.
use crate::commands::gate;
use crate::state::AppState;
use std::sync::Arc;
use serde_json::{json, Value};
use std::path::PathBuf;
use tauri::State;

fn client_configs() -> Vec<(String, PathBuf)> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let h = PathBuf::from(home);
    vec![
        ("Claude Desktop".into(), h.join("Library/Application Support/Claude/claude_desktop_config.json")),
        ("Cursor".into(), h.join(".cursor/mcp.json")),
        ("Windsurf".into(), h.join(".codeium/windsurf/mcp_config.json")),
        ("Claude Code".into(), h.join(".claude.json")),
        ("Cline".into(), h.join("Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json")),
    ]
}

fn warden_bin() -> String {
    std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "/Applications/Warden.app/Contents/MacOS/warden".into())
}

fn shell_join(parts: &[String]) -> String {
    parts.iter().map(|p| if p.contains(' ') { format!("\"{}\"", p) } else { p.clone() }).collect::<Vec<_>>().join(" ")
}

fn read_config(path: &PathBuf) -> Result<Value, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw).map_err(|e| format!("{}: {}", path.display(), e))
}

#[tauri::command]
pub fn scan_mcp_clients(state: State<'_, Arc<AppState>>) -> Result<Value, String> {
    gate(&state)?;
    let mut clients = Vec::new();
    for (name, path) in client_configs() {
        if !path.exists() {
            clients.push(json!({"client": name, "path": path.display().to_string(), "exists": false}));
            continue;
        }
        let cfg = match read_config(&path) { Ok(c) => c, Err(e) => { clients.push(json!({"client": name, "path": path.display().to_string(), "exists": true, "error": e})); continue; } };
        let mut servers = Vec::new();
        if let Some(map) = cfg.get("mcpServers").and_then(|m| m.as_object()) {
            for (sname, entry) in map {
                let cmd = entry.get("command").and_then(|c| c.as_str()).unwrap_or("");
                let is_remote = entry.get("url").is_some();
                let protected = cmd.to_lowercase().contains("warden");
                servers.push(json!({"name": sname, "command": cmd, "remote": is_remote, "protected": protected}));
            }
        }
        let backup = PathBuf::from(format!("{}.warden-backup", path.display()));
        clients.push(json!({"client": name, "path": path.display().to_string(), "exists": true, "servers": servers, "backup_exists": backup.exists()}));
    }
    Ok(json!({"clients": clients}))
}

#[tauri::command]
pub fn protect_all_clients(state: State<'_, Arc<AppState>>) -> Result<Value, String> {
    gate(&state)?;
    let warden_bin = warden_bin();
    let mut summary = Vec::new();
    for (name, path) in client_configs() {
        if !path.exists() { continue; }
        let mut cfg = match read_config(&path) { Ok(c) => c, Err(_) => continue };
        let Some(map) = cfg.get("mcpServers").and_then(|m| m.as_object().cloned()) else { continue };
        let mut changed = 0usize;
        let mut skipped = 0usize;
        let mut out = serde_json::Map::new();
        for (sname, entry) in map {
            let cmd = entry.get("command").and_then(|c| c.as_str()).unwrap_or("");
            if cmd.is_empty() || cmd.to_lowercase().contains("warden") {
                skipped += 1;
                out.insert(sname.clone(), entry.clone());
                continue;
            }
            let mut parts = vec![cmd.to_string()];
            if let Some(args) = entry.get("args").and_then(|a| a.as_array()) {
                for a in args { parts.push(a.as_str().unwrap_or_default().to_string()); }
            }
            let upstream = shell_join(&parts);
            let mut new_entry = entry.clone();
            new_entry["command"] = json!(warden_bin);
            new_entry["args"] = json!(["--upstream", upstream]);
            out.insert(sname.clone(), new_entry);
            changed += 1;
        }
        if changed > 0 {
            let backup = PathBuf::from(format!("{}.warden-backup", path.display()));
            if !backup.exists() {
                std::fs::copy(&path, &backup).map_err(|e| format!("backup failed for {}: {}", name, e))?;
            }
            cfg["mcpServers"] = Value::Object(out);
            let pretty = serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?;
            std::fs::write(&path, pretty).map_err(|e| e.to_string())?;
        }
        summary.push(json!({"client": name, "protected": changed, "skipped": skipped}));
    }
    Ok(json!({"results": summary, "warden_bin": warden_bin}))
}

#[tauri::command]
pub fn restore_clients(state: State<'_, Arc<AppState>>) -> Result<Value, String> {
    gate(&state)?;
    let mut restored = Vec::new();
    for (name, path) in client_configs() {
        let backup = PathBuf::from(format!("{}.warden-backup", path.display()));
        if backup.exists() {
            std::fs::copy(&backup, &path).map_err(|e| format!("restore failed for {}: {}", name, e))?;
            restored.push(name);
        }
    }
    Ok(json!({"restored": restored}))
}
