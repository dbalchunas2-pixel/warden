use crate::rules::{RuleEngine, SharedEngine};
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command as TokioCommand;
use tracing::{error, info, warn};

pub struct AppState {
    pub entries: Mutex<VecDeque<Value>>,
    pub engine: SharedEngine,
    pub confidence_threshold: f64,
    pub audit_path: String,
    pub config: RwLock<toml::Value>,
    pub config_path: RwLock<Option<PathBuf>>,
    pub api_key_config: RwLock<Option<String>>,
    pub app_handle: RwLock<Option<AppHandle>>,
    pub upstream_cmd: RwLock<Option<String>>,
    pub proxy_status: RwLock<String>,
    pub proxy_running: AtomicBool,
}

impl AppState {
    pub fn new(config: &toml::Value, config_path: Option<PathBuf>) -> Result<Self> {
        let rules_config = config
            .get("rules")
            .ok_or_else(|| anyhow::anyhow!("Missing [rules] section in config"))?;
        let engine = Arc::new(RwLock::new(RuleEngine::new(rules_config)?));

        let confidence_threshold = config
            .get("nebius")
            .and_then(|n| n.get("confidence_threshold"))
            .and_then(|c| c.as_float())
            .unwrap_or(0.7);

        let audit_path = config
            .get("audit")
            .and_then(|a| a.get("log_path"))
            .and_then(|p| p.as_str())
            .unwrap_or("./warden-audit.jsonl")
            .to_string();

        let upstream = config
            .get("upstream_command")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.trim().is_empty());

        let api_key = config
            .get("nebius")
            .and_then(|n| n.get("api_key"))
            .and_then(|k| k.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.trim().is_empty());

        Ok(Self {
            entries: Mutex::new(VecDeque::with_capacity(1000)),
            engine,
            confidence_threshold,
            audit_path,
            config: RwLock::new(config.clone()),
            config_path: RwLock::new(config_path),
            api_key_config: RwLock::new(api_key),
            app_handle: RwLock::new(None),
            upstream_cmd: RwLock::new(upstream),
            proxy_status: RwLock::new("idle".into()),
            proxy_running: AtomicBool::new(false),
        })
    }

    pub fn set_handle(&self, h: AppHandle) {
        *self.app_handle.write().unwrap() = Some(h);
    }

    pub fn set_status(&self, s: &str) {
        *self.proxy_status.write().unwrap() = s.to_string();
    }

    pub fn emit(&self, event: &str, payload: &Value) {
        if let Some(h) = self.app_handle.read().unwrap().as_ref() {
            let _ = h.emit(event, payload);
        }
    }

    /// API key: environment first (proxy spawned from a shell), then config (GUI launch).
    pub fn api_key(&self) -> Option<String> {
        if let Ok(k) = std::env::var("NEBIUS_API_KEY") {
            if !k.is_empty() && k != "your-key" && k != "your-nebius-key" {
                return Some(k);
            }
        }
        self.api_key_config.read().unwrap().clone()
    }

    pub fn upstream_from_config(&self) -> Option<String> {
        self.config
            .read()
            .unwrap()
            .get("upstream_command")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.trim().is_empty())
    }

    pub fn push_event(&self, method: &str, params: &Value, verdict: &str, reason: &str, layer: &str) {
        let params_str = serde_json::to_string(params).unwrap_or_default();
        let head = params_str.get(..1024).unwrap_or(&params_str);
        let truncated = if params_str.len() > 1024 {
            format!("{}...[truncated]", head)
        } else {
            params_str
        };
        let entry = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "method": method,
            "params": truncated,
            "verdict": verdict,
            "reason": reason,
            "layer": layer,
        });
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&self.audit_path) {
            let _ = writeln!(file, "{}", entry);
        }
        {
            let mut entries = self.entries.lock().unwrap();
            if entries.len() >= 1000 {
                entries.pop_front();
            }
            entries.push_back(entry.clone());
        }
        self.emit("tool-call-event", &entry);
    }

    pub fn start_proxy(self: &Arc<Self>, cmd: &str) -> Result<()> {
        if self.proxy_running.load(Ordering::SeqCst) {
            anyhow::bail!("Proxy already running");
        }
        *self.upstream_cmd.write().unwrap() = Some(cmd.to_string());
        self.proxy_running.store(true, Ordering::SeqCst);
        self.set_status("running");

        let st = self.clone();
        let cmd_owned = cmd.to_string();
        self.emit("proxy-status", &json!({"status": "running", "upstream": cmd}));
        tauri::async_runtime::spawn(async move {
            if let Err(e) = proxy_loop(st.clone(), cmd_owned).await {
                error!("Proxy error: {}", e);
                st.set_status(&format!("error: {}", e));
                st.emit("proxy-status", &json!({"status": "error", "error": e.to_string()}));
            }
            st.proxy_running.store(false, Ordering::SeqCst);
            st.emit("proxy-status", &json!({"status": "stopped"}));
        });
        Ok(())
    }

    pub fn save_setup(&self, upstream: &str, api_key: Option<String>) -> Result<String> {
        let target = {
            let cur = self.config_path.read().unwrap().clone();
            match cur {
                Some(p) => p,
                None => {
                    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                    let dir = PathBuf::from(home).join("Library/Application Support/Warden");
                    std::fs::create_dir_all(&dir)?;
                    dir.join("warden.toml")
                }
            }
        };
        {
            let mut cfg = self.config.write().unwrap();
            if let Some(t) = cfg.as_table_mut() {
                t.insert("upstream_command".into(), toml::Value::String(upstream.to_string()));
                if let Some(key) = &api_key {
                    if let Some(n) = t.get_mut("nebius").and_then(|v| v.as_table_mut()) {
                        n.insert("api_key".into(), toml::Value::String(key.clone()));
                    }
                }
            }
            let out = toml::to_string_pretty(&*cfg)?;
            std::fs::write(&target, out)?;
        }
        *self.upstream_cmd.write().unwrap() = Some(upstream.to_string());
        if api_key.is_some() {
            *self.api_key_config.write().unwrap() = api_key;
        }
        Ok(target.display().to_string())
    }
}

async fn proxy_loop(state: Arc<AppState>, upstream_cmd: String) -> Result<()> {
    let parts: Vec<&str> = upstream_cmd.split_whitespace().collect();
    if parts.is_empty() {
        anyhow::bail!("Empty upstream command");
    }
    info!("Upstream: {}", upstream_cmd);

    let mut child = TokioCommand::new(parts[0])
        .args(&parts[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn upstream '{}': {}", parts[0], e))?;

    let mut child_stdin = child.stdin.take().expect("child stdin");
    let mut child_stdout = BufReader::new(child.stdout.take().expect("child stdout"));
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();

    info!("Warden proxy running. Tool calls are being inspected.");

    let mut line = String::new();
    loop {
        line.clear();
        let n = stdin.read_line(&mut line).await?;
        if n == 0 {
            info!("MCP client closed stdin");
            break;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                error!("JSON-RPC parse error: {}", e);
                continue;
            }
        };

        let method = request
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        let params = request.get("params").cloned().unwrap_or(Value::Null);

        if method.starts_with("tools/") {
            let decision = {
                let engine = state.engine.read().unwrap();
                engine.check(&method, &params)
            };

            match decision {
                Some(d) => {
                    if d.allow {
                        info!("ALLOW: {} - {}", method, d.reason);
                        forward(&mut child_stdin, &line).await?;
                        state.push_event(&method, &params, "allowed", &d.reason, "rules");
                    } else {
                        warn!("BLOCK: {} - {}", method, d.reason);
                        let err = jsonrpc_error(&request, &d.reason);
                        stdout.write_all(err.as_bytes()).await?;
                        stdout.flush().await?;
                        state.push_event(&method, &params, "blocked", &d.reason, "rules");
                        continue;
                    }
                }
                None => {
                    let key = state.api_key();
                    match key {
                        None => {
                            let reason = "No rule match and LLM disabled (no API key). Blocked conservatively.";
                            warn!("BLOCK: {} - {}", method, reason);
                            let err = jsonrpc_error(&request, reason);
                            stdout.write_all(err.as_bytes()).await?;
                            stdout.flush().await?;
                            state.push_event(&method, &params, "blocked", reason, "rules");
                            continue;
                        }
                        Some(key) => {
                            info!("No rule match: {} -> LLM classification", method);
                            match crate::classify::classify_tool_call(&method, &params, &key).await {
                                Ok(c) => {
                                    let allow =
                                        c.verdict == "allow" && c.confidence >= state.confidence_threshold;
                                    let reason = format!(
                                        "{} ({:.2}) category: {}",
                                        c.reasoning, c.confidence, c.category
                                    );
                                    if allow {
                                        info!("LLM ALLOW: {}", reason);
                                        forward(&mut child_stdin, &line).await?;
                                        state.push_event(&method, &params, "allowed", &format!("LLM: {}", reason), "llm");
                                    } else {
                                        warn!("LLM BLOCK: {}", reason);
                                        let msg = format!("Blocked by LLM: {}", reason);
                                        let err = jsonrpc_error(&request, &msg);
                                        stdout.write_all(err.as_bytes()).await?;
                                        stdout.flush().await?;
                                        state.push_event(&method, &params, "blocked", &msg, "llm");
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    error!("LLM classification error: {}", e);
                                    let reason = format!("Classification error: {}", e);
                                    let err = jsonrpc_error(&request, &reason);
                                    stdout.write_all(err.as_bytes()).await?;
                                    stdout.flush().await?;
                                    state.push_event(&method, &params, "blocked", &reason, "error");
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        } else {
            forward(&mut child_stdin, &line).await?;
        }

        let mut resp = String::new();
        let n = child_stdout.read_line(&mut resp).await?;
        if n == 0 {
            info!("Upstream closed connection");
            break;
        }
        stdout.write_all(resp.as_bytes()).await?;
        stdout.flush().await?;
    }

    let _ = child.kill().await;
    info!("Warden proxy stopped");
    Ok(())
}

async fn forward(
    stdin: &mut tokio::process::ChildStdin,
    line: &str,
) -> Result<()> {
    stdin.write_all(line.as_bytes()).await?;
    stdin.flush().await?;
    Ok(())
}

fn jsonrpc_error(request: &Value, message: &str) -> String {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": -32603, "message": message }
    })
    .to_string()
        + "\n"
}
