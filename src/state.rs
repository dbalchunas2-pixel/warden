use crate::rules::{RuleEngine, SharedEngine};
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command as TokioCommand;
use tracing::{error, info, warn};

#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct CumulativeStats {
    pub total_calls: u64,
    pub total_allowed: u64,
    pub total_blocked: u64,
    pub posture_history: Vec<Value>,
}

pub struct AppState {
    pub entries: Mutex<VecDeque<Value>>,
    pub engine: SharedEngine,
    pub confidence_threshold: f64,
    pub audit_path: String,
    pub state_path: String,
    pub last_call_ms: AtomicU64,
    pub classifier_fails: std::sync::atomic::AtomicU32,
    pub breaker_until_ms: AtomicU64,
    pub last_notify: Mutex<std::time::Instant>,
    pub llm_bucket: Mutex<TokenBucket>,
    verdict_cache: Mutex<HashMap<u64, crate::classify::Classification>>,
    /// Selected intelligence tier (0 SCOUT, 1 SENTINEL, 2 ULTRA).
    /// u8::MAX means "not yet read from config".
    pub llm_tier: std::sync::atomic::AtomicU8,
    pub discovery_cache: Mutex<HashMap<String, serde_json::Value>>,
    pub config: RwLock<toml::Value>,
    pub config_path: RwLock<Option<PathBuf>>,
    pub api_key_config: RwLock<Option<String>>,
    pub app_handle: RwLock<Option<AppHandle>>,
    pub upstream_cmd: RwLock<Option<String>>,
    pub proxy_status: RwLock<String>,
    pub proxy_running: AtomicBool,
    pub unlocked: AtomicBool,
    pub baseline: Mutex<HashMap<String, (u64, String)>>,
    pub cum_stats: Mutex<CumulativeStats>,
    pub call_windows: Mutex<std::collections::HashMap<String, Vec<u64>>>,
    pub outbreak_servers: Mutex<std::collections::HashSet<String>>,
    /// Deployment-specific threat categories the LLM invented at runtime
    /// (standard categories live in classify::STANDARD_CATEGORIES).
    pub categories: Mutex<Vec<String>>,
}

impl AppState {
    pub fn new(config: &toml::Value, config_path: Option<PathBuf>) -> Result<Self> {
        // Heal a config missing [rules] (e.g. written by a fresh GUI setup before any template existed).
        let default_rules: toml::Value = toml::from_str(
            "block_tools = []\nallow_tools = [\"tools/list\", \"initialize\", \"notifications/initialized\"]\npath_block_patterns = []\ncmd_block_patterns = []\nentries = []\n",
        )?;
        let rules_config = config
            .get("rules")
            .cloned()
            .unwrap_or(default_rules);
        let engine = Arc::new(RwLock::new(RuleEngine::new(&rules_config)?));

        let confidence_threshold = config
            .get("nebius")
            .and_then(|n| n.get("confidence_threshold"))
            .and_then(|c| c.as_float())
            .unwrap_or(0.7);

        let audit_path = {
            let raw = config
                .get("audit")
                .and_then(|a| a.get("log_path"))
                .and_then(|p| p.as_str())
                .unwrap_or("warden-audit.jsonl");
            let p = std::path::Path::new(raw);
            if p.is_absolute() {
                raw.to_string()
            } else {
                // Resolve relative to config file dir, or App Support if no config path
                let base = config_path
                    .as_ref()
                    .and_then(|p| p.parent())
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| {
                        std::env::var_os("HOME")
                            .map(|h| std::path::PathBuf::from(h).join("Library/Application Support/Warden"))
                            .unwrap_or_else(|| std::path::PathBuf::from("."))
                    });
                base.join(raw).to_string_lossy().to_string()
            }
        };

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
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                // Also support api_key_env: look up the named env var at launch
                config
                    .get("nebius")
                    .and_then(|n| n.get("api_key_env"))
                    .and_then(|k| k.as_str())
                    .and_then(|env_name| std::env::var(env_name).ok())
                    .filter(|s| !s.trim().is_empty())
            });

        let state_path = {
            let sp = config_path
                .as_ref()
                .and_then(|p| p.parent())
                .map(|p| p.join("warden-state.json"))
                .unwrap_or_else(|| {
                    std::env::var_os("HOME")
                        .map(|h| std::path::PathBuf::from(h).join("Library/Application Support/Warden/warden-state.json"))
                        .unwrap_or_else(|| std::path::PathBuf::from("warden-state.json"))
                });
            sp.to_string_lossy().to_string()
        };
        let (baseline, cum_stats, known_cats) = load_persistent_state(&state_path);

        let st = Self {
            entries: Mutex::new(VecDeque::with_capacity(1000)),
            engine,
            confidence_threshold,
            audit_path,
            state_path,
            config: RwLock::new(config.clone()),
            config_path: RwLock::new(config_path),
            api_key_config: RwLock::new(api_key),
            app_handle: RwLock::new(None),
            last_call_ms: AtomicU64::new(0),
            classifier_fails: std::sync::atomic::AtomicU32::new(0),
            breaker_until_ms: AtomicU64::new(0),
            last_notify: Mutex::new(std::time::Instant::now()),
            llm_bucket: Mutex::new(TokenBucket::new()),
            verdict_cache: Mutex::new(HashMap::new()),
            llm_tier: std::sync::atomic::AtomicU8::new(u8::MAX),
            discovery_cache: Mutex::new(HashMap::new()),
            upstream_cmd: RwLock::new(upstream),
            proxy_status: RwLock::new("idle".into()),
            proxy_running: AtomicBool::new(false),
            unlocked: AtomicBool::new(false),
            baseline: Mutex::new(baseline),
            cum_stats: Mutex::new(cum_stats),
            call_windows: Mutex::new(std::collections::HashMap::new()),
            outbreak_servers: Mutex::new(std::collections::HashSet::new()),
            categories: Mutex::new(known_cats),
        };
        st.load_audit_history();
        {
            let entries = st.entries.lock().unwrap_or_else(|e| e.into_inner());
            let mut cs = st.cum_stats.lock().unwrap_or_else(|e| e.into_inner());
            for e in entries.iter() {
                cs.total_calls += 1;
                if e.get("verdict").and_then(|v| v.as_str()) == Some("allowed") { cs.total_allowed += 1; }
                if e.get("verdict").and_then(|v| v.as_str()) == Some("blocked") { cs.total_blocked += 1; }
            }
        }
        Ok(st)
    }

    pub fn set_handle(&self, h: AppHandle) {
        *self.app_handle.write().unwrap_or_else(|e| e.into_inner()) = Some(h);
    }

    pub fn set_status(&self, s: &str) {
        *self.proxy_status.write().unwrap_or_else(|e| e.into_inner()) = s.to_string();
    }

    pub fn emit(&self, event: &str, payload: &Value) {
        if let Some(h) = self.app_handle.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
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
        self.api_key_config.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// True when the /check caller presented the operator token from warden.toml [trusted].
    /// The token NEVER bypasses rules - it only changes fail-open behavior when the
    /// classifier itself is unavailable (trusted operator vs unknown caller).
    pub fn check_operator(&self, tok: Option<&Value>) -> bool {
        let Some(t) = tok.and_then(|v| v.as_str()) else { return false };
        if t.is_empty() { return false }
        self.config
            .read().unwrap_or_else(|e| e.into_inner())
            .get("trusted")
            .and_then(|s| s.get("operator_token"))
            .and_then(|v| v.as_str())
            .map(|secret| secret == t)
            .unwrap_or(false)
    }

    pub fn record_call_and_check_rate(&self, server: &str) -> bool {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let mut windows = self.call_windows.lock().unwrap_or_else(|e| e.into_inner());
        let w = windows.entry(server.to_string()).or_insert_with(Vec::new);
        w.retain(|&ts| now - ts < 10);
        w.push(now);
        let is_outbreak = w.len() > 20;
        if is_outbreak { self.outbreak_servers.lock().unwrap_or_else(|e| e.into_inner()).insert(server.to_string()); }
        is_outbreak
    }


        pub fn apply_preset(&self, preset: &str) {
        let patterns: Vec<(&str, Vec<&str>)> = match preset {
            "paranoid" => vec![("cmd", vec![r"rm\s+.*", r"curl.*\|.*sh", r"wget.*\|.*sh", r"dd\s+of=", r"chmod\s+777", "mkfs", "shutdown", "reboot", "kill", "sudo"]), ("path", vec![r".*\.ssh/.*", r".*\.aws/.*", ".*shadow", r".*\.env", r".*\.netrc", r".*\.gnupg/.*"])],
            "balanced" => vec![("cmd", vec![r"rm\s+-rf\s+/", r"curl.*\|.*sh", r"wget.*\|.*sh", r"dd\s+of=/dev/sd", "mkfs"]), ("path", vec![r".*\.ssh/id_rsa", r".*\.aws/credentials", "/etc/shadow"])],
            "permissive" => vec![],
            _ => vec![],
        };
        let mut engine = self.engine.write().unwrap_or_else(|e| e.into_inner());
        *engine = crate::rules::RuleEngine::from_preset(&patterns);
    }

    pub fn upstream_from_config(&self) -> Option<String> {
        self.config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get("upstream_command")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.trim().is_empty())
    }

    /// Restore the last ~1000 audit entries from the JSONL file on startup
    fn load_audit_history(&self) {
        if let Ok(content) = std::fs::read_to_string(&self.audit_path) {
            let mut count = 0usize;
            for line in content.lines().rev() {
                if count >= 1000 { break; }
                if let Ok(v) = serde_json::from_str::<Value>(line) {
                    self.entries.lock().unwrap_or_else(|e| e.into_inner()).push_front(v);
                    count += 1;
                }
            }
            if count > 0 {
                info!("Restored {} audit entries from {}", count, self.audit_path);
            }
            // Backfill threat categories on legacy entries so every call in
            // the dashboard counts toward a real category, not "unclassified".
            let mut ev = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            let mut backfilled = 0usize;
            for e in ev.iter_mut() {
                let has_cat = e.get("category").and_then(|v| v.as_str())
                    .map(|s| !s.trim().is_empty()).unwrap_or(false);
                if has_cat { continue; }
                let verdict = e.get("verdict").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let reason = e.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let layer = e.get("layer").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let extracted = reason.find("category: ").and_then(|pos| {
                    reason[pos + 10..].split(|c| c == ' ' || c == '.' || c == ',').next()
                        .map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
                });
                let cat = extracted.unwrap_or_else(|| {
                    if verdict == "allowed" { "safe".to_string() }
                    else { crate::commands::infer_category(&reason, &layer).to_string() }
                });
                if let Some(obj) = e.as_object_mut() {
                    obj.insert("category".to_string(), Value::String(cat));
                    backfilled += 1;
                }
            }
            if backfilled > 0 {
                info!("Backfilled {} legacy audit entries with inferred threat categories", backfilled);
            }
        }
    }

    /// Deterministic classification: identical (method, params) always gets
    /// the same verdict within a session - no re-rolling the LLM dice.
    /// Current intelligence tier, lazily loaded from [nebius].tier in config.
    pub fn tier(&self) -> u8 {
        let stored = self.llm_tier.load(std::sync::atomic::Ordering::Relaxed);
        if stored != u8::MAX { return stored; }
        let t = self.config.read().unwrap_or_else(|e| e.into_inner())
            .get("nebius").and_then(|n| n.get("tier")).and_then(|v| v.as_str())
            .map(|s| match s { "sentinel" => 1u8, "ultra" => 2, _ => 0 })
            .unwrap_or(0);
        self.llm_tier.store(t, std::sync::atomic::Ordering::Relaxed);
        t
    }

    pub fn set_tier(&self, t: u8) {
        self.llm_tier.store(t, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn clear_verdict_cache(&self) {
        self.verdict_cache.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// Register a threat category observed at runtime. Returns true if it was
    /// novel (not a standard label, not seen before). Persists immediately.
    pub fn register_category(&self, cat: &str) -> bool {
        let c = cat.trim();
        if c.is_empty() || crate::classify::STANDARD_CATEGORIES.contains(&c) { return false; }
        {
            let mut cats = self.categories.lock().unwrap_or_else(|e| e.into_inner());
            if cats.iter().any(|k| k == c) { return false; }
            cats.push(c.to_string());
        }
        self.save_state();
        info!("New threat category registered: {}", c);
        true
    }

    /// Full category list (standard + deployment-specific) for the LLM prompt.
    pub fn known_categories(&self) -> Vec<String> {
        let mut v: Vec<String> = crate::classify::STANDARD_CATEGORIES.iter().map(|s| s.to_string()).collect();
        v.extend(self.categories.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned());
        v
    }

    pub async fn classify_cached(&self, method: &str, params: &Value, api_key: &str) -> Result<crate::classify::Classification> {
        use std::hash::{Hash, Hasher};
        let tier = self.tier();
        let mut h = std::collections::hash_map::DefaultHasher::new();
        method.hash(&mut h);
        serde_json::to_string(params).unwrap_or_default().hash(&mut h);
        tier.hash(&mut h);
        let k = h.finish();
        if let Some(c) = self.verdict_cache.lock().unwrap_or_else(|e| e.into_inner()).get(&k) {
            tracing::info!("Verdict cache hit for {} (deterministic)", method);
            return Ok(c.clone());
        }
        // ULTRA feature: session-context analysis over the recent audit tail.
        let session_ctx = if tier >= 2 {
            let ev = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            let tail: Vec<String> = ev.iter().rev().take(20).map(|e| {
                let m = e.get("method").and_then(|v| v.as_str()).unwrap_or("?");
                let v = e.get("verdict").and_then(|v| v.as_str()).unwrap_or("?");
                let r: String = e.get("reason").and_then(|v| v.as_str()).unwrap_or("").chars().take(80).collect();
                format!("{} -> {} ({})", m, v, r)
            }).collect();
            if tail.is_empty() { None } else {
                Some(format!("\n\nRecent session context (most recent call last). Use it to detect multi-step or staged attacks where this single call alone looks benign:\n{}", tail.into_iter().rev().collect::<Vec<_>>().join("\n")))
            }
        } else { None };
        let threshold = self.confidence_threshold;
        let known = self.known_categories();
        let c = crate::classify::classify_with_tier(method, params, api_key, tier, threshold, session_ctx, &known).await?;
        self.register_category(&c.category);
        self.verdict_cache.lock().unwrap_or_else(|e| e.into_inner()).insert(k, c.clone());
        Ok(c)
    }

    /// Show a macOS notification about a blocked call, but only when the
    /// window is not focused and not more often than every 10 seconds.
    pub fn notify_block(&self, title: &str, body: &str) {
        use tauri::Manager;
        use tauri_plugin_notification::NotificationExt;
        let handle = self.app_handle.read().unwrap_or_else(|e| e.into_inner());
        let Some(app) = handle.as_ref() else { return };
        let focused = app
            .get_webview_window("main")
            .and_then(|w| w.is_focused().ok())
            .unwrap_or(false);
        if focused { return; }
        {
            let mut last = self.last_notify.lock().unwrap_or_else(|e| e.into_inner());
            if last.elapsed() < std::time::Duration::from_secs(10) { return; }
            *last = std::time::Instant::now();
        }
        let _ = app.notification().builder().title(title).body(body).show();
    }

    pub fn push_event(&self, method: &str, params: &Value, verdict: &str, reason: &str, layer: &str) {
        self.push_event_c(method, params, verdict, reason, layer, None)
    }

    pub fn push_event_c(&self, method: &str, params: &Value, verdict: &str, reason: &str, layer: &str, cat: Option<&str>) {
        let params_str = serde_json::to_string(params).unwrap_or_default();
        let head = params_str.get(..1024).unwrap_or(&params_str);
        let truncated = if params_str.len() > 1024 {
            format!("{}...[truncated]", head)
        } else {
            params_str
        };
        let entry = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "ms": self.last_call_ms.load(Ordering::SeqCst),
            "method": method,
            "params": truncated,
            "verdict": verdict,
            "reason": reason,
            "layer": layer,
            "category": cat,
        });
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&self.audit_path) {
            let _ = writeln!(file, "{}", entry);
        }
        {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            if entries.len() >= 1000 {
                entries.pop_front();
            }
            entries.push_back(entry.clone());
        }
        self.emit("tool-call-event", &entry);
        {
            let mut bl = self.baseline.lock().unwrap_or_else(|e| e.into_inner());
            let ec = bl.entry(method.to_string()).or_insert((0, chrono::Utc::now().to_rfc3339()));
            ec.0 += 1;
        }
        {
            let mut cs = self.cum_stats.lock().unwrap_or_else(|e| e.into_inner());
            cs.total_calls += 1;
            if verdict == "allowed" { cs.total_allowed += 1; }
            if verdict == "blocked" { cs.total_blocked += 1; }
            if cs.total_calls % 10 == 0 {
                save_persistent_state(&self.state_path, &self.baseline.lock().unwrap_or_else(|e| e.into_inner()), &cs, &self.categories.lock().unwrap_or_else(|e| e.into_inner()));
            }
        }
    }

    pub fn check_anomaly(&self, method: &str) -> Option<String> {
        let bl = self.baseline.lock().unwrap_or_else(|e| e.into_inner());
        if !bl.contains_key(method) {
            return Some(format!("Anomaly: '{}' has never been called in baseline", method));
        }
        if let Some((count, _)) = bl.get(method) {
            if *count <= 1 && method.starts_with("tools/") {
                return Some(format!("Anomaly: '{}' rarely called (count={})", method, count));
            }
        }
        None
    }

    pub fn save_state(&self) {
        save_persistent_state(&self.state_path, &self.baseline.lock().unwrap_or_else(|e| e.into_inner()), &self.cum_stats.lock().unwrap_or_else(|e| e.into_inner()), &self.categories.lock().unwrap_or_else(|e| e.into_inner()));
    }

    pub fn start_proxy(self: &Arc<Self>, cmd: &str) -> Result<()> {
        if self.proxy_running.load(Ordering::SeqCst) {
            anyhow::bail!("Proxy already running");
        }
        *self.upstream_cmd.write().unwrap_or_else(|e| e.into_inner()) = Some(cmd.to_string());
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

    pub fn save_setup(
        &self,
        upstream: &str,
        api_key: Option<String>,
        client_id: Option<String>,
    ) -> Result<String> {
        let target = {
            let cur = self.config_path.read().unwrap_or_else(|e| e.into_inner()).clone();
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
            // Re-read from disk so we never clobber concurrent writes (e.g. servers added by add_server during setup).
            let disk_content = std::fs::read_to_string(&target).unwrap_or_default();
            let mut disk_cfg: toml::Value = disk_content.parse().unwrap_or(toml::Value::Table(Default::default()));
            if let Some(t) = disk_cfg.as_table_mut() {
                t.insert("upstream_command".into(), toml::Value::String(upstream.to_string()));
                if let Some(key) = &api_key {
                    if !t.contains_key("nebius") {
                        let mut n = toml::map::Map::new();
                        n.insert("model".into(), toml::Value::String("nvidia/Nemotron-3_5-Lightning".into()));
                        n.insert("base_url".into(), toml::Value::String("https://api.tokenfactory.nebius.com/v1/".into()));
                        n.insert("api_key_env".into(), toml::Value::String("NEBIUS_API_KEY".into()));
                        n.insert("max_context_chars".into(), toml::Value::Integer(4096));
                        n.insert("confidence_threshold".into(), toml::Value::Float(0.7));
                        t.insert("nebius".into(), toml::Value::Table(n));
                    }
                    if let Some(n) = t.get_mut("nebius").and_then(|v| v.as_table_mut()) {
                        n.insert("api_key".into(), toml::Value::String(key.clone()));
                    }
                }
                if let Some(cid) = &client_id {
                    if !t.contains_key("auth") {
                        t.insert("auth".into(), toml::Value::Table(toml::map::Map::new()));
                    }
                    if let Some(a) = t.get_mut("auth").and_then(|v| v.as_table_mut()) {
                        a.insert("github_client_id".into(), toml::Value::String(cid.clone()));
                    }
                }
            }
            let out = toml::to_string_pretty(&disk_cfg)?;
            std::fs::write(&target, out)?;
            // Keep the in-memory snapshot in sync with what we just wrote.
            *self.config.write().unwrap_or_else(|e| e.into_inner()) = disk_cfg;
        }
        *self.upstream_cmd.write().unwrap_or_else(|e| e.into_inner()) = Some(upstream.to_string());
        if api_key.is_some() {
            *self.api_key_config.write().unwrap_or_else(|e| e.into_inner()) = api_key;
        }
        Ok(target.display().to_string())
    }

    /// Path of the persistent connected-clients DB (survives restarts, like servers).
    fn clients_db_path(&self) -> PathBuf {
        let cur = self.config_path.read().unwrap_or_else(|e| e.into_inner()).clone();
        let dir = match cur {
            Some(p) => p.parent().map(|d| d.to_path_buf()).unwrap_or_else(|| PathBuf::from(".")),
            None => {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                PathBuf::from(home).join("Library/Application Support/Warden")
            }
        };
        let _ = std::fs::create_dir_all(&dir);
        dir.join("clients.json")
    }

    /// Record a client (by gateway server name) as connected. Persisted to disk.
    pub fn record_client(&self, name: &str) {
        if name.is_empty() { return; }
        let path = self.clients_db_path();
        let mut db: Value = std::fs::read_to_string(&path).ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| json!({}));
        let now = chrono::Utc::now().to_rfc3339();
        let Some(obj) = db.as_object_mut() else { return };
        let entry = obj.entry(name.to_string()).or_insert_with(|| json!({"first_seen": now, "connections": 0}));
        let Some(e) = entry.as_object_mut() else { return };
        e.insert("last_seen".into(), json!(now));
        let n = e.get("connections").and_then(|v| v.as_u64()).unwrap_or(0) + 1;
        e.insert("connections".into(), json!(n));
        let _ = std::fs::write(&path, serde_json::to_string_pretty(&db).unwrap_or_default());
    }

    /// List persisted connected clients, most recent first.
    pub fn list_clients(&self) -> Vec<Value> {
        let path = self.clients_db_path();
        let db: Value = std::fs::read_to_string(&path).ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| json!({}));
        let mut out: Vec<Value> = db.as_object().map(|o| {
            o.iter().map(|(k, v)| {
                let mut e = v.as_object().cloned().unwrap_or_default();
                e.insert("name".into(), json!(k.clone()));
                json!(e)
            }).collect()
        }).unwrap_or_default();
        out.sort_by(|a, b| b.get("last_seen").and_then(|v| v.as_str()).unwrap_or("").cmp(&a.get("last_seen").and_then(|v| v.as_str()).unwrap_or("")));
        out
    }
}

fn load_persistent_state(path: &str) -> (HashMap<String, (u64, String)>, CumulativeStats, Vec<String>) {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let v: Value = serde_json::from_str(&content).unwrap_or(Value::Null);
            let baseline = v.get("baseline")
                .and_then(|b| b.as_object())
                .map(|obj| obj.iter().filter_map(|(k, v)| {
                    let count = v.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
                    let first_seen = v.get("first_seen").and_then(|f| f.as_str()).unwrap_or("").to_string();
                    Some((k.clone(), (count, first_seen)))
                }).collect())
                .unwrap_or_default();
            let cum = v.get("cumulative").cloned().unwrap_or(Value::Null);
            let cum_stats: CumulativeStats = if cum.is_null() { CumulativeStats::default() } else { serde_json::from_value(cum).unwrap_or_default() };
            let known_cats = v.get("known_categories")
                .and_then(|k| k.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).map(|s| s.to_string()).collect())
                .unwrap_or_default();
            (baseline, cum_stats, known_cats)
        }
        Err(_) => (HashMap::new(), CumulativeStats::default(), Vec::new())
    }
}

fn save_persistent_state(path: &str, baseline: &HashMap<String, (u64, String)>, cum: &CumulativeStats, cats: &[String]) {
    let bl_json: serde_json::Map<String, Value> = baseline.iter().map(|(k, (count, first_seen))| (k.clone(), json!({"count": count, "first_seen": first_seen}))).collect();
    let state = json!({"baseline": Value::Object(bl_json), "cumulative": cum, "known_categories": cats, "saved_at": chrono::Utc::now().to_rfc3339()});
    let _ = std::fs::write(path, serde_json::to_string_pretty(&state).unwrap_or_default());
}

/// Token bucket guarding the LLM classification budget.
/// Under flood, we stop calling the LLM entirely and fail closed.
pub struct TokenBucket {
    tokens: f64,
    pub burst: f64,
    pub refill_per_sec: f64,
    last: std::time::Instant,
}

impl TokenBucket {
    fn new() -> Self {
        let burst = std::env::var("WARDEN_LLM_BURST").ok().and_then(|v| v.parse().ok()).unwrap_or(10.0);
        let refill = std::env::var("WARDEN_LLM_REFILL").ok().and_then(|v| v.parse().ok()).unwrap_or(1.0);
        Self { tokens: burst, burst, refill_per_sec: refill, last: std::time::Instant::now() }
    }

    /// Refill passively and report current tokens without spending.
    pub fn available(&mut self) -> f64 {
        let now = std::time::Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.refill_per_sec).min(self.burst);
        self.last = now;
        self.tokens
    }

    pub fn try_acquire(&mut self) -> bool {
        let now = std::time::Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.refill_per_sec).min(self.burst);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

fn resolve_program(prog: &str) -> String {
    if prog.contains('/') {
        return prog.to_string();
    }
    let mut dirs: Vec<std::path::PathBuf> = vec![
        "/opt/homebrew/bin".into(),
        "/usr/local/bin".into(),
        "/usr/bin".into(),
        "/bin".into(),
        "/usr/sbin".into(),
        "/sbin".into(),
    ];
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(format!("{}/.local/bin", home).into());
        dirs.push(format!("{}/.cargo/bin", home).into());
        if let Ok(rd) = std::fs::read_dir(format!("{}/.nvm/versions/node", home)) {
            let mut vers: Vec<std::path::PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
            vers.sort();
            if let Some(last) = vers.pop() {
                dirs.push(last.join("bin"));
            }
        }
    }
    for d in dirs {
        let p = d.join(prog);
        if p.is_file() {
            return p.to_string_lossy().to_string();
        }
    }
    prog.to_string()
}

static SAVE_TICK: AtomicU64 = AtomicU64::new(0);

async fn proxy_loop(state: Arc<AppState>, upstream_cmd: String) -> Result<()> {
    let parts: Vec<&str> = upstream_cmd.split_whitespace().collect();
    if parts.is_empty() {
        anyhow::bail!("Empty upstream command");
    }
    info!("Upstream: {}", upstream_cmd);

    let prog = resolve_program(parts[0]);
    let mut child = TokioCommand::new(&prog)
        .args(&parts[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn upstream '{}': {}", prog, e))?;

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

        let call_start = std::time::Instant::now();
        let method = request
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        let params = request.get("params").cloned().unwrap_or(Value::Null);

        if method.starts_with("tools/") {
            let decision = {
                let engine = state.engine.read().unwrap_or_else(|e| e.into_inner());
                engine.check(&method, &params)
            };

            match decision {
                Some(d) => {
                    if d.allow {
                        info!("ALLOW: {} - {}", method, d.reason);
                        forward(&mut child_stdin, &line).await?;
                        state.last_call_ms.store(call_start.elapsed().as_millis() as u64, Ordering::SeqCst);
                        state.push_event(&method, &params, "allowed", &d.reason, "rules");
                    } else {
                        warn!("BLOCK: {} - {}", method, d.reason);
                        let err = jsonrpc_error(&request, &d.reason);
                        stdout.write_all(err.as_bytes()).await?;
                        stdout.flush().await?;
                        state.last_call_ms.store(call_start.elapsed().as_millis() as u64, Ordering::SeqCst);
                        state.push_event(&method, &params, "blocked", &d.reason, "rules");
                            state.notify_block("Warden blocked a tool call", &d.reason);
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
                            state.last_call_ms.store(call_start.elapsed().as_millis() as u64, Ordering::SeqCst);
                        state.push_event(&method, &params, "blocked", reason, "rules");
                            state.notify_block("Warden blocked a tool call", &reason);
                            continue;
                        }
                        Some(key) => {
                            if !state.llm_bucket.lock().unwrap_or_else(|e| e.into_inner()).try_acquire() {
                                let reason = "Rate limit exceeded: LLM classification budget exhausted. Blocked fail-closed without calling the LLM.";
                                warn!("BLOCK: {} - {}", method, reason);
                                let err = jsonrpc_error(&request, reason);
                                stdout.write_all(err.as_bytes()).await?;
                                stdout.flush().await?;
                                state.last_call_ms.store(call_start.elapsed().as_millis() as u64, Ordering::SeqCst);
                        state.push_event(&method, &params, "blocked", reason, "rate-limit");
                            state.notify_block("Warden rate-limited a tool call", &reason);
                                continue;
                            }
                            info!("No rule match: {} -> LLM classification", method);
                            match state.classify_cached(&method, &params, &key).await {
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
                                        state.last_call_ms.store(call_start.elapsed().as_millis() as u64, Ordering::SeqCst);
                        state.push_event_c(&method, &params, "allowed", &format!("LLM: {}", reason), "llm", Some(&c.category));
                                    } else {
                                        warn!("LLM BLOCK: {}", reason);
                                        let msg = format!("Blocked by LLM: {}", reason);
                                        let err = jsonrpc_error(&request, &msg);
                                        stdout.write_all(err.as_bytes()).await?;
                                        stdout.flush().await?;
                                        state.last_call_ms.store(call_start.elapsed().as_millis() as u64, Ordering::SeqCst);
                        state.push_event_c(&method, &params, "blocked", &msg, "llm", Some(&c.category));
                            state.notify_block("Warden blocked a tool call", &msg);
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    error!("LLM classification error: {:#}", e);
                                    let reason = format!("Classification error: {}", e);
                                    let err = jsonrpc_error(&request, &reason);
                                    stdout.write_all(err.as_bytes()).await?;
                                    stdout.flush().await?;
                                    state.last_call_ms.store(call_start.elapsed().as_millis() as u64, Ordering::SeqCst);
                        state.push_event(&method, &params, "blocked", &reason, "error");
                            state.notify_block("Warden blocked a tool call", &reason);
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

        // JSON-RPC notifications (no id) get NO response from the upstream.
        // Waiting for one here would stall the pipeline forever on the
        // standard MCP handshake (initialize -> notifications/initialized).
        if request.get("id").is_none() {
            continue;
        }

        let mut resp = String::new();
        let n = child_stdout.read_line(&mut resp).await?;
        if n == 0 {
            info!("Upstream closed connection");
            break;
        }
        stdout.write_all(resp.as_bytes()).await?;
        stdout.flush().await?;
        SAVE_TICK.fetch_add(1, Ordering::SeqCst);
        if SAVE_TICK.load(Ordering::SeqCst) % 10 == 0 {
            state.save_state();
        }
    }

    let _ = child.kill().await;
    state.save_state();
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
