use axum::{
    extract::{Path, State},
    http::header::CONTENT_TYPE,
    response::{IntoResponse, Json, sse::{Event, Sse}},
    routing::{get, post},
    Router,
};
use tokio_stream::StreamExt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::convert::Infallible;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::broadcast;

pub struct DashboardState {
    pub entries: Arc<Mutex<VecDeque<Value>>>,
    pub tx: broadcast::Sender<Value>,
    pub rules: Arc<Mutex<Vec<RuleEntry>>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RuleEntry {
    #[serde(rename = "type")]
    pub rule_type: String,
    pub pattern: String,
}

impl DashboardState {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            entries: Arc::new(Mutex::new(VecDeque::with_capacity(500))),
            tx,
            rules: Arc::new(Mutex::new(vec![
                RuleEntry { rule_type: "path".into(), pattern: "/etc/.*".into() },
                RuleEntry { rule_type: "path".into(), pattern: "~/.ssh/.*".into() },
                RuleEntry { rule_type: "path".into(), pattern: ".*\\.env$".into() },
                RuleEntry { rule_type: "path".into(), pattern: ".*/\\.aws/credentials".into() },
                RuleEntry { rule_type: "path".into(), pattern: ".*/\\.npmrc".into() },
                RuleEntry { rule_type: "path".into(), pattern: ".*/\\.git-credentials".into() },
                RuleEntry { rule_type: "cmd".into(), pattern: "rm .*-rf .*/".into() },
                RuleEntry { rule_type: "cmd".into(), pattern: "curl.*\\|.*sh".into() },
                RuleEntry { rule_type: "cmd".into(), pattern: "dd of=".into() },
                RuleEntry { rule_type: "cmd".into(), pattern: "chmod 777".into() },
                RuleEntry { rule_type: "cmd".into(), pattern: "mkfs".into() },
                RuleEntry { rule_type: "cmd".into(), pattern: "shutdown".into() },
                RuleEntry { rule_type: "cmd".into(), pattern: "reboot".into() },
                RuleEntry { rule_type: "cmd".into(), pattern: "kill -9".into() },
            ])),
        }
    }

    pub fn push_entry(&self, entry: Value) {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= 500 {
            entries.pop_front();
        }
        entries.push_back(entry.clone());
        let _ = self.tx.send(entry);
    }
}

const DASHBOARD_HTML: &str = include_str!("../dashboard.html");

async fn serve_dashboard() -> impl IntoResponse {
    ([(CONTENT_TYPE, "text/html; charset=utf-8")], DASHBOARD_HTML)
}

async fn serve_audit(State(state): State<Arc<DashboardState>>) -> Json<Vec<Value>> {
    let entries = state.entries.lock().unwrap();
    Json(entries.iter().rev().cloned().collect())
}

async fn serve_rules(State(state): State<Arc<DashboardState>>) -> Json<Vec<RuleEntry>> {
    Json(state.rules.lock().unwrap().clone())
}

#[derive(Deserialize)]
struct AddRuleBody {
    #[serde(rename = "type")]
    rule_type: String,
    pattern: String,
}

async fn add_rule(State(state): State<Arc<DashboardState>>, Json(body): Json<AddRuleBody>) -> Json<Value> {
    let mut rules = state.rules.lock().unwrap();
    rules.push(RuleEntry { rule_type: body.rule_type, pattern: body.pattern });
    Json(json!({"ok": true, "total": rules.len()}))
}

async fn del_rule(State(state): State<Arc<DashboardState>>, Path(idx): Path<usize>) -> Json<Value> {
    let mut rules = state.rules.lock().unwrap();
    if idx < rules.len() {
        rules.remove(idx);
    }
    Json(json!({"ok": true, "total": rules.len()}))
}

async fn serve_events(State(state): State<Arc<DashboardState>>) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.tx.subscribe();
    let stream = tokio_stream::wrappers::BroadcastStream::new(rx)
        .filter_map(|r| r.ok())
        .map(|entry| Event::default().data(entry.to_string()))
        .map(Ok::<_, Infallible>);
    Sse::new(stream)
}

#[derive(Deserialize)]
struct TestBody {
    method: String,
    params: String,
}

async fn serve_test(State(state): State<Arc<DashboardState>>, Json(body): Json<TestBody>) -> Json<Value> {
    let params: Value = serde_json::from_str(&body.params).unwrap_or(Value::Null);

    // Check rules first
    let rules = state.rules.lock().unwrap().clone();
    for rule in &rules {
        if let Ok(re) = regex::Regex::new(&rule.pattern) {
            if let Some(strings) = extract_strings(&params) {
                for s in &strings {
                    if re.is_match(s) {
                        return Json(json!({
                            "verdict": "blocked",
                            "reason": format!("Blocked by rule engine: {}", rule.pattern),
                            "layer": "RULES",
                            "confidence": 1.0,
                            "category": if rule.rule_type == "path" { "credential_access" } else { "destructive" }
                        }));
                    }
                }
            }
        }
    }

    // Try LLM classification
    match crate::classify::classify_tool_call(&body.method, &params).await {
        Ok(c) => Json(json!({
            "verdict": c.verdict,
            "reason": c.reasoning,
            "confidence": c.confidence,
            "category": c.category,
            "layer": "LLM"
        })),
        Err(e) => Json(json!({
            "verdict": "blocked",
            "reason": format!("Classification error: {}", e),
            "layer": "ERROR",
            "error": e.to_string()
        })),
    }
}

fn extract_strings(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::String(s) => Some(vec![s.clone()]),
        Value::Array(arr) => {
            let mut out = Vec::new();
            for v in arr { if let Some(mut i) = extract_strings(v) { out.append(&mut i); } }
            if out.is_empty() { None } else { Some(out) }
        }
        Value::Object(map) => {
            let mut out = Vec::new();
            for (_, v) in map { if let Some(mut i) = extract_strings(v) { out.append(&mut i); } }
            if out.is_empty() { None } else { Some(out) }
        }
        _ => None,
    }
}

pub fn start(state: Arc<DashboardState>, port: u16) {
    let app = Router::new()
        .route("/", get(serve_dashboard))
        .route("/api/audit", get(serve_audit))
        .route("/api/rules", get(serve_rules).post(add_rule))
        .route("/api/rules/:idx", axum::routing::delete(del_rule))
        .route("/api/events", get(serve_events))
        .route("/api/test", post(serve_test))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("Dashboard: http://{}", addr);

    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                if let Err(e) = axum::serve(listener, app).await {
                    tracing::error!("Dashboard error: {}", e);
                }
            }
            Err(e) => tracing::warn!("Port {} in use: {}", port, e),
        }
    });
}
