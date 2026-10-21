use axum::{
    extract::State,
    http::header::CONTENT_TYPE,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use serde_json::Value;

/// Shared state for the dashboard server
pub struct DashboardState {
    /// Recent audit entries (max 100)
    pub entries: Arc<Mutex<VecDeque<Value>>>,
}

impl DashboardState {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
        }
    }

    /// Add a new audit entry to the dashboard
    pub fn push_entry(&self, entry: Value) {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= 100 {
            entries.pop_front();
        }
        entries.push_back(entry);
    }
}

const DASHBOARD_HTML: &str = include_str!("../dashboard.html");

async fn serve_dashboard() -> impl IntoResponse {
    ([(CONTENT_TYPE, "text/html; charset=utf-8")], DASHBOARD_HTML)
}

async fn serve_audit(State(state): State<Arc<DashboardState>>) -> Json<Vec<Value>> {
    let entries = state.entries.lock().unwrap();
    let result: Vec<Value> = entries.iter().rev().cloned().collect();
    Json(result)
}

/// Start the dashboard HTTP server on the given port.
pub fn start(state: Arc<DashboardState>, port: u16) {
    let app = Router::new()
        .route("/", get(serve_dashboard))
        .route("/api/audit", get(serve_audit))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("Dashboard running at http://{}", addr);

    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                if let Err(e) = axum::serve(listener, app).await {
                    tracing::error!("Dashboard server error: {}", e);
                }
            }
            Err(e) => {
                tracing::warn!("Dashboard port {} in use, skipping: {}", port, e);
            }
        }
    });
}
