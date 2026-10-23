// Warden — local HTTP/WebSocket gateway: inspect JSON-RPC for any MCP client that points at 127.0.0.1:8765.
use crate::state::AppState;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tracing::info;

pub fn start_gateway(state: Arc<AppState>, port: u16) {
    tauri::async_runtime::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            Ok(l) => l,
            Err(e) => { info!("[gateway] bind 127.0.0.1:{} failed: {}", port, e); return; }
        };
        info!("[gateway] listening on 127.0.0.1:{}", port);
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let st = state.clone();
                tokio::spawn(handle_connection(st, stream));
            }
        }
    });
}

fn upstream_url(state: &Arc<AppState>, name: &str) -> Option<String> {
    let cfg = state.config.read().unwrap();
    cfg.get("http_servers")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.iter().find(|s| s.get("name").and_then(|n| n.as_str()) == Some(name)))
        .and_then(|s| s.get("url").and_then(|u| u.as_str()))
        .map(String::from)
}

async fn decide(state: &Arc<AppState>, method: &str, params: &Value) -> (bool, String, &'static str) {
    let decision = { let engine = state.engine.read().unwrap(); engine.check(method, params) };
    match decision {
        Some(d) => (d.allow, d.reason, "RULES"),
        None => match state.api_key() {
            Some(k) => match state.classify_cached(method, params, &k).await {
                Ok(c) => {
                    let allow = c.verdict == "allow" && c.confidence >= state.confidence_threshold;
                    (allow, format!("{} ({:.2})", c.reasoning, c.confidence), "LLM")
                }
                Err(e) => (false, format!("classifier error: {} (fail closed)", e), "ERROR"),
            },
            None => (false, "no rule match + no LLM key (fail closed)".into(), "RULES"),
        },
    }
}

async fn handle_connection(state: Arc<AppState>, mut stream: tokio::net::TcpStream) {
        // Read headers
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = match tokio::io::AsyncReadExt::read(&mut stream, &mut tmp).await { Ok(0) => return, Ok(n) => n, Err(_) => return };
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") { header_end = pos; break; }
        if buf.len() > 64 * 1024 { return; }
    }
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let http_method = parts.next().unwrap_or("").to_string();
    let full_path = parts.next().unwrap_or("").to_string();
    let mut headers = std::collections::HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(": ") { headers.insert(k.to_lowercase(), v.to_string()); }
    }
    let content_len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    if content_len > 1024 * 1024 { return; }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_len {
        let n = match tokio::io::AsyncReadExt::read(&mut stream, &mut tmp).await { Ok(0) => break, Ok(n) => n, Err(_) => return };
        body.extend_from_slice(&tmp[..n]);
    }

    // Decision-only route: POST /check/<name> with a JSON-RPC body -> {allow, reason, layer}.
    if full_path.starts_with("/check/") {
        let sname = full_path.trim_start_matches("/check/").to_string();
        if http_method != "POST" {
            let _ = stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\n\r\n");
            return;
        }
        let req: Value = match serde_json::from_slice(&body) { Ok(v) => v, Err(_) => {
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n");
            return;
        }};
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
        let params = req.get("params").cloned().unwrap_or(json!({}));
        let (allow, reason, layer) = decide(&state, &method, &params).await;
        state.push_event(&method, &params, if allow {"allowed"} else {"blocked"}, &reason, &format!("CHK-{}-{}", layer, sname));
        let payload = json!({"allow": allow, "reason": reason, "layer": layer}).to_string();
        let resp = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}", payload.len(), payload);
        let _ = stream.write_all(resp.as_bytes());
        return;
    }
    let name = full_path.trim_start_matches("/mcp/").split('/').next().unwrap_or("").to_string();
    if headers.get("upgrade").map(|v| v.to_lowercase().contains("websocket")).unwrap_or(false) {
        handle_ws(state, stream, &name).await;
        return;
    }
    let Some(upstream) = upstream_url(&state, &name) else {
        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\n\r\n{\"error\":\"unknown gateway server; add it to warden.toml [http_servers]\"}");
        return;
    };

    // Inspect JSON-RPC POST bodies for tool calls.
    if http_method == "POST" {
        if let Ok(req) = serde_json::from_slice::<Value>(&body) {
            let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
            if method == "tools/call" {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let id = req.get("id").cloned();
                let t0 = std::time::Instant::now();
                let (allow, reason, layer) = decide(&state, &method, &params).await;
                state.push_event(&method, &params, if allow {"allowed"} else {"blocked"}, &reason, &format!("GW-{}", layer));
                let _ms = t0.elapsed().as_millis();
                if !allow {
                    let err_body = match &id {
                        Some(id) => json!({"jsonrpc": "2.0", "id": id.clone(), "error": {"code": -32600, "message": format!("Blocked by Warden: {}", reason)}}),
                        None => json!({}),
                    };
                    let payload = if id.is_some() { serde_json::to_string(&err_body).unwrap_or_default() } else { String::new() };
                    let resp = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}", payload.len(), payload);
                    let _ = stream.write_all(resp.as_bytes());
                    return;
                }
            }
        }
    }

    // Forward to upstream.
    let client = reqwest::Client::new();
    let method_req = match reqwest::Method::from_bytes(http_method.as_bytes()) { Ok(m) => m, Err(_) => return };
    let mut fwd = client.request(method_req, &upstream);
    if !body.is_empty() { fwd = fwd.body(body.clone()); }
    if let Some(ct) = headers.get("content-type") { fwd = fwd.header("content-type", ct.clone()); }
    if let Some(ac) = headers.get("accept") { fwd = fwd.header("accept", ac.clone()); }
    if let Some(sid) = headers.get("mcp-session-id") { fwd = fwd.header("mcp-session-id", sid.clone()); }
    let upstream_resp = match fwd.send().await { Ok(r) => r, Err(e) => {
        let resp = format!("HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n");
        let _ = stream.write_all(resp.as_bytes());
        info!("[gateway] upstream error: {}", e);
        return;
    }};
    let status = upstream_resp.status();
    let ct = upstream_resp.headers().get("content-type").cloned().map(|v| v.to_str().unwrap_or_default().to_string().into_bytes()).unwrap_or_default();
    let sid = upstream_resp.headers().get("mcp-session-id").cloned().map(|v| format!("mcp-session-id: {}\r\n", v.to_str().unwrap_or_default()));
    let resp_body = upstream_resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
    let mut resp = format!("HTTP/1.1 {} \r\n", status.as_str()).into_bytes();
    resp.extend_from_slice(format!("content-type: {}\r\n", String::from_utf8_lossy(&ct)).as_bytes());
    if let Some(s) = sid { resp.extend_from_slice(s.as_bytes()); }
    resp.extend_from_slice(format!("content-length: {}\r\nconnection: close\r\n\r\n", resp_body.len()).as_bytes());
    resp.extend_from_slice(&resp_body);
    let _ = stream.write_all(&resp);
}

async fn handle_ws(state: Arc<AppState>, stream: tokio::net::TcpStream, name: &str) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let Some(upstream) = upstream_url(&state, name) else { return };
    let ws_url = if upstream.starts_with("http") { upstream.replacen("http", "ws", 1) } else { upstream };
    let mut server_ws = match tokio_tungstenite::accept_async(stream).await { Ok(x) => x, Err(_) => return };
    let (mut up_ws, _) = match tokio_tungstenite::connect_async(&ws_url).await { Ok(x) => x, Err(e) => { info!("[gateway] ws upstream dial failed: {}", e); return } };
    info!("[gateway] ws session for '{}' -> {}", name, ws_url);
    while let Some(msg) = server_ws.next().await {
        let Ok(Message::Text(text)) = msg else { continue };
        let req: Value = match serde_json::from_str(&text) { Ok(v) => v, Err(_) => { let _ = up_ws.send(Message::Text(text)).await; continue } };
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
        if method == "tools/call" {
            let params = req.get("params").cloned().unwrap_or(json!({}));
            let (allow, reason, layer) = decide(&state, &method, &params).await;
            state.push_event(&method, &params, if allow {"allowed"} else {"blocked"}, &reason, &format!("GW-{}", layer));
            if !allow {
                let id = req.get("id").cloned().unwrap_or(json!(null));
                let err = json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32600, "message": format!("Blocked by Warden: {}", reason)}});
                let _ = server_ws.send(Message::Text(err.to_string())).await;
                continue;
            }
        }
        if let Err(e) = up_ws.send(Message::Text(text)).await { info!("[gateway] ws forward failed: {}", e); break; }
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
