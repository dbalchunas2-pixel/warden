use anyhow::Result;
use clap::Parser;
use serde_json::Value;
use std::{process::Stdio};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command as TokioCommand;
use tracing::{error, info};
use crate::rules::{Decision, RuleEngine};
use crate::classify::Classification;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "config/default.toml")]
    config: String,

    /// Command to launch upstream MCP server
    #[arg(short, long)]
    upstream: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // Load configuration
    let config_str = std::fs::read_to_string(&args.config)?;
    let config_toml: toml::Value = toml::from_str(&config_str)?;

    // Initialize rule engine
    let rule_engine = RuleEngine::new(&config_toml)?;

    // Spawn upstream MCP server
    let mut child = TokioCommand::new(&args.upstream)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn upstream MCP server");

    let mut child_stdin = child.stdin.take().expect("Missing child stdin");
    let mut child_stdout = child.stdout.take().expect("Missing child stdout");

    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();

    let mut line = String::new();
    loop {
        line.clear();
        let n = stdin.read_line(&mut line).await?;
        if n == 0 {
            break; // EOF
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to parse JSON-RPC: {}", e);
                continue;
            }
        };

        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(Value::Null);

        // Determine if this is a tool call that needs interception
        let intercept = method.starts_with("tool/");

        if intercept {
            match rule_engine.check(method, &params).await {
                Some(decision) => {
                    if decision.allow {
                        forward(&mut child_stdin, &line).await?;
                    } else {
                        let err = jsonrpc_error(&request, -32603, &decision.reason);
                        stdout.write_all(err.as_bytes()).await?;
                        continue;
                    }
                }
                None => {
                    // No rule matched, call LLM
                    match classify_tool_call(method, &params).await {
                        Ok(classification) => {
                            if classification.verdict == "allow" && classification.confidence >= 0.7 {
                                forward(&mut child_stdin, &line).await?;
                            } else {
                                let reason = format!("Blocked by LLM: {}", classification.reasoning);
                                let err = jsonrpc_error(&request, -32603, &reason);
                                stdout.write_all(err.as_bytes()).await?;
                                continue;
                            }
                        }
                        Err(e) => {
                            error!("LLM classification error: {}", e);
                            let err = jsonrpc_error(&request, -32603, "Classification error");
                            stdout.write_all(err.as_bytes()).await?;
                            continue;
                        }
                    }
                }
            }
        } else {
            // Non‑tool request, forward directly
            forward(&mut child_stdin, &line).await?;
        }

        // Read response from upstream
        let mut resp_line = String::new();
        let n = child_stdout.read_line(&mut resp_line).await?;
        if n == 0 {
            break;
        }

        // Log audit entry
        log_audit(method, &params, &resp_line).await;

        // Write response back to client
        stdout.write_all(resp_line.as_bytes()).await?;
    }

    Ok(())
}

async fn forward(stdin: &mut tokio::process::ChildStdin, line: &str) -> Result<()> {
    stdin.write_all(line.as_bytes()).await?;
    stdin.flush().await?;
    Ok(())
}

fn jsonrpc_error(request: &Value, code: i64, message: &str) -> String {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
    .to_string()
        + "\n"
}

async fn log_audit(method: &str, params: &Value, response: &str) {
    use chrono::Utc;
    let entry = serde_json::json!({
        "timestamp": Utc::now().to_rfc3339(),
        "method": method,
        "params": params,
        "response": response,
    });
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("audit.log")
    {
        let _ = writeln!(file, "{}", entry);
    }
}

async fn classify_tool_call(method: &str, params: &Value) -> Result<Classification> {
    crate::classify::classify_tool_call(method, params).await
}
