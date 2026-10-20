mod rules;
mod classify;

use anyhow::Result;
use clap::Parser;
use serde_json::Value;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command as TokioCommand;
use tracing::{error, info, warn};

use rules::RuleEngine;

#[derive(Parser, Debug)]
#[command(
    name = "warden",
    version = "0.1.0",
    about = "MCP Security Gateway - LLM-powered tool call classification"
)]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "config/default.toml")]
    config: String,

    /// Command to launch upstream MCP server (overrides config)
    #[arg(short, long)]
    upstream: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    // Load configuration
    let config_str = std::fs::read_to_string(&args.config)
        .map_err(|e| anyhow::anyhow!("Failed to read config file {}: {}", args.config, e))?;
    let config_toml: toml::Value = toml::from_str(&config_str)?;

    // Extract rules section
    let rules_config = config_toml
        .get("rules")
        .ok_or_else(|| anyhow::anyhow!("Missing [rules] section in config"))?;

    // Initialize rule engine
    let rule_engine = RuleEngine::new(rules_config)?;
    info!("Rule engine initialized");

    // Determine upstream command
    let upstream_cmd = if let Some(ref u) = args.upstream {
        u.clone()
    } else {
        config_toml
            .get("upstream_command")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("No upstream command in config or CLI"))?
    };

    // Split upstream command into program + args
    let parts: Vec<&str> = upstream_cmd.split_whitespace().collect();
    if parts.is_empty() {
        anyhow::bail!("Empty upstream command");
    }

    info!("Spawning upstream MCP server: {}", upstream_cmd);

    let mut child = TokioCommand::new(parts[0])
        .args(&parts[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn upstream MCP server: {}", e))?;

    let mut child_stdin = child.stdin.take().expect("Missing child stdin");
    let mut child_stdout = BufReader::new(
        child
            .stdout
            .take()
            .expect("Missing child stdout"),
    );

    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();

    let audit_path = config_toml
        .get("audit")
        .and_then(|a| a.get("log_path"))
        .and_then(|p| p.as_str())
        .unwrap_or("./warden-audit.jsonl");

    let confidence_threshold = config_toml
        .get("nebius")
        .and_then(|n| n.get("confidence_threshold"))
        .and_then(|c| c.as_float())
        .unwrap_or(0.7);

    info!("Confidence threshold: {}", confidence_threshold);
    info!("Audit log: {}", audit_path);

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

        let method = request
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(Value::Null);

        // Determine if this is a tool call that needs interception
        let intercept = method.starts_with("tools/");

        if intercept {
            match rule_engine.check(method, &params).await {
                Some(decision) => {
                    if decision.allow {
                        info!("Rule engine ALLOW: {} - {}", method, decision.reason);
                        forward(&mut child_stdin, &line).await?;
                    } else {
                        warn!("Rule engine BLOCK: {} - {}", method, decision.reason);
                        let err = jsonrpc_error(&request, -32603, &decision.reason);
                        stdout.write_all(err.as_bytes()).await?;
                        log_audit(audit_path, method, &params, "blocked", &decision.reason).await;
                        continue;
                    }
                }
                None => {
                    // No rule matched, call LLM classification
                    info!("No rule match for {}, sending to LLM classifier", method);
                    match classify::classify_tool_call(method, &params).await {
                        Ok(classification) => {
                            let allow = classification.verdict == "allow"
                                && classification.confidence >= confidence_threshold;

                            info!(
                                "LLM verdict: {} confidence={:.2} category={} reason={}",
                                classification.verdict,
                                classification.confidence,
                                classification.category,
                                classification.reasoning
                            );

                            if allow {
                                forward(&mut child_stdin, &line).await?;
                                log_audit(
                                    audit_path,
                                    method,
                                    &params,
                                    "allowed",
                                    &format!(
                                        "LLM: {} ({:.2})",
                                        classification.reasoning, classification.confidence
                                    ),
                                )
                                .await;
                            } else {
                                let reason = format!(
                                    "Blocked by LLM classifier: {} (confidence: {:.2})",
                                    classification.reasoning, classification.confidence
                                );
                                warn!("{}", reason);
                                let err = jsonrpc_error(&request, -32603, &reason);
                                stdout.write_all(err.as_bytes()).await?;
                                log_audit(audit_path, method, &params, "blocked", &reason).await;
                                continue;
                            }
                        }
                        Err(e) => {
                            error!("LLM classification error: {}", e);
                            // Conservative: block on classification failure
                            let reason = format!("Classification error: {}", e);
                            let err = jsonrpc_error(&request, -32603, &reason);
                            stdout.write_all(err.as_bytes()).await?;
                            log_audit(audit_path, method, &params, "blocked", &reason).await;
                            continue;
                        }
                    }
                }
            }
        } else {
            // Non-tool request (initialize, notifications, tools/list), forward directly
            forward(&mut child_stdin, &line).await?;
        }

        // Read response from upstream
        let mut resp_line = String::new();
        let n = child_stdout.read_line(&mut resp_line).await?;
        if n == 0 {
            info!("Upstream server closed connection");
            break;
        }

        // Write response back to client
        stdout.write_all(resp_line.as_bytes()).await?;
    }

    // Clean up
    let _ = child.kill().await;
    info!("Warden shutting down");
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

async fn log_audit(path: &str, method: &str, params: &Value, verdict: &str, reason: &str) {
    use chrono::Utc;

    // Truncate params in audit log
    let params_str = serde_json::to_string(params).unwrap_or_default();
    let truncated = if params_str.len() > 1024 {
        format!("{}...[truncated]", &params_str[..1024])
    } else {
        params_str
    };

    let entry = serde_json::json!({
        "timestamp": Utc::now().to_rfc3339(),
        "method": method,
        "params": truncated,
        "verdict": verdict,
        "reason": reason,
    });

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        use std::io::Write;
        let _ = writeln!(file, "{}", entry);
    }
}