mod rules;
mod classify;
mod dashboard;

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::io::{self, Write};
use std::process::Stdio;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command as TokioCommand;
use tracing::{error, info, warn};

use rules::RuleEngine;

const DEFAULT_CONFIG: &str = r#"upstream_command = "echo"

[nebius]
model = "nvidia/Nemotron-3_5-Lightning"
base_url = "https://api.tokenfactory.nebius.com/v1/"
api_key_env = "NEBIUS_API_KEY"
max_context_chars = 4096
confidence_threshold = 0.7

[rules]
block_tools = []
allow_tools = ["tools/list", "initialize", "notifications/initialized"]
path_block_patterns = [
  "/etc/.*",
  "~/.ssh/.*",
  ".*\\.env$",
  ".*/\\.aws/credentials",
  ".*/\\.npmrc",
  ".*/\\.git-credentials",
]
cmd_block_patterns = [
  "rm .*-rf .*/",
  "curl.*\\|.*sh",
  "wget.*\\|.*sh",
  "dd of=",
  "chmod 777",
  "mkfs",
  "shutdown",
  "reboot",
  "halt",
  "kill -9",
]

[audit]
log_path = "./warden-audit.jsonl"
"#;

const BANNER: &str = r#"
  __        _    
  \ \ ___  (_)__ 
   \ V / _ \| / _|
    \_/\___/_|\__|
  MCP Security Gateway
"#;

#[derive(Parser, Debug)]
#[command(
    name = "warden",
    version = "0.1.0",
    about = "MCP Security Gateway - LLM-powered tool call classification on Nebius Token Factory"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(short, long)]
    config: Option<String>,

    #[arg(short, long)]
    upstream: Option<String>,

    #[arg(long, default_value = "31337")]
    port: u16,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Guided setup - configure Warden for first use
    Setup,
    /// Start in proxy mode (default when --upstream is given)
    Serve {
        #[arg(long, default_value = "31337")]
        port: u16,
        #[arg(short, long)]
        upstream: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Setup) => run_setup().await,
        Some(Commands::Serve { port, upstream }) => {
            run_proxy(None, upstream, port).await
        }
        None => {
            if cli.upstream.is_some() {
                run_proxy(cli.config, cli.upstream, cli.port).await
            } else {
                run_setup().await
            }
        }
    }
}

fn check_api_key() -> bool {
    match std::env::var("NEBIUS_API_KEY") {
        Ok(key) => !key.is_empty() && key != "your-key" && key != "your-nebius-key",
        Err(_) => false,
    }
}

fn print_banner() {
    eprintln!("{}", BANNER);
    eprintln!("  Layered defense: deterministic rules + NVIDIA Nemotron on Nebius Token Factory");
    eprintln!();
}

async fn run_setup() -> Result<()> {
    print_banner();

    eprintln!("  === GUIDED SETUP ===");
    eprintln!();

    // Step 1: API Key
    eprintln!("  Step 1: Nebius API Key");
    eprintln!("  -----------------------");
    eprintln!("  Warden uses NVIDIA Nemotron on Nebius Token Factory for LLM classification.");
    eprintln!("  Without it, the rule engine still works but LLM classification is disabled.");
    eprintln!();

    if check_api_key() {
        eprintln!("  [OK] NEBIUS_API_KEY is set and valid.");
    } else {
        eprintln!("  [MISSING] NEBIUS_API_KEY is not set or contains a placeholder.");
        eprintln!();
        eprintln!("  Get a free key:");
        eprintln!("    1. Go to https://studio.nebius.ai");
        eprintln!("    2. Sign in with Google or GitHub");
        eprintln!("    3. Go to API Keys -> Create API Key");
        eprintln!("    4. Copy the key");
        eprintln!("    5. Export it in your shell:");
        eprintln!();
        eprintln!("       export NEBIUS_API_KEY=\"your-actual-key\"");
        eprintln!();
        eprintln!("    6. Add to shell profile to persist across sessions:");
        eprintln!("       echo 'export NEBIUS_API_KEY=\"your-key\"' >> ~/.zshrc");
        eprintln!("       source ~/.zshrc");
    }
    eprintln!();

    // Step 2: Upstream server
    eprintln!("  Step 2: Upstream MCP Server");
    eprintln!("  ---------------------------");
    eprintln!("  What MCP server will Warden protect?");
    eprintln!("  Examples:");
    eprintln!("    node /path/to/mcp-server.js");
    eprintln!("    python /path/to/server.py");
    eprintln!("    npx @modelcontextprotocol/server-filesystem /home/user");
    eprintln!();
    eprint!("  Enter upstream command (or press Enter to skip): ");
    io::stderr().flush()?;

    let mut upstream = String::new();
    io::stdin().read_line(&mut upstream)?;
    let upstream = upstream.trim().to_string();

    if upstream.is_empty() {
        eprintln!();
        eprintln!("  No upstream set. You can pass it later with --upstream.");
        eprintln!();
    } else {
        eprintln!();
        eprintln!("  Upstream set to: {}", upstream);
        eprintln!();
    }

    // Step 3: Generate config file
    eprintln!("  Step 3: Config File");
    eprintln!("  ------------------");
    let config_path = "warden.toml";
    let config_content = if upstream.is_empty() {
        DEFAULT_CONFIG.replace("upstream_command = \"echo\"", "# upstream_command = \"node /path/to/mcp-server.js\"")
    } else {
        DEFAULT_CONFIG.replace("upstream_command = \"echo\"", &format!("upstream_command = \"{}\"", upstream))
    };
    std::fs::write(config_path, &config_content)?;
    eprintln!("  Config written to: ./{}", config_path);
    eprintln!("  Edit it anytime to change rules, thresholds, or upstream.");
    eprintln!();

    // Step 4: Dashboard
    eprintln!("  Step 4: Dashboard");
    eprintln!("  ----------------");
    eprintln!("  Warden runs a live dashboard at http://127.0.0.1:31337");
    eprintln!("  showing real-time tool call interception, stats, and audit log.");
    eprintln!();

    // Step 5: MCP Client Config
    eprintln!("  Step 5: Connect Your MCP Client");
    eprintln!("  -------------------------------");
    eprintln!("  Point your MCP client (Claude Desktop, Cursor, etc.) at Warden:");
    eprintln!();
    if upstream.is_empty() {
        eprintln!("  {{");
        eprintln!("    \"mcpServers\": {{");
        eprintln!("      \"my-server\": {{");
        eprintln!("        \"command\": \"warden\",");
        eprintln!("        \"args\": [\"--upstream\", \"node /path/to/mcp-server.js\"]");
        eprintln!("      }}");
        eprintln!("    }}");
        eprintln!("  }}");
    } else {
        eprintln!("  {{");
        eprintln!("    \"mcpServers\": {{");
        eprintln!("      \"my-server\": {{");
        eprintln!("        \"command\": \"warden\",");
        eprintln!("        \"args\": [\"--config\", \"warden.toml\"]");
        eprintln!("      }}");
        eprintln!("    }}");
        eprintln!("  }}");
    }
    eprintln!();

    // Ready
    eprintln!("  === READY ===");
    eprintln!();
    if upstream.is_empty() {
        eprintln!("  To start Warden:");
        eprintln!("    warden --upstream \"node /path/to/mcp-server.js\"");
    } else {
        eprintln!("  To start Warden:");
        eprintln!("    warden --config warden.toml");
        eprintln!();
        eprintln!("  Or directly:");
        eprintln!("    warden --upstream \"{}\"", upstream);
    }
    eprintln!();

    Ok(())
}

fn load_config(config_path: &Option<String>) -> Result<toml::Value> {
    let config_str = if let Some(path) = config_path {
        std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Config file {}: {}", path, e))?
    } else {
        DEFAULT_CONFIG.to_string()
    };
    Ok(toml::from_str(&config_str)?)
}

async fn run_proxy(config_path: Option<String>, upstream: Option<String>, port: u16) -> Result<()> {
    let config = load_config(&config_path)?;

    let rules_config = config.get("rules")
        .ok_or_else(|| anyhow::anyhow!("Missing [rules] section in config"))?;
    let engine = Arc::new(RwLock::new(RuleEngine::new(rules_config)?));
    info!("Rule engine: {} patterns", engine.read().unwrap().rule_count());

    let confidence_threshold = config.get("nebius")
        .and_then(|n| n.get("confidence_threshold"))
        .and_then(|c| c.as_float())
        .unwrap_or(0.7);

    if !check_api_key() {
        warn!("NEBIUS_API_KEY not set or invalid - LLM classification disabled");
        warn!("Rule engine still active. Run 'warden setup' to configure.");
    } else {
        info!("NEBIUS_API_KEY detected - LLM classification enabled");
    }

    let state = Arc::new(dashboard::AppState::new(engine.clone(), confidence_threshold));
    dashboard::start(state.clone(), port);
    info!("Dashboard: http://127.0.0.1:{}", port);
    info!("Confidence threshold: {}", confidence_threshold);

    let upstream_cmd = if let Some(u) = upstream {
        u
    } else {
        config.get("upstream_command")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("No upstream specified. Use --upstream or run 'warden setup'"))?
    };

    let parts: Vec<&str> = upstream_cmd.split_whitespace().collect();
    if parts.is_empty() { anyhow::bail!("Empty upstream command"); }
    info!("Upstream: {}", upstream_cmd);

    let audit_path = config.get("audit")
        .and_then(|a| a.get("log_path"))
        .and_then(|p| p.as_str())
        .unwrap_or("./warden-audit.jsonl").to_string();

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

    info!("Warden running. Press Ctrl+C to stop.");

    let mut line = String::new();
    loop {
        line.clear();
        let n = stdin.read_line(&mut line).await?;
        if n == 0 { break; }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => { error!("JSON-RPC parse error: {}", e); continue; }
        };

        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(Value::Null);

        if method.starts_with("tools/") {
            let decision = {
                let engine = state.engine.read().unwrap();
                engine.check(method, &params)
            };

            match decision {
                Some(d) => {
                    if d.allow {
                        info!("ALLOW: {} - {}", method, d.reason);
                        forward(&mut child_stdin, &line).await?;
                        push_event(&state, &audit_path, method, &params, "allowed", &d.reason);
                    } else {
                        warn!("BLOCK: {} - {}", method, d.reason);
                        let err = jsonrpc_error(&request, &d.reason);
                        stdout.write_all(err.as_bytes()).await?;
                        push_event(&state, &audit_path, method, &params, "blocked", &d.reason);
                        continue;
                    }
                }
                None => {
                    if !check_api_key() {
                        let reason = "No rule match and LLM disabled (NEBIUS_API_KEY not set). Blocked conservatively.";
                        warn!("BLOCK: {} - {}", method, reason);
                        let err = jsonrpc_error(&request, reason);
                        stdout.write_all(err.as_bytes()).await?;
                        push_event(&state, &audit_path, method, &params, "blocked", reason);
                        continue;
                    }
                    info!("No rule match: {} -> LLM classification", method);
                    let threshold = *state.confidence_threshold.lock().unwrap();
                    match classify::classify_tool_call(method, &params).await {
                        Ok(c) => {
                            let allow = c.verdict == "allow" && c.confidence >= threshold;
                            let reason = format!("{} ({:.2}) category: {}", c.reasoning, c.confidence, c.category);
                            if allow {
                                info!("LLM ALLOW: {}", reason);
                                forward(&mut child_stdin, &line).await?;
                                push_event(&state, &audit_path, method, &params, "allowed", &format!("LLM: {}", reason));
                            } else {
                                warn!("LLM BLOCK: {}", reason);
                                let err = jsonrpc_error(&request, &format!("Blocked by LLM: {}", reason));
                                stdout.write_all(err.as_bytes()).await?;
                                push_event(&state, &audit_path, method, &params, "blocked", &format!("Blocked by LLM: {}", reason));
                                continue;
                            }
                        }
                        Err(e) => {
                            error!("LLM classification error: {}", e);
                            let reason = format!("Classification error: {}", e);
                            let err = jsonrpc_error(&request, &reason);
                            stdout.write_all(err.as_bytes()).await?;
                            push_event(&state, &audit_path, method, &params, "blocked", &reason);
                            continue;
                        }
                    }
                }
            }
        } else {
            forward(&mut child_stdin, &line).await?;
        }

        let mut resp = String::new();
        let n = child_stdout.read_line(&mut resp).await?;
        if n == 0 { info!("Upstream closed connection"); break; }
        stdout.write_all(resp.as_bytes()).await?;
    }

    let _ = child.kill().await;
    info!("Warden shutting down");
    Ok(())
}

async fn forward(stdin: &mut tokio::process::ChildStdin, line: &str) -> Result<()> {
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
    }).to_string() + "\n"
}

fn push_event(state: &Arc<dashboard::AppState>, path: &str, method: &str, params: &Value, verdict: &str, reason: &str) {
    use chrono::Utc;
    let params_str = serde_json::to_string(params).unwrap_or_default();
    let truncated = if params_str.len() > 1024 {
        format!("{}...[truncated]", &params_str[..1024])
    } else { params_str };
    let entry = serde_json::json!({
        "timestamp": Utc::now().to_rfc3339(),
        "method": method, "params": truncated,
        "verdict": verdict, "reason": reason,
    });
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        use std::io::Write;
        let _ = writeln!(file, "{}", entry);
    }
    state.push_event(entry);
}
