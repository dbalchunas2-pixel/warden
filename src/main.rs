mod classify;
mod commands;
mod rules;
mod state;

use state::AppState;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};

const DEFAULT_CONFIG: &str = r##"# upstream_command = "node /path/to/mcp-server.js"

[nebius]
model = "nvidia/Nemotron-3_5-Lightning"
base_url = "https://api.tokenfactory.nebius.com/v1/"
api_key_env = "NEBIUS_API_KEY"
max_context_chars = 4096
confidence_threshold = 0.7
# api_key = "..."  # optional: used when NEBIUS_API_KEY is not in the environment (GUI launch)

[rules]
block_tools = []
allow_tools = ["tools/list", "initialize", "notifications/initialized"]
path_block_patterns = [
  "/etc/.*",
  "~/.ssh/.*",
  ".*\\.ssh/.*",
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
"##;

fn parse_args() -> (Option<String>, Option<String>) {
    let mut config = None;
    let mut upstream = None;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                config = args.get(i).cloned();
            }
            "--upstream" | "-u" => {
                i += 1;
                upstream = args.get(i).cloned();
            }
            "--version" | "-V" => {
                println!("warden 0.2.0");
                std::process::exit(0);
            }
            "--help" | "-h" => {
                eprintln!("warden - MCP Security Gateway");
                eprintln!("usage: warden [--config warden.toml] [--upstream \"node /path/to/mcp-server.js\"]");
                eprintln!("  With no args: opens the Warden dashboard (setup screen if unconfigured).");
                eprintln!("  With --upstream: runs the stdio MCP proxy AND the dashboard.");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }
    (config, upstream)
}

fn load_config(cli_config: &Option<String>) -> anyhow::Result<(toml::Value, Option<PathBuf>)> {
    if let Some(p) = cli_config {
        let s = std::fs::read_to_string(p)
            .map_err(|e| anyhow::anyhow!("Config file {}: {}", p, e))?;
        return Ok((toml::from_str(&s)?, Some(PathBuf::from(p))));
    }
    let cwd_conf = PathBuf::from("warden.toml");
    if cwd_conf.exists() {
        let s = std::fs::read_to_string(&cwd_conf)?;
        return Ok((toml::from_str(&s)?, Some(cwd_conf)));
    }
    if let Some(home) = std::env::var_os("HOME") {
        let p = PathBuf::from(home).join("Library/Application Support/Warden/warden.toml");
        if p.exists() {
            let s = std::fs::read_to_string(&p)?;
            return Ok((toml::from_str(&s)?, Some(p)));
        }
    }
    Ok((toml::from_str(DEFAULT_CONFIG)?, None))
}

fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let (config_path_arg, upstream_arg) = parse_args();

    let (config, config_path) = match load_config(&config_path_arg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("warden: {}", e);
            std::process::exit(1);
        }
    };

    let state = match AppState::new(&config, config_path) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("warden: {}", e);
            std::process::exit(1);
        }
    };

    let setup_state = state.clone();

    tauri::Builder::default()
        .manage(state.clone())
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![
            commands::get_audit_log,
            commands::get_rules,
            commands::add_rule,
            commands::delete_rule,
        commands::toggle_rule,
        commands::export_audit,
            commands::test_tool_call,
            commands::get_stats,
            commands::get_status,
            commands::save_setup,
            commands::start_proxy,
        ])
        .setup(move |app| {
            use tauri::Emitter;
            setup_state.set_handle(app.handle().clone());

            let upstream = upstream_arg
                .clone()
                .or_else(|| setup_state.upstream_from_config())
                .filter(|s| !s.trim().is_empty());

            match upstream {
                Some(cmd) => {
                    info!("Auto-starting proxy: {}", cmd);
                    if let Err(e) = setup_state.start_proxy(&cmd) {
                        error!("Failed to start proxy: {}", e);
                    }
                }
                None => {
                    info!("No upstream configured - showing setup screen");
                    let _ = app.emit("setup-required", true);
                }
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running warden");
}
