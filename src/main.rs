mod auth;

use tauri::Manager;
mod classify;
mod commands;
mod clients;
mod gateway;
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

[auth]
github_client_id = "Ov23ct40UXi2yfU05UYx"
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

    std::panic::set_hook(Box::new(|info| {
        let msg = format!("WARDEN PANIC: {}", info);
        eprintln!("{}", msg);
        if let Ok(home) = std::env::var("HOME") {
            let p = std::path::Path::new(&home).join("Library/Application Support/Warden/panics.log");
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
                use std::io::Write;
                let _ = writeln!(f, "{} | {} | {}", chrono::Utc::now().to_rfc3339(), msg, info.location().map(|l| l.to_string()).unwrap_or_default());
            }
        }
    }));

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
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            for (_, w) in app.webview_windows() {
                let _ = w.show();
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
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
            commands::auth_status,
            commands::set_master_password,
            commands::unlock,
            commands::lock_app,
            commands::oauth_start,
            commands::oauth_check,
            commands::list_servers,
            commands::add_server,
            commands::remove_server,
            commands::client_snippet,
            commands::explain_block,
            commands::synthesize_rule,
            commands::review_tools,
            commands::summarize_audit,
            commands::run_attack_simulation,
            commands::discover_servers,
            commands::get_baseline,
            commands::check_anomaly_cmd,
            commands::run_comparative,
            commands::get_posture_score,
            commands::export_policy,
            commands::import_policy,
        clients::scan_mcp_clients,
            clients::protect_all_clients,
            clients::restore_clients,
            
        commands::setup_operator_token,])
        .setup(move |app| {
            use tauri::Emitter;
            setup_state.set_handle(app.handle().clone());
            gateway::start_gateway(setup_state.clone(), 8765);

            // F3 startup self-test: prove /check round-trips a BLOCKED verdict, else scream.
            {
                let st = setup_state.clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                    let client = reqwest::Client::new();
                    let body = serde_json::json!({
                        "jsonrpc": "2.0", "method": "tools/call", "id": 0,
                        "params": {"name": "__selftest__", "arguments": {"command": "cat ~/.ssh/id_rsa"}}
                    });
                    let probe = async {
                        let resp = client.post("http://127.0.0.1:8765/check/__selftest__")
                            .json(&body)
                            .timeout(std::time::Duration::from_secs(15))
                            .send().await.ok()?;
                        let v: serde_json::Value = resp.json().await.ok()?;
                        Some(v.get("allow")?.as_bool()? == false)
                    };
                    match probe.await {
                        Some(true) => info!("[selftest] /check round-trip OK: known-bad payload BLOCKED (enforcement verified)"),
                        _ => {
                            error!("PROTECTION DEGRADED: /check self-test FAILED - known-bad payload did not come back BLOCKED. Do not trust enforcement; check panics.log");
                            st.emit("protection-degraded", &serde_json::json!({
                                "ok": false,
                                "detail": "startup self-test: /check did not return a blocked verdict for a known-bad payload"
                            }));
                        }
                    }
                });
            }

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
        .build(tauri::generate_context!())
        .expect("error while building warden")
        .run({
            let exit_state = state.clone();
            move |_app, event| {
                if let tauri::RunEvent::Exit = event {
                    exit_state.save_state();
                    info!("Warden state saved on exit");
                }
            }
        });
}
