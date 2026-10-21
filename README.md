# Warden

MCP Security Gateway - LLM-powered tool call classification on Nebius Token Factory with NVIDIA Nemotron.

Warden is a **native Mac app** (Tauri) that sits between your MCP client (Claude Desktop, Cursor, etc.) and your MCP server, intercepting every `tools/call` through a layered defense pipeline:

1. **Deterministic rules** - regex patterns for known attack vectors (credential paths, destructive commands, data exfiltration). Instant, zero latency.
2. **LLM classification** - NVIDIA Nemotron on Nebius Token Factory analyzes ambiguous calls the rules don't cover.
3. **Audit logging** - every decision recorded to JSONL with timestamp, method, params, verdict, and reason.

The stdio proxy and the dashboard are **one application**: the proxy inspects JSON-RPC on stdin/stdout while the native window shows what it's doing in real time over Tauri IPC events.

## Install

One command - no frontend build step, no Node required:

```bash
cargo install --git https://github.com/dbalchunas2-pixel/warden
```

Or download `Warden_0.2.0_aarch64.dmg` from a release and drag **Warden.app** to Applications.

## Quick Start

```bash
# First run - opens the Warden window with a setup screen
# (set your upstream MCP server; optionally paste a Nebius API key)
warden

# Start protecting an MCP server (proxy + live dashboard in one app)
warden --upstream "node /path/to/mcp-server.js"

# Or use a config file
warden --config warden.toml
```

When your MCP client spawns `warden --upstream ...`, the proxy reads the client's requests from stdin and the Warden window opens as the control plane.

## Nebius API Key

Warden uses NVIDIA Nemotron models on Nebius Token Factory for LLM classification.

```bash
# Get a free key at https://studio.nebius.ai
export NEBIUS_API_KEY="your-key"

# Persist it
echo 'export NEBIUS_API_KEY="your-key"' >> ~/.zshrc
source ~/.zshrc
```

GUI-launched apps don't inherit shell env vars, so the setup screen also accepts a key directly - it is stored in `warden.toml` under `[nebius] api_key`. Env var wins if both are present.

Without any key, the rule engine still blocks known attacks; unmatched calls are **blocked conservatively**.

## MCP Client Configuration

Point your MCP client at Warden instead of the real server:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "warden",
      "args": ["--upstream", "node /path/to/mcp-server.js"]
    }
  }
}
```

Or with a config file:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "warden",
      "args": ["--config", "/path/to/warden.toml"]
    }
  }
}
```

## Dashboard

The native Warden window has four views:

- **Overview** - live tool call feed, stats (total/allowed/blocked/rate), threat category breakdown, block rate sparkline
- **Audit Log** - searchable, filterable table of all decisions
- **Rules** - view, add, and delete regex rules at runtime (takes effect immediately, no restart)
- **Tester** - run any tool call (method + JSON args) through the full pipeline: rules first, then Nemotron LLM classification

## Configuration

Warden looks for a config at `--config <path>`, then `./warden.toml`, then `~/Library/Application Support/Warden/warden.toml`.

```toml
upstream_command = "node /path/to/mcp-server.js"

[nebius]
model = "nvidia/Nemotron-3_5-Lightning"
base_url = "https://api.tokenfactory.nebius.com/v1/"
confidence_threshold = 0.7
# api_key = "..."  # optional, for GUI launches without shell env

[rules]
block_tools = []
allow_tools = ["tools/list", "initialize", "notifications/initialized"]
path_block_patterns = [
  "/etc/.*",
  "~/.ssh/.*",
  ".*\\.ssh/.*",
  ".*\\.env$",
  ".*/\\.aws/credentials",
]
cmd_block_patterns = [
  "rm .*-rf .*/",
  "curl.*\\|.*sh",
  "dd of=",
  "chmod 777",
  "mkfs",
  "shutdown",
  "kill -9",
]

[audit]
log_path = "./warden-audit.jsonl"
```

## How It Works

```
MCP Client (Claude, Cursor)
        |
   stdin | stdout
        v   ^
    Warden (single Tauri app)
    +- stdio proxy: JSON-RPC in, inspected JSON-RPC out
    +- rule engine: regex patterns block known attacks instantly
    +- LLM classifier: Nemotron analyzes ambiguous calls
    +- audit log: JSONL with full decision context
    +- native window: control plane, receives live Tauri events
        |
   stdin | stdout
        v   ^
    MCP Server (your actual server)
```

## Architecture

Single Rust binary and single `.app` bundle. No separate frontend build, no external services, no localhost HTTP server.

- **Proxy** (`src/state.rs`) - reads JSON-RPC from stdin, forwards to the upstream process spawned by Warden, emits `tool-call-event` / `proxy-status` Tauri events for every decision
- **Rule engine** (`src/rules.rs`) - regex-based pattern matching on tool names, paths, and commands; hot-reloadable at runtime
- **LLM classifier** (`src/classify.rs`) - sends tool call to Nemotron via the Nebius Token Factory API, parses the JSON verdict, threshold 0.7
- **Commands** (`src/commands.rs`) - Tauri IPC commands (`get_audit_log`, `get_rules`, `add_rule`, `delete_rule`, `test_tool_call`, `get_stats`, `get_status`, `save_setup`, `start_proxy`) replace the old REST API
- **Frontend** (`ui/index.html`) - plain HTML/JS SPA embedded into the binary at compile time, calls `invoke()` and listens to proxy events

Tracing goes to stderr only - stdout carries MCP JSON-RPC, nothing else.

## Building from Source

```bash
git clone https://github.com/dbalchunas2-pixel/warden.git
cd warden
cargo build --release                      # binary at target/release/warden
npx @tauri-apps/cli@2 build                # Warden.app + dmg installer
```

## Adversarial Evaluation

Warden ships with a reproducible adversarial evaluation harness (`eval/attack_harness.cjs`, zero dependencies):

```sh
node eval/attack_harness.cjs --seed 1337          # full tiered suite
node eval/attack_harness.cjs --seed 42 --flood 30 # DoS / budget-exhaustion test
```

It fires randomized attacks across five difficulty tiers (loud rule-level, explicit, obfuscated, indirect/multi-step, evasion-grade) plus benign controls, grades every verdict against ground truth, and writes a markdown + JSON report to `eval/results/`.

Latest results (seed 1337, 22 attacks + 6 benign controls):

- Attack detection rate: **100%**
- False-positive rate on benign traffic: **0%**
- Avg latency per verdict: **~3.5s** (rule-level decisions in <10ms)

Flood test (30 back-to-back attacks, tight LLM budget): **30/30 blocked**, with only 3 calls consuming LLM budget — the rest stopped by the rate limiter (fail-closed) or the rule engine. The classifier request itself is hard-capped at a 20s timeout; any failure fails closed.

## License

Apache-2.0
