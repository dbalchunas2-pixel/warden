# Warden

MCP Security Gateway — a native Mac app that intercepts every MCP tool call and decides whether it should execute, using deterministic rules, NVIDIA Nemotron LLM classification on Nebius Token Factory, and a fail-closed fallback stack.

Warden sits between your MCP client (Claude Desktop, Claude Code, Cursor, Windsurf, Cline) and your MCP servers. Every `tools/call` passes through a layered defense pipeline:

1. **Deterministic rules** — regex patterns for known attack vectors (credential paths, destructive commands, exfiltration). Instant, zero latency.
2. **LLM classification** — NVIDIA Nemotron on Nebius Token Factory analyzes the calls the rules don't cover, with a dynamic threat-category label on every verdict.
3. **Heuristic fallback** — a static analyzer decides protocol and dangerous-shape calls even when the LLM is unreachable, so no call is left without a decision.
4. **Fail-closed everything** — classifier outage, missing API key, or rate-limit trip means block (or rules-only mode), never a silent allow.
5. **Audit logging** — every decision recorded to JSONL with timestamp, method, params, verdict, reason, layer, and category.

## Install

### Option 1: Download the DMG

Grab `Warden_X.Y.Z_aarch64.dmg` from the [latest release](https://github.com/dbalchunas2-pixel/warden/releases/latest), drag **Warden.app** to Applications, and launch.

### Option 2: In-app updates

Once installed, Warden self-updates: **Security tab > Check for Updates**. Releases are minisign-signed; the app verifies, installs, and relaunches itself.

### Option 3: Build from source

```bash
git clone https://github.com/dbalchunas2-pixel/warden.git
cd warden
./install.sh        # builds, bundles, installs to /Applications
# or:
npx @tauri-apps/cli@2 build
open target/release/bundle/macos/Warden.app
```

## Quick Start

1. Launch Warden. First run shows the setup screen: set your upstream MCP server, optionally paste a Nebius API key, set a master password, and link a GitHub identity.
2. **Protect > Protect All Clients** rewrites your installed MCP clients' configs to route every stdio server through Warden (originals are backed up to `.warden-backup`, one click restores them).
3. Or wire a client manually:

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

## Two Operation Modes

**stdio proxy** — Warden is the `command` in the client's `mcpServers` entry. It reads JSON-RPC from stdin, inspects every call, and forwards clean traffic to the real server. The native window is the control plane.

**HTTP gateway** — Warden exposes a local gateway on `127.0.0.1:8765` for HTTP/WebSocket MCP transports:

- `POST /check/<server_name>` — decision-only endpoint: `{allow, reason, layer}` for a JSON-RPC body
- `POST /mcp/<server_name>` — forwarding proxy for HTTP transports
- WebSocket proxying with the same decision pipeline

Executors like terminal agents can gate every command through `/check/` before running it.

## The Decision Pipeline

```
tool call
   |
   v
1. Rule engine (regex, <10ms) .................. allow / block
2. Nemotron LLM (Nebius Token Factory) ......... verdict + confidence + category
   |  confidence below threshold = block
   v
Fallbacks when the LLM can't answer:
   - heuristic_decide(): protocol safe-list + dangerous-shape analyzer
   - circuit breaker: 3 consecutive failures -> 60s rules-only mode
   - trusted operator token: allow WITHOUT LLM during outages (rules still apply)
   - anything else: fail closed (blocked)
   |
   v
audit JSONL + live dashboard event
```

Every audit entry carries a threat category: `safe`, `data_exfiltration`, `destructive`, `credential_access`, `privilege_escalation`, `prompt_injection`, or a free-form label the LLM assigns. Weekly digest export rolls these up per category.

## Dashboard

- **Overview** — live call feed, stats, threat-category breakdown, block-rate sparkline, system info (LLM budget, classify timeout)
- **Audit Log** — searchable, filterable table of every decision
- **Timeline** — chronological scrubber over the audit stream: drag or press Play to replay the day's traffic, with full decision detail (reason, category, one-click pin-to-rule) per entry
- **Rules** — add, toggle, delete regex rules at runtime, no restart
- **Baseline** — per-call-count baseline with drift detection
- **Posture** — security posture summary
- **Servers** — registry of proxied MCP servers, per-server configs, copy-paste client snippets
- **Protect** — one-click Protect All across Claude Desktop, Claude Code, Cursor, Windsurf, and Cline (with backups + restore), plus a persistent record of every client that has connected through the gateway
- **Red Team** — continuous randomized attack simulation through the real pipeline; attacks vary in structure each run and passed attacks are auto-pinned as rules
- **Tester** — push any method + JSON params through the full pipeline and see the exact verdict, layer, and latency

## Security Model

- **Master password** — Argon2id, hash stored in the macOS Keychain. All mutating operations are gated server-side while locked.
- **GitHub identity** — OAuth device flow, token in Keychain.
- **Trusted operator** — a token in `warden.toml [trusted]`, echoed by trusted executors. It never bypasses rules; it only changes outage behavior from fail-closed to allow-without-LLM.
- **Rate limiting** — token bucket on LLM calls (env-tunable burst/refill); under flood, calls are stopped without spending LLM budget.
- **Zero default rules** — ships empty; apply a preset (Permissive / Balanced / Paranoid) or add your own.

## Configuration

Warden looks for a config at `--config <path>`, then `./warden.toml`, then `~/Library/Application Support/Warden/warden.toml`. Missing sections self-heal on startup.

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
path_block_patterns = [".*\\.ssh/.*", ".*\\.env$", ".*/\\.aws/credentials"]
cmd_block_patterns = ["rm .*-rf .*/", "curl.*\\|.*sh", "dd of=", "chmod 777"]

[trusted]
operator_token = "..."   # enables TRUSTED-OPEN outage mode for token holders

[auth]
github_client_id = "..." # enables the GitHub identity link

[audit]
log_path = "./warden-audit.jsonl"
```

The API key comes from `NEBIUS_API_KEY` or the config file (env wins). Without any key, rules and heuristics still block known attacks; everything else fails closed.

## How It Works

```
MCP Client (Claude, Cursor, ...)
        |
   stdin | stdout          (or HTTP / WebSocket to 127.0.0.1:8765)
        v   ^
    Warden (single Tauri app)
    +- stdio proxy / HTTP gateway: every call inspected
    +- rule engine: regex patterns block known attacks instantly
    +- LLM classifier: Nemotron verdict + confidence + category
    +- heuristic fallback + circuit breaker + rate limiter: fail-closed stack
    +- audit log: JSONL with full decision context
    +- native window: live control plane over Tauri IPC
        |
   stdin | stdout
        v   ^
    MCP Server (your actual server)
```

## Architecture

Single Rust binary, single `.app` bundle, no separate frontend build, no external services.

- `src/main.rs` — entry, gateway startup, command registration, startup self-test
- `src/state.rs` — AppState, audit persistence, config management, verdict cache, rate limiting, persistent client registry
- `src/gateway.rs` — HTTP/WS gateway on 127.0.0.1:8765, decide() pipeline
- `src/rules.rs` — regex rule engine, hot-reloadable
- `src/classify.rs` — Nebius/Nemotron client (reqwest + curl fallback), 20s timeout, temperature 0 + seeded
- `src/commands.rs` — Tauri IPC commands (audit, rules, digest, presets, clients, red team, updates)
- `src/clients.rs` — MCP client config scanner/protector with backup + restore
- `src/auth.rs` � Argon2id master password + GitHub OAuth device flow
- `ui/index.html` — plain HTML/JS SPA embedded at compile time

Tracing goes to stderr only — stdout carries MCP JSON-RPC, nothing else.

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

Flood test (30 back-to-back attacks, tight LLM budget): **30/30 blocked**, with only 3 calls consuming LLM budget — the rest stopped by the rate limiter (fail-closed) or the rule engine. The classifier request is hard-capped at a 20s timeout; any failure fails closed.

## License

Apache-2.0
