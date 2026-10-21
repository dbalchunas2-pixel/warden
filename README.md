# Warden

**MCP Security Gateway with LLM-Powered Tool Call Classification**

Warden is a security proxy that sits between an AI agent and its MCP (Model Context Protocol) tools. It intercepts every tool call and runs it through a layered defense pipeline before allowing execution.

## One-Command Install

```bash
cargo install --git https://github.com/dbalchunas2-pixel/warden
export NEBIUS_API_KEY="your-key"
warden demo
```

That's it. The demo runs 5 attack scenarios through Warden with a built-in mock MCP server and opens a live dashboard.

## How It Works

```
AI Agent (MCP Client)
    |
    v
  Warden (proxy + security pipeline)
    |
    +---> Layer 1: Rule Engine (deterministic, instant)
    |     - Tool name allow/deny lists
    |     - Path pattern matching (blocks /etc/*, ~/.ssh/*, .env, etc.)
    |     - Command pattern matching (blocks rm -rf /, curl|sh, etc.)
    |
    +---> Layer 2: LLM Classification (NVIDIA Nemotron on Nebius)
    |     - Analyzes ambiguous calls the rules don't cover
    |     - Classifies as safe/unsafe with confidence score
    |     - Conservative: blocks if confidence < threshold
    |
    v
  Upstream MCP Server (actual tool execution)
```

## Why Layered Defense?

Using an LLM as the sole security gate is vulnerable to prompt injection - the same attack that tricks the agent can trick the classifier. Warden uses a deterministic rule engine as the first layer (unbypassable) and the LLM as a second layer for nuanced classification.

- Known-bad patterns are blocked instantly by rules, no LLM needed
- Novel attacks are caught by the LLM's contextual understanding
- Even if the LLM is tricked, the rules still catch obvious attacks

## Usage

### Demo Mode
```bash
warden demo
```
Runs 5 attack scenarios with a built-in mock MCP server. Opens a live dashboard at http://127.0.0.1:31337.

### Proxy Mode
```bash
# With CLI args
warden --upstream "node /path/to/mcp-server.js"

# With a config file
warden --config my-config.toml --upstream "node server.js"

# Custom dashboard port
warden --upstream "node server.js" --port 8080
```

### Config File (optional)
All config is built into the binary. To customize, create a TOML file:

```toml
upstream_command = "node /path/to/server.js"

[nebius]
model = "nvidia/Nemotron-3_5-Lightning"
confidence_threshold = 0.7

[rules]
block_tools = []
allow_tools = ["tools/list", "initialize"]
path_block_patterns = ["/etc/.*", "~/.ssh/.*", ".*\.env$"]
cmd_block_patterns = ["rm .*-rf .*/", "curl.*\|.*sh", "dd of="]

[audit]
log_path = "./warden-audit.jsonl"
```

## Dashboard

When running, Warden serves a live monitoring dashboard at http://127.0.0.1:31337 showing:
- Real-time tool call feed (allowed/blocked with colors)
- Stats: total calls, allowed, blocked, block rate
- Threat category breakdown
- Active rule patterns

## Demo Scenarios

1. **Credential Access** - Agent reads `~/.ssh/id_rsa` -> BLOCKED by Nemotron LLM (credential_access)
2. **Destructive Command** - Agent runs `dd of=/dev/sda` -> BLOCKED by rule engine (instant)
3. **Safe File Read** - Agent reads project source -> ALLOWED by Nemotron LLM (safe)
4. **Data Exfiltration** - Agent pipes auth logs through base64+curl -> BLOCKED by Nemotron LLM (data_exfiltration)
5. **Prompt Injection** - Agent writes file with embedded `curl|bash` -> BLOCKED by rule engine (instant)

## Built For

- **Nebius x NVIDIA Global AI Hackathon** - Coding & Agentic Engineering track
- Uses NVIDIA Nemotron-3.5-Lightning on Nebius Token Factory
- OpenAI-compatible API, open-source models, open infrastructure

## Tech Stack

- Rust + Tokio (async runtime)
- Model Context Protocol (MCP) JSON-RPC 2.0 over stdio
- Nebius Token Factory API (NVIDIA Nemotron models)
- Deterministic rule engine (regex patterns)
- Embedded web dashboard (axum)
- Append-only audit log (JSONL)
- Zero external config files - everything compiled into the binary
