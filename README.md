# Warden

MCP Security Gateway - LLM-powered tool call classification on Nebius Token Factory with NVIDIA Nemotron.

Warden sits between your MCP client (Claude Desktop, Cursor, etc.) and your MCP server, intercepting every `tools/call` through a layered defense pipeline:

1. **Deterministic rules** - regex patterns for known attack vectors (credential paths, destructive commands, data exfiltration). Instant, zero latency.
2. **LLM classification** - NVIDIA Nemotron on Nebius Token Factory analyzes ambiguous calls the rules don't cover.
3. **Audit logging** - every decision recorded to JSONL with timestamp, method, params, verdict, and reason.

## Install

```bash
cargo install --git https://github.com/dbalchunas2-pixel/warden
```

## Quick Start

```bash
# First run - guided setup (generates warden.toml, checks API key)
warden

# Start protecting an MCP server
warden --upstream "node /path/to/mcp-server.js"

# Or use a config file
warden --config warden.toml
```

## Nebius API Key

Warden uses NVIDIA Nemotron models on Nebius Token Factory for LLM classification.

```bash
# Get a free key at https://studio.nebius.ai
export NEBIUS_API_KEY="your-key"

# Persist it
echo 'export NEBIUS_API_KEY="your-key"' >> ~/.zshrc
source ~/.zshrc
```

Without the API key, the rule engine still blocks known attacks. LLM classification is only used for calls that don't match any rule.

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

Warden runs a live dashboard at `http://127.0.0.1:31337` with:

- **Overview** - live tool call feed, stats (total/allowed/blocked/rate), threat category breakdown, block rate sparkline
- **Audit Log** - searchable, filterable table of all decisions
- **Rules** - view active rule patterns, delete rules
- **Tester** - run test scenarios through the full security pipeline

## Configuration

```toml
upstream_command = "node /path/to/mcp-server.js"

[nebius]
model = "nvidia/Nemotron-3_5-Lightning"
base_url = "https://api.tokenfactory.nebius.com/v1/"
confidence_threshold = 0.7

[rules]
block_tools = []
allow_tools = ["tools/list", "initialize", "notifications/initialized"]
path_block_patterns = [
  "/etc/.*",
  "~/.ssh/.*",
  ".*\.env$",
  ".*/\.aws/credentials",
]
cmd_block_patterns = [
  "rm .*-rf .*/",
  "curl.*\|.*sh",
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
    Warden (Rust binary)
    - Rule engine: regex patterns block known attacks instantly
    - LLM classifier: Nemotron analyzes ambiguous calls
    - Audit log: JSONL with full decision context
    - Dashboard: Axum server with SSE live events
        |
      stdin | stdout
        v   ^
    MCP Server (your actual server)
```

## Architecture

Single Rust binary. No separate frontend, no external services.

- **Proxy** - reads JSON-RPC from stdin, forwards to upstream process via stdin/stdout
- **Rule engine** - regex-based pattern matching on tool names, paths, and commands
- **LLM classifier** - sends tool call to Nemotron via Nebius Token Factory API, parses JSON verdict
- **Dashboard** - Axum web server with embedded HTML, SSE for live events, REST API for audit/rules/test
- **Audit log** - JSONL file, one line per decision

## Building from Source

```bash
git clone https://github.com/dbalchunas2-pixel/warden.git
cd warden
cargo build --release
./target/release/warden
```

## License

MIT
