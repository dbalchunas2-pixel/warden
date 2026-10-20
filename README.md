---
name: warden-readme-md
description: Project overview and usage guide for Warden
metadata:
  type: reference
---
# Warden

**Warden** is an LLM‑powered MCP (Model Context Protocol) security gateway designed for the Nebius × NVIDIA hackathon. It sits between an MCP client and one or more upstream MCP servers, intercepting tool calls and classifying them as safe or unsafe using a deterministic rule engine (Layer 1) and NVIDIA Nemotron models via the Nebius Token Factory (Layer 2).

## Features

- **Async Rust** implementation built on Tokio for high‑performance, non‑blocking I/O.
- **Rule Engine** – fast, deterministic checks based on a TOML configuration file.
- **LLM Classification** – calls the Nemotron‑3.5 Lightning model when rules are inconclusive.
- **Audit Logging** – every decision is written to `audit.log` in JSONL format with timestamps.
- **Standard JSON‑RPC 2.0** – fully compatible with the MCP protocol over stdio.

## Architecture

```
MCP Client  ──►  Warden (proxy)  ──►  Upstream MCP Server
                │                │
                │   Rule Engine │
                │   LLM Classifier (Nemotron)
                │   Audit Log
```

## Quick Start

```bash
# Clone the repository (already created in ~/warden)
cd ~/warden

# Build the binary
cargo build --release

# Run Warden, pointing it at an upstream MCP server executable
# Example placeholder: ./upstream_mcp
./target/release/warden --upstream ./upstream_mcp
```

The proxy will read JSON‑RPC messages from its own `stdin`, apply the security pipeline, forward allowed calls to the upstream server, and write responses back to the client.

## Configuration

The default configuration lives in `config/default.toml`. You can copy it to `config/local.toml` and adjust the rules to your needs. The fields are:

- `block_tools` – exact tool names that are always denied.
- `allow_tools` – exact tool names that bypass the LLM and are always allowed.
- `path_block_patterns` – regexes matching path arguments that should be blocked.
- `cmd_block_patterns` – regexes matching dangerous command strings.

## Development

Run the test suite (currently none) and format the code:

```bash
cargo fmt
cargo clippy -- -D warnings
```

## License

MIT © 2026 Nebius × NVIDIA Hackathon Team.
