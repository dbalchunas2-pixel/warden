# Warden

**MCP Security Gateway with LLM-Powered Tool Call Classification**

Warden is a security proxy that sits between an AI agent and its MCP (Model Context Protocol) tools. It intercepts every tool call and runs it through a layered defense pipeline before allowing execution.

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

Using an LLM as the sole security gate is vulnerable to prompt injection - the same attack that tricks the agent can trick the classifier. Warden uses a deterministic rule engine as the first layer (unbypassable) and the LLM as a second layer for nuanced classification. This layered approach means:

- Known-bad patterns are blocked instantly by rules, no LLM needed
- Novel attacks are caught by the LLM's contextual understanding
- Even if the LLM is tricked, the rules still catch obvious attacks

## Quick Start

```bash
# Set your Nebius API key
export NEBIUS_API_KEY="your-key-here"

# Build
cargo build --release

# Run with a real MCP server
./target/release/warden --config config/default.toml --upstream "node /path/to/mcp-server.js"

# Or test without a real server
./target/release/warden --config config/default.toml --upstream "cat"
```

## Configuration

See `config/default.toml` for all options. Key sections:

- `upstream_command`: The MCP server command to proxy to
- `[nebius]`: Nebius Token Factory settings (model, API key, confidence threshold)
- `[rules]`: Deterministic rule engine (tool names, path patterns, command patterns)
- `[audit]`: Audit log path (JSONL format)

## Built For

- **Nebius x NVIDIA Global AI Hackathon** - Coding & Agentic Engineering track
- Uses NVIDIA Nemotron-3.5 Lightning model on Nebius Token Factory
- OpenAI-compatible API, open-source models, open infrastructure

## Tech Stack

- Rust + Tokio (async runtime)
- Model Context Protocol (MCP) JSON-RPC 2.0 over stdio
- Nebius Token Factory API (NVIDIA Nemotron models)
- Deterministic rule engine (regex patterns)
- Append-only audit log (JSONL)

## Architecture Decisions

### Why not LLM-only security?
LLM-only security gates are vulnerable to prompt injection. An attacker can craft tool call arguments that contain instructions to the classifier itself. Warden's rule engine provides a deterministic first layer that cannot be bypassed by prompt injection.

### Why not rules-only security?
Rules can't catch novel attacks or understand context. A tool call that reads `passwords.txt` from a non-standard path, or chains `curl` with `base64` in a novel way, would slip past static patterns. The LLM layer catches what rules can't.

### Why conservative blocking?
When the LLM classifier returns confidence below the threshold (default 0.7), Warden blocks the call. In security, false negatives (allowing an attack) are worse than false positives (blocking a safe call). The audit log records every decision for review.
