# Trusted Operator mode (terminal-mcp executor)

Warden v0.4.4+ supports an operator token on the decision-only endpoint.

## What it does

- The executor attaches `"operator": "<token>"` to every POST /check/ body.
- Warden compares it against `operator_token` in warden.toml `[trusted]`.
- Rules are authoritative for EVERYONE: a rule block blocks the operator too.
- The token only changes what happens when the classifier (Nebius) is down or
  the breaker is open: trusted calls are ALLOWED with layer TRUSTED-OPEN
  (audited as no-LLM-decision), unknown callers keep strict fail-closed.

Threat model, honestly stated: this is availability for the operator, not
authority escalation. A local process that can read warden.toml can read the
token; the security boundary remains the rules layer plus LLM classification
for everything that is not the operator's own executor.

## One-time setup (run these yourself)

1. Generate a token and add it to the Warden config:

       TOKEN=$(openssl rand -hex 24)
       printf '\n[trusted]\noperator_token = "%s"\n' "$TOKEN" >> "$HOME/Library/Application Support/Warden/warden.toml"

2. Give the executor the same token (launchd agent env):

       /bin/launchctl setenv WARDEN_OPERATOR_TOKEN "$TOKEN"
       # and add env vars in the agent plist for persistence:
       #   EnvironmentVariables -> WARDEN_OPERATOR_TOKEN

3. In ~/terminal-mcp/tunnel-client.js, inside the Warden check, change the
   POST body to include the operator field:

       body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "tools/call",
         params: { name: tool, arguments: args || {} },
         operator: process.env.WARDEN_OPERATOR_TOKEN || "" }),

4. Restart the executor agent and verify: a benign call should return
   layer=LLM; kill -STOP the Warden app to simulate an outage and a benign
   call should return layer=TRUSTED-OPEN while an unknown caller (no token)
   still gets fail-closed.
