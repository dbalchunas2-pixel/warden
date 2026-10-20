---
name: warden-classify-rs
description: LLM classification integration with Nebius Token Factory
metadata:
  type: reference
---
use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;

#[derive(Debug, Deserialize, Serialize)]
pub struct Classification {
    /// "allow" or "block"
    pub verdict: String,
    /// Confidence between 0.0 and 1.0
    pub confidence: f64,
    /// Short explanation from the LLM
    pub reasoning: String,
    /// Category label, e.g. "safe", "data_exfiltration", etc.
    pub category: String,
}

/// Sends a tool‑call description to the Nebius Nemotron model and parses the response.
///
/// The request follows the OpenAI‑compatible chat‑completion schema expected by the
/// Token Factory endpoint. It constructs a system prompt and a user message
/// containing the method name, JSON arguments (truncated to 4 KB), and a free‑form
/// context string (currently empty – callers may extend this).
pub async fn classify_tool_call(method: &str, params: &Value) -> Result<Classification> {
    // ---------------------------------------------------------------------
    // Build request payload
    // ---------------------------------------------------------------------
    let system_prompt = "You are Warden, a security classification engine for AI agent tool calls. Analyze the tool call and determine if it is SAFE or UNSAFE. Consider: data exfiltration, file deletion, credential access, privilege escalation, prompt injection. Respond ONLY with JSON.";

    // Truncate large argument blobs to 4 KB to stay within token limits.
    let mut args_str = serde_json::to_string(params)?;
    const MAX_BYTES: usize = 4 * 1024;
    if args_str.len() > MAX_BYTES {
        args_str.truncate(MAX_BYTES);
    }

    let user_msg = serde_json::json!({
        "tool_name": method,
        "arguments": args_str,
        "context": "",
    });

    let payload = serde_json::json!({
        "model": "nvidia/Nemotron-3_5_Lightning",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_msg},
        ],
        "temperature": 0.0,
        "max_tokens": 512,
    });

    // ---------------------------------------------------------------------
    // HTTP call
    // ---------------------------------------------------------------------
    let api_key = env::var("NEBIUS_API_KEY")
        .map_err(|_| anyhow::anyhow("NEBIUS_API_KEY not set in environment"))?;
    let client = Client::new();
    let resp = client
        .post("https://api.tokenfactory.nebius.com/v1/chat/completions")
        .bearer_auth(api_key)
        .json(&payload)
        .send()
        .await?
        .error_for_status()?;

    // Nebius returns an OpenAI‑style response where the assistant's message
    // contains the JSON payload we need.
    let resp_json: Value = resp.json().await?;
    let content = resp_json
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .ok_or_else(|| anyhow::anyhow("Malformed response from Nebius API"))?;

    // The LLM is instructed to emit only JSON, so we can deserialize directly.
    let classification: Classification = serde_json::from_str(content)?;
    Ok(classification)
}
