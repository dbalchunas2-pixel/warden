---
name: warden-rules-rs
description: Rule engine implementation for Warden
metadata:
  type: reference
---
use anyhow::Result;
use regex::Regex;
use serde_json::Value;

pub struct RuleEngine {
    block_tools: Vec<String>,
    allow_tools: Vec<String>,
    path_block_patterns: Vec<Regex>,
    cmd_block_patterns: Vec<Regex>,
}

impl RuleEngine {
    pub fn new(config: &toml::Value) -> Result<Self> {
        let block_tools = config
            .get("block_tools")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let allow_tools = config
            .get("allow_tools")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let path_block_patterns = config
            .get("path_block_patterns")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|pat| Regex::new(pat).ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let cmd_block_patterns = config
            .get("cmd_block_patterns")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|pat| Regex::new(pat).ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(Self {
            block_tools,
            allow_tools,
            path_block_patterns,
            cmd_block_patterns,
        })
    }

    pub async fn check(&self, method: &str, params: &Value) -> Option<Decision> {
        // Exact tool name matches
        if self.block_tools.iter().any(|t| t == method) {
            return Some(Decision {
                allow: false,
                reason: "Blocked by rule engine (explicit block).".into(),
            });
        }
        if self.allow_tools.iter().any(|t| t == method) {
            return Some(Decision {
                allow: true,
                reason: "Allowed by rule engine (explicit allow).".into(),
            });
        }

        // Inspect string fields in params for patterns
        if let Some(strings) = extract_string_fields(params) {
            for s in strings {
                if self.path_block_patterns.iter().any(|re| re.is_match(&s)) {
                    return Some(Decision {
                        allow: false,
                        reason: format!("Path pattern blocked: {}", s),
                    });
                }
                if self.cmd_block_patterns.iter().any(|re| re.is_match(&s)) {
                    return Some(Decision {
                        allow: false,
                        reason: format!("Command pattern blocked: {}", s),
                    });
                }
            }
        }
        None // No definitive rule
    }
}

fn extract_string_fields(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::String(s) => Some(vec![s.clone()]),
        Value::Array(arr) => {
            let mut out = Vec::new();
            for v in arr {
                if let Some(mut inner) = extract_string_fields(v) {
                    out.append(&mut inner);
                }
            }
            if out.is_empty() { None } else { Some(out) }
        }
        Value::Object(map) => {
            let mut out = Vec::new();
            for (_, v) in map {
                if let Some(mut inner) = extract_string_fields(v) {
                    out.append(&mut inner);
                }
            }
            if out.is_empty() { None } else { Some(out) }
        }
        _ => None,
    }
}

pub struct Decision {
    pub allow: bool,
    pub reason: String,
}
