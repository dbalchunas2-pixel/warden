use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{Arc, RwLock};

#[derive(Clone, Serialize, Deserialize)]
pub struct RuleEntry {
    #[serde(rename = "type")]
    pub rule_type: String, // "path" or "cmd"
    pub pattern: String,
}

pub struct RuleEngine {
    pub block_tools: Vec<String>,
    pub allow_tools: Vec<String>,
    rules: Vec<CompiledRule>,
}

struct CompiledRule {
    rule_type: String,
    pattern: String,
    regex: Regex,
}

/// Thread-safe shared rule engine that can be updated at runtime
pub type SharedEngine = Arc<RwLock<RuleEngine>>;

impl RuleEngine {
    pub fn new(config: &toml::Value) -> Result<Self> {
        let block_tools = get_string_array(config, "block_tools");
        let allow_tools = get_string_array(config, "allow_tools");
        let path_patterns = get_string_array(config, "path_block_patterns");
        let cmd_patterns = get_string_array(config, "cmd_block_patterns");

        let mut rules = Vec::new();
        for p in &path_patterns {
            if let Ok(re) = Regex::new(p) {
                rules.push(CompiledRule { rule_type: "path".into(), pattern: p.clone(), regex: re });
            }
        }
        for p in &cmd_patterns {
            if let Ok(re) = Regex::new(p) {
                rules.push(CompiledRule { rule_type: "cmd".into(), pattern: p.clone(), regex: re });
            }
        }

        Ok(Self { block_tools, allow_tools, rules })
    }

    /// Create from a list of rule entries (used when updating from dashboard)
    pub fn from_entries(block_tools: Vec<String>, allow_tools: Vec<String>, entries: &[RuleEntry]) -> Result<Self> {
        let mut rules = Vec::new();
        for e in entries {
            if let Ok(re) = Regex::new(&e.pattern) {
                rules.push(CompiledRule { rule_type: e.rule_type.clone(), pattern: e.pattern.clone(), regex: re });
            }
        }
        Ok(Self { block_tools, allow_tools, rules })
    }

    pub fn check(&self, method: &str, params: &Value) -> Option<Decision> {
        if self.block_tools.iter().any(|t| t == method) {
            return Some(Decision { allow: false, reason: "Blocked by rule engine (explicit block)".into() });
        }
        if self.allow_tools.iter().any(|t| t == method) {
            return Some(Decision { allow: true, reason: "Allowed by rule engine (explicit allow)".into() });
        }
        if let Some(strings) = extract_string_fields(params) {
            for s in &strings {
                for rule in &self.rules {
                    if rule.regex.is_match(s) {
                        return Some(Decision {
                            allow: false,
                            reason: format!("Blocked by rule: {}", rule.pattern),
                        });
                    }
                }
            }
        }
        None
    }

    pub fn list_rules(&self) -> Vec<RuleEntry> {
        self.rules.iter().map(|r| RuleEntry { rule_type: r.rule_type.clone(), pattern: r.pattern.clone() }).collect()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

fn get_string_array(config: &toml::Value, key: &str) -> Vec<String> {
    config.get(key)
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default()
}

fn extract_string_fields(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::String(s) => Some(vec![s.clone()]),
        Value::Array(arr) => {
            let mut out = Vec::new();
            for v in arr { if let Some(mut i) = extract_string_fields(v) { out.append(&mut i); } }
            if out.is_empty() { None } else { Some(out) }
        }
        Value::Object(map) => {
            let mut out = Vec::new();
            for (_, v) in map { if let Some(mut i) = extract_string_fields(v) { out.append(&mut i); } }
            if out.is_empty() { None } else { Some(out) }
        }
        _ => None,
    }
}

pub struct Decision {
    pub allow: bool,
    pub reason: String,
}
