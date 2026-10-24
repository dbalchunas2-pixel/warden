import pathlib
NL = chr(10)
S = pathlib.Path('/tmp/warden-check/src')

# Fix state.rs: use raw string literals for regex patterns
p = S / 'state.rs'
t = p.read_text()
if 'apply_preset' in t:
    # Find and replace the preset patterns with raw strings
    old = t[t.find('pub fn apply_preset'):t.find('    pub fn upstream_from_config')]
    new = NL.join([
        'pub fn apply_preset(&self, preset: &str) {',
        '        let patterns: Vec<(&str, Vec<&str>)> = match preset {',
        '            "paranoid" => vec![("cmd", vec![r"rm\s+.*", r"curl.*\|.*sh", r"wget.*\|.*sh", r"dd\s+of=", r"chmod\s+777", "mkfs", "shutdown", "reboot", "kill", "sudo"]), ("path", vec![r".*\.ssh/.*", r".*\.aws/.*", ".*shadow", r".*\.env", r".*\.netrc", r".*\.gnupg/.*"])],',
        '            "balanced" => vec![("cmd", vec![r"rm\s+-rf\s+/", r"curl.*\|.*sh", r"wget.*\|.*sh", r"dd\s+of=/dev/sd", "mkfs"]), ("path", vec![r".*\.ssh/id_rsa", r".*\.aws/credentials", "/etc/shadow"])],',
        '            "permissive" => vec![],',
        '            _ => vec![],',
        '        };',
        '        let mut engine = self.engine.write().unwrap_or_else(|e| e.into_inner());',
        '        *engine = crate::rules::RuleEngine::from_preset(&patterns);',
        '    }',
        '',
    ])
    t = t[:t.find('pub fn apply_preset')] + new + t[t.find('    pub fn upstream_from_config'):]
    p.write_text(t)
    print('state.rs fixed with raw strings')
else:
    print('apply_preset not found')
