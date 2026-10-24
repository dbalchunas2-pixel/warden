# v0.5.4 Rust patches - apply with: python3 scripts/apply_v054_rust.py
# This file patches state.rs and classify.rs with double-quoted Rust strings
import pathlib
NL = chr(10)
DQ = chr(34)
SQ = chr(39)
S = pathlib.Path('/tmp/warden-check/src')
errs = []

# ============ state.rs: preset method with double quotes ============
p = S / 'state.rs'
t = p.read_text()
if 'apply_preset' not in t:
    a = '    pub fn upstream_from_config'
    if a in t:
        preset = NL.join([
            '    pub fn apply_preset(&self, preset: &str) {',
            '        let patterns: Vec<(&str, Vec<&str>)> = match preset {',
            '            "paranoid" => vec![("cmd", vec!["rm\\s+.*", "curl.*\\|.*sh", "wget.*\\|.*sh", "dd\\s+of=", "chmod\\s+777", "mkfs", "shutdown", "reboot", "kill", "sudo"]), ("path", vec![".*\\.ssh/.*", ".*\\.aws/.*", ".*shadow", ".*\\.env", ".*\\.netrc", ".*\\.gnupg/.*"])],',
            '            "balanced" => vec![("cmd", vec!["rm\\s+-rf\\s+/", "curl.*\\|.*sh", "wget.*\\|.*sh", "dd\\s+of=/dev/sd", "mkfs"]), ("path", vec![".*\\.ssh/id_rsa", ".*\\.aws/credentials", "/etc/shadow"])],',
            '            "permissive" => vec![],',
            '            _ => vec![],',
            '        };',
            '        let mut engine = self.engine.write().unwrap_or_else(|e| e.into_inner());',
            '        *engine = crate::rules::RuleEngine::from_preset(&patterns);',
            '    }',
            '',
        ])
        t = t.replace(a, preset + a, 1)
        p.write_text(t)
        print('state.rs: preset method added')
    else:
        errs.append('state.rs anchor')
else:
    print('state.rs: SKIP')

# ============ classify.rs: dynamic categories ============
p = S / 'classify.rs'
t = p.read_text()
# Remove the fixed category list from the prompt
start = t.find('- data_exfiltration:')
if start > 0:
    end = t.find('Respond ONLY')
    if end > start:
        t = t[:start] + t[end:]
# Replace the fixed category list in the JSON response template
target = '| "other"}' + DQ + '#;'
replacement = '| "<choose any descriptive label>"}' + DQ + '#;'
if target in t:
    t = t.replace(target, replacement, 1)
    print('classify.rs: category made dynamic')
else:
    print('classify.rs: category target not found (may be already fixed)')
p.write_text(t)

if errs:
    print('ERRORS:', errs)
else:
    print('RUST PATCHES DONE')
