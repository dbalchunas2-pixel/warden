import pathlib, re
NL = chr(10)
DQ = chr(34)
SQ = chr(39)
BS = chr(92)

S = pathlib.Path('/tmp/warden-check/src')
U = pathlib.Path('/tmp/warden-check/ui/index.html')
errs = []

# ============ 1. CLASSIFY.RS: truly dynamic categories ============
p = S / 'classify.rs'
t = p.read_text()
old_prompt_end = '- other: anything else suspicious' + NL + NL + 'Respond ONLY with a JSON object, no markdown, no explanation outside the JSON:' + NL + '{"verdict": "allow" | "block", "confidence": <0.0-1.0>, "reasoning": "<one sentence>", "category": "safe" | "data_exfiltration" | "destructive" | "credential_access" | "privilege_escalation" | "prompt_injection" | "other"}#;'
new_prompt_end = NL + 'Respond ONLY with a JSON object, no markdown, no explanation outside the JSON:' + NL + '{"verdict": "allow" | "block", "confidence": <0.0-1.0>, "reasoning": "<one sentence>", "category": "<your own category - choose any descriptive label that fits, e.g. data_exfiltration, destructive, credential_access, privilege_escalation, prompt_injection, reverse_shell, persistence, anti_forensics, supply_chain, lateral_movement, reconnaissance, or any other fitting label>"}#;'
if old_prompt_end in t:
    cat_list_start = t.find('- data_exfiltration:')
    if cat_list_start > 0:
        t = t[:cat_list_start] + new_prompt_end
    t = t.replace('pub category: String,', 'pub category: String, // freely chosen by LLM')
    p.write_text(t)
    print('1. classify.rs: dynamic categories')
else:
    print('1. classify.rs: SKIP')

# ============ 2. STATE.RS: security presets ============
p = S / 'state.rs'
t = p.read_text()
if 'apply_security_preset' not in t:
    a = '    pub fn upstream_from_config'
    if a in t:
        preset_method = NL.join([
            '    pub fn apply_preset(&self, preset: &str) {',
            '        let patterns: Vec<(&str, Vec<&str>)> = match preset {',
            '            ' + SQ + 'paranoid' + SQ + ' => vec![(' + SQ + 'cmd' + SQ + ', vec![' + SQ + 'rm\\s+.*' + SQ + ', ' + SQ + 'curl.*\\|.*sh' + SQ + ', ' + SQ + 'wget.*\\|.*sh' + SQ + ', ' + SQ + 'dd\\s+of=' + SQ + ', ' + SQ + 'chmod\\s+777' + SQ + ', ' + SQ + 'mkfs' + SQ + ', ' + SQ + 'shutdown' + SQ + ', ' + SQ + 'reboot' + SQ + ', ' + SQ + 'kill' + SQ + ', ' + SQ + 'sudo' + SQ + ']), (' + SQ + 'path' + SQ + ', vec![' + SQ + '.*\\.ssh/.*' + SQ + ', ' + SQ + '.*\\.aws/.*' + SQ + ', ' + SQ + '.*shadow' + SQ + ', ' + SQ + '.*\\.env' + SQ + ', ' + SQ + '.*\\.netrc' + SQ + ', ' + SQ + '.*\\.gnupg/.*' + SQ + '])],',
            '            ' + SQ + 'balanced' + SQ + ' => vec![(' + SQ + 'cmd' + SQ + ', vec![' + SQ + 'rm\\s+-rf\\s+/' + SQ + ', ' + SQ + 'curl.*\\|.*sh' + SQ + ', ' + SQ + 'wget.*\\|.*sh' + SQ + ', ' + SQ + 'dd\\s+of=/dev/sd' + SQ + ', ' + SQ + 'mkfs' + SQ + ']), (' + SQ + 'path' + SQ + ', vec![' + SQ + '.*\\.ssh/id_rsa' + SQ + ', ' + SQ + '.*\\.aws/credentials' + SQ + ', ' + SQ + '/etc/shadow' + SQ + '])],',
            '            ' + SQ + 'permissive' + SQ + ' => vec![],',
            '            _ => vec![],',
            '        };',
            '        let mut engine = self.engine.write().unwrap_or_else(|e| e.into_inner());',
            '        *engine = crate::rules::RuleEngine::from_preset(&patterns);',
            '    }',
            '',
        ])
        t = t.replace(a, preset_method + a, 1)
        p.write_text(t)
        print('2. state.rs: preset method added')
    else:
        errs.append('state.rs preset anchor')
else:
    print('2. state.rs: SKIP')

# ============ 3. RULES.RS: from_preset ============
p = S / 'rules.rs'
t = p.read_text()
if 'from_preset' not in t:
    a = '    pub fn from_entries'
    preset_fn = NL.join([
        '    pub fn from_preset(patterns: &[(&str, Vec<&str>)]) -> Self {',
        '        let mut rules = Vec::new();',
        '        for (rule_type, pats) in patterns {',
            '            for p in pats {',
            '                if let Ok(re) = Regex::new(p) {',
            '                    rules.push(CompiledRule { rule_type: rule_type.to_string(), pattern: p.to_string(), regex: re, enabled: true });',
            '                }',
            '            }',
        '        }',
        '        Self { block_tools: vec![], allow_tools: vec![], rules }',
        '    }',
        '',
    ])
    t = t.replace(a, preset_fn + a, 1)
    p.write_text(t)
    print('3. rules.rs: from_preset added')
else:
    print('3. rules.rs: SKIP')

# ============ 4. COMMANDS.RS: apply_preset + red team learning ============
p = S / 'commands.rs'
t = p.read_text()

if 'apply_security_preset' not in t:
    preset_cmd = NL.join([
        '',
        '#[tauri::command]',
        'pub fn apply_security_preset(state: State<' + SQ + '_, Arc<AppState>>, preset: String) -> Result<Value, String> {',
        '    gate(&state)?;',
        '    state.apply_preset(&preset);',
        '    Ok(json!({"ok": true, "preset": preset}))',
        '}',
        '',
    ])
    t = t + NL + preset_cmd
    print('4a. commands.rs: apply_security_preset added')

m = S / 'main.rs'
mt = m.read_text()
if 'apply_security_preset' not in mt:
    a = 'commands::relaunch_app,]'
    if a in mt:
        mt = mt.replace(a, 'commands::relaunch_app,' + NL + '        commands::apply_security_preset,]', 1)
        m.write_text(mt)
        print('4b. main.rs: registered')
    else:
        errs.append('main.rs registration anchor')

if 'auto_pin' not in t:
    old_push = 'results.push(json!({"level": attack["level"], "name": attack["name"], "description": attack["description"], "method": method, "params": params, "verdict": verdict, "reason": sim_reason, "layer": layer, "ms": t0.elapsed().as_millis() as u64, "category": cat}));'
    if old_push in t:
        learning_code = NL.join([
            '        results.push(json!({"level": attack["level"], "name": attack["name"], "description": attack["description"], "method": method, "params": params, "verdict": verdict, "reason": sim_reason, "layer": layer, "ms": t0.elapsed().as_millis() as u64, "category": cat}));',
            '        if verdict == "allowed" && attack["level"].as_u64().unwrap_or(0) > 0 {',
            '            let cmd = params.get("command").and_then(|v| v.as_str())',
            '                .or_else(|| params.get("arguments").and_then(|a| a.get("command")).and_then(|v| v.as_str()));',
            '            let path = params.get("path").and_then(|v| v.as_str())',
            '                .or_else(|| params.get("arguments").and_then(|a| a.get("path")).and_then(|v| v.as_str()));',
            '            let (rt, raw) = if let Some(c) = cmd { ("cmd", c.to_string()) }',
            '                else if let Some(p) = path { ("path", p.to_string()) }',
            '                else { ("cmd", serde_json::to_string(params).unwrap_or_default()) };',
            '            let escaped = regex::escape(&raw);',
            '            let mut engine = state.engine.write().unwrap_or_else(|e| e.into_inner());',
            '            *engine = crate::rules::RuleEngine::from_entries(vec![], vec![], &{',
            '                let mut e = engine.list_rules();',
            '                e.push(crate::rules::RuleEntry { rule_type: rt.to_string(), pattern: escaped, enabled: true });',
            '                e',
            '            });',
            '            tracing::warn!("[redteam] ATTACK PASSED - auto-pinned rule: {} = {}", rt, escaped);',
            '        }',
        ])
        t = t.replace(old_push, learning_code, 1)
        print('4c. commands.rs: red team auto-learning added')
    else:
        errs.append('red team learning anchor')

p.write_text(t)
print('5. gateway.rs: no change needed')

# ============ 6. UI ============
u = U
s = u.read_text()

if "'timeline'" not in s:
    s = s.replace("'audit','rules','baseline','posture'", "'audit','timeline','rules','baseline','posture'")
    s = s.replace("'audit':'Audit Log'", "'audit':'Audit Log','timeline':'Timeline'")
    print('6a. UI: Timeline tab added')

if 'view-timeline' not in s:
    s = re.sub(r'<div class="scrubber-bar">.*?</div>\s*<div class="filter-bar"', '<div class="filter-bar"', s, flags=re.S)
    timeline_html = '<div class="view" id="view-timeline"><div style="padding:18px 22px;height:calc(100vh - 155px);overflow-y:auto"><div class="section-title">Audit Timeline Replay</div><p style="color:var(--dim);font-size:11px;margin-bottom:16px">Playback security decisions as a timeline. Press Play to auto-advance, or drag the slider to scrub.</p><div class="scrubber-bar"><button class="scrubber-btn" id="scrub-play" onclick="toggleScrub()">Play</button><input type="range" id="scrub-slider" min="0" max="0" value="0" oninput="seekScrub(this.value)"><span class="scrubber-time" id="scrub-time">-</span></div><div id="timeline-feed" style="margin-top:16px"></div></div></div>'
    audit_end = s.find('</div></div>', s.find('view-audit'))
    if audit_end > 0:
        s = s[:audit_end+8] + timeline_html + s[audit_end+8:]
        print('6b. UI: Timeline view added')
    else:
        errs.append('timeline view insert point')

if 'applyPreset' not in s:
    preset_html = '<div class="panel" style="margin-top:16px"><div class="section-title">Security Presets</div><p style="color:var(--dim);font-size:11px;margin:8px 0">Apply a curated rules profile. Ships with zero rules by default - choose a preset or add your own.</p><div style="display:flex;gap:8px;margin-top:8px"><button class="export-btn" onclick="applyPreset(' + DQ + 'permissive' + DQ + ')">Permissive (LLM only)</button><button class="export-btn" onclick="applyPreset(' + DQ + 'balanced' + DQ + ')">Balanced</button><button class="export-btn" onclick="applyPreset(' + DQ + 'paranoid' + DQ + ')">Paranoid</button></div></div>'
    id_panel = s.find('id="op-panel"')
    if id_panel > 0:
        s = s[:id_panel] + preset_html + s[id_panel:]
    else:
        sec_title = s.find('view-security')
        if sec_title > 0:
            insert_pt = s.find('</div>', sec_title + 100)
            if insert_pt > 0:
                s = s[:insert_pt+6] + preset_html + s[insert_pt+6:]
    preset_js = 'async function applyPreset(p){try{await invoke(' + DQ + 'apply_security_preset' + DQ + ',{preset:p});toast(' + DQ + 'Preset applied: ' + DQ + '+p,' + DQ + 'ok' + DQ + ')}catch(e){toast(String(e),' + DQ + 'err' + DQ + ')}}'
    s = s.replace('<script>', '<script>' + NL + preset_js, 1)
    print('6c. UI: preset buttons added')

old_cat = "const c=e.category||((e.reason||'').split('cat:')[1]||'').trim().split(/[ ,.]/)[0]||(e.verdict==='allowed'?'safe':'other');"
new_cat = "const c=e.category||((e.reason||'').split('cat:')[1]||'').trim()||(e.verdict==='allowed'?'safe':'unclassified');"
if old_cat in s:
    s = s.replace(old_cat, new_cat, 1)
    print('6d. UI: dynamic categories')
else:
    print('6d. UI: category anchor not found')

old_protect = 'setTimeout(function(){invoke(' + DQ + 'relaunch_app' + DQ + ')},1500);'
new_protect = 'setTimeout(function(){invoke(' + DQ + 'relaunch_app' + DQ + ').then(function(){toast(' + DQ + 'Warden restarted. Checking protected clients...' + DQ + ',' + DQ + 'ok' + DQ + ');setTimeout(scanClients,3000)})},1500);'
if old_protect in s:
    s = s.replace(old_protect, new_protect, 1)
    print('6e. UI: protect status after restart')

if 'renderTimeline' not in s:
    tl_js = 'async function loadTimeline(){try{const r=await invoke(' + DQ + 'get_audit' + DQ + ',{limit:100});window._auditEntries=r||[];var feed=document.getElementById(' + DQ + 'timeline-feed' + DQ + ');if(!feed)return;feed.innerHTML=' + DQ + '' + DQ + ';(r||[]).slice(-50).reverse().forEach(function(e){var el=document.createElement(' + DQ + 'div' + DQ + ');el.className=' + DQ + 'entry ' + DQ + '+(e.verdict===' + DQ + 'allowed' + DQ + '?' + DQ + 'allowed' + DQ + ':' + DQ + 'blocked' + DQ + ');var ts=(e.timestamp||' + DQ + '' + DQ + ').slice(11,19);el.innerHTML=' + DQ + '<span style="color:var(--dim);font-size:9px">' + DQ + '+ts+' + DQ + '</span> <span style="font-size:10px">' + DQ + '+(e.method||' + DQ + '?' + DQ + ')+' + DQ + ' <b>' + DQ + '+(e.verdict||' + DQ + '?' + DQ + ')+' + DQ + '</b> <span style="color:var(--dim)">' + DQ + '+(e.category||' + DQ + '' + DQ + ')+' + DQ + '</span>' + DQ + ';feed.appendChild(el)})}catch(e){}}'
    s = s.replace('<script>', '<script>' + NL + tl_js, 1)
    s = s.replace("function showView(name){", "function showView(name){if(name==='timeline')loadTimeline();")
    print('6f. UI: timeline feed rendering')

u.write_text(s)

if errs:
    print('ERRORS:', errs)
else:
    print('ALL PATCHES APPLIED')
