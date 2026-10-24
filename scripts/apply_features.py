import pathlib, re
NL = chr(10)
DQ = chr(34)
u = pathlib.Path('ui/index.html')
s = u.read_text()
errs = []
def sw(a, b, tag):
    global s
    if b in s: return
    if a not in s: errs.append(tag); return
    s = s.replace(a, b, 1)

css = NL.join([
'.toast-wrap{position:fixed;bottom:20px;right:20px;z-index:99999;display:flex;flex-direction:column;gap:6px}',
'.toast{padding:10px 16px;border-radius:6px;font-size:11px;max-width:340px;animation:slideIn 0.3s;box-shadow:0 4px 12px rgba(0,0,0,0.4)}',
'.toast.err{background:var(--danger);color:#fff}',
'.toast.ok{background:var(--accent);color:var(--bg)}',
'.toast.warn{background:var(--warn);color:var(--bg)}',
'.toast.fade{opacity:0;transition:opacity 0.4s}',
'.pin-btn{background:none;border:1px solid var(--border-hi);color:var(--warn);font-size:8px;padding:2px 6px;border-radius:3px;cursor:pointer;font-family:var(--mono);margin-left:4px}',
'.pin-btn:hover{background:var(--warn-d);border-color:var(--warn)}',
'.outbreak-badge{font-size:8px;padding:1px 5px;border-radius:2px;background:var(--danger);color:#fff;font-weight:700;animation:pulse 1s infinite}',
'.scrubber-bar{display:flex;align-items:center;gap:10px;padding:8px 0;margin-bottom:8px}',
'.scrubber-bar input[type=range]{flex:1;height:4px}',
'.scrubber-btn{background:var(--panel);border:1px solid var(--border);color:var(--text);padding:4px 12px;border-radius:4px;cursor:pointer;font-family:var(--mono);font-size:10px}',
'.scrubber-btn:hover{border-color:var(--accent);color:var(--accent)}',
'.scrubber-time{font-size:10px;color:var(--dim);min-width:120px}',
''])
sw('</style>', css + '</style>', 'css')
sw('<body>', '<body><div class="toast-wrap" id="toast-wrap"></div>', 'container')

fns = []
fns.append('function toast(msg,kind){kind=kind||"warn";var w=document.getElementById("toast-wrap");if(!w)return;var t=document.createElement("div");t.className="toast "+kind;t.textContent=msg;w.appendChild(t);setTimeout(function(){t.classList.add("fade");setTimeout(function(){t.remove()},400)},3500)}')
fns.append('async function pinEntry(btn,e){btn.disabled=true;btn.textContent="Pinning...";try{var r=await invoke("pin_rule",{method:e.method||"",paramsJson:JSON.stringify(e.params||{})});toast("Rule pinned: "+r.type+" = "+r.pattern,"ok");btn.textContent="Pinned!"}catch(ex){toast(String(ex),"err");btn.disabled=false;btn.textContent="Pin Rule"}}')
fns.append('function addPinBtn(entry,el){if(!entry||dvClass(entry)!=="blocked")return;var btn=document.createElement("button");btn.className="pin-btn";btn.textContent="Pin Rule";btn.onclick=function(){pinEntry(btn,entry)};el.appendChild(btn)}')
fns.append('var scrubTimer=null,scrubIdx=0,scrubEntries=[]')
fns.append('function toggleScrub(){if(scrubTimer){clearInterval(scrubTimer);scrubTimer=null;document.getElementById("scrub-play").textContent="Play";return}scrubEntries=(window._auditEntries||[]).slice().reverse();if(!scrubEntries.length){toast("No entries to replay","warn");return}var sl=document.getElementById("scrub-slider");sl.max=scrubEntries.length-1;document.getElementById("scrub-play").textContent="Pause";scrubTimer=setInterval(function(){if(scrubIdx>=scrubEntries.length){clearInterval(scrubTimer);scrubTimer=null;document.getElementById("scrub-play").textContent="Play";return}sl.value=scrubIdx;seekScrub(scrubIdx);scrubIdx++},800)}')
fns.append('function seekScrub(v){if(!scrubEntries.length)return;var e=scrubEntries[v];if(!e)return;var ts=(e.timestamp||"").slice(11,19);document.getElementById("scrub-time").textContent=ts+" | "+(e.method||"?")+" => "+(e.verdict||"?")}')
fns.append('async function exportDigest(){try{var r=await invoke("export_digest",{days:7});toast("Digest: "+r.total+" calls, "+r.blocked+" blocked - "+r.path,"ok")}catch(e){toast(String(e),"err")}}')
js = NL.join(fns)
sw('<script>', '<script>' + NL + js, 'js')

sw('feed.insertBefore(el,feed.firstChild);', 'feed.insertBefore(el,feed.firstChild);addPinBtn(entry,el);if(entry._outbreak){var ob=document.createElement("span");ob.className="outbreak-badge";ob.textContent="OUTBREAK";el.appendChild(ob)}', 'pin-ob')
sw('>CSV</button>', '>CSV</button>' + NL + '    <button class="export-btn" onclick="exportDigest()">Weekly Digest</button>', 'digest')
sw('Audit Timeline</div><div class="filter-bar">', 'Audit Timeline</div><div class="scrubber-bar"><button class="scrubber-btn" id="scrub-play" onclick="toggleScrub()">Play</button><input type="range" id="scrub-slider" min="0" max="0" value="0" oninput="seekScrub(this.value)"><span class="scrubber-time" id="scrub-time">-</span></div><div class="filter-bar">', 'scrubber')

if 'window._auditEntries' not in s:
    m = re.search(r'function renderAudit\(', s)
    if m:
        s = s[:m.start()] + 'window._auditEntries=entries;' + s[m.start():]
    else:
        errs.append('audit-store')

s = s.replace('console.error(String(e))', 'toast(String(e),"err")')

if 'e.category||' not in s:
    old_cat = "const c=m?m[1]:(e.verdict==='allowed'?'safe':'other');"
    if old_cat in s:
        new_cat = "const c=e.category||((e.reason||'').split('cat:')[1]||'').trim().split(/[ ,.]/)[0]||(e.verdict==='allowed'?'safe':'other');"
        s = s.replace(old_cat, new_cat, 1)
    else:
        errs.append('category')

u.write_text(s)
if errs:
    print('ERRORS:', errs)
else:
    print('ALL PATCHES OK')
