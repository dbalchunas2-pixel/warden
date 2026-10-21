/**
 * Mock MCP upstream for Warden demos and adversarial evaluation.
 * Echoes every tools/call back as a successful result; never executes anything.
 */
'use strict';
let buf = '';
process.stdin.on('data', (d) => {
  buf += d.toString();
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    let msg; try { msg = JSON.parse(line); } catch (e) { continue; }
    if (msg.id === undefined) continue;
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0', id: msg.id,
      result: { content: [{ type: 'text', text: 'mock ok: ' + (msg.method || '') }] }
    }) + '\n');
  }
});
