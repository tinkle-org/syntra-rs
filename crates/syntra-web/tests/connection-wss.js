// Real browser WebSocket + native direct TLS1.3 host, NOT a synthetic carrier.
// Supply externally trusted certificate/key to browser_wss_fixture for positive
// runs. Never install roots or disable TLS verification here. Query pins are
// public test pins, not authority learned from a connecting peer. Test AK below
// is intentionally public and authorizes only fixture echo data.
const params = new URL(location.href).searchParams;
const evidence = { scope: 'real browser WebSocket, native direct TLS1.3 Syntra 1.0 fixture', passed: [], skipped: [], failed: [] };
globalThis.syntraWssEvidence = evidence;
const assert = (ok, reason) => { if (!ok) throw new Error(reason); };
let api;
const RealSocket = WebSocket;
let sends = 0, dials = 0;
class ObservedSocket extends RealSocket {
  constructor(...args) { super(...args); dials++; }
  send(data) { sends++; super.send(data); }
}
const ids = [];
try {
  api = await import(params.get('module') || '/target/syntra-browser-production/syntra_web.js');
  await api.default();
  globalThis.WebSocket = ObservedSocket;
  const expected = params.get('expect');
  assert(expected === 'verified' || expected === 'untrusted', 'expect=verified|untrusted must be explicit');
  if (expected === 'untrusted') evidence.scope = 'real browser WSS URL, TLS certificate rejection before Upgrade/Syntra; not a successful WSS/Syntra exchange';
  for (const returning of [false, true]) {
    const name = returning ? 'returning' : 'bootstrap';
    const endpoint = params.get(`${name}Url`);
    const hex = params.get(`${name}Pin`);
    if (!endpoint || !hex) { evidence.skipped.push(`${name}: no provisioned endpoint/pin`); continue; }
    assert(/^[0-9a-fA-F]{64}$/.test(hex), 'exact 32-byte public Noise pin required');
    const pin = Uint8Array.from(hex.match(/../g), byte => parseInt(byte, 16));
    let options = new api.ConnectionOptions(pin, 0, 'browser-fixture');
    if (returning) options = options.returning(new Uint8Array(32).fill(9), new Uint8Array(8).fill(7), 1n);
    const before = sends, attempts = dials;
    if (expected === 'untrusted') {
      let rejected = false;
      try { const id = await api.connect(endpoint, new Uint8Array([1, 2, 3]), options); ids.push(id); }
      catch (_) { rejected = true; }
      assert(rejected, 'untrusted certificate must reject');
      assert(dials === attempts + 1 && sends === before, 'TLS rejection must send no M1/hello and never fall back');
      evidence.passed.push(`${name}: untrusted TLS rejected before any Syntra send; no retry`);
    } else {
      const id = await api.connect(endpoint, new Uint8Array([1, 2, 3]), options);
      ids.push(id);
      const input = new Uint8Array(180000).map((_, i) => i % 251);
      const output = await api.call(id, '/example.Echo/Echo', input, 2000);
      assert(output.length === input.length && output.every((v, i) => v === input[i]), 'WSS segmented echo');
      assert(await api.close(id), 'WSS owner stopped'); ids.pop();
      evidence.passed.push(`${name}: browser-verified WSS encrypted hello, segmented echo, bounded close`);
    }
  }
  assert(api.client_count() === 0, 'no registered client retained');
} catch (error) { evidence.failed.push(String(error.stack || error)); }
finally {
  if (api) for (const id of ids) await api.close(id);
  globalThis.WebSocket = RealSocket;
  document.querySelector('#result').textContent = JSON.stringify(evidence, null, 2);
  document.documentElement.dataset.result = evidence.failed.length ? 'fail' : evidence.passed.length ? 'pass' : 'skip';
}
