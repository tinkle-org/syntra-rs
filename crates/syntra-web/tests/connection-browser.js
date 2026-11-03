// Actual browser JS/WASM execution with a synthetic WebSocket and same-library
// Noise peer. NOT WSS/TLS, independent interop, or formal conformance evidence.
// Production artifacts must omit browser-test-fixture. Real WSS lane below is
// opt-in; missing fixtures are SKIP, never PASS. No credentials in URL parameters.
const params = new URL(location.href).searchParams;
const result = document.querySelector('#result');
const evidence = { scope: 'browser synthetic carrier, same-library crypto', passed: [], skipped: [], failed: [] };
globalThis.syntraEvidence = evidence;
const assert = (ok, why) => { if (!ok) throw new Error(why); };
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const bounded = (promise, ms = 17000) => Promise.race([promise, delay(ms).then(() => { throw new Error('harness deadline'); })]);
const rejects = async (promise, ms) => {
  try { await bounded(promise, ms); } catch (error) {
    if (String(error).includes('harness deadline')) throw error;
    return error;
  }
  throw new Error('expected rejection');
};
const originalWebSocket = globalThis.WebSocket;
let api, fixtureApi, peer, fault = '', sockets = [];
class SyntheticSocket {
  static OPEN = 1;
  constructor(url, protocol) {
    assert(url === 'wss://fixture.invalid/syntra/1.0/ws', 'endpoint');
    assert(protocol === 'syntra.1.0', 'exact protocol');
    this.readyState = 0;
    this.bufferedAmount = 0;
    this.extensions = fault === 'compression' ? 'permessage-deflate' : '';
    this.protocol = fault === 'subprotocol' ? 'wrong.protocol' : protocol;
    this.sent = [];
    this.timers = [];
    sockets.push(this);
    if (fault === 'constructor-stall') {
      const started = performance.now();
      while (performance.now() - started < 2100) { /* synchronous outer setup */ }
    }
    if (fault !== 'open-stall') queueMicrotask(() => {
      if (this.readyState !== 0) return;
      this.readyState = 1;
      this.onopen?.(new Event('open'));
    });
  }
  send(bytes) {
    const data = new Uint8Array(bytes).slice();
    this.sent.push(data);
    if (this.sent.length === 1) {
      assert(new TextDecoder().decode(data.slice(0, 10)) === 'syntra.1.0', 'canonical context');
      assert(data[10] === (returningMode ? 2 : 1), 'authentication mode');
      assert(data[11] === 3, 'WSS context carrier');
      assert(data.length >= 83 && data.length <= 337, 'candidate M1 extent');
      if (fault === 'm2-stall') return;
      if (fault === 'text') return this.deliver('not binary');
      if (fault === 'empty') return this.deliver(new ArrayBuffer(0));
      if (fault === 'oversize') return this.deliver(new ArrayBuffer(65536));
      if (fault === 'queue-count') {
        for (let i = 0; i < 33; i++) this.onmessage?.(new MessageEvent('message', { data: new ArrayBuffer(48) }));
        return;
      }
      let second;
      try { second = peer.handshake(data); } catch (_) { this.close(); return; }
      if (fault === 'm2-tag') second[0] ^= 1;
      if (['late-m2', 'late-m2-write-stall', 'late-m2-ready-stall', 'expired-m2'].includes(fault)) {
        const mode = fault;
        this.later(() => {
          if (mode === 'late-m2-write-stall') this.bufferedAmount = 131072;
          this.deliver(second.buffer);
        }, mode === 'expired-m2' ? 5100 : 4500);
      } else this.deliver(second.buffer);
    } else {
      if (fault === 'late-m2-ready-stall') return;
      if (fault === 'send-stall') this.bufferedAmount = 131072;
      if (fault === 'bad-tag') data[0] ^= 1;
      let replies;
      try { replies = peer.receive(data); } catch (_) { this.close(); return; }
      for (const [index, reply] of Array.from(replies).entries()) {
        if (fault === 'partial-trickle') {
          // Keep the frame incomplete; a later record must not refresh assembly.
          if (index === 0) this.deliver(reply.buffer);
          else if (index === 1) this.later(() => this.deliver(reply.buffer), 15000);
        } else this.deliver(reply.buffer);
      }
    }
  }
  deliver(data) { queueMicrotask(() => this.onmessage?.(new MessageEvent('message', { data }))); }
  later(callback, ms) { this.timers.push(setTimeout(callback, ms)); }
  close() {
    this.timers.forEach(clearTimeout);
    this.readyState = 3;
    queueMicrotask(() => this.onclose?.(new Event('close')));
  }
}

const endpoint = 'wss://fixture.invalid/syntra/1.0/ws';
let returningMode = false;
const options = returning => {
  returningMode = returning;
  let option = new api.ConnectionOptions(peer.public_key(), 0, 'browser-fixture');
  if (returning) option = option.returning(new Uint8Array(32).fill(9), new Uint8Array(8).fill(7), 1n);
  return option;
};
const cleanup = async () => {
  // Any live socket must have callbacks removed even after a failed attempt.
  await delay(30);
  for (const socket of sockets) {
    assert(socket.readyState === 3, 'socket closed');
    // web-sys passes undefined for Option::None; a native DOM setter coerces it
    // to null, whereas this synthetic object retains undefined. Neither may
    // retain a callable Rust closure.
    assert([socket.onmessage, socket.onopen, socket.onclose, socket.onerror].every(handler => handler == null), 'callbacks detached');
  }
  assert(api.client_count() === 0, 'registry empty');
  sockets = [];
  peer?.free(); peer = null;
};
async function test(name, run) {
  await run();
  await cleanup();
  evidence.passed.push(name);
}
try {
  api = await import(params.get('module') || '../pkg-fixture/syntra_web.js');
  await api.default();
  fixtureApi = params.has('fixtureModule') ? await import(params.get('fixtureModule')) : api;
  if (fixtureApi !== api) await fixtureApi.default();
  const supportedExports = [
    'ConnectionOptions', 'call', 'client_count', 'close', 'connect',
    'connection_support', 'default', 'initSync', 'poll_notify',
  ];
  // A combined test artifact may expose the peer; a production client may not.
  if (fixtureApi === api) supportedExports.push('ConnectionFixture');
  else assert(!Object.keys(api).some(name => /connectionfixture/i.test(name)), 'no production fixture exports');
  assert(JSON.stringify(Object.keys(api).sort()) === JSON.stringify(supportedExports.sort()), 'supported JS binding surface');
  assert(supportedExports.every(name => typeof api[name] === 'function'), 'callable JS bindings');
  assert(typeof api.ConnectionOptions.prototype.returning === 'function', 'returning options method');
  const option = new api.ConnectionOptions(new Uint8Array(32).fill(5), 0, 'browser-fixture');
  assert(option instanceof api.ConnectionOptions, 'supported options constructor');
  option.free();
  globalThis.WebSocket = SyntheticSocket;
  await test('trusted options required before any dial', async () => {
    await rejects(Promise.resolve().then(() => api.connect(endpoint, new Uint8Array())));
    for (const url of [
      'ws://fixture.invalid/syntra/1.0/ws',
      'wss://fixture.invalid/invalid/connection',
      'wss://fixture.invalid/invalid/nested/connection',
    ]) {
      for (const returning of [false, true]) {
        let option = new api.ConnectionOptions(new Uint8Array(32).fill(5), 0, 'browser-fixture');
        if (returning) option = option.returning(new Uint8Array(32).fill(9), new Uint8Array(8).fill(7), 1n);
        await rejects(api.connect(url, new Uint8Array(), option));
      }
    }
    await rejects(api.connect(endpoint, new Uint8Array(), new api.ConnectionOptions(new Uint8Array(32), 0, 'browser-fixture')));
    assert(sockets.length === 0, 'missing options, invalid endpoints and zero pin must not dial');
  });
  for (const returning of [false, true]) await test(returning ? 'NKpsk0 echo/segmentation/close' : 'NK echo/segmentation/close', async () => {
    fault = ''; peer = new fixtureApi.ConnectionFixture(returning);
    const id = await bounded(api.connect(endpoint, new Uint8Array([1, 2, 3]), options(returning)));
    const bytes = new Uint8Array(180000).map((_, i) => i % 251);
    const reply = await bounded(api.call(id, '/example.Echo/Echo', bytes, 2000));
    assert(reply.length === bytes.length && reply.every((b, i) => b === bytes[i]), 'large echo');
    const poll = rejects(api.poll_notify(id, 10000));
    assert(await api.close(id), 'owner completion');
    await poll;
    assert(!await api.close(id), 'id retired');
    await rejects(api.call(id, '/example.Echo/Echo', new Uint8Array(), 100));
  });
  await test('late valid M2 keeps the original hello deadline', async () => {
    fault = 'late-m2'; peer = new fixtureApi.ConnectionFixture(false);
    const started = performance.now();
    const id = await api.connect(endpoint, new Uint8Array(), options(false));
    assert(performance.now() - started >= 4400, 'M2 was delayed');
    const reply = await api.call(id, '/example.Echo/Echo', new Uint8Array([4]), 1000);
    assert(reply[0] === 4, 'valid M2 and hello complete before original deadline');
    await api.close(id);
  });
  for (const mode of ['late-m2-write-stall', 'late-m2-ready-stall', 'expired-m2']) await test(mode, async () => {
    fault = mode; peer = new fixtureApi.ConnectionFixture(false);
    const started = performance.now();
    await rejects(api.connect(endpoint, new Uint8Array([1]), options(false)), 6500);
    const elapsed = performance.now() - started;
    assert(elapsed >= 4900 && elapsed < 6200, 'M2 cannot renew the shared five-second budget');
    assert(sockets[0].sent.length === (mode === 'late-m2-ready-stall' ? 2 : 1), 'no late hello or retry');
  });
  await test('outer Upgrade stall uses the total fifteen-second budget', async () => {
    fault = 'open-stall'; peer = new fixtureApi.ConnectionFixture(false);
    const started = performance.now();
    await rejects(api.connect(endpoint, new Uint8Array(), options(false)), 17000);
    const elapsed = performance.now() - started;
    assert(elapsed >= 14900 && elapsed < 16500, 'total attempt ceiling');
    assert(sockets[0].sent.length === 0, 'no M1 before Upgrade');
  });
  await test('outer synchronous setup loses continuity before any M1', async () => {
    fault = 'constructor-stall'; peer = new fixtureApi.ConnectionFixture(false);
    await rejects(api.connect(endpoint, new Uint8Array(), options(false)));
    assert(sockets[0].sent.length === 0, 'origin and continuity precede WebSocket construction');
  });
  await test('next-record budget includes idle wait', async () => {
    fault = ''; peer = new fixtureApi.ConnectionFixture(false);
    const id = await api.connect(endpoint, new Uint8Array(), options(false));
    try {
      await delay(31000);
      await rejects(api.call(id, '/example.Echo/Echo', new Uint8Array([4]), 2000));
      assert(sockets[0].readyState === 3, 'idle next-record deadline retires the connection');
    } finally { await api.close(id); }
  });
  await test('partial frame trickle cannot extend assembly budget', async () => {
    fault = ''; peer = new fixtureApi.ConnectionFixture(false);
    const id = await api.connect(endpoint, new Uint8Array(), options(false));
    try {
      fault = 'partial-trickle';
      const started = performance.now();
      await rejects(api.call(id, '/example.Echo/Echo', new Uint8Array([4]), 60000), 35000);
      const elapsed = performance.now() - started;
      assert(elapsed >= 29000 && elapsed < 35000, 'original frame deadline, not trickle or RPC deadline');
      await rejects(api.call(id, '/example.Echo/Echo', new Uint8Array(), 100));
    } finally { await api.close(id); }
  });
  for (const mode of ['subprotocol', 'compression', 'text', 'empty', 'oversize', 'queue-count', 'm2-tag', 'bad-tag', 'm2-stall']) await test(mode, async () => {
    for (const returning of [false, true]) {
      fault = mode; peer = new fixtureApi.ConnectionFixture(returning);
      await rejects(api.connect(endpoint, new Uint8Array([1]), options(returning)));
      if (mode === 'subprotocol' || mode === 'compression') assert(sockets[0].sent.length === 0, 'no M1 before protocol validation');
      else if (mode !== 'bad-tag') assert(sockets[0].sent.length === 1, 'no credential before verified M2');
      await cleanup();
    }
  });
  await test('wrong Noise pin', async () => {
    fault = ''; peer = new fixtureApi.ConnectionFixture(false);
    returningMode = false;
    await rejects(api.connect(endpoint, new Uint8Array([1]), new api.ConnectionOptions(new Uint8Array(32).fill(5), 0, 'browser-fixture')));
    assert(sockets[0].sent.length === 1, 'no hello on wrong pin');
  });
  await test('wrong PSK does not bootstrap', async () => {
    fault = ''; peer = new fixtureApi.ConnectionFixture(true);
    returningMode = true;
    const option = new api.ConnectionOptions(peer.public_key(), 0, 'browser-fixture')
      .returning(new Uint8Array(32).fill(8), new Uint8Array(8).fill(7), 1n);
    await rejects(api.connect(endpoint, new Uint8Array([1]), option));
    assert(sockets.length === 1 && sockets[0].sent.length === 1, 'no downgrade/retry');
  });
  await test('pagehide retires generation and callbacks', async () => {
    fault = ''; peer = new fixtureApi.ConnectionFixture(false);
    const id = await api.connect(endpoint, new Uint8Array(), options(false));
    dispatchEvent(new Event('pagehide'));
    await rejects(api.call(id, '/example.Echo/Echo', new Uint8Array(), 100));
    await api.close(id);
  });
  await test('receive byte bound discards queued records', async () => {
    fault = ''; peer = new fixtureApi.ConnectionFixture(false);
    const id = await api.connect(endpoint, new Uint8Array(), options(false));
    for (let i = 0; i < 5; i++) sockets[0].onmessage?.(new MessageEvent('message', { data: new ArrayBuffer(65535) }));
    await rejects(api.call(id, '/example.Echo/Echo', new Uint8Array(), 100));
    await api.close(id);
  });
  await test('notification waiter admission is bounded', async () => {
    fault = ''; peer = new fixtureApi.ConnectionFixture(false);
    const id = await api.connect(endpoint, new Uint8Array(), options(false));
    const polls = Array.from({ length: 32 }, () => rejects(api.poll_notify(id, 10000)));
    await rejects(api.poll_notify(id, 10000));
    await api.close(id);
    await Promise.all(polls);
  });
  await test('wake discontinuity rejects buffered work', async () => {
    fault = ''; peer = new fixtureApi.ConnectionFixture(false);
    const id = await api.connect(endpoint, new Uint8Array(), options(false));
    const started = performance.now();
    while (performance.now() - started < 2100) { /* controlled main-thread freeze */ }
    await rejects(api.call(id, '/example.Echo/Echo', new Uint8Array(), 100));
    await api.close(id);
  });
  for (const skew of ['regression', 'forward jump', 'unavailable']) await test(`wall clock ${skew} retires connection`, async () => {
    fault = ''; peer = new fixtureApi.ConnectionFixture(false);
    const id = await api.connect(endpoint, new Uint8Array(), options(false));
    const original = Date.now, sampled = original();
    try {
      Date.now = () => skew === 'unavailable' ? NaN : sampled + (skew === 'regression' ? -3000 : 3000);
      await rejects(api.call(id, '/example.Echo/Echo', new Uint8Array(), 100));
    } finally { Date.now = original; await api.close(id); }
  });
  await test('send stall terminates owner', async () => {
    fault = ''; peer = new fixtureApi.ConnectionFixture(false);
    const id = await api.connect(endpoint, new Uint8Array(), options(false));
    fault = 'send-stall';
    // Hold browser output full before runtime emission; no new nonce is consumed.
    sockets[0].bufferedAmount = 131072;
    await rejects(api.call(id, '/example.Echo/Echo', new Uint8Array(), 100));
    await delay(10200);
    await rejects(api.call(id, '/example.Echo/Echo', new Uint8Array(), 100));
    await api.close(id);
  });
  evidence.skipped.push('browser durable persistence and recovery generation integration: no durable store fixture');
  evidence.skipped.push('OS freeze/suspend, memory/energy/soak budgets: synthetic freeze is not device evidence');
  globalThis.WebSocket = originalWebSocket;
  const realEndpoint = params.get('wss');
  if (!realEndpoint) evidence.skipped.push('real verified TLS WSS NK/NKpsk0: no independently provisioned fixture');
  else {
    // Public pin only. Never put an AK/application credential in a query string.
    const pin = Uint8Array.from((params.get('pin') || '').match(/../g) || [], b => parseInt(b, 16));
    assert(pin.length === 32, 'real WSS requires provisioned pin');
    const id = await api.connect(realEndpoint, new Uint8Array(), new api.ConnectionOptions(pin, Number(params.get('keyId') || 0), params.get('scope') || 'browser-fixture'));
    const reply = await api.call(id, '/example.Echo/Echo', new Uint8Array([4]), 1000);
    assert(reply[0] === 4, 'real WSS echo');
    assert(await api.close(id), 'real WSS owner completion');
    evidence.passed.push('real WSS NK (browser TLS policy only)');
    evidence.skipped.push('real WSS NKpsk0: provide credentials through a separate trusted harness, never query parameters');
  }
} catch (error) {
  evidence.failed.push(String(error.stack || error));
} finally {
  globalThis.WebSocket = originalWebSocket;
  result.textContent = JSON.stringify(evidence, null, 2);
  document.documentElement.dataset.result = evidence.failed.length ? 'fail' : 'pass';
}
