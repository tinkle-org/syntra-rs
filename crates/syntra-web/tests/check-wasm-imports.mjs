// A successful cargo build is not a loadable browser module. In particular,
// unresolved C/provider imports must not be papered over with dummy functions.
import { readFileSync } from 'node:fs';
const module = await WebAssembly.compile(readFileSync(process.argv[2]));
const unsupported = WebAssembly.Module.imports(module).filter(item => item.module === 'env');
if (unsupported.length) {
  console.error(JSON.stringify({ status: 'BLOCKED', reason: 'unresolved provider imports; shared channel owner must fix WASM linkage', imports: unsupported }, null, 2));
  process.exitCode = 1;
}
const exports = WebAssembly.Module.exports(module).map(item => item.name);
const production = process.argv.includes('--production');
const fixture = process.argv.includes('--fixture');
if (production || fixture) {
  if (production && exports.some(name => /connectionfixture/i.test(name))) {
    console.error('BLOCKED: production browser artifact contains test-peer exports');
    process.exitCode = 1;
  }
  // Raw WASM method names differ from the high-level JS constructor/API names.
  const supported = new Set([
    'call', 'client_count', 'close', 'connect', 'connection_support',
    'connectionoptions_bootstrap', 'connectionoptions_returning', 'poll_notify',
  ]);
  if (fixture && !production) {
    for (const name of ['connectionfixture_new', 'connectionfixture_public_key', 'connectionfixture_handshake', 'connectionfixture_receive']) supported.add(name);
  }
  for (const name of supported) {
    if (!exports.includes(name)) {
      console.error(`BLOCKED: supported Syntra API export missing: ${name}`);
      process.exitCode = 1;
    }
  }
  // Keep code-generated helpers and runtime memory/globals out of the API list.
  const runtime = new Set(['memory', '__abort_handler', '__instance_terminated']);
  const internal = name => runtime.has(name) || /^(?:__wbg_|__wbindgen_|__externref_|wasm_bindgen__)/.test(name);
  const unexpected = exports.filter(name => !supported.has(name) && !internal(name));
  if (unexpected.length) {
    console.error(`BLOCKED: unexpected public WASM exports: ${unexpected.join(', ')}`);
    process.exitCode = 1;
  }
}
