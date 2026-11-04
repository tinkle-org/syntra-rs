"""Compile actual Rust constant/context bodies; not a Noise or carrier executor."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from sdd_inputs import regular_file

KERNEL = "crates/syntra-core/src/secure_channel/mod.rs"
NATIVE_FIXTURES = "crates/syntra-core/tests/fixtures/syntra_1_0_context.rs"
RECORD_FIXTURES = "crates/syntra-core/tests/connection_records.rs"
NATIVE_WS = "crates/syntra-net/src/websocket.rs"
NATIVE_TLS = "crates/syntra-net/src/tls.rs"
CONSTANTS = (
    "PROTOCOL", "DOMAIN", "AEAD_TAG_BYTES", "NOISE_MESSAGE_BYTES", "MIN_SCOPE_BYTES",
    "MAX_SCOPE_BYTES", "MODE_OFFSET", "CARRIER_OFFSET", "SERVER_KEY_ID_OFFSET",
    "EPOCH_OFFSET", "HANDLE_OFFSET", "SCOPE_LEN_OFFSET", "SCOPE_OFFSET", "MIN_WRAPPER",
    "MAX_CIPHERTEXT", "MAX_PLAINTEXT", "MAX_FRAME", "MAX_WRAPPER", "MAX_RECORDS", "MAX_AGE",
)


def one(pattern, text, label, flags=0):
    matches = list(re.finditer(pattern, text, flags))
    if len(matches) != 1:
        raise ValueError(f"expected one reviewed Rust boundary: {label}; found {len(matches)}")
    return matches[0]


def block(text, marker):
    """Extract a known Rust block, ignoring braces in comments/quoted strings."""
    match = one(r"(?m)^" + re.escape(marker) + r"\s*\{", text, marker)
    start, depth, index = match.start(), 1, match.end()
    token = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|[{}]', re.S)
    for part in token.finditer(text, index):
        if part[0] == "{":
            depth += 1
        elif part[0] == "}":
            depth -= 1
            if not depth:
                return text[start:part.end()]
    raise ValueError(f"unterminated Rust boundary: {marker}")


def const(text, name):
    return one(r"(?m)^(?:pub )?const " + re.escape(name) + r"\s*:[^=]+=[\s\S]*?;(?=[ \t]*(?:\n|$))", text, name)[0]


def negative_bytes(row, base, layout):
    value = bytearray.fromhex(base["context_hex"])
    mode, carrier = layout["mode"][0], layout["carrier"][0]
    epoch, handle = layout["epoch"], layout["handle"]
    scope_len, scope = layout["scope_length_u16be"], layout["scope"][0]
    mutation = row["mutation"]
    if mutation == "unsupported-domain":
        domain = b"invalid.00"
        if layout["domain"] != [0, len(domain)] or mode != len(domain):
            raise ValueError("unsupported-domain recipe requires the reviewed ten-byte domain layout")
        value[:mode] = domain
    elif mutation == "unsupported-format": value = bytearray(8)
    elif mutation == "zero-mode": value[mode] = 0
    elif mutation == "unknown-carrier": value[carrier] = 4
    elif mutation == "bootstrap-epoch": value[epoch[0]:epoch[1]] = (1).to_bytes(8, "big")
    elif mutation == "returning-handle": value[handle[0]:handle[1]] = bytes(8)
    elif mutation in ("empty-scope", "oversize-scope"):
        count = 0 if mutation == "empty-scope" else 256
        value[scope_len[0]:scope_len[1]] = count.to_bytes(2, "big")
        value[scope:] = b"a" * count
    elif mutation == "truncated": value.pop()
    elif mutation == "trailing": value.append(0)
    elif mutation == "invalid-utf8": value[scope:] = b"\xff"
    elif mutation == "scope-byte-length": value[scope_len[0]:scope_len[1]] = (1).to_bytes(2, "big")
    else: raise ValueError(f"unreviewed negative recipe: {mutation}")
    return value


def probe(root, contexts, negatives, layout):
    """No crate-source edits or exports. Compile copied bodies with rustc 1.88.0.

    The probe has only a local Error::Invalid stub, no Noise/socket implementation.
    Compilation of the complete crates and real-carrier tests are separate gates.
    """
    text = regular_file(root, KERNEL).decode()
    native = regular_file(root, NATIVE_FIXTURES).decode()
    records = regular_file(root, RECORD_FIXTURES).decode()
    code = ["#![allow(dead_code)]", "use std::mem::size_of;", "#[derive(Debug)] enum Error { Invalid }"]
    code += [const(text, name) for name in CONSTANTS]
    for name in ("Mode", "Carrier", "Context"):
        code += ["#[derive(Debug, Clone, Copy, PartialEq, Eq)]" if name != "Context"
                 else "#[derive(Debug, Clone, PartialEq, Eq)]",
                 block(text, "pub enum " + name if name != "Context" else "pub struct Context"),
                 block(text, "impl " + name)]
    code += ["mod independent {", native, "}",
             'fn hex(v: &[u8]) -> String { v.iter().map(|b| format!("{b:02x}")).collect() }',
             "fn main() {"]
    metrics = {"tag": "AEAD_TAG_BYTES", "noise": "NOISE_MESSAGE_BYTES", "min_scope": "MIN_SCOPE_BYTES",
               "max_scope": "MAX_SCOPE_BYTES", "mode": "MODE_OFFSET", "carrier": "CARRIER_OFFSET",
               "key_id": "SERVER_KEY_ID_OFFSET", "epoch": "EPOCH_OFFSET", "handle": "HANDLE_OFFSET",
               "scope_len": "SCOPE_LEN_OFFSET", "scope": "SCOPE_OFFSET", "min_m1": "MIN_WRAPPER",
               "max_m1": "MAX_WRAPPER", "ciphertext": "MAX_CIPHERTEXT", "plaintext": "MAX_PLAINTEXT",
               "frame": "MAX_FRAME", "records": "MAX_RECORDS", "age": "MAX_AGE.as_secs()"}
    key_array = one(r"pub struct Secret32\(Zeroizing<(\[u8;\s*\d+\])>\);", text, "Secret32 array size")[1]
    metrics["auth_key"] = "size_of::<" + key_array + ">()"
    handshake = regular_file(root, "crates/syntra-core/src/handshake.rs").decode()
    code += [const(handshake, name) for name in ("MIN_VERSION", "MAX_VERSION")]
    metrics.update(min_version="MIN_VERSION", max_version="MAX_VERSION")
    code.append(const(regular_file(root, "crates/syntra-core/src/frame.rs").decode(), "MAX_FRAME_BYTES"))
    metrics["core_frame"] = "MAX_FRAME_BYTES"
    fields = ','.join('"' + key + '":{}' for key in metrics)
    fmt = '{{"kind":"constants","protocol":{:?},"domain":{:?},' + fields + '}}'
    code.append('println!(' + json.dumps(fmt) + ', PROTOCOL, std::str::from_utf8(DOMAIN).unwrap(), '
                + ', '.join(metrics.values()) + ');')
    modes = {1: "Bootstrap", 2: "Returning"}
    carriers = {1: "Tcp", 2: "WebSocket", 3: "SecureWebSocket"}
    for row in contexts:
        values = ','.join(str(byte) for byte in bytes.fromhex(row["handle_hex"]))
        scope = ','.join(str(byte) for byte in row["scope"].encode())
        code.append(f'let c = Context {{ mode: Mode::{modes[row["mode"]]}, carrier: Carrier::{carriers[row["carrier"]]}, '
                    f'server_key_id: {row["server_key_id"]}, epoch: {row["epoch"]}, handle: [{values}], scope: vec![{scope}] }};')
        code.append('let encoded = c.encode().unwrap(); let mut first = encoded.clone(); '
                    'first.extend_from_slice(&[0; NOISE_MESSAGE_BYTES]); '
                    'assert_eq!(Context::parse_first(&first).unwrap().0, c); '
                    'assert_eq!(c.prologue().unwrap(), encoded);')
        code.append('println!("{{\\\"kind\\\":\\\"context\\\",\\\"id\\\":{:?},\\\"hex\\\":{:?}}}", '
                    + json.dumps(row["id"]) + ', hex(&encoded));')
    indexed = {row["id"]: row for row in contexts}
    for row in negatives:
        invalid = negative_bytes(row, indexed[row["base"]], layout)
        values = ','.join(str(byte) for byte in invalid)
        code.append(f'let mut bad = vec![{values}]; bad.extend_from_slice(&[0; NOISE_MESSAGE_BYTES]);')
        code.append('println!("{{\\\"kind\\\":\\\"negative\\\",\\\"id\\\":{:?},\\\"rejected\\\":{}}}", '
                    + json.dumps(row["id"]) + ', Context::parse_first(&bad).is_err());')
    # This probe deliberately compiles without http-candidate. Candidate codes
    # must not enter the active three-carrier parser through copied source.
    base = next(row for row in contexts if row["mode"] == 1 and row["carrier"] == 1)
    for carrier in (4, 5):
        invalid = bytearray.fromhex(base["context_hex"])
        invalid[layout["carrier"][0]] = carrier
        values = ','.join(str(byte) for byte in invalid)
        code.append(f'let mut bad = vec![{values}]; bad.extend_from_slice(&[0; NOISE_MESSAGE_BYTES]);')
        code.append('println!("{{\\\"kind\\\":\\\"default_candidate_rejection\\\",\\\"carrier\\\":{},\\\"rejected\\\":{}}}", '
                    + str(carrier) + ', Context::parse_first(&bad).is_err());')
    code.append('for f in independent::CONTEXTS { println!("{{\\\"kind\\\":\\\"independent\\\",\\\"id\\\":{:?},'
                '\\\"mode\\\":{},\\\"carrier\\\":{},\\\"server_key_id\\\":{},\\\"epoch\\\":{},'
                '\\\"handle_hex\\\":{:?},\\\"scope\\\":{:?},\\\"context_hex\\\":{:?},'
                '\\\"prologue_hex\\\":{:?},\\\"context_bytes\\\":{},\\\"m1_bytes\\\":{}}}", '
                'f.id, f.mode, f.carrier, f.server_key_id, f.epoch, f.handle_hex, f.scope, '
                'f.context_hex, f.prologue_hex, f.context_bytes, f.m1_bytes); }')
    expected = one(r'let expected\s*=\s*(b"(?:\\.|[^"\\])*")\s*;', records, RECORD_FIXTURES)[1]
    code.append('println!("{{\\\"kind\\\":\\\"record_fixture\\\",\\\"hex\\\":{:?}}}", hex(' + expected + '));')
    code.append("}")
    with tempfile.TemporaryDirectory(prefix="syntra-candidate-probe-") as directory:
        source, binary = Path(directory) / "probe.rs", Path(directory) / "probe"
        source.write_text('\n'.join(code), encoding="utf-8")
        env = {**os.environ, "RUSTUP_TOOLCHAIN": "1.88.0"}
        subprocess.run(["rustc", "--edition=2021", str(source), "-o", str(binary)],
                       check=True, capture_output=True, text=True, env=env, timeout=60)
        output = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=30).stdout
    return [json.loads(line) for line in output.splitlines()]


def binding_sources(root, contract):
    """Fail-closed source guards, not a claim that TLS scenarios ran."""
    native = regular_file(root, NATIVE_WS).decode()
    provider = regular_file(root, NATIVE_TLS).decode()
    for text, endpoint in ((native, "ENDPOINT_PATH"),):
        for name, value in ((endpoint, contract["websocket_endpoint"]), ("SUBPROTOCOL", contract["websocket_subprotocol"])):
            literal = one(r'(?m)^pub const ' + name + r': &str = ("[^"\n]+");', text, name)[1]
            if json.loads(literal) != value:
                raise ValueError(f"Rust {name} disagrees with candidate contract")
    compact = lambda text: re.sub(r"\s+", "", re.sub(r"//[^\n]*", "", text))
    guards = {
        "native WSS carrier": '"wss"ifcarrier==Carrier::SecureWebSocket=>{}',
        "native WS carrier": '"ws"ifcarrier==Carrier::WebSocket=>{',
        "WS loopback dial": 'if!loopback{returnErr(Error::Configuration);}',
        "WS accepted peer": 'if!peer.ip().is_loopback(){returnErr(Error::Configuration);}',
        "WS stream cannot assert WSS": 'ifsecurity.carrier!=Carrier::WebSocket{returnErr(Error::Configuration);}',
        "owned TLS binding": 'ifsecurity.carrier!=Carrier::SecureWebSocket{returnErr(Error::Configuration);}',
        "TLS 1.3 only": '.with_protocol_versions(&[&rustls::version::TLS13])',
        "negotiated TLS 1.3": 'protocol_version()!=Some(rustls::ProtocolVersion::TLSv1_3)',
        "exact native endpoint": 'parsed.path()!=ENDPOINT_PATH',
        "provider client role and authority": 'tls::validate(&metadata,&authority,TlsRole::Client)?;',
        "provider server role and authority": 'tls::validate(&metadata,authority,TlsRole::Server)?;',
        "provider retains original budget": 'let(stream,metadata,budget)=stream.into_parts();',
    }
    normalized = compact(native)
    for label, guard in guards.items():
        if guard not in normalized:
            raise ValueError(f"reviewed transport binding guard changed/missing: {label}")
    if normalized.count(guards["TLS 1.3 only"]) != 2:
        raise ValueError("both client and server must retain reviewed TLS 1.3-only builders")
    provider_guards = {
        "provider authority": 'metadata.authority!=*authority',
        "provider role": 'metadata.role!=role',
        "provider TLS 1.3": 'metadata.protocol_version!=0x0304',
        "provider HTTP/1.1 ALPN": 'metadata.alpn.as_deref()!=Some(b"http/1.1".as_slice())',
        "provider disables early data": 'metadata.early_data!=EarlyData::Disabled',
        "provider result checked": 'validate(&result.metadata,&authority,role)?;',
        "provider I/O deadline gate": 'inner:result.stream,budget:budget.io.clone(),',
    }
    normalized_provider = compact(provider)
    for label, guard in provider_guards.items():
        if guard not in normalized_provider:
            raise ValueError(f"reviewed TLS provider binding guard changed/missing: {label}")
    return {"kind": "source_guard_agreement_not_carrier_execution", "native_guards": sorted(guards),
            "provider_guards": sorted(provider_guards),
            "provider_trust": "trusted application implementation; metadata is not proof of certificate validation"}


def record_fixture_bounds(root, contract):
    """Check handwritten kernel record expectations, without executing a carrier."""
    rust = regular_file(root, RECORD_FIXTURES).decode()
    layout = contract["context_layout"]
    def numbers(pattern, text, label):
        return tuple(int(value) for value in one(pattern, text, label).groups())
    if numbers(r"\((\d+)\.\.=(\d+)\)\.contains\(&first.len\(\)\)", rust, "Rust record M1 extent") != tuple(layout["m1_bytes"]):
        raise ValueError("independent record Rust M1 bounds disagree")
    if int(one(r'assert_eq!\(encoded.len\(\), (\d+) \+ b"example.service".len\(\)\);', rust, "record context prefix")[1]) != layout["scope"][0]:
        raise ValueError("independent record Rust context-prefix length disagrees")
    offsets = numbers(r"returning\[(\d+)\] = 2;\s*returning\[(\d+)\] = 1;\s*returning\[(\d+)\.\.(\d+)\].fill\(7\);", rust, "record returning context")
    if offsets != (layout["mode"][0], layout["epoch"][1] - 1, *layout["handle"]):
        raise ValueError("independent record Rust returning offsets disagree")
    return {"kind": "handwritten_expectation_agreement_not_carrier_execution", "sources": [RECORD_FIXTURES]}
