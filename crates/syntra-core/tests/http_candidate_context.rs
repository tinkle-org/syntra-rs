//! Draft RFC0013 candidate evidence only, not public registration, independent
//! cryptographic vectors, formal conformance or independent interoperability.
//! The raw source snapshot below is self-contained: an upstream checkout is not
//! required, and merely having that checkout cannot enable candidate parsing.

use snow::{
    params::HashChoice,
    resolvers::{CryptoResolver, DefaultResolver},
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use syntra_core::secure_channel::*;

// Exact raw bytes observed at ../syntra/rfcs/0013-http-tls/context-vectors.json,
// including its final LF. Worktree observation, NOT a committed/release pin.
// No upstream lock, public registry or protocol-contract record is changed.
const SOURCE_SHA256: &str = "cba7e8404afae8f3dc95bd85af7fc504bf2f69e9692cd535d66a344767a8381c";
const SOURCE: &str = r#"{
  "status": "pending-adoption",
  "source": "conformance/test-vectors/connection/context-vectors.json",
  "transformation": "base-context-with-proposed-carrier-only",
  "scope": "public-context-encoding-only-not-Noise-ciphertext",
  "prologue_equals_context": true,
  "contexts": [
    {"id": "R13-CONTEXT-01", "base": "SYNTRA-CONTEXT-01", "carrier": 4, "context_hex": "73796e7472612e312e3001040000000000000000000000000000000000000000000161"},
    {"id": "R13-CONTEXT-02", "base": "SYNTRA-CONTEXT-05", "carrier": 4, "context_hex": "73796e7472612e312e3002040102030400000000000000010102030405060708000f6578616d706c652e73657276696365"},
    {"id": "R13-CONTEXT-03", "base": "SYNTRA-CONTEXT-01", "carrier": 5, "context_hex": "73796e7472612e312e3001050000000000000000000000000000000000000000000161"},
    {"id": "R13-CONTEXT-04", "base": "SYNTRA-CONTEXT-05", "carrier": 5, "context_hex": "73796e7472612e312e3002050102030400000000000000010102030405060708000f6578616d706c652e73657276696365"}
  ],
  "negative_recipes": [
    {"id": "R13-N01", "base": "R13-CONTEXT-01", "changes": {"carrier": 6}, "expected": "reject-before-noise"},
    {"id": "R13-N02", "base": "R13-CONTEXT-03", "changes": {"carrier": 3}, "expected": "reject-before-noise"},
    {"id": "R13-N03", "base": "R13-CONTEXT-01", "changes": {"epoch": 1}, "expected": "reject-before-noise"},
    {"id": "R13-N04", "base": "R13-CONTEXT-02", "changes": {"handle_hex": "0000000000000000"}, "expected": "reject-before-noise"},
    {"id": "R13-N05", "base": "R13-CONTEXT-03", "changes": {"scope": ""}, "expected": "reject-before-noise"},
    {"id": "R13-N06", "base": "R13-CONTEXT-04", "changes": {"mode": 0}, "expected": "reject-before-noise"},
    {"id": "R13-N07", "base": "R13-CONTEXT-02", "changes": {"carrier": 5}, "expected_carrier": 4, "expected": "reject-before-lookup"},
    {"id": "R13-N08", "base": "R13-CONTEXT-04", "changes": {"carrier": 4}, "expected_carrier": 5, "expected": "reject-before-lookup"}
  ]
}
"#;

const NOISE_BYTES: usize = 48;

fn hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |byte| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("invalid fixture hex"),
            };
            nibble(pair[0]) << 4 | nibble(pair[1])
        })
        .collect()
}

// Deliberately limited to the exact, hash-checked, one-line fixture rows above;
// this is not a JSON parser or any production input path. Read the source rows
// directly so the exercised golden bytes and mutation recipes cannot drift into
// a separate, unverified transcription. No new dependency is needed.
fn field<'a>(row: &'a str, key: &str) -> Option<&'a str> {
    let (_, value) = row.split_once(&format!("\"{key}\": "))?;
    Some(if let Some(value) = value.strip_prefix('"') {
        value.split_once('"').unwrap().0
    } else {
        value.split([',', '}']).next().unwrap().trim()
    })
}

fn context_rows() -> Vec<&'static str> {
    SOURCE
        .lines()
        .filter(|row| row.contains("\"context_hex\""))
        .collect()
}

fn wrapper(mut bytes: Vec<u8>) -> Vec<u8> {
    // Parser/policy-only suffix, intentionally not a valid Noise message.
    bytes.extend_from_slice(&[0; NOISE_BYTES]);
    bytes
}

fn context(row: &str, carrier: Carrier) -> Context {
    let returning = match field(row, "base").unwrap() {
        "SYNTRA-CONTEXT-01" => false,
        "SYNTRA-CONTEXT-05" => true,
        _ => panic!("unknown base fixture"),
    };
    Context {
        mode: if returning {
            Mode::Returning
        } else {
            Mode::Bootstrap
        },
        carrier,
        server_key_id: if returning { 0x01020304 } else { 0 },
        epoch: u64::from(returning),
        handle: if returning {
            [1, 2, 3, 4, 5, 6, 7, 8]
        } else {
            [0; 8]
        },
        scope: if returning {
            b"example.service".to_vec()
        } else {
            b"a".to_vec()
        },
    }
}

struct Store {
    expected: Context,
    lookups: AtomicUsize,
}

impl KeyStore for Store {
    fn lookup(&self, context: &Context) -> Result<Secret32, Error> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        if context == &self.expected {
            Ok(Secret32::new([9; 32]))
        } else {
            Err(Error::Authentication)
        }
    }
}

fn server(context: &Context) -> (ServerConfig, [u8; 32], Arc<Store>) {
    let (private_key, public_key) = generate_server_key().unwrap();
    let store = Arc::new(Store {
        expected: context.clone(),
        lookups: AtomicUsize::new(0),
    });
    (
        ServerConfig {
            mode: context.mode,
            carrier: context.carrier,
            server_key_id: context.server_key_id,
            scope: context.scope.clone(),
            private_key,
            store: Some(store.clone()),
        },
        public_key,
        store,
    )
}

#[test]
fn exact_raw_rfc0013_source_sha256_and_inventory() {
    let mut hash = DefaultResolver.resolve_hash(&HashChoice::SHA256).unwrap();
    hash.input(SOURCE.as_bytes());
    let mut digest = [0; 32];
    hash.result(&mut digest);
    assert_eq!(digest.as_slice(), hex(SOURCE_SHA256));
    assert_eq!(field(SOURCE, "status"), Some("pending-adoption"));
    assert_eq!(field(SOURCE, "prologue_equals_context"), Some("true"));
    assert_eq!(context_rows().len(), 4);
    assert_eq!(
        SOURCE
            .lines()
            .filter(|row| row.contains("\"changes\""))
            .count(),
        8
    );
}

#[cfg(not(feature = "http-candidate"))]
#[test]
fn default_rejects_all_four_candidate_rows_even_with_source_present() {
    for row in context_rows() {
        // The unfeatured public type cannot represent HTTP/HTTPS. Use an
        // otherwise matching accepted server policy to check early rejection.
        let (server, _, store) = server(&context(row, Carrier::Tcp));
        let first = wrapper(hex(field(row, "context_hex").unwrap()));
        assert!(
            matches!(Context::parse_first(&first), Err(Error::Invalid)),
            "{row}"
        );
        assert!(
            matches!(respond(&server, &first), Err(Error::Invalid)),
            "{row}"
        );
        assert_eq!(store.lookups.load(Ordering::SeqCst), 0);
    }
}

#[cfg(feature = "http-candidate")]
mod candidate {
    use super::*;

    const MODE_OFFSET: usize = 10;
    const CARRIER_OFFSET: usize = 11;
    const EPOCH_OFFSET: usize = 16;
    const HANDLE_OFFSET: usize = 24;
    const SCOPE_LEN_OFFSET: usize = 32;
    const SCOPE_OFFSET: usize = 34;

    fn carrier(row: &str) -> Carrier {
        match field(row, "carrier").unwrap() {
            "4" => Carrier::Http,
            "5" => Carrier::Https,
            _ => panic!("unknown candidate carrier"),
        }
    }

    fn client(context: &Context, public_key: [u8; 32]) -> ClientConfig {
        ClientConfig {
            context: context.clone(),
            server_public_key: public_key,
            authorization_key: (context.mode == Mode::Returning).then(|| Secret32::new([9; 32])),
        }
    }

    #[test]
    fn four_golden_contexts_encode_parse_and_first_flight() {
        for row in context_rows() {
            let context = context(row, carrier(row));
            let golden = hex(field(row, "context_hex").unwrap());
            assert_eq!(context.encode().unwrap(), golden, "{row}");
            let first = wrapper(golden.clone());
            let (parsed, suffix) = Context::parse_first(&first).unwrap();
            assert_eq!(parsed, context, "{row}");
            assert_eq!(suffix, [0; NOISE_BYTES]);
            let (_, public_key) = generate_server_key().unwrap();
            let (_, first) = ClientHandshake::start(client(&context, public_key)).unwrap();
            assert_eq!(first.len(), golden.len() + NOISE_BYTES);
            assert_eq!(&first[..golden.len()], golden, "{row}");
        }
    }

    #[test]
    fn eight_source_negative_recipes_reject_before_lookup_or_noise() {
        let rows = context_rows();
        let mut count = 0;
        for recipe in SOURCE.lines().filter(|row| row.contains("\"changes\"")) {
            count += 1;
            let row = rows
                .iter()
                .find(|row| field(row, "id") == field(recipe, "base"))
                .unwrap();
            let context = context(row, carrier(row));
            let (server, _, store) = server(&context);
            if let Some(expected) = field(recipe, "expected_carrier") {
                assert_eq!(expected, field(row, "carrier").unwrap());
            }
            let mut bytes = hex(field(row, "context_hex").unwrap());
            let changes = recipe
                .split_once("\"changes\": {")
                .unwrap()
                .1
                .split_once('}')
                .unwrap()
                .0;
            if let Some(value) = field(changes, "carrier") {
                bytes[CARRIER_OFFSET] = value.parse().unwrap();
            } else if let Some(value) = field(changes, "epoch") {
                bytes[EPOCH_OFFSET..HANDLE_OFFSET]
                    .copy_from_slice(&value.parse::<u64>().unwrap().to_be_bytes());
            } else if let Some(value) = field(changes, "handle_hex") {
                bytes[HANDLE_OFFSET..SCOPE_LEN_OFFSET].copy_from_slice(&hex(value));
            } else if let Some(value) = field(changes, "scope") {
                bytes.truncate(SCOPE_OFFSET);
                bytes[SCOPE_LEN_OFFSET..SCOPE_OFFSET]
                    .copy_from_slice(&(value.len() as u16).to_be_bytes());
                bytes.extend_from_slice(value.as_bytes());
            } else if let Some(value) = field(changes, "mode") {
                bytes[MODE_OFFSET] = value.parse().unwrap();
            } else {
                panic!("unhandled recipe: {recipe}");
            }
            let first = wrapper(bytes);
            let policy_mismatch = field(changes, "carrier").is_some_and(|value| value != "6");
            if policy_mismatch {
                // N02 is valid WSS syntax, N07/N08 are valid candidate syntax;
                // each must fail the configured carrier policy BEFORE lookup.
                assert!(Context::parse_first(&first).is_ok(), "{recipe}");
                assert!(
                    matches!(respond(&server, &first), Err(Error::Authentication)),
                    "{recipe}"
                );
            } else {
                assert!(
                    matches!(Context::parse_first(&first), Err(Error::Invalid)),
                    "{recipe}"
                );
                assert!(
                    matches!(respond(&server, &first), Err(Error::Invalid)),
                    "{recipe}"
                );
            }
            assert_eq!(store.lookups.load(Ordering::SeqCst), 0, "{recipe}");
        }
        assert_eq!(count, 8);
    }

    #[test]
    fn both_bindings_and_modes_bidirectional_confirmation_and_terminal_replay() {
        for row in context_rows() {
            let context = context(row, carrier(row));
            let (config, public_key, store) = server(&context);
            let (client, first) = ClientHandshake::start(client(&context, public_key)).unwrap();
            let (mut server, second) = respond(&config, &first).unwrap();
            assert!(server.verified_identity().is_none());
            let mut client = client.finish(&second).unwrap();
            assert!(client.verified_identity().is_none());
            let mut first_request = Vec::new();
            let mut first_reply = Vec::new();
            for i in 0..3 {
                let request = [b'c', i];
                let ciphertext = client.encrypt(&request).unwrap();
                assert_eq!(&**server.decrypt(&ciphertext).unwrap(), request);
                let identity = server.verified_identity().unwrap();
                assert_eq!(identity.context(), &context);
                let reply = [b's', i];
                let response = server.encrypt(&reply).unwrap();
                assert_eq!(&**client.decrypt(&response).unwrap(), reply);
                if i == 0 {
                    first_request = ciphertext;
                    first_reply = response;
                }
            }
            assert_eq!(
                store.lookups.load(Ordering::SeqCst),
                usize::from(context.mode == Mode::Returning)
            );
            assert!(matches!(
                server.decrypt(&first_request),
                Err(Error::Authentication)
            ));
            assert!(server.verified_identity().is_none());
            assert!(matches!(server.encrypt(b"closed"), Err(Error::Closed)));
            assert!(matches!(server.decrypt(&first_request), Err(Error::Closed)));
            assert!(matches!(
                client.decrypt(&first_reply),
                Err(Error::Authentication)
            ));
            assert!(matches!(client.encrypt(b"closed"), Err(Error::Closed)));
            assert!(matches!(client.decrypt(&first_reply), Err(Error::Closed)));
        }
    }

    #[test]
    fn responder_send_before_confirmation_is_still_terminal() {
        for row in context_rows() {
            let context = context(row, carrier(row));
            let (config, public_key, _) = server(&context);
            let (client, first) = ClientHandshake::start(client(&context, public_key)).unwrap();
            let (mut server, second) = respond(&config, &first).unwrap();
            let mut client = client.finish(&second).unwrap();
            assert!(matches!(
                server.encrypt(b"unconfirmed"),
                Err(Error::Authentication)
            ));
            let record = client.encrypt(b"too late").unwrap();
            assert!(matches!(server.decrypt(&record), Err(Error::Closed)));
            assert!(server.verified_identity().is_none());
        }
    }

    #[test]
    fn wrong_carrier_scope_pin_and_psk_fail_without_fallback() {
        for row in context_rows() {
            let context = context(row, carrier(row));
            for (other, code) in [
                (Carrier::Tcp, 1),
                (Carrier::WebSocket, 2),
                (Carrier::SecureWebSocket, 3),
                (Carrier::Http, 4),
                (Carrier::Https, 5),
            ]
            .into_iter()
            .filter(|(other, _)| *other != context.carrier)
            {
                let mut expected = context.clone();
                expected.carrier = other;
                let (config, public_key, store) = server(&expected);
                let (_, mut first) = ClientHandshake::start(client(&context, public_key)).unwrap();
                assert!(matches!(
                    respond(&config, &first),
                    Err(Error::Authentication)
                ));
                assert_eq!(store.lookups.load(Ordering::SeqCst), 0);
                // Rewriting routing bytes to match policy cannot rewrite the
                // authenticated Noise prologue, even between HTTP and HTTPS.
                first[CARRIER_OFFSET] = code;
                assert!(matches!(
                    respond(&config, &first),
                    Err(Error::Authentication)
                ));
                assert_eq!(
                    store.lookups.load(Ordering::SeqCst),
                    usize::from(context.mode == Mode::Returning)
                );
            }
            let mut expected = context.clone();
            expected.scope[0] ^= 1;
            let (config, public_key, store) = server(&expected);
            let (_, mut first) = ClientHandshake::start(client(&context, public_key)).unwrap();
            assert!(matches!(
                respond(&config, &first),
                Err(Error::Authentication)
            ));
            assert_eq!(store.lookups.load(Ordering::SeqCst), 0);
            first[SCOPE_OFFSET] ^= 1;
            assert!(matches!(
                respond(&config, &first),
                Err(Error::Authentication)
            ));
            assert_eq!(
                store.lookups.load(Ordering::SeqCst),
                usize::from(context.mode == Mode::Returning)
            );

            let (config, _, _) = server(&context);
            let (_, wrong_pin) = generate_server_key().unwrap();
            let (_, first) = ClientHandshake::start(client(&context, wrong_pin)).unwrap();
            assert!(matches!(
                respond(&config, &first),
                Err(Error::Authentication)
            ));
            if context.mode == Mode::Returning {
                let (config, public_key, _) = server(&context);
                let mut client = client(&context, public_key);
                client.authorization_key = Some(Secret32::new([10; 32]));
                let (_, first) = ClientHandshake::start(client).unwrap();
                assert!(matches!(
                    respond(&config, &first),
                    Err(Error::Authentication)
                ));
            }
        }
    }

    #[test]
    fn exact_golden_context_is_entire_noise_prologue_for_both_roles() {
        // Raw Snow peers use the SAME pinned library/primitives, not an
        // independent implementation. This checks actual prologue wiring in
        // both kernel roles, not independent ciphertext vectors or interop.
        for row in context_rows() {
            let context = context(row, carrier(row));
            let golden = hex(field(row, "context_hex").unwrap());
            for kernel_is_client in [true, false] {
                let (config, public_key, _) = server(&context);
                let pattern = match context.mode {
                    Mode::Bootstrap => "Noise_NK_25519_ChaChaPoly_SHA256",
                    Mode::Returning => "Noise_NKpsk0_25519_ChaChaPoly_SHA256",
                };
                let key = Secret32::new([9; 32]);
                let mut builder = snow::Builder::new(pattern.parse().unwrap())
                    .prologue(&golden)
                    .unwrap();
                if context.mode == Mode::Returning {
                    builder = builder.psk(0, key.expose()).unwrap();
                }
                let mut msg = [0; NOISE_BYTES];
                let mut scratch = [0; 128];
                let (mut kernel, mut raw) = if kernel_is_client {
                    let mut raw = builder
                        .local_private_key(config.private_key.expose())
                        .unwrap()
                        .build_responder()
                        .unwrap();
                    let (client, first) =
                        ClientHandshake::start(client(&context, public_key)).unwrap();
                    assert_eq!(&first[..golden.len()], golden);
                    assert_eq!(
                        raw.read_message(&first[golden.len()..], &mut scratch)
                            .unwrap(),
                        0
                    );
                    assert_eq!(raw.write_message(&[], &mut msg).unwrap(), NOISE_BYTES);
                    (
                        client.finish(&msg).unwrap(),
                        raw.into_transport_mode().unwrap(),
                    )
                } else {
                    let mut raw = builder
                        .remote_public_key(&public_key)
                        .unwrap()
                        .build_initiator()
                        .unwrap();
                    assert_eq!(raw.write_message(&[], &mut msg).unwrap(), NOISE_BYTES);
                    let mut first = golden.clone();
                    first.extend_from_slice(&msg);
                    let (kernel, second) = respond(&config, &first).unwrap();
                    assert!(kernel.verified_identity().is_none());
                    assert_eq!(raw.read_message(&second, &mut scratch).unwrap(), 0);
                    (kernel, raw.into_transport_mode().unwrap())
                };
                if kernel_is_client {
                    let ciphertext = kernel.encrypt(b"client confirmation").unwrap();
                    let n = raw.read_message(&ciphertext, &mut scratch).unwrap();
                    assert_eq!(&scratch[..n], b"client confirmation");
                    let n = raw.write_message(b"reply", &mut scratch).unwrap();
                    assert_eq!(&**kernel.decrypt(&scratch[..n]).unwrap(), b"reply");
                } else {
                    let n = raw
                        .write_message(b"client confirmation", &mut scratch)
                        .unwrap();
                    assert_eq!(
                        &**kernel.decrypt(&scratch[..n]).unwrap(),
                        b"client confirmation"
                    );
                    assert_eq!(kernel.verified_identity().unwrap().context(), &context);
                    let ciphertext = kernel.encrypt(b"reply").unwrap();
                    let n = raw.read_message(&ciphertext, &mut scratch).unwrap();
                    assert_eq!(&scratch[..n], b"reply");
                }
            }
        }
    }
}
