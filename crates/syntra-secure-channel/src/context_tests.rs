use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[path = "../tests/fixtures/sc1_context_v1.rs"]
mod fixtures;

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

fn context(fixture: &fixtures::Fixture) -> Context {
    Context {
        mode: match fixture.mode {
            1 => Mode::Bootstrap,
            2 => Mode::Returning,
            _ => panic!("invalid fixture mode"),
        },
        carrier: match fixture.carrier {
            1 => Carrier::Tcp,
            2 => Carrier::WebSocket,
            3 => Carrier::SecureWebSocket,
            _ => panic!("invalid fixture carrier"),
        },
        server_key_id: fixture.server_key_id,
        epoch: fixture.epoch,
        handle: hex(fixture.handle_hex).try_into().unwrap(),
        scope: fixture.scope.as_bytes().to_vec(),
    }
}

// Parser-only suffix: deliberately not a valid Noise message or a crypto vector.
fn wrapper(mut context: Vec<u8>) -> Vec<u8> {
    context.extend_from_slice(&[0; 48]);
    context
}

#[test]
fn four_pinned_upstream_context_and_prologue_fixtures() {
    for fixture in &fixtures::CONTEXTS {
        let expected = hex(fixture.context_hex);
        let context = context(fixture);
        assert_eq!(expected.len(), fixture.context_bytes, "{}", fixture.id);
        assert_eq!(context.encode().unwrap(), expected, "{}", fixture.id);
        assert_eq!(
            context.prologue().unwrap(),
            hex(fixture.prologue_hex),
            "{}",
            fixture.id
        );
        let first = wrapper(expected.clone());
        assert_eq!(first.len(), fixture.m1_bytes, "{}", fixture.id);
        let (parsed, suffix) = Context::parse_first(&first).unwrap();
        assert_eq!(parsed, context, "{}", fixture.id);
        assert_eq!(suffix, &[0; 48]);
        assert_eq!(parsed.encode().unwrap(), expected, "{}", fixture.id);

        // Exercise the actual initiator with fresh entropy; only public context
        // bytes and lengths are compared with the fixtures, never ciphertext.
        let (_, public) = generate_server_key().unwrap();
        let (_, first) = ClientHandshake::start(ClientConfig {
            context,
            server_public_key: public,
            authorization_key: (fixture.mode == 2).then(|| Secret32::generate().unwrap()),
        })
        .unwrap();
        assert_eq!(first.len(), fixture.m1_bytes, "{}", fixture.id);
        assert_eq!(&first[..expected.len()], expected, "{}", fixture.id);
    }
}

#[derive(Default)]
struct CountingStore(AtomicUsize);

impl KeyStore for CountingStore {
    fn lookup(&self, _: &Context) -> Result<Secret32, Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Error::Authentication)
    }
}

fn rejecting_server() -> (ServerConfig, Arc<CountingStore>) {
    let context = context(&fixtures::CONTEXTS[2]);
    let store = Arc::new(CountingStore::default());
    (
        ServerConfig {
            mode: context.mode,
            carrier: context.carrier,
            server_key_id: context.server_key_id,
            scope: context.scope,
            private_key: generate_server_key().unwrap().0,
            store: Some(store.clone()),
        },
        store,
    )
}

fn assert_rejected_before_lookup(server: &ServerConfig, first: &[u8], label: &str) {
    assert!(
        matches!(Context::parse_first(first), Err(Error::Invalid)),
        "parser accepted {label}"
    );
    assert!(
        matches!(respond(server, first), Err(Error::Invalid)),
        "responder did not reject malformed {label} before Noise"
    );
}

#[test]
fn upstream_negative_recipes_reject_before_lookup_and_noise() {
    let bootstrap = hex(fixtures::CONTEXTS[0].context_hex);
    let returning = hex(fixtures::CONTEXTS[2].context_hex);
    let mut cases = Vec::new();

    let mut legacy_go = b"syntra.sc1.draft1".to_vec();
    legacy_go.extend_from_slice(&bootstrap[13..]);
    cases.push(("SC1-N01 legacy Go domain", legacy_go));

    // Complete old Rust local-revision context: revision, mode/carrier, key,
    // scope length/scope, then handle/epoch (not canonical field order).
    let mut legacy_rust = b"SNTRSC1L\x00\x01\x00\x01".to_vec();
    legacy_rust.extend_from_slice(&0u32.to_be_bytes());
    legacy_rust.extend_from_slice(&1u16.to_be_bytes());
    legacy_rust.push(b'a');
    legacy_rust.extend_from_slice(&[0; 16]);
    cases.push(("SC1-N02 legacy Rust context", legacy_rust));

    let mut bad = bootstrap.clone();
    bad[13] = 0;
    cases.push(("SC1-N03 zero mode", bad));
    let mut bad = bootstrap.clone();
    bad[14] = 4;
    cases.push(("SC1-N04 unknown carrier", bad));
    let mut bad = bootstrap.clone();
    bad[26] = 1;
    cases.push(("SC1-N05 bootstrap epoch", bad));
    let mut bad = returning;
    bad[27..35].fill(0);
    cases.push(("SC1-N06 returning zero handle", bad));
    let mut bad = bootstrap[..37].to_vec();
    bad[35..37].copy_from_slice(&0u16.to_be_bytes());
    cases.push(("SC1-N07 empty scope", bad));
    let mut bad = bootstrap[..37].to_vec();
    bad[35..37].copy_from_slice(&256u16.to_be_bytes());
    bad.extend_from_slice(&[b'a'; 256]);
    cases.push(("SC1-N08 oversized scope", bad));
    cases.push(("SC1-N09 truncated scope", bootstrap[..37].to_vec()));
    let mut bad = bootstrap.clone();
    bad.push(0);
    cases.push(("SC1-N10 trailing context byte", bad));
    let mut bad = bootstrap;
    bad[37] = 0xff;
    cases.push(("SC1-N11 invalid UTF-8", bad));
    let mut bad = hex(fixtures::CONTEXTS[3].context_hex);
    bad[35..37].copy_from_slice(&1u16.to_be_bytes());
    cases.push(("SC1-N12 character count instead of byte length", bad));

    let (server, store) = rejecting_server();
    for (label, bytes) in cases {
        assert_rejected_before_lookup(&server, &wrapper(bytes), label);
        assert_eq!(store.0.load(Ordering::SeqCst), 0, "{label}");
    }
    // Positive control: a structurally valid returning wrapper reaches lookup.
    let valid = wrapper(hex(fixtures::CONTEXTS[2].context_hex));
    assert!(matches!(
        respond(&server, &valid),
        Err(Error::Authentication)
    ));
    assert_eq!(store.0.load(Ordering::SeqCst), 1);
}

#[test]
fn malformed_fields_and_every_truncation_reject_without_lookup() {
    let (server, store) = rejecting_server();
    let fixture = &fixtures::CONTEXTS[2];
    let mut legacy = b"SNTRSC1L\x00\x01\x01\x02".to_vec();
    legacy.extend_from_slice(&fixture.server_key_id.to_be_bytes());
    legacy.extend_from_slice(&(fixture.scope.len() as u16).to_be_bytes());
    legacy.extend_from_slice(fixture.scope.as_bytes());
    legacy.extend_from_slice(&hex(fixture.handle_hex));
    legacy.extend_from_slice(&fixture.epoch.to_be_bytes());
    let legacy = wrapper(legacy);
    assert!(legacy.len() >= 86);
    assert_rejected_before_lookup(&server, &legacy, "complete legacy returning context");
    for fixture in &fixtures::CONTEXTS {
        let bytes = hex(fixture.context_hex);
        let first = wrapper(bytes.clone());
        for n in 0..first.len() {
            assert_rejected_before_lookup(&server, &first[..n], fixture.id);
        }
        let mut extra = first;
        extra.push(0);
        assert_rejected_before_lookup(&server, &extra, "49-byte Noise suffix");
        for mode in [0, 3, 255] {
            let mut bad = bytes.clone();
            bad[13] = mode;
            assert_rejected_before_lookup(&server, &wrapper(bad), "invalid mode");
        }
        for carrier in [0, 4, 255] {
            let mut bad = bytes.clone();
            bad[14] = carrier;
            assert_rejected_before_lookup(&server, &wrapper(bad), "invalid carrier");
        }
        let mut bad = bytes;
        if fixture.mode == 1 {
            bad[27] = 1;
        } else {
            bad[19..27].fill(0);
        }
        assert_rejected_before_lookup(&server, &wrapper(bad), "invalid enrollment fields");
    }
    let mut oversized = vec![0; MAX_WRAPPER + 1];
    oversized[..13].copy_from_slice(b"syntra.sc1.v1");
    assert_rejected_before_lookup(&server, &oversized, "wrapper above maximum");
    let mut bad = hex(fixtures::CONTEXTS[2].context_hex);
    bad[35..37].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_rejected_before_lookup(&server, &wrapper(bad), "oversized claimed scope");
    assert_eq!(store.0.load(Ordering::SeqCst), 0);
}

#[test]
fn invalid_contexts_reject_before_initiator_noise_rng() {
    let mut invalid = Vec::new();
    for mode in [Mode::Bootstrap, Mode::Returning] {
        let base = context(&fixtures::CONTEXTS[if mode == Mode::Bootstrap { 0 } else { 2 }]);
        for scope in [vec![], vec![b'a'; 256], vec![0xff], vec![0xc3]] {
            let mut bad = base.clone();
            bad.scope = scope;
            invalid.push(bad);
        }
        let mut bad = base.clone();
        bad.handle = if mode == Mode::Bootstrap {
            [1; 8]
        } else {
            [0; 8]
        };
        invalid.push(bad);
        let mut bad = base;
        bad.epoch = if mode == Mode::Bootstrap { 1 } else { 0 };
        invalid.push(bad);
    }
    for context in invalid {
        assert!(matches!(context.encode(), Err(Error::Invalid)));
        assert!(matches!(context.prologue(), Err(Error::Invalid)));
        let authorization_key =
            (context.mode == Mode::Returning).then(|| Secret32::generate().unwrap());
        assert!(matches!(
            ClientHandshake::start_with_resolver(
                ClientConfig {
                    context,
                    server_public_key: [5; 32],
                    authorization_key,
                },
                Box::new(resolver::Resolver { fail_rng: true }),
            ),
            Err(Error::Invalid)
        ));
    }
}

#[test]
fn scope_byte_bounds_utf8_and_no_normalization() {
    assert_eq!(MAX_WRAPPER, 340);
    for fixture in &fixtures::CONTEXTS {
        for scope in [
            "a".to_owned(),
            "a".repeat(255),
            format!("{}a", "é".repeat(127)),
            "é".to_owned(),
            "e\u{301}".to_owned(),
            "\0".to_owned(),
        ] {
            let mut context = context(fixture);
            context.scope = scope.as_bytes().to_vec();
            let encoded = context.encode().unwrap();
            assert_eq!(&encoded[35..37], &(scope.len() as u16).to_be_bytes());
            assert_eq!(&encoded[37..], scope.as_bytes());
            let first = wrapper(encoded);
            assert_eq!(first.len(), 85 + scope.len());
            if scope.len() == 255 {
                assert_eq!(first.len(), MAX_WRAPPER);
            }
            assert_eq!(Context::parse_first(&first).unwrap().0, context);
        }
        let mut context = context(fixture);
        context.scope = "é".repeat(128).into_bytes();
        assert_eq!(context.scope.len(), 256);
        assert!(matches!(context.encode(), Err(Error::Invalid)));
    }
    let (server, store) = rejecting_server();
    for scope in [
        vec![0xff],
        vec![0xc3],
        vec![0xc0, 0xaf],
        vec![0xed, 0xa0, 0x80],
        vec![0xf4, 0x90, 0x80, 0x80],
    ] {
        let mut bad = hex(fixtures::CONTEXTS[2].context_hex)[..37].to_vec();
        bad[35..37].copy_from_slice(&(scope.len() as u16).to_be_bytes());
        bad.extend_from_slice(&scope);
        assert_rejected_before_lookup(&server, &wrapper(bad), "malformed UTF-8 scope");
    }
    assert_eq!(store.0.load(Ordering::SeqCst), 0);
}
