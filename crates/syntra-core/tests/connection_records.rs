//! Same-library Syntra 1.0 context, record, and authentication checks.
//! These checks are supplemental evidence, not independent interoperability or conformance evidence.
#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;
use syntra_core::secure_channel::*;

struct Store;
impl KeyStore for Store {
    fn lookup(&self, _: &Context) -> Result<Secret32, Error> {
        Ok(Secret32::new([9; 32]))
    }
}

fn context(returning: bool) -> Context {
    Context {
        mode: if returning {
            Mode::Returning
        } else {
            Mode::Bootstrap
        },
        carrier: Carrier::SecureWebSocket,
        server_key_id: 0x01020304,
        scope: b"example.service".to_vec(),
        handle: if returning { [7; 8] } else { [0; 8] },
        epoch: u64::from(returning),
    }
}

#[test]
fn wss_context_uses_candidate_syntra_1_0_bytes() {
    // domain (no terminator), mode, carrier, key id, epoch, handle, u16 scope length/scope.
    // Explicit expected bytes for the WSS context.
    let expected =
        b"syntra.1.0\x01\x03\x01\x02\x03\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0fexample.service";
    let encoded = context(false).encode().unwrap();
    assert_eq!(encoded, expected);
    assert_eq!(encoded.len(), 34 + b"example.service".len());
    let mut returning = expected.to_vec();
    returning[10] = 2;
    returning[23] = 1;
    returning[24..32].fill(7);
    assert_eq!(context(true).encode().unwrap(), returning);
}

#[test]
fn both_modes_fragmented_hello_records_and_terminal_tag_failure() {
    for returning in [false, true] {
        let (private_key, public) = generate_server_key().unwrap();
        let context = context(returning);
        let (handshake, first) = ClientHandshake::start(ClientConfig {
            context: context.clone(),
            server_public_key: public,
            authorization_key: returning.then(|| Secret32::new([9; 32])),
        })
        .unwrap();
        assert_eq!(first.len(), 34 + context.scope.len() + 48);
        assert!((83..=337).contains(&first.len()));
        assert_eq!(
            &first[..context.encode().unwrap().len()],
            context.encode().unwrap()
        );
        let (mut server, second) = respond(
            &ServerConfig {
                mode: context.mode,
                carrier: context.carrier,
                server_key_id: context.server_key_id,
                scope: context.scope,
                private_key,
                store: returning.then(|| Arc::new(Store) as Arc<dyn KeyStore>),
            },
            &first,
        )
        .unwrap();
        assert!(server.verified_identity().is_none());
        let mut client = handshake.finish(&second).unwrap();
        let hello = syntra_core::encode_frame(
            &syntra_core::Frame {
                version: 1,
                request_id: 0,
                body: Some(syntra_core::proto::frame::Body::Hello(
                    syntra_core::build_hello(1, 1, vec![5; 8_000]).unwrap(),
                )),
            },
            syntra_core::ValidationContext::pre_handshake(syntra_core::ConnectionState::Connected),
        )
        .unwrap();
        let framed = frame_plaintext(&hello).unwrap();
        let mut decoder = FrameDecoder::default();
        let mut decoded = Vec::new();
        for chunk in framed.chunks(2_003) {
            let record = client.encrypt(chunk).unwrap();
            assert!(record.len() <= MAX_CIPHERTEXT);
            decoded.extend(decoder.push(&server.decrypt(&record).unwrap()).unwrap());
        }
        assert_eq!(decoded, vec![hello]);
        assert!(!decoder.is_partial());
        assert!(server.verified_identity().is_some());
        let mut record = server.encrypt(b"reply").unwrap();
        record[0] ^= 1;
        assert!(client.decrypt(&record).is_err());
        assert!(matches!(client.decrypt(&record), Err(Error::Closed)));
    }
}

#[test]
fn wrong_pin_or_psk_never_produces_a_client_channel() {
    for returning in [false, true] {
        let (private_key, public) = generate_server_key().unwrap();
        let ctx = context(returning);
        let (_, first) = ClientHandshake::start(ClientConfig {
            context: ctx.clone(),
            server_public_key: public,
            authorization_key: returning.then(|| Secret32::new([8; 32])),
        })
        .unwrap();
        let config = ServerConfig {
            mode: ctx.mode,
            carrier: ctx.carrier,
            server_key_id: ctx.server_key_id,
            scope: ctx.scope.clone(),
            private_key,
            store: returning.then(|| Arc::new(Store) as Arc<dyn KeyStore>),
        };
        if returning {
            assert!(respond(&config, &first).is_err());
        }
        let (_, wrong_pin) = generate_server_key().unwrap();
        let (_, first) = ClientHandshake::start(ClientConfig {
            context: ctx,
            server_public_key: wrong_pin,
            authorization_key: returning.then(|| Secret32::new([9; 32])),
        })
        .unwrap();
        assert!(respond(&config, &first).is_err());
    }
}
