use std::sync::Arc;
use syntra_secure_channel::*;

struct Store;
impl KeyStore for Store {
    fn lookup(&self, c: &Context) -> Result<Secret32, Error> {
        if c.handle == [7; 8] && c.epoch == 3 {
            Ok(Secret32::new([9; 32]))
        } else {
            Err(Error::Authentication)
        }
    }
}

fn configs(mode: Mode) -> (ClientConfig, ServerConfig) {
    let (key, public) = generate_server_key().unwrap();
    let returning = mode == Mode::Returning;
    let context = Context {
        mode,
        carrier: Carrier::Tcp,
        server_key_id: 42,
        scope: b"service.example/chat".to_vec(),
        handle: if returning { [7; 8] } else { [0; 8] },
        epoch: if returning { 3 } else { 0 },
    };
    (
        ClientConfig {
            context: context.clone(),
            server_public_key: public,
            authorization_key: returning.then(|| Secret32::new([9; 32])),
        },
        ServerConfig {
            mode,
            carrier: context.carrier,
            server_key_id: 42,
            scope: context.scope,
            private_key: key,
            store: returning.then(|| Arc::new(Store) as Arc<dyn KeyStore>),
        },
    )
}

fn pair(mode: Mode) -> (Channel, Channel) {
    let (client, server) = configs(mode);
    let (client, first) = ClientHandshake::start(client).unwrap();
    let (server, second) = respond(&server, &first).unwrap();
    assert!(server.verified_identity().is_none());
    (client.finish(&second).unwrap(), server)
}

#[test]
fn both_modes_bidirectional_and_fresh_confirmation() {
    for mode in [Mode::Bootstrap, Mode::Returning] {
        for (carrier, code) in [
            (Carrier::Tcp, 1),
            (Carrier::WebSocket, 2),
            (Carrier::SecureWebSocket, 3),
        ] {
            let (mut client_config, mut server_config) = configs(mode);
            client_config.context.carrier = carrier;
            server_config.carrier = carrier;
            let (client, first) = ClientHandshake::start(client_config).unwrap();
            assert_eq!(first[14], code);
            let (mut server, second) = respond(&server_config, &first).unwrap();
            assert!(server.verified_identity().is_none());
            let mut client = client.finish(&second).unwrap();
            let first = client.encrypt(b"hello").unwrap();
            assert_eq!(&**server.decrypt(&first).unwrap(), b"hello");
            assert_eq!(server.verified_identity().unwrap().context().mode, mode);
            assert_eq!(
                server.verified_identity().unwrap().context().carrier,
                carrier
            );
            assert_eq!(
                &**client.decrypt(&server.encrypt(b"ready").unwrap()).unwrap(),
                b"ready"
            );
        }
    }
}

#[test]
fn carrier_context_cannot_be_reinterpreted() {
    let carriers = [Carrier::Tcp, Carrier::WebSocket, Carrier::SecureWebSocket];
    for mode in [Mode::Bootstrap, Mode::Returning] {
        for carrier in carriers {
            let (mut client, mut server) = configs(mode);
            client.context.carrier = carrier;
            let (_, first) = ClientHandshake::start(client).unwrap();
            for other in carriers.into_iter().filter(|other| *other != carrier) {
                server.carrier = other;
                // Even valid context for a different configured carrier fails.
                assert!(matches!(
                    respond(&server, &first),
                    Err(Error::Authentication)
                ));
                let mut tampered = first.clone();
                tampered[14] = match other {
                    Carrier::Tcp => 1,
                    Carrier::WebSocket => 2,
                    Carrier::SecureWebSocket => 3,
                };
                // Matching the public carrier to server policy cannot change
                // the prologue authenticated by the original Noise M1.
                assert!(matches!(
                    respond(&server, &tampered),
                    Err(Error::Authentication)
                ));
            }
        }
    }
}

#[test]
fn mode_requires_exact_authorization_key_presence() {
    let (mut bootstrap, _) = configs(Mode::Bootstrap);
    bootstrap.authorization_key = Some(Secret32::generate().unwrap());
    assert!(matches!(
        ClientHandshake::start(bootstrap),
        Err(Error::Invalid)
    ));
    let (mut returning, _) = configs(Mode::Returning);
    returning.authorization_key = None;
    assert!(matches!(
        ClientHandshake::start(returning),
        Err(Error::Invalid)
    ));
}

#[test]
fn responder_cannot_send_before_confirmation() {
    let (_, mut server) = pair(Mode::Returning);
    assert!(server.encrypt(b"sensitive").is_err());
    assert!(server.verified_identity().is_none());
    assert!(matches!(server.decrypt(&[0; 17]), Err(Error::Closed)));
}

#[test]
fn wrong_keys_and_prologue_fail_without_fallback() {
    let (mut client, _) = configs(Mode::Bootstrap);
    client.server_public_key = [0; 32];
    assert!(ClientHandshake::start(client).is_err());
    for mode in [Mode::Bootstrap, Mode::Returning] {
        let (mut client, server) = configs(mode);
        client.server_public_key = generate_server_key().unwrap().1;
        let (_, first) = ClientHandshake::start(client).unwrap();
        assert!(respond(&server, &first).is_err());
    }
    let (mut client, server) = configs(Mode::Returning);
    client.authorization_key = Some(Secret32::new([10; 32]));
    let (_, first) = ClientHandshake::start(client).unwrap();
    assert!(respond(&server, &first).is_err());
    for offset in [0, 12, 13, 14, 15, 19, 27, 35, 37] {
        let (client, server) = configs(Mode::Returning);
        let (_, mut first) = ClientHandshake::start(client).unwrap();
        first[offset] ^= 1;
        assert!(respond(&server, &first).is_err(), "offset {offset}");
    }
}

#[test]
fn tampered_second_flight_and_early_payload_lengths_are_rejected() {
    for mode in [Mode::Bootstrap, Mode::Returning] {
        let (client, server) = configs(mode);
        let (client, first) = ClientHandshake::start(client).unwrap();
        let (_, mut second) = respond(&server, &first).unwrap();
        second[47] ^= 1;
        assert!(client.finish(&second).is_err());
        let mut early = first;
        early.push(0);
        assert!(respond(&server, &early).is_err());
    }
}

#[test]
fn replay_m1_does_not_confirm_and_old_transport_record_fails() {
    let (client, server) = configs(Mode::Returning);
    let (client, first) = ClientHandshake::start(client).unwrap();
    let (mut original, second) = respond(&server, &first).unwrap();
    let mut client = client.finish(&second).unwrap();
    let record = client.encrypt(b"hello").unwrap();
    original.decrypt(&record).unwrap();
    let (mut replay, fresh_second) = respond(&server, &first).unwrap();
    assert_ne!(second, fresh_second);
    assert!(replay.verified_identity().is_none());
    assert!(replay.decrypt(&record).is_err());
    assert!(replay.verified_identity().is_none());
}

#[test]
fn tamper_and_reorder_poison_state() {
    for mode in [Mode::Bootstrap, Mode::Returning] {
        let (mut client, mut server) = pair(mode);
        let good = client.encrypt(b"hello").unwrap();
        let mut bad = good.clone();
        bad[0] ^= 1;
        assert!(server.decrypt(&bad).is_err());
        assert!(matches!(server.decrypt(&good), Err(Error::Closed)));
        let (mut client, mut server) = pair(mode);
        let first = client.encrypt(b"one").unwrap();
        let second = client.encrypt(b"two").unwrap();
        assert!(server.decrypt(&second).is_err());
        assert!(server.decrypt(&first).is_err());
    }
}

#[test]
fn record_and_frame_limits_and_segmentation() {
    let (mut client, mut server) = pair(Mode::Returning);
    let frame = vec![123; MAX_FRAME];
    let stream = frame_plaintext(&frame).unwrap();
    let mut decoder = FrameDecoder::default();
    let mut assembled = Vec::new();
    for chunk in stream.chunks(MAX_PLAINTEXT) {
        let encrypted = client.encrypt(chunk).unwrap();
        assert!(encrypted.len() <= MAX_CIPHERTEXT);
        assembled.extend(decoder.push(&server.decrypt(&encrypted).unwrap()).unwrap());
    }
    assert_eq!(assembled, [frame]);
    assert!(!decoder.is_partial());
    assert!(frame_plaintext(&[]).is_err());
    assert!(frame_plaintext(&vec![0; MAX_FRAME + 1]).is_err());
    assert!(client.encrypt(&vec![0; MAX_PLAINTEXT + 1]).is_err());
    assert!(client.encrypt(b"closed").is_err());
    for bad in [0u32, (MAX_FRAME + 1) as u32, u32::MAX] {
        let mut decoder = FrameDecoder::default();
        assert!(decoder.push(&bad.to_be_bytes()).is_err());
        assert!(decoder.push(&[0, 0, 0, 1, 5]).is_err());
    }
}

#[test]
fn every_inner_split_point_and_coalescing() {
    let mut bytes = frame_plaintext(b"first").unwrap().to_vec();
    bytes.extend_from_slice(&frame_plaintext(b"second").unwrap());
    for split in 0..=bytes.len() {
        let mut decoder = FrameDecoder::default();
        let mut frames = decoder.push(&bytes[..split]).unwrap();
        frames.extend(decoder.push(&bytes[split..]).unwrap());
        assert_eq!(frames, [b"first".to_vec(), b"second".to_vec()]);
        assert!(!decoder.is_partial());
    }
}

#[test]
fn wrapper_is_canonical_and_bounded() {
    let (client, _) = configs(Mode::Returning);
    let context = client.context.clone();
    let (_, first) = ClientHandshake::start(client).unwrap();
    let (parsed, message) = Context::parse_first(&first).unwrap();
    assert_eq!(parsed, context);
    assert_eq!(message.len(), 48);
    assert_eq!(&first[..19], b"syntra.sc1.v1\x02\x01\x00\x00\x00\x2a");
    assert_eq!(&first[19..27], &3u64.to_be_bytes());
    assert_eq!(&first[27..35], &[7; 8]);
    assert_eq!(&first[35..37], &20u16.to_be_bytes());
    assert_eq!(&first[37..57], b"service.example/chat");
    for n in 0..first.len() {
        assert!(Context::parse_first(&first[..n]).is_err());
    }
    let mut extra = first;
    extra.push(0);
    assert!(Context::parse_first(&extra).is_err());
}

#[test]
fn secrets_are_redacted_and_enrollments_are_independent() {
    let a = Enrollment::generate(1).unwrap();
    let b = Enrollment::generate(1).unwrap();
    assert_ne!(a.key.expose(), b.key.expose());
    assert_ne!(a.handle, b.handle);
    assert_eq!(format!("{:?}", a.key), "Secret32([REDACTED])");
}
