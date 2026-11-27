//! Independent Noise and primitive KATs for the resolver, not Syntra wire-format vectors.
use super::{context_tests::hex, resolver::Resolver, Mode};
use snow::{
    params::{CipherChoice, DHChoice},
    resolvers::CryptoResolver,
    Builder,
};

#[path = "../../tests/fixtures/resolver_kats/cacophony.rs"]
mod cacophony;
#[path = "../../tests/fixtures/resolver_kats/wycheproof.rs"]
mod wycheproof;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn cacophony_noise_transcripts() {
    for (mode, kat) in [
        (Mode::Bootstrap, cacophony::NK),
        (Mode::Returning, cacophony::NKPSK0),
    ] {
        let suite = mode.pattern();
        assert_eq!(suite, kat.protocol_name);
        let prologue = hex(cacophony::PROLOGUE);
        let psk = kat.psk0.map(|s| <[u8; 32]>::try_from(hex(s)).unwrap());
        let builder = || {
            let b = Builder::with_resolver(suite.parse().unwrap(), Box::<Resolver>::default())
                .prologue(&prologue)
                .unwrap();
            match &psk {
                Some(key) => b.psk(0, key).unwrap(),
                None => b,
            }
        };
        let mut init = builder()
            .remote_public_key(&hex(cacophony::INIT_REMOTE_STATIC))
            .unwrap()
            .fixed_ephemeral_key_for_testing_only(&hex(cacophony::INIT_EPHEMERAL))
            .build_initiator()
            .unwrap();
        let mut resp = builder()
            .local_private_key(&hex(cacophony::RESP_STATIC))
            .unwrap()
            .fixed_ephemeral_key_for_testing_only(&hex(cacophony::RESP_EPHEMERAL))
            .build_responder()
            .unwrap();

        let mut messages = cacophony::PAYLOADS
            .into_iter()
            .zip(kat.ciphertexts)
            .map(|(p, c)| (hex(p), hex(c)));
        let mut buf = [0; 256];
        for i in 0..2 {
            let (send, recv) = if i == 0 {
                (&mut init, &mut resp)
            } else {
                (&mut resp, &mut init)
            };
            let (payload, ciphertext) = messages.next().unwrap();
            let n = send.write_message(&payload, &mut buf).unwrap();
            assert_eq!(buf[..n], ciphertext, "{suite} handshake {i}");
            let n = recv.read_message(&ciphertext, &mut buf).unwrap();
            assert_eq!(buf[..n], payload, "{suite} handshake {i}");
        }
        let hash = hex(kat.handshake_hash);
        assert_eq!(init.get_handshake_hash(), hash, "{suite} initiator");
        assert_eq!(resp.get_handshake_hash(), hash, "{suite} responder");

        let mut init = init.into_transport_mode().unwrap();
        let mut resp = resp.into_transport_mode().unwrap();
        for (i, (payload, ciphertext)) in messages.enumerate() {
            let (send, recv) = if i % 2 == 0 {
                (&mut init, &mut resp)
            } else {
                (&mut resp, &mut init)
            };
            let n = send.write_message(&payload, &mut buf).unwrap();
            assert_eq!(buf[..n], ciphertext, "{suite} transport {i}");
            let n = recv.read_message(&ciphertext, &mut buf).unwrap();
            assert_eq!(buf[..n], payload, "{suite} transport {i}");
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn wycheproof_x25519() {
    let mut dh = Resolver::default()
        .resolve_dh(&DHChoice::Curve25519)
        .unwrap();
    for case in wycheproof::X25519_CASES {
        dh.set(&hex(case.private));
        let mut out = [0; 32];
        let result = dh.dh(&hex(case.public), &mut out);
        let shared = hex(case.shared);
        if shared == [0; 32] {
            assert!(matches!(result, Err(snow::Error::Dh)), "tcId {}", case.id);
        } else {
            result.unwrap();
            assert_eq!(out.as_slice(), shared, "tcId {}", case.id);
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn wycheproof_chachapoly_and_derived_bad_tags() {
    use wycheproof::{AAD, CT};
    let mut cipher = Resolver::default()
        .resolve_cipher(&CipherChoice::ChaChaPoly)
        .unwrap();
    cipher.set(&hex(wycheproof::KEY).try_into().unwrap());
    for case in wycheproof::CHACHAPOLY_CASES {
        let iv = hex(case.iv);
        assert_eq!(iv[..4], [0; 4], "IV must fit a Noise nonce");
        let nonce = u64::from_le_bytes(iv[4..].try_into().unwrap());
        let msg = hex(case.msg);
        let mut sealed = CT.to_vec();
        sealed.extend(hex(case.tag));
        let mut out = vec![0; sealed.len()];
        let n = cipher.encrypt(nonce, &AAD, &msg, &mut out);
        assert_eq!(out[..n], sealed, "tcId {}", case.id);
        let n = cipher.decrypt(nonce, &AAD, &sealed, &mut out).unwrap();
        assert_eq!(out[..n], msg, "tcId {}", case.id);

        sealed[CT.len()] ^= 1;
        assert!(
            matches!(
                cipher.decrypt(nonce, &AAD, &sealed, &mut out),
                Err(snow::Error::Decrypt)
            ),
            "modified tag for tcId {}",
            case.id
        );
    }
}
