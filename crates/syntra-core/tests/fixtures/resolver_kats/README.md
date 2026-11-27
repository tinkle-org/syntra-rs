# Resolver known-answer fixtures

These are public test keys and expected bytes from independent corpora, transcribed
as Rust constants so tests need neither the network nor a corpus parser.

Wycheproof data: Copyright 2016–2026 The Wycheproof Authors.

| Fixture | Pinned source / vector IDs | License |
| --- | --- | --- |
| `cacophony.rs` | [Cacophony, `vectors/cacophony.txt`](https://github.com/centromere/cacophony/blob/18b7348c54fd61fcd0c220298883de0d09c8364d/vectors/cacophony.txt): `Noise_NK_25519_ChaChaPoly_SHA256` and `Noise_NKpsk0_25519_ChaChaPoly_SHA256` | [Unlicense (public domain)](https://github.com/centromere/cacophony/blob/18b7348c54fd61fcd0c220298883de0d09c8364d/LICENSE) |
| `wycheproof.rs` (DH) | [Project Wycheproof, `testvectors_v1/x25519_test.json`](https://github.com/C2SP/wycheproof/blob/65ca494727a52944c204441c860b039e6786b99b/testvectors_v1/x25519_test.json): tcIds 1, 100 (`valid`); 32, 64 (`acceptable`, `ZeroSharedSecret`) | [Apache-2.0](../../../../../LICENSE) |
| `wycheproof.rs` (AEAD) | [Project Wycheproof, `testvectors_v1/chacha20_poly1305_test.json`](https://github.com/C2SP/wycheproof/blob/65ca494727a52944c204441c860b039e6786b99b/testvectors_v1/chacha20_poly1305_test.json): tcIds 216, 217 (`valid`, `EdgeCasePolyKey`) | [Apache-2.0](https://github.com/C2SP/wycheproof/blob/65ca494727a52944c204441c860b039e6786b99b/LICENSE) |

The Cacophony cases share keys, prologue and payloads. Each has two handshake
messages, a final handshake hash, and four alternating transport messages. They
exercise Snow with Syntra's resolver, not Syntra's context encoding, empty
handshake payloads, framing, or record policy.

Syntra rejects all-zero DH results, including for tcId 64's nonzero low-order
public key. Wycheproof permits rejection; it does not label those cases `invalid`.

Snow's ChaChaPoly nonce represents `00000000 || little_endian_u64`. None of
the published `invalid` AEAD IVs fit that interface. The tests preserve the
two selected IVs exactly and check `ct || tag`. They also flip bit 0 of the
first tag byte as a **derived** rejection check, not a published invalid tcId.
