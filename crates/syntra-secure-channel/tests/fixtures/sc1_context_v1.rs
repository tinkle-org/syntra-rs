// Public context/prologue fixtures transcribed without changing their bytes from:
// https://github.com/tinkle-org/syntra/blob/94404d7378136d8b6c88ece28bf945c88d1653ba/conformance/plans/sc1-context-v1.json
// Proposal: RFC 0007 section 11; upstream status: proposal-only.
// These are encoding examples, not Noise ciphertext or cryptographic vectors,
// conformance registration, or evidence of executed interoperability.

pub struct Fixture {
    pub id: &'static str,
    pub mode: u8,
    pub carrier: u8,
    pub server_key_id: u32,
    pub epoch: u64,
    pub handle_hex: &'static str,
    pub scope: &'static str,
    pub context_hex: &'static str,
    pub prologue_hex: &'static str,
    pub context_bytes: usize,
    pub m1_bytes: usize,
}

pub const CONTEXTS: [Fixture; 4] = [
    Fixture {
        id: "SC1-CONTEXT-01",
        mode: 1,
        carrier: 1,
        server_key_id: 0,
        epoch: 0,
        handle_hex: "0000000000000000",
        scope: "a",
        context_hex: "73796e7472612e7363312e763101010000000000000000000000000000000000000000000161",
        prologue_hex: "73796e7472612e7363312e763101010000000000000000000000000000000000000000000161",
        context_bytes: 38,
        m1_bytes: 86,
    },
    Fixture {
        id: "SC1-CONTEXT-02",
        mode: 1,
        carrier: 3,
        server_key_id: 16909060,
        epoch: 0,
        handle_hex: "0000000000000000",
        scope: "example.service",
        context_hex: "73796e7472612e7363312e763101030102030400000000000000000000000000000000000f6578616d706c652e73657276696365",
        prologue_hex: "73796e7472612e7363312e763101030102030400000000000000000000000000000000000f6578616d706c652e73657276696365",
        context_bytes: 52,
        m1_bytes: 100,
    },
    Fixture {
        id: "SC1-CONTEXT-03",
        mode: 2,
        carrier: 2,
        server_key_id: 16909060,
        epoch: 1,
        handle_hex: "0102030405060708",
        scope: "example.service",
        context_hex: "73796e7472612e7363312e763102020102030400000000000000010102030405060708000f6578616d706c652e73657276696365",
        prologue_hex: "73796e7472612e7363312e763102020102030400000000000000010102030405060708000f6578616d706c652e73657276696365",
        context_bytes: 52,
        m1_bytes: 100,
    },
    Fixture {
        id: "SC1-CONTEXT-04",
        mode: 2,
        carrier: 3,
        server_key_id: 4294967295,
        epoch: 18446744073709551615,
        handle_hex: "0807060504030201",
        scope: "é",
        context_hex: "73796e7472612e7363312e76310203ffffffffffffffffffffffff08070605040302010002c3a9",
        prologue_hex: "73796e7472612e7363312e76310203ffffffffffffffffffffffff08070605040302010002c3a9",
        context_bytes: 39,
        m1_bytes: 87,
    },
];
