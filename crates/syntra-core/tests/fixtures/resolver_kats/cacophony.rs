// Public test data only. See README.md for source, selection and license.
pub const PROLOGUE: &str = "4a6f686e2047616c74";
pub const INIT_EPHEMERAL: &str = "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a";
pub const INIT_REMOTE_STATIC: &str =
    "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62";
pub const RESP_STATIC: &str = "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893";
pub const RESP_EPHEMERAL: &str = "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b";
pub const PAYLOADS: [&str; 6] = [
    "4c756477696720766f6e204d69736573",
    "4d757272617920526f746862617264",
    "462e20412e20486179656b",
    "4361726c204d656e676572",
    "4a65616e2d426170746973746520536179",
    "457567656e2042f6686d20766f6e2042617765726b",
];

pub struct Transcript {
    pub protocol_name: &'static str,
    pub psk0: Option<&'static str>,
    pub handshake_hash: &'static str,
    pub ciphertexts: [&'static str; 6],
}

pub const NK: Transcript = Transcript {
    protocol_name: "Noise_NK_25519_ChaChaPoly_SHA256",
    psk0: None,
    handshake_hash: "2efa38a9c7c93ac98f3a097af25c2f58b9e7673787717bc27e98827118c2c1a5",
    ciphertexts: [
        "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79448134d00711fdb390a0d178fa008f6d47d2891e5ea18ae136c3b4c23ac384efb0",
        "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088438ea16e3701bc0d77744f117bee22451c9afa7f4cdbbcff00c04a8ee0913c88",
        "a62de29ce27cb80245d440d986ed816c156e9d757d7008df2198b0",
        "174a35f11c689f4530d7208618e0564ae12f2f50ba8eb4df5382ff",
        "337e475ebb8eae60f91974c4e455a5af38d1d8628d1803b160d60442874b0a1777",
        "047e80e060b7bb08b53c5a23dfe9920cae135b9d1dc6302fc475003062723700366346ac9d",
    ],
};

pub const NKPSK0: Transcript = Transcript {
    protocol_name: "Noise_NKpsk0_25519_ChaChaPoly_SHA256",
    psk0: Some("54686973206973206d7920417573747269616e20706572737065637469766521"),
    handshake_hash: "1609ef057bdd62c752b5960546a255a78aebff08c5f07ef2adaa1db8350e7077",
    ciphertexts: [
        "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944190fec41487219f2069c3ba7b7f9521437045935231f0ed399dfd4baf6bd825b",
        "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884385010e0c56e886e6da0c69aee7388bcf4000cc357af5ebd11a46a169a3712c",
        "4beed26535f1a387c950fab9a162dc613cc5bf84e8a62653130b83",
        "ceaffe71ce7f1bf7b080736d62e0579ce5dc1530a36e7df795a4cc",
        "da927a272831394122d0f2fef3e16ddf0814c4878401135b44b1e23873b45b2929",
        "4fed2b394fb4dbdc9cf863bc99ebb3397651d27bdd32e40d8f7fed109e46445c0fd66fc3f3",
    ],
};
