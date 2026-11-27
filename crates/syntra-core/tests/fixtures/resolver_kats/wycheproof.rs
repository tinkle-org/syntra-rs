// Public test data only. See README.md for tcIds, results and license.
pub struct X25519 {
    pub id: u16,
    pub private: &'static str,
    pub public: &'static str,
    pub shared: &'static str,
}

pub const X25519_CASES: [X25519; 4] = [
    X25519 {
        id: 1,
        private: "c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475",
        public: "504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829",
        shared: "436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320",
    },
    X25519 {
        id: 100,
        private: "a046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a44",
        public: "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        shared: "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    },
    X25519 {
        id: 32,
        private: "88227494038f2bb811d47805bcdf04a2ac585ada7f2f23389bfd4658f9ddd45e",
        public: "0000000000000000000000000000000000000000000000000000000000000000",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
    },
    X25519 {
        id: 64,
        private: "387355d995616090503aafad49da01fb3dc3eda962704eaee6b86f9e20c92579",
        public: "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        shared: "0000000000000000000000000000000000000000000000000000000000000000",
    },
];

pub const KEY: &str = "9de836aa579585081f330a7c4036e20e38ef15eff3945184d231867f505fffdf";
pub const AAD: [u8; 64] = [0xff; 64];
pub const CT: [u8; 127] = [0xff; 127];

pub struct Aead {
    pub id: u16,
    pub iv: &'static str,
    pub msg: &'static str,
    pub tag: &'static str,
}

pub const CHACHAPOLY_CASES: [Aead; 2] = [
    Aead {
        id: 216,
        iv: "00000000101112130bc672c3",
        msg: "3619cb470af86dceceb6940f2d9abb34c9a9131476053387445ffebbe240d4f9818377855652f46a8219c7f71c3554f8acef8258de4b7d17c0f3d353ac981cc6a13287be1e6b41dc6d133df4ababebdf43d665ce7a4a5c982a0b139cb8202eebc74173e3224a440e4c37d2b595f384290e939ba016df0d49b36cdb4bd91c39",
        tag: "133fe62391744d11ce44594b96c53baf",
    },
    Aead {
        id: 217,
        iv: "000000001011121303e9b9a4",
        msg: "af205bda819f7451be0f28667d4b01b59ff2daa8173cab52046c3c9e0d989889c5e021ef7afd06e9ce6cc30e3a6ebab509134ba10d10e570c55587c13eee53e73be54804c8539ffbf23b35922b1ca37b9e9bc24ee204837ca5a294ce05d12600c7eff6aee32270db2feff47dc5a04176169e15850628e6035f78994f9f5603",
        tag: "e3451adb9d23a7710a1aafba26f56387",
    },
];
