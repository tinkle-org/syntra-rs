#![no_main]

use libfuzzer_sys::fuzz_target;
use syntra_core::proto::{
    RecoveryBatchTrailer, RecoveryNotification, RecoveryReplayPage, RecoverySubscribeRequest,
};
use syntra_runtime::recovery::wire::codec::{decode, encode, ProfileMessage};

fn roundtrip<M: ProfileMessage + PartialEq>(data: &[u8]) {
    if let Ok(message) = decode::<M>(data) {
        let canonical = encode(&message).unwrap();
        assert!(decode::<M>(&canonical).unwrap() == message);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() <= 4096 {
        roundtrip::<RecoverySubscribeRequest>(data);
        roundtrip::<RecoveryBatchTrailer>(data);
        roundtrip::<RecoveryNotification>(data);
        roundtrip::<RecoveryReplayPage>(data);
    }
});
