#![no_main]

use libfuzzer_sys::fuzz_target;
use syntra_core::secure_channel::{frame_plaintext, FrameDecoder};

fuzz_target!(|data: &[u8]| {
    if !(4..=4096).contains(&data.len()) {
        return;
    }
    let width = 1 + usize::from(data[0]);
    let payload = &data[2..];
    let (first, second) = payload.split_at(1 + usize::from(data[1]) % (payload.len() - 1));
    let mut stream = frame_plaintext(first).unwrap();
    stream.extend_from_slice(&frame_plaintext(second).unwrap());

    let mut decoder = FrameDecoder::default();
    let mut output = Vec::new();
    let mut consumed = 0;
    for fragment in stream.chunks(width) {
        output.extend(decoder.push(fragment).unwrap());
        consumed += fragment.len();
        assert_eq!(
            decoder.is_partial(),
            consumed != 4 + first.len() && consumed != stream.len()
        );
    }
    assert!(output == [first, second]);
});
