//! SDK-local examples calculated from schemas/v1/frame.bop without the Rust codec.
//! A union length excludes its discriminator; a message length includes its terminator.
//! Non-palindromic correlation/timeout values, multibyte text and opaque bytes distinguish
//! byte order, byte length, and binary versus text fields. These aren't transport records.

pub const HELLO: &str =
    "010000000000000000000000160000000a12000000010100000002010000000302000000ff0000";
pub const READY: &str = "0100000000000000000000000c0000000b080000000102000000c3a900";
pub const CALL: &str =
    "0100000008070605040302011a0000000c1600000001040000002f612f420202000000ff00034433221100";
pub const SUCCESS: &str = "0100000008070605040302010b0000000d060000000102000000ff00";
pub const EMPTY_SUCCESS: &str = "010000000807060504030201090000000d040000000100000000";
pub const ERROR: &str =
    "010000000807060504030201160000000d11000000020d000000010d0000000202000000c3a900";
pub const CANCEL: &str = "010000000807060504030201050000000e0100000000";
pub const NOTIFICATION: &str = "0100000000000000000000000c0000000f080000000102000000ff0000";
