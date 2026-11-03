//! Syntra 1.0's integral encryption layer: a networking-independent Noise kernel.
//!
//! This module separates cryptographic state from scheduling and I/O.
//! Native and browser drivers compose this kernel with the message runtime as
//! integral layers of the same Syntra protocol.
//! Experimental and unpublished; no independent interoperability verdict is claimed here.
#![deny(unsafe_code)]

use std::fmt;
use zeroize::{Zeroize, Zeroizing};

mod clock;
mod resolver;

pub use clock::{Clock, ElapsedSource};

/// Browser clocks are observations, not a trusted suspend-inclusive hardware
/// source. Use both elapsed and wall observations and retire on disagreement,
/// regression or unavailable time. No runtime dependency (and therefore no
/// channel/runtime dependency cycle) is introduced. Browser owners additionally
/// close on lifecycle loss BEFORE allowing buffered work into the runtime.
#[cfg(any(test, target_arch = "wasm32"))]
mod browser_elapsed {
    #[cfg(target_arch = "wasm32")]
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Clone, Copy)]
    pub(super) struct Sample {
        pub monotonic_ms: f64,
        pub wall_ms: f64,
    }

    pub(super) struct Observations {
        origin: Sample,
        previous: Sample,
        age: f64,
        failed: bool,
    }

    impl Observations {
        pub fn new(origin: Sample) -> Self {
            Self {
                origin,
                previous: origin,
                age: 0.0,
                failed: !origin.monotonic_ms.is_finite() || !origin.wall_ms.is_finite(),
            }
        }

        pub fn observe(&mut self, sample: Sample) -> Duration {
            let monotonic = sample.monotonic_ms - self.origin.monotonic_ms;
            let wall = sample.wall_ms - self.origin.wall_ms;
            if !sample.monotonic_ms.is_finite() || !sample.wall_ms.is_finite()
                || sample.monotonic_ms < self.previous.monotonic_ms
                || sample.wall_ms < self.previous.wall_ms
                // A stopped Performance clock across suspend, an adjustable wall
                // clock jump, or accumulating disagreement is unknown continuity.
                // Retire rather than inventing a resumed budget. 2s is tolerance
                // for clock precision/skew, not permission to extend a lifetime.
                || (monotonic - wall).abs() > 2_000.0
            {
                self.failed = true;
            }
            self.previous = sample;
            self.age = self.age.max(monotonic).max(wall);
            if self.failed || self.age >= super::MAX_AGE.as_secs_f64() * 1000.0 {
                return super::MAX_AGE;
            }
            Duration::from_secs_f64(self.age / 1000.0)
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub(super) struct Clock {
        origin: web_time::Instant,
        observations: Mutex<Observations>,
    }

    #[cfg(target_arch = "wasm32")]
    impl Clock {
        pub fn new() -> Self {
            Self {
                origin: web_time::Instant::now(),
                observations: Mutex::new(Observations::new(Sample {
                    monotonic_ms: 0.0,
                    wall_ms: js_sys::Date::now(),
                })),
            }
        }
        pub fn age(&self) -> Duration {
            // A short synchronous lock keeps Channel's Send/Sync properties;
            // no JS callback, runtime work or await is performed while held.
            let sample = Sample {
                monotonic_ms: self.origin.elapsed().as_secs_f64() * 1000.0,
                wall_ms: js_sys::Date::now(),
            };
            self.observations
                .lock()
                .map_or(super::MAX_AGE, |mut time| time.observe(sample))
        }

        #[cfg(test)]
        pub fn invalidate_for_test(&self) {
            self.observations.lock().unwrap().observe(Sample {
                monotonic_ms: f64::NAN,
                wall_ms: f64::NAN,
            });
        }
    }
}

/// Canonical protocol identity, without a terminator or negotiation aliases.
pub const PROTOCOL: &str = "syntra.1.0";
/// Exact authenticated domain bytes at the start of every public context.
pub const DOMAIN: &[u8] = PROTOCOL.as_bytes();

const AEAD_TAG_BYTES: usize = 16;
const NOISE_MESSAGE_BYTES: usize = 32 + AEAD_TAG_BYTES;
const MIN_SCOPE_BYTES: usize = 1;
const MAX_SCOPE_BYTES: usize = u8::MAX as usize;
const MODE_OFFSET: usize = DOMAIN.len();
const CARRIER_OFFSET: usize = MODE_OFFSET + size_of::<u8>();
const SERVER_KEY_ID_OFFSET: usize = CARRIER_OFFSET + size_of::<u8>();
const EPOCH_OFFSET: usize = SERVER_KEY_ID_OFFSET + size_of::<u32>();
const HANDLE_OFFSET: usize = EPOCH_OFFSET + size_of::<u64>();
const SCOPE_LEN_OFFSET: usize = HANDLE_OFFSET + size_of::<[u8; 8]>();
const SCOPE_OFFSET: usize = SCOPE_LEN_OFFSET + size_of::<u16>();
const MIN_WRAPPER: usize = SCOPE_OFFSET + MIN_SCOPE_BYTES + NOISE_MESSAGE_BYTES;

pub const MAX_CIPHERTEXT: usize = 65_535;
pub const MAX_PLAINTEXT: usize = MAX_CIPHERTEXT - AEAD_TAG_BYTES;
pub const MAX_FRAME: usize = 1_048_576;
pub const MAX_WRAPPER: usize = SCOPE_OFFSET + MAX_SCOPE_BYTES + NOISE_MESSAGE_BYTES;
pub const MAX_RECORDS: u64 = 1 << 32;
pub const MAX_AGE: std::time::Duration = std::time::Duration::from_secs(86_400);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Syntra context or message rejected")]
    Invalid,
    #[error("Syntra authentication failed")]
    Authentication,
    #[error("Syntra entropy unavailable")]
    Entropy,
    #[error("Syntra resource limit reached")]
    Limit,
    #[error("Syntra connection is closed")]
    Closed,
}

fn noise_error(e: snow::Error) -> Error {
    if matches!(e, snow::Error::Rng) {
        Error::Entropy
    } else {
        Error::Authentication
    }
}

/// Secret input, redacted in diagnostics and erased on drop. Deliberately not Clone.
pub struct Secret32(Zeroizing<[u8; 32]>);

impl Secret32 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| Error::Entropy)?;
        Ok(Self(bytes))
    }
    /// Export for a caller-owned protected enrollment store.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret32([REDACTED])")
    }
}

/// A newly generated AK and independently sampled lookup handle. The store owns
/// collision checking, epoch allocation, scope, expiry and revocation.
pub struct Enrollment {
    pub key: Secret32,
    pub handle: [u8; 8],
    pub epoch: u64,
}

impl Enrollment {
    pub fn generate(epoch: u64) -> Result<Self, Error> {
        let key = Secret32::generate()?;
        let mut handle = [0; 8];
        getrandom::fill(&mut handle).map_err(|_| Error::Entropy)?;
        Ok(Self { key, handle, epoch })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Bootstrap,
    Returning,
}
impl Mode {
    fn code(self) -> u8 {
        match self {
            Self::Bootstrap => 1,
            Self::Returning => 2,
        }
    }
    fn pattern(self) -> &'static str {
        match self {
            Self::Bootstrap => "Noise_NK_25519_ChaChaPoly_SHA256",
            Self::Returning => "Noise_NKpsk0_25519_ChaChaPoly_SHA256",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    Tcp,
    /// Plain WebSocket (WS), context carrier code 2.
    WebSocket,
    /// Secure WebSocket (WSS), context carrier code 3.
    SecureWebSocket,
}
impl Carrier {
    fn code(self) -> u8 {
        match self {
            Self::Tcp => 1,
            Self::WebSocket => 2,
            Self::SecureWebSocket => 3,
        }
    }
}

/// Public routing context. A parsed context and handle lookup are never proof.
/// Scope is valid UTF-8 of 1..=255 bytes, preserved without normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub mode: Mode,
    pub carrier: Carrier,
    pub server_key_id: u32,
    pub scope: Vec<u8>,
    pub handle: [u8; 8],
    pub epoch: u64,
}

impl Context {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.scope.is_empty()
            || self.scope.len() > MAX_SCOPE_BYTES
            || std::str::from_utf8(&self.scope).is_err()
            || (self.mode == Mode::Bootstrap && (self.handle != [0; 8] || self.epoch != 0))
            || (self.mode == Mode::Returning && (self.handle == [0; 8] || self.epoch == 0))
        {
            return Err(Error::Invalid);
        }
        let mut out = Vec::with_capacity(SCOPE_OFFSET + self.scope.len());
        out.extend_from_slice(DOMAIN);
        out.push(self.mode.code());
        out.push(self.carrier.code());
        out.extend_from_slice(&self.server_key_id.to_be_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.handle);
        out.extend_from_slice(&(self.scope.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.scope);
        Ok(out)
    }

    /// Parse exactly one first-flight wrapper, including its 48-byte Noise message.
    pub fn parse_first(input: &[u8]) -> Result<(Self, &[u8]), Error> {
        if !(MIN_WRAPPER..=MAX_WRAPPER).contains(&input.len()) || &input[..DOMAIN.len()] != DOMAIN {
            return Err(Error::Invalid);
        }
        let mode = match input[MODE_OFFSET] {
            1 => Mode::Bootstrap,
            2 => Mode::Returning,
            _ => return Err(Error::Invalid),
        };
        let carrier = match input[CARRIER_OFFSET] {
            1 => Carrier::Tcp,
            2 => Carrier::WebSocket,
            3 => Carrier::SecureWebSocket,
            _ => return Err(Error::Invalid),
        };
        let n =
            u16::from_be_bytes(input[SCOPE_LEN_OFFSET..SCOPE_OFFSET].try_into().unwrap()) as usize;
        if !(MIN_SCOPE_BYTES..=MAX_SCOPE_BYTES).contains(&n)
            || input.len() != SCOPE_OFFSET + n + NOISE_MESSAGE_BYTES
        {
            return Err(Error::Invalid);
        }
        let context = Self {
            mode,
            carrier,
            server_key_id: u32::from_be_bytes(
                input[SERVER_KEY_ID_OFFSET..EPOCH_OFFSET]
                    .try_into()
                    .unwrap(),
            ),
            epoch: u64::from_be_bytes(input[EPOCH_OFFSET..HANDLE_OFFSET].try_into().unwrap()),
            handle: input[HANDLE_OFFSET..SCOPE_LEN_OFFSET].try_into().unwrap(),
            scope: input[SCOPE_OFFSET..SCOPE_OFFSET + n].to_vec(),
        };
        context.encode()?;
        Ok((context, &input[SCOPE_OFFSET + n..]))
    }

    fn prologue(&self) -> Result<Vec<u8>, Error> {
        self.encode()
    }
}

/// Caller-owned lookup policy. Must validate epoch, expiry, revocation and scope,
/// and only return a nonzero 32-byte AK (an all-zero AK is rejected as unauthenticated).
/// Called before proof of possession; must not grant a principal or cause effects.
pub trait KeyStore: Send + Sync {
    fn lookup(&self, context: &Context) -> Result<Secret32, Error>;
}

pub struct ClientConfig {
    pub context: Context,
    pub server_public_key: [u8; 32],
    pub authorization_key: Option<Secret32>,
}

pub struct ServerConfig {
    pub mode: Mode,
    pub carrier: Carrier,
    pub server_key_id: u32,
    pub scope: Vec<u8>,
    pub private_key: Secret32,
    pub store: Option<std::sync::Arc<dyn KeyStore>>,
}

/// Consuming handshake API: an error cannot leave reusable handshake state.
pub struct ClientHandshake {
    state: snow::HandshakeState,
    context: Context,
    established: Clock,
}

impl ClientHandshake {
    pub fn start(config: ClientConfig) -> Result<(Self, Vec<u8>), Error> {
        Self::start_with_clock(config, Clock::new())
    }

    /// Retains the supplied establishment origin through Split and all records.
    pub fn start_with_clock(config: ClientConfig, clock: Clock) -> Result<(Self, Vec<u8>), Error> {
        Self::start_with_resolver(config, Box::<resolver::Resolver>::default(), clock)
    }

    fn start_with_resolver(
        config: ClientConfig,
        resolver: snow::resolvers::BoxedCryptoResolver,
        established: Clock,
    ) -> Result<(Self, Vec<u8>), Error> {
        established.check()?;
        // Returning mode requires a nonzero 32-byte AK; reject a zero AK before
        // building any snow Builder or consuming RNG so no handshake state exists.
        if config.context.mode == Mode::Returning
            && matches!(config.authorization_key.as_ref(), Some(key) if key.expose().iter().fold(0u8, |acc, byte| acc | byte) == 0)
        {
            return Err(Error::Invalid);
        }
        let prologue = config.context.prologue()?;
        let mut builder = snow::Builder::with_resolver(
            config.context.mode.pattern().parse().map_err(noise_error)?,
            resolver,
        )
        .prologue(&prologue)
        .map_err(noise_error)?
        .remote_public_key(&config.server_public_key)
        .map_err(noise_error)?;
        match (config.context.mode, config.authorization_key.as_ref()) {
            (Mode::Returning, Some(key)) => {
                builder = builder.psk(0, key.expose()).map_err(noise_error)?
            }
            (Mode::Bootstrap, None) => {}
            _ => return Err(Error::Invalid),
        }
        let mut state = builder.build_initiator().map_err(noise_error)?;
        let mut msg = [0; NOISE_MESSAGE_BYTES];
        let n = state.write_message(&[], &mut msg).map_err(noise_error)?;
        if n != NOISE_MESSAGE_BYTES {
            return Err(Error::Invalid);
        }
        let mut first = config.context.encode()?;
        first.extend_from_slice(&msg);
        established.check()?;
        Ok((
            Self {
                state,
                context: config.context,
                established,
            },
            first,
        ))
    }

    pub fn finish(mut self, second: &[u8]) -> Result<Channel, Error> {
        self.established.check()?;
        if second.len() != NOISE_MESSAGE_BYTES {
            return Err(Error::Invalid);
        }
        let mut payload = Zeroizing::new([0; NOISE_MESSAGE_BYTES]);
        if self
            .state
            .read_message(second, payload.as_mut())
            .map_err(noise_error)?
            != 0
        {
            return Err(Error::Invalid);
        }
        Channel::from_handshake(self.state, self.context, false, self.established)
    }
}

/// Produces M2 and unconfirmed responder state. No identity is issued at M1/M2.
pub fn respond(config: &ServerConfig, first: &[u8]) -> Result<(Channel, Vec<u8>), Error> {
    respond_with_clock(config, first, Clock::new())
}

/// Respond with an origin captured before carrier establishment or M1 receive.
pub fn respond_with_clock(
    config: &ServerConfig,
    first: &[u8],
    established: Clock,
) -> Result<(Channel, Vec<u8>), Error> {
    established.check()?;
    let (context, msg) = Context::parse_first(first)?;
    if context.mode != config.mode
        || context.carrier != config.carrier
        || context.server_key_id != config.server_key_id
        || context.scope != config.scope
    {
        return Err(Error::Authentication);
    }
    let key = match context.mode {
        Mode::Bootstrap => None,
        Mode::Returning => Some(
            config
                .store
                .as_ref()
                .ok_or(Error::Authentication)?
                .lookup(&context)?,
        ),
    };
    // A zero AK from the store is never usable as a PSK; reject with generic
    // authentication failure before prologue/Noise construction, without logging
    // or otherwise exposing key material.
    if let Some(key) = key.as_ref() {
        if key.expose().iter().fold(0u8, |acc, byte| acc | byte) == 0 {
            return Err(Error::Authentication);
        }
    }
    established.check()?;
    let prologue = context.prologue()?;
    let mut builder = snow::Builder::with_resolver(
        context.mode.pattern().parse().map_err(noise_error)?,
        Box::<resolver::Resolver>::default(),
    )
    .prologue(&prologue)
    .map_err(noise_error)?
    .local_private_key(config.private_key.expose())
    .map_err(noise_error)?;
    if let Some(key) = key.as_ref() {
        builder = builder.psk(0, key.expose()).map_err(noise_error)?;
    }
    let mut state = builder.build_responder().map_err(noise_error)?;
    let mut payload = Zeroizing::new([0; NOISE_MESSAGE_BYTES]);
    if state
        .read_message(msg, payload.as_mut())
        .map_err(noise_error)?
        != 0
    {
        return Err(Error::Invalid);
    }
    let mut second = vec![0; NOISE_MESSAGE_BYTES];
    if state.write_message(&[], &mut second).map_err(noise_error)? != NOISE_MESSAGE_BYTES {
        return Err(Error::Invalid);
    }
    Ok((
        Channel::from_handshake(state, context, true, established)?,
        second,
    ))
}

pub fn generate_server_key() -> Result<(Secret32, [u8; 32]), Error> {
    let mut pair = snow::Builder::with_resolver(
        Mode::Bootstrap.pattern().parse().map_err(noise_error)?,
        Box::<resolver::Resolver>::default(),
    )
    .generate_keypair()
    .map_err(noise_error)?;
    let key = Secret32::new(
        pair.private
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid)?,
    );
    pair.private.zeroize();
    Ok((
        key,
        pair.public
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid)?,
    ))
}

/// Only a successfully decrypted client transport record can construct this.
/// Bootstrap confirms fresh channel participation, not enrollment authority.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    context: Context,
    handshake_hash: [u8; 32],
}
impl VerifiedIdentity {
    pub fn context(&self) -> &Context {
        &self.context
    }
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }
}

/// Ordered transport state. Never cloned; all record errors permanently poison it.
pub struct Channel {
    state: Option<snow::TransportState>,
    context: Context,
    hash: [u8; 32],
    responder: bool,
    confirmed: bool,
    sent: u64,
    received: u64,
    established: Clock,
}

impl Channel {
    fn from_handshake(
        mut state: snow::HandshakeState,
        context: Context,
        responder: bool,
        established: Clock,
    ) -> Result<Self, Error> {
        established.check()?;
        let hash = state
            .get_handshake_hash()
            .try_into()
            .map_err(|_| Error::Invalid)?;
        if context.mode == Mode::Returning {
            state.set_psk(0, &[0; 32]).map_err(noise_error)?;
        }
        let state = state.into_transport_mode().map_err(noise_error)?;
        established.check()?;
        Ok(Self {
            state: Some(state),
            context,
            hash,
            responder,
            confirmed: false,
            sent: 0,
            received: 0,
            established,
        })
    }
    pub fn age(&self) -> std::time::Duration {
        self.established.age()
    }
    pub fn close(&mut self) {
        self.state = None;
    }
    pub fn verified_identity(&self) -> Option<VerifiedIdentity> {
        (self.state.is_some() && self.responder && self.confirmed && self.check_limits().is_ok())
            .then(|| VerifiedIdentity {
                context: self.context.clone(),
                handshake_hash: self.hash,
            })
    }
    fn check_limits(&self) -> Result<(), Error> {
        if self.sent >= MAX_RECORDS || self.received >= MAX_RECORDS {
            return Err(Error::Limit);
        }
        self.established.check()
    }
    /// Commits the next send nonce. Retain and emit the returned ciphertext in
    /// order, or call `close` if output fails or is cancelled. Never retry by
    /// encrypting a replacement. Native adapters enforce this ownership rule.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut state = self.state.take().ok_or(Error::Closed)?;
        self.check_limits()?;
        if self.responder && !self.confirmed {
            return Err(Error::Authentication);
        }
        if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT {
            return Err(Error::Limit);
        }
        let mut out = vec![0; plaintext.len() + AEAD_TAG_BYTES];
        let n = state
            .write_message(plaintext, &mut out)
            .map_err(noise_error)?;
        out.truncate(n);
        self.sent += 1;
        self.state = Some(state);
        Ok(out)
    }
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut state = self.state.take().ok_or(Error::Closed)?;
        self.check_limits()?;
        if !(AEAD_TAG_BYTES + 1..=MAX_CIPHERTEXT).contains(&ciphertext.len()) {
            return Err(Error::Limit);
        }
        let mut out = Zeroizing::new(vec![0; ciphertext.len() - AEAD_TAG_BYTES]);
        let n = state
            .read_message(ciphertext, &mut out)
            .map_err(noise_error)?;
        out.truncate(n);
        self.received += 1;
        self.confirmed = true;
        self.state = Some(state);
        Ok(out)
    }
}

/// Incremental authenticated inner stream parser, with at most one incomplete frame.
#[derive(Default)]
pub struct FrameDecoder {
    prefix: Vec<u8>,
    body: Zeroizing<Vec<u8>>,
    expected: Option<usize>,
    failed: bool,
}
impl FrameDecoder {
    pub fn is_partial(&self) -> bool {
        !self.prefix.is_empty() || self.expected.is_some()
    }
    pub fn push(&mut self, mut bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        if self.failed {
            return Err(Error::Closed);
        }
        if bytes.len() > MAX_PLAINTEXT {
            self.failed = true;
            self.body.zeroize();
            return Err(Error::Limit);
        }
        let mut frames = Vec::new();
        while !bytes.is_empty() {
            if self.expected.is_none() {
                let n = (4 - self.prefix.len()).min(bytes.len());
                self.prefix.extend_from_slice(&bytes[..n]);
                bytes = &bytes[n..];
                if self.prefix.len() != 4 {
                    break;
                }
                let n = u32::from_be_bytes(self.prefix.as_slice().try_into().unwrap()) as usize;
                if !(1..=MAX_FRAME).contains(&n) {
                    self.failed = true;
                    self.body.zeroize();
                    return Err(Error::Limit);
                }
                self.body.reserve_exact(n);
                self.prefix.clear();
                self.expected = Some(n);
            }
            let expected = self.expected.unwrap();
            let n = (expected - self.body.len()).min(bytes.len());
            self.body.extend_from_slice(&bytes[..n]);
            bytes = &bytes[n..];
            if self.body.len() == expected {
                frames.push(std::mem::take(&mut *self.body));
                self.expected = None;
            }
        }
        Ok(frames)
    }
}

pub fn frame_plaintext(frame: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !(1..=MAX_FRAME).contains(&frame.len()) {
        return Err(Error::Limit);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(frame.len() + 4));
    out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    out.extend_from_slice(frame);
    Ok(out)
}

#[cfg(test)]
mod context_tests;

#[cfg(test)]
mod lifetime_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn frame_decoder_reserves_body_after_complete_validated_prefix() {
        for size in [1, MAX_PLAINTEXT, MAX_FRAME] {
            let prefix = (size as u32).to_be_bytes();
            for split in 0..4 {
                let mut decoder = FrameDecoder::default();
                assert!(decoder.push(&prefix[..split]).unwrap().is_empty());
                assert_eq!(decoder.body.capacity(), 0);
                assert_eq!(decoder.expected, None);

                assert!(decoder.push(&prefix[split..]).unwrap().is_empty());
                assert!(decoder.body.capacity() >= size);
                assert!(decoder.body.is_empty());
                assert_eq!(decoder.expected, Some(size));
            }
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn frame_decoder_rejects_invalid_length_before_body_allocation() {
        for size in [0, (MAX_FRAME + 1) as u32, u32::MAX] {
            let mut decoder = FrameDecoder::default();
            assert!(matches!(
                decoder.push(&size.to_be_bytes()),
                Err(Error::Limit)
            ));
            assert_eq!(decoder.body.capacity(), 0);
            assert_eq!(decoder.expected, None);
            assert!(matches!(decoder.push(&[1]), Err(Error::Closed)));
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn browser_elapsed_discontinuity_is_sticky_and_never_extends_age() {
        use browser_elapsed::{Observations, Sample};
        let initial = Sample {
            monotonic_ms: 0.0,
            wall_ms: 1_000_000.0,
        };
        let mut clock = Observations::new(initial);
        assert_eq!(
            clock.observe(Sample {
                monotonic_ms: 10.0,
                wall_ms: 1_000_015.0
            }),
            std::time::Duration::from_millis(15)
        );
        // Wall regression is terminal even when a later sample looks normal.
        assert_eq!(clock.observe(initial), MAX_AGE);
        assert_eq!(
            clock.observe(Sample {
                monotonic_ms: 20.0,
                wall_ms: 1_000_020.0
            }),
            MAX_AGE
        );
        for sample in [
            Sample {
                monotonic_ms: 10.0,
                wall_ms: 1_003_000.0,
            },
            Sample {
                monotonic_ms: f64::NAN,
                wall_ms: 1_000_000.0,
            },
            Sample {
                monotonic_ms: 1.0,
                wall_ms: f64::INFINITY,
            },
            Sample {
                monotonic_ms: 86_400_000.0,
                wall_ms: 87_400_000.0,
            },
        ] {
            assert_eq!(Observations::new(initial).observe(sample), MAX_AGE);
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn both_suites_kernel_records_and_framing() {
        struct Store;
        impl KeyStore for Store {
            fn lookup(&self, _: &Context) -> Result<Secret32, Error> {
                Ok(Secret32::new([9; 32]))
            }
        }
        for mode in [Mode::Bootstrap, Mode::Returning] {
            let (private_key, server_public_key) = generate_server_key().unwrap();
            let context = Context {
                mode,
                carrier: Carrier::SecureWebSocket,
                server_key_id: 1,
                scope: b"kernel-test".to_vec(),
                handle: if mode == Mode::Returning {
                    [7; 8]
                } else {
                    [0; 8]
                },
                epoch: u64::from(mode == Mode::Returning),
            };
            let (client, first) = ClientHandshake::start(ClientConfig {
                context: context.clone(),
                server_public_key,
                authorization_key: (mode == Mode::Returning).then(|| Secret32::new([9; 32])),
            })
            .unwrap();
            let (mut server, second) = respond(
                &ServerConfig {
                    mode,
                    carrier: context.carrier,
                    server_key_id: 1,
                    scope: context.scope,
                    private_key,
                    store: Some(std::sync::Arc::new(Store)),
                },
                &first,
            )
            .unwrap();
            assert!(server.verified_identity().is_none());
            let mut client = client.finish(&second).unwrap();
            assert!(client.age() < MAX_AGE);
            let mut decoder = FrameDecoder::default();
            let mut received = Vec::new();
            let frame = frame_plaintext(b"kernel framed payload").unwrap();
            for chunk in frame.chunks(2) {
                received.extend(
                    decoder
                        .push(&server.decrypt(&client.encrypt(chunk).unwrap()).unwrap())
                        .unwrap(),
                );
            }
            assert_eq!(received, [b"kernel framed payload".to_vec()]);
            assert!(server.verified_identity().is_some());
            let mut reply = server.encrypt(b"protected reply").unwrap();
            assert_eq!(&*client.decrypt(&reply).unwrap(), b"protected reply");
            reply[0] ^= 1;
            assert!(client.decrypt(&reply).is_err());
            assert!(matches!(
                client.encrypt(b"after failure"),
                Err(Error::Closed)
            ));
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn snow_entropy_error_is_returned_without_first_flight() {
        let config = ClientConfig {
            context: Context {
                mode: Mode::Bootstrap,
                carrier: Carrier::Tcp,
                server_key_id: 1,
                scope: b"test".to_vec(),
                handle: [0; 8],
                epoch: 0,
            },
            server_public_key: [5; 32],
            authorization_key: None,
        };
        assert!(matches!(
            ClientHandshake::start_with_resolver(
                config,
                Box::new(resolver::Resolver { fail_rng: true }),
                Clock::new(),
            ),
            Err(Error::Entropy)
        ));
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn returning_zero_ak_client_rejects_before_noise_rng() {
        let context = Context {
            mode: Mode::Returning,
            carrier: Carrier::Tcp,
            server_key_id: 1,
            scope: b"test".to_vec(),
            handle: [7; 8],
            epoch: 1,
        };
        let err = match ClientHandshake::start(ClientConfig {
            context: context.clone(),
            server_public_key: [5; 32],
            authorization_key: Some(Secret32::new([0; 32])),
        }) {
            Err(err) => err,
            Ok(_) => panic!("zero AK must reject"),
        };
        assert!(matches!(err, Error::Invalid));
        assert_eq!(format!("{err}"), "Syntra context or message rejected");
        // A failing RNG must not change the outcome: rejection happens before
        // any snow Builder is built or entropy is consumed.
        let err = match ClientHandshake::start_with_resolver(
            ClientConfig {
                context,
                server_public_key: [5; 32],
                authorization_key: Some(Secret32::new([0; 32])),
            },
            Box::new(resolver::Resolver { fail_rng: true }),
            Clock::new(),
        ) {
            Err(err) => err,
            Ok(_) => panic!("zero AK must reject before RNG"),
        };
        assert!(matches!(err, Error::Invalid));
        assert_eq!(format!("{err}"), "Syntra context or message rejected");
    }

    struct ZeroAkStore;
    impl KeyStore for ZeroAkStore {
        fn lookup(&self, _: &Context) -> Result<Secret32, Error> {
            Ok(Secret32::new([0; 32]))
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn returning_zero_ak_store_rejects_before_noise() {
        let (private_key, server_public_key) = generate_server_key().unwrap();
        let context = Context {
            mode: Mode::Returning,
            carrier: Carrier::Tcp,
            server_key_id: 1,
            scope: b"test".to_vec(),
            handle: [7; 8],
            epoch: 1,
        };
        let (_, first) = ClientHandshake::start(ClientConfig {
            context: context.clone(),
            server_public_key,
            authorization_key: Some(Secret32::new([1; 32])),
        })
        .unwrap();
        let err = match respond(
            &ServerConfig {
                mode: context.mode,
                carrier: context.carrier,
                server_key_id: 1,
                scope: context.scope,
                private_key,
                store: Some(std::sync::Arc::new(ZeroAkStore)),
            },
            &first,
        ) {
            Err(err) => err,
            Ok(_) => panic!("zero AK from store must reject"),
        };
        assert!(matches!(err, Error::Authentication));
        assert_eq!(format!("{err}"), "Syntra authentication failed");
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn record_budget_is_terminal_in_each_direction() {
        let (private_key, server_public_key) = generate_server_key().unwrap();
        let context = Context {
            mode: Mode::Bootstrap,
            carrier: Carrier::Tcp,
            server_key_id: 1,
            scope: b"test".to_vec(),
            handle: [0; 8],
            epoch: 0,
        };
        let (client, first) = ClientHandshake::start(ClientConfig {
            context: context.clone(),
            server_public_key,
            authorization_key: None,
        })
        .unwrap();
        let (mut server, second) = respond(
            &ServerConfig {
                mode: context.mode,
                carrier: context.carrier,
                server_key_id: 1,
                scope: context.scope,
                private_key,
                store: None,
            },
            &first,
        )
        .unwrap();
        let mut client = client.finish(&second).unwrap();
        let record = client.encrypt(b"hello").unwrap();
        client.sent = MAX_RECORDS;
        assert!(matches!(client.encrypt(b"limit"), Err(Error::Limit)));
        assert!(matches!(client.encrypt(b"closed"), Err(Error::Closed)));
        server.received = MAX_RECORDS;
        assert!(matches!(server.decrypt(&record), Err(Error::Limit)));
        assert!(server.verified_identity().is_none());
        assert!(matches!(server.decrypt(&record), Err(Error::Closed)));
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn browser_clock_failure_poisons_both_directions() {
        let (private_key, server_public_key) = generate_server_key().unwrap();
        let context = Context {
            mode: Mode::Bootstrap,
            carrier: Carrier::SecureWebSocket,
            server_key_id: 1,
            scope: b"clock-test".to_vec(),
            handle: [0; 8],
            epoch: 0,
        };
        let (handshake, first) = ClientHandshake::start(ClientConfig {
            context: context.clone(),
            server_public_key,
            authorization_key: None,
        })
        .unwrap();
        let (mut server, second) = respond(
            &ServerConfig {
                mode: context.mode,
                carrier: context.carrier,
                server_key_id: 1,
                scope: context.scope,
                private_key,
                store: None,
            },
            &first,
        )
        .unwrap();
        let mut client = handshake.finish(&second).unwrap();
        let record = client.encrypt(b"before discontinuity").unwrap();
        let source = std::sync::Arc::new(browser_elapsed::Clock::new());
        client.established = Clock::with_source(source.clone());
        server.established = Clock::with_source(source.clone());
        source.invalidate_for_test();
        assert!(matches!(
            client.encrypt(b"after discontinuity"),
            Err(Error::Limit)
        ));
        assert!(matches!(server.decrypt(&record), Err(Error::Limit)));
        assert!(matches!(client.encrypt(b"no revival"), Err(Error::Closed)));
        assert!(matches!(server.decrypt(&record), Err(Error::Closed)));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn unknown_continuity_is_terminal_without_adapter_timers() {
        let (private_key, server_public_key) = generate_server_key().unwrap();
        let context = Context {
            mode: Mode::Bootstrap,
            carrier: Carrier::Tcp,
            server_key_id: 1,
            scope: b"test".to_vec(),
            handle: [0; 8],
            epoch: 0,
        };
        let (client, first) = ClientHandshake::start(ClientConfig {
            context: context.clone(),
            server_public_key,
            authorization_key: None,
        })
        .unwrap();
        let (mut server, second) = respond(
            &ServerConfig {
                mode: context.mode,
                carrier: context.carrier,
                server_key_id: 1,
                scope: context.scope,
                private_key,
                store: None,
            },
            &first,
        )
        .unwrap();
        let mut client = client.finish(&second).unwrap();
        let record = client.encrypt(b"hello").unwrap();
        server.established.invalidate();
        client.established.invalidate();
        assert!(matches!(server.decrypt(&record), Err(Error::Limit)));
        assert!(matches!(client.encrypt(b"expired"), Err(Error::Limit)));
        assert!(matches!(client.encrypt(b"closed"), Err(Error::Closed)));
    }
}
