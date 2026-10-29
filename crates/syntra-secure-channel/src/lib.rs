//! Networking-independent experimental SC1 channel using the canonical context
//! proposal in RFC 0007 section 11. This is not an accepted production profile.
#![forbid(unsafe_code)]

use std::fmt;
use zeroize::{Zeroize, Zeroizing};

mod resolver;

pub const MAX_CIPHERTEXT: usize = 65_535;
pub const MAX_PLAINTEXT: usize = MAX_CIPHERTEXT - 16;
pub const MAX_FRAME: usize = 1_048_576;
pub const MAX_WRAPPER: usize = 340;
pub const MAX_RECORDS: u64 = 1 << 32;
pub const MAX_AGE: std::time::Duration = std::time::Duration::from_secs(86_400);
const DOMAIN: &[u8; 13] = b"syntra.sc1.v1";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("SC1 context or message rejected")]
    Invalid,
    #[error("SC1 authentication failed")]
    Authentication,
    #[error("SC1 entropy unavailable")]
    Entropy,
    #[error("SC1 resource limit reached")]
    Limit,
    #[error("SC1 channel is closed")]
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
            || self.scope.len() > 255
            || std::str::from_utf8(&self.scope).is_err()
            || (self.mode == Mode::Bootstrap && (self.handle != [0; 8] || self.epoch != 0))
            || (self.mode == Mode::Returning && (self.handle == [0; 8] || self.epoch == 0))
        {
            return Err(Error::Invalid);
        }
        let mut out = Vec::with_capacity(37 + self.scope.len());
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
        if input.len() < 86 || input.len() > MAX_WRAPPER || &input[..13] != DOMAIN {
            return Err(Error::Invalid);
        }
        let mode = match input[13] {
            1 => Mode::Bootstrap,
            2 => Mode::Returning,
            _ => return Err(Error::Invalid),
        };
        let carrier = match input[14] {
            1 => Carrier::Tcp,
            2 => Carrier::WebSocket,
            3 => Carrier::SecureWebSocket,
            _ => return Err(Error::Invalid),
        };
        let n = u16::from_be_bytes(input[35..37].try_into().unwrap()) as usize;
        if !(1..=255).contains(&n) || input.len() != 37 + n + 48 {
            return Err(Error::Invalid);
        }
        let context = Self {
            mode,
            carrier,
            server_key_id: u32::from_be_bytes(input[15..19].try_into().unwrap()),
            epoch: u64::from_be_bytes(input[19..27].try_into().unwrap()),
            handle: input[27..35].try_into().unwrap(),
            scope: input[37..37 + n].to_vec(),
        };
        context.encode()?;
        Ok((context, &input[37 + n..]))
    }

    fn prologue(&self) -> Result<Vec<u8>, Error> {
        self.encode()
    }
}

/// Caller-owned lookup policy. Must validate epoch, expiry, revocation and scope.
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
}

impl ClientHandshake {
    pub fn start(config: ClientConfig) -> Result<(Self, Vec<u8>), Error> {
        Self::start_with_resolver(config, Box::<resolver::Resolver>::default())
    }

    fn start_with_resolver(
        config: ClientConfig,
        resolver: snow::resolvers::BoxedCryptoResolver,
    ) -> Result<(Self, Vec<u8>), Error> {
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
        let mut msg = [0; 48];
        let n = state.write_message(&[], &mut msg).map_err(noise_error)?;
        if n != 48 {
            return Err(Error::Invalid);
        }
        let mut first = config.context.encode()?;
        first.extend_from_slice(&msg);
        Ok((
            Self {
                state,
                context: config.context,
            },
            first,
        ))
    }

    pub fn finish(mut self, second: &[u8]) -> Result<Channel, Error> {
        if second.len() != 48 {
            return Err(Error::Invalid);
        }
        let mut payload = Zeroizing::new([0; 48]);
        if self
            .state
            .read_message(second, payload.as_mut())
            .map_err(noise_error)?
            != 0
        {
            return Err(Error::Invalid);
        }
        Channel::from_handshake(self.state, self.context, false)
    }
}

/// Produces M2 and unconfirmed responder state. No identity is issued at M1/M2.
pub fn respond(config: &ServerConfig, first: &[u8]) -> Result<(Channel, Vec<u8>), Error> {
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
    let mut payload = Zeroizing::new([0; 48]);
    if state
        .read_message(msg, payload.as_mut())
        .map_err(noise_error)?
        != 0
    {
        return Err(Error::Invalid);
    }
    let mut second = vec![0; 48];
    if state.write_message(&[], &mut second).map_err(noise_error)? != 48 {
        return Err(Error::Invalid);
    }
    Ok((Channel::from_handshake(state, context, true)?, second))
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
    established: std::time::Instant,
}

impl Channel {
    fn from_handshake(
        mut state: snow::HandshakeState,
        context: Context,
        responder: bool,
    ) -> Result<Self, Error> {
        let hash = state
            .get_handshake_hash()
            .try_into()
            .map_err(|_| Error::Invalid)?;
        if context.mode == Mode::Returning {
            state.set_psk(0, &[0; 32]).map_err(noise_error)?;
        }
        Ok(Self {
            state: Some(state.into_transport_mode().map_err(noise_error)?),
            context,
            hash,
            responder,
            confirmed: false,
            sent: 0,
            received: 0,
            established: std::time::Instant::now(),
        })
    }
    pub fn age(&self) -> std::time::Duration {
        self.established.elapsed()
    }
    pub fn close(&mut self) {
        self.state = None;
    }
    pub fn verified_identity(&self) -> Option<VerifiedIdentity> {
        (self.state.is_some() && self.responder && self.confirmed).then(|| VerifiedIdentity {
            context: self.context.clone(),
            handshake_hash: self.hash,
        })
    }
    /// Commits the next send nonce. Retain and emit the returned ciphertext in
    /// order, or call `close` if output fails or is cancelled. Never retry by
    /// encrypting a replacement. Native adapters enforce this ownership rule.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut state = self.state.take().ok_or(Error::Closed)?;
        if self.age() >= MAX_AGE {
            return Err(Error::Limit);
        }
        if self.responder && !self.confirmed {
            return Err(Error::Authentication);
        }
        if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT || self.sent >= MAX_RECORDS {
            return Err(Error::Limit);
        }
        let mut out = vec![0; plaintext.len() + 16];
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
        if self.age() >= MAX_AGE {
            return Err(Error::Limit);
        }
        if !(17..=MAX_CIPHERTEXT).contains(&ciphertext.len()) || self.received >= MAX_RECORDS {
            return Err(Error::Limit);
        }
        let mut out = Zeroizing::new(vec![0; ciphertext.len() - 16]);
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
mod tests {
    use super::*;

    #[test]
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
                Box::new(resolver::Resolver { fail_rng: true })
            ),
            Err(Error::Entropy)
        ));
    }

    #[test]
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

    #[test]
    fn age_ceiling_is_terminal_without_adapter_timers() {
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
        server.established = std::time::Instant::now() - MAX_AGE;
        client.established = std::time::Instant::now() - MAX_AGE;
        assert!(matches!(server.decrypt(&record), Err(Error::Limit)));
        assert!(matches!(client.encrypt(b"expired"), Err(Error::Limit)));
        assert!(matches!(client.encrypt(b"closed"), Err(Error::Closed)));
    }
}
