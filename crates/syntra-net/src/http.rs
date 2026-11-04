//! Opt-in, unaccepted RFC0013 HTTP/HTTPS protected-connection candidate.
//!
//! This is isolated implementation evidence, not upstream acceptance, public
//! carrier registration, formal conformance or independent interoperability.
//! High-level connections use the same Noise kernel/runtime/pump with candidate
//! carriers 4/5; they are never relabelled as TCP or WebSocket.
//!
//! [`codec`] is a bounded origin request/response codec (not a general HTTP or
//! CONNECT implementation). [`client_pair`] and [`server_pair`] expose raw
//! [`crate::RecordReader`]/[`crate::RecordWriter`] implementations. Drive the
//! returned server driver inline alongside its record consumer/producer; there
//! are no internally spawned tasks. A successful send acknowledges bounded
//! carrier-input admission only, never authentication, execution, or delivery.
//!
//! Streams must be two distinct, exclusively owned, persistent connections to
//! the same provisioned endpoint, explicit network route, owner and policy
//! generation. Generic I/O cannot establish those network properties or TLS
//! trust. There is deliberately no `verified: bool`, automatic retry or resumption.
//! Low-level raw adapter callers reserve
//! both streams and aggregate admission permits before constructing a pair and
//! retain them through driver completion. They provision a unique route selector
//! from an independently bounded CSPRNG/registry; deterministic selectors are
//! useful for tests only. A route is not a credential or durable identifier.
//!
//! The adapter retains at most one input slot and one selected output slot; a
//! driver-held input and a reader-held record also count toward embedding memory
//! accounting. Each body is at most 65,535 bytes, headers at most 16,384 bytes.
//! The server writer makes one bounded immutable copy for inline driver handoff.
//! Callers must separately enforce aggregate byte/item/rate/worker bounds,
//! current authorization, record/frame/lifetime budgets, and the original
//! allocation/emission contract before encryption. Aborting or dropping a polled
//! operation invalidates the pair, including operations on the other direction.
//! No I/O future may be retried after cancellation or an unknown outcome.
//! Supplied I/O polls must be nonblocking and must not reenter pair controls.

#[path = "http/codec.rs"]
pub mod codec;
mod connections;
#[path = "http/pair.rs"]
mod pair;
mod server;

pub use connections::{
    connect_streams_with_budget, connect_tls_pair_with_budget, connect_tls_streams_with_budget,
    connect_with_budget, verify_tls_streams_with_budget, VerifiedTlsPair,
};
pub use server::{
    bind, retired_servers, ServerConfig, ServerHandle, ServerLimits, ServerRun, ServerStatus,
    MAX_HOST_BUFFER_BYTES,
};

pub use pair::{
    client_pair, server_pair, ClientReader, ClientWriter, Control, ServerDriver, ServerReader,
    ServerWriter,
};

use crate::Error;
use std::fmt;

/// Opaque transient association selector. Debug output never includes its bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Route(String);

impl Route {
    pub fn parse(value: &str) -> Result<Self, Error> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(Error::Framing);
        }
        Ok(Self(value.to_owned()))
    }

    /// Explicit wire access, not a diagnostic/logging representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Route([redacted])")
    }
}

/// Canonical origin authority. This is syntax/routing configuration, not trust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authority(String);

impl Authority {
    /// Accept an already canonical lower-case DNS A-label or IP authority with
    /// explicit effective port. Reject URL syntax and normalization surprises.
    pub fn new(value: &str) -> Result<Self, Error> {
        if !value.is_ascii() || value.len() > 320 {
            return Err(Error::Configuration);
        }
        let (host, port) = value.rsplit_once(':').ok_or(Error::Configuration)?;
        let number = codec::decimal(port).map_err(|_| Error::Configuration)?;
        if number == 0 || number > u16::MAX as u64 {
            return Err(Error::Configuration);
        }
        if host.starts_with('[') && host.ends_with(']') {
            let ip: std::net::Ipv6Addr = host[1..host.len() - 1]
                .parse()
                .map_err(|_| Error::Configuration)?;
            if format!("[{ip}]") != host {
                return Err(Error::Configuration);
            }
        } else if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            if ip.to_string() != host {
                return Err(Error::Configuration);
            }
        } else if host.len() > 253
            || host.is_empty()
            || !host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
        {
            return Err(Error::Configuration);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Expected *public* M1 prefix supplied by a candidate experiment. No context
/// offsets, proposed carrier enum, or alternative context encoder lives here.
/// Matching this prefix/flight length does not validate context or Noise.
#[derive(Clone)]
pub struct OpenEnvelope(Vec<u8>);

impl OpenEnvelope {
    pub fn new(public_context: Vec<u8>) -> Result<Self, Error> {
        if !(35..=289).contains(&public_context.len()) {
            return Err(Error::Configuration);
        }
        Ok(Self(public_context))
    }

    pub fn m1_len(&self) -> usize {
        self.0.len() + 48
    }

    pub fn check_m1(&self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() != self.m1_len() || !bytes.starts_with(&self.0) {
            return Err(Error::Framing);
        }
        Ok(())
    }
}

/// Origin is absent for native clients. An explicit allowlist is required to
/// accept any present Origin; it is checked before body/route processing.
#[derive(Clone, Debug, Default)]
pub struct OriginPolicy {
    allowed: Vec<String>,
}

impl OriginPolicy {
    /// Allow exact canonical serialized HTTP(S) origins only, without a path,
    /// credentials, list syntax, or an explicitly spelled default port.
    pub fn allow_exact(origins: Vec<String>) -> Result<Self, Error> {
        if origins.len() > 64
            || origins.iter().any(|o| {
                o == "null"
                    || o.is_empty()
                    || o.len() > 2048
                    || o.bytes().any(|b| !(0x21..=0x7e).contains(&b))
                    || !url::Url::parse(o).is_ok_and(|url| {
                        matches!(url.scheme(), "http" | "https")
                            && url.origin().ascii_serialization() == *o
                    })
            })
        {
            return Err(Error::Configuration);
        }
        Ok(Self { allowed: origins })
    }

    fn accepts(&self, origin: &str) -> bool {
        origin != "null" && self.allowed.iter().any(|o| o == origin)
    }
}
