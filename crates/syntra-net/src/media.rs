//! Resumable, immutable media objects over ordinary application RPCs. No core
//! negotiation or automatic mutation replay. Keep the same [`Manifest`] across
//! attempts; an RPC failure (including a deadline) need not mean rollback.
//!
//! V1 uses the method paths in [`Method::path`]. All integers are big endian.
//! A key is `object[16], version:u64`; a manifest is `key, transfer_id[16],
//! length:u64, sha256[32]`. Describe takes a key and returns a manifest. All
//! other requests start with a manifest. Read adds an offset (u64); Put adds a
//! block. A block (also the Read reply) is `offset:u64, sha256[32], bytes`.
//! Reading exactly `length` returns an EOF block with empty bytes and their
//! digest. It requires Read permission, including for an empty object. Describe
//! grants metadata only. Online download completion always checks Read at EOF;
//! an older server without EOF support fails closed.
//! Other replies are state: 0 absent, 1 followed by next byte offset (u64),
//! 2 committed, 3 aborted. There are no optional/trailing fields. The principal
//! is never sent in the payload. IDs are opaque names, not capabilities.
//!
//! Use a fresh [`SqliteMediaHost::handler`] per accepted connection. A router
//! must forward both `Handler::authorize` and `Handler::handle_with_context`
//! for these exact paths; do not wrap it in an authorization bypass. Serialize
//! any mutable ACL with the SQLite transaction in [`ObjectPolicy`].
//! For the managed media lane, construct `MediaClient::new(Arc::clone(&lanes))`.
//! One attempt pins its first reservation's generation; replacement requires
//! explicit re-entry starting at Query or Describe. One lane owner must always
//! represent the same provisioned authority and account. Rotation of the pin,
//! context, key or opaque hello credential requires a new production owner;
//! the server must not reassign an unchanged credential. The application pins
//! the manifest and authority/account across explicit resumes. Dropping a transfer future stops
//! issuing new calls; an admitted RPC or local transaction may still complete.
//!
//! Begin binds one transfer ID to its authenticated owner and exact manifest.
//! Put accepts only the next offset or an identical existing block. Finalize
//! verifies the pinned SHA-256 in a read-only WAL snapshot. A short writer
//! transaction checks the current ACL, binding, verified content revision and
//! request budget before publishing. Only committed versions can be described or read.
//! Abort releases the object/version for another upload but preserves the ID's
//! tombstone; it cannot undo a committed version. Neither IDs nor checkpoints
//! replace fresh authorization. Quotas across objects and at-rest encryption
//! belong to the deployment.

mod client;
mod host;
mod store;
#[cfg(test)]
mod tests;

pub use client::{DownloadStore, MediaClient, MediaRpc};
pub use host::{MediaHandler, ObjectPolicy, SqliteMediaHost};
use sha2::{Digest, Sha256};
use syntra_core::ErrorCode;

/// Fixed geometry permits only a short last chunk; an empty file has no chunks.
pub const CHUNK_BYTES: usize = 256 * 1024;
/// Per-object v1 bound (not a quota across objects).
pub const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;

const MANIFEST_BYTES: usize = 80;
const BLOCK_HEADER: usize = 40;
const STATE_BYTES: usize = 9;

/// Keys live in the host database's authority scope. Version zero is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectVersion {
    pub object: [u8; 16],
    pub version: u64,
}

impl ObjectVersion {
    fn bytes(self) -> Vec<u8> {
        [self.object.as_slice(), &self.version.to_be_bytes()].concat()
    }

    fn parse(src: &mut &[u8]) -> Result<Self> {
        let key = Self {
            object: take(src)?,
            version: number(src)?,
        };
        if key.version == 0 {
            return Err(MediaError::Invalid);
        }
        Ok(key)
    }
}

/// Application-pinned identity and expected content. Allocate a fresh stable
/// transfer ID for each upload; never generate a new ID to resolve uncertainty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub key: ObjectVersion,
    pub transfer_id: [u8; 16],
    pub length: u64,
    pub sha256: [u8; 32],
}

impl Manifest {
    fn validate(self) -> Result<()> {
        if self.length > MAX_OBJECT_BYTES || self.key.version == 0 {
            return Err(MediaError::Invalid);
        }
        Ok(())
    }

    fn bytes(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MANIFEST_BYTES);
        out.extend(self.key.bytes());
        out.extend(self.transfer_id);
        out.extend(self.length.to_be_bytes());
        out.extend(self.sha256);
        out
    }

    fn parse(src: &mut &[u8]) -> Result<Self> {
        let spec = Self {
            key: ObjectVersion::parse(src)?,
            transfer_id: take(src)?,
            length: number(src)?,
            sha256: take(src)?,
        };
        spec.validate()?;
        Ok(spec)
    }

    fn chunk_len(self, offset: u64) -> Result<usize> {
        if offset >= self.length || offset % CHUNK_BYTES as u64 != 0 {
            return Err(MediaError::Invalid);
        }
        Ok((self.length - offset).min(CHUNK_BYTES as u64) as usize)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UploadState {
    Absent,
    Uploading(u64),
    Committed,
    Aborted,
}

impl UploadState {
    fn bytes(self) -> Vec<u8> {
        match self {
            Self::Absent => vec![0],
            Self::Uploading(n) => [&[1][..], &n.to_be_bytes()].concat(),
            Self::Committed => vec![2],
            Self::Aborted => vec![3],
        }
    }

    fn parse(data: &[u8], spec: Manifest) -> Result<Self> {
        match data {
            [0] => Ok(Self::Absent),
            [2] => Ok(Self::Committed),
            [3] => Ok(Self::Aborted),
            [1, rest @ ..] if rest.len() == 8 => {
                let n = number(&mut &rest[..])?;
                if n != spec.length {
                    spec.chunk_len(n)?;
                }
                Ok(Self::Uploading(n))
            }
            _ => Err(MediaError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Begin,
    Query,
    Put,
    Finalize,
    Abort,
    Describe,
    Read,
}

impl Method {
    /// Conservative encoded-result reservation for a method-based host
    /// admission policy, including Core envelope/diagnostic headroom.
    pub fn response_frame_bytes(self) -> usize {
        if self == Self::Read {
            CHUNK_BYTES + BLOCK_HEADER + 1024
        } else {
            1024
        }
    }

    pub fn path(self) -> &'static str {
        match self {
            Self::Begin => "/syntra.media.v1.Media/Begin",
            Self::Query => "/syntra.media.v1.Media/Query",
            Self::Put => "/syntra.media.v1.Media/Put",
            Self::Finalize => "/syntra.media.v1.Media/Finalize",
            Self::Abort => "/syntra.media.v1.Media/Abort",
            Self::Describe => "/syntra.media.v1.Media/Describe",
            Self::Read => "/syntra.media.v1.Media/Read",
        }
    }

    pub fn from_path(path: &str) -> Option<Self> {
        [
            Self::Begin,
            Self::Query,
            Self::Put,
            Self::Finalize,
            Self::Abort,
            Self::Describe,
            Self::Read,
        ]
        .into_iter()
        .find(|m| m.path() == path)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[error("invalid media message or chunk geometry")]
    Invalid,
    #[error("media identity or content conflicts with existing data")]
    Conflict,
    #[error("media data failed verification")]
    Corrupt,
    #[error("media operation refused: {0:?}")]
    Refused(ErrorCode),
    #[error("media call failed; query before resuming: {0}")]
    Call(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("media storage: {0}")]
    Storage(#[from] rusqlite::Error),
    #[error("media I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("media worker stopped")]
    Worker,
}

pub type Result<T> = std::result::Result<T, MediaError>;

fn take<const N: usize>(src: &mut &[u8]) -> Result<[u8; N]> {
    let (value, rest) = src.split_first_chunk().ok_or(MediaError::Invalid)?;
    *src = rest;
    Ok(*value)
}
fn number(src: &mut &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(take(src)?))
}
fn end(src: &[u8]) -> Result<()> {
    if src.is_empty() {
        Ok(())
    } else {
        Err(MediaError::Invalid)
    }
}
fn digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

// An authorized EOF read is also available for a zero-length object.
fn eof(spec: Manifest) -> Vec<u8> {
    [spec.length.to_be_bytes().as_slice(), &digest(&[])].concat()
}

fn block(spec: Manifest, src: &[u8]) -> Result<(u64, &[u8])> {
    let mut bytes = src;
    let pos = number(&mut bytes)?;
    let hash: [u8; 32] = take(&mut bytes)?;
    if bytes.len() != spec.chunk_len(pos)? {
        return Err(MediaError::Invalid);
    }
    if digest(bytes) != hash {
        return Err(MediaError::Corrupt);
    }
    Ok((pos, bytes))
}
