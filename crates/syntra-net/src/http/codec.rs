//! Strict bounded origin HTTP codec for the unaccepted RFC0013 candidate.
//! No I/O, identity, connection pooling, CONNECT tunnels or cryptographic parsing.
//! `parse_*` accepts exactly a header block; `decode_*` accepts exactly one whole
//! message and rejects trailing bytes. Streaming users retain unread bytes and
//! enforce operation sequencing and absolute deadlines themselves.

use super::{Authority, OpenEnvelope, OriginPolicy, Route};
use crate::Error;

pub const MAX_HEADERS: usize = 16_384;
pub const MAX_FIELDS: usize = 64;
pub const MAX_START_LINE: usize = 2_048;
pub const MAX_FIELD_LINE: usize = 4_096;
pub const MAX_RECORD: usize = 65_535;

/// Safe pre-body native rejection. The wire bytes are fixed: no peer header,
/// credential, route, principal, parser error or policy detail is reflected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rejection {
    BadRequest,
    Forbidden,
    NotFound,
    Method,
    Gone,
    BodyBound,
    HeaderBound,
    Rate,
    Unavailable,
    Version,
}
impl Rejection {
    pub(crate) fn response(self) -> &'static [u8] {
        match self {
            Self::BadRequest => b"HTTP/1.1 400 Bad Request\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n",
            Self::Forbidden => b"HTTP/1.1 403 Forbidden\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n",
            Self::NotFound => b"HTTP/1.1 404 Not Found\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n",
            Self::Method => b"HTTP/1.1 405 Method Not Allowed\r\nAllow: POST\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n",
            Self::Gone => b"HTTP/1.1 410 Gone\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n",
            Self::BodyBound => b"HTTP/1.1 413 Content Too Large\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n",
            Self::HeaderBound => b"HTTP/1.1 431 Request Header Fields Too Large\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n",
            Self::Rate => b"HTTP/1.1 429 Too Many Requests\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n",
            Self::Unavailable => b"HTTP/1.1 503 Service Unavailable\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n",
            Self::Version => b"HTTP/1.1 505 HTTP Version Not Supported\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Open,
    Send,
    Poll,
    Close,
}

impl Operation {
    pub fn path(self) -> &'static str {
        match self {
            Self::Open => "/syntra/1.0/http/open",
            Self::Send => "/syntra/1.0/http/send",
            Self::Poll => "/syntra/1.0/http/poll",
            Self::Close => "/syntra/1.0/http/close",
        }
    }
}

/// Parsed, operation-validated metadata. Payload bytes are never logged here.
#[derive(Debug)]
pub struct Head {
    pub operation: Operation,
    pub status: Option<u16>,
    pub body_len: usize,
    pub route: Option<Route>,
    pub counter: Option<u64>,
}

pub fn decimal(value: &str) -> Result<u64, Error> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(Error::Framing);
    }
    value.bytes().try_fold(0u64, |n, b| {
        if !b.is_ascii_digit() {
            return Err(Error::Framing);
        }
        n.checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(b - b'0')))
            .ok_or(Error::Framing)
    })
}

fn token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

struct Headers<'a> {
    start: &'a str,
    fields: Vec<(&'a str, &'a str)>,
}

impl<'a> Headers<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let h = Self::parse_fields(bytes).map_err(|_| Error::Framing)?;
        if h.get("cache-control") != Some("no-store") {
            return Err(Error::Framing);
        }
        Ok(h)
    }

    fn parse_fields(bytes: &'a [u8]) -> Result<Self, Rejection> {
        if bytes.len() > MAX_HEADERS {
            return Err(Rejection::HeaderBound);
        }
        if !bytes.ends_with(b"\r\n\r\n") {
            return Err(Rejection::BadRequest);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| Rejection::BadRequest)?;
        let mut lines = text[..text.len() - 4].split("\r\n");
        let start = lines.next().ok_or(Rejection::BadRequest)?;
        if start.len() + 2 > MAX_START_LINE {
            return Err(Rejection::HeaderBound);
        }
        if !start.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
            return Err(Rejection::BadRequest);
        }
        let mut fields: Vec<(&str, &str)> = Vec::with_capacity(MAX_FIELDS);
        for line in lines {
            if fields.len() == MAX_FIELDS || line.len() + 2 > MAX_FIELD_LINE {
                return Err(Rejection::HeaderBound);
            }
            let (name, raw) = line.split_once(':').ok_or(Rejection::BadRequest)?;
            if name.is_empty()
                || !name.bytes().all(token)
                || !raw
                    .bytes()
                    .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
            {
                return Err(Rejection::BadRequest);
            }
            // Conservative singleton policy even for ignored fields. No header
            // merging or implicit extension negotiation at this boundary.
            if fields.iter().any(|(n, _)| name.eq_ignore_ascii_case(n)) {
                return Err(if name.eq_ignore_ascii_case("origin") {
                    Rejection::Forbidden
                } else {
                    Rejection::BadRequest
                });
            }
            let value = raw.trim_matches([' ', '\t']);
            let lower = name.to_ascii_lowercase();
            if matches!(
                lower.as_str(),
                "transfer-encoding"
                    | "content-encoding"
                    | "trailer"
                    | "expect"
                    | "upgrade"
                    | "te"
                    | "authorization"
                    | "proxy-authorization"
                    | "cookie"
                    | "set-cookie"
            ) || (lower.starts_with("syntra-")
                && !matches!(
                    lower.as_str(),
                    "syntra-route" | "syntra-upload" | "syntra-poll"
                ))
            {
                return Err(Rejection::BadRequest);
            }
            if lower == "connection"
                && (value.is_empty()
                    || value.split(',').any(|t| {
                        let t = t.trim_matches([' ', '\t']);
                        // Only persistence is supported; upgrade/close and unrecognized
                        // connection-nominated framing fields cannot be smuggled through.
                        !t.eq_ignore_ascii_case("keep-alive")
                    }))
            {
                return Err(Rejection::BadRequest);
            }
            fields.push((name, value));
        }
        Ok(Self { start, fields })
    }

    fn get(&self, name: &str) -> Option<&'a str> {
        self.fields
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }

    fn body_len(&self, status: Option<u16>) -> Result<usize, Error> {
        let length = self.get("content-length");
        let len = if status == Some(204) {
            if length.is_some() {
                return Err(Error::Framing);
            }
            0
        } else {
            usize::try_from(decimal(length.ok_or(Error::Framing)?)?).map_err(|_| Error::Framing)?
        };
        if len > MAX_RECORD
            || self.get("content-type")
                != if len > 0 {
                    Some("application/octet-stream")
                } else {
                    None
                }
        {
            return Err(Error::Framing);
        }
        Ok(len)
    }

    fn association(
        &self,
        route: bool,
        upload: bool,
        poll: bool,
    ) -> Result<(Option<Route>, Option<u64>), Error> {
        let h = self.get("syntra-route");
        let n = self.get("syntra-upload");
        let p = self.get("syntra-poll");
        if h.is_some() != route || n.is_some() != upload || p.is_some() != poll {
            return Err(Error::Framing);
        }
        Ok((
            h.map(Route::parse).transpose()?,
            n.or(p).map(decimal).transpose()?,
        ))
    }
}

pub fn parse_request(
    bytes: &[u8],
    authority: &Authority,
    origin: &OriginPolicy,
    envelope: &OpenEnvelope,
) -> Result<Head, Error> {
    parse_request_inner(bytes, authority, origin, Some(envelope))
}

/// Pre-association admission validates authority, Origin and all header/body
/// bounds before any route or cryptographic lookup. Open's exact context length
/// is checked by the kernel after reading its independently bounded M1 body.
pub(crate) fn parse_initial_request(
    bytes: &[u8],
    authority: &Authority,
    origin: &OriginPolicy,
) -> Result<Head, Rejection> {
    let h = Headers::parse_fields(bytes)?;
    let mut words = h.start.split(' ');
    let method = words.next().ok_or(Rejection::BadRequest)?;
    let path = words.next().ok_or(Rejection::BadRequest)?;
    let version = words.next().ok_or(Rejection::BadRequest)?;
    if words.next().is_some()
        || method.is_empty()
        || !method.bytes().all(token)
        || path.is_empty()
        || version.len() != 8
        || !version.starts_with("HTTP/")
        || !version.as_bytes()[5].is_ascii_digit()
        || version.as_bytes()[6] != b'.'
        || !version.as_bytes()[7].is_ascii_digit()
    {
        return Err(Rejection::BadRequest);
    }
    if version != "HTTP/1.1" {
        return Err(Rejection::Version);
    }
    if method != "POST" {
        return Err(Rejection::Method);
    }
    if !path.starts_with('/') {
        return Err(Rejection::BadRequest);
    }
    let operation = [
        Operation::Open,
        Operation::Send,
        Operation::Poll,
        Operation::Close,
    ]
    .into_iter()
    .find(|op| path == op.path())
    .ok_or(Rejection::NotFound)?;
    let host = h
        .get("host")
        .filter(|host| !host.is_empty())
        .ok_or(Rejection::BadRequest)?;
    if host != authority.as_str() {
        return Err(Rejection::NotFound);
    }
    if h.get("origin").is_some_and(|o| !origin.accepts(o)) {
        return Err(Rejection::Forbidden);
    }
    if h.get("accept") != Some("application/octet-stream")
        || h.get("cache-control") != Some("no-store")
    {
        return Err(Rejection::BadRequest);
    }
    let length = h.get("content-length").ok_or(Rejection::BadRequest)?;
    let length = decimal(length).map_err(|_| {
        if !length.is_empty()
            && !length.starts_with('0')
            && length.bytes().all(|b| b.is_ascii_digit())
        {
            Rejection::BodyBound // canonical positive integer beyond u64
        } else {
            Rejection::BadRequest
        }
    })?;
    let maximum = match operation {
        Operation::Open => syntra_core::secure_channel::MAX_WRAPPER,
        Operation::Send => MAX_RECORD,
        Operation::Poll | Operation::Close => 0,
    };
    if length > maximum as u64 {
        return Err(Rejection::BodyBound);
    }
    let body_len = h.body_len(None).map_err(|_| Rejection::BadRequest)?;
    if operation == Operation::Open && body_len < 83
        || operation == Operation::Send && body_len < 17
    {
        return Err(Rejection::BadRequest);
    }
    let (route, counter) = h
        .association(
            operation != Operation::Open,
            operation == Operation::Send,
            operation == Operation::Poll,
        )
        .map_err(|_| Rejection::BadRequest)?;
    Ok(Head {
        operation,
        status: None,
        body_len,
        route,
        counter,
    })
}

fn parse_request_inner(
    bytes: &[u8],
    authority: &Authority,
    origin: &OriginPolicy,
    envelope: Option<&OpenEnvelope>,
) -> Result<Head, Error> {
    let h = Headers::parse(bytes)?;
    if h.get("host") != Some(authority.as_str())
        || h.get("accept") != Some("application/octet-stream")
        || h.get("origin").is_some_and(|o| !origin.accepts(o))
    {
        return Err(Error::Framing);
    }
    let op = [
        Operation::Open,
        Operation::Send,
        Operation::Poll,
        Operation::Close,
    ]
    .into_iter()
    .find(|op| h.start == format!("POST {} HTTP/1.1", op.path()))
    .ok_or(Error::Framing)?;
    let len = h.body_len(None)?;
    if !match op {
        Operation::Open => envelope.map_or(
            (83..=syntra_core::secure_channel::MAX_WRAPPER).contains(&len),
            |envelope| len == envelope.m1_len(),
        ),
        Operation::Send => (17..=MAX_RECORD).contains(&len),
        Operation::Poll | Operation::Close => len == 0,
    } {
        return Err(Error::Framing);
    }
    let (route, counter) = h.association(
        op != Operation::Open,
        op == Operation::Send,
        op == Operation::Poll,
    )?;
    Ok(Head {
        operation: op,
        status: None,
        body_len: len,
        route,
        counter,
    })
}

/// Only operation-specific successes are accepted; native errors, redirects,
/// challenges and informational responses are fatal, never retry instructions.
pub fn parse_response(bytes: &[u8], op: Operation) -> Result<Head, Error> {
    let h = Headers::parse(bytes)?;
    let rest = h.start.strip_prefix("HTTP/1.1 ").ok_or(Error::Framing)?;
    let (code, _) = rest.split_once(' ').ok_or(Error::Framing)?;
    if code.len() != 3 {
        return Err(Error::Framing);
    }
    let status = u16::try_from(decimal(code)?).map_err(|_| Error::Framing)?;
    let len = h.body_len(Some(status))?;
    if !match op {
        Operation::Open => status == 201 && len == 48,
        Operation::Send | Operation::Close => status == 204,
        Operation::Poll => status == 204 || (status == 200 && (17..=MAX_RECORD).contains(&len)),
    } {
        return Err(Error::Framing);
    }
    let (route, counter) = h.association(
        op == Operation::Open,
        op == Operation::Send,
        op == Operation::Poll,
    )?;
    Ok(Head {
        operation: op,
        status: Some(status),
        body_len: len,
        route,
        counter,
    })
}

pub fn decode_request<'a>(
    bytes: &'a [u8],
    authority: &Authority,
    origin: &OriginPolicy,
    envelope: &OpenEnvelope,
) -> Result<(Head, &'a [u8]), Error> {
    let split = header_end(bytes)?;
    let head = parse_request(&bytes[..split], authority, origin, envelope)?;
    let body = &bytes[split..];
    if body.len() != head.body_len {
        return Err(Error::Framing);
    }
    if head.operation == Operation::Open {
        envelope.check_m1(body)?;
    }
    Ok((head, body))
}

pub fn decode_response(bytes: &[u8], op: Operation) -> Result<(Head, &[u8]), Error> {
    let split = header_end(bytes)?;
    let head = parse_response(&bytes[..split], op)?;
    let body = &bytes[split..];
    if body.len() != head.body_len {
        return Err(Error::Framing);
    }
    Ok((head, body))
}

fn header_end(bytes: &[u8]) -> Result<usize, Error> {
    bytes[..bytes.len().min(MAX_HEADERS)]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .ok_or(Error::Framing)
}

/// Generate just the bounded header, borrowing the original body separately.
pub fn request(
    op: Operation,
    authority: &Authority,
    route: Option<&Route>,
    counter: Option<u64>,
    body: &[u8],
    envelope: &OpenEnvelope,
) -> Result<Vec<u8>, Error> {
    let mut text = format!("POST {} HTTP/1.1\r\nHost: {}\r\nCache-Control: no-store\r\nAccept: application/octet-stream\r\nContent-Length: {}\r\n",
        op.path(), authority.as_str(), body.len());
    content_type(&mut text, body);
    if let Some(route) = route {
        text.push_str(&format!("Syntra-Route: {}\r\n", route.as_str()));
    }
    counter_header(&mut text, op, counter);
    text.push_str("\r\n");
    parse_request(
        text.as_bytes(),
        authority,
        &OriginPolicy::default(),
        envelope,
    )?;
    if op == Operation::Open {
        envelope.check_m1(body)?;
    }
    Ok(text.into_bytes())
}

pub fn response(
    op: Operation,
    route: Option<&Route>,
    counter: Option<u64>,
    body: &[u8],
) -> Result<Vec<u8>, Error> {
    let status = match op {
        Operation::Open => "201 Created",
        Operation::Poll if !body.is_empty() => "200 OK",
        _ => "204 No Content",
    };
    let mut text = format!("HTTP/1.1 {status}\r\nCache-Control: no-store\r\n");
    if !status.starts_with("204") {
        text.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    content_type(&mut text, body);
    if let Some(route) = route {
        text.push_str(&format!("Syntra-Route: {}\r\n", route.as_str()));
    }
    counter_header(&mut text, op, counter);
    text.push_str("\r\n");
    let head = parse_response(text.as_bytes(), op)?;
    if head.body_len != body.len() {
        return Err(Error::Framing);
    }
    Ok(text.into_bytes())
}

fn content_type(text: &mut String, body: &[u8]) {
    if !body.is_empty() {
        text.push_str("Content-Type: application/octet-stream\r\n");
    }
}

fn counter_header(text: &mut String, op: Operation, counter: Option<u64>) {
    if let Some(n) = counter {
        // An inapplicable counter is emitted under an unknown header and rejected
        // by the same parser, rather than silently omitted.
        let name = match op {
            Operation::Send => "Upload",
            Operation::Poll => "Poll",
            _ => "Invalid",
        };
        text.push_str(&format!("Syntra-{name}: {n}\r\n"));
    }
}

#[cfg(test)]
mod native_tests {
    use super::*;

    #[test]
    fn all_native_rejections_are_static_empty_and_at_most_92_bytes() {
        let mut maximum = 0;
        for (rejection, status) in [
            (Rejection::BadRequest, 400),
            (Rejection::Forbidden, 403),
            (Rejection::NotFound, 404),
            (Rejection::Method, 405),
            (Rejection::Gone, 410),
            (Rejection::BodyBound, 413),
            (Rejection::Rate, 429),
            (Rejection::HeaderBound, 431),
            (Rejection::Unavailable, 503),
            (Rejection::Version, 505),
        ] {
            let bytes = rejection.response();
            maximum = maximum.max(bytes.len());
            let headers = Headers::parse(bytes).unwrap();
            assert!(headers.start.starts_with(&format!("HTTP/1.1 {status} ")));
            assert_eq!(headers.body_len(Some(status)).unwrap(), 0);
            assert_eq!(headers.get("content-length"), Some("0"));
            assert_eq!(headers.get("cache-control"), Some("no-store"));
            assert_eq!(
                headers.get("allow"),
                if status == 405 { Some("POST") } else { None }
            );
            assert_eq!(headers.fields.len(), if status == 405 { 3 } else { 2 });
            assert_eq!(header_end(bytes).unwrap(), bytes.len());
        }
        assert_eq!(maximum, 92);
    }
}
