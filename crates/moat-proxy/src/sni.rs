//! The server name (SNI) a TLS client sends in its `ClientHello` (RFC 8446 §4.1.2,
//! RFC 6066 §3).
//!
//! The proxy reads the `ClientHello` a tunnel starts with, compares its SNI with
//! the CONNECT host and only then forwards it, unchanged. Nothing is decrypted.
//! A `ClientHello` may be split over several TLS records; they are reassembled up
//! to [`MAX_HELLO`] bytes.

/// Largest `ClientHello` handshake message accepted. Real ones are 0.5–2 KiB,
/// more with post-quantum key shares; 64 KiB leaves room without letting a
/// client make the proxy buffer without bound.
pub const MAX_HELLO: usize = 64 * 1024;

const RECORD_HEADER: usize = 5;
const MAX_RECORD: usize = 16 * 1024 + 2048;
const CONTENT_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;
const NAME_TYPE_HOST: u8 = 0;

/// What the start of a tunnel says about the server it wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hello {
    /// More bytes are needed.
    Incomplete,
    /// A complete `ClientHello`; `None` when it carries no SNI.
    ServerName(Option<String>),
}

/// Why the start of a tunnel is not a `ClientHello` the proxy can check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HelloError {
    /// The bytes are not a TLS handshake record.
    #[error("the tunnel does not start with a TLS handshake")]
    NotTls,
    /// A TLS handshake that is not a well-formed `ClientHello`.
    #[error("malformed TLS ClientHello")]
    Malformed,
    /// Larger than [`MAX_HELLO`].
    #[error("TLS ClientHello larger than {MAX_HELLO} bytes")]
    TooLarge,
}

/// Read the SNI from the TLS records at the start of `buf`.
pub fn server_name(buf: &[u8]) -> Result<Hello, HelloError> {
    let mut handshake = Vec::new();
    let mut pos = 0;
    loop {
        let Some(header) = buf.get(pos..pos + RECORD_HEADER) else {
            return Ok(Hello::Incomplete);
        };
        if header[0] != CONTENT_HANDSHAKE || header[1] != 3 {
            return Err(HelloError::NotTls);
        }
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if len == 0 || len > MAX_RECORD {
            return Err(HelloError::Malformed);
        }
        let start = pos + RECORD_HEADER;
        let Some(fragment) = buf.get(start..start + len) else {
            return Ok(Hello::Incomplete);
        };
        handshake.extend_from_slice(fragment);
        pos = start + len;

        if handshake.len() >= 4 {
            if handshake[0] != HANDSHAKE_CLIENT_HELLO {
                return Err(HelloError::Malformed);
            }
            let body_len = usize::from(handshake[1]) << 16
                | usize::from(handshake[2]) << 8
                | usize::from(handshake[3]);
            if body_len > MAX_HELLO {
                return Err(HelloError::TooLarge);
            }
            if let Some(body) = handshake.get(4..4 + body_len) {
                return client_hello_sni(body).map(Hello::ServerName);
            }
        }
    }
}

fn client_hello_sni(body: &[u8]) -> Result<Option<String>, HelloError> {
    let mut r = Reader(body);
    r.take(2 + 32)?; // legacy_version, random
    let session_id_len = r.u8()?;
    r.take(session_id_len.into())?;
    let suites_len = r.u16()?;
    r.take(suites_len.into())?;
    let compression_len = r.u8()?;
    r.take(compression_len.into())?;
    if r.0.is_empty() {
        return Ok(None);
    }
    let ext_len = r.u16()?;
    let mut exts = Reader(r.take(ext_len.into())?);
    r.end()?;
    let mut name = None;
    while !exts.0.is_empty() {
        let kind = exts.u16()?;
        let len = exts.u16()?;
        let data = exts.take(len.into())?;
        if kind == EXT_SERVER_NAME {
            if name.is_some() {
                return Err(HelloError::Malformed);
            }
            name = Some(server_name_list(data)?);
        }
    }
    Ok(name.flatten())
}

/// `ServerNameList`: at most one `host_name` entry (RFC 6066 §3).
fn server_name_list(data: &[u8]) -> Result<Option<String>, HelloError> {
    let mut r = Reader(data);
    let list_len = r.u16()?;
    let mut list = Reader(r.take(list_len.into())?);
    r.end()?;
    let mut host = None;
    while !list.0.is_empty() {
        let kind = list.u8()?;
        let len = list.u16()?;
        let value = list.take(len.into())?;
        if kind != NAME_TYPE_HOST {
            continue;
        }
        if host.is_some() || value.is_empty() || !value.is_ascii() {
            return Err(HelloError::Malformed);
        }
        let text = std::str::from_utf8(value).map_err(|_| HelloError::Malformed)?;
        host = Some(text.strip_suffix('.').unwrap_or(text).to_ascii_lowercase());
    }
    Ok(host)
}

/// Bounds-checked big-endian reads; every short read is [`HelloError::Malformed`].
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], HelloError> {
        if n > self.0.len() {
            return Err(HelloError::Malformed);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, HelloError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, HelloError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn end(&self) -> Result<(), HelloError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(HelloError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests;
