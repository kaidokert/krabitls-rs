//! Minimal HTTP/1.0 GET over any [`embedded_io`] byte stream.
//!
//! Transport-agnostic: the same code runs over a plaintext socket or a
//! [`TlsStream`](krabitls::client::TlsStream) (→ HTTPS). No allocation — the
//! caller owns the response buffer; a response larger than it is reported as
//! `truncated`.

use embedded_io::{Read, Write};

/// Parsed response head plus a view of the body captured in the caller buffer.
pub struct Response<'b> {
    pub status: u16,
    pub body: &'b [u8],
    /// The response exceeded the caller buffer and was cut off.
    pub truncated: bool,
}

#[derive(Debug)]
pub enum Error<E> {
    Io(E),
    /// No parseable `HTTP/1.x NNN` status line.
    Malformed,
}

/// Send `GET {path}` with `Host: {host}` and drain the response into `buf`.
pub fn get<'b, T>(
    io: &mut T,
    host: &str,
    path: &str,
    buf: &'b mut [u8],
) -> Result<Response<'b>, Error<T::Error>>
where
    T: Read + Write,
{
    for part in [
        b"GET ".as_slice(),
        path.as_bytes(),
        b" HTTP/1.0\r\nHost: ",
        host.as_bytes(),
        b"\r\nUser-Agent: krabitls_cli/0.1\r\nConnection: close\r\n\r\n",
    ] {
        io.write_all(part).map_err(Error::Io)?;
    }

    let mut n = 0;
    let mut truncated = false;
    while n < buf.len() {
        match io.read(&mut buf[n..]).map_err(Error::Io)? {
            0 => break,
            k => n += k,
        }
    }
    if n == buf.len() {
        // Ran out of buffer before EOF; treat as truncated even if the peer
        // happened to end exactly here — we can't tell without over-reading.
        truncated = true;
    }

    let full: &'b [u8] = buf;
    let resp = &full[..n];
    let status = parse_status(resp).ok_or(Error::Malformed)?;
    let body_start = find(resp, b"\r\n\r\n").map(|i| i + 4).unwrap_or(n);
    Ok(Response {
        status,
        body: &full[body_start..n],
        truncated,
    })
}

/// Parse the numeric code from an `HTTP/1.x NNN ...` status line.
fn parse_status(resp: &[u8]) -> Option<u16> {
    let line_end = resp.iter().position(|&b| b == b'\n').unwrap_or(resp.len());
    let line = &resp[..line_end];
    let sp = line.iter().position(|&b| b == b' ')?;
    let code = line.get(sp + 1..sp + 4)?;
    core::str::from_utf8(code).ok()?.parse().ok()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
