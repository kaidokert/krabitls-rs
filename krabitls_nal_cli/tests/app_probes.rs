//! `http` / `mqtt` probes over a mock `embedded_io` stream — transport-agnostic,
//! so no TLS is involved here.

use embedded_io::{ErrorType, Read, Write};
use krabitls_nal_cli::{http, mqtt};

#[derive(Debug)]
struct MockError;
impl core::fmt::Display for MockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("mock io error")
    }
}
impl core::error::Error for MockError {}
impl embedded_io::Error for MockError {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

/// A canned response tape plus a capture of everything written.
struct MockIo {
    rx: Vec<u8>,
    rx_pos: usize,
    tx: Vec<u8>,
}

impl MockIo {
    fn new(rx: &[u8]) -> Self {
        Self {
            rx: rx.to_vec(),
            rx_pos: 0,
            tx: Vec::new(),
        }
    }
}

impl ErrorType for MockIo {
    type Error = MockError;
}
impl Read for MockIo {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, MockError> {
        let take = (self.rx.len() - self.rx_pos).min(buf.len());
        buf[..take].copy_from_slice(&self.rx[self.rx_pos..self.rx_pos + take]);
        self.rx_pos += take;
        Ok(take)
    }
}
impl Write for MockIo {
    fn write(&mut self, buf: &[u8]) -> Result<usize, MockError> {
        self.tx.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> Result<(), MockError> {
        Ok(())
    }
}

#[test]
fn http_get_parses_status_and_body() {
    let mut io = MockIo::new(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    let mut buf = [0u8; 256];
    let resp = http::get(&mut io, "example.com", "/", &mut buf).expect("parse");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"hello");
    assert!(!resp.truncated);
    assert!(
        io.tx
            .starts_with(b"GET / HTTP/1.0\r\nHost: example.com\r\n")
    );
}

#[test]
fn http_get_flags_truncation() {
    let mut io = MockIo::new(b"HTTP/1.1 404 Not Found\r\n\r\nxxxxxxxxxx");
    let mut buf = [0u8; 26]; // smaller than the response
    let resp = http::get(&mut io, "h", "/", &mut buf).expect("parse");
    assert_eq!(resp.status, 404);
    assert!(resp.truncated);
}

#[test]
fn mqtt_connect_probe_accepts_connack() {
    let mut io = MockIo::new(&[0x20, 0x02, 0x01, 0x00]); // CONNACK, session_present=1, rc=0
    let session_present = mqtt::connect_probe(&mut io).expect("connack");
    assert!(session_present);
    assert!(io.tx.starts_with(&[0x10])); // CONNECT
    assert!(io.tx.ends_with(&[0xe0, 0x00])); // DISCONNECT
}

#[test]
fn mqtt_connect_probe_rejects_nonzero_rc() {
    let mut io = MockIo::new(&[0x20, 0x02, 0x00, 0x05]); // rc=5 (not authorized)
    assert!(matches!(
        mqtt::connect_probe(&mut io),
        Err(mqtt::Error::Protocol(_))
    ));
}
