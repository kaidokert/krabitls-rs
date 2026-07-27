//! Minimal MQTT 3.1.1 CONNECT probe over any [`embedded_io`] byte stream
//! (plaintext or a [`TlsStream`](krabitls::client::TlsStream) for MQTT-over-TLS).

use embedded_io::{Read, Write};

/// CONNECT: clean session, keepalive 60 s, client id "krabitls".
const CONNECT: &[u8] = &[
    0x10, 0x14, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x08, b'k', b'r',
    b'a', b'b', b'i', b't', b'l', b's',
];

#[derive(Debug)]
pub enum Error<E> {
    Io(E),
    Protocol(&'static str),
}

/// Send CONNECT, validate the CONNACK (return code 0), send DISCONNECT.
/// Returns the CONNACK `session_present` flag.
pub fn connect_probe<T>(io: &mut T) -> Result<bool, Error<T::Error>>
where
    T: Read + Write,
{
    io.write_all(CONNECT).map_err(Error::Io)?;

    let mut resp = [0u8; 4];
    let mut got = 0;
    while got < resp.len() {
        match io.read(&mut resp[got..]).map_err(Error::Io)? {
            0 => break,
            n => got += n,
        }
    }
    if got < 4 || resp[0] != 0x20 || resp[1] != 0x02 {
        return Err(Error::Protocol("expected MQTT CONNACK"));
    }
    if resp[3] != 0x00 {
        return Err(Error::Protocol("MQTT CONNACK non-zero return code"));
    }

    io.write_all(&[0xe0, 0x00]).map_err(Error::Io)?; // DISCONNECT
    Ok(resp[2] & 1 == 1)
}
