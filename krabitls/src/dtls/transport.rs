//! Datagram transport abstraction for the DTLS 1.3 client.
//!
//! DTLS runs over an unreliable, message-oriented transport (UDP), so — unlike
//! the stream-oriented TLS [`Transport`](crate::client::Transport) — the unit of
//! I/O is a whole datagram, and a receive can legitimately return "nothing yet"
//! without meaning end-of-connection. The retransmission timer that a lossy link
//! needs is driven by the caller, so `recv` reports would-block as `Ok(None)`
//! rather than blocking forever.

/// A bidirectional datagram channel already connected to one DTLS peer.
pub trait DatagramTransport {
    /// Transport error surfaced by [`send`](Self::send) / [`recv`](Self::recv).
    type Error;

    /// Send one datagram. DTLS records are never split across datagrams by the
    /// sender, so the whole slice is one datagram on the wire.
    fn send(&mut self, datagram: &[u8]) -> Result<(), Self::Error>;

    /// Receive one datagram into `buf`, returning the number of bytes read.
    /// `Ok(None)` means nothing was available before the transport's timeout —
    /// the caller retransmits or waits, it is not an error or a closed channel.
    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Self::Error>;
}

/// A `std` UDP-socket transport, used by tests and host tooling. The socket must
/// already be `connect`ed to the peer; a read timeout turns a quiet link into
/// `Ok(None)` instead of a block.
#[cfg(test)]
pub struct UdpTransport {
    socket: std::net::UdpSocket,
}

#[cfg(test)]
impl UdpTransport {
    /// Wrap a connected [`std::net::UdpSocket`].
    pub fn new(socket: std::net::UdpSocket) -> Self {
        Self { socket }
    }
}

#[cfg(test)]
impl DatagramTransport for UdpTransport {
    type Error = std::io::Error;

    fn send(&mut self, datagram: &[u8]) -> Result<(), Self::Error> {
        self.socket.send(datagram)?;
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        match self.socket.recv(buf) {
            Ok(n) => Ok(Some(n)),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::time::Duration;

    #[test]
    fn udp_transport_round_trips_and_times_out() {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        a.connect(b.local_addr().unwrap()).unwrap();
        b.connect(a.local_addr().unwrap()).unwrap();
        a.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();

        let mut ta = UdpTransport::new(a);
        let mut tb = UdpTransport::new(b);
        tb.send(b"ping").unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(ta.recv(&mut buf).unwrap(), Some(4));
        assert_eq!(&buf[..4], b"ping");
        // Nothing more queued: the timeout surfaces as Ok(None), not an error.
        assert_eq!(ta.recv(&mut buf).unwrap(), None);
    }
}
