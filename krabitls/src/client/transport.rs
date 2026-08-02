//! Single-error `Transport` trait; blanket-impl over `embedded_io::Read + Write`.

/// Single-error read+write abstraction. No flush, no timeouts.
pub trait Transport {
    /// Unified error for both read and write.
    type Error;

    /// Read up to `buf.len()` bytes into `buf`. Returns the number of
    /// bytes actually read. `Ok(0)` is interpreted as unexpected
    /// transport-side EOF by the wrapper.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Non-blocking read for [`TlsStream::try_read`](crate::client::TlsStream::try_read).
    /// `Ok(Some(n))` = `n` bytes read (`Some(0)` = transport EOF); `Ok(None)` =
    /// no data available yet, so the caller should service its stack and retry.
    ///
    /// The default blocks — it delegates to [`read`](Self::read) — so a purely
    /// blocking transport keeps working (its `try_read` simply blocks once). A
    /// non-blocking transport (e.g. over an `nb` network stack) overrides this
    /// to surface `Ok(None)` instead of parking, which is what lets a caller
    /// interleave TLS reads with other work in a single-threaded event loop.
    fn read_nb(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        self.read(buf).map(Some)
    }

    /// Write all of `buf`; all-or-error per record.
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error>;
}

impl<R> Transport for R
where
    R: embedded_io::Read + embedded_io::Write,
{
    type Error = <R as embedded_io::ErrorType>::Error;

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        embedded_io::Read::read(self, buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        embedded_io::Write::write_all(self, buf)
    }
}
