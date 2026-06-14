//! Single-error `Transport` trait; blanket-impl over `embedded_io::Read + Write`.

/// Single-error read+write abstraction. No flush, no timeouts.
pub trait Transport {
    /// Unified error for both read and write.
    type Error;

    /// Read up to `buf.len()` bytes into `buf`. Returns the number of
    /// bytes actually read. `Ok(0)` is interpreted as unexpected
    /// transport-side EOF by the wrapper.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;

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
