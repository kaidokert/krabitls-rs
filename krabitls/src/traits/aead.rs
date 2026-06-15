/// AEAD tag verification failed. RFC 8446 §5.2: tear down with `bad_record_mac`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AeadError;
