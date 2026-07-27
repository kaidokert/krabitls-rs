//! Shared helpers for the canned-fixture integration tests.

/// Parse the testdata `.hex` format (skips `#`-comments + whitespace).
pub fn parse_hex(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut nibbles = [0u8; 2];
    let mut have = 0;
    let mut in_comment = false;
    for &b in s.as_bytes() {
        if in_comment {
            if b == b'\n' {
                in_comment = false;
            }
            continue;
        }
        match b {
            b'#' => in_comment = true,
            b' ' | b'\t' | b'\r' | b'\n' => {}
            c => {
                let nib = match c {
                    b'0'..=b'9' => c - b'0',
                    b'a'..=b'f' => c - b'a' + 10,
                    b'A'..=b'F' => c - b'A' + 10,
                    _ => panic!("bad hex char: {c:#x}"),
                };
                nibbles[have] = nib;
                have += 1;
                if have == 2 {
                    out.push((nibbles[0] << 4) | nibbles[1]);
                    have = 0;
                }
            }
        }
    }
    assert_eq!(have, 0, "dangling nibble in hex input");
    out
}
