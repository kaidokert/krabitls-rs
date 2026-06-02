#![no_main]
#![no_std]

use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use der::{Reader, SliceReader, Tag};

// Random garbage that vaguely looks like the start of a DER SEQUENCE.
const GARBAGE: &[u8] = &[
    0x30, 0x10, 0x02, 0x01, 0x42, 0x04, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x05, 0x00, 0x06,
    0x03, 0x2b, 0x65, 0x70,
];

#[entry]
fn main() -> ! {
    let mut accept = true;

    // 1. Build a reader and read the outer tag/length. Garbage starts with
    //    0x30 0x10 — SEQUENCE, 16-byte body — so this should succeed.
    let r = match SliceReader::new(GARBAGE) {
        Ok(r) => r,
        Err(e) => {
            hprintln!("SliceReader::new err: {:?}", e);
            accept = false;
            // dummy reader so we can still attempt subsequent steps
            SliceReader::new(&[0x30, 0x00]).unwrap()
        }
    };
    drop(r);

    // 2. Take a peek at tag — proves header decoding works.
    let mut r = SliceReader::new(GARBAGE).unwrap();
    match r.peek_tag() {
        Ok(t) => hprintln!("peek_tag ok: {:?}", t),
        Err(e) => {
            hprintln!("peek_tag err: {:?}", e);
            accept = false;
        }
    }
    let _ = Tag::Sequence;

    if accept {
        hprintln!("eval_der ACCEPT");
        debug::exit(debug::EXIT_SUCCESS);
    } else {
        hprintln!("eval_der REJECT");
        debug::exit(debug::EXIT_FAILURE);
    }
    loop {}
}

use panic_semihosting as _;
