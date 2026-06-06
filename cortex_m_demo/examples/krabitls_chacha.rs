#![no_main]
#![no_std]

use cortex_m_rt::entry;
use krabitls::RustCrypto;

#[entry]
fn main() -> ! {
    cortex_m_demo::test_fixture(
        || cortex_m_demo::run_handshake_chacha::<RustCrypto>().is_ok(),
        "krabitls_chacha",
    );
    loop {
        cortex_m::asm::nop();
    }
}
