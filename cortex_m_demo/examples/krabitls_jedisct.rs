#![no_main]
#![no_std]

use cortex_m_rt::entry;
use krabitls::JedisctCrypto;

#[entry]
fn main() -> ! {
    cortex_m_demo::test_fixture(
        || cortex_m_demo::run_handshake::<JedisctCrypto>().is_ok(),
        "krabitls_jedisct",
    );
    // See krabitls.rs: `loop { nop }` to satisfy `fn() -> !` without
    // pulling in panic-fmt machinery via `unreachable!()`.
    loop {
        cortex_m::asm::nop();
    }
}
