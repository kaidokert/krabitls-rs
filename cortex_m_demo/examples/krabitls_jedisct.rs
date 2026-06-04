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
    unreachable!()
}
