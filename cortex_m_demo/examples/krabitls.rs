#![no_main]
#![no_std]

use cortex_m_rt::entry;
#[cfg(not(feature = "baseline"))]
use krabitls::RustCrypto;

#[entry]
fn main() -> ! {
    cortex_m_demo::test_fixture(
        #[cfg(feature = "baseline")]
        || cortex_m_demo::fake_krabitls_pipeline(),
        #[cfg(not(feature = "baseline"))]
        || cortex_m_demo::run_handshake::<RustCrypto>().is_ok(),
        "krabitls",
    );
    // test_fixture always exits via cortex_m_semihosting::debug::exit, so we
    // never get here; satisfies cortex_m_rt's `fn() -> !` requirement without
    // clippy's empty_loop warning.
    unreachable!()
}
