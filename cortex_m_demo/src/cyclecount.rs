use core::sync::atomic::{AtomicU32, Ordering};

use cortex_m::peripheral::{SYST, syst::SystClkSource};
use cortex_m_rt::exception;

static SYSTICK_WRAPS: AtomicU32 = AtomicU32::new(0);

#[exception]
fn SysTick() {
    let current = SYSTICK_WRAPS.load(Ordering::Relaxed);
    SYSTICK_WRAPS.store(current + 1, Ordering::Relaxed);
}

pub struct CycleCounter {
    start_cycles: u64,
}

impl CycleCounter {
    const RELOAD_VALUE: u32 = 0x00ffffff;

    /// Read total cycles since SysTick was started, with consistency check.
    /// Retries if a wrap interrupt fires between reading counter and wraps.
    ///
    /// **Known limitation (diagnostic-only impact).** If a wrap occurs
    /// while the SysTick exception is masked (`PRIMASK`/`BASEPRI` set,
    /// or a higher-priority exception still executing), the ISR can't
    /// bump `SYSTICK_WRAPS` in time. The `wraps1 == wraps2` guard then
    /// passes spuriously and we under-report by one full period
    /// (16,777,216 cycles ≈ 16 ms at 1 GHz). Detecting that case
    /// requires peeking `SYST_CSR.COUNTFLAG` *and* coordinating with
    /// the ISR to avoid double-counting (e.g. clearing the pended
    /// SysTick bit in `SCB.ICSR` from the user path) — non-trivial.
    /// The demo doesn't enter long critical sections during
    /// measurement and its measured operations all complete in well
    /// under one period, so the race doesn't manifest in practice.
    /// Flagged by gemini-code-assist on PR#1; tracked as future work.
    fn total_cycles() -> u64 {
        let period = Self::RELOAD_VALUE as u64 + 1;
        loop {
            let wraps1 = SYSTICK_WRAPS.load(Ordering::SeqCst);
            let val = SYST::get_current();
            let wraps2 = SYSTICK_WRAPS.load(Ordering::SeqCst);
            if wraps1 == wraps2 {
                // SysTick counts DOWN from reload, so elapsed = reload - val
                return wraps1 as u64 * period + (Self::RELOAD_VALUE as u64 - val as u64);
            }
        }
    }

    // Not `Default`: `new` has side effects (claims SYST peripheral, enables
    // counter + interrupt) and panics if Peripherals::take has already been
    // called. `Default::default()` is the wrong shape for that.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut peripherals = cortex_m::Peripherals::take().unwrap();
        let syst = &mut peripherals.SYST;
        syst.set_clock_source(SystClkSource::Core);
        syst.set_reload(Self::RELOAD_VALUE);
        syst.clear_current();
        syst.enable_interrupt();
        syst.enable_counter();

        // Wait for the counter to load from the reload register.
        cortex_m::asm::dsb();
        while SYST::get_current() == 0 {
            cortex_m::asm::nop();
        }

        Self {
            start_cycles: Self::total_cycles(),
        }
    }

    pub fn elapsed(&self) -> u64 {
        Self::total_cycles() - self.start_cycles
    }
}
