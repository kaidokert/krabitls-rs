use crate::{Engine, Pse84CryptoError};
#[cfg(feature = "qualification")]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{Ordering, compiler_fence};
use psoc_pac_pse8x4::{CRYPTO, RegisterValue};

const WAIT_LIMIT: usize = 2_000_000;
const ERROR_MASK: u32 = 0x003f_0000;
const TR_INITIALIZED: u32 = 1 << 2;
const TR_DATA_AVAILABLE: u32 = 1 << 3;
const TR_HEALTH_ERRORS: u32 = (1 << 19) | (1 << 20);

const FF_START: u32 = 0x70 << 24;
const BLOCK_MOV: u32 = 0x40 << 24;
const AES: u32 = 0x50 << 24;
const RB_CLEAR: u32 = 0x64 << 24;
const LOAD0: u32 = 8;
const STORE: u32 = 12;
const BLOCK0: u32 = 0;
const BLOCK1: u32 = 1;
const KEY0: u32 = 4;

#[cfg(feature = "qualification")]
static FORCE_TIMEOUT: AtomicBool = AtomicBool::new(false);

pub(crate) struct Hardware {
    trng_initialized: bool,
}

impl Hardware {
    pub(crate) fn start() -> Result<Self, Pse84CryptoError> {
        force_reset();
        // BLOCK=0 is intentional: software checks FIFO capacity, so a bad
        // peripheral state cannot hold the CPU in an unbounded AHB wait state.
        unsafe {
            CRYPTO.instr_ff_ctl().write_raw(1);
            CRYPTO.ctl().write_raw(1 << 31);
            CRYPTO.ram_pwr_ctl().write_raw(3);
            CRYPTO.intr().write_raw(u32::MAX);
        }
        Ok(Self {
            trng_initialized: false,
        })
    }

    pub(crate) fn finish(mut self) -> Result<(), Pse84CryptoError> {
        let result = self.clear_register_file();
        clear_sensitive_registers();
        force_reset();
        result
    }

    fn clear_register_file(&mut self) -> Result<(), Pse84CryptoError> {
        self.push(&[RB_CLEAR])?;
        self.wait_idle()
    }

    fn push(&mut self, words: &[u32]) -> Result<(), Pse84CryptoError> {
        for _ in 0..WAIT_LIMIT {
            let used = unsafe { CRYPTO.instr_ff_status().read().get_raw() } & 0xf;
            if used + words.len() as u32 <= 8 {
                for word in words {
                    unsafe { CRYPTO.instr_ff_wr().write_raw(*word) };
                }
                return self.check_errors();
            }
        }
        Err(Pse84CryptoError::Timeout)
    }

    fn wait_idle(&mut self) -> Result<(), Pse84CryptoError> {
        for _ in 0..WAIT_LIMIT {
            self.check_errors()?;
            if unsafe { CRYPTO.status().read().get_raw() } & (1 << 31) == 0 {
                compiler_fence(Ordering::Acquire);
                return Ok(());
            }
        }
        Err(Pse84CryptoError::Timeout)
    }

    fn check_errors(&self) -> Result<(), Pse84CryptoError> {
        if unsafe { CRYPTO.intr().read().get_raw() } & ERROR_MASK != 0 {
            Err(Pse84CryptoError::Hardware)
        } else {
            Ok(())
        }
    }

    fn start_fifo(
        &mut self,
        resource: u32,
        address: u32,
        size: u32,
    ) -> Result<(), Pse84CryptoError> {
        self.push(&[FF_START | resource, address, size])
    }

    fn block_move(
        &mut self,
        destination: u32,
        source: u32,
        size: u32,
    ) -> Result<(), Pse84CryptoError> {
        self.push(&[BLOCK_MOV | (size << 16) | (destination << 12) | source])
    }

    fn initialize_trng(&mut self) -> Result<(), Pse84CryptoError> {
        if self.trng_initialized {
            return Ok(());
        }
        unsafe {
            CRYPTO.tr_mon_cmd().write_raw(0);
            CRYPTO.tr_ctl1().write_raw(0);
            CRYPTO
                .intr()
                .write_raw(TR_INITIALIZED | TR_DATA_AVAILABLE | TR_HEALTH_ERRORS);
            CRYPTO.tr_garo_ctl().write_raw(0x04c1_1db7);
            CRYPTO.tr_firo_ctl().write_raw(0x04c1_1db7);
            // INIT_DELAY=3, Von Neumann corrector, stop on AP and RC faults.
            CRYPTO
                .tr_ctl0()
                .write_raw((3 << 16) | (1 << 24) | (1 << 28) | (1 << 29));
            // Enable all six documented oscillator sources.
            CRYPTO.tr_ctl1().write_raw(0x3f);
            CRYPTO.tr_mon_ctl().write_raw(2);
            CRYPTO.tr_mon_rc_ctl().write_raw(255);
            CRYPTO.tr_mon_ap_ctl().write_raw(u32::MAX);
            CRYPTO.tr_mon_cmd().write_raw(3);
        }
        for _ in 0..WAIT_LIMIT {
            let interrupts = unsafe { CRYPTO.intr().read().get_raw() };
            if interrupts & TR_HEALTH_ERRORS != 0 {
                return Err(Pse84CryptoError::EntropyHealth);
            }
            if interrupts & TR_INITIALIZED != 0 {
                unsafe { CRYPTO.intr().write_raw(TR_INITIALIZED) };
                self.trng_initialized = true;
                return Ok(());
            }
        }
        Err(Pse84CryptoError::Timeout)
    }
}

impl Engine for Hardware {
    fn encrypt_block(
        &mut self,
        key: &[u8; 16],
        block: &[u8; 16],
    ) -> Result<[u8; 16], Pse84CryptoError> {
        #[cfg(feature = "qualification")]
        if FORCE_TIMEOUT.swap(false, Ordering::AcqRel) {
            return Err(Pse84CryptoError::Timeout);
        }
        let mut output = [0u8; 16];
        compiler_fence(Ordering::Release);
        self.start_fifo(LOAD0, key.as_ptr() as u32, 16)?;
        self.block_move(KEY0, LOAD0, 16)?;
        unsafe { CRYPTO.aes_ctl().write_raw(0) };
        self.wait_idle()?;

        self.start_fifo(LOAD0, block.as_ptr() as u32, 16)?;
        self.start_fifo(STORE, output.as_mut_ptr() as u32, 16)?;
        self.block_move(BLOCK0, LOAD0, 16)?;
        self.push(&[AES])?;
        self.block_move(STORE, BLOCK1, 16)?;
        self.wait_idle()?;
        // The volatile store completed before wait_idle returned; acquire fence
        // makes those bytes visible before returning the DMA buffer.
        compiler_fence(Ordering::Acquire);
        Ok(output)
    }

    fn random_word(&mut self) -> Result<u32, Pse84CryptoError> {
        self.initialize_trng()?;
        unsafe {
            CRYPTO.intr().write_raw(TR_DATA_AVAILABLE);
            CRYPTO.tr_ctl2().write_raw(32);
            CRYPTO.tr_cmd().write_raw(1);
        }
        for _ in 0..WAIT_LIMIT {
            let interrupts = unsafe { CRYPTO.intr().read().get_raw() };
            if interrupts & TR_HEALTH_ERRORS != 0 {
                return Err(Pse84CryptoError::EntropyHealth);
            }
            if interrupts & TR_DATA_AVAILABLE != 0 {
                let value = unsafe { CRYPTO.tr_result().read().get_raw() };
                unsafe {
                    CRYPTO.tr_result().write_raw(0);
                    CRYPTO.intr().write_raw(TR_DATA_AVAILABLE);
                }
                return Ok(value);
            }
        }
        Err(Pse84CryptoError::Timeout)
    }
}

pub(crate) fn force_reset() {
    clear_sensitive_registers();
    unsafe {
        CRYPTO.ctl().write_raw(0);
        CRYPTO.ram_pwr_ctl().write_raw(0);
    }
}

fn clear_sensitive_registers() {
    unsafe {
        CRYPTO.tr_mon_cmd().write_raw(0);
        CRYPTO.tr_ctl1().write_raw(0);
        CRYPTO.tr_ctl2().write_raw(0);
        CRYPTO.tr_result().write_raw(0);
        CRYPTO.aes_ctl().write_raw(0);
    }
}

#[cfg(feature = "qualification")]
pub(crate) fn force_next_timeout() {
    FORCE_TIMEOUT.store(true, Ordering::Release);
}

#[cfg(feature = "qualification")]
pub(crate) fn peripheral_disabled() -> bool {
    unsafe {
        CRYPTO.ctl().read().get_raw() & (1 << 31) == 0
            && CRYPTO.ram_pwr_ctl().read().get_raw() & 3 == 0
    }
}
