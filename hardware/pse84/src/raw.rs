use crate::{Engine, Pse84CryptoError};
use core::cell::UnsafeCell;
#[cfg(feature = "qualification")]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{Ordering, compiler_fence};
use psoc_pac_pse8x4::{CRYPTO, RegisterValue};
use zeroize::Zeroize;

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
    trng_health_qualified: bool,
}

#[repr(C, align(32))]
struct DmaBlock([u8; 32]);

#[repr(C, align(32))]
struct DmaBuffers {
    key: DmaBlock,
    input: DmaBlock,
    output: DmaBlock,
}

struct DmaStorage(UnsafeCell<DmaBuffers>);

// SAFETY: every access is made while the adapter's global BUSY lock is held.
unsafe impl Sync for DmaStorage {}

#[unsafe(link_section = ".pse84_crypto_dma")]
static DMA_STORAGE: DmaStorage = DmaStorage(UnsafeCell::new(DmaBuffers {
    key: DmaBlock([0; 32]),
    input: DmaBlock([0; 32]),
    output: DmaBlock([0; 32]),
}));

const _: () = assert!(core::mem::size_of::<DmaBlock>() == 32);
const _: () = assert!(core::mem::align_of::<DmaBlock>() == 32);

struct DmaGuard(&'static mut DmaBuffers);

impl DmaGuard {
    fn acquire(key: &[u8; 16], input: &[u8; 16]) -> Self {
        // SAFETY: with_engine holds the global BUSY lock for the guard's entire
        // lifetime, so no other adapter operation can alias this storage.
        let buffers = unsafe { &mut *DMA_STORAGE.0.get() };
        buffers.key.0.fill(0);
        buffers.key.0[..16].copy_from_slice(key);
        buffers.input.0.fill(0);
        buffers.input.0[..16].copy_from_slice(input);
        buffers.output.0.fill(0);
        Self(buffers)
    }
}

impl Drop for DmaGuard {
    fn drop(&mut self) {
        for block in [&mut self.0.key, &mut self.0.input, &mut self.0.output] {
            block.0.zeroize();
            clean_cache(block);
        }
    }
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
            trng_health_qualified: false,
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
            // RCT rejects 32 equal bits. APT rejects 325 occurrences of one
            // value in a complete 512-bit window (WINDOW_SIZE is minus one).
            CRYPTO.tr_mon_rc_ctl().write_raw(32);
            CRYPTO.tr_mon_ap_ctl().write_raw((511 << 16) | 325);
        }
        for _ in 0..WAIT_LIMIT {
            let interrupts = unsafe { CRYPTO.intr().read().get_raw() };
            if interrupts & TR_HEALTH_ERRORS != 0 {
                return Err(Pse84CryptoError::EntropyHealth);
            }
            if interrupts & TR_INITIALIZED != 0 {
                unsafe {
                    CRYPTO.intr().write_raw(TR_INITIALIZED | TR_HEALTH_ERRORS);
                    CRYPTO.tr_mon_cmd().write_raw(3);
                }
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
        let dma = DmaGuard::acquire(key, block);
        clean_cache(&dma.0.key);
        clean_cache(&dma.0.input);
        clean_cache(&dma.0.output);
        let operation = (|| {
            self.start_fifo(LOAD0, dma.0.key.0.as_ptr() as u32, 16)?;
            self.block_move(KEY0, LOAD0, 16)?;
            unsafe { CRYPTO.aes_ctl().write_raw(0) };
            self.wait_idle()?;

            self.start_fifo(LOAD0, dma.0.input.0.as_ptr() as u32, 16)?;
            self.start_fifo(STORE, dma.0.output.0.as_mut_ptr() as u32, 16)?;
            self.block_move(BLOCK0, LOAD0, 16)?;
            self.push(&[AES])?;
            self.block_move(STORE, BLOCK1, 16)?;
            self.wait_idle()
        })();
        if let Err(error) = operation {
            // Halt DMA while its aligned staging buffers are still live.
            force_reset();
            return Err(error);
        }
        invalidate_cache(&mut dma.0.output);
        let mut result = [0; 16];
        result.copy_from_slice(&dma.0.output.0[..16]);
        Ok(result)
    }

    fn random_word(&mut self) -> Result<u32, Pse84CryptoError> {
        self.initialize_trng()?;
        if !self.trng_health_qualified {
            let mut word = 0;
            // Complete one APT window before releasing any entropy. The
            // monitor remains active for all later words in this operation.
            for _ in 0..16 {
                word = self.generate_random_word()?;
            }
            self.trng_health_qualified = true;
            return Ok(word);
        }
        self.generate_random_word()
    }
}

impl Hardware {
    fn generate_random_word(&mut self) -> Result<u32, Pse84CryptoError> {
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

fn clean_cache(block: &DmaBlock) {
    compiler_fence(Ordering::Release);
    cortex_m::asm::dsb();
    if cortex_m::peripheral::SCB::dcache_enabled() {
        // SAFETY: this temporary handle touches only stateless cache-maintenance
        // registers, and the engine lock serializes all adapter maintenance.
        let mut scb = unsafe { cortex_m::Peripherals::steal().SCB };
        scb.clean_dcache_by_address(block as *const DmaBlock as usize, 32);
    }
    compiler_fence(Ordering::Release);
}

fn invalidate_cache(block: &mut DmaBlock) {
    cortex_m::asm::dsb();
    compiler_fence(Ordering::Acquire);
    if cortex_m::peripheral::SCB::dcache_enabled() {
        // SAFETY: see clean_cache; the engine lock excludes concurrent adapter
        // cache maintenance while this temporary handle exists.
        let mut scb = unsafe { cortex_m::Peripherals::steal().SCB };
        // SAFETY: DmaBlock has one complete 32-byte cache line, initialized in
        // main memory before DMA, and the engine lock excludes CPU writers.
        unsafe {
            scb.invalidate_dcache_by_address(block as *mut DmaBlock as usize, 32);
        }
    }
    compiler_fence(Ordering::Acquire);
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

#[cfg(feature = "qualification")]
pub(crate) fn dma_staging_address() -> usize {
    DMA_STORAGE.0.get() as usize
}
