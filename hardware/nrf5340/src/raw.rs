use core::sync::atomic::{AtomicBool, Ordering, compiler_fence};
use zeroize::{Zeroize, Zeroizing};

use crate::{CryptoCellError, EngineGuard};
use nrf_pac as pac;
use pac::cc_aes::vals::{DecKey0, ModeKey0, NkKey0, Status};
use pac::cc_ctl::vals::{CryptoBusyStatus, HashBusyStatus, Mode};
use pac::cc_din::vals::DinDmaMemBusyStatus;
use pac::cc_dout::vals::DoutDmaMemBusyStatus;
use pac::cc_ghash::vals::Status as GhashStatus;
use pac::cc_hash::vals::Engine;
use pac::cc_host_rgf::vals::HostCcIsIdle;

const BLOCK_LEN: usize = 16;
const SPIN_LIMIT: u32 = 1_000_000;

#[cfg(feature = "qualification")]
pub(crate) static FORCE_TIMEOUT: AtomicBool = AtomicBool::new(false);

#[cfg(not(feature = "qualification"))]
static FORCE_TIMEOUT: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Direction {
    Encrypt,
    Decrypt,
}

pub(crate) fn gcm(
    key: &[u8; BLOCK_LEN],
    iv: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
    direction: Direction,
) -> Result<[u8; BLOCK_LEN], CryptoCellError> {
    let guard = EngineGuard::acquire()?;
    power(true);

    let result = gcm_inner(key, iv, aad, data, direction);
    guard.finish()?;
    result
}

fn gcm_inner(
    key: &[u8; BLOCK_LEN],
    iv: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
    direction: Direction,
) -> Result<[u8; BLOCK_LEN], CryptoCellError> {
    let zero = Zeroizing::new([0u8; BLOCK_LEN]);
    let hash_key = Zeroizing::new(aes_block(key, &zero)?);

    let mut j0 = Zeroizing::new([0u8; BLOCK_LEN]);
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;
    let mut counter = Zeroizing::new(*j0);

    if direction == Direction::Encrypt {
        apply_ctr(key, &mut counter, data)?;
    }
    let mut state = ghash_message(&hash_key, aad, data)?;
    if direction == Direction::Decrypt {
        apply_ctr(key, &mut counter, data)?;
    }

    let tag_mask = Zeroizing::new(aes_block(key, &j0)?);
    for (tag, mask) in state.iter_mut().zip(tag_mask.iter()) {
        *tag ^= *mask;
    }

    Ok(state)
}

fn apply_ctr(
    key: &[u8; BLOCK_LEN],
    counter: &mut [u8; BLOCK_LEN],
    data: &mut [u8],
) -> Result<(), CryptoCellError> {
    for chunk in data.chunks_mut(BLOCK_LEN) {
        increment_counter(counter);
        let mut stream = aes_block(key, counter)?;
        for (byte, mask) in chunk.iter_mut().zip(stream.iter()) {
            *byte ^= *mask;
        }
        stream.zeroize();
    }
    Ok(())
}

fn bit_length(bytes: usize) -> u64 {
    (bytes as u64).wrapping_mul(8)
}

fn increment_counter(counter: &mut [u8; BLOCK_LEN]) {
    let next = u32::from_be_bytes(counter[12..].try_into().unwrap()).wrapping_add(1);
    counter[12..].copy_from_slice(&next.to_be_bytes());
}

fn ghash_message(
    hash_key: &[u8; BLOCK_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<[u8; BLOCK_LEN], CryptoCellError> {
    enable_hash_dma_clocks(true);
    prepare(Mode::HashActive)?;
    pac::CC_GHASH_S.ghash_init().write(|w| w.set_enable(true));
    wait_for(|| pac::CC_GHASH_S.ghash_busy().read().status() != GhashStatus::Busy)?;
    for (index, word) in hash_key.chunks_exact(4).enumerate() {
        pac::CC_GHASH_S
            .ghash_subkey(index)
            .write_value(u32::from_le_bytes(word.try_into().unwrap()));
    }
    for index in 0..4 {
        pac::CC_GHASH_S.ghash_iv(index).write_value(0);
    }
    pac::CC_HASH_S
        .hash_select()
        .write(|w| w.set_engine(Engine::Ghash));
    pac::CC_HASH_S.hash_xor_din().write_value(0);

    ghash_padded(aad)?;
    ghash_padded(ciphertext)?;

    let mut lengths = [0u8; BLOCK_LEN];
    lengths[..8].copy_from_slice(&bit_length(aad.len()).to_be_bytes());
    lengths[8..].copy_from_slice(&bit_length(ciphertext.len()).to_be_bytes());
    transfer(lengths.as_ptr(), core::ptr::null_mut(), BLOCK_LEN)?;
    let state = read_ghash_state();
    lengths.zeroize();

    pac::CC_HASH_S
        .hash_select()
        .write(|w| w.set_engine(Engine::Hash));
    enable_hash_dma_clocks(false);
    Ok(state)
}

fn ghash_padded(input: &[u8]) -> Result<(), CryptoCellError> {
    for chunk in input.chunks(BLOCK_LEN) {
        let mut block = [0u8; BLOCK_LEN];
        block[..chunk.len()].copy_from_slice(chunk);
        transfer(block.as_ptr(), core::ptr::null_mut(), BLOCK_LEN)?;
        block.zeroize();
    }
    Ok(())
}

fn read_ghash_state() -> [u8; BLOCK_LEN] {
    let mut state = [0u8; BLOCK_LEN];
    for (index, word) in state.chunks_exact_mut(4).enumerate() {
        word.copy_from_slice(&pac::CC_GHASH_S.ghash_iv(index).read().to_le_bytes());
    }
    state
}

fn aes_block(
    key: &[u8; BLOCK_LEN],
    input: &[u8; BLOCK_LEN],
) -> Result<[u8; BLOCK_LEN], CryptoCellError> {
    enable_aes_dma_clocks(true);
    prepare(Mode::AesActive)?;
    pac::CC_AES_S.aes_control().write(|w| {
        w.set_dec_key0(DecKey0::Encrypt);
        w.set_mode_key0(ModeKey0::Ecb);
        w.set_nk_key0(NkKey0::_128bits);
    });
    pac::CC_AES_S.aes_remaining_bytes().write_value(0);
    for (index, word) in key.chunks_exact(4).enumerate() {
        pac::CC_AES_S
            .aes_key_0(index)
            .write_value(u32::from_le_bytes(word.try_into().unwrap()));
    }

    let mut output = [0u8; BLOCK_LEN];
    let result = transfer(input.as_ptr(), output.as_mut_ptr(), BLOCK_LEN);
    enable_aes_dma_clocks(false);
    match result {
        Ok(()) => Ok(output),
        Err(error) => {
            output.zeroize();
            Err(error)
        }
    }
}

fn prepare(mode: Mode) -> Result<(), CryptoCellError> {
    wait_idle()?;
    pac::CC_HOST_RGF_S.imr().modify(|w| {
        use pac::cc_host_rgf::vals::{DoutToMemMask, DoutToSramMask, MemToDinMask, SramToDinMask};
        w.set_sram_to_din_mask(SramToDinMask::IrqDisable);
        w.set_dout_to_sram_mask(DoutToSramMask::IrqDisable);
        w.set_mem_to_din_mask(MemToDinMask::IrqDisable);
        w.set_dout_to_mem_mask(DoutToMemMask::IrqDisable);
    });
    clear_interrupts();
    pac::CC_CTL_S.crypto_ctl().write(|w| w.set_mode(mode));
    Ok(())
}

fn transfer(input: *const u8, output: *mut u8, len: usize) -> Result<(), CryptoCellError> {
    compiler_fence(Ordering::SeqCst);
    if !output.is_null() {
        pac::CC_DOUT_S.dst_mem_addr().write_value(output as u32);
        pac::CC_DOUT_S
            .dst_mem_size()
            .write(|w| w.set_size(len as u32));
    }
    pac::CC_DIN_S.src_mem_addr().write_value(input as u32);
    pac::CC_DIN_S
        .src_mem_size()
        .write(|w| w.set_size(len as u32));

    let complete = || {
        let interrupts = pac::CC_HOST_RGF_S.irr().read();
        if output.is_null() {
            interrupts.sym_dma_int()
        } else {
            interrupts.dout_to_mem_int()
        }
    };
    wait_for_transfer(complete)?;
    wait_idle()?;
    compiler_fence(Ordering::SeqCst);
    clear_interrupts();
    Ok(())
}

fn wait_idle() -> Result<(), CryptoCellError> {
    wait_for(|| {
        pac::CC_CTL_S.crypto_busy().read().status() != CryptoBusyStatus::Busy
            && pac::CC_CTL_S.hash_busy().read().status() != HashBusyStatus::Busy
            && pac::CC_AES_S.aes_busy().read().status() != Status::Busy
            && pac::CC_GHASH_S.ghash_busy().read().status() != GhashStatus::Busy
    })
}

fn wait_for(mut ready: impl FnMut() -> bool) -> Result<(), CryptoCellError> {
    for _ in 0..SPIN_LIMIT {
        if ready() {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(CryptoCellError::Timeout)
}

fn wait_for_transfer(mut complete: impl FnMut() -> bool) -> Result<(), CryptoCellError> {
    let force_timeout = FORCE_TIMEOUT.swap(false, Ordering::AcqRel);
    for _ in 0..SPIN_LIMIT {
        if !force_timeout {
            if pac::CC_HOST_RGF_S.irr().read().ahb_err_int() {
                return Err(CryptoCellError::Hardware);
            }
            if complete() {
                return Ok(());
            }
        }
        core::hint::spin_loop();
    }
    Err(CryptoCellError::Timeout)
}

fn clear_interrupts() {
    pac::CC_HOST_RGF_S.icr().write(|w| w.0 = u32::MAX);
}

fn clear_all_interrupts() {
    clear_interrupts();
    pac::CC_RNG_S.rng_clk().write(|w| w.set_enable(true));
    pac::CC_RNG_S.rng_icr().write(|w| w.0 = u32::MAX);
    pac::CC_RNG_S.rng_clk().write(|w| w.set_enable(false));
}

fn enable_aes_dma_clocks(enable: bool) {
    pac::CC_MISC_S.aes_clk().write(|w| w.set_enable(enable));
    pac::CC_MISC_S.dma_clk().write(|w| w.set_enable(enable));
}

fn enable_hash_dma_clocks(enable: bool) {
    pac::CC_MISC_S.hash_clk().write(|w| w.set_enable(enable));
    pac::CC_MISC_S.dma_clk().write(|w| w.set_enable(enable));
}

fn power(enable: bool) {
    pac::CRYPTOCELL_S.enable().write(|w| w.set_enable(enable));
}

pub(crate) fn cleanup() -> Result<(), CryptoCellError> {
    enable_aes_dma_clocks(true);
    enable_hash_dma_clocks(true);

    pac::CC_DIN_S.din_sw_reset().write(|w| w.set_reset(true));
    pac::CC_DOUT_S.dout_sw_reset().write(|w| w.set_reset(true));
    pac::CC_DIN_S.din_fifo_reset().write(|w| w.set_reset(true));
    for _ in 0..8 {
        core::hint::spin_loop();
    }
    compiler_fence(Ordering::SeqCst);
    pac::CC_CTL_S
        .crypto_ctl()
        .write(|w| w.set_mode(Mode::Bypass));

    let idle = wait_for(|| {
        pac::CC_DIN_S.din_dma_mem_busy().read().status() == DinDmaMemBusyStatus::Idle
            && pac::CC_DOUT_S.dout_dma_mem_busy().read().status() == DoutDmaMemBusyStatus::Idle
            && pac::CC_HOST_RGF_S
                .host_cc_is_idle()
                .read()
                .host_cc_is_idle()
                == HostCcIsIdle::Idle
    });
    if idle.is_err() {
        clear_all_interrupts();
        power(false);
        return Err(CryptoCellError::Hardware);
    }

    for index in 0..4 {
        pac::CC_AES_S.aes_key_0(index).write_value(0);
    }
    pac::CC_AES_S.aes_remaining_bytes().write_value(0);
    for index in 0..4 {
        pac::CC_GHASH_S.ghash_subkey(index).write_value(0);
        pac::CC_GHASH_S.ghash_iv(index).write_value(0);
    }
    clear_all_interrupts();
    enable_aes_dma_clocks(false);
    enable_hash_dma_clocks(false);
    Ok(())
}

pub(crate) fn shutdown() -> Result<(), CryptoCellError> {
    if !pac::CRYPTOCELL_S.enable().read().enable() {
        return Ok(());
    }
    cleanup()?;
    pac::CC_HOST_RGF_S
        .host_powerdown()
        .write(|w| w.set_host_powerdown(true));
    power(false);
    Ok(())
}

#[cfg(feature = "qualification")]
pub(crate) fn observable_state_cleared() -> bool {
    (0..4).all(|index| pac::CC_GHASH_S.ghash_iv(index).read() == 0)
        && pac::CC_HOST_RGF_S
            .host_cc_is_idle()
            .read()
            .host_cc_is_idle()
            == HostCcIsIdle::Idle
}

#[cfg(feature = "qualification")]
pub(crate) fn subsystem_disabled() -> bool {
    !pac::CRYPTOCELL_S.enable().read().enable()
}
