//! STM32H533 PKA (Public Key Accelerator) drivers: modular exponentiation
//! (`base^exp mod n`, backs RSA verify) and native ECDSA-P256 verification.
//!
//! The PAC does not model the PKA RAM window, so operands are accessed via raw
//! volatile pointers at `PKA_base + 0x400` (= 0x420C_2400), word-indexed
//! (`word = (RM0481 byte_offset - 0x400)/4`). Numbers are little-endian by
//! 32-bit word (least-significant word at the lowest offset), each word packed
//! LSB-first from the big-endian input; every operand is followed by a two-zero
//! `__PKA_RAM_PARAM_END` terminator. The AHB2 PKA clock must be enabled
//! ([`crate::enable_crypto_clocks`]).

use stm32h5::stm32h533 as pac;

const MAX_BYTES: usize = 256; // 2048-bit max operand width
const MAX_WORDS: usize = MAX_BYTES / 4;
const SPIN: u32 = 20_000_000;

#[inline(always)]
fn pka_ram_ptr() -> *mut u32 {
    (pac::PKA::ptr() as usize + 0x400) as *mut u32
}
#[inline(always)]
unsafe fn ram_w(i: usize, v: u32) {
    unsafe { core::ptr::write_volatile(pka_ram_ptr().add(i), v) }
}
#[inline(always)]
unsafe fn ram_r(i: usize) -> u32 {
    unsafe { core::ptr::read_volatile(pka_ram_ptr().add(i)) }
}

/// Enable PKA (writes are ignored during RAM erase, so hammer EN) and wait for
/// INITOK; clear stale flags. Returns false on timeout.
fn pka_enable(pka: &pac::pka::RegisterBlock) -> bool {
    let mut spun = 0u32;
    while pka.cr().read().en().bit_is_clear() && spun < SPIN {
        pka.cr().write(|w| w.en().set_bit());
        spun += 1;
    }
    spun = 0;
    while pka.sr().read().initok().bit_is_clear() && spun < SPIN {
        spun += 1;
    }
    clear_flags(pka);
    pka.sr().read().initok().bit_is_set()
}

fn clear_flags(pka: &pac::pka::RegisterBlock) {
    pka.clrfr().write(|w| {
        w.procendfc().set_bit();
        w.ramerrfc().set_bit();
        w.addrerrfc().set_bit();
        w.operrfc().set_bit()
    });
}

/// Set MODE (preserving EN), START, poll PROCENDF, check HW error flags, clear.
/// Returns true iff the op completed with no hardware/RAM/address error.
fn pka_run(pka: &pac::pka::RegisterBlock, mode: u8) -> bool {
    pka.cr().modify(|_, w| unsafe { w.mode().bits(mode) });
    pka.cr().modify(|_, w| w.start().set_bit());
    let mut spun = 0u32;
    while pka.sr().read().procendf().bit_is_clear() && spun < SPIN {
        spun += 1;
    }
    let sr = pka.sr().read();
    let ok = sr.procendf().bit_is_set()
        && sr.ramerrf().bit_is_clear()
        && sr.addrerrf().bit_is_clear()
        && sr.operrf().bit_is_clear();
    clear_flags(pka);
    ok
}

/// Pack a big-endian operand into `word_count` little-endian-ordered PKA words
/// (LSW first), zero-padded, at `base_word`, then the two-zero terminator.
unsafe fn write_operand_be(base_word: usize, be: &[u8], word_count: usize) {
    let mut words = [0u32; MAX_WORDS];
    for (i, &b) in be.iter().rev().enumerate() {
        let w = i / 4;
        if w >= word_count {
            break;
        }
        words[w] |= (b as u32) << ((i % 4) * 8);
    }
    unsafe {
        for (w, word) in words.iter().take(word_count).enumerate() {
            ram_w(base_word + w, *word);
        }
        ram_w(base_word + word_count, 0);
        ram_w(base_word + word_count + 1, 0);
    }
}

/// Read `word_count` PKA words at `base_word` into a big-endian buffer,
/// right-aligned into `out[..word_count*4]`.
unsafe fn read_operand_be(base_word: usize, out: &mut [u8], word_count: usize) {
    for w in 0..word_count {
        let v = unsafe { ram_r(base_word + w) };
        let bb = (word_count - 1 - w) * 4; // MSW -> lowest out index
        out[bb] = (v >> 24) as u8;
        out[bb + 1] = (v >> 16) as u8;
        out[bb + 2] = (v >> 8) as u8;
        out[bb + 3] = v as u8;
    }
}

unsafe fn read_operand_width(base_word: usize, out: &mut [u8], byte_count: usize) {
    let words = byte_count.div_ceil(4);
    let mut padded = [0u8; MAX_BYTES];
    unsafe { read_operand_be(base_word, &mut padded[..words * 4], words) };
    out[..byte_count].copy_from_slice(&padded[words * 4 - byte_count..words * 4]);
}

// ======================= Modular exponentiation =======================
// RAM word indices (from stm32h533xx.h): word = (byte_offset - 0x400)/4.
const MODEXP_EXP_NB_BITS: usize = 0;
const MODEXP_OP_NB_BITS: usize = 2;
const MODEXP_BASE: usize = 538;
const MODEXP_EXPONENT: usize = 670;
const MODEXP_MODULUS: usize = 802;
const MODEXP_RESULT: usize = 270;
const MODEXP_ERROR: usize = 934; // 0 = PKA_NO_ERROR
const MODE_MODULAR_EXP: u8 = 0x00; // computes Montgomery param internally

/// `base^exp mod modulus`, all big-endian; `modulus` must be odd.
///
/// Returns the result big-endian, right-aligned into `out[..modulus.len()]`,
/// and whether the operation succeeded. This is exactly the `s^e mod n` that
/// RSA verification's `PowBoundedExp::pow_bounded_exp` computes.
pub fn modexp(base: &[u8], exp: &[u8], modulus: &[u8], out: &mut [u8]) -> bool {
    let op_bytes = modulus.len();
    if op_bytes == 0
        || op_bytes > MAX_BYTES
        || out.len() < op_bytes
        || (modulus[op_bytes - 1] & 1) == 0
    {
        return false;
    }
    let op_words = op_bytes.div_ceil(4);
    let exp_bytes = exp.len().max(1);
    let exp_words = exp_bytes.div_ceil(4);

    let pka = unsafe { &*pac::PKA::ptr() };
    if !pka_enable(pka) {
        return false;
    }
    unsafe {
        ram_w(MODEXP_OP_NB_BITS, (op_bytes as u32) * 8); // lengths in BITS
        ram_w(MODEXP_EXP_NB_BITS, (exp_bytes as u32) * 8);
        write_operand_be(MODEXP_BASE, base, op_words);
        write_operand_be(MODEXP_EXPONENT, exp, exp_words);
        write_operand_be(MODEXP_MODULUS, modulus, op_words);
    }
    if !pka_run(pka, MODE_MODULAR_EXP) {
        return false;
    }
    if unsafe { ram_r(MODEXP_ERROR) } != 0 {
        return false;
    }
    unsafe { read_operand_width(MODEXP_RESULT, out, op_bytes) };
    true
}

// ======================= Modular field arithmetic =======================
// The arithmetic commands share one operand layout in the PKA RAM.
const ARITH_NB_BITS: usize = 2;
const ARITH_OP1: usize = 404;
const ARITH_OP2: usize = 538;
const ARITH_MODULUS: usize = 802;
const ARITH_RESULT: usize = 670;
const MODRED_OP_NB_BITS: usize = 0;
const MODRED_MOD_NB_BITS: usize = 2;
const MODE_ARITH_MUL: u8 = 0x0b;
const MODE_MOD_REDUCE: u8 = 0x0d;
const MODE_MOD_ADD: u8 = 0x0e;
const MODE_MOD_SUB: u8 = 0x0f;

fn modular_binary(lhs: &[u8], rhs: &[u8], modulus: &[u8], out: &mut [u8], mode: u8) -> bool {
    let bytes = modulus.len();
    if bytes == 0
        || bytes > MAX_BYTES
        || lhs.len() > bytes
        || rhs.len() > bytes
        || out.len() < bytes
        || modulus[bytes - 1] & 1 == 0
    {
        return false;
    }
    let words = bytes.div_ceil(4);
    let pka = unsafe { &*pac::PKA::ptr() };
    if !pka_enable(pka) {
        return false;
    }
    unsafe {
        ram_w(ARITH_NB_BITS, (bytes * 8) as u32);
        write_operand_be(ARITH_OP1, lhs, words);
        write_operand_be(ARITH_OP2, rhs, words);
        write_operand_be(ARITH_MODULUS, modulus, words);
    }
    if !pka_run(pka, mode) {
        return false;
    }
    unsafe { read_operand_width(ARITH_RESULT, out, bytes) };
    true
}

/// `(lhs + rhs) mod modulus`, using modulus-width big-endian values.
pub fn mod_add(lhs: &[u8], rhs: &[u8], modulus: &[u8], out: &mut [u8]) -> bool {
    modular_binary(lhs, rhs, modulus, out, MODE_MOD_ADD)
}

/// `(lhs - rhs) mod modulus`, using modulus-width big-endian values.
pub fn mod_sub(lhs: &[u8], rhs: &[u8], modulus: &[u8], out: &mut [u8]) -> bool {
    modular_binary(lhs, rhs, modulus, out, MODE_MOD_SUB)
}

/// `(lhs * rhs) mod modulus`. PKA arithmetic multiplication produces the wide
/// product, which is immediately fed to its modular-reduction command.
pub fn mod_mul(lhs: &[u8], rhs: &[u8], modulus: &[u8], out: &mut [u8]) -> bool {
    let bytes = modulus.len();
    if bytes == 0
        || bytes > MAX_BYTES / 2
        || lhs.len() > bytes
        || rhs.len() > bytes
        || out.len() < bytes
        || modulus[bytes - 1] & 1 == 0
    {
        return false;
    }
    let words = bytes.div_ceil(4);
    let pka = unsafe { &*pac::PKA::ptr() };
    if !pka_enable(pka) {
        return false;
    }
    unsafe {
        ram_w(ARITH_NB_BITS, (bytes * 8) as u32);
        write_operand_be(ARITH_OP1, lhs, words);
        write_operand_be(ARITH_OP2, rhs, words);
    }
    if !pka_run(pka, MODE_ARITH_MUL) {
        return false;
    }
    let mut product = zeroize::Zeroizing::new([0u8; MAX_BYTES]);
    unsafe { read_operand_be(ARITH_RESULT, &mut product[..words * 8], words * 2) };

    if !pka_enable(pka) {
        return false;
    }
    unsafe {
        ram_w(MODRED_OP_NB_BITS, (bytes * 16) as u32);
        ram_w(MODRED_MOD_NB_BITS, (bytes * 8) as u32);
        write_operand_be(ARITH_OP1, &product[..words * 8], words * 2);
        write_operand_be(ARITH_OP2, modulus, words);
    }
    if !pka_run(pka, MODE_MOD_REDUCE) {
        return false;
    }
    unsafe { read_operand_width(ARITH_RESULT, out, bytes) };
    true
}

fn clear_arithmetic_ram(words: usize) {
    unsafe {
        for base in [ARITH_OP1, ARITH_OP2, ARITH_MODULUS, ARITH_RESULT] {
            for index in 0..words * 2 + 2 {
                ram_w(base + index, 0);
            }
        }
        for index in 0..words + 2 {
            ram_w(MODEXP_RESULT + index, 0);
        }
    }
}

const P25519: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed,
];
const P25519_MINUS_2: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xeb,
];
const X25519_A24: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    0xdb, 0x41,
];

fn cswap(swap: u8, lhs: &mut [u8; 32], rhs: &mut [u8; 32]) {
    let mask = 0u8.wrapping_sub(swap);
    for i in 0..32 {
        let selected = mask & (lhs[i] ^ rhs[i]);
        lhs[i] ^= selected;
        rhs[i] ^= selected;
    }
}

/// RFC 7748 X25519 using a fixed-command Montgomery ladder. Field add,
/// subtract, multiply/reduce, and final inversion all execute on the PKA.
pub fn x25519(scalar_le: &[u8; 32], peer_u_le: &[u8; 32], output_le: &mut [u8; 32]) -> bool {
    let mut scalar = zeroize::Zeroizing::new(*scalar_le);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    let mut x1 = [0u8; 32];
    for i in 0..32 {
        x1[31 - i] = peer_u_le[i];
    }
    x1[0] &= 0x7f;
    // Inputs are interpreted modulo p by RFC 7748.
    if x1 >= P25519 {
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let value = x1[i] as i16 - P25519[i] as i16 - borrow;
            x1[i] = value as u8;
            borrow = i16::from(value < 0);
        }
    }

    let mut x2 = zeroize::Zeroizing::new([0u8; 32]);
    x2[31] = 1;
    let mut z2 = zeroize::Zeroizing::new([0u8; 32]);
    let mut x3 = zeroize::Zeroizing::new(x1);
    let mut z3 = zeroize::Zeroizing::new([0u8; 32]);
    z3[31] = 1;
    let mut swap = 0u8;
    let mut ok = true;
    for t in (0..255).rev() {
        let bit = (scalar[t / 8] >> (t & 7)) & 1;
        swap ^= bit;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = bit;

        let mut a = zeroize::Zeroizing::new([0u8; 32]);
        let mut aa = zeroize::Zeroizing::new([0u8; 32]);
        let mut b = zeroize::Zeroizing::new([0u8; 32]);
        let mut bb = zeroize::Zeroizing::new([0u8; 32]);
        let mut e = zeroize::Zeroizing::new([0u8; 32]);
        let mut c = zeroize::Zeroizing::new([0u8; 32]);
        let mut d = zeroize::Zeroizing::new([0u8; 32]);
        let mut da = zeroize::Zeroizing::new([0u8; 32]);
        let mut cb = zeroize::Zeroizing::new([0u8; 32]);
        let mut sum = zeroize::Zeroizing::new([0u8; 32]);
        let mut diff = zeroize::Zeroizing::new([0u8; 32]);
        let mut tmp = zeroize::Zeroizing::new([0u8; 32]);
        ok &= mod_add(&x2[..], &z2[..], &P25519, &mut a[..]);
        ok &= mod_mul(&a[..], &a[..], &P25519, &mut aa[..]);
        ok &= mod_sub(&x2[..], &z2[..], &P25519, &mut b[..]);
        ok &= mod_mul(&b[..], &b[..], &P25519, &mut bb[..]);
        ok &= mod_sub(&aa[..], &bb[..], &P25519, &mut e[..]);
        ok &= mod_add(&x3[..], &z3[..], &P25519, &mut c[..]);
        ok &= mod_sub(&x3[..], &z3[..], &P25519, &mut d[..]);
        ok &= mod_mul(&d[..], &a[..], &P25519, &mut da[..]);
        ok &= mod_mul(&c[..], &b[..], &P25519, &mut cb[..]);
        ok &= mod_add(&da[..], &cb[..], &P25519, &mut sum[..]);
        ok &= mod_mul(&sum[..], &sum[..], &P25519, &mut x3[..]);
        ok &= mod_sub(&da[..], &cb[..], &P25519, &mut diff[..]);
        ok &= mod_mul(&diff[..], &diff[..], &P25519, &mut tmp[..]);
        ok &= mod_mul(&x1, &tmp[..], &P25519, &mut z3[..]);
        ok &= mod_mul(&aa[..], &bb[..], &P25519, &mut x2[..]);
        ok &= mod_mul(&X25519_A24, &e[..], &P25519, &mut tmp[..]);
        ok &= mod_add(&aa[..], &tmp[..], &P25519, &mut sum[..]);
        ok &= mod_mul(&e[..], &sum[..], &P25519, &mut z2[..]);
        if !ok {
            break;
        }
    }
    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);
    let mut inverse = zeroize::Zeroizing::new([0u8; 32]);
    let mut result = zeroize::Zeroizing::new([0u8; 32]);
    ok &= modexp(&z2[..], &P25519_MINUS_2, &P25519, &mut inverse[..]);
    ok &= mod_mul(&x2[..], &inverse[..], &P25519, &mut result[..]);
    if ok {
        for i in 0..32 {
            output_le[i] = result[31 - i];
        }
    }
    clear_arithmetic_ram(8);
    ok
}

// ======================= ECDSA P-256 verification =======================
// P-256 (secp256r1) constants, 32-byte big-endian (ST prime256v1.c).
const P256_P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const P256_A_SIGN: u32 = 1; // a = -3 mod p: sign = negative, |a| = 3
const P256_A_ABS: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0x03,
];
// Generic ECC multiplication takes a positive coefficient rather than the
// sign/magnitude pair used by the dedicated ECDSA commands.
const P256_A_POS: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
];
const P256_GX: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];
const P256_GY: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

// ECDSA-verify RAM word indices (from stm32h533xx.h).
const W_ORDER_NB_BITS: usize = 2;
const W_MOD_NB_BITS: usize = 50;
const W_A_SIGN: usize = 26;
const W_A_COEFF: usize = 28;
const W_MOD_P: usize = 52;
const W_GX: usize = 158;
const W_GY: usize = 180;
const W_QX: usize = 958;
const W_QY: usize = 980;
const W_SIG_R: usize = 824;
const W_SIG_S: usize = 538;
const W_HASH: usize = 1002;
const W_ORDER_N: usize = 802;
const W_RESULT: usize = 116;
const MODE_ECDSA_VERIFY: u8 = 0x26;
const ECDSA_VALID_MAGIC: u32 = 0xD60D;

/// Write a 32-byte big-endian operand (8 words LSW-first + terminator).
unsafe fn write_be32(base: usize, be: &[u8; 32]) {
    unsafe { write_operand_be(base, be, 8) }
}

/// Software range check: scalar in [1, n-1]. BE arrays compare lexicographically.
fn scalar_in_range(x: &[u8; 32]) -> bool {
    x.iter().any(|&b| b != 0) && *x < P256_N
}

/// Verify an ECDSA-P256 signature `(r, s)` over `hash` for public key `(qx, qy)`.
/// All inputs are 32-byte big-endian. Returns true iff valid.
///
/// The PKA does not range-check r,s — we reject out-of-range scalars in software
/// first (standard ECDSA step 1), matching what the software crate does.
pub fn ecdsa_p256_verify(
    qx: &[u8; 32],
    qy: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    hash: &[u8; 32],
) -> bool {
    if !scalar_in_range(r) || !scalar_in_range(s) {
        return false;
    }
    let pka = unsafe { &*pac::PKA::ptr() };
    if !pka_enable(pka) {
        return false;
    }
    unsafe {
        ram_w(W_ORDER_NB_BITS, 256);
        ram_w(W_MOD_NB_BITS, 256);
        ram_w(W_A_SIGN, P256_A_SIGN);
        write_be32(W_A_COEFF, &P256_A_ABS);
        write_be32(W_MOD_P, &P256_P);
        write_be32(W_GX, &P256_GX);
        write_be32(W_GY, &P256_GY);
        write_be32(W_QX, qx);
        write_be32(W_QY, qy);
        write_be32(W_SIG_R, r);
        write_be32(W_SIG_S, s);
        write_be32(W_HASH, hash);
        write_be32(W_ORDER_N, &P256_N);
    }
    if !pka_run(pka, MODE_ECDSA_VERIFY) {
        return false;
    }
    unsafe { ram_r(W_RESULT) == ECDSA_VALID_MAGIC }
}

// ============= Generic ECC Fp scalar multiplication [k]P (MODE 0x20) =============
// RAM word indices from stm32h533xx.h. `a` is supplied as a full positive
// field value (sign=0). `b` and the curve order `n` are mandatory inputs.
const ECCMUL_EXP_NB_BITS: usize = 0; // 0x400: bit-length of order n
const ECCMUL_OP_NB_BITS: usize = 2; // 0x408: bit-length of modulus p
const ECCMUL_A_SIGN: usize = 4; // 0x410
const ECCMUL_A_COEFF: usize = 6; // 0x418: |a|
const ECCMUL_B_COEFF: usize = 72; // 0x520
const ECCMUL_MOD_P: usize = 802; // 0x1088
const ECCMUL_K: usize = 936; // 0x12A0
const ECCMUL_PX: usize = 94; // 0x578 (result Xr overwrites this)
const ECCMUL_PY: usize = 28; // 0x470
const ECCMUL_N: usize = 738; // 0xF88
const ECCMUL_OUT_X: usize = 94; // 0x578
const ECCMUL_OUT_Y: usize = 116; // 0x5D0
const ECCMUL_OUT_ERROR: usize = 160; // 0x680
const MODE_ECC_MUL: u8 = 0x20;

/// Exact MSB-based bit length of a 32-byte big-endian value (matches HAL
/// `PKA_GetOptBitSize_u8`).
fn bit_len_be(x: &[u8; 32]) -> u32 {
    for (i, &b) in x.iter().enumerate() {
        if b != 0 {
            return ((31 - i) as u32) * 8 + (8 - b.leading_zeros());
        }
    }
    0
}

/// Generic short-Weierstrass scalar multiplication `[k]·P = (Xr, Yr)` over
/// `y^2 = x^3 + a*x + b (mod p)`, all 32-byte big-endian (256-bit operands).
///
/// `a` is passed as its full positive value (sign forced to 0). `b` and `n`
/// (curve order) are mandatory. The hardware does NOT verify P is on-curve — the
/// caller must ensure it. Returns true and fills `out_x`/`out_y` iff the op
/// succeeded (`OUT_ERROR == 0xD60D`).
#[allow(clippy::too_many_arguments)]
pub fn ecc_scalar_mul(
    p: &[u8; 32],
    a: &[u8; 32],
    b: &[u8; 32],
    n: &[u8; 32],
    k: &[u8; 32],
    px: &[u8; 32],
    py: &[u8; 32],
    out_x: &mut [u8; 32],
    out_y: &mut [u8; 32],
) -> bool {
    let pka = unsafe { &*pac::PKA::ptr() };
    if !pka_enable(pka) {
        return false;
    }
    unsafe {
        ram_w(ECCMUL_EXP_NB_BITS, bit_len_be(n));
        ram_w(ECCMUL_OP_NB_BITS, bit_len_be(p));
        ram_w(ECCMUL_A_SIGN, 0); // a positive
        write_operand_be(ECCMUL_A_COEFF, a, 8);
        write_operand_be(ECCMUL_B_COEFF, b, 8);
        write_operand_be(ECCMUL_MOD_P, p, 8);
        write_operand_be(ECCMUL_K, k, 8);
        write_operand_be(ECCMUL_PX, px, 8);
        write_operand_be(ECCMUL_PY, py, 8);
        write_operand_be(ECCMUL_N, n, 8);
    }
    let ok = pka_run(pka, MODE_ECC_MUL) && unsafe { ram_r(ECCMUL_OUT_ERROR) } == ECDSA_VALID_MAGIC;
    if ok {
        unsafe {
            read_operand_be(ECCMUL_OUT_X, out_x, 8);
            read_operand_be(ECCMUL_OUT_Y, out_y, 8);
        }
    }
    clear_eccmul_ram();
    ok
}

fn clear_eccmul_ram() {
    unsafe {
        for base in [
            ECCMUL_A_COEFF,
            ECCMUL_B_COEFF,
            ECCMUL_MOD_P,
            ECCMUL_K,
            ECCMUL_PX,
            ECCMUL_PY,
            ECCMUL_N,
            ECCMUL_OUT_Y,
        ] {
            for index in 0..10 {
                ram_w(base + index, 0);
            }
        }
        ram_w(ECCMUL_OUT_ERROR, 0);
    }
}

// ============ ECDSA P-256 signature generation (MODE 0x24) ============
const SIGN_ORDER_NB_BITS: usize = 0;
const SIGN_MOD_NB_BITS: usize = 2;
const SIGN_A_SIGN: usize = 4;
const SIGN_A_COEFF: usize = 6;
const SIGN_B_COEFF: usize = 72;
const SIGN_MOD_P: usize = 802;
const SIGN_K: usize = 936;
const SIGN_GX: usize = 94;
const SIGN_GY: usize = 28;
const SIGN_HASH_Z: usize = 762;
const SIGN_PRIV_D: usize = 714;
const SIGN_ORDER_N: usize = 738;
const SIGN_OUT_R: usize = 204;
const SIGN_OUT_S: usize = 226;
const SIGN_OUT_ERROR: usize = 760; // 0xD60D = success
const MODE_ECDSA_SIGN: u8 = 0x24;

fn clear_ecdsa_sign_secrets() {
    unsafe {
        for i in 0..8 {
            ram_w(SIGN_K + i, 0);
            ram_w(SIGN_PRIV_D + i, 0);
        }
    }
}

const P256_B: [u8; 32] = [
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
    0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
];

/// Whether a big-endian scalar is a valid P-256 private value in `[1, n-1]`.
pub fn p256_private_scalar_is_valid(scalar: &[u8; 32]) -> bool {
    scalar_in_range(scalar)
}

fn p256_point_on_curve(x: &[u8; 32], y: &[u8; 32]) -> bool {
    if *x >= P256_P || *y >= P256_P {
        return false;
    }
    let mut lhs = zeroize::Zeroizing::new([0u8; 32]);
    let mut x2 = zeroize::Zeroizing::new([0u8; 32]);
    let mut x3 = zeroize::Zeroizing::new([0u8; 32]);
    let mut ax = zeroize::Zeroizing::new([0u8; 32]);
    let mut rhs = zeroize::Zeroizing::new([0u8; 32]);
    let ok = mod_mul(y, y, &P256_P, &mut lhs[..])
        && mod_mul(x, x, &P256_P, &mut x2[..])
        && mod_mul(&x2[..], x, &P256_P, &mut x3[..])
        && mod_mul(&P256_A_POS, x, &P256_P, &mut ax[..])
        && mod_add(&x3[..], &ax[..], &P256_P, &mut rhs[..])
        && mod_add(&rhs[..], &P256_B, &P256_P, &mut x3[..]);
    let matches = ok && lhs.as_slice() == x3.as_slice();
    clear_arithmetic_ram(8);
    matches
}

/// Compute the uncompressed SEC1 public point for a P-256 private scalar.
pub fn p256_public_from_secret(scalar: &[u8; 32], public: &mut [u8; 65]) -> bool {
    public.fill(0);
    if !scalar_in_range(scalar) {
        return false;
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    if !ecc_scalar_mul(
        &P256_P,
        &P256_A_POS,
        &P256_B,
        &P256_N,
        scalar,
        &P256_GX,
        &P256_GY,
        &mut x,
        &mut y,
    ) {
        return false;
    }
    public[0] = 0x04;
    public[1..33].copy_from_slice(&x);
    public[33..].copy_from_slice(&y);
    true
}

/// P-256 ECDH with an uncompressed SEC1 peer point. The public point is
/// range- and curve-checked before entering the PKA because MODE 0x20 does not
/// perform that validation itself. The shared secret is the affine X value.
pub fn p256_ecdh(scalar: &[u8; 32], peer: &[u8; 65], shared_x: &mut [u8; 32]) -> bool {
    shared_x.fill(0);
    if !scalar_in_range(scalar) || peer[0] != 0x04 {
        return false;
    }
    let x: &[u8; 32] = match peer[1..33].try_into() {
        Ok(value) => value,
        Err(_) => return false,
    };
    let y: &[u8; 32] = match peer[33..65].try_into() {
        Ok(value) => value,
        Err(_) => return false,
    };
    if !p256_point_on_curve(x, y) {
        return false;
    }
    let mut out_y = zeroize::Zeroizing::new([0u8; 32]);
    ecc_scalar_mul(
        &P256_P,
        &P256_A_POS,
        &P256_B,
        &P256_N,
        scalar,
        x,
        y,
        shared_x,
        &mut out_y,
    )
}

/// Generate an ECDSA-P256 signature `(r, s)` for 32-byte big-endian hash `z`
/// under private key `d`, using per-signature nonce `k` (all 32-byte BE).
///
/// SECURITY: `k` MUST be a secret uniformly-random value in `[1, n-1]` in
/// production (feed from the TRNG or RFC 6979) — reusing/biasing `k` leaks `d`.
/// A fixed `k` gives a reproducible signature for testing. Returns true iff the
/// PKA reported success (`OUT_ERROR == 0xD60D`); false may mean r/s == 0 (retry
/// with a fresh `k`).
pub fn ecdsa_p256_sign(
    d: &[u8; 32],
    z: &[u8; 32],
    k: &[u8; 32],
    out_r: &mut [u8; 32],
    out_s: &mut [u8; 32],
) -> bool {
    if !scalar_in_range(d) || !scalar_in_range(k) {
        return false;
    }
    let pka = unsafe { &*pac::PKA::ptr() };
    if !pka_enable(pka) {
        return false;
    }
    unsafe {
        ram_w(SIGN_ORDER_NB_BITS, 256);
        ram_w(SIGN_MOD_NB_BITS, 256);
        ram_w(SIGN_A_SIGN, P256_A_SIGN);
        write_be32(SIGN_A_COEFF, &P256_A_ABS);
        write_be32(SIGN_B_COEFF, &P256_B);
        write_be32(SIGN_MOD_P, &P256_P);
        write_be32(SIGN_K, k);
        write_be32(SIGN_GX, &P256_GX);
        write_be32(SIGN_GY, &P256_GY);
        write_be32(SIGN_HASH_Z, z);
        write_be32(SIGN_PRIV_D, d);
        write_be32(SIGN_ORDER_N, &P256_N);
    }
    if !pka_run(pka, MODE_ECDSA_SIGN) {
        clear_ecdsa_sign_secrets();
        return false;
    }
    if unsafe { ram_r(SIGN_OUT_ERROR) } != ECDSA_VALID_MAGIC {
        clear_ecdsa_sign_secrets();
        return false;
    }
    unsafe {
        read_operand_be(SIGN_OUT_R, out_r, 8);
        read_operand_be(SIGN_OUT_S, out_s, 8);
    }
    clear_ecdsa_sign_secrets();
    true
}
