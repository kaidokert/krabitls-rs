//! Minimal bindings to the SAME5x PUKCL ROM services used by qualification.

const SELF_TEST_ENTRY: usize = 0x0200_0055;
const SELF_TEST_SERVICE: u8 = 0x5b;
const COMPUTATION_NOT_STARTED: u16 = 0xc001;
const EXPECTED_LIBRARY_VERSION: u32 = 0x0407_0100;
const EXPECTED_CHECKSUM_1: u32 = 0x6e70_ddd2;
const EXPECTED_CHECKSUM_2: u32 = 0x25c8_d64f;
const CRYPTO_RAM: usize = 0x0201_1000;
const REDMOD_ENTRY: usize = 0x0200_0009;
const EXPMOD_ENTRY: usize = 0x0200_0081;
const ZP_ECDSA_VERIFY_ENTRY: usize = 0x0200_002d;
const ZP_ECC_MUL_FAST_ENTRY: usize = 0x0200_0041;
const ZP_EC_POINT_IS_ON_CURVE_ENTRY: usize = 0x0200_008d;
const ZP_EC_CONV_PROJ_TO_AFFINE_ENTRY: usize = 0x0200_0085;
const REDMOD_SERVICE: u8 = 0x50;
const EXPMOD_SERVICE: u8 = 0x6c;
const ZP_ECDSA_VERIFY_SERVICE: u8 = 0x55;
const ZP_ECC_MUL_FAST_SERVICE: u8 = 0x65;
const ZP_EC_POINT_IS_ON_CURVE_SERVICE: u8 = 0x68;
const ZP_EC_CONV_PROJ_TO_AFFINE_SERVICE: u8 = 0x56;
const WRONG_SIGNATURE: u16 = 0x8002;
const CRYPTO_RAM_END: usize = CRYPTO_RAM + 0x1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidModulus,
    InvalidOperand,
    OutputSize,
    Hardware(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelfTestResult {
    pub library_version: u32,
    pub accelerator_version: u32,
    pub checksum_1: u32,
    pub checksum_2: u32,
    pub status: u16,
}

impl SelfTestResult {
    pub fn passed(&self) -> bool {
        self.status == 0
            && self.library_version == EXPECTED_LIBRARY_VERSION
            && self.checksum_1 == EXPECTED_CHECKSUM_1
            && self.checksum_2 == EXPECTED_CHECKSUM_2
    }
}

#[repr(C)]
struct Header {
    service: u8,
    subservice: u8,
    option: u16,
    specific: u32,
    status: u16,
    padding_0: u16,
    padding_1: u32,
}

#[repr(C)]
struct SelfTestParameters {
    header: Header,
    library_version: u32,
    accelerator_version: u32,
    checksum_1: u32,
    checksum_2: u32,
    step: u8,
    padding: [u8; 3],
}

#[repr(C)]
struct RedModParameters {
    header: Header,
    modulus_base: u16,
    constant_base: u16,
    modulus_len: u16,
    result_base: u16,
    padding_0: u16,
    padding_1: u16,
    workspace_base: u16,
}

#[repr(C)]
struct ExpModParameters {
    header: Header,
    value_base: u16,
    modulus_base: u16,
    constant_base: u16,
    precomputed_base: u16,
    exponent_base: *const u8,
    modulus_len: u16,
    exponent_len: u16,
    blinding: u8,
    padding_0: u8,
    padding_1: u16,
}

#[repr(C)]
struct ZpEcdsaVerifyParameters {
    header: Header,
    point_a_base: u16,
    order_base: u16,
    modulus_base: u16,
    constant_base: u16,
    public_key_base: u16,
    signature_base: u16,
    curve_a_base: u16,
    hash_base: u16,
    workspace_base: u16,
    modulus_len: u16,
    scalar_len: u16,
    padding: u16,
}

#[repr(C)]
struct ZpEccMulFastParameters {
    header: Header,
    point_base: u16,
    modulus_base: u16,
    constant_base: u16,
    scalar_base: u16,
    curve_a_base: u16,
    workspace_base: u16,
    modulus_len: u16,
    scalar_len: u16,
}

#[repr(C)]
struct ZpEcPointIsOnCurveParameters {
    header: Header,
    modulus_base: u16,
    constant_base: u16,
    modulus_len: u16,
    curve_a_base: u16,
    curve_b_base: u16,
    point_base: u16,
    workspace_base: u16,
    padding_0: u16,
    padding_1: u16,
}

#[repr(C)]
struct ZpEcConvProjToAffineParameters {
    header: Header,
    modulus_base: u16,
    constant_base: u16,
    modulus_len: u16,
    point_base: u16,
    padding: u16,
    workspace_base: u16,
}

const _: () = assert!(core::mem::size_of::<Header>() == 16);
const _: () = assert!(core::mem::size_of::<SelfTestParameters>() == 36);
const _: () = assert!(core::mem::size_of::<RedModParameters>() == 32);
const _: () = assert!(core::mem::size_of::<ExpModParameters>() == 36);
const _: () = assert!(core::mem::size_of::<ZpEcdsaVerifyParameters>() == 40);
const _: () = assert!(core::mem::size_of::<ZpEccMulFastParameters>() == 32);
const _: () = assert!(core::mem::size_of::<ZpEcPointIsOnCurveParameters>() == 36);
const _: () = assert!(core::mem::size_of::<ZpEcConvProjToAffineParameters>() == 28);

/// Run the mandatory PUKCL ROM self-test.
///
/// This service resets PUKCC and clears its dedicated Crypto RAM. Interrupts
/// remain masked for the synchronous call so another local context cannot use
/// the globally shared accelerator concurrently.
pub fn self_test() -> SelfTestResult {
    cortex_m::interrupt::free(|_| self_test_inner())
}

fn self_test_inner() -> SelfTestResult {
    let mut parameters = SelfTestParameters {
        header: Header {
            service: SELF_TEST_SERVICE,
            subservice: 0,
            option: 0,
            specific: 0,
            status: COMPUTATION_NOT_STARTED,
            padding_0: 0,
            padding_1: 0,
        },
        library_version: 0,
        accelerator_version: 0,
        checksum_1: 0,
        checksum_2: 0,
        step: 0,
        padding: [0; 3],
    };

    type Service = unsafe extern "C" fn(*mut SelfTestParameters);
    // SAFETY: SELF_TEST_ENTRY is the fixed Thumb entry in the SAME5x PUKCL ROM
    // jump table, and `SelfTestParameters` reproduces the vendor ABI layout.
    let service: Service = unsafe { core::mem::transmute(SELF_TEST_ENTRY) };
    // SAFETY: the parameter block remains exclusively borrowed and resident in
    // CPU SRAM for the synchronous duration of the ROM service.
    unsafe { service(&mut parameters) };

    SelfTestResult {
        library_version: parameters.library_version,
        accelerator_version: parameters.accelerator_version,
        checksum_1: parameters.checksum_1,
        checksum_2: parameters.checksum_2,
        status: parameters.header.status,
    }
}

/// Evaluate a 512-bit public RSA operation with exponent 65537.
///
/// Inputs and output are big-endian. The operation resets PUKCC through its
/// mandatory self-test and uses the accelerator's dedicated Crypto RAM.
pub fn rsa_public_512(modulus: &[u8; 64], value: &[u8; 64]) -> Result<[u8; 64], Error> {
    let mut output = [0; 64];
    modular_exponentiate(value, &[1, 0, 1], modulus, &mut output)?;
    Ok(output)
}

/// Compute `base^exponent mod modulus` using the PUKCC ROM.
///
/// Values are unsigned big-endian byte strings. Operands wider than the
/// modulus are reduced before invoking the ROM service, and the result is
/// left-padded to the exact modulus width.
pub fn modular_exponentiate(
    base: &[u8],
    exponent: &[u8],
    modulus: &[u8],
    output: &mut [u8],
) -> Result<(), Error> {
    if modulus.is_empty() || modulus.iter().all(|byte| *byte == 0) {
        return Err(Error::InvalidModulus);
    }
    if output.len() != modulus.len() {
        return Err(Error::OutputSize);
    }
    cortex_m::interrupt::free(|_| {
        normalize_base(base, modulus, output);
        modular_exponentiate_inner(output, exponent, modulus)?;
        read_reversed(CRYPTO_RAM + aligned_len(modulus.len()) * 2 + 12, output);
        Ok(())
    })
}

fn normalize_base(input: &[u8], modulus: &[u8], output: &mut [u8]) {
    let significant = input
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&[][..], |start| &input[start..]);
    if significant.len() < modulus.len()
        || (significant.len() == modulus.len() && less_than(significant, modulus))
    {
        output.fill(0);
        let start = output.len() - significant.len();
        output[start..].copy_from_slice(significant);
    } else {
        reduce_be(significant, modulus, output);
    }
}

fn modular_exponentiate_inner(
    reduced_base: &[u8],
    exponent: &[u8],
    modulus: &[u8],
) -> Result<(), Error> {
    let self_test = self_test_inner();
    if !self_test.passed() {
        return Err(Error::Hardware(self_test.status));
    }

    let len = aligned_len(modulus.len());
    let exponent_len = aligned_len(exponent.len().max(1));
    if exponent_len > 0xfc {
        return Err(Error::InvalidOperand);
    }

    let modulus_address = CRYPTO_RAM;
    let constant = modulus_address + len + 4;
    let value = constant + len + 8;
    let precomputed = value + len + 16;
    const EXPONENT: usize = CRYPTO_RAM + 0xf00;
    if precomputed + 4 * len + 64 > EXPONENT || EXPONENT + 4 + exponent_len > CRYPTO_RAM_END {
        return Err(Error::InvalidModulus);
    }

    write_reversed_padded(modulus_address, modulus, len - modulus.len() + 4);

    let mut reduction = RedModParameters {
        header: header(REDMOD_SERVICE, 0x0100),
        modulus_base: near(modulus_address),
        constant_base: near(constant),
        modulus_len: len as u16,
        result_base: near(value),
        padding_0: 0,
        padding_1: 0,
        workspace_base: near(precomputed),
    };
    call(REDMOD_ENTRY, &mut reduction);
    if reduction.header.status != 0 {
        return Err(Error::Hardware(reduction.header.status));
    }

    write_reversed_padded(value, reduced_base, len - reduced_base.len() + 16);
    // ExpMod requires one zero word on the low-address/LSB side. The reported
    // exponent length excludes this supplemental word.
    zero(EXPONENT, 4);
    write_reversed(EXPONENT + 4, exponent);
    zero(EXPONENT + 4 + exponent.len(), exponent_len - exponent.len());
    let mut exponentiation = ExpModParameters {
        // FASTRSA | EXPINPUKCCRAM, window size 1.
        header: header(EXPMOD_SERVICE, 0x0006),
        value_base: near(value),
        modulus_base: near(modulus_address),
        constant_base: near(constant),
        precomputed_base: near(precomputed),
        exponent_base: EXPONENT as *const u8,
        modulus_len: len as u16,
        exponent_len: exponent_len as u16,
        blinding: 0,
        padding_0: 0,
        padding_1: 0,
    };
    call(EXPMOD_ENTRY, &mut exponentiation);
    if exponentiation.header.status != 0 {
        return Err(Error::Hardware(exponentiation.header.status));
    }
    Ok(())
}

/// Verify a raw P-256 ECDSA signature through the PUKCL ROM service.
///
/// `public_key` is the uncompressed `x || y` coordinate pair, while `digest`
/// and `signature` are fixed-width big-endian `z` and `r || s` values.
pub fn ecdsa_p256_verify(
    public_key: &[u8; 64],
    digest: &[u8; 32],
    signature: &[u8; 64],
) -> Result<bool, Error> {
    cortex_m::interrupt::free(|_| ecdsa_p256_verify_inner(public_key, digest, signature))
}

fn ecdsa_p256_verify_inner(
    public_key: &[u8; 64],
    digest: &[u8; 32],
    signature: &[u8; 64],
) -> Result<bool, Error> {
    const N: [u8; 32] = hex32(b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    if !scalar_in_range(&signature[..32], &N) || !scalar_in_range(&signature[32..], &N) {
        return Ok(false);
    }
    const LEN: usize = 32;
    const MODULUS: usize = CRYPTO_RAM;
    const CONSTANT: usize = MODULUS + LEN + 4;
    const ORDER: usize = CONSTANT + LEN + 12;
    const SIGNATURE: usize = ORDER + LEN + 12;
    const SIGNATURE_S: usize = SIGNATURE + LEN + 4;
    const HASH: usize = SIGNATURE + 2 * LEN + 8;
    const POINT_A: usize = HASH + LEN + 4;
    const POINT_A_Y: usize = POINT_A + LEN + 4;
    const POINT_A_Z: usize = POINT_A_Y + LEN + 4;
    const PUBLIC_KEY: usize = POINT_A_Z + LEN + 4;
    const PUBLIC_KEY_Y: usize = PUBLIC_KEY + LEN + 4;
    const PUBLIC_KEY_Z: usize = PUBLIC_KEY_Y + LEN + 4;
    const CURVE_A: usize = PUBLIC_KEY_Z + LEN + 4;
    const WORKSPACE: usize = CURVE_A + LEN + 4;
    const REDUCTION_R: usize = CONSTANT + LEN + 12;
    const REDUCTION_X: usize = REDUCTION_R + 68;

    const P: [u8; LEN] = hex32(b"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    const A: [u8; LEN] = hex32(b"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
    const GX: [u8; LEN] =
        hex32(b"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    const GY: [u8; LEN] =
        hex32(b"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

    let self_test = self_test_inner();
    if !self_test.passed() {
        return Err(Error::Hardware(self_test.status));
    }

    write_reversed_padded(MODULUS, &P, 4);
    zero(CONSTANT, LEN + 12);
    zero(REDUCTION_R, 68);
    zero(REDUCTION_X, 2 * LEN + 8);
    let mut reduction = RedModParameters {
        header: header(REDMOD_SERVICE, 0x0100),
        modulus_base: near(MODULUS),
        constant_base: near(CONSTANT),
        modulus_len: LEN as u16,
        result_base: near(REDUCTION_R),
        padding_0: 0,
        padding_1: 0,
        workspace_base: near(REDUCTION_X),
    };
    call(REDMOD_ENTRY, &mut reduction);
    if reduction.header.status != 0 {
        return Err(Error::Hardware(reduction.header.status));
    }

    write_reversed_padded(ORDER, &N, 4);
    write_reversed_padded(SIGNATURE, &signature[..LEN], 4);
    write_reversed_padded(SIGNATURE_S, &signature[LEN..], 4);
    write_reversed_padded(HASH, digest, 4);
    write_reversed_padded(POINT_A, &GX, 4);
    write_reversed_padded(POINT_A_Y, &GY, 4);
    zero(POINT_A_Z, LEN + 4);
    unsafe { (POINT_A_Z as *mut u8).write_volatile(1) };
    write_reversed_padded(PUBLIC_KEY, &public_key[..LEN], 4);
    write_reversed_padded(PUBLIC_KEY_Y, &public_key[LEN..], 4);
    zero(PUBLIC_KEY_Z, LEN + 4);
    unsafe { (PUBLIC_KEY_Z as *mut u8).write_volatile(1) };
    write_reversed_padded(CURVE_A, &A, 4);
    zero(WORKSPACE, 8 * LEN + 44);

    let mut verification = ZpEcdsaVerifyParameters {
        header: header(ZP_ECDSA_VERIFY_SERVICE, 0),
        point_a_base: near(POINT_A),
        order_base: near(ORDER),
        modulus_base: near(MODULUS),
        constant_base: near(CONSTANT),
        public_key_base: near(PUBLIC_KEY),
        signature_base: near(SIGNATURE),
        curve_a_base: near(CURVE_A),
        hash_base: near(HASH),
        workspace_base: near(WORKSPACE),
        modulus_len: LEN as u16,
        scalar_len: LEN as u16,
        padding: 0,
    };
    call(ZP_ECDSA_VERIFY_ENTRY, &mut verification);
    match verification.header.status {
        0 => Ok(true),
        WRONG_SIGNATURE => Ok(false),
        status => Err(Error::Hardware(status)),
    }
}

/// Compute a P-256 scalar multiplication through the PUKCC prime-field engine.
///
/// `point_sec1` and `output_sec1` use the uncompressed SEC1 representation.
/// The input point is checked on-curve before the secret scalar is consumed.
pub fn p256_scalar_mult(
    scalar: &[u8; 32],
    point_sec1: &[u8; 65],
    output_sec1: &mut [u8; 65],
) -> Result<(), Error> {
    cortex_m::interrupt::free(|_| p256_scalar_mult_inner(scalar, point_sec1, output_sec1))
}

fn p256_scalar_mult_inner(
    scalar: &[u8; 32],
    point_sec1: &[u8; 65],
    output_sec1: &mut [u8; 65],
) -> Result<(), Error> {
    const LEN: usize = 32;
    const MODULUS: usize = CRYPTO_RAM;
    const CONSTANT: usize = MODULUS + LEN + 4;
    const POINT: usize = CONSTANT + LEN + 12;
    const POINT_Y: usize = POINT + LEN + 4;
    const POINT_Z: usize = POINT_Y + LEN + 4;
    const SCALAR: usize = POINT_Z + LEN + 4;
    const CURVE_A: usize = SCALAR + LEN + 4;
    const CURVE_B: usize = CURVE_A + LEN + 4;
    const WORKSPACE: usize = CURVE_B + LEN + 4;

    const P: [u8; LEN] = hex32(b"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    const A: [u8; LEN] = hex32(b"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
    const B: [u8; LEN] = hex32(b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
    const N: [u8; LEN] = hex32(b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

    if point_sec1[0] != 4 || !scalar_in_range(scalar, &N) {
        return Err(Error::InvalidOperand);
    }

    let result = (|| {
        let self_test = self_test_inner();
        if !self_test.passed() {
            return Err(Error::Hardware(self_test.status));
        }

        write_reversed_padded(MODULUS, &P, 4);
        zero(CONSTANT, LEN + 12);
        zero(POINT, 68);
        zero(WORKSPACE, 2 * LEN + 8);
        let mut reduction = RedModParameters {
            header: header(REDMOD_SERVICE, 0x0100),
            modulus_base: near(MODULUS),
            constant_base: near(CONSTANT),
            modulus_len: LEN as u16,
            result_base: near(POINT),
            padding_0: 0,
            padding_1: 0,
            workspace_base: near(WORKSPACE),
        };
        call(REDMOD_ENTRY, &mut reduction);
        if reduction.header.status != 0 {
            return Err(Error::Hardware(reduction.header.status));
        }

        write_reversed_padded(POINT, &point_sec1[1..33], 4);
        write_reversed_padded(POINT_Y, &point_sec1[33..], 4);
        zero(POINT_Z, LEN + 4);
        unsafe { (POINT_Z as *mut u8).write_volatile(1) };
        write_reversed_padded(SCALAR, scalar, 4);
        write_reversed_padded(CURVE_A, &A, 4);
        write_reversed_padded(CURVE_B, &B, 4);
        zero(WORKSPACE, CRYPTO_RAM_END - WORKSPACE);

        let mut check = ZpEcPointIsOnCurveParameters {
            header: header(ZP_EC_POINT_IS_ON_CURVE_SERVICE, 0),
            modulus_base: near(MODULUS),
            constant_base: near(CONSTANT),
            modulus_len: LEN as u16,
            curve_a_base: near(CURVE_A),
            curve_b_base: near(CURVE_B),
            point_base: near(POINT),
            workspace_base: near(WORKSPACE),
            padding_0: 0,
            padding_1: 0,
        };
        call(ZP_EC_POINT_IS_ON_CURVE_ENTRY, &mut check);
        if check.header.status != 0 {
            return Err(Error::InvalidOperand);
        }

        let mut multiply = ZpEccMulFastParameters {
            header: header(ZP_ECC_MUL_FAST_SERVICE, 0),
            point_base: near(POINT),
            modulus_base: near(MODULUS),
            constant_base: near(CONSTANT),
            scalar_base: near(SCALAR),
            curve_a_base: near(CURVE_A),
            workspace_base: near(WORKSPACE),
            modulus_len: LEN as u16,
            scalar_len: LEN as u16,
        };
        call(ZP_ECC_MUL_FAST_ENTRY, &mut multiply);
        if multiply.header.status != 0 {
            return Err(Error::Hardware(multiply.header.status));
        }

        let mut affine = ZpEcConvProjToAffineParameters {
            header: header(ZP_EC_CONV_PROJ_TO_AFFINE_SERVICE, 0),
            modulus_base: near(MODULUS),
            constant_base: near(CONSTANT),
            modulus_len: LEN as u16,
            point_base: near(POINT),
            padding: 0,
            workspace_base: near(WORKSPACE),
        };
        call(ZP_EC_CONV_PROJ_TO_AFFINE_ENTRY, &mut affine);
        if affine.header.status != 0 {
            return Err(Error::Hardware(affine.header.status));
        }

        output_sec1[0] = 4;
        read_reversed(POINT, &mut output_sec1[1..33]);
        read_reversed(POINT_Y, &mut output_sec1[33..]);
        Ok(())
    })();
    zero(CRYPTO_RAM, CRYPTO_RAM_END - CRYPTO_RAM);
    if result.is_err() {
        output_sec1.fill(0);
    }
    result
}

fn aligned_len(len: usize) -> usize {
    (len + 3) & !3
}

fn reduce_be(input: &[u8], modulus: &[u8], output: &mut [u8]) {
    output.fill(0);
    for byte in input {
        for bit in (0..8).rev() {
            let mut carry = (*byte >> bit) & 1;
            for digit in output.iter_mut().rev() {
                let next = *digit >> 7;
                *digit = (*digit << 1) | carry;
                carry = next;
            }
            if carry != 0 || !less_than(output, modulus) {
                subtract(output, modulus);
            }
        }
    }
}

fn less_than(lhs: &[u8], rhs: &[u8]) -> bool {
    lhs.iter().cmp(rhs.iter()).is_lt()
}

fn subtract(lhs: &mut [u8], rhs: &[u8]) {
    let mut borrow = false;
    for (left, right) in lhs.iter_mut().rev().zip(rhs.iter().rev()) {
        let (value, first) = left.overflowing_sub(*right);
        let (value, second) = value.overflowing_sub(u8::from(borrow));
        *left = value;
        borrow = first || second;
    }
}

fn scalar_in_range(value: &[u8], order: &[u8; 32]) -> bool {
    value.iter().any(|byte| *byte != 0) && less_than(value, order)
}

fn header(service: u8, option: u16) -> Header {
    Header {
        service,
        subservice: 0,
        option,
        specific: 0,
        status: COMPUTATION_NOT_STARTED,
        padding_0: 0,
        padding_1: 0,
    }
}

fn near(address: usize) -> u16 {
    address as u16
}

fn write_reversed(address: usize, source: &[u8]) {
    for (index, byte) in source.iter().rev().enumerate() {
        unsafe { ((address + index) as *mut u8).write_volatile(*byte) };
    }
}

fn write_reversed_padded(address: usize, source: &[u8], padding: usize) {
    write_reversed(address, source);
    zero(address + source.len(), padding);
}

fn read_reversed(address: usize, output: &mut [u8]) {
    let len = output.len();
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = unsafe { ((address + len - 1 - index) as *const u8).read_volatile() };
    }
}

const fn hex32(text: &[u8; 64]) -> [u8; 32] {
    let mut output = [0; 32];
    let mut index = 0;
    while index < output.len() {
        output[index] = (nibble(text[index * 2]) << 4) | nibble(text[index * 2 + 1]);
        index += 1;
    }
    output
}

const fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid hex"),
    }
}

fn zero(address: usize, len: usize) {
    for offset in 0..len {
        unsafe { ((address + offset) as *mut u8).write_volatile(0) };
    }
}

fn call<T>(entry: usize, parameters: &mut T) {
    type Service<T> = unsafe extern "C" fn(*mut T);
    let service: Service<T> = unsafe { core::mem::transmute_copy(&entry) };
    unsafe { service(parameters) };
}
