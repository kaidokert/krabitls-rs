use core::sync::atomic::{AtomicU8, Ordering};

use crate::{CryptoCellError, EngineGuard};

const PSA_SUCCESS: i32 = 0;
const PSA_ECC_FAMILY_SECP_R1: u8 = 0x12;
const PSA_KEY_TYPE_ECC_KEY_PAIR_SECP_R1: u16 = 0x7112;

// ABI from TF-PSA-Crypto fa92349590a54959ee2efc21b668e5afdb144726,
// the revision selected by nRF Connect SDK 3.4.1.
#[repr(C)]
struct PsaKeyPolicy {
    usage: u32,
    algorithm: u32,
    algorithm2: u32,
}

#[repr(C)]
struct PsaKeyAttributes {
    key_type: u16,
    bits: u16,
    lifetime: u32,
    policy: PsaKeyPolicy,
    id: u32,
}

impl PsaKeyAttributes {
    const P256_KEY_PAIR: Self = Self {
        key_type: PSA_KEY_TYPE_ECC_KEY_PAIR_SECP_R1,
        bits: 256,
        lifetime: 0,
        policy: PsaKeyPolicy {
            usage: 0,
            algorithm: 0,
            algorithm2: 0,
        },
        id: 0,
    };
}

unsafe extern "C" {
    fn nrf_cc3xx_platform_init() -> i32;
    fn nrf_cc3xx_platform_deinit() -> i32;
    fn nrf_cc3xx_platform_entropy_get(buffer: *mut u8, length: usize, olen: *mut usize) -> i32;
    fn cc3xx_internal_export_ecc_wrst_public_key(
        attributes: *const PsaKeyAttributes,
        private_key: *const u8,
        private_key_size: usize,
        public_key: *mut u8,
        public_key_size: usize,
        public_key_length: *mut usize,
    ) -> i32;
    fn cc3xx_ecdh_calc_secret_wrst(
        curve: u8,
        key_bits: u16,
        private_key: *const u8,
        private_key_size: usize,
        public_key: *const u8,
        public_key_size: usize,
        secret: *mut u8,
        secret_size: usize,
        secret_length: *mut usize,
    ) -> i32;
}

pub(crate) fn deinit_locked() -> Result<(), CryptoCellError> {
    match PLATFORM_STATE.swap(2, Ordering::AcqRel) {
        0 | 2 => Ok(()),
        1 => {
            // SAFETY: `shutdown` holds the same process-global guard used for
            // every vendor call, and no later operation is accepted.
            if unsafe { nrf_cc3xx_platform_deinit() } == 0 {
                Ok(())
            } else {
                Err(CryptoCellError::Hardware)
            }
        }
        _ => unreachable!(),
    }
}

// 0 = not initialized, 1 = initialized, 2 = permanently failed.
static PLATFORM_STATE: AtomicU8 = AtomicU8::new(0);

#[cfg(feature = "qualification")]
static FORCE_TIMEOUT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn with_platform<T>(
    operation: impl FnOnce() -> Result<T, CryptoCellError>,
) -> Result<T, CryptoCellError> {
    let guard = EngineGuard::acquire()?;
    match PLATFORM_STATE.load(Ordering::Acquire) {
        0 => {
            // SAFETY: the process-global guard gives the Nordic library exclusive
            // CryptoCell ownership, and initialization is attempted only once.
            if unsafe { nrf_cc3xx_platform_init() } != 0 {
                PLATFORM_STATE.store(2, Ordering::Release);
                guard.finish_vendor_call();
                return Err(CryptoCellError::Hardware);
            }
            PLATFORM_STATE.store(1, Ordering::Release);
        }
        1 => {}
        _ => {
            guard.finish_vendor_call();
            return Err(CryptoCellError::PoweredDown);
        }
    }
    #[cfg(feature = "qualification")]
    if FORCE_TIMEOUT.swap(false, Ordering::AcqRel) {
        guard.finish_vendor_call();
        return Err(CryptoCellError::Timeout);
    }
    let result = operation();
    guard.finish_vendor_call();
    result
}

#[cfg(feature = "qualification")]
pub(crate) fn force_next_timeout() {
    FORCE_TIMEOUT.store(true, Ordering::Release);
}

pub(crate) fn entropy(output: &mut [u8]) -> Result<(), CryptoCellError> {
    with_platform(|| {
        let mut written = 0;
        // SAFETY: `output` is writable for its reported length and `written`
        // remains live for the duration of this synchronous call.
        let status = unsafe {
            nrf_cc3xx_platform_entropy_get(output.as_mut_ptr(), output.len(), &mut written)
        };
        if status == 0 && written == output.len() {
            Ok(())
        } else {
            Err(CryptoCellError::Entropy)
        }
    })
}

pub(crate) fn p256_public(
    private_key: &[u8; 32],
    public_key: &mut [u8; 65],
) -> Result<(), CryptoCellError> {
    with_platform(|| {
        let mut written = 0;
        // SAFETY: all pointers refer to live fixed-size buffers; the attributes
        // layout is pinned above to the SDK revision supplying this archive.
        let status = unsafe {
            cc3xx_internal_export_ecc_wrst_public_key(
                &PsaKeyAttributes::P256_KEY_PAIR,
                private_key.as_ptr(),
                private_key.len(),
                public_key.as_mut_ptr(),
                public_key.len(),
                &mut written,
            )
        };
        map_psa(status, written == public_key.len())
    })
}

pub(crate) fn p256_ecdh(
    private_key: &[u8; 32],
    public_key: &[u8; 65],
    secret: &mut [u8; 32],
) -> Result<(), CryptoCellError> {
    with_platform(|| {
        let mut written = 0;
        // SAFETY: all pointers refer to live fixed-size buffers and the Nordic
        // call is synchronous under exclusive CryptoCell ownership.
        let status = unsafe {
            cc3xx_ecdh_calc_secret_wrst(
                PSA_ECC_FAMILY_SECP_R1,
                256,
                private_key.as_ptr(),
                private_key.len(),
                public_key.as_ptr(),
                public_key.len(),
                secret.as_mut_ptr(),
                secret.len(),
                &mut written,
            )
        };
        map_psa(status, written == secret.len())
    })
}

fn map_psa(status: i32, length_is_valid: bool) -> Result<(), CryptoCellError> {
    if status == PSA_SUCCESS && length_is_valid {
        Ok(())
    } else if status == -135 || status == -134 {
        Err(CryptoCellError::InvalidArgument)
    } else {
        Err(CryptoCellError::Hardware)
    }
}
