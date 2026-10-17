use crate::Pg26Error;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, compiler_fence};
use zeroize::Zeroize;

const MAILBOX: usize = 0x4c00_0000;
const FIFO: usize = MAILBOX;
const TX_STATUS: usize = MAILBOX + 0x40;
const RX_STATUS: usize = MAILBOX + 0x44;
const TX_HEADER: usize = MAILBOX + 0x50;
const RX_HEADER: usize = MAILBOX + 0x54;

const TX_READY: u32 = 1 << 20;
const RX_READY: u32 = 1 << 20;
const STATUS_ERROR: u32 = 1 << 23;
const RESPONSE_MASK: u32 = 0x000f_0000;
const WAIT_LIMIT: usize = 8_000_000;

const REALIGN: u32 = 0x2000_0000;
const STOP: usize = 1;

const SHA256: u32 = 0x0000_0400;
const HASH: u32 = 0x0300_0000 | SHA256;
const HASH_UPDATE: u32 = 0x0301_0000 | SHA256;
const HMAC: u32 = 0x0302_0000 | SHA256;
const HASH_FINISH: u32 = 0x0303_0000 | SHA256;
const AES_GCM_ENCRYPT: u32 = 0x0402_0000;
const AES_GCM_DECRYPT: u32 = 0x0403_0000 | (16 << 8);
const TRNG: u32 = 0x0700_0000;
const CREATE_KEY: u32 = 0x0200_0000;
const READ_PUBLIC_KEY: u32 = 0x0201_0000;
const ECDH: u32 = 0x0e00_0000;

const AES128_PLAINTEXT: u32 = 16;
const P256_PRIVATE_WRAPPED_LOCKED: u32 = 0x8900_401f;
const RAW_64_PLAINTEXT: u32 = 64;

const DEFAULT_AUTH: [u32; 2] = [0; 2];

#[repr(C)]
struct Descriptor {
    data: *mut u8,
    next: *mut Descriptor,
    length: u32,
}

impl Descriptor {
    fn input(data: &[u8]) -> Self {
        Self {
            data: data.as_ptr().cast_mut(),
            next: STOP as *mut Self,
            length: data.len() as u32 | REALIGN,
        }
    }

    fn output(data: &mut [u8]) -> Self {
        Self {
            data: data.as_mut_ptr(),
            next: STOP as *mut Self,
            length: data.len() as u32 | REALIGN,
        }
    }
}

const _: () = assert!(core::mem::size_of::<Descriptor>() == 12);
const _: () = assert!(core::mem::align_of::<Descriptor>() == 4);

fn chain(descriptors: &mut [Descriptor]) -> *mut Descriptor {
    if descriptors.is_empty() {
        return core::ptr::null_mut();
    }
    for index in 0..descriptors.len() - 1 {
        let next = &mut descriptors[index + 1] as *mut Descriptor;
        descriptors[index].next = next;
    }
    descriptors.as_mut_ptr()
}

fn execute(
    command: u32,
    inputs: &mut [Descriptor],
    outputs: &mut [Descriptor],
    parameters: &[u32],
) -> Result<(), Pg26Error> {
    if parameters.len() > 5 {
        return Err(Pg26Error::InvalidLength);
    }
    let input = chain(inputs);
    let output = chain(outputs);
    // The SE is a DMA observer across a Normal-memory/Device-memory boundary.
    // Compiler fences preserve Rust ordering; DMB orders the actual bus access.
    compiler_fence(Ordering::Release);
    cortex_m::asm::dmb();

    for _ in 0..WAIT_LIMIT {
        let status = unsafe { read_volatile(TX_STATUS as *const u32) };
        if status & STATUS_ERROR != 0 {
            return Err(Pg26Error::MailboxProtocol);
        }
        if status & TX_READY != 0 {
            unsafe {
                write_volatile(TX_HEADER as *mut u32, 4 * (4 + parameters.len() as u32));
                write_volatile(FIFO as *mut u32, command);
                write_volatile(FIFO as *mut u32, input as u32);
                write_volatile(FIFO as *mut u32, output as u32);
                for parameter in parameters {
                    write_volatile(FIFO as *mut u32, *parameter);
                }
            }
            for _ in 0..WAIT_LIMIT {
                let status = unsafe { read_volatile(RX_STATUS as *const u32) };
                if status & STATUS_ERROR != 0 {
                    active_command_reset();
                }
                if status & RX_READY != 0 {
                    let response = unsafe { read_volatile(RX_HEADER as *const u32) };
                    // Do not consume DMA output before the completed Device
                    // response is globally ordered against Normal SRAM writes.
                    cortex_m::asm::dmb();
                    compiler_fence(Ordering::Acquire);
                    return decode_response(response & RESPONSE_MASK);
                }
            }
            active_command_reset();
        }
    }
    Err(Pg26Error::Timeout)
}

/// Once submitted, a command may still own stack-backed DMA descriptors. The
/// mailbox has no documented cancellation operation, so returning would make
/// those pointers dangle. A system reset is the only safe bounded recovery.
fn active_command_reset() -> ! {
    cortex_m::peripheral::SCB::sys_reset()
}

fn decode_response(response: u32) -> Result<(), Pg26Error> {
    match response {
        0 => Ok(()),
        0x0001_0000 => Err(Pg26Error::InvalidCommand),
        0x0002_0000 => Err(Pg26Error::Authorization),
        0x0003_0000 => Err(Pg26Error::Authentication),
        0x0004_0000 => Err(Pg26Error::Bus),
        0x0005_0000 => Err(Pg26Error::Internal),
        0x0006_0000 => Err(Pg26Error::Crypto),
        0x0007_0000 => Err(Pg26Error::InvalidParameter),
        0x000b_0000 => Err(Pg26Error::NotInitialized),
        0x000f_0000 => Err(Pg26Error::Aborted),
        code => Err(Pg26Error::UnknownResponse(code)),
    }
}

fn auth_descriptor() -> Descriptor {
    Descriptor::input(unsafe { core::slice::from_raw_parts(DEFAULT_AUTH.as_ptr().cast::<u8>(), 8) })
}

fn plaintext_auth_descriptor() -> Descriptor {
    let mut descriptor = Descriptor::input(&[]);
    descriptor.length = REALIGN;
    descriptor
}

pub(crate) fn random(output: &mut [u8]) -> Result<(), Pg26Error> {
    for chunk in output.chunks_mut(u32::MAX as usize & !3) {
        let aligned = chunk.len() & !3;
        if aligned > 0 {
            let mut outputs = [Descriptor::output(&mut chunk[..aligned])];
            execute(TRNG, &mut [], &mut outputs, &[aligned as u32])?;
        }
        if aligned != chunk.len() {
            let mut word = [0u8; 4];
            let mut outputs = [Descriptor::output(&mut word)];
            let result = execute(TRNG, &mut [], &mut outputs, &[4]);
            if result.is_ok() {
                let surplus = chunk.len() - aligned;
                chunk[aligned..].copy_from_slice(&word[..surplus]);
            }
            word.zeroize();
            result?;
        }
    }
    Ok(())
}

pub(crate) fn sha256(message: &[u8], output: &mut [u8; 32]) -> Result<(), Pg26Error> {
    let mut inputs = [Descriptor::input(message)];
    let mut outputs = [Descriptor::output(output)];
    execute(HASH, &mut inputs, &mut outputs, &[message.len() as u32])
}

pub(crate) fn sha256_update(state: &mut [u8; 32], blocks: &[u8]) -> Result<(), Pg26Error> {
    if blocks.is_empty() || !blocks.len().is_multiple_of(64) {
        return Err(Pg26Error::InvalidLength);
    }
    let state_in = *state;
    let mut inputs = [Descriptor::input(&state_in), Descriptor::input(blocks)];
    let mut outputs = [Descriptor::output(state)];
    execute(
        HASH_UPDATE,
        &mut inputs,
        &mut outputs,
        &[blocks.len() as u32],
    )
}

pub(crate) fn sha256_finish(
    state: &[u8; 32],
    tail: &[u8],
    total: u32,
    output: &mut [u8; 32],
) -> Result<(), Pg26Error> {
    if tail.len() >= 64 {
        return Err(Pg26Error::InvalidLength);
    }
    let mut inputs = [Descriptor::input(state), Descriptor::input(tail)];
    let mut outputs = [Descriptor::output(output)];
    execute(
        HASH_FINISH,
        &mut inputs,
        &mut outputs,
        &[tail.len() as u32, total],
    )
}

pub(crate) fn hmac_sha256_parts(
    key: &[u8],
    parts: &[&[u8]],
    output: &mut [u8; 32],
) -> Result<(), Pg26Error> {
    if key.is_empty() || key.len() > 0x7fff || parts.len() > 3 {
        return Err(Pg26Error::InvalidLength);
    }
    let message_len = parts
        .iter()
        .try_fold(0usize, |total, part| total.checked_add(part.len()))
        .ok_or(Pg26Error::InvalidLength)?;
    let mut outputs = [Descriptor::output(output)];
    let parameters = [key.len() as u32, message_len as u32];
    let mut compact = [&[][..]; 3];
    let mut count = 0;
    for part in parts.iter().copied().filter(|part| !part.is_empty()) {
        compact[count] = part;
        count += 1;
    }

    // REALIGN delimits logical command fields. Message fragments are one
    // field, so only its last descriptor retains REALIGN. Zero-length linked
    // descriptors are omitted because the SE attempts to fetch them.
    match count {
        0 => {
            let mut inputs = [
                plaintext_auth_descriptor(),
                Descriptor::input(key),
                Descriptor::input(&[]),
            ];
            execute(HMAC, &mut inputs, &mut outputs, &parameters)
        }
        1 => {
            let mut inputs = [
                plaintext_auth_descriptor(),
                Descriptor::input(key),
                Descriptor::input(compact[0]),
            ];
            execute(HMAC, &mut inputs, &mut outputs, &parameters)
        }
        2 => {
            let mut inputs = [
                plaintext_auth_descriptor(),
                Descriptor::input(key),
                Descriptor::input(compact[0]),
                Descriptor::input(compact[1]),
            ];
            inputs[2].length &= !REALIGN;
            execute(HMAC, &mut inputs, &mut outputs, &parameters)
        }
        3 => {
            let mut inputs = [
                plaintext_auth_descriptor(),
                Descriptor::input(key),
                Descriptor::input(compact[0]),
                Descriptor::input(compact[1]),
                Descriptor::input(compact[2]),
            ];
            inputs[2].length &= !REALIGN;
            inputs[3].length &= !REALIGN;
            execute(HMAC, &mut inputs, &mut outputs, &parameters)
        }
        _ => unreachable!(),
    }
}

pub(crate) fn gcm_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
    tag: &mut [u8; 16],
) -> Result<(), Pg26Error> {
    let mut auth = Descriptor::input(&[]);
    auth.length = REALIGN;
    let data_len = data.len();
    // The SE command explicitly supports in-place GCM. The shared input view
    // exists only while the mailbox owns the operation and is not read by the
    // CPU while DMA writes through `data`.
    let input_copy = unsafe { core::slice::from_raw_parts(data.as_ptr(), data_len) };
    let mut inputs = [
        auth,
        Descriptor::input(key),
        Descriptor::input(nonce),
        Descriptor::input(aad),
        Descriptor::input(input_copy),
    ];
    let mut outputs = [Descriptor::output(data), Descriptor::output(tag)];
    execute(
        AES_GCM_ENCRYPT,
        &mut inputs,
        &mut outputs,
        &[AES128_PLAINTEXT, aad.len() as u32, data_len as u32],
    )
}

pub(crate) fn gcm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), Pg26Error> {
    let mut auth = Descriptor::input(&[]);
    auth.length = REALIGN;
    let data_len = data.len();
    // See the in-place aliasing note in `gcm_encrypt`.
    let input_copy = unsafe { core::slice::from_raw_parts(data.as_ptr(), data_len) };
    let mut inputs = [
        auth,
        Descriptor::input(key),
        Descriptor::input(nonce),
        Descriptor::input(aad),
        Descriptor::input(input_copy),
        Descriptor::input(tag),
    ];
    let mut outputs = [Descriptor::output(data)];
    execute(
        AES_GCM_DECRYPT,
        &mut inputs,
        &mut outputs,
        &[AES128_PLAINTEXT, aad.len() as u32, data_len as u32],
    )
}

pub(crate) fn generate_p256_wrapped(output: &mut [u8; 60]) -> Result<(), Pg26Error> {
    let mut inputs = [auth_descriptor()];
    let mut outputs = [Descriptor::output(output)];
    execute(
        CREATE_KEY,
        &mut inputs,
        &mut outputs,
        &[P256_PRIVATE_WRAPPED_LOCKED],
    )
}

pub(crate) fn p256_public(wrapped: &[u8; 60], output: &mut [u8; 64]) -> Result<(), Pg26Error> {
    let mut inputs = [auth_descriptor(), Descriptor::input(wrapped)];
    let mut outputs = [Descriptor::output(output)];
    execute(
        READ_PUBLIC_KEY,
        &mut inputs,
        &mut outputs,
        &[P256_PRIVATE_WRAPPED_LOCKED],
    )
}

pub(crate) fn p256_ecdh(
    wrapped: &[u8; 60],
    peer: &[u8; 64],
    output: &mut [u8; 64],
) -> Result<(), Pg26Error> {
    let mut inputs = [
        auth_descriptor(),
        Descriptor::input(wrapped),
        Descriptor::input(peer),
    ];
    let mut outputs = [Descriptor::output(output)];
    execute(
        ECDH,
        &mut inputs,
        &mut outputs,
        &[P256_PRIVATE_WRAPPED_LOCKED, RAW_64_PLAINTEXT],
    )
}

pub(crate) fn probe_mailbox() -> Result<(), Pg26Error> {
    let mut digest = [0u8; 32];
    let result = sha256(b"", &mut digest);
    digest.zeroize();
    result
}

#[cfg(feature = "qualification")]
pub(crate) fn qualification_invalid_command() -> Result<(), Pg26Error> {
    execute(0xffff_ffff, &mut [], &mut [], &[])
}
