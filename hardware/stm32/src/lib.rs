#![no_std]

#[cfg(not(feature = "stm32h533"))]
compile_error!("select a supported STM32 device feature (currently stm32h533)");

#[cfg(feature = "aes")]
mod aes;
#[cfg(feature = "kx")]
mod kx;
#[cfg(feature = "kx")]
#[allow(dead_code)]
mod pka;

#[cfg(feature = "aes")]
pub use aes::{Aes128GcmHw, H533Aead};
#[cfg(feature = "kx")]
pub use kx::{H533Kx, H533KxError, H533P256Group, H533X25519Group};
