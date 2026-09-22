#![no_std]

#[cfg(not(any(
    feature = "samd51g",
    feature = "samd51j",
    feature = "samd51n",
    feature = "samd51p",
    feature = "same51g",
    feature = "same51j",
    feature = "same51n",
    feature = "same53j",
    feature = "same53n",
    feature = "same54n",
    feature = "same54p",
)))]
compile_error!("select one SAM D5x/E5x device feature");

#[cfg(feature = "aes")]
pub mod aes;
#[cfg(feature = "p256-kx")]
pub mod kx;
#[cfg(feature = "p256-kx")]
pub mod pukcc;

#[cfg(feature = "aes")]
pub use aes::{Aes128GcmHw, Same5xAead, seed_countermeasures};
#[cfg(feature = "p256-kx")]
pub use kx::{Same5xKx, Same5xKxError, Same5xP256KxGroup};
