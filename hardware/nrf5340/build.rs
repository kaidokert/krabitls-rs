use std::{env, fs, path::PathBuf};

fn main() {
    let target = env::var("TARGET").expect("TARGET");
    if env::var_os("CARGO_FEATURE_P256").is_some() && target == "thumbv8m.main-none-eabihf" {
        let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
        println!(
            "cargo:rustc-link-search=native={}",
            manifest.join("vendor/nrfxlib").display()
        );
        println!("cargo:rustc-link-lib=static=nrf_cc312_psa_crypto_0.9.23");
        println!("cargo:rustc-link-lib=static=nrf_cc312_core_0.9.23");
        println!("cargo:rustc-link-lib=static=nrf_cc312_platform_0.9.23");
        println!("cargo:rerun-if-changed=vendor/nrfxlib");
    }

    if env::var_os("CARGO_FEATURE_QUALIFICATION").is_some() {
        let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
        fs::write(out.join("memory.x"), include_bytes!("memory.x"))
            .expect("write qualification linker script");
        println!("cargo:rustc-link-search={}", out.display());
        println!("cargo:rerun-if-changed=memory.x");
    }
}
