use std::{env, fs, path::PathBuf};

fn main() {
    if env::var_os("CARGO_FEATURE_QUALIFICATION").is_some() {
        let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
        fs::write(out.join("memory.x"), include_bytes!("memory.x"))
            .expect("write qualification linker script");
        println!("cargo:rustc-link-search={}", out.display());
        println!("cargo:rerun-if-changed=memory.x");
    }
}
