use std::{env, fs, path::PathBuf};

fn main() {
    if env::var_os("CARGO_FEATURE_QUALIFICATION").is_some() {
        let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set"));
        fs::write(out.join("memory.x"), include_bytes!("memory.x"))
            .expect("write E84 qualification linker memory");
        println!("cargo:rustc-link-search={}", out.display());
        println!("cargo:rustc-link-arg-examples=-Tlink.x");
        println!("cargo:rustc-link-arg-examples=-Tdefmt.x");
    }
    println!("cargo:rerun-if-changed=memory.x");
}
