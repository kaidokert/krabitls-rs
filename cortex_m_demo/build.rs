use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").unwrap_or_else(|_| "thumbv6m-none-eabi".to_string());

    let include_bytes_cm0 = include_bytes!("memory_cm0.x").as_slice();
    let include_bytes_cm3 = include_bytes!("memory_cm3.x").as_slice();
    let (memory_file, include_bytes) = match target.as_str() {
        "thumbv6m-none-eabi" => ("memory_cm0.x", include_bytes_cm0),
        "thumbv7m-none-eabi" => ("memory_cm3.x", include_bytes_cm3),
        t if t.contains("thumbv7") => ("memory_cm3.x", include_bytes_cm3),
        _ => panic!("Unsupported target: {}", target),
    };

    // Put `memory.x` in output directory and add to linker search path
    let out = &PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    File::create(out.join("memory.x"))
        .expect("Failed to create memory.x")
        .write_all(include_bytes)
        .expect("Failed to write memory.x");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed={}", memory_file);

    // Linker flags for cortex-m-rt
    println!("cargo:rustc-link-arg=--nmagic");
    println!("cargo:rustc-link-arg=-Tlink.x");

    // Set target-specific cfg flags
    if target.contains("thumbv6m") {
        println!("cargo:rustc-cfg=thumbv6m");
    } else if target.contains("thumbv7em") {
        println!("cargo:rustc-cfg=thumbv7em");
    } else if target.contains("thumbv7m") {
        println!("cargo:rustc-cfg=thumbv7m");
    }
}
