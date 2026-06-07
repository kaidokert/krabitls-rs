use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let out = &PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    File::create(out.join("memory.x"))
        .expect("Failed to create memory.x")
        .write_all(include_bytes!("memory.x"))
        .expect("Failed to write memory.x");

    // riscv-rt's `link.x` places `.eh_frame` / `.eh_frame_hdr` as `(INFO)`
    // sections with no anchor region. lld defaults them to address 0, so
    // the PCREL32 fixups from `.text` at 0x80000000 overflow as soon as
    // the binary grows past a few KiB. With `panic = "abort"` we don't
    // unwind, so drop the sections entirely.
    //
    // We can't modify riscv-rt's `link.x` in place, but our `OUT_DIR` is
    // added to the linker search path before riscv-rt's, so `-Tlink.x`
    // resolves to a copy we write here. Find riscv-rt's generated
    // `link.x` by walking up to the workspace `build/` directory, copy
    // it, and strip the offending two lines.
    let our_build_dir = out
        .parent()
        .expect("OUT_DIR has no parent")
        .parent()
        .expect("OUT_DIR has no grandparent");
    let riscv_rt_link_x = fs::read_dir(our_build_dir)
        .expect("read build dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("riscv-rt-"))
                .unwrap_or(false)
                && p.join("out").join("link.x").is_file()
        })
        .map(|p| p.join("out").join("link.x"))
        .expect(
            "could not find riscv-rt's generated link.x; ensure riscv-rt build script ran first",
        );
    let original = fs::read_to_string(&riscv_rt_link_x).expect("read riscv-rt link.x");
    let patched: String = original
        .lines()
        .filter(|line| !line.contains(".eh_frame"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(out.join("link.x"), patched).expect("write patched link.x");

    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-arg=-Tmemory.x");
    println!("cargo:rustc-link-arg=-Tlink.x");
}
