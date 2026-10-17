use std::{
    env, fs,
    path::{Path, PathBuf},
};

const SCE9_RELATIVE: &str = "ra/fsp/src/r_sce_protected/crypto_procedures_protected/src/sce9";

fn collect_c_files(directory: &Path, files: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
        .map(|entry| entry.expect("read SCE9 directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_c_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "c") {
            files.push(path);
        }
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=RENESAS_FSP_PATH");
    println!("cargo:rerun-if-changed=c/sce9_shim.c");
    println!("cargo:rerun-if-changed=compat/bsp_api.h");
    println!("cargo:rerun-if-changed=compat/r_sce_cfg.h");
    println!("cargo:rerun-if-changed=compat/string.h");

    if env::var_os("CARGO_FEATURE_QUALIFICATION").is_some() {
        let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
        fs::write(out.join("memory.x"), include_bytes!("memory.x"))
            .expect("write qualification linker script");
        println!("cargo:rustc-link-search={}", out.display());
        println!("cargo:rerun-if-changed=memory.x");
    }

    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("arm") {
        return;
    }

    let fsp_root = PathBuf::from(env::var_os("RENESAS_FSP_PATH").unwrap_or_else(|| {
        panic!(
            "RENESAS_FSP_PATH must point to the Renesas FSP v6.6.0 checkout; see hardware/ra6m5/README.md"
        )
    }));
    let sce9 = fsp_root.join(SCE9_RELATIVE);
    let version = fsp_root.join("version.txt");
    if !sce9.join("public/r_sce.c").is_file() {
        panic!(
            "{} is not an FSP checkout containing SCE9",
            fsp_root.display()
        );
    }
    if version.is_file() {
        println!("cargo:rerun-if-changed={}", version.display());
    }

    let mut sources = Vec::new();
    collect_c_files(&sce9.join("primitive"), &mut sources);
    collect_c_files(&sce9.join("private"), &mut sources);
    collect_c_files(&sce9.join("public"), &mut sources);
    sources.push(PathBuf::from("c/sce9_shim.c"));
    for source in &sources {
        println!("cargo:rerun-if-changed={}", source.display());
    }

    let mut build = cc::Build::new();
    build
        .compiler("clang")
        .target("thumbv8m.main-none-eabihf")
        .flag("--target=arm-none-eabi")
        .flag("-mcpu=cortex-m33")
        .flag("-mthumb")
        .flag("-mfloat-abi=hard")
        .flag("-mfpu=fpv5-sp-d16")
        .flag("-ffreestanding")
        .flag("-fno-strict-aliasing")
        .flag("-ffunction-sections")
        .flag("-fdata-sections")
        .flag("-fno-short-enums")
        .flag("-Wno-unused-parameter")
        .include("compat")
        .include(sce9.join("inc/api"))
        .include(sce9.join("inc/instances"))
        .include(sce9.join("private/inc"))
        .include(sce9.join("primitive"))
        .files(sources);
    build.compile("ra6m5_sce9");
}
