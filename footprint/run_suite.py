#!/usr/bin/env python3
"""Build + run the krabitls footprint examples on QEMU for every supported
target, emit one combined `.text` / stack table.

For each (target, row) pair the suite builds two binaries — a `baseline`
build (crypto + protocol path replaced by a do-nothing stub touching the
same rodata) and a real build — and reports the real-minus-baseline delta.
The wire-data scratch buffers live in `.bss` via
`footprint_handshakes::with_buffers`, so the stack column is the honest
crypto + protocol cost (no fictional discount).

Must be run from the `footprint/` directory.
"""

import re
import subprocess
import sys

# (suite label, sig label, example, no_default_features, cargo --features list)
# Every row pins features explicitly: no defaults, exactly one cipher,
# exactly one sig algorithm. `tlv_cert` (the `not(cert-der)` fallback)
# is picked over the heavier `der`-crate parser. Order is
# smallest-to-largest footprint.
ROWS = [
    ("ChaCha20-Poly1305", "Ed25519",      "krabitls_chacha", True, ["chacha20", "canned-replay"]),
    ("AES-128-GCM",       "Ed25519",      "krabitls",        True, ["cipher-aes", "canned-replay"]),
    ("AES-128-GCM",       "RSA-2048-PSS", "krabitls_rsa",    True, ["cipher-aes", "rsa", "canned-replay"]),
    ("AES-128-GCM",       "ECDSA-P256",   "krabitls_ecdsa",  True, ["cipher-aes", "ecdsa", "canned-replay"]),
    ("AES-128-GCM",       "X25519MLKEM768",   "krabitls_mlkem",       True, ["cipher-aes", "mlkem", "canned-replay"]),
    ("AES-128-GCM",       "ML-DSA-44",        "krabitls_mldsa",       True, ["cipher-aes", "mldsa", "canned-replay"]),
    ("AES-128-GCM",       "MLKEM768+MLDSA44", "krabitls_mlkem_mldsa", True, ["cipher-aes", "mlkem", "mldsa", "canned-replay"]),
    ("ChaCha20-Poly1305", "MLKEM768+MLDSA44", "krabitls_chacha_mlkem_mldsa", True, ["chacha20", "mlkem", "mldsa", "canned-replay"]),
]

# (label, directory, cargo --target)
TARGETS = [
    ("M3",         "cortex-m", "thumbv7m-none-eabi"),
    ("RV32IMAC",   "risc-v",   "riscv32imac-unknown-none-elf"),
]

TIMEOUT_RUN = 60
TIMEOUT_BUILD = 600


def find_llvm_size():
    """Locate `llvm-size` shipped with the active rustc — works for any
    target ELF, so we don't need per-target binutils on the host."""
    sysroot = subprocess.check_output(
        ["rustc", "--print", "sysroot"], text=True
    ).strip()
    import os
    for entry in os.listdir(os.path.join(sysroot, "lib", "rustlib")):
        path = os.path.join(sysroot, "lib", "rustlib", entry, "bin", "llvm-size")
        if os.path.isfile(path):
            return path
    raise RuntimeError(
        "llvm-size not found; install with `rustup component add llvm-tools`"
    )


SIZE_TOOL = find_llvm_size()


def run_cmd(args, cwd=None, timeout=TIMEOUT_RUN):
    try:
        return subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, cwd=cwd
        )
    except subprocess.TimeoutExpired as e:
        # Mark the row as failed instead of crashing the whole suite — one
        # hung example shouldn't take out every measurement after it.
        return subprocess.CompletedProcess(
            args=args,
            returncode=124,
            stdout=e.stdout.decode("utf-8", errors="replace") if e.stdout else "",
            stderr=(e.stderr.decode("utf-8", errors="replace") if e.stderr else "")
            + f"\nTIMEOUT after {timeout}s: {' '.join(args)}",
        )


def cargo_features_arg(features, no_default):
    args = []
    if no_default:
        args.append("--no-default-features")
    if features:
        args += ["--features", ",".join(features)]
    return args


def build(target_dir, target_triple, example, no_default, features):
    args = (
        ["cargo", "build", "--target", target_triple, "--release", "--example", example]
        + cargo_features_arg(features, no_default)
    )
    r = run_cmd(args, cwd=target_dir, timeout=TIMEOUT_BUILD)
    if r.returncode != 0:
        print(
            f"BUILD FAILED: dir={target_dir} example={example} features={features}\n{r.stderr}",
            file=sys.stderr,
        )
        return False
    return True


def text_size(target_dir, target_triple, example):
    """`.text` section size in bytes via `llvm-size` (target-agnostic)."""
    binary = f"{target_dir}/target/{target_triple}/release/examples/{example}"
    r = run_cmd([SIZE_TOOL, binary], timeout=60)
    if r.returncode != 0:
        print(f"llvm-size failed: {r.stderr}", file=sys.stderr)
        return None
    # Output: "   text   data    bss    dec    hex    filename"
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    if len(lines) < 2:
        return None
    try:
        return int(lines[1].split()[0])
    except (ValueError, IndexError):
        return None


def qemu_run(target_dir, target_triple, example, no_default, features):
    """Run the example under QEMU; return stdout+stderr."""
    args = (
        ["cargo", "run", "--target", target_triple, "--release", "--example", example]
        + cargo_features_arg(features, no_default)
    )
    r = run_cmd(args, cwd=target_dir)
    return r.stdout + r.stderr


STACK_RE = re.compile(
    r"EM_STACK schema:\d+ benchmark:(\S+) used:(\d+).* architecture:(\S+)"
)
OUTCOME_RE = re.compile(r"EM_OUTCOME schema:\d+ benchmark:(\S+) status:PASS(?: |$)")


def parse_metric(output):
    m = STACK_RE.search(output)
    if not m:
        return None
    return {"stack": int(m.group(2)), "target": m.group(3), "name": m.group(1)}


def measure(target_dir, target_triple, example, no_default, features):
    """Build + size + run + parse METRIC. Returns (text_size, stack) or (None, None)."""
    if not build(target_dir, target_triple, example, no_default, features):
        return None, None
    ts = text_size(target_dir, target_triple, example)
    out = qemu_run(target_dir, target_triple, example, no_default, features)
    if not any(match.group(1) == example for match in OUTCOME_RE.finditer(out)):
        print(
            f"NOT ACCEPTED: dir={target_dir} example={example} features={features}",
            file=sys.stderr,
        )
        return ts, None
    metric = parse_metric(out)
    return ts, metric["stack"] if metric else None


def main():
    failures = []
    rendered_rows = []
    for label, target_dir, target_triple in TARGETS:
        for suite, sig, example, no_default, features in ROWS:
            baseline_text, baseline_stack = measure(
                target_dir, target_triple, example, no_default, features + ["baseline"]
            )
            real_text, real_stack = measure(
                target_dir, target_triple, example, no_default, features
            )
            if None in (baseline_text, real_text, baseline_stack, real_stack):
                failures.append(f"{label}/{example}: incomplete measurement")
                rendered_rows.append((label, suite, sig, "-", "-"))
                continue
            dtext_kib = (real_text - baseline_text) / 1024
            dstack = real_stack - baseline_stack
            rendered_rows.append((label, suite, sig, f"{dtext_kib:.1f}", f"{dstack}"))

    print()
    print("Values are real-minus-baseline deltas: the incremental flash and stack")
    print("cost of krabitls + the AEAD + the sig-verify path over the harness floor.")
    print()
    print("| Target   | Suite             | Sig          | .text (KiB) | Stack (B) |")
    print("|----------|-------------------|--------------|------------:|----------:|")
    for label, suite, sig, dtext, dstack in rendered_rows:
        print(
            f"| {label:<8} | {suite:<17} | {sig:<12} | {dtext:>11} | {dstack:>9} |"
        )

    if failures:
        print(f"\nFailures: {len(failures)}", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
