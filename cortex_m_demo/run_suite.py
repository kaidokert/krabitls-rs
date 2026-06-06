#!/usr/bin/env python3
"""Build and run krabitls examples on QEMU, emit the M3 footprint table.

For each row the suite builds two binaries: a `baseline` build (the crypto
+ protocol path replaced by a do-nothing stub touching the same rodata) and
a real build. Reported `.text` and stack values are real-minus-baseline
deltas, isolating the cost of krabitls + the AEAD + the sig-verify path
from the harness floor.
"""

import re
import subprocess
import sys

# (row label, example, cargo --features on the real build)
# Each row is built twice: once with `baseline` added to the feature list,
# once without. The real build's column values are reported as
# real-minus-baseline deltas.
ROWS = [
    ("AES-128-GCM",       "Ed25519",      "krabitls",        []),
    ("ChaCha20-Poly1305", "Ed25519",      "krabitls_chacha", ["chacha20"]),
    ("AES-128-GCM",       "RSA-2048-PSS", "krabitls_rsa",    ["rsa"]),
]
TARGET = "thumbv7m-none-eabi"
TARGET_LABEL = "M3"
TIMEOUT_RUN = 120
TIMEOUT_BUILD = 600

# Wire-data buffer footprint each example allocates on the stack (8 KiB
# per-record decrypt scratch + 8 KiB flight accumulator). Kept identical
# across all examples so the rows compare directly; subtracted here so
# the reported stack delta isolates the crypto + protocol cost.
BUFFER_DISCOUNT = 16 * 1024


def run_cmd(args, timeout=TIMEOUT_RUN):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def cargo_features_arg(features):
    return ["--features", ",".join(features)] if features else []


def build(example, features):
    args = (
        ["cargo", "build", "--target", TARGET, "--release", "--example", example]
        + cargo_features_arg(features)
    )
    r = run_cmd(args, timeout=TIMEOUT_BUILD)
    if r.returncode != 0:
        print(
            f"BUILD FAILED: example={example} features={features}\n{r.stderr}",
            file=sys.stderr,
        )
        return False
    return True


def text_size(example, _features):
    """`.text` section size in bytes via `arm-none-eabi-size` on the linked ELF."""
    binary = f"target/{TARGET}/release/examples/{example}"
    r = run_cmd(["arm-none-eabi-size", binary], timeout=60)
    if r.returncode != 0:
        print(f"arm-none-eabi-size failed: {r.stderr}", file=sys.stderr)
        return None
    # Output: "   text   data    bss    dec    hex    filename"
    #         "  47252      0     16  47268   b8a4    target/..."
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    if len(lines) < 2:
        return None
    try:
        return int(lines[1].split()[0])
    except (ValueError, IndexError):
        return None


def qemu_run(example, features):
    """Run on QEMU; return stdout+stderr (semihosting tees to both)."""
    args = (
        ["cargo", "run", "--target", TARGET, "--release", "--example", example]
        + cargo_features_arg(features)
    )
    r = run_cmd(args)
    return r.stdout + r.stderr


METRIC_RE = re.compile(r"METRIC stack:(\d+) kcycles:\d+ target:(\S+) name:(\S+)")


def parse_metric(output):
    m = METRIC_RE.search(output)
    if not m:
        return None
    return {"stack": int(m.group(1)), "target": m.group(2), "name": m.group(3)}


def measure(example, features):
    """Build + size + run + parse METRIC. Returns (text_size, stack) or (None, None)."""
    if not build(example, features):
        return None, None
    ts = text_size(example, features)
    out = qemu_run(example, features)
    if f"{example} ACCEPT" not in out:
        print(f"NOT ACCEPTED: example={example} features={features}", file=sys.stderr)
        return ts, None
    metric = parse_metric(out)
    return ts, metric["stack"] if metric else None


def main():
    failures = []
    rendered_rows = []
    for suite, sig, example, features in ROWS:
        baseline_text, baseline_stack = measure(example, features + ["baseline"])
        real_text, real_stack = measure(example, features)
        if None in (baseline_text, real_text, baseline_stack, real_stack):
            failures.append(f"{example}: incomplete measurement")
            rendered_rows.append((suite, sig, "-", "-"))
            continue
        dtext_kib = (real_text - baseline_text) / 1024
        # Each example allocates 8 KiB record + 8 KiB flight buffers on the
        # stack so all three rows pay the same wire-data cost; subtract that
        # 16 KiB uniformly to report the "crypto + protocol" stack delta.
        dstack = real_stack - baseline_stack - BUFFER_DISCOUNT
        rendered_rows.append((suite, sig, f"{dtext_kib:.1f}", f"{dstack}"))

    print()
    print("Values are real-minus-baseline deltas: the incremental flash and stack")
    print("cost of krabitls + the AEAD + the sig-verify path over the harness floor.")
    print()
    print("| Target | Suite             | Sig          | .text (KiB) | Stack (B) |")
    print("|--------|-------------------|--------------|------------:|----------:|")
    for suite, sig, dtext, dstack in rendered_rows:
        print(f"| {TARGET_LABEL:<6} | {suite:<17} | {sig:<12} | {dtext:>11} | {dstack:>9} |")

    if failures:
        print(f"\nFailures: {len(failures)}", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
