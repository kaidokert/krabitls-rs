# Rustc bug 1 — `rsa_heapless::cios_mont_mul` infinite-loop on thumbv7m at `opt-level=z`

Discovered while migrating the cortex-m RSA footprint demo to drive the
full TLS 1.3 facade. RSA-2048 PSS verify on QEMU `thumbv7m-none-eabi`
runs forever; AES and ChaCha demos finish normally. Root-caused to a
MIR-opt change in `rust-lang/rust`; fix already in master, will ship in
stable rustc 1.97 (≈ early July 2026). No upstream issue to file —
already tracked, already fixed.

## Trigger

Build the cortex-m `krabitls_rsa` footprint example:

```
cargo build --release --manifest-path=footprint/cortex-m/Cargo.toml \
  --example krabitls_rsa --target thumbv7m-none-eabi \
  --features rsa,canned-replay
```

Under release profile `opt-level = "z"` + `lto = true`, the binary
spins forever in QEMU. No output, no panic. Witnessed in CI as a job
that burns through the full 6 h limit before being cancelled.

## Workaround in this repo

Bundled with the bug-2 mitigation: the `#[inline(never)]` on
`krabitls::backends::rsa_verify::build_vk_pair` (which we already need
for bug 2) ALSO masks bug 1. Adding an inline barrier at the krabitls
call site shifts the codegen LLVM sees through the chain down into
`rsa_heapless::cios_mont_mul` enough that the buggy MIR-opt no longer
turns the modexp loop infinite.

Originally we shipped a separate per-package profile override
(`[profile.release.package.rsa_heapless] opt-level = 2` in both
`footprint/cortex-m/Cargo.toml` and `footprint/risc-v/Cargo.toml`),
which also worked. Dropped that in favour of the single call-site
attribute — one workaround instead of two, costs ~320 bytes / ~7 %
verify perf on M3 RSA and is far harder for a future contributor to
accidentally "clean up". Both M3 and RV32 RSA still ACCEPT cleanly
without the override.

When stable rustc 1.97 ships (~early July 2026), bug 1's underlying
miscompile is gone upstream. The `#[inline(never)]` stays until bug 2
is also fixed; once both are resolved upstream the attribute can come
off entirely.

## Symptoms in QEMU

`stack:` reading: harness never reaches the print step.
`kcycles:` reading: same.
QEMU stays at ~100 % CPU forever (one of my zombie processes accumulated
210 minutes of CPU before I killed it).

The "Timer with period zero, disabling" message that LM3S6965 prints at
startup is unrelated — that line shows up on every successful run too.

## How we bisected

Three things had to be true before bisection was even useful:

1. The facade-driven RSA demo had to actually start running. It
   wouldn't until we moved the ~37 KiB `DefaultScratch` out of stack
   into `.bss` via a `Mutex<RefCell<_>>` slot (`facade_scratch::with`
   in `footprint/handshakes/src/lib.rs`). Otherwise the M3's 64 KiB
   SRAM overflowed during RSA verify.
2. The seed-0 RSA fixture cert had to be PSS-signed (was PKCS#1-v1.5
   originally), so the `rsa_pss_only` feature wouldn't reject it at
   parse time. Re-signed in `tls_fixture/tls13.py`.
3. The crate-graph bisection had to be done with per-package profile
   overrides in `footprint/cortex-m/Cargo.toml`:

   ```toml
   [profile.release.package.<crate>]
   opt-level = 2
   ```

   That isolates which crate at `-Oz` is the source. Bisected to
   `rsa_heapless`.

With that in place, the toolchain bisection was just `rustup install
nightly-YYYY-MM-DD` plus a 30-second QEMU timeout to detect "hangs vs
finishes." Six iterations narrowed it to one day in `rust-lang/rust`
master:

| toolchain | master HEAD date | bug 1 |
|---|---|---|
| stable 1.96.0 (`ac68faa20`) | 2026-05-25 | hangs |
| stable 1.93.1 | 2026-02-11 | hangs |
| nightly-2026-04-15 | 2026-04-14 | hangs |
| nightly-2026-04-17 (`7af3402cd`) | 2026-04-16 | hangs |
| nightly-2026-04-18 (`e9e32aca5`) | 2026-04-17 | hangs |
| nightly-2026-04-19 (`0febdbab2`) | 2026-04-18 | **fixed** |
| nightly-2026-04-23 | 2026-04-22 | fixed |
| nightly-2026-05-01 | 2026-04-30 | fixed |
| nightly-2026-05-19 | 2026-05-18 | fixed |
| nightly-2026-06-06 | 2026-06-05 | fixed |
| nightly-2026-06-19 | 2026-06-18 | fixed |

Then `gh api repos/rust-lang/rust/compare/e9e32aca5...0febdbab2` to
list commits in that one-day window, filtered for codegen-relevant
keywords. One commit stood out.

## Root cause

[rust-lang/rust#142531 — "Remove fewer Storage calls in CopyProp and
GVN"](https://github.com/rust-lang/rust/pull/142531), commit
`5632001f83`, merged 2026-04-18 12:21 UTC.

Tracks issue [rust-lang/rust#141649](https://github.com/rust-lang/rust/issues/141649)
("Missed optimization: multiple instances of a small struct don't
reuse the stack allocation"). The underlying problem was that the
`CopyProp` and `GVN` MIR-opt passes were dropping `StorageLive` and
`StorageDead` markers around stack locals more aggressively than was
safe. Without those markers LLVM has no idea when a local goes out of
scope, which both blocks legitimate stack-reuse optimizations and —
under enough downstream optimization — can cause incorrect transforms.

In our case, on `thumbv7m` at `-Oz`, the loss of storage markers
around the inner counter of `rsa_heapless::cios_mont_mul`
(Coarsely-Integrated Operand Scanning Montgomery multiplication) gave
LLVM enough rope to apply a loop transformation that turned a finite
counter loop into an infinite one. The constant-time variant
(`cios_mont_mul_ct`) sits in the same call graph; either or both may be
involved.

We did not extract a minimal repro because the upstream fix already
exists. PR #142531 also adds regression tests at
`tests/assembly-llvm/issue-141649.rs` and
`tests/codegen-llvm/issues/issue-141649.rs`.

## Lifecycle

- **Already fixed in master.** Will ship in stable rustc 1.97 (the next
  stable release after 1.96.0, scheduled ~early July 2026).
- **Remove the workaround when:** stable rustc reports `>= 1.97.0`.
  Drop the `[profile.release.package.rsa_heapless]` block from both
  `footprint/cortex-m/Cargo.toml` and `footprint/risc-v/Cargo.toml`.
  Re-verify with `cargo build --release ... --example krabitls_rsa
  --target thumbv7m-none-eabi --features rsa,canned-replay` followed
  by a 30-second QEMU run — expect `ACCEPT` in a few million cycles.

## What this taught us

- The `rustup install nightly-YYYY-MM-DD` + per-package profile
  override workflow is a fast way to identify _which_ crate is
  affected by a codegen bug — much faster than per-function
  `#[inline(never)]` games.
- The 6-week stable release cadence means most "real LLVM bugs"
  encountered on stable have already been fixed in master and are
  waiting in the queue. Worth checking before reducing.
- For bug 2 (`build_vk_pair` wrong-result on thumbv7m, still live on
  the latest nightly), this shortcut won't help — that one needs an
  actual reduction.
