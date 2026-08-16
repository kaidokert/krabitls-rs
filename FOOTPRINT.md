# Footprint

Peak stack and `.text` for a full TLS 1.3 handshake, measured on QEMU (real
binary minus a baseline stub that touches the same fixtures). Numbers reflect
what a real caller sees: each row drives `connect` across a call boundary, not
inlined into the measurement harness. Regenerate with `python3
footprint/run_suite.py`.

- **Stack** — peak painted stack during the handshake, minus the harness baseline.
- **.text** — real `.text` minus the baseline stub's.
- **Client cert** — mutual TLS: the client also sends a Certificate +
  CertificateVerify (its own signature). Cost is dominated by that client
  signature, so it is roughly key-exchange- and cipher-independent.

Peak stack is the per-record key-schedule storage plus the deepest crypto chain;
the bulk of a large row is the asymmetric primitive (ML-DSA / ML-KEM / RSA), not
the protocol.

## Cortex-M3 (`thumbv7m-none-eabi`)

| KEX             | AEAD              | Server cert  | Client cert  | .text (KiB) | Stack (B) |
|-----------------|-------------------|--------------|--------------|------------:|----------:|
| X25519          | ChaCha20-Poly1305 | Ed25519      | —            |        37.5 |    10 660 |
| X25519          | AES-128-GCM       | Ed25519      | —            |        41.0 |    10 604 |
| X25519          | AES-128-GCM       | RSA-2048-PSS | —            |        47.8 |    29 492 |
| X25519          | AES-128-GCM       | ECDSA-P256   | —            |        58.5 |     9 716 |
| P-256 ECDHE     | AES-128-GCM       | Ed25519      | —            |        50.1 |    12 884 |
| X25519          | AES-128-GCM       | Ed25519      | Ed25519      |        47.1 |    12 484 |
| X25519          | AES-128-GCM       | ECDSA-P256   | ECDSA-P256   |        75.8 |    12 844 |
| X25519          | AES-128-GCM       | Ed25519      | RSA-2048-PSS |        55.4 |    47 268 |
| X25519          | AES-128-GCM       | RSA-2048-PSS | RSA-2048-PSS |        55.3 |    47 276 |
| X25519          | ChaCha20-Poly1305 | Ed25519      | Ed25519      |        43.6 |    12 668 |
| X25519MLKEM768  | AES-128-GCM       | Ed25519      | —            |        54.6 |    86 268 |
| X25519          | AES-128-GCM       | ML-DSA-44    | —            |        53.3 |    42 748 |
| X25519MLKEM768  | AES-128-GCM       | ML-DSA-44    | —            |        62.1 |   107 668 |
| X25519MLKEM768  | ChaCha20-Poly1305 | ML-DSA-44    | —            |        58.1 |   107 668 |

## RV32IMAC (`riscv32imac-unknown-none-elf`)

| KEX             | AEAD              | Server cert  | Client cert  | .text (KiB) | Stack (B) |
|-----------------|-------------------|--------------|--------------|------------:|----------:|
| X25519          | ChaCha20-Poly1305 | Ed25519      | —            |        56.7 |    10 524 |
| X25519          | AES-128-GCM       | Ed25519      | —            |        63.9 |    10 476 |
| X25519          | AES-128-GCM       | RSA-2048-PSS | —            |        74.9 |    29 412 |
| X25519          | AES-128-GCM       | ECDSA-P256   | —            |        91.6 |     9 596 |
| P-256 ECDHE     | AES-128-GCM       | Ed25519      | —            |        78.1 |    12 748 |
| X25519          | AES-128-GCM       | Ed25519      | Ed25519      |        74.8 |    12 396 |
| X25519          | AES-128-GCM       | ECDSA-P256   | ECDSA-P256   |       119.3 |    12 744 |
| X25519          | AES-128-GCM       | Ed25519      | RSA-2048-PSS |        87.8 |    46 892 |
| X25519          | AES-128-GCM       | RSA-2048-PSS | RSA-2048-PSS |        87.8 |    46 908 |
| X25519          | ChaCha20-Poly1305 | Ed25519      | Ed25519      |        67.6 |    12 572 |
| X25519MLKEM768  | AES-128-GCM       | Ed25519      | —            |        85.4 |    90 324 |
| X25519          | AES-128-GCM       | ML-DSA-44    | —            |        82.7 |    42 724 |
| X25519MLKEM768  | AES-128-GCM       | ML-DSA-44    | —            |        96.2 |   111 640 |
| X25519MLKEM768  | ChaCha20-Poly1305 | ML-DSA-44    | —            |        87.9 |   111 636 |
