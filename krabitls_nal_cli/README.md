# krabitls_nal_cli

The krabitls TLS 1.3 client, written against the [`embedded-nal`] network
abstraction rather than `std::net`. The concrete stack is injected: on the host
it is [`std-embedded-nal`]; the same code runs unchanged on a target NAL stack
(smoltcp, winc-rs). Because `std-embedded-nal` *is* the std implementation of
`embedded-nal`, this is the single client — there is no separate `std::net`
variant.

## Layers (reusable `no_std` lib)

- **`transport`** — `NalTransport` bridges any [`embedded_nal::TcpClientStack`]
  socket to an [`embedded_io`] byte stream (retries `nb::WouldBlock`, `Ok(0)` =
  EOF, releases the socket on drop). krabitls's blanket `Transport` impl then
  applies, and the resulting `TlsStream` is itself an `embedded_io` stream.
  `connect` / `resolve` drive DNS (or an IP literal) and the handshake.
- **`http`** / **`mqtt`** — probes over *any* `embedded_io` stream, so they run
  over a plaintext socket or a `TlsStream` (→ HTTPS / MQTT-over-TLS) unchanged.
  No allocation; the caller owns the buffers.

The lib is `no_std`/no-alloc. `std` appears only in the `nal_connect` binary
(arg parsing, `std-embedded-nal`, mTLS key loading).

## Run

```
cargo run --bin nal_connect -- --self-signed <host>[:<port>]
cargo run --bin nal_connect -- --pin <hex> <host>
cargo run --bin nal_connect -- --self-signed --mqtt <host>:8883
cargo run --features rsa --bin nal_connect -- \
    --self-signed --client-cert leaf.der --client-rsa-key key.der <host>
```

A trust mode (`--pin` or `--self-signed`) is required; krabitls has no CA
bundle, so an unattended no-pin connect would be MITM-vulnerable. Mutual TLS is
supported via `--client-cert` plus one of `--client-seed` (Ed25519) or
`--client-rsa-key` (needs `--features rsa`).

## Tests

- `tests/nal_handshake.rs` drives `connect` through the seed-0 fixtures over a
  mock `TcpClientStack`, asserting the same byte-exact wire output as
  `krabitls/tests/canned_handshake.rs` — the transport differs, the assertions
  do not.
- `tests/app_probes.rs` exercises `http` / `mqtt` over a mock `embedded_io`
  stream (no TLS), covering status/body parsing, truncation, and CONNACK.

## Deferred

Target/M3 build (a different `Stack` type) and a live pinned soak.

[`embedded-nal`]: https://crates.io/crates/embedded-nal
[`std-embedded-nal`]: https://crates.io/crates/std-embedded-nal
