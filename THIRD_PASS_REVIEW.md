# Third-pass review — whole-crate design pass

Scope: this pass looks at the crate as a small `no_std`, no-heap TLS 1.3 client for compact embedded targets, not just the recent cert-validity refactor. I still call out the recent `NoClock` / `Clocked` work where relevant, but the notes below are organized around crate-level design, correctness boundaries, API shape, code-size/stack tradeoffs, and maintainability under the project rules: no heap, avoid panics, compact code size.

## Executive summary

The crate has a coherent compact-embedded architecture:

- Caller-owned `Scratch` buffers make memory use explicit and avoid heap allocation.
- `TlsConnection<State, H>` typestate keeps the protocol-phase API hard to misuse internally.
- `TlsEngine` wraps that typestate in a small event machine for blocking transport integration.
- Feature flags and runtime suite policy keep crypto/linkage costs under user control.
- The verification strategy split (`VerifyStrategy`, `TrustRootDecision`, `SafeStrategy`, `Clock`) is a good direction for making security policy explicit without forcing a CA-store model.

I did not find a clear “must fix before merge” runtime correctness issue in this pass. The main risks are documentation/API-contract clarity and a few structural opportunities to better encode invariants or reduce duplicated constants. The highest-value cleanup remains stale documentation from the old `validity` feature model, because it now conflicts with the type-level `NoClock` / `Clocked` design.

## Crate-level strengths

### 1. Memory ownership matches the no-heap goal

`Scratch<FLIGHT, RECV, SEND>` is a good central abstraction: it makes the largest memory costs visible at the type level, supports static placement through `const fn new`, and keeps backend choice orthogonal to buffer sizing. The comments explaining what each buffer bounds are useful for embedded callers sizing `.bss` deliberately.

This is preferable to hiding fixed buffers inside `TlsStream`, because users can decide whether they want the public-internet default or a smaller controlled-profile footprint.

### 2. Typestate is used in the right layer

The lower-level `TlsConnection<State, H>` typestate is a strong Rust fit: illegal protocol transitions become missing methods rather than runtime branches. Keeping `TlsEngine` as the wrapper that converts typestate transitions into `Send` / `Recv` / `AppData` events is a reasonable compromise: compact internal correctness without forcing a complex typestate API on the public blocking facade.

### 3. The verification strategy design is appropriately explicit

The newer `SafeStrategy<T, C, K = NoClock>` direction is a strong improvement over an optional per-call clock. It makes “validity skipped” visible in the type and lets `Clocked<T>` carry the cost in a separate monomorphization. That fits the crate’s goals better than dynamic dispatch or hidden runtime options.

### 4. Error enums are generally panic-avoiding and inspectable

Most protocol/encoding failures are propagated through small error enums instead of `.unwrap()` / `.expect()`, including internal “should be unreachable” encoding failures. This is the right bias for a TLS implementation, especially under `no_std`.

## Findings / risks / suggestions

### 1. Stale documentation from the old `validity` feature model is misleading

Some comments still describe a separate `validity` feature, `MissingClock`, and tests excluding validity. The current model is different: the concrete validity parser is tied to `cert-der`, default verification uses `NoClock`, and validity is opt-in with `Clocked`.

Examples to update:

- `krabitls/tests/canned_handshake.rs` still says `validity` is excluded because fixture code lacks a `TimeSource` and would fail with `MissingClock`.
- `krabitls/tests/strategy_coverage.rs` has the same old rationale.
- `krabitls/Cargo.toml` docs.rs comments still say default features omit the “validity TimeSource,” but `TimeSource` is now part of the public client surface regardless of that old feature.

Suggested fix: update these comments to the current `NoClock` / `Clocked` / `cert-der` model. This is not nitpicky: security posture is encoded in public API types, so stale comments can lead users to think validity is enabled, disabled, or feature-gated differently than it really is.

### 2. Document the trust-root / validity ordering as a contract

`SafeStrategy::verify_chain` parses the chain, verifies per-link signatures, calls `TrustRootDecision::accept_chain`, then checks validity over all parsed certs through `Clock`.

That ordering is reasonable, but it is now part of the security contract. A custom `TrustRootDecision` cannot observe validity details because validity is enforced separately by `SafeStrategy` and collapsed to `SafeStrategyError::Validity`. If this is intentional, document it directly on `TrustRootDecision`, `SafeStrategy`, or both.

Suggested wording direction: “`accept_chain` decides whether the structurally verified path terminates in an acceptable trust root. Time validity is a separate `Clock` policy owned by `SafeStrategy` and is evaluated independently.”

### 3. Consider sealing or explicitly blessing `Clock` as a policy hook

`Clock` is public and compact, but it is more powerful than a wall-clock interface: downstream implementations can skip validity, reject all certs, or add unrelated policy. That may be exactly what advanced users need, but it should be named/documented as a policy hook if so.

Two acceptable paths:

- Seal `Clock` and expose only `NoClock` and `Clocked<T: TimeSource>` if the crate wants a narrow, auditable validity switch.
- Keep `Clock` public, but document that it is an extension point whose implementor participates in verification policy.

The first path narrows the security surface; the second path preserves flexibility. Both are compatible with no-heap and compact-code goals.

### 4. Preserve detailed validity diagnostics where they are useful, but keep the compact path lean

`ValidityRejected` intentionally erases concrete `ValidityError` details to avoid dragging DER-gated error types into the always-compiled strategy surface. That is good for compact builds. However, its current doc comment suggests a `Clocked` strategy can log details before erasing them, while the bundled `Clocked<T>` simply maps every validity error to `ValidityRejected`.

Suggested fix: adjust docs to say detailed diagnostics are available only to custom `Clock` implementations or direct calls to `identity::verify_validity`. Do not add logging to the embedded default path.

### 5. Buffer-size invariants are well documented but could be encoded one step earlier

The public scratch constants (`MIN_RECV`, `MIN_SEND_STANDARD`, `DefaultScratch`) are clear, and construction-time validation is acceptable. If future refactors touch this area, consider whether a tiny `const` assertion pattern can catch obviously invalid default aliases or internal aliases at compile time, while still keeping user-provided const generics runtime-validated.

This is not urgent. The current runtime validation is probably the right tradeoff for user-supplied const generics, but compile-time self-checks on crate-provided aliases can prevent accidental regressions without code-size cost.

### 6. Consider newtypes for negotiated record limits

`our_recv_limit` and `peer_recv_limit` are plain `u16`s that carry protocol constraints from RFC 8449. The code already validates floors/ceilings in several places, but a small internal newtype such as `RecordSizeLimit(u16)` could encode “already validated” and reduce accidental mixing with arbitrary lengths.

This may or may not be worth the extra code. If implemented carefully as a `#[repr(transparent)]` internal type with `const` constructors for known-good defaults and `TryFrom<u16>` for peer values, it could improve correctness without heap or meaningful size cost. If it makes call sites noisier, skip it.

### 7. Centralize duplicated TLS record constants where practical

`CT_APPLICATION_DATA`, `CT_HANDSHAKE`, and alert constants appear in multiple layers. Some duplication is deliberate to avoid exposing internals or feature-gated test-only paths, but repeated numeric constants are an easy place for drift.

Suggested fix: when next touching these modules, prefer reusing the crate-level constants where it does not increase visibility or code size. Do not do a broad churn-only refactor; just prevent new duplication.

### 8. Reassembler and engine invariants deserve continued targeted tests

The receive state invariants are documented, and the test coverage looks strong around parking plaintext, compaction, record-size limits, and post-handshake behavior. Keep adding focused state-machine tests when modifying `TlsEngine`; this area is where compact buffer reuse can most easily create subtle bugs.

A useful future direction would be small table-driven tests for event priority (`Send > HandshakeDone > AppData > Closed > Recv`) and for close/error interactions. The existing style already points in this direction.

### 9. Public API naming is compact, but some aliases could advertise security posture more clearly

`DefaultVerify = SafeStrategy<PinOrSelfSigned, DerCert>` is compact, but users may not immediately realize that the default clock parameter is `NoClock`. The docs now mention `.clocked()`, but the alias name itself hides the validity posture.

Suggested fix: not necessarily a rename, because compact API matters. Instead, add a short doc line near `DefaultVerify` saying “uses `NoClock`; call `.clocked(...)` to check certificate validity windows.” That makes the security default explicit without adding API surface.

### 10. Avoid adding more public generics unless they buy compile-time guarantees

The crate already exposes several const generics and strategy generics. They serve real goals: no heap, configurable buffers, selectable crypto/config, bounded chain depth. Future API changes should be cautious about adding more generic parameters unless they remove runtime states or avoid linked code. Otherwise, aliases like `DefaultStream` become increasingly important for ergonomics.

### 11. Test-only panics are acceptable; production panic surface looks intentionally small

Most `unwrap()` / `panic!()` occurrences are test helpers, fixture decoding, or build-script style checks. The production-facing paths generally propagate errors. Keep that boundary clear: test fixture helpers can panic loudly, but any parser/handshake path handling peer input should continue returning typed errors.

One small cleanup: `krabitls/src/traits/verify_strategy.rs` has duplicate `use super::*;` lines in its test module. Harmless, but worth removing when next editing that file.

### 12. README accurately warns users, but crate docs could mirror the same threat model

The README is admirably direct: hobby project, fixed profile, no CA bundle, unaudited, not constant-time. Consider mirroring a condensed version of that warning in the crate-level docs so docs.rs users see the same threat model without opening the repository README.

This is especially important because the API is polished enough that users may otherwise overestimate the security level.

## Checks run during this review

- `cargo test` from `krabitls/`: passed after broadening this review file.
- `cargo test --workspace` from the repository root: not applicable because the repository root does not contain a `Cargo.toml` workspace manifest.

## Overall assessment

The crate design is consistent with its stated constraints: no heap, compact target, explicit buffers, typestate where it pays off, and no broad CA-store ambition. I would not recommend a large architecture rewrite. The best next steps are documentation/API-contract tightening, small invariant-encoding improvements where they do not add code size, and continued targeted tests around buffer reuse and state-machine edges.
