# Third-pass review

Scope: reviewed the current crate state with emphasis on correctness, leftover detritus, undocumented risks, and opportunities to use Rust's type system idiomatically without violating the no-heap / avoid-panics / compact-code-size goals.

## Summary

Overall, the direction looks good: moving validity from a per-call `Option<&dyn TimeSource>` into the `SafeStrategy<T, C, K = NoClock>` type parameter is a strong embedded/Rust fit. The default `NoClock` monomorphization keeps the compact target credible, while `Clocked<T>` makes the validity-cost opt-in explicit in the type system.

I found no obvious runtime correctness bug in the core handshake path from this pass. The main things I would address are documentation/API detritus from the old `validity` feature model, and one security-semantics risk around whether validity is meant to be part of the trust-root decision or a chain-wide structural check.

## Findings / suggestions

### 1. Stale `validity` feature comments are still present and misleading

The code has moved away from a separate `validity` feature and now gates the concrete DER time parser / `.clocked()` path on `cert-der`, with default `NoClock` skipping the check. However, some comments still describe the old model where tests excluded `validity` because self-signed fixtures had no `TimeSource` and would fail with `MissingClock`.

Examples:

- `krabitls/tests/canned_handshake.rs` still says the `validity` feature is excluded because fixtures call `self_signed(...)` without a `TimeSource`, causing `MissingClock`.
- `krabitls/tests/strategy_coverage.rs` has the same stale explanation.
- `krabitls/Cargo.toml` docs.rs metadata still says default features omit the “validity TimeSource,” but `TimeSource` is now always re-exported and validity is opt-in through `Clocked` under `cert-der`.

Suggested fix: update these comments to the new `NoClock` / `Clocked` / `cert-der` model, or remove the old rationale where it no longer affects the cfg expression. This is documentation-only but important because the public API intentionally encodes security behavior in types.

### 2. Clarify the validity-check ordering and trust-root semantics

`SafeStrategy::verify_chain` currently parses the chain, verifies per-link signatures, asks the `TrustRootDecision` to accept the chain, then runs the configured validity check over every parsed cert.

That is internally consistent, but it is worth documenting as an explicit contract because it is a change from validity being part of `PinOrSelfSigned::accept_chain`. A custom `TrustRootDecision` can no longer observe whether validity passed or failed; validity is enforced by `SafeStrategy` after trust-root acceptance. This is probably the better separation, but the trait docs for `TrustRootDecision` still only say the chain has been parsed and structurally validated before `accept_chain` is called.

Suggested fix: document in `TrustRootDecision` / `SafeStrategy` that time validity is not part of `accept_chain`; it is a separate `Clock` slot owned by `SafeStrategy` and is evaluated after trust-root acceptance. If any caller is expected to make trust decisions based on validity details, the current detail-erasing `ValidityRejected` design deliberately prevents that and should be called out.

### 3. `ValidityRejected` docs mention logging that does not exist on the current type

`ValidityRejected` says the concrete reason is available to a `Clocked` strategy's own logging before it reaches the erased error. The current `Clocked<T>` implementation simply maps every `verify_validity` error to `ValidityRejected` and does not log or expose the reason.

Suggested fix: either soften that sentence to “could be logged by a custom `Clock` implementation” or introduce an intentionally tiny extension point if detailed diagnostics are desired in host/test builds. For the compact target, keeping the public error detail-free is reasonable.

### 4. Consider whether `Clock` should remain public or be sealed

`Clock` is a compact and idiomatic type-level slot, but exposing it publicly lets downstream code implement clocks that do something other than certificate validity checks. That may be desirable for advanced users, but it broadens the verification surface: a custom `Clock` can accept everything, reject everything, or add unrelated policy.

Suggested fix: if the intent is only “no clock” vs “real TimeSource,” consider sealing `Clock` and exposing only `NoClock`/`Clocked<T>`. If custom policy is intentionally supported, document that `Clock` is a policy hook and not just a wall-clock abstraction. Either path is fine; the important thing is to make the security boundary explicit.

### 5. Nice Rust/type-system direction: the `NoClock` default is strong

The `SafeStrategy<T, C, K = NoClock>` design is a good use of Rust generics for this project’s constraints:

- No heap allocation is introduced.
- No dynamic dispatch is needed for the default path.
- The default type remains short for users.
- The opt-in validity path carries the cost in a distinct monomorphization.
- The API makes “validity skipped” visible as a type-level default instead of a hidden `None`.

I would keep this structure. If you want to make it even more self-documenting without code-size impact, the main improvement is clearer docs around `DefaultVerify = SafeStrategy<PinOrSelfSigned, DerCert>` meaning “NoClock.”

### 6. Minor leftover detritus: duplicate import in `verify_strategy` tests

The test module in `krabitls/src/traits/verify_strategy.rs` contains two consecutive `use super::*;` lines. This is harmless and test-only, but it is the kind of leftover cleanup that can distract during future review.

Suggested fix: remove one duplicate import when next touching the file.

## Checks run

- `cargo test` from `krabitls/`: passed, including unit tests, integration tests, and doc-tests.
- `cargo test --workspace` from the repository root: not applicable because the repository root does not contain a `Cargo.toml` workspace manifest.

## Overall assessment

No blocking correctness issue found in this pass. I would treat the stale `validity` comments as the highest-priority cleanup because they describe an old feature model and can lead users to misunderstand whether validity is skipped, required, or feature-gated. The type-level clock slot is a good fit for the compact/no-heap target; the remaining work is mostly tightening API documentation so the security semantics are as explicit as the implementation.
