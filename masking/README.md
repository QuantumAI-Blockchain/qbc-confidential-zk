# qbc-pq-confidential

**Post-quantum confidential-transaction proofs for the [QuantumAI Blockchain](https://qbc.network) (QBC) L1.**

The live confidential layer (Pedersen commitments + Bulletproofs + Schnorr) already gives
two quantum-secure guarantees:

- **Amount privacy** — Pedersen commitments are *information-theoretically* hiding, so amounts
  stay hidden forever, even against a quantum computer.
- **Authorization** — every move is gated by CRYSTALS-Dilithium5 (ML-DSA-87, NIST Level 5).

But its **soundness** (the no-inflation guarantee) rests on the discrete-log assumption, which
a large quantum computer breaks. This crate replaces that soundness layer with a **Winterfell
STARK** — a FRI / hash-based, transparent-setup proof system whose security reduces only to the
collision-resistance of a hash. Hence: **quantum-secure from every aspect** — privacy,
authorization, *and* soundness.

## Why a STARK

| Property | Bulletproofs (today) | STARK (this crate) |
|---|---|---|
| Soundness assumption | discrete log (classical) | collision-resistant hash (**post-quantum**) |
| Trusted setup | none | none (transparent) |
| Browser prover | yes | yes (`wasm32`, single-threaded) |
| Native verifier | yes | yes (substrate host fn) |

The architecture mirrors the existing `confidential_host`: the heavy prover runs **off** the
runtime (in the browser via `wasm32`, or in the CLI), and the verifier runs in a **native**
substrate host function. The no_std wasm runtime never carries the STARK code.

## Status

This is an **active build** toward fully post-quantum confidential transactions, including
note→note transfers (both ends hidden). Milestones:

- **M1 — range proof (done):** the anti-overflow / anti-mint core. Proves in zero-knowledge
  that a value is a valid `RANGE_BITS`-bit number (`0 ≤ v < 2^63`), so it can't be a wrapped
  negative used to mint value. ≥96-bit conjectured security (cubic extension over Goldilocks),
  adversarially tested, compiles native + `wasm32`.
- **M2 — in-circuit hash commitment binding (done):** `C = Rescue(value, blinding)` proven in ZK; in-circuit digest matches the audited native hash.
- **M2.5 — note→note transfer (done):** openings + balance (`Σin=Σout+fee`) + per-output range,
  linked by the binding commitments. Full transfer proves + verifies; unbalanced / out-of-range /
  forged-fee / tampered all rejected. 27 adversarial tests pass; native + wasm32.
- **M3 — pallet/host integration:** `confidential_transfer_v2` extrinsic + native STARK verifier
  host fn; try-runtime rehearsed, staged, owner-gated deploy (additive — v1 stays accepted; no fork).
- **M4 — browser prover + frontend note→note transfer**, battle-tested via the public relay.
- **M5 — external audit prep.**

Full design: [`docs/DESIGN.md`](docs/DESIGN.md).

## Security

The proving/verifying core is the **audited** Winterfell library; the AIR constraints in
`src/lib.rs` are the small, reviewable delta. As with any custom zero-knowledge circuit, the
constraints are soundness-critical and **require an external audit before securing mainnet
value**. No hand-rolled field, FRI, or hash cryptography.

## Build & test

```bash
cargo test --release                              # native: prove + verify + adversarial tests
cargo build --release --target wasm32-unknown-unknown   # browser prover target
```

## API (M1)

```rust
use qbc_pq_confidential::{prove_range, verify_range};

let proof = prove_range(1_527_000_000).expect("value in [0, 2^63)"); // 15.27 QBC, units
assert!(verify_range(1_527_000_000, &proof));   // post-quantum range proof verifies
assert!(!verify_range(1_527_000_001, &proof));  // proof binds to its value
```

## License

MIT © 2026 QuantumAI Blockchain / SusyLabs Pty Ltd
