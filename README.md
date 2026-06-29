# qbc-confidential-zk — peer-review artifacts

Reference implementations and test artifacts for the paper **"Post-Quantum Confidential
Transactions with In-Runtime STARK Verification on a Sovereign Layer-1"** (`PAPER.md`).

This repository exists so the paper's claims can be inspected and reproduced. It contains the
zero-knowledge constructions, their verifiers, the test vectors, and the empirical batteries
referenced in the paper. It deliberately contains **no chain, node, consensus, AI, or
integration code, and no keys or infrastructure**: only the cryptography under review.

## Layout

| Path | Paper sections | What it is |
|---|---|---|
| `plonky3/` | 3.x, 5.2, A.7 (Track I), A.8, B | The **live, value-bearing** construction: the natively zero-knowledge path on Plonky3's hiding polynomial-commitment scheme. Opening, public-value opening, and 2-in/2-out transfer circuits, the `no_std` verifier, the prover, and the full test/fuzz/empirical suite. |
| `masking/` | 3.2, 5.1, A.1–A.7 (Track II) | The **prior** construction: the Winterfell STARK with the trace-masking hiding layer. Retained because the paper analyzes it (the soundness argument and the formal zero-knowledge proof plan), including the mechanized masking-margin count (milestone M1) and the empirical witness-indistinguishability battery. Retired from the live chain; documented here for the record and for the Track II proof. |

## Reproduce

Each directory is a self-contained Rust crate (stable toolchain).

```
# Plonky3 path: circuits prove + verify, binding/balance/range, browser-prove to native-verify,
# panic-safety fuzz, adversarial public inputs, empirical amount-hiding at chance, verify cost.
cd plonky3 && cargo test --release

# no_std verifier builds for the runtime target class (wasm32). --lib builds only the verifier
# library; the CLI provers under src/bin are std-only tools and are not part of the no_std surface.
cd plonky3 && cargo build --lib --target wasm32-unknown-unknown --no-default-features --release

# Masking path: range/opening tests + the masking-margin regression test (M1).
# Use --release: the upstream Winterfell prover carries debug-assertions that are over-strict
# for the masked (exemption-padded) trace layout; they do not affect soundness or the release path.
cd masking && cargo test --release
cd masking && cargo run --release --bin zk_leakage   # empirical held-out distinguisher (Appendix A.6)
cd masking && cargo run --release --bin zk_evidence  # full empirical battery
```

### Key things a reviewer can check directly

- **Rescue compatibility** (`plonky3/tests/rescue_compat.rs`): the Plonky3 Rescue digest equals the
  reference hash bit-for-bit across edge and near-modulus inputs.
- **Masking margin, mechanized** (`masking/src/lib.rs::masking_margin`, milestone M1): the free
  masking rows (B), query count (Q), and out-of-domain base-field constraints are derived from the
  live parameters; the test asserts `B - (Q + ood) = 14 > 0`. Section A.3 of the paper.
- **Soundness, no inflation**: forged fee / forged commitment / tampered proof are rejected; the
  field-wraparound case is bounded out by the 62-bit range. Section 5.1.
- **Hiding by the proving system** (`plonky3/`): two proofs of one statement differ; the held-out
  distinguisher is at chance; a valid proof is rejected under any altered public input
  (`adversarial_public_inputs.rs`); the verifier never panics over thousands of adversarial inputs
  (`fuzz_verify.rs`).

## Scope and what is intentionally excluded

Included: the AIR constraint systems, the verifiers, the provers, the test vectors, the fuzz and
empirical harnesses, and the paper.

Excluded (not required to review the cryptography, and out of scope): the Layer-1 node, runtime,
pallets, and consensus; the on/off-ramp and relay integration; the AI and virtual-machine layers;
all deployment, infrastructure, and key material.

## License

MIT (`LICENSE`).
