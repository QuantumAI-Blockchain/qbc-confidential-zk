//! # qbc-pq-confidential
//!
//! Post-quantum confidential-transaction proofs for the QuantumAI Blockchain (QBC) L1.
//!
//! The live confidential layer (Pedersen + Bulletproofs + Schnorr) is quantum-secure for
//! *amount privacy* (Pedersen is information-theoretically hiding) and *authorization*
//! (Dilithium5), but its *soundness* (no-inflation) rests on the discrete-log assumption,
//! which a large quantum computer breaks. This crate replaces that soundness layer with a
//! **Winterfell STARK** — a FRI/hash-based, transparent-setup proof system whose security
//! reduces only to the collision-resistance of a hash, hence **post-quantum**.
//!
//! Architecture mirrors the existing `confidential_host`: the (heavy) prover runs off the
//! runtime — in `wasm32` in the browser, or natively in the CLI — and the verifier runs in
//! a native substrate host function. The no_std wasm runtime never carries the STARK code.
//!
//! ## This module (Milestone 1): range proof
//! The anti-overflow / anti-mint core of confidential soundness: prove, with a STARK, that
//! a value `v` is a valid `RANGE_BITS`-bit number (`0 <= v < 2^RANGE_BITS`) — i.e. it cannot
//! be a wrapped negative used to mint value. Built on the audited Winterfell prove/verify
//! core; the AIR constraints below are the small, reviewable delta.
//!
//! `RANGE_BITS = 63` HERE: this module is the standalone single-value range circuit, used to
//! demonstrate the range gadget in isolation, where a 63-bit bound stays strictly below the
//! Goldilocks modulus (~2^63.99) so reconstruction never wraps. NOTE: the value-bearing
//! transfer path uses a tighter `RANGE_BITS = 62` (see `zk_transfer.rs`, and the Plonky3
//! `transfer.rs`), so that the sum of two outputs plus a fee cannot wrap the field in the balance
//! equation. The paper's 62-bit soundness argument refers to that transfer bound, not to this
//! standalone demo. (Plaintext balances remain u128 on-chain; only confidential values are bounded.)
//!
//! AIR: an MSB-first doubling accumulator over a 64-row trace. `acc[0]=0`,
//! `acc[i+1]=2·acc[i]+bit[i]`, so `acc[63]=Σ bit[i]·2^(62-i) = value`; each `bit` is forced
//! binary. Boundaries pin `acc[0]=0` and `acc[63]=value`. A value that needs more than 63
//! bits cannot satisfy the accumulator with binary bits → unprovable.
//!
//! Milestones M2+ (in-circuit hash commitment binding, balance, pallet/host, browser, audit)
//! are tracked in `docs/PQ_CONFIDENTIAL_V2_DESIGN.md`.
//!
//! ## no_std
//! The verifier + AIR are `no_std` (default-features off), so they run inside the substrate
//! runtime. The prover (the `prover` feature, std-only) is for the CLI / browser-wasm and is
//! never compiled into the runtime.
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "prover"), allow(unused_imports))]

extern crate alloc;

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin},
    math::{fields::f64::BaseElement, FieldElement, StarkField, ToElements},
    matrix::ColMatrix,
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements,
    ConstraintCompositionCoefficients, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, FieldExtension, Proof, ProofOptions, Prover, StarkDomain,
    TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

/// v3 ZERO-KNOWLEDGE commitment opening (exemption-masked; witness hidden).
pub mod zk_commit;
/// v3 FULL zero-knowledge confidential transfer (note→note, amounts hidden).
pub mod zk_transfer;
/// v3 commitment opening to a PUBLIC value (shield/unshield on/off-ramp; blinding hidden).
pub mod zk_open;

/// Milestone 2: in-circuit Rescue commitment binding (`C = RescuePrime(value, blinding)`).
pub mod commit;
/// Milestone 2.5: multi-IO commitment openings + balance (note→note value conservation).
pub mod transfer;
/// Milestone 2.5b: per-output range + commitment opening (closes wrap-around → full soundness).
pub mod range_commit;
/// Full confidential transfer = balance/openings + per-output range proofs (linked by commitments).
pub mod full;

/// Standalone range-demo bound: `0 <= v < 2^RANGE_BITS`. This is the isolated range circuit only;
/// the value-bearing transfer path bounds values to 2^62 (see `zk_transfer.rs` / Plonky3 `transfer.rs`).
pub const RANGE_BITS: usize = 63;
/// Trace length (power of two): 64 rows = 63 accumulation steps + final value row.
const TRACE_LEN: usize = 64;
/// Trace columns: the per-step bit, the running doubling accumulator, and a clock
/// (0,1,2,…). The clock is always strictly increasing, so the trace is never degenerate
/// (a constant column — e.g. when value=0 — breaks the STARK's DEEP composition).
const BIT_COL: usize = 0;
const ACC_COL: usize = 1;
const CLK_COL: usize = 2;

// ───────────────────────── public inputs ─────────────────────────

/// Public statement: "I know the bit-decomposition of `value`, and it is RANGE_BITS bits."
/// For Milestone 1 the value is public (validates the AIR end-to-end). In M2 the value is
/// hidden and bound to a public Rescue commitment proven in-circuit.
#[derive(Clone)]
pub struct RangePublicInputs {
    pub value: BaseElement,
}

impl ToElements<BaseElement> for RangePublicInputs {
    fn to_elements(&self) -> alloc_vec::Vec<BaseElement> {
        alloc_vec::vec![self.value]
    }
}

// Small alias so the crate is std/no_std agnostic for the Vec type used above.
mod alloc_vec {
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

// ───────────────────────── the AIR ─────────────────────────

pub struct RangeAir {
    context: AirContext<BaseElement>,
    value: BaseElement,
}

impl Air for RangeAir {
    type BaseField = BaseElement;
    type PublicInputs = RangePublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Transition constraints:
        //   1. bit is binary:        bit·(bit-1) = 0                  → degree 2
        //   2. accumulator doubling: acc_next - (2·acc + bit) = 0     → degree 1
        let degrees = alloc_vec::vec![
            TransitionConstraintDegree::new(2), // binary bit
            TransitionConstraintDegree::new(1), // accumulator doubling
            TransitionConstraintDegree::new(1), // clock increment
        ];
        // three boundary assertions: acc[0]=0, acc[last]=value, clk[0]=0
        let context = AirContext::new(trace_info, degrees, 3, options);
        RangeAir { context, value: pub_inputs.value }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let next = frame.next();
        let two = E::ONE + E::ONE;
        // 1. current bit is binary
        let b = cur[BIT_COL];
        result[0] = b * (b - E::ONE);
        // 2. doubling accumulator: acc_next == 2·acc_cur + bit_cur
        result[1] = next[ACC_COL] - (two * cur[ACC_COL] + cur[BIT_COL]);
        // 3. clock increments by one each row
        result[2] = next[CLK_COL] - (cur[CLK_COL] + E::ONE);
    }

    fn get_assertions(&self) -> alloc_vec::Vec<Assertion<Self::BaseField>> {
        alloc_vec::vec![
            Assertion::single(ACC_COL, 0, BaseElement::ZERO),
            Assertion::single(ACC_COL, TRACE_LEN - 1, self.value),
            Assertion::single(CLK_COL, 0, BaseElement::ZERO),
        ]
    }
}

// ───────────────────────── the prover ─────────────────────────

#[cfg(feature = "prover")]
pub struct RangeProver {
    options: ProofOptions,
}

#[cfg(feature = "prover")]
impl RangeProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    /// Build the execution trace for a value in `[0, 2^RANGE_BITS)`.
    /// Returns `None` if the value does not fit the range (an honest prover never does this).
    pub fn build_trace(&self, value: u64) -> Option<TraceTable<BaseElement>> {
        if value >= (1u64 << RANGE_BITS) {
            return None;
        }
        let two = BaseElement::ONE + BaseElement::ONE;
        let mut bit_col = alloc_vec::vec![BaseElement::ZERO; TRACE_LEN];
        let mut acc_col = alloc_vec::vec![BaseElement::ZERO; TRACE_LEN];
        let mut clk_col = alloc_vec::vec![BaseElement::ZERO; TRACE_LEN];
        // MSB-first bits drive the doubling accumulator: acc[i+1] = 2·acc[i] + bit[i].
        // bit[i] is bit (62-i) of value, so acc[63] = Σ bit[i]·2^(62-i) = value.
        let mut acc = BaseElement::ZERO;
        for i in 0..(TRACE_LEN - 1) {
            let bit = if i < RANGE_BITS {
                (value >> (RANGE_BITS - 1 - i)) & 1
            } else {
                0
            };
            bit_col[i] = BaseElement::new(bit);
            acc_col[i] = acc;
            clk_col[i] = BaseElement::new(i as u64);
            acc = two * acc + BaseElement::new(bit);
        }
        acc_col[TRACE_LEN - 1] = acc; // == value
        clk_col[TRACE_LEN - 1] = BaseElement::new((TRACE_LEN - 1) as u64);
        debug_assert_eq!(acc, BaseElement::new(value));
        Some(TraceTable::init(alloc_vec::vec![bit_col, acc_col, clk_col]))
    }
}

#[cfg(feature = "prover")]
impl Prover for RangeProver {
    type BaseField = BaseElement;
    type Air = RangeAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> RangePublicInputs {
        // The value is the final accumulator cell.
        RangePublicInputs { value: trace.get(ACC_COL, TRACE_LEN - 1) }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

// ───────────────────────── public API ─────────────────────────

/// STARK security: 96-bit conjectured. Blake3, 62-degree extension off (base field is large),
/// 8x blowup, 27 queries, grinding 16. Deterministic across prover/verifier.
pub(crate) fn proof_options() -> ProofOptions {
    // Cubic extension over the 64-bit Goldilocks base → OOD/DEEP challenges live in a
    // ~192-bit field, lifting conjectured security past 96 bits. 42 queries @ 8x blowup +
    // 20 bits grinding. Deterministic across prover (browser/CLI) and verifier (host fn).
    ProofOptions::new(42, 8, 20, FieldExtension::Cubic, 8, 31)
}

/// Minimum conjectured security (bits) the verifier will accept. The options above must
/// meet or exceed this; mismatches fail closed (a weak proof is rejected).
pub const MIN_SECURITY_BITS: u32 = 96;

/// Prove that `value` is in `[0, 2^RANGE_BITS)`. Returns the serialized STARK proof bytes.
/// `None` if `value` is out of range (a prover-side guard; an honest prover never does this).
#[cfg(feature = "prover")]
pub fn prove_range(value: u64) -> Option<alloc_vec::Vec<u8>> {
    let prover = RangeProver::new(proof_options());
    let trace = prover.build_trace(value)?;
    let proof = prover.prove(trace).ok()?;
    Some(proof.to_bytes())
}

/// Verify a range proof for the claimed public `value`. Post-quantum: soundness reduces to
/// Blake3 collision-resistance (FRI), no discrete-log. Returns true iff the proof is valid.
pub fn verify_range(value: u64, proof_bytes: &[u8]) -> bool {
    let proof = match Proof::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let pub_inputs = RangePublicInputs { value: BaseElement::new(value) };
    let min_opts = AcceptableOptions::MinConjecturedSecurity(MIN_SECURITY_BITS);
    winterfell::verify::<
        RangeAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &min_opts)
    .is_ok()
}

/// Field modulus exposed for callers/tests (Goldilocks).
pub fn field_modulus() -> u128 {
    BaseElement::MODULUS as u128
}

/// Mechanized masking-margin counting (paper Track II, milestone M1).
///
/// The amount-hiding of the masking construction (paper Section 3.2 / Appendix A.3) rests on a
/// strict inequality: the number of free random rows per trace column must exceed the number of
/// base-field values the verifier observes about that column. This function derives all four
/// quantities directly from the live proof parameters and the trace layout, so the paper's count is
/// a regression test rather than a hand calculation. Returns (free_rows B, queries Q, ood base-field
/// constraints, margin = B - (Q + ood)).
pub fn masking_margin() -> (usize, usize, usize, isize) {
    use crate::zk_commit::{EXEMPT, TRACE_LEN};
    // Free random rows per column: the masking fills the rows after the last constrained source row.
    // last_src = TRACE_LEN - 1 - EXEMPT (transitions are exempt over the trailing rows) and the first
    // masked row is last_src + 2, so B = TRACE_LEN - (last_src + 2).
    let last_src = TRACE_LEN - 1 - EXEMPT;
    let free_rows = TRACE_LEN - (last_src + 2);
    let opts = proof_options();
    let queries = opts.num_queries();
    // The out-of-domain frame is two rows; over an extension field each observed extension element is
    // `degree` base-field coordinates, so the OOD frame fixes 2 * degree base-field values per column.
    let ext_degree = match opts.field_extension() {
        FieldExtension::None => 1,
        FieldExtension::Quadratic => 2,
        FieldExtension::Cubic => 3,
    };
    let ood = 2 * ext_degree;
    let margin = free_rows as isize - (queries + ood) as isize;
    (free_rows, queries, ood, margin)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Track II M1: the masking margin, computed from the live parameters, must be strictly
    /// positive (the security-critical invariant) and must match the value claimed in the paper.
    /// Lowering the masking (EXEMPT) or raising the query count erodes the margin and fails here.
    #[test]
    fn masking_margin_is_positive_and_matches_paper() {
        let (free_rows, queries, ood, margin) = masking_margin();
        // The exact figures stated in Appendix A.3 of the paper.
        assert_eq!(free_rows, 62, "free masking rows per column");
        assert_eq!(queries, 42, "FRI query count");
        assert_eq!(ood, 6, "out-of-domain base-field constraints (2 rows x cubic degree 3)");
        assert_eq!(margin, 14, "masking margin B - (Q + ood)");
        // The invariant the hiding argument rests on: more free rows than observed values.
        assert!(margin > 0, "masking margin must be strictly positive ({margin})");
        println!("masking margin: B={free_rows}, Q={queries}, ood={ood}, margin={margin}");
    }

    #[test]
    fn valid_range_proof_verifies() {
        let v = 1_527_000_000u64; // 15.27 QBC in units
        let proof = prove_range(v).expect("in range");
        assert!(verify_range(v, &proof), "valid proof must verify");
    }

    #[test]
    fn zero_and_max_in_range() {
        let max = (1u64 << RANGE_BITS) - 1;
        for v in [0u64, 1, max] {
            let p = prove_range(v).expect("in range");
            assert!(verify_range(v, &p), "boundary value {v} must verify");
        }
    }

    #[test]
    fn out_of_range_value_cannot_be_proven() {
        // This standalone demo uses RANGE_BITS=63, so 2^63 is out of range — the prover refuses.
        let over = 1u64 << RANGE_BITS;
        assert!(prove_range(over).is_none(), "out-of-range value must not be provable");
    }

    #[test]
    fn proof_does_not_verify_against_a_different_value() {
        // Soundness/binding: a proof for v must NOT verify for v' != v.
        let v = 42_000_000u64;
        let proof = prove_range(v).expect("in range");
        assert!(verify_range(v, &proof));
        assert!(!verify_range(v + 1, &proof), "proof must bind to its value");
        assert!(!verify_range(v - 1, &proof), "proof must bind to its value");
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let v = 100_000_000u64;
        let mut proof = prove_range(v).expect("in range");
        // Flip a byte in the middle of the proof.
        let mid = proof.len() / 2;
        proof[mid] ^= 0xff;
        assert!(!verify_range(v, &proof), "tampered proof must be rejected");
    }

    #[test]
    fn garbage_bytes_rejected() {
        assert!(!verify_range(1, &[0u8; 16]));
        assert!(!verify_range(1, &[]));
    }
}

