//! Milestone 2.5b — per-output "range + commitment" proof (closes wrap-around).
//!
//! Proves, in zero-knowledge, that a PUBLIC commitment `C` opens to `(value, blinding)` with
//! `C = Rescue(value, blinding)` AND `0 <= value < 2^63`. One value, one 8-row trace.
//!
//! ## Why this makes the transfer fully sound (without a monolithic circuit)
//! The M2.5 `transfer` proof already proves all openings + `Σin = Σout + fee`. The only gap is
//! that an output could be a wrapped-negative (huge) value. This proof closes it. Because the
//! Rescue commitment is **binding**, the value proven in-range *here* (against `C_out_j`) is the
//! same value used in the balance proof *there* (against the same `C_out_j`) — so verifying the
//! transfer proof plus one range+commitment proof per output yields full soundness, with no
//! giant fused AIR. Standard "link separate STARKs by a shared binding commitment".
//!
//! ## Layout (8-row trace, mirrors the proven `commit` + `range` gadgets)
//! - cols 0..11: Rescue state (the M2 commitment-opening gadget; value at state[4] row 0).
//! - cols 12..20: 9 binary bit columns; cols 21: range accumulator; col 22: a constant `value`.
//! - range: `acc_next = 512·acc + Σ_k bit_k·2^(8-k)` (9 bits/row, MSB-first); 7 folds (rows 0..6)
//!   reconstruct the 63-bit value into `acc[7]`. Each bit is binary.
//! - linking (selector-gated, same pattern proven in `transfer`): `value[0] == state[4][0]` and
//!   `acc[7] == value[7]`, so the range-checked value IS the committed value.

use winterfell::{
    crypto::{hashers::Blake3_256, hashers::Rp64_256, DefaultRandomCoin, ElementHasher},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements,
    ConstraintCompositionCoefficients, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, Proof, ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable,
    TraceTable, TransitionConstraintDegree,
};

use crate::{proof_options, MIN_SECURITY_BITS, RANGE_BITS};

const STATE_WIDTH: usize = 12;
const NUM_ROUNDS: usize = 7;
const TRACE_LEN: usize = 8;
const DIGEST_SIZE: usize = 4;
const CAPACITY_INIT: u64 = 2;
const VALUE_CELL: usize = 4;
const BLIND_CELL: usize = 5;

const BITS_PER_ROW: usize = 9; // 7 folds × 9 = 63 bits == RANGE_BITS
const BIT0: usize = STATE_WIDTH; // first bit column (12)
const ACC: usize = STATE_WIDTH + BITS_PER_ROW; // 21
const VAL: usize = ACC + 1; // 22
const WIDTH: usize = VAL + 1; // 23
const FOLDS: usize = TRACE_LEN - 1; // 7

mod v {
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

#[inline]
fn pow7<E: FieldElement>(x: E) -> E {
    let x2 = x * x;
    let x3 = x2 * x;
    let x6 = x3 * x3;
    x6 * x
}

#[inline]
fn mat_mul<E: FieldElement<BaseField = BaseElement>>(
    m: &[[BaseElement; STATE_WIDTH]; STATE_WIDTH],
    vec: &[E; STATE_WIDTH],
) -> [E; STATE_WIDTH] {
    let mut out = [E::ZERO; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        let mut acc = E::ZERO;
        for j in 0..STATE_WIDTH {
            acc += vec[j].mul_base(m[i][j]);
        }
        out[i] = acc;
    }
    out
}

// ───────────────────────── public inputs ─────────────────────────

#[derive(Clone)]
pub struct RangeCommitPublicInputs {
    pub commitment: [BaseElement; DIGEST_SIZE],
}

impl ToElements<BaseElement> for RangeCommitPublicInputs {
    fn to_elements(&self) -> v::Vec<BaseElement> {
        self.commitment.to_vec()
    }
}

// ───────────────────────── the AIR ─────────────────────────

pub struct RangeCommitAir {
    context: AirContext<BaseElement>,
    commitment: [BaseElement; DIGEST_SIZE],
}

impl Air for RangeCommitAir {
    type BaseField = BaseElement;
    type PublicInputs = RangeCommitPublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let mut degrees = v::Vec::new();
        // 12 Rescue round constraints (degree 7)
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::new(7));
        }
        // 9 binary bit constraints (degree 2)
        for _ in 0..BITS_PER_ROW {
            degrees.push(TransitionConstraintDegree::new(2));
        }
        degrees.push(TransitionConstraintDegree::new(1)); // acc recurrence
        degrees.push(TransitionConstraintDegree::new(1)); // val constant
        degrees.push(TransitionConstraintDegree::new(2)); // link first (selector × linear)
        degrees.push(TransitionConstraintDegree::new(2)); // link last  (selector × linear)
        // boundaries: 10 (Rescue row0) + 4 (digest) + 1 (acc[0]=0) = 15
        let context = AirContext::new(trace_info, degrees, 15, options);
        RangeCommitAir { context, commitment: pub_inputs.commitment }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn get_periodic_column_values(&self) -> v::Vec<v::Vec<BaseElement>> {
        let mut cols = v::Vec::with_capacity(2 * STATE_WIDTH + 2);
        for k in 0..STATE_WIDTH {
            let mut col = v::vec![BaseElement::ZERO; TRACE_LEN];
            for r in 0..NUM_ROUNDS {
                col[r] = Rp64_256::ARK1[r][k];
            }
            cols.push(col);
        }
        for k in 0..STATE_WIDTH {
            let mut col = v::vec![BaseElement::ZERO; TRACE_LEN];
            for r in 0..NUM_ROUNDS {
                col[r] = Rp64_256::ARK2[r][k];
            }
            cols.push(col);
        }
        // sel_first: 1 at row 0
        let mut s0 = v::vec![BaseElement::ZERO; TRACE_LEN];
        s0[0] = BaseElement::ONE;
        cols.push(s0);
        // sel_lastfold: 1 at row FOLDS-1 (=6); the row-6 transition produces acc[7]
        let mut s6 = v::vec![BaseElement::ZERO; TRACE_LEN];
        s6[FOLDS - 1] = BaseElement::ONE;
        cols.push(s6);
        cols
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let next = frame.next();
        let ark1 = &periodic_values[0..STATE_WIDTH];
        let ark2 = &periodic_values[STATE_WIDTH..2 * STATE_WIDTH];
        let sel_first = periodic_values[2 * STATE_WIDTH];
        let sel_lastfold = periodic_values[2 * STATE_WIDTH + 1];

        // --- Rescue round (12 constraints, degree 7) ---
        let mut cur_pow7 = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            cur_pow7[i] = pow7(cur[i]);
        }
        let mds_cur = mat_mul::<E>(&Rp64_256::MDS, &cur_pow7);
        let mut next_minus_ark2 = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            next_minus_ark2[i] = next[i] - ark2[i];
        }
        let inv_mds = mat_mul::<E>(&Rp64_256::INV_MDS, &next_minus_ark2);
        for i in 0..STATE_WIDTH {
            result[i] = pow7(inv_mds[i]) - (mds_cur[i] + ark1[i]);
        }

        // --- range: binary bits + doubling-by-512 accumulator ---
        let two = E::ONE + E::ONE;
        let mut p = 0;
        for k in 0..BITS_PER_ROW {
            let b = cur[BIT0 + k];
            result[STATE_WIDTH + k] = b * (b - E::ONE);
            p += 1;
        }
        debug_assert_eq!(p, BITS_PER_ROW);
        // rowval = Σ_k bit_k · 2^(8-k)   (MSB-first within the 9-bit row)
        let mut rowval = E::ZERO;
        for k in 0..BITS_PER_ROW {
            let kk = BITS_PER_ROW - 1 - k; // weight 2^kk for bit at column k => MSB first
            // build 2^kk lazily; cheaper to precompute, but BITS_PER_ROW is tiny
            let mut w = E::ONE;
            for _ in 0..kk {
                w *= two;
            }
            rowval += cur[BIT0 + k] * w;
        }
        // 2^9 = 512
        let mut p512 = E::ONE;
        for _ in 0..BITS_PER_ROW {
            p512 *= two;
        }
        // acc_next = 512·acc_cur + rowval
        result[STATE_WIDTH + BITS_PER_ROW] = next[ACC] - (p512 * cur[ACC] + rowval);

        // --- val constant ---
        result[STATE_WIDTH + BITS_PER_ROW + 1] = next[VAL] - cur[VAL];

        // --- links (selector-gated) ---
        // value[0] == Rescue input state[4][0]
        result[STATE_WIDTH + BITS_PER_ROW + 2] = sel_first * (cur[VAL] - cur[VALUE_CELL]);
        // acc[7] == value   (acc_next at the row-6 transition is acc[7]; val_next == val)
        result[STATE_WIDTH + BITS_PER_ROW + 3] = sel_lastfold * (next[ACC] - next[VAL]);
    }

    fn get_assertions(&self) -> v::Vec<Assertion<Self::BaseField>> {
        let mut a = v::Vec::with_capacity(15);
        // Rescue row 0: capacity + zero padding (value@4, blinding@5 FREE)
        a.push(Assertion::single(0, 0, BaseElement::new(CAPACITY_INIT)));
        for c in [1usize, 2, 3, 6, 7, 8, 9, 10, 11] {
            a.push(Assertion::single(c, 0, BaseElement::ZERO));
        }
        // digest == commitment
        for k in 0..DIGEST_SIZE {
            a.push(Assertion::single(VALUE_CELL + k, TRACE_LEN - 1, self.commitment[k]));
        }
        // accumulator starts at 0
        a.push(Assertion::single(ACC, 0, BaseElement::ZERO));
        a
    }
}

// ───────────────────────── the prover ─────────────────────────

#[cfg(feature = "prover")]
pub struct RangeCommitProver {
    options: ProofOptions,
}

#[cfg(feature = "prover")]
impl RangeCommitProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    pub fn build_trace(&self, value: u64, blinding: u64) -> Option<TraceTable<BaseElement>> {
        if value >= (1u64 << RANGE_BITS) {
            return None;
        }
        let mut cols: v::Vec<v::Vec<BaseElement>> =
            v::vec![v::vec![BaseElement::ZERO; TRACE_LEN]; WIDTH];

        // Rescue permutation over (value, blinding)
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[0] = BaseElement::new(CAPACITY_INIT);
        state[VALUE_CELL] = BaseElement::new(value);
        state[BLIND_CELL] = BaseElement::new(blinding);
        for c in 0..STATE_WIDTH {
            cols[c][0] = state[c];
        }
        for r in 0..NUM_ROUNDS {
            Rp64_256::apply_round(&mut state, r);
            for c in 0..STATE_WIDTH {
                cols[c][r + 1] = state[c];
            }
        }

        // range: 9 bits/row MSB-first over 7 folds = 63 bits; acc doubles by 512.
        let val_fe = BaseElement::new(value);
        let mut acc = 0u128;
        for row in 0..FOLDS {
            // bits for this fold: MSB-first within the row; overall MSB-first across rows
            for k in 0..BITS_PER_ROW {
                let global_bit_index = RANGE_BITS - 1 - (row * BITS_PER_ROW + k); // 62 down to 0
                let bit = (value >> global_bit_index) & 1;
                cols[BIT0 + k][row] = BaseElement::new(bit);
            }
            cols[ACC][row] = BaseElement::new(acc as u64);
            // rowval = the 9 bits as an MSB-first integer
            let mut rowval = 0u128;
            for k in 0..BITS_PER_ROW {
                let global_bit_index = RANGE_BITS - 1 - (row * BITS_PER_ROW + k);
                let bit = (value >> global_bit_index) & 1;
                rowval = (rowval << 1) | bit as u128;
            }
            acc = acc * 512 + rowval;
        }
        cols[ACC][TRACE_LEN - 1] = BaseElement::new(acc as u64); // == value
        debug_assert_eq!(acc as u64, value);

        // val column: constant = value
        for row in 0..TRACE_LEN {
            cols[VAL][row] = val_fe;
        }

        Some(TraceTable::init(cols))
    }
}

#[cfg(feature = "prover")]
impl Prover for RangeCommitProver {
    type BaseField = BaseElement;
    type Air = RangeCommitAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> RangeCommitPublicInputs {
        let mut c = [BaseElement::ZERO; DIGEST_SIZE];
        for k in 0..DIGEST_SIZE {
            c[k] = trace.get(VALUE_CELL + k, TRACE_LEN - 1);
        }
        RangeCommitPublicInputs { commitment: c }
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

fn note_commitment(value: u64, blinding: u64) -> [BaseElement; DIGEST_SIZE] {
    let d = Rp64_256::hash_elements(&[BaseElement::new(value), BaseElement::new(blinding)]);
    let mut out = [BaseElement::ZERO; DIGEST_SIZE];
    out.copy_from_slice(d.as_elements());
    out
}

/// Prove `C = Rescue(value, blinding)` AND `value < 2^63`. Returns `(commitment, proof)`.
/// `None` if `value` is out of range (the honest-prover guard; an out-of-range value is in any
/// case unprovable — the 63-bit accumulator cannot reconstruct it, so the link constraint fails).
#[cfg(feature = "prover")]
pub fn prove_range_commit(value: u64, blinding: u64) -> Option<(
    [BaseElement; DIGEST_SIZE],
    v::Vec<u8>,
)> {
    let prover = RangeCommitProver::new(proof_options());
    let trace = prover.build_trace(value, blinding)?;
    let commitment = prover.get_pub_inputs(&trace).commitment;
    let proof = prover.prove(trace).ok()?;
    Some((commitment, proof.to_bytes()))
}

/// Verify a range+commitment proof against the public commitment. Post-quantum.
pub fn verify_range_commit(commitment: &[BaseElement; DIGEST_SIZE], proof_bytes: &[u8]) -> bool {
    let proof = match Proof::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let pubs = RangeCommitPublicInputs { commitment: *commitment };
    let min_opts = AcceptableOptions::MinConjecturedSecurity(MIN_SECURITY_BITS);
    winterfell::verify::<
        RangeCommitAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
    >(proof, pubs, &min_opts)
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_range_commitment_opening_verifies() {
        let value = 1_527_000_000u64; // 15.27 QBC, units, in range
        let blinding = 0xABCD_1234_5678_9999u64;
        let (c, proof) = prove_range_commit(value, blinding).expect("in range");
        assert_eq!(c, note_commitment(value, blinding), "digest must match native hash");
        assert!(verify_range_commit(&c, &proof), "valid range+commitment must verify");
    }

    #[test]
    fn boundary_values_verify() {
        let max = (1u64 << RANGE_BITS) - 1;
        for value in [0u64, 1, 512, max] {
            let (c, proof) = prove_range_commit(value, 7).expect("in range");
            assert!(verify_range_commit(&c, &proof), "value {value} must verify");
        }
    }

    #[test]
    fn out_of_range_value_unprovable() {
        // 2^63 and above cannot be range-proven (63-bit accumulator can't reconstruct it).
        assert!(prove_range_commit(1u64 << RANGE_BITS, 1).is_none());
        assert!(prove_range_commit(u64::MAX, 1).is_none());
    }

    #[test]
    fn binds_to_commitment() {
        let (c, proof) = prove_range_commit(100, 7).expect("in range");
        assert!(verify_range_commit(&c, &proof));
        let mut c2 = c;
        c2[0] += BaseElement::ONE;
        assert!(!verify_range_commit(&c2, &proof), "must bind to commitment");
    }

    #[test]
    fn tampered_proof_rejected() {
        let (c, mut proof) = prove_range_commit(42_000_000, 99).expect("in range");
        let mid = proof.len() / 2;
        proof[mid] ^= 0xff;
        assert!(!verify_range_commit(&c, &proof));
    }
}
