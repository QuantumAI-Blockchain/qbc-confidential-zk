//! Milestone 2 — in-circuit commitment binding.
//!
//! Proves, in zero-knowledge, `C = RescuePrime(value, blinding)` for a PUBLIC commitment `C`
//! and SECRET `(value, blinding)`. This is what ties a confidential proof to a public on-chain
//! note: the verifier learns the proof is *about* commitment `C` without learning the value.
//!
//! Built on Winterfell's AUDITED `Rp64_256` parameters (`MDS`, `INV_MDS`, `ARK1`, `ARK2`,
//! `apply_round`), exposed as public constants — no hand-transcribed round constants.
//!
//! The 7-round Rescue-Prime permutation is encoded as an 8-row, 12-column trace (row 0 = the
//! sponge's initial state, rows 1..7 = state after each round). The inverse S-box is avoided
//! via the standard identity — for each round `r`:
//!
//!   `(INV_MDS · (next − ARK2[r]))^7  ==  MDS · (cur^7) + ARK1[r]`   (12 constraints, degree 7)
//!
//! Sponge layout matches `Rp64_256::hash_elements([value, blinding])`:
//!   state₀ = [2,0,0,0, value, blinding, 0,0,0,0,0,0]; digest = state₇[4..8].
//! Capacity/padding cells of row 0 are pinned (domain separation); `value`/`blinding` are FREE
//! (zero-knowledge); the final digest cells are pinned to the public commitment.

use winterfell::{
    crypto::{hashers::Rp64_256, hashers::Blake3_256, DefaultRandomCoin, ElementHasher},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements,
    ConstraintCompositionCoefficients, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, Proof, ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable,
    TraceTable, TransitionConstraintDegree,
};

use crate::{proof_options, MIN_SECURITY_BITS};

const STATE_WIDTH: usize = 12;
const NUM_ROUNDS: usize = 7;
const TRACE_LEN: usize = 8; // 7 rounds + initial state row (power of two)
const DIGEST_SIZE: usize = 4;
const CAPACITY_INIT: u64 = 2; // num_elements absorbed (value, blinding)
const RATE_START: usize = 4; // RATE_RANGE = 4..12; value at 4, blinding at 5
const DIGEST_RANGE: core::ops::Range<usize> = 4..8;

mod v {
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

// ───────────────────────── helpers ─────────────────────────

#[inline]
fn pow7<E: FieldElement>(x: E) -> E {
    let x2 = x * x;
    let x3 = x2 * x;
    let x6 = x3 * x3;
    x6 * x
}

/// `out = M · vec` where `M` is a base-field matrix and `vec` is in the (extension) field E.
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
pub struct CommitPublicInputs {
    pub commitment: [BaseElement; DIGEST_SIZE],
}

impl ToElements<BaseElement> for CommitPublicInputs {
    fn to_elements(&self) -> v::Vec<BaseElement> {
        self.commitment.to_vec()
    }
}

// ───────────────────────── the AIR ─────────────────────────

pub struct CommitAir {
    context: AirContext<BaseElement>,
    commitment: [BaseElement; DIGEST_SIZE],
}

impl Air for CommitAir {
    type BaseField = BaseElement;
    type PublicInputs = CommitPublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // 12 transition constraints, each degree 7 (the Rescue round).
        let degrees = v::vec![TransitionConstraintDegree::new(7); STATE_WIDTH];
        // boundaries: row0 capacity+padding (10) + final digest (4) = 14
        let context = AirContext::new(trace_info, degrees, 14, options);
        CommitAir { context, commitment: pub_inputs.commitment }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    /// Periodic columns carry the per-round constants: 12 for ARK1, then 12 for ARK2.
    fn get_periodic_column_values(&self) -> v::Vec<v::Vec<BaseElement>> {
        let mut cols = v::Vec::with_capacity(2 * STATE_WIDTH);
        // ARK1 components
        for k in 0..STATE_WIDTH {
            let mut col = v::vec![BaseElement::ZERO; TRACE_LEN];
            for r in 0..NUM_ROUNDS {
                col[r] = Rp64_256::ARK1[r][k];
            }
            cols.push(col);
        }
        // ARK2 components
        for k in 0..STATE_WIDTH {
            let mut col = v::vec![BaseElement::ZERO; TRACE_LEN];
            for r in 0..NUM_ROUNDS {
                col[r] = Rp64_256::ARK2[r][k];
            }
            cols.push(col);
        }
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

        // forward half-round: MDS · (cur^7) + ARK1
        let mut cur_pow7 = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            cur_pow7[i] = pow7(cur[i]);
        }
        let mds_cur = mat_mul::<E>(&Rp64_256::MDS, &cur_pow7);

        // inverse half-round (rearranged to avoid x^(1/7)):
        //   s^(1/7) = INV_MDS · (next − ARK2)   ⇒   lhs = (INV_MDS · (next − ARK2))^7
        let mut next_minus_ark2 = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            next_minus_ark2[i] = next[i] - periodic_values[STATE_WIDTH + i];
        }
        let inv_mds = mat_mul::<E>(&Rp64_256::INV_MDS, &next_minus_ark2);

        for i in 0..STATE_WIDTH {
            let lhs = pow7(inv_mds[i]);
            let rhs = mds_cur[i] + periodic_values[i]; // + ARK1
            result[i] = lhs - rhs;
        }
    }

    fn get_assertions(&self) -> v::Vec<Assertion<Self::BaseField>> {
        let mut a = v::Vec::with_capacity(14);
        // row 0: capacity init + zero padding (value@4, blinding@5 left FREE for ZK)
        a.push(Assertion::single(0, 0, BaseElement::new(CAPACITY_INIT)));
        for c in [1usize, 2, 3, 6, 7, 8, 9, 10, 11] {
            a.push(Assertion::single(c, 0, BaseElement::ZERO));
        }
        // final row: digest cells == public commitment
        for (k, col) in DIGEST_RANGE.enumerate() {
            a.push(Assertion::single(col, TRACE_LEN - 1, self.commitment[k]));
        }
        a
    }
}

// ───────────────────────── the prover ─────────────────────────

#[cfg(feature = "prover")]
pub struct CommitProver {
    options: ProofOptions,
}

#[cfg(feature = "prover")]
impl CommitProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    /// Build the 7-round permutation trace for the sponge over (value, blinding).
    pub fn build_trace(&self, value: u64, blinding: u64) -> TraceTable<BaseElement> {
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[0] = BaseElement::new(CAPACITY_INIT);
        state[RATE_START] = BaseElement::new(value);
        state[RATE_START + 1] = BaseElement::new(blinding);

        let mut cols: v::Vec<v::Vec<BaseElement>> =
            v::vec![v::vec![BaseElement::ZERO; TRACE_LEN]; STATE_WIDTH];
        // row 0 = initial state
        for c in 0..STATE_WIDTH {
            cols[c][0] = state[c];
        }
        // rows 1..=7 = state after each round
        for r in 0..NUM_ROUNDS {
            Rp64_256::apply_round(&mut state, r);
            for c in 0..STATE_WIDTH {
                cols[c][r + 1] = state[c];
            }
        }
        TraceTable::init(cols)
    }
}

#[cfg(feature = "prover")]
impl Prover for CommitProver {
    type BaseField = BaseElement;
    type Air = CommitAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> CommitPublicInputs {
        let mut c = [BaseElement::ZERO; DIGEST_SIZE];
        for (k, col) in DIGEST_RANGE.enumerate() {
            c[k] = trace.get(col, TRACE_LEN - 1);
        }
        CommitPublicInputs { commitment: c }
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

/// The Rescue commitment of `(value, blinding)` — exactly `Rp64_256::hash_elements`.
pub fn commit(value: u64, blinding: u64) -> [BaseElement; DIGEST_SIZE] {
    let digest = Rp64_256::hash_elements(&[BaseElement::new(value), BaseElement::new(blinding)]);
    let mut out = [BaseElement::ZERO; DIGEST_SIZE];
    out.copy_from_slice(digest.as_elements());
    out
}

/// Serialize a commitment to 32 bytes (4 × u64 little-endian).
pub fn commitment_to_bytes(c: &[BaseElement; DIGEST_SIZE]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (k, e) in c.iter().enumerate() {
        b[k * 8..k * 8 + 8].copy_from_slice(&e.as_int().to_le_bytes());
    }
    b
}

/// Prove knowledge of `(value, blinding)` opening the returned commitment. Returns
/// `(commitment, proof_bytes)`.
#[cfg(feature = "prover")]
pub fn prove_commit_open(value: u64, blinding: u64) -> (
    [BaseElement; DIGEST_SIZE],
    v::Vec<u8>,
) {
    let prover = CommitProver::new(proof_options());
    let trace = prover.build_trace(value, blinding);
    let commitment = {
        let mut c = [BaseElement::ZERO; DIGEST_SIZE];
        for (k, col) in DIGEST_RANGE.enumerate() {
            c[k] = trace.get(col, TRACE_LEN - 1);
        }
        c
    };
    let proof = prover.prove(trace).expect("commit prove");
    (commitment, proof.to_bytes())
}

/// Verify a commitment-opening proof against a public commitment. Post-quantum.
pub fn verify_commit_open(commitment: &[BaseElement; DIGEST_SIZE], proof_bytes: &[u8]) -> bool {
    let proof = match Proof::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let pub_inputs = CommitPublicInputs { commitment: *commitment };
    let min_opts = AcceptableOptions::MinConjecturedSecurity(MIN_SECURITY_BITS);
    winterfell::verify::<
        CommitAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &min_opts)
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_proof_verifies_against_real_commitment() {
        let value = 1_527_000_000u64;
        let blinding = 0xDEAD_BEEF_CAFE_1234u64;
        let (c, proof) = prove_commit_open(value, blinding);
        // the proof's commitment equals the native Rescue hash
        assert_eq!(c, commit(value, blinding), "in-circuit digest must match native hash");
        assert!(verify_commit_open(&c, &proof), "valid opening must verify");
    }

    #[test]
    fn proof_does_not_verify_against_a_different_commitment() {
        let (c, proof) = prove_commit_open(100, 7);
        assert!(verify_commit_open(&c, &proof));
        // tweak one digest element → different commitment
        let mut c2 = c;
        c2[0] += BaseElement::ONE;
        assert!(!verify_commit_open(&c2, &proof), "proof must bind to its commitment");
    }

    #[test]
    fn different_preimage_yields_different_commitment() {
        let (c1, _) = prove_commit_open(100, 7);
        let (c2, _) = prove_commit_open(101, 7); // different value
        let (c3, _) = prove_commit_open(100, 8); // different blinding
        assert_ne!(c1, c2);
        assert_ne!(c1, c3);
    }

    #[test]
    fn tampered_proof_rejected() {
        let (c, mut proof) = prove_commit_open(42, 99);
        let mid = proof.len() / 2;
        proof[mid] ^= 0xff;
        assert!(!verify_commit_open(&c, &proof));
    }

    #[test]
    fn commitment_bytes_roundtrip_shape() {
        let c = commit(123, 456);
        let b = commitment_to_bytes(&c);
        assert_eq!(b.len(), 32);
        // first element low bytes are non-trivial
        assert!(c[0].as_int() != 0 || c[1].as_int() != 0);
    }
}
