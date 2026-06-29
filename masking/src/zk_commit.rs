//! Zero-knowledge commitment opening — the foundational ZK unit for confidential v3.
//!
//! Proves `C = Rescue(value, blinding)` for a PUBLIC commitment `C`, SECRET `(value, blinding)`,
//! AND in **statistical zero-knowledge**: the proof reveals nothing about `value`/`blinding`.
//!
//! ## How ZK is achieved (in-API, no Winterfell fork)
//! Winterfell evaluates the LDE on a coset disjoint from the trace rows, so FRI queries never read
//! a real row directly — leakage is only via interpolation, which needs ≥ trace_length openings.
//! We therefore (a) make the trace long, (b) fill the trailing half with cryptographic RANDOM
//! rows, and (c) use `num_transition_exemptions` so those rows are unconstrained. With
//! `#openings (queries + OOD) < #random rows`, the trace polynomials are underdetermined → the
//! witness is statistically hidden.
//!
//! The Rescue opening is only 7 rounds, too short to host the masking tail. We run the permutation
//! CONTINUOUSLY for the real region with period-8 round constants (`ARK[7] = 0`, a zero-constant
//! round), capturing the real digest at row 7 via a boundary. The round constraint is then uniform
//! (period-8, low degree) — no high-degree single-row selectors.

use winterfell::{
    crypto::{hashers::Blake3_256, hashers::Rp64_256, DefaultRandomCoin, ElementHasher},
    math::{fields::f64::BaseElement, FieldElement, StarkField, ToElements},
    AcceptableOptions, Air, AirContext, Assertion, EvaluationFrame, Proof, ProofOptions,
    TraceInfo, TransitionConstraintDegree,
};
#[cfg(feature = "prover")]
use winterfell::{
    math::ToElements as _, matrix::ColMatrix, AuxRandElements, ConstraintCompositionCoefficients,
    DefaultConstraintEvaluator, DefaultTraceLde, Prover, StarkDomain, Trace, TracePolyTable,
    TraceTable,
};

use crate::MIN_SECURITY_BITS;

pub(crate) const STATE_WIDTH: usize = 12;
pub(crate) const TRACE_LEN: usize = 128;
const REAL_ROWS: usize = 64; // rows 0..63 carry continuous Rescue rounds (digest captured at row 7)
pub(crate) const EXEMPT: usize = 63; // trailing rows masked (≤ TRACE_LEN/2); ≥ query count → ZK
pub(crate) const DIGEST_ROW: usize = 7; // after 7 real rounds
pub(crate) const DIGEST_SIZE: usize = 4;
pub(crate) const CAPACITY_INIT: u64 = 2;
pub(crate) const VALUE_CELL: usize = 4;
pub(crate) const BLIND_CELL: usize = 5;
const INV_ALPHA: u64 = 10540996611094048183; // Rp64_256 inverse S-box exponent (x^(1/7))

mod v {
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

#[inline]
pub(crate) fn pow7<E: FieldElement>(x: E) -> E {
    let x2 = x * x;
    let x3 = x2 * x;
    let x6 = x3 * x3;
    x6 * x
}

#[inline]
pub(crate) fn mat_mul<E: FieldElement<BaseField = BaseElement>>(
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
pub struct ZkCommitPublicInputs {
    pub commitment: [BaseElement; DIGEST_SIZE],
}

impl ToElements<BaseElement> for ZkCommitPublicInputs {
    fn to_elements(&self) -> v::Vec<BaseElement> {
        self.commitment.to_vec()
    }
}

// ───────────────────────── the AIR ─────────────────────────

pub struct ZkCommitAir {
    context: AirContext<BaseElement>,
    commitment: [BaseElement; DIGEST_SIZE],
}

impl Air for ZkCommitAir {
    type BaseField = BaseElement;
    type PublicInputs = ZkCommitPublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let degrees = v::vec![TransitionConstraintDegree::new(7); STATE_WIDTH];
        // boundaries: row0 capacity+padding (10) + digest (4) = 14
        let context = AirContext::new(trace_info, degrees, 14, options)
            .set_num_transition_exemptions(EXEMPT);
        ZkCommitAir { context, commitment: pub_inputs.commitment }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    /// Period-8 round constants: indices 0..6 are the real Rescue ARK, index 7 is zero (a
    /// zero-constant round used only to keep the permutation running across the masking budget).
    fn get_periodic_column_values(&self) -> v::Vec<v::Vec<BaseElement>> {
        let mut cols = v::Vec::with_capacity(2 * STATE_WIDTH);
        for k in 0..STATE_WIDTH {
            let mut c = v::vec![BaseElement::ZERO; 8];
            for r in 0..7 {
                c[r] = Rp64_256::ARK1[r][k];
            }
            cols.push(c);
        }
        for k in 0..STATE_WIDTH {
            let mut c = v::vec![BaseElement::ZERO; 8];
            for r in 0..7 {
                c[r] = Rp64_256::ARK2[r][k];
            }
            cols.push(c);
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
        let ark1 = &periodic_values[0..STATE_WIDTH];
        let ark2 = &periodic_values[STATE_WIDTH..2 * STATE_WIDTH];
        let mut cur_pow7 = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            cur_pow7[i] = pow7(cur[i]);
        }
        let mds_cur = mat_mul::<E>(&Rp64_256::MDS, &cur_pow7);
        let mut nm = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            nm[i] = next[i] - ark2[i];
        }
        let inv = mat_mul::<E>(&Rp64_256::INV_MDS, &nm);
        for i in 0..STATE_WIDTH {
            result[i] = pow7(inv[i]) - (mds_cur[i] + ark1[i]);
        }
    }

    fn get_assertions(&self) -> v::Vec<Assertion<Self::BaseField>> {
        let mut a = v::Vec::with_capacity(14);
        a.push(Assertion::single(0, 0, BaseElement::new(CAPACITY_INIT)));
        for c in [1usize, 2, 3, 6, 7, 8, 9, 10, 11] {
            a.push(Assertion::single(c, 0, BaseElement::ZERO));
        }
        for k in 0..DIGEST_SIZE {
            a.push(Assertion::single(VALUE_CELL + k, DIGEST_ROW, self.commitment[k]));
        }
        a
    }
}

// ───────────────────────── prover (std only) ─────────────────────────

#[cfg(feature = "prover")]
pub(crate) fn zero_round(state: &mut [BaseElement; STATE_WIDTH]) {
    // A Rescue round with zero round constants: sbox(x^7) -> MDS -> inv_sbox(x^(1/7)) -> MDS.
    for s in state.iter_mut() {
        *s = pow7(*s);
    }
    *state = mat_mul_base(&Rp64_256::MDS, state);
    for s in state.iter_mut() {
        *s = s.exp(INV_ALPHA);
    }
    *state = mat_mul_base(&Rp64_256::MDS, state);
}

#[cfg(feature = "prover")]
pub(crate) fn mat_mul_base(
    m: &[[BaseElement; STATE_WIDTH]; STATE_WIDTH],
    s: &[BaseElement; STATE_WIDTH],
) -> [BaseElement; STATE_WIDTH] {
    let mut out = [BaseElement::ZERO; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        let mut acc = BaseElement::ZERO;
        for j in 0..STATE_WIDTH {
            acc += s[j] * m[i][j];
        }
        out[i] = acc;
    }
    out
}

#[cfg(feature = "prover")]
pub(crate) fn rand_felt() -> BaseElement {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("rng");
    BaseElement::new(u64::from_le_bytes(b))
}

#[cfg(feature = "prover")]
pub struct ZkCommitProver {
    options: ProofOptions,
}

#[cfg(feature = "prover")]
impl ZkCommitProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    pub fn build_trace(&self, value: u64, blinding: u64) -> TraceTable<BaseElement> {
        let mut cols: v::Vec<v::Vec<BaseElement>> =
            v::vec![v::vec![BaseElement::ZERO; TRACE_LEN]; STATE_WIDTH];
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[0] = BaseElement::new(CAPACITY_INIT);
        state[VALUE_CELL] = BaseElement::new(value);
        state[BLIND_CELL] = BaseElement::new(blinding);
        for c in 0..STATE_WIDTH {
            cols[c][0] = state[c];
        }
        // Transition constraints are enforced for source rows 0..=last_src (the last EXEMPT rows
        // are exempt). The transition at last_src constrains row last_src+1, so continuous rounds
        // must produce rows 1..=last_src+1; masking starts at last_src+2.
        let last_src = TRACE_LEN - 1 - EXEMPT; // 64
        for t in 0..=last_src {
            let idx = t % 8;
            if idx < 7 {
                Rp64_256::apply_round(&mut state, idx);
            } else {
                zero_round(&mut state);
            }
            for c in 0..STATE_WIDTH {
                cols[c][t + 1] = state[c];
            }
        }
        // Masking: fill the (fully) exempt tail with cryptographic randomness.
        for row in (last_src + 2)..TRACE_LEN {
            for c in 0..STATE_WIDTH {
                cols[c][row] = rand_felt();
            }
        }
        let _ = REAL_ROWS;
        TraceTable::init(cols)
    }
}

#[cfg(feature = "prover")]
impl Prover for ZkCommitProver {
    type BaseField = BaseElement;
    type Air = ZkCommitAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> ZkCommitPublicInputs {
        let mut c = [BaseElement::ZERO; DIGEST_SIZE];
        for k in 0..DIGEST_SIZE {
            c[k] = trace.get(VALUE_CELL + k, DIGEST_ROW);
        }
        ZkCommitPublicInputs { commitment: c }
    }
    fn options(&self) -> &ProofOptions {
        &self.options
    }
    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        ti: &TraceInfo,
        mt: &ColMatrix<Self::BaseField>,
        d: &StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(ti, mt, d)
    }
    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux: Option<AuxRandElements<E>>,
        cc: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux, cc)
    }
}

// ───────────────────────── public API ─────────────────────────

#[cfg(feature = "prover")]
pub fn commit(value: u64, blinding: u64) -> [BaseElement; DIGEST_SIZE] {
    let d = Rp64_256::hash_elements(&[BaseElement::new(value), BaseElement::new(blinding)]);
    let mut out = [BaseElement::ZERO; DIGEST_SIZE];
    out.copy_from_slice(d.as_elements());
    out
}

#[cfg(feature = "prover")]
pub fn prove_zk_commit(value: u64, blinding: u64) -> ([BaseElement; DIGEST_SIZE], v::Vec<u8>) {
    let prover = ZkCommitProver::new(crate::proof_options());
    let trace = prover.build_trace(value, blinding);
    let c = prover.get_pub_inputs(&trace).commitment;
    let proof = prover.prove(trace).expect("zk-commit prove");
    (c, proof.to_bytes())
}

pub fn verify_zk_commit(commitment: &[BaseElement; DIGEST_SIZE], proof_bytes: &[u8]) -> bool {
    let proof = match Proof::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let pubs = ZkCommitPublicInputs { commitment: *commitment };
    let min = AcceptableOptions::MinConjecturedSecurity(MIN_SECURITY_BITS);
    winterfell::verify::<
        ZkCommitAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
    >(proof, pubs, &min)
    .is_ok()
}

#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;

    #[test]
    fn zk_opening_verifies_and_matches_native_hash() {
        let (c, p) = prove_zk_commit(1_527_000_000, 0xDEAD_BEEF);
        assert_eq!(c, commit(1_527_000_000, 0xDEAD_BEEF));
        assert!(verify_zk_commit(&c, &p));
    }

    #[test]
    fn proofs_are_randomized() {
        // ZK necessary condition: two proofs of the SAME (value,blinding) must DIFFER
        // (the masking rows are fresh randomness each time). If identical → not hiding.
        let (c1, p1) = prove_zk_commit(42, 7);
        let (c2, p2) = prove_zk_commit(42, 7);
        assert_eq!(c1, c2, "same witness → same commitment");
        assert_ne!(p1, p2, "proofs must be randomized (ZK)");
        assert!(verify_zk_commit(&c1, &p1) && verify_zk_commit(&c2, &p2));
    }

    #[test]
    fn binds_to_commitment() {
        let (c, p) = prove_zk_commit(100, 9);
        assert!(verify_zk_commit(&c, &p));
        let mut c2 = c;
        c2[0] += BaseElement::ONE;
        assert!(!verify_zk_commit(&c2, &p));
    }

    #[test]
    fn tampered_rejected() {
        let (c, mut p) = prove_zk_commit(55, 66);
        let m = p.len() / 2;
        p[m] ^= 0xff;
        assert!(!verify_zk_commit(&c, &p));
    }

    #[test]
    fn zk_security_margin_holds() {
        // Statistical ZK requires #masking(free random) rows > #trace openings.
        // Openings per column ≈ num_queries + OOD frame (2). Masking rows = TRACE_LEN-(last_src+2).
        let last_src = TRACE_LEN - 1 - EXEMPT;
        let masking_rows = TRACE_LEN - (last_src + 2);
        let opts = crate::proof_options();
        let openings = opts.num_queries() + 2; // queries + OOD current/next
        assert!(
            masking_rows > openings,
            "ZK margin violated: masking_rows={masking_rows} must exceed openings={openings}"
        );
        assert!(EXEMPT <= TRACE_LEN / 2, "exemptions must be <= trace_length/2");
    }
}
