//! Milestone 2.5 — multi-IO commitment openings + balance (note→note core).
//!
//! Proves, in zero-knowledge, for a fixed shape `N_IN` inputs / `N_OUT` outputs:
//!   1. each input  commitment `C_in_i  = Rescue(v_in_i,  r_in_i)`  (opening = spend authority)
//!   2. each output commitment `C_out_j = Rescue(v_out_j, r_out_j)` (output well-formed)
//!   3. balance: `Σ v_in_i == Σ v_out_j + fee`                       (no inflation)
//!
//! This is the value-conservation core of a confidential transfer. The hidden values are bound
//! to the public commitments by the in-circuit Rescue (same audited gadget proven in `commit`),
//! and balance is enforced over those bound values — so the relayer/observer never learns the
//! amounts, yet cannot create value. RANGE proofs on outputs (the `range` gadget) are fused in
//! M2.5b to close the wrap-around case; see `docs/DESIGN.md`.
//!
//! Each commitment opening is a 12-column Rescue block; `N = N_IN + N_OUT` blocks sit side by
//! side in one 8-row trace. Balance is a single row-0 (selector-gated) linear constraint over the
//! per-block value cells. Built on Winterfell's audited `Rp64_256` constants.

use winterfell::{
    crypto::{hashers::Blake3_256, hashers::Rp64_256, DefaultRandomCoin, ElementHasher},
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
const TRACE_LEN: usize = 8;
const DIGEST_SIZE: usize = 4;
const CAPACITY_INIT: u64 = 2;
const VALUE_CELL: usize = 4; // state[4] = first absorbed element (the value)
const BLIND_CELL: usize = 5; // state[5] = second absorbed element (the blinding)

/// Fixed transfer shape. 2-in / 2-out covers the common wallet case (spend up to two notes →
/// recipient + change). Larger shapes are mechanical replication.
pub const N_IN: usize = 2;
pub const N_OUT: usize = 2;
const N_BLOCKS: usize = N_IN + N_OUT;
const WIDTH: usize = N_BLOCKS * STATE_WIDTH;

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
pub struct TransferPublicInputs {
    pub in_commitments: [[BaseElement; DIGEST_SIZE]; N_IN],
    pub out_commitments: [[BaseElement; DIGEST_SIZE]; N_OUT],
    pub fee: BaseElement,
}

impl ToElements<BaseElement> for TransferPublicInputs {
    fn to_elements(&self) -> v::Vec<BaseElement> {
        let mut e = v::Vec::with_capacity(N_BLOCKS * DIGEST_SIZE + 1);
        for c in &self.in_commitments {
            e.extend_from_slice(c);
        }
        for c in &self.out_commitments {
            e.extend_from_slice(c);
        }
        e.push(self.fee);
        e
    }
}

// ───────────────────────── the AIR ─────────────────────────

pub struct TransferAir {
    context: AirContext<BaseElement>,
    pubs: TransferPublicInputs,
}

impl Air for TransferAir {
    type BaseField = BaseElement;
    type PublicInputs = TransferPublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // N_BLOCKS × 12 Rescue round constraints (degree 7) + 1 balance constraint (degree 2).
        let mut degrees = v::vec![TransitionConstraintDegree::new(7); WIDTH];
        degrees.push(TransitionConstraintDegree::new(2));
        // boundaries: per block 10 (capacity+padding) + 4 (digest) = 14 ⇒ 14·N_BLOCKS
        let num_assertions = 14 * N_BLOCKS;
        let context = AirContext::new(trace_info, degrees, num_assertions, options);
        TransferAir { context, pubs: pub_inputs }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn get_periodic_column_values(&self) -> v::Vec<v::Vec<BaseElement>> {
        let mut cols = v::Vec::with_capacity(2 * STATE_WIDTH + 1);
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
        // is_first selector: 1 at row 0, else 0 → gates the balance constraint to row 0.
        let mut sel = v::vec![BaseElement::ZERO; TRACE_LEN];
        sel[0] = BaseElement::ONE;
        cols.push(sel);
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
        let is_first = periodic_values[2 * STATE_WIDTH];

        // Rescue round constraints, replicated per block.
        for b in 0..N_BLOCKS {
            let base = b * STATE_WIDTH;
            let mut cur_pow7 = [E::ZERO; STATE_WIDTH];
            for i in 0..STATE_WIDTH {
                cur_pow7[i] = pow7(cur[base + i]);
            }
            let mds_cur = mat_mul::<E>(&Rp64_256::MDS, &cur_pow7);
            let mut next_minus_ark2 = [E::ZERO; STATE_WIDTH];
            for i in 0..STATE_WIDTH {
                next_minus_ark2[i] = next[base + i] - ark2[i];
            }
            let inv_mds = mat_mul::<E>(&Rp64_256::INV_MDS, &next_minus_ark2);
            for i in 0..STATE_WIDTH {
                result[base + i] = pow7(inv_mds[i]) - (mds_cur[i] + ark1[i]);
            }
        }

        // Balance (row 0 only): Σ in_value − Σ out_value − fee == 0.
        let mut bal = E::ZERO;
        for b in 0..N_IN {
            bal += cur[b * STATE_WIDTH + VALUE_CELL];
        }
        for b in 0..N_OUT {
            bal -= cur[(N_IN + b) * STATE_WIDTH + VALUE_CELL];
        }
        bal -= E::from(self.pubs.fee);
        result[WIDTH] = is_first * bal;
    }

    fn get_assertions(&self) -> v::Vec<Assertion<Self::BaseField>> {
        let mut a = v::Vec::with_capacity(14 * N_BLOCKS);
        for b in 0..N_BLOCKS {
            let base = b * STATE_WIDTH;
            // row 0: capacity init + zero padding (value@4, blinding@5 FREE)
            a.push(Assertion::single(base, 0, BaseElement::new(CAPACITY_INIT)));
            for c in [1usize, 2, 3, 6, 7, 8, 9, 10, 11] {
                a.push(Assertion::single(base + c, 0, BaseElement::ZERO));
            }
            // final digest == public commitment for this block
            let commitment = if b < N_IN {
                &self.pubs.in_commitments[b]
            } else {
                &self.pubs.out_commitments[b - N_IN]
            };
            for k in 0..DIGEST_SIZE {
                a.push(Assertion::single(base + VALUE_CELL + k, TRACE_LEN - 1, commitment[k]));
            }
        }
        a
    }
}

// ───────────────────────── the prover ─────────────────────────

#[cfg(feature = "prover")]
pub struct TransferProver {
    options: ProofOptions,
}

#[cfg(feature = "prover")]
impl TransferProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    /// Build the trace: one Rescue permutation per IO block over (value, blinding).
    pub fn build_trace(
        &self,
        in_notes: &[(u64, u64); N_IN],
        out_notes: &[(u64, u64); N_OUT],
    ) -> TraceTable<BaseElement> {
        let mut cols: v::Vec<v::Vec<BaseElement>> =
            v::vec![v::vec![BaseElement::ZERO; TRACE_LEN]; WIDTH];
        let mut fill = |block: usize, value: u64, blinding: u64, cols: &mut v::Vec<v::Vec<BaseElement>>| {
            let base = block * STATE_WIDTH;
            let mut state = [BaseElement::ZERO; STATE_WIDTH];
            state[0] = BaseElement::new(CAPACITY_INIT);
            state[VALUE_CELL] = BaseElement::new(value);
            state[BLIND_CELL] = BaseElement::new(blinding);
            for c in 0..STATE_WIDTH {
                cols[base + c][0] = state[c];
            }
            for r in 0..NUM_ROUNDS {
                Rp64_256::apply_round(&mut state, r);
                for c in 0..STATE_WIDTH {
                    cols[base + c][r + 1] = state[c];
                }
            }
        };
        for (b, &(val, bl)) in in_notes.iter().enumerate() {
            fill(b, val, bl, &mut cols);
        }
        for (b, &(val, bl)) in out_notes.iter().enumerate() {
            fill(N_IN + b, val, bl, &mut cols);
        }
        TraceTable::init(cols)
    }
}

#[cfg(feature = "prover")]
impl Prover for TransferProver {
    type BaseField = BaseElement;
    type Air = TransferAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> TransferPublicInputs {
        let digest = |block: usize| -> [BaseElement; DIGEST_SIZE] {
            let base = block * STATE_WIDTH;
            let mut c = [BaseElement::ZERO; DIGEST_SIZE];
            for k in 0..DIGEST_SIZE {
                c[k] = trace.get(base + VALUE_CELL + k, TRACE_LEN - 1);
            }
            c
        };
        let mut in_c = [[BaseElement::ZERO; DIGEST_SIZE]; N_IN];
        let mut out_c = [[BaseElement::ZERO; DIGEST_SIZE]; N_OUT];
        for b in 0..N_IN {
            in_c[b] = digest(b);
        }
        for b in 0..N_OUT {
            out_c[b] = digest(N_IN + b);
        }
        // fee is recovered from balance: Σin − Σout (the prover sets it; verifier supplies it).
        let val = |block: usize| trace.get(block * STATE_WIDTH + VALUE_CELL, 0);
        let mut fee = BaseElement::ZERO;
        for b in 0..N_IN {
            fee += val(b);
        }
        for b in 0..N_OUT {
            fee -= val(N_IN + b);
        }
        TransferPublicInputs { in_commitments: in_c, out_commitments: out_c, fee }
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

/// Prove a balanced confidential transfer. Returns `(public_inputs, proof_bytes)`.
/// Requires `Σ in_values == Σ out_values + fee` (else the prover cannot build a valid proof).
#[cfg(feature = "prover")]
pub fn prove_transfer(
    in_notes: &[(u64, u64); N_IN],
    out_notes: &[(u64, u64); N_OUT],
    fee: u64,
) -> Option<(TransferPublicInputs, v::Vec<u8>)> {
    let sum_in: u128 = in_notes.iter().map(|n| n.0 as u128).sum();
    let sum_out: u128 = out_notes.iter().map(|n| n.0 as u128).sum();
    if sum_in != sum_out + fee as u128 {
        return None; // unbalanced — honest prover refuses
    }
    let prover = TransferProver::new(proof_options());
    let trace = prover.build_trace(in_notes, out_notes);
    let pubs = prover.get_pub_inputs(&trace);
    let proof = prover.prove(trace).ok()?;
    Some((pubs, proof.to_bytes()))
}

/// Verify a confidential transfer against public inputs (commitments + fee). Post-quantum.
pub fn verify_transfer(pubs: &TransferPublicInputs, proof_bytes: &[u8]) -> bool {
    let proof = match Proof::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let min_opts = AcceptableOptions::MinConjecturedSecurity(MIN_SECURITY_BITS);
    winterfell::verify::<
        TransferAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
    >(proof, pubs.clone(), &min_opts)
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pubs_for(
        in_notes: &[(u64, u64); N_IN],
        out_notes: &[(u64, u64); N_OUT],
        fee: u64,
    ) -> TransferPublicInputs {
        let mut in_c = [[BaseElement::ZERO; DIGEST_SIZE]; N_IN];
        let mut out_c = [[BaseElement::ZERO; DIGEST_SIZE]; N_OUT];
        for (b, n) in in_notes.iter().enumerate() {
            in_c[b] = note_commitment(n.0, n.1);
        }
        for (b, n) in out_notes.iter().enumerate() {
            out_c[b] = note_commitment(n.0, n.1);
        }
        TransferPublicInputs { in_commitments: in_c, out_commitments: out_c, fee: BaseElement::new(fee) }
    }

    #[test]
    fn balanced_transfer_verifies() {
        // 10 + 7 in  ->  12 + 4 out  + fee 1   (17 == 16 + 1)
        let ins = [(10u64, 111u64), (7u64, 222u64)];
        let outs = [(12u64, 333u64), (4u64, 444u64)];
        let (pubs, proof) = prove_transfer(&ins, &outs, 1).expect("balanced");
        assert!(verify_transfer(&pubs, &proof), "valid balanced transfer must verify");
        // public commitments match the native hashes
        assert_eq!(pubs.in_commitments[0], note_commitment(10, 111));
        assert_eq!(pubs.out_commitments[1], note_commitment(4, 444));
        assert_eq!(pubs.fee, BaseElement::new(1));
    }

    #[test]
    fn unbalanced_transfer_cannot_be_proven() {
        // 10 + 7 in -> 12 + 5 out + fee 1  (17 != 18) — honest prover refuses
        let ins = [(10u64, 1u64), (7u64, 2u64)];
        let outs = [(12u64, 3u64), (5u64, 4u64)];
        assert!(prove_transfer(&ins, &outs, 1).is_none());
    }

    #[test]
    fn proof_binds_to_fee() {
        let ins = [(10u64, 1u64), (7u64, 2u64)];
        let outs = [(12u64, 3u64), (4u64, 4u64)];
        let (mut pubs, proof) = prove_transfer(&ins, &outs, 1).expect("balanced");
        assert!(verify_transfer(&pubs, &proof));
        // claim a different fee → statement changes → rejected
        pubs.fee = BaseElement::new(2);
        assert!(!verify_transfer(&pubs, &proof), "proof must bind to fee");
    }

    #[test]
    fn proof_binds_to_commitments() {
        let ins = [(10u64, 1u64), (7u64, 2u64)];
        let outs = [(12u64, 3u64), (4u64, 4u64)];
        let (mut pubs, proof) = prove_transfer(&ins, &outs, 1).expect("balanced");
        assert!(verify_transfer(&pubs, &proof));
        // swap an output commitment for an unrelated one → rejected
        pubs.out_commitments[0] = note_commitment(999, 999);
        assert!(!verify_transfer(&pubs, &proof), "proof must bind to commitments");
    }

    #[test]
    fn tampered_proof_rejected() {
        let ins = [(5u64, 9u64), (5u64, 8u64)];
        let outs = [(6u64, 7u64), (3u64, 6u64)];
        let (pubs, mut proof) = prove_transfer(&ins, &outs, 1).expect("balanced");
        let mid = proof.len() / 2;
        proof[mid] ^= 0xff;
        assert!(!verify_transfer(&pubs, &proof));
    }

    #[test]
    fn zero_fee_transfer() {
        let ins = [(8u64, 11u64), (2u64, 22u64)];
        let outs = [(6u64, 33u64), (4u64, 44u64)];
        let (pubs, proof) = prove_transfer(&ins, &outs, 0).expect("balanced, fee 0");
        assert!(verify_transfer(&pubs, &proof));
    }
}
