//! Full zero-knowledge confidential transfer (note→note), 2-in/2-out, in ONE circuit.
//!
//! Proves, in statistical zero-knowledge (amounts hidden):
//!   1. each input/output commitment opens: `C = Rescue(value, blinding)`
//!   2. balance: `Σ v_in = Σ v_out + fee`
//!   3. range: each output `v_out ∈ [0, 2^63)`
//!
//! ZK is achieved exactly as in `zk_commit` (continuous Rescue + `num_transition_exemptions`
//! masking, coset LDE). All constraints are uniform or single-cell boundaries — NO high-degree
//! single-row selectors. The balance/range values are bound to the openings via a `diff` column
//! trick: a column `d = state[4] − vheld` with the single-cell boundary `d[0] = 0` forces the
//! constant `vheld` column to equal the Rescue input value; balance + range then operate on the
//! constant `vheld` columns with uniform constraints.

use winterfell::{
    crypto::{hashers::Blake3_256, hashers::Rp64_256, DefaultRandomCoin, ElementHasher},
    math::{fields::f64::BaseElement, FieldElement, StarkField, ToElements},
    AcceptableOptions, Air, AirContext, Assertion, EvaluationFrame, Proof, ProofOptions,
    TraceInfo, TransitionConstraintDegree,
};
#[cfg(feature = "prover")]
use winterfell::{
    matrix::ColMatrix, AuxRandElements, ConstraintCompositionCoefficients,
    DefaultConstraintEvaluator, DefaultTraceLde, Prover, StarkDomain, Trace, TracePolyTable,
    TraceTable,
};

use crate::zk_commit::{
    mat_mul, pow7, CAPACITY_INIT, DIGEST_ROW, DIGEST_SIZE, EXEMPT, STATE_WIDTH, TRACE_LEN,
    VALUE_CELL,
};
use crate::MIN_SECURITY_BITS;
#[cfg(feature = "prover")]
use crate::zk_commit::{mat_mul_base, rand_felt, zero_round, BLIND_CELL};

mod v {
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

// AUDIT FIX (2026-06-29): outputs are range-proven to < 2^62 (not 2^63). With the fee also
// bounded < 2^62 (see `verify_zk_transfer_bundle`) and inputs inductively < 2^62 (every note
// enters via shield_v3 / a prior transfer output, both < 2^62), the balance sums satisfy
// Σin < 2^63 and Σout + fee < 3·2^62, BOTH below the Goldilocks modulus p ≈ 2^64 − 2^32. The
// field balance equation therefore equals the integer equation — closing the fee-wraparound
// inflation hole (a malicious prover could otherwise set fee = p − X to mint X). 2^62 base units
// ≈ 4.6e10 QBC ≫ the 3.3e9 max supply, so no legitimate amount is excluded.
pub const RANGE_BITS: usize = 62;
/// Hard bound on every value (output range, fee) so no balance sum can reach the field modulus.
pub const MAX_VALUE: u64 = 1u64 << 62;

// ── column layout (WIDTH = 62) ──────────────────────────────────────────────
// input block b (0,1): [state*12][vheld][d]               base = b*14
// output block j(0,1): [state*12][vheld][d][bit][acc][de] base = 28 + j*17
const IN_BLOCK: usize = 14;
const OUT_BLOCK: usize = 17;
const OUT_BASE: usize = 2 * IN_BLOCK; // 28
const WIDTH: usize = OUT_BASE + 2 * OUT_BLOCK; // 62

#[inline]
fn in_base(b: usize) -> usize { b * IN_BLOCK }
#[inline]
fn out_base(j: usize) -> usize { OUT_BASE + j * OUT_BLOCK }
/// state base, vheld col, d col for any of the 4 blocks (0,1 inputs; 2,3 outputs).
fn block_cols(b: usize) -> (usize, usize, usize) {
    if b < 2 {
        let base = in_base(b);
        (base, base + STATE_WIDTH, base + STATE_WIDTH + 1)
    } else {
        let base = out_base(b - 2);
        (base, base + STATE_WIDTH, base + STATE_WIDTH + 1)
    }
}
/// bit, acc, de cols for output j.
fn out_extra(j: usize) -> (usize, usize, usize) {
    let base = out_base(j);
    (base + STATE_WIDTH + 2, base + STATE_WIDTH + 3, base + STATE_WIDTH + 4)
}

// ───────────────────────── public inputs ─────────────────────────

#[derive(Clone)]
pub struct ZkTransferPublicInputs {
    pub in_commitments: [[BaseElement; DIGEST_SIZE]; 2],
    pub out_commitments: [[BaseElement; DIGEST_SIZE]; 2],
    pub fee: BaseElement,
}

impl ToElements<BaseElement> for ZkTransferPublicInputs {
    fn to_elements(&self) -> v::Vec<BaseElement> {
        let mut e = v::Vec::new();
        for c in &self.in_commitments { e.extend_from_slice(c); }
        for c in &self.out_commitments { e.extend_from_slice(c); }
        e.push(self.fee);
        e
    }
}

// ───────────────────────── the AIR ─────────────────────────

pub struct ZkTransferAir {
    context: AirContext<BaseElement>,
    pubs: ZkTransferPublicInputs,
}

// constraint index layout
const C_RESCUE: usize = 0; // 0..48  (4 blocks × 12)
const C_VHELD: usize = 48; // 48..52 (4 blocks vheld-constant)
const C_DLINK: usize = 52; // 52..56 (4 blocks d = state4 - vheld)
const C_BALANCE: usize = 56; // 56
const C_BIT: usize = 57; // 57..59 (2 outputs bit binary)
const C_ACC: usize = 59; // 59..61 (2 outputs acc recurrence)
const C_DE: usize = 61; // 61..63 (2 outputs de = acc - vheld)
const N_CONSTRAINTS: usize = 63;

impl Air for ZkTransferAir {
    type BaseField = BaseElement;
    type PublicInputs = ZkTransferPublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let mut degrees = v::Vec::with_capacity(N_CONSTRAINTS);
        for _ in 0..48 { degrees.push(TransitionConstraintDegree::new(7)); } // rescue
        for _ in 0..4 { degrees.push(TransitionConstraintDegree::new(1)); } // vheld const
        for _ in 0..4 { degrees.push(TransitionConstraintDegree::new(1)); } // d link
        degrees.push(TransitionConstraintDegree::new(1)); // balance
        for _ in 0..2 { degrees.push(TransitionConstraintDegree::new(2)); } // bit binary
        for _ in 0..2 { degrees.push(TransitionConstraintDegree::new(1)); } // acc recurrence
        for _ in 0..2 { degrees.push(TransitionConstraintDegree::new(1)); } // de
        // boundaries: 4×(10 capacity + 4 digest) + 4 d[0] + 2 acc[0] + 2 de[63] = 64
        let context = AirContext::new(trace_info, degrees, 64, options)
            .set_num_transition_exemptions(EXEMPT);
        ZkTransferAir { context, pubs: pub_inputs }
    }

    fn context(&self) -> &AirContext<Self::BaseField> { &self.context }

    fn get_periodic_column_values(&self) -> v::Vec<v::Vec<BaseElement>> {
        let mut cols = v::Vec::with_capacity(2 * STATE_WIDTH);
        for k in 0..STATE_WIDTH {
            let mut c = v::vec![BaseElement::ZERO; 8];
            for r in 0..7 { c[r] = Rp64_256::ARK1[r][k]; }
            cols.push(c);
        }
        for k in 0..STATE_WIDTH {
            let mut c = v::vec![BaseElement::ZERO; 8];
            for r in 0..7 { c[r] = Rp64_256::ARK2[r][k]; }
            cols.push(c);
        }
        cols
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let next = frame.next();
        let ark1 = &periodic[0..STATE_WIDTH];
        let ark2 = &periodic[STATE_WIDTH..2 * STATE_WIDTH];
        let two = E::ONE + E::ONE;

        // 1. Rescue round per block (uniform, continuous, period-8 ARK).
        for b in 0..4 {
            let (sb, vheld_c, d_c) = block_cols(b);
            let mut cp7 = [E::ZERO; STATE_WIDTH];
            for i in 0..STATE_WIDTH { cp7[i] = pow7(cur[sb + i]); }
            let mds_cur = mat_mul::<E>(&Rp64_256::MDS, &cp7);
            let mut nm = [E::ZERO; STATE_WIDTH];
            for i in 0..STATE_WIDTH { nm[i] = next[sb + i] - ark2[i]; }
            let inv = mat_mul::<E>(&Rp64_256::INV_MDS, &nm);
            for i in 0..STATE_WIDTH {
                result[C_RESCUE + b * STATE_WIDTH + i] = pow7(inv[i]) - (mds_cur[i] + ark1[i]);
            }
            // vheld constant
            result[C_VHELD + b] = next[vheld_c] - cur[vheld_c];
            // d = state[4] - vheld  (boundary d[0]=0 forces vheld[0] = input value)
            result[C_DLINK + b] = cur[d_c] - (cur[sb + VALUE_CELL] - cur[vheld_c]);
        }

        // 2. balance: Σ vheld_in − Σ vheld_out − fee == 0 (uniform; vheld are constant).
        let vin0 = cur[block_cols(0).1];
        let vin1 = cur[block_cols(1).1];
        let vout0 = cur[block_cols(2).1];
        let vout1 = cur[block_cols(3).1];
        result[C_BALANCE] = vin0 + vin1 - vout0 - vout1 - E::from(self.pubs.fee);

        // 3. range per output: bit binary + acc doubling + de = acc - vheld (boundary de[63]=0).
        for j in 0..2 {
            let (bit_c, acc_c, de_c) = out_extra(j);
            let vheld_out = block_cols(2 + j).1;
            let b = cur[bit_c];
            result[C_BIT + j] = b * (b - E::ONE);
            result[C_ACC + j] = next[acc_c] - (two * cur[acc_c] + cur[bit_c]);
            result[C_DE + j] = cur[de_c] - (cur[acc_c] - cur[vheld_out]);
        }
    }

    fn get_assertions(&self) -> v::Vec<Assertion<Self::BaseField>> {
        let mut a = v::Vec::with_capacity(64);
        for b in 0..4 {
            let (sb, _vheld, d_c) = block_cols(b);
            // Rescue sponge init: capacity + zero padding (value@4, blinding@5 free)
            a.push(Assertion::single(sb, 0, BaseElement::new(CAPACITY_INIT)));
            for c in [1usize, 2, 3, 6, 7, 8, 9, 10, 11] {
                a.push(Assertion::single(sb + c, 0, BaseElement::ZERO));
            }
            // digest == commitment
            let commitment = if b < 2 { &self.pubs.in_commitments[b] } else { &self.pubs.out_commitments[b - 2] };
            for k in 0..DIGEST_SIZE {
                a.push(Assertion::single(sb + VALUE_CELL + k, DIGEST_ROW, commitment[k]));
            }
            // d[0] = 0  → vheld[0] = input value
            a.push(Assertion::single(d_c, 0, BaseElement::ZERO));
        }
        for j in 0..2 {
            let (_bit, acc_c, de_c) = out_extra(j);
            a.push(Assertion::single(acc_c, 0, BaseElement::ZERO)); // acc starts 0
            a.push(Assertion::single(de_c, RANGE_BITS, BaseElement::ZERO)); // acc[63] = vout
        }
        a
    }
}

// ───────────────────────── prover (std only) ─────────────────────────

#[cfg(feature = "prover")]
pub struct ZkTransferProver { options: ProofOptions }

#[cfg(feature = "prover")]
impl ZkTransferProver {
    pub fn new(options: ProofOptions) -> Self { Self { options } }

    pub fn build_trace(
        &self,
        in_notes: &[(u64, u64); 2],
        out_notes: &[(u64, u64); 2],
    ) -> TraceTable<BaseElement> {
        let mut cols: v::Vec<v::Vec<BaseElement>> =
            v::vec![v::vec![BaseElement::ZERO; TRACE_LEN]; WIDTH];
        let last_src = TRACE_LEN - 1 - EXEMPT; // 64
        let two = BaseElement::new(2);

        let mut fill_block = |b: usize, value: u64, blinding: u64, cols: &mut v::Vec<v::Vec<BaseElement>>| {
            let (sb, vheld_c, d_c) = block_cols(b);
            let val_fe = BaseElement::new(value);
            // Rescue continuous rounds
            let mut state = [BaseElement::ZERO; STATE_WIDTH];
            state[0] = BaseElement::new(CAPACITY_INIT);
            state[VALUE_CELL] = val_fe;
            state[BLIND_CELL] = BaseElement::new(blinding);
            // row 0
            for c in 0..STATE_WIDTH { cols[sb + c][0] = state[c]; }
            cols[vheld_c][0] = val_fe;
            cols[d_c][0] = state[VALUE_CELL] - val_fe; // = 0
            for t in 0..=last_src {
                let idx = t % 8;
                if idx < 7 { Rp64_256::apply_round(&mut state, idx); } else { zero_round(&mut state); }
                for c in 0..STATE_WIDTH { cols[sb + c][t + 1] = state[c]; }
                cols[vheld_c][t + 1] = val_fe;
                cols[d_c][t + 1] = cols[sb + VALUE_CELL][t + 1] - val_fe;
            }
        };
        for (b, &(val, bl)) in in_notes.iter().enumerate() { fill_block(b, val, bl, &mut cols); }
        for (j, &(val, bl)) in out_notes.iter().enumerate() { fill_block(2 + j, val, bl, &mut cols); }

        // output range columns (bit/acc/de)
        for j in 0..2 {
            let (bit_c, acc_c, de_c) = out_extra(j);
            let value = out_notes[j].0;
            let val_fe = BaseElement::new(value);
            let mut acc = 0u128;
            cols[acc_c][0] = BaseElement::ZERO;
            cols[de_c][0] = BaseElement::new(acc as u64) - val_fe;
            for t in 0..=last_src {
                let bit = if t < RANGE_BITS { (value >> (RANGE_BITS - 1 - t)) & 1 } else { 0 };
                cols[bit_c][t] = BaseElement::new(bit);
                acc = acc.wrapping_mul(2).wrapping_add(bit as u128);
                cols[acc_c][t + 1] = BaseElement::new(acc as u64);
                cols[de_c][t + 1] = cols[acc_c][t + 1] - val_fe;
            }
            // bit at last produced row already set in loop range; ensure bit col has value at last_src
            debug_assert_eq!(cols[acc_c][RANGE_BITS], val_fe, "acc[63] must equal output value");
        }

        // masking tail (exempt rows) — cryptographic randomness in ALL columns
        for row in (last_src + 2)..TRACE_LEN {
            for c in 0..WIDTH {
                cols[c][row] = rand_felt();
            }
        }
        let _ = two;
        TraceTable::init(cols)
    }
}

#[cfg(feature = "prover")]
impl Prover for ZkTransferProver {
    type BaseField = BaseElement;
    type Air = ZkTransferAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> ZkTransferPublicInputs {
        let digest = |b: usize| -> [BaseElement; DIGEST_SIZE] {
            let (sb, _, _) = block_cols(b);
            let mut c = [BaseElement::ZERO; DIGEST_SIZE];
            for k in 0..DIGEST_SIZE { c[k] = trace.get(sb + VALUE_CELL + k, DIGEST_ROW); }
            c
        };
        let in_c = [digest(0), digest(1)];
        let out_c = [digest(2), digest(3)];
        // fee = Σ vin − Σ vout (read from constant vheld columns)
        let vh = |b: usize| trace.get(block_cols(b).1, 0);
        let fee = vh(0) + vh(1) - vh(2) - vh(3);
        ZkTransferPublicInputs { in_commitments: in_c, out_commitments: out_c, fee }
    }
    fn options(&self) -> &ProofOptions { &self.options }
    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self, ti: &TraceInfo, mt: &ColMatrix<Self::BaseField>, d: &StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) { DefaultTraceLde::new(ti, mt, d) }
    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self, air: &'a Self::Air, aux: Option<AuxRandElements<E>>, cc: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> { DefaultConstraintEvaluator::new(air, aux, cc) }
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
pub fn prove_zk_transfer(
    in_notes: &[(u64, u64); 2],
    out_notes: &[(u64, u64); 2],
    fee: u64,
) -> Option<(ZkTransferPublicInputs, v::Vec<u8>)> {
    let si: u128 = in_notes.iter().map(|n| n.0 as u128).sum();
    let so: u128 = out_notes.iter().map(|n| n.0 as u128).sum();
    if si != so + fee as u128 { return None; }
    if out_notes.iter().any(|n| n.0 >= (1u64 << RANGE_BITS)) { return None; }
    let prover = ZkTransferProver::new(crate::proof_options());
    let trace = prover.build_trace(in_notes, out_notes);
    let pubs = prover.get_pub_inputs(&trace);
    let proof = prover.prove(trace).ok()?;
    Some((pubs, proof.to_bytes()))
}

/// Prover convenience that returns 32-byte commitments (4×u64-LE, matching
/// `verify_zk_transfer_bundle`) + the proof — no winterfell types leak to callers
/// (CLI / browser-wasm). Returns None on unbalanced or out-of-range inputs.
#[cfg(feature = "prover")]
pub fn prove_zk_transfer_bytes(
    in_notes: &[(u64, u64); 2],
    out_notes: &[(u64, u64); 2],
    fee: u64,
) -> Option<([[u8; 32]; 2], [[u8; 32]; 2], v::Vec<u8>)> {
    let (pubs, proof) = prove_zk_transfer(in_notes, out_notes, fee)?;
    let to_b = |c: &[BaseElement; DIGEST_SIZE]| -> [u8; 32] {
        let mut b = [0u8; 32];
        for k in 0..DIGEST_SIZE {
            b[k * 8..k * 8 + 8].copy_from_slice(&c[k].as_int().to_le_bytes());
        }
        b
    };
    Some((
        [to_b(&pubs.in_commitments[0]), to_b(&pubs.in_commitments[1])],
        [to_b(&pubs.out_commitments[0]), to_b(&pubs.out_commitments[1])],
        proof,
    ))
}

pub fn verify_zk_transfer(pubs: &ZkTransferPublicInputs, proof_bytes: &[u8]) -> bool {
    let proof = match Proof::from_bytes(proof_bytes) { Ok(p) => p, Err(_) => return false };
    let min = AcceptableOptions::MinConjecturedSecurity(MIN_SECURITY_BITS);
    winterfell::verify::<
        ZkTransferAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
    >(proof, pubs.clone(), &min)
    .is_ok()
}

/// Runtime-facing raw-bytes verify (no winterfell types leak). 32-byte commitments (4×u64-LE) + u64 fee.
pub fn verify_zk_transfer_bundle(
    in_commitments: &[[u8; 32]],
    out_commitments: &[[u8; 32]],
    fee: u64,
    proof_bytes: &[u8],
) -> bool {
    if in_commitments.len() != 2 || out_commitments.len() != 2 { return false; }
    // AUDIT FIX: reject an unbounded fee. Without this, a malicious prover sets fee = p − X so the
    // FIELD balance Σin − Σout − fee ≡ 0 holds while Σout − Σin = X in the integers → mints X.
    if fee >= MAX_VALUE { return false; }
    let to_d = |b: &[u8; 32]| -> [BaseElement; DIGEST_SIZE] {
        let mut d = [BaseElement::new(0); DIGEST_SIZE];
        for k in 0..DIGEST_SIZE {
            let mut le = [0u8; 8];
            le.copy_from_slice(&b[k * 8..k * 8 + 8]);
            d[k] = BaseElement::new(u64::from_le_bytes(le));
        }
        d
    };
    let pubs = ZkTransferPublicInputs {
        in_commitments: [to_d(&in_commitments[0]), to_d(&in_commitments[1])],
        out_commitments: [to_d(&out_commitments[0]), to_d(&out_commitments[1])],
        fee: BaseElement::new(fee),
    };
    verify_zk_transfer(&pubs, proof_bytes)
}

#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;

    #[test]
    fn zk_transfer_verifies_and_binds() {
        let ins = [(10u64, 111u64), (7u64, 222u64)];
        let outs = [(12u64, 333u64), (4u64, 444u64)];
        let (pubs, proof) = prove_zk_transfer(&ins, &outs, 1).expect("balanced+in range");
        assert!(verify_zk_transfer(&pubs, &proof), "valid ZK transfer must verify");
        assert_eq!(pubs.in_commitments[0], commit(10, 111));
        assert_eq!(pubs.out_commitments[1], commit(4, 444));
    }

    #[test]
    fn proofs_are_zero_knowledge_randomized() {
        let ins = [(8u64, 5u64), (2u64, 6u64)];
        let outs = [(6u64, 7u64), (4u64, 8u64)];
        let (_p1, b1) = prove_zk_transfer(&ins, &outs, 0).unwrap();
        let (_p2, b2) = prove_zk_transfer(&ins, &outs, 0).unwrap();
        assert_ne!(b1, b2, "ZK: proofs of the same transfer must be randomized");
    }

    #[test]
    fn unbalanced_unprovable() {
        let ins = [(10u64, 1u64), (7u64, 2u64)];
        let outs = [(12u64, 3u64), (5u64, 4u64)]; // 17 != 18
        assert!(prove_zk_transfer(&ins, &outs, 1).is_none());
    }

    #[test]
    fn out_of_range_unprovable() {
        let ins = [((1u64 << 63), 1u64), (0u64, 2u64)]; // input huge — but balance forces output huge
        let outs = [((1u64 << 63), 3u64), (0u64, 4u64)];
        assert!(prove_zk_transfer(&ins, &outs, 0).is_none(), "out-of-range output unprovable");
    }

    #[test]
    fn forged_fee_and_commitment_rejected() {
        let ins = [(10u64, 1u64), (7u64, 2u64)];
        let outs = [(12u64, 3u64), (4u64, 4u64)];
        let (mut pubs, proof) = prove_zk_transfer(&ins, &outs, 1).unwrap();
        assert!(verify_zk_transfer(&pubs, &proof));
        let good = pubs.clone();
        pubs.fee = BaseElement::new(2);
        assert!(!verify_zk_transfer(&pubs, &proof), "forged fee rejected");
        pubs = good;
        pubs.out_commitments[0] = commit(999, 1);
        assert!(!verify_zk_transfer(&pubs, &proof), "forged commitment rejected");
    }

    #[test]
    fn poc_fee_wraparound_inflation_rejected() {
        // AUDIT REGRESSION: a malicious prover builds a trace where outputs sum to MORE than
        // inputs (inflation), and sets fee = p - X so the field balance still holds. Before the
        // fix this verified (minting X). After the fix (fee bounded < 2^62 in the verifier) it
        // must be REJECTED.
        let ins = [(10u64, 1u64), (7u64, 2u64)]; // sum 17
        let outs = [(600u64, 3u64), (400u64, 4u64)]; // sum 1000 -> inflate 983
        let prover = ZkTransferProver::new(crate::proof_options());
        let trace = prover.build_trace(&ins, &outs);
        let pubs = prover.get_pub_inputs(&trace); // fee = 17-1000 = p-983 (field wrap)
        let proof = prover.prove(trace).expect("malicious trace still proves").to_bytes();
        // Convert to the runtime-facing bundle form (this is what the chain actually calls).
        let db = |c: &[BaseElement; 4]| { let mut b=[0u8;32]; for k in 0..4 { b[k*8..k*8+8].copy_from_slice(&c[k].as_int().to_le_bytes()); } b };
        let inc: v::Vec<[u8;32]> = pubs.in_commitments.iter().map(db).collect();
        let outc: v::Vec<[u8;32]> = pubs.out_commitments.iter().map(db).collect();
        let fee_u64 = pubs.fee.as_int(); // = p - 983, a huge u64
        assert!(
            !verify_zk_transfer_bundle(&inc, &outc, fee_u64, &proof),
            "INFLATION: a transfer minting value via fee-wraparound must be rejected"
        );
    }

    #[test]
    fn tampered_rejected() {
        let ins = [(5u64, 1u64), (5u64, 2u64)];
        let outs = [(6u64, 3u64), (3u64, 4u64)];
        let (pubs, mut proof) = prove_zk_transfer(&ins, &outs, 1).unwrap();
        let m = proof.len() / 2;
        proof[m] ^= 0xff;
        assert!(!verify_zk_transfer(&pubs, &proof));
    }

    #[test]
    fn raw_bundle_api() {
        use winterfell::math::StarkField;
        let ins = [(9u64, 1u64), (1u64, 2u64)];
        let outs = [(6u64, 3u64), (4u64, 4u64)];
        let (pubs, proof) = prove_zk_transfer(&ins, &outs, 0).unwrap();
        let db = |c: &[BaseElement; 4]| { let mut b=[0u8;32]; for k in 0..4 { b[k*8..k*8+8].copy_from_slice(&c[k].as_int().to_le_bytes()); } b };
        let inc: v::Vec<[u8;32]> = pubs.in_commitments.iter().map(db).collect();
        let outc: v::Vec<[u8;32]> = pubs.out_commitments.iter().map(db).collect();
        assert!(verify_zk_transfer_bundle(&inc, &outc, 0, &proof));
        assert!(!verify_zk_transfer_bundle(&inc, &outc, 1, &proof), "wrong fee rejected");
    }
}

